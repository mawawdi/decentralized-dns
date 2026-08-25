package server

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/mawawdi/decentralized-dns/resolver/internal/cache"
	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
	"github.com/mawawdi/decentralized-dns/resolver/internal/zk"
)

// ChainReader is the read-only chain surface the query path depends on.
// *chain.Client satisfies it; tests substitute a fake.
type ChainReader interface {
	Resolve(ctx context.Context, name, recordType, selector string) (*chain.ResolveResult, error)
	GetDomain(ctx context.Context, name string) (*chain.Domain, error)
	ListRecords(ctx context.Context, name string) ([]chain.Record, error)
	ListTypes(ctx context.Context) ([]string, error)
	ChainHead(ctx context.Context) (uint64, error)
}

// QueryResult is HandleQuery's answer: the chain result plus provenance.
type QueryResult struct {
	Result *chain.ResolveResult
	Cached bool
}

// HandleQuery is the single resolution path shared by the REST and UDP
// front ends (HLD §4.1.2): read-through cache -> chain, caching positive
// answers for the record's on-chain TTL. Owner signatures are verified
// once at cache-fill time (UC-5) and the verdict cached with the entry.
// Misses are not negatively cached so new records become visible
// immediately.
func (s *Server) HandleQuery(ctx context.Context, q query.Query) (*QueryResult, error) {
	key := cache.Key{Name: q.Name, Type: q.Type, Selector: q.Selector}
	if res, ok := s.cache.Get(key); ok {
		return &QueryResult{Result: res, Cached: true}, nil
	}
	res, err := s.chain.Resolve(ctx, q.Name, q.Type, q.Selector)
	if err != nil {
		return nil, err
	}
	if res.Record.Exists {
		if err := pki.VerifyOwnerSig(q.Name, res.Record, res.Owner, res.PubKey); err != nil {
			s.log.Warn("owner signature failed", "name", q.Name, "type", q.Type, "err", err)
		} else {
			res.OwnerSigValid = true
		}
		res.ZKProof = s.proveRecord(q.Name, res.Record)
		if res.Record.TTL > 0 {
			s.cache.Set(key, res, time.Duration(res.Record.TTL)*time.Second)
		}
	}
	return &QueryResult{Result: res}, nil
}

// proveRecord generates the Groth16 record-commitment proof (HLD §3.5)
// when the record carries a commitment. The proof is cached with the
// entry, so the ~50ms proving cost is paid once per TTL window. An empty
// result means no commitment, an oversized payload, or a commitment that
// does not match the payload (nothing true can be proven).
func (s *Server) proveRecord(name string, rec chain.Record) []byte {
	if rec.Commitment == ([32]byte{}) {
		return nil
	}
	if len(rec.FieldNames) != len(rec.FieldVals) {
		s.log.Warn("record field arrays length mismatch", "name", name, "type", rec.Type)
		return nil
	}
	msg := pki.RecordMessage(name, rec)
	com, err := zk.Commitment(msg)
	if err != nil {
		s.log.Warn("zk commitment", "name", name, "err", err)
		return nil
	}
	if com != rec.Commitment {
		s.log.Warn("on-chain commitment does not match payload", "name", name, "type", rec.Type)
		return nil
	}
	proof, err := zk.Prove(msg)
	if err != nil {
		s.log.Warn("zk prove", "name", name, "err", err)
		return nil
	}
	calldata, err := zk.SolidityCalldata(proof)
	if err != nil {
		s.log.Warn("zk calldata", "name", name, "err", err)
		return nil
	}
	return calldata
}

// Found reports whether the result carries a live record.
func (r *QueryResult) Found() bool {
	return r.Result != nil && r.Result.Record.Exists && r.Result.Owner != (common.Address{})
}
