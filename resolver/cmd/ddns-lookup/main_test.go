package main

import (
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
	"github.com/mawawdi/decentralized-dns/resolver/internal/zk"
)

// cloneResp deep-copies the response so a test can tamper with a single field
// without disturbing the shared record pointer.
func cloneResp(r resolveResponse) resolveResponse {
	out := r
	if r.Record != nil {
		rec := *r.Record
		rec.FieldNames = append([]string(nil), r.Record.FieldNames...)
		rec.FieldValues = append([]string(nil), r.Record.FieldValues...)
		out.Record = &rec
	}
	return out
}

// honestPair builds a self-consistent (on-chain record, resolver response) for
// "example A", exactly as an honest resolver would echo on-chain truth.
func honestPair(t *testing.T) (*chain.ResolveResult, query.Query, resolveResponse) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	owner := crypto.PubkeyToAddress(key.PublicKey)
	pubKey := crypto.FromECDSAPub(&key.PublicKey)

	rec := chain.Record{
		Type: "A", Selector: "", FieldNames: []string{"address"},
		FieldVals: []string{"93.184.216.34"}, TTL: 3600, Generation: 4, Exists: true,
	}
	if rec.OwnerSig, err = pki.SignRecord("example", rec, key); err != nil {
		t.Fatal(err)
	}
	if rec.Commitment, err = zk.Commitment(pki.RecordMessage("example", rec)); err != nil {
		t.Fatal(err)
	}

	onchain := &chain.ResolveResult{Record: rec, Owner: owner, PubKey: pubKey}
	q, err := query.New("example", "A", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := resolveResponse{
		Found:  true,
		Owner:  owner.Hex(),
		PubKey: hexutil.Encode(pubKey),
		Record: &recordJSON{
			Type:        rec.Type,
			Selector:    rec.Selector,
			FieldNames:  rec.FieldNames,
			FieldValues: rec.FieldVals,
			TTL:         rec.TTL,
			Generation:  rec.Generation,
			OwnerSig:    hexutil.Encode(rec.OwnerSig),
			Commitment:  hexutil.Encode(rec.Commitment[:]),
		},
	}
	return onchain, q, resp
}

func TestDiffAgainstChainHonest(t *testing.T) {
	onchain, q, resp := honestPair(t)
	if err := diffAgainstChain(onchain, q, resp); err != nil {
		t.Fatalf("honest answer rejected: %v", err)
	}
}

// A resolver that alters any signature-bearing or identity field must be
// caught by the cross-check (the whole point of --discover hardening).
func TestDiffAgainstChainRejectsTampering(t *testing.T) {
	other, _ := crypto.GenerateKey()
	otherAddr := crypto.PubkeyToAddress(other.PublicKey)
	otherPub := crypto.FromECDSAPub(&other.PublicKey)

	cases := []struct {
		name   string
		mutate func(resp *resolveResponse)
	}{
		{"owner", func(r *resolveResponse) { r.Owner = otherAddr.Hex() }},
		{"pubKey", func(r *resolveResponse) { r.PubKey = hexutil.Encode(otherPub) }},
		{"commitment", func(r *resolveResponse) {
			r.Record.Commitment = hexutil.Encode(make([]byte, 32)) // zero, != real
		}},
		{"ownerSig", func(r *resolveResponse) {
			b := make([]byte, 65)
			r.Record.OwnerSig = hexutil.Encode(b)
		}},
		{"fieldValue", func(r *resolveResponse) { r.Record.FieldValues[0] = "6.6.6.6" }},
		{"ttl", func(r *resolveResponse) { r.Record.TTL = 60 }},
		{"generation", func(r *resolveResponse) { r.Record.Generation = 5 }},
		{"withholding", func(r *resolveResponse) { r.Found = false; r.Record = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			onchain, q, resp := honestPair(t)
			tampered := cloneResp(resp)
			tc.mutate(&tampered)
			if err := diffAgainstChain(onchain, q, tampered); err == nil {
				t.Errorf("tampered %s accepted by cross-check", tc.name)
			}
		})
	}
}

// A resolver that fabricates a record the chain does not hold must be rejected.
func TestDiffAgainstChainRejectsFabricated(t *testing.T) {
	_, q, resp := honestPair(t)
	empty := &chain.ResolveResult{} // Record.Exists == false
	if err := diffAgainstChain(empty, q, resp); err == nil {
		t.Error("record absent on-chain but accepted from resolver")
	}
}

// When the resolver honestly reports no match and the chain agrees, the
// cross-check passes.
func TestDiffAgainstChainNoMatchAgreement(t *testing.T) {
	q, err := query.New("example", "AAAA", nil)
	if err != nil {
		t.Fatal(err)
	}
	empty := &chain.ResolveResult{}
	resp := resolveResponse{Found: false}
	if err := diffAgainstChain(empty, q, resp); err != nil {
		t.Errorf("agreed no-match rejected: %v", err)
	}
}
