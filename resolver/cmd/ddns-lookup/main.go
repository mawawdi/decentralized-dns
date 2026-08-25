// Command ddns-lookup queries a resolver and INDEPENDENTLY verifies the
// response: the resolver's ed25519 envelope signature, the domain owner's
// secp256k1 record signature (recovered against the on-chain pubKey returned in
// the response), and the Groth16 record-commitment proof (HLD §4.3, UC-4/UC-5).
// It never trusts the resolver's own "verified" flags — it re-checks the
// cryptography itself, which is the whole point of the PKI design.
//
// With --discover (which already dials the chain to find the resolver) it
// additionally CROSS-CHECKS the answer against NamespaceDApp.resolve: the
// owner, pubKey, ZK commitment and full signed record body must equal on-chain
// state — closing the gap where the owner-sig and ZK checks would otherwise
// verify only against resolver-supplied data — and a "no match" must be
// corroborated by the chain so a resolver cannot silently withhold a record.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/chain/bindings"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
	"github.com/mawawdi/decentralized-dns/resolver/internal/zk"
)

type recordJSON struct {
	Type        string   `json:"type"`
	Selector    string   `json:"selector"`
	FieldNames  []string `json:"fieldNames"`
	FieldValues []string `json:"fieldValues"`
	TTL         uint32   `json:"ttl"`
	Generation  uint64   `json:"generation"`
	OwnerSig    string   `json:"ownerSig"`
	Commitment  string   `json:"commitment"`
}

type resolveResponse struct {
	Found            bool        `json:"found"`
	Error            string      `json:"error"`
	Record           *recordJSON `json:"record"`
	Owner            string      `json:"owner"`
	PubKey           string      `json:"pubKey"`
	OwnerSigVerified bool        `json:"ownerSigVerified"`
	ZKProof          string      `json:"zkProof"`
	Cached           bool        `json:"cached"`
}

func main() {
	fs := flag.NewFlagSet("ddns-lookup", flag.ExitOnError)
	resolver := fs.String("resolver", envOr("DDNS_RESOLVER", "http://127.0.0.1:8080"), "resolver base URL")
	selector := fs.String("selector", "", `selector, e.g. "service=HTTP&transport=TCP&port=443"`)
	timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
	discover := fs.Bool("discover", false, "discover a resolver from the on-chain ResolverRegistry and pin its key")
	rpc := fs.String("rpc", envOr("RPC_URL", "http://127.0.0.1:8545"), "blockchain RPC URL (for --discover)")
	deployments := fs.String("deployments", envOr("DDNS_DEPLOYMENTS", "contracts/deployments/localhost.json"), "deploy json (for --discover)")
	registryFlag := fs.String("resolver-registry", "", "ResolverRegistry address (for --discover)")
	namespaceFlag := fs.String("namespace", "", "NamespaceDApp address (for the --discover on-chain cross-check)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ddns-lookup [flags] <name> <type>")
		fmt.Fprintln(os.Stderr, "\nQueries a resolver and verifies the signed response end-to-end.")
		fs.PrintDefaults()
	}
	_ = fs.Parse(reorder(os.Args[1:], "discover"))

	// Bootstrap: discover a resolver from the on-chain directory (HLD issue 7)
	// and remember the key it advertised, so we can pin the answer to it.
	pinnedKey := ""
	if *discover {
		endpoint, key := discoverResolver(*rpc, *deployments, *registryFlag)
		*resolver, pinnedKey = endpoint, key
		fmt.Printf("discovered: %s (pinned key %s)\n", endpoint, key)
	}
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}
	name, typ := fs.Arg(0), fs.Arg(1)

	pairs, err := query.ParsePairs(*selector)
	fatal(err)
	q, err := query.New(name, typ, pairs)
	fatal(err)

	endpoint := *resolver + "/resolve?" + url.Values{
		"name": {q.Name}, "type": {q.Type}, "selector": {q.Selector},
	}.Encode()

	client := &http.Client{Timeout: *timeout}
	httpResp, err := client.Get(endpoint)
	fatal(err)
	defer httpResp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, 8<<20))
	fatal(err)

	// 1. Verify the resolver's identity signature over the response.
	var env pki.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fatal(fmt.Errorf("resolver returned a non-envelope response (HTTP %d): %s", httpResp.StatusCode, raw))
	}
	if err := pki.VerifyEnvelope(&env); err != nil {
		fatal(fmt.Errorf("resolver envelope signature INVALID: %w", err))
	}
	// When discovered via the registry, the answering resolver's key must match
	// the one the registry advertised — otherwise we are talking to an impostor.
	if pinnedKey != "" && !strings.EqualFold(env.Resolver, pinnedKey) {
		fatal(fmt.Errorf("resolver key MISMATCH: registry pinned %s but answer signed by %s", pinnedKey, env.Resolver))
	}
	var resp resolveResponse
	fatal(json.Unmarshal(env.Data, &resp))

	fmt.Printf("resolver:  %s (envelope signature OK)\n", env.Resolver)
	fmt.Printf("query:     %s %s%s\n", q.Name, q.Type, bracket(q.Selector))
	fmt.Printf("cached:    %v\n", resp.Cached)

	if !resp.Found {
		fmt.Printf("result:    NO MATCH (%s)\n", orDefault(resp.Error, "no_match"))
		// A discovered resolver's "no match" is corroborated against the chain
		// so it cannot silently withhold a record that actually exists.
		if *discover {
			crossCheck(*rpc, *deployments, *namespaceFlag, q, resp)
		}
		return
	}

	fmt.Printf("owner:     %s\n", resp.Owner)
	fmt.Printf("record:    %s\n", formatRecord(resp.Record))

	// 2. Independently verify the owner's record signature.
	if err := verifyOwnerSig(q.Name, resp); err != nil {
		fmt.Printf("owner sig: INVALID — %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("owner sig: OK (recovered to on-chain pubKey + owner address)\n")

	// 3. In discover mode, cross-check the resolver's answer against the
	//    authoritative on-chain record so the owner-sig and ZK checks are
	//    anchored to chain state, not to resolver-supplied data.
	if *discover {
		crossCheck(*rpc, *deployments, *namespaceFlag, q, resp)
	}

	// 4. Independently verify the ZK record-commitment proof, if present.
	if resp.ZKProof == "" {
		fmt.Printf("zk proof:  none (record carries no commitment)\n")
		return
	}
	if err := verifyZK(resp); err != nil {
		fmt.Printf("zk proof:  INVALID — %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("zk proof:  OK (Groth16 commitment proof verifies)\n")
}

// discoverResolver reads the on-chain ResolverRegistry and returns the first
// active resolver's endpoint and advertised ed25519 key (HLD open issue 7).
func discoverResolver(rpc, deployments, registryFlag string) (endpoint, pubKey string) {
	rr := resolverRegistryAddr(deployments, registryFlag)
	if rr == (common.Address{}) {
		fatal(errors.New("--discover needs the ResolverRegistry address: set --resolver-registry, --deployments, or RESOLVER_REGISTRY_ADDRESS"))
	}
	eth, err := ethclient.DialContext(context.Background(), rpc)
	fatal(err)
	defer eth.Close()
	rc, err := bindings.NewResolverRegistry(rr, eth)
	fatal(err)
	out, err := rc.ActiveResolvers(&bind.CallOpts{Context: context.Background()})
	fatal(err)
	if len(out.Operators) == 0 {
		fatal(errors.New("no resolvers announced in the registry yet"))
	}
	return out.Endpoints[0], hexutil.Encode(out.PubKeys[0][:])
}

// resolverRegistryAddr resolves the ResolverRegistry address from a flag, the
// deploy artifact, or RESOLVER_REGISTRY_ADDRESS.
func resolverRegistryAddr(deployments, flagVal string) common.Address {
	if flagVal != "" {
		return common.HexToAddress(flagVal)
	}
	if deployments != "" {
		if data, err := os.ReadFile(deployments); err == nil {
			var d struct {
				Contracts struct{ ResolverRegistry string } `json:"contracts"`
			}
			if json.Unmarshal(data, &d) == nil && d.Contracts.ResolverRegistry != "" {
				return common.HexToAddress(d.Contracts.ResolverRegistry)
			}
		}
	}
	if v := os.Getenv("RESOLVER_REGISTRY_ADDRESS"); v != "" {
		return common.HexToAddress(v)
	}
	return common.Address{}
}

// recordFromResponse rebuilds the chain.Record the resolver described, decoding
// the owner signature and (when present) the ZK commitment. The generation is
// carried through so it is bound into the canonical message exactly as it was
// signed.
func recordFromResponse(resp resolveResponse) (chain.Record, error) {
	sig, err := hexutil.Decode(resp.Record.OwnerSig)
	if err != nil {
		return chain.Record{}, fmt.Errorf("bad ownerSig encoding: %w", err)
	}
	rec := chain.Record{
		Type:       resp.Record.Type,
		Selector:   resp.Record.Selector,
		FieldNames: resp.Record.FieldNames,
		FieldVals:  resp.Record.FieldValues,
		TTL:        resp.Record.TTL,
		Generation: resp.Record.Generation,
		OwnerSig:   sig,
	}
	if resp.Record.Commitment != "" {
		cb, err := hexutil.Decode(resp.Record.Commitment)
		if err != nil || len(cb) != 32 {
			return chain.Record{}, errors.New("bad commitment encoding")
		}
		copy(rec.Commitment[:], cb)
	}
	return rec, nil
}

func verifyOwnerSig(name string, resp resolveResponse) error {
	pubKey, err := hexutil.Decode(resp.PubKey)
	if err != nil {
		return fmt.Errorf("bad pubKey encoding: %w", err)
	}
	rec, err := recordFromResponse(resp)
	if err != nil {
		return err
	}
	return pki.VerifyOwnerSig(name, rec, common.HexToAddress(resp.Owner), pubKey)
}

// crossCheck (discover mode) verifies the resolver's answer against the
// authoritative on-chain record and prints the verdict; it exits non-zero on
// any mismatch so a lying or record-withholding resolver fails closed.
func crossCheck(rpc, deployments, nsFlag string, q query.Query, resp resolveResponse) {
	if err := compareOnChain(rpc, deployments, nsFlag, q, resp); err != nil {
		fmt.Printf("on-chain:  MISMATCH — %v\n", err)
		os.Exit(1)
	}
	if resp.Found {
		fmt.Printf("on-chain:  OK (resolver answer matches NamespaceDApp.resolve)\n")
	} else {
		fmt.Printf("on-chain:  OK (NamespaceDApp.resolve also returns no record)\n")
	}
}

// compareOnChain reads NamespaceDApp.resolve directly and asserts the resolver
// echoed on-chain truth. For a positive answer every field the owner signature
// and ZK commitment depend on — owner, pubKey, commitment, ownerSig and the
// canonical record body — must match; for a "no match" the chain must also
// hold no live record.
func compareOnChain(rpc, deployments, nsFlag string, q query.Query, resp resolveResponse) error {
	ns := namespaceAddr(deployments, nsFlag)
	if ns == (common.Address{}) {
		return errors.New("set --namespace, --deployments, or CONTRACT_ADDRESS to enable the on-chain cross-check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := chain.Dial(ctx, rpc, ns, common.Address{}, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	defer c.Close()
	onchain, err := c.Resolve(ctx, q.Name, q.Type, q.Selector)
	if err != nil {
		return err
	}
	return diffAgainstChain(onchain, q, resp)
}

// diffAgainstChain is the pure comparison between the authoritative on-chain
// record and the resolver's answer (split from the RPC dial so it is
// unit-testable). For a positive answer every field the owner signature and ZK
// commitment depend on — owner, pubKey, commitment, ownerSig and the canonical
// record body — must match on-chain state; for a "no match" the chain must also
// hold no live record (otherwise the resolver is withholding one).
func diffAgainstChain(onchain *chain.ResolveResult, q query.Query, resp resolveResponse) error {
	if !resp.Found {
		if onchain.Record.Exists {
			return fmt.Errorf("resolver returned NO MATCH but NamespaceDApp holds a live %s record", q.Type)
		}
		return nil
	}
	if !onchain.Record.Exists {
		return errors.New("resolver returned a record that does not exist on-chain")
	}

	respRec, err := recordFromResponse(resp)
	if err != nil {
		return err
	}
	if onchain.Owner != common.HexToAddress(resp.Owner) {
		return fmt.Errorf("owner mismatch: chain=%s resolver=%s", onchain.Owner.Hex(), resp.Owner)
	}
	respPub, err := hexutil.Decode(resp.PubKey)
	if err != nil {
		return fmt.Errorf("bad pubKey encoding: %w", err)
	}
	if !bytes.Equal(onchain.PubKey, respPub) {
		return errors.New("pubKey mismatch between chain and resolver")
	}
	if onchain.Record.Commitment != respRec.Commitment {
		return errors.New("commitment mismatch: the ZK proof was checked against a commitment that is not on-chain")
	}
	if !bytes.Equal(onchain.Record.OwnerSig, respRec.OwnerSig) {
		return errors.New("ownerSig mismatch between chain and resolver")
	}
	// type, selector, ttl, generation and the field set in one comparison.
	if !bytes.Equal(pki.RecordMessage(q.Name, onchain.Record), pki.RecordMessage(q.Name, respRec)) {
		return errors.New("record body mismatch between chain and resolver")
	}
	return nil
}

// namespaceAddr resolves the NamespaceDApp address from a flag, the deploy
// artifact, or CONTRACT_ADDRESS.
func namespaceAddr(deployments, flagVal string) common.Address {
	if flagVal != "" {
		return common.HexToAddress(flagVal)
	}
	if deployments != "" {
		if data, err := os.ReadFile(deployments); err == nil {
			var d struct {
				Contracts struct{ NamespaceDApp string } `json:"contracts"`
			}
			if json.Unmarshal(data, &d) == nil && d.Contracts.NamespaceDApp != "" {
				return common.HexToAddress(d.Contracts.NamespaceDApp)
			}
		}
	}
	if v := os.Getenv("CONTRACT_ADDRESS"); v != "" {
		return common.HexToAddress(v)
	}
	return common.Address{}
}

func verifyZK(resp resolveResponse) error {
	commitBytes, err := hexutil.Decode(resp.Record.Commitment)
	if err != nil || len(commitBytes) != 32 {
		return fmt.Errorf("bad commitment encoding")
	}
	var commitment [32]byte
	copy(commitment[:], commitBytes)
	calldata, err := hexutil.Decode(resp.ZKProof)
	if err != nil {
		return fmt.Errorf("bad zkProof encoding: %w", err)
	}
	proof, err := zk.ProofFromSolidityCalldata(calldata)
	if err != nil {
		return err
	}
	return zk.Verify(proof, commitment)
}

func formatRecord(r *recordJSON) string {
	out := r.Type
	if r.Selector != "" {
		out += " [" + r.Selector + "]"
	}
	for i, n := range r.FieldNames {
		v := ""
		if i < len(r.FieldValues) {
			v = r.FieldValues[i]
		}
		out += fmt.Sprintf(" %s=%s", n, v)
	}
	return fmt.Sprintf("%s (ttl=%ds)", out, r.TTL)
}

func bracket(sel string) string {
	if sel == "" {
		return ""
	}
	return " [" + sel + "]"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// reorder moves flags ahead of positional args so flags may appear anywhere on
// the command line (Go's flag package otherwise stops at the first positional).
// Named bool flags take no value; everything else consumes the next token.
func reorder(args []string, boolFlags ...string) []string {
	bset := map[string]bool{}
	for _, b := range boolFlags {
		bset[b] = true
	}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]
			if !strings.Contains(a, "=") && !bset[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ddns-lookup:", err)
		os.Exit(1)
	}
}
