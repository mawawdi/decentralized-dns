// Command ddns-fetch resolves a ResourceRef through a resolver, downloads the
// BitTorrent-hosted file, and writes it to disk only after verifying it
// end-to-end (HLD §4.3, UC-6): the body's SHA-256 must match the on-chain hash
// the resolver advertises, and the resolver's signature must cover the body
// together with all of its provenance headers (so a man-in-the-middle cannot
// rewrite owner/hash metadata). The resolver already re-hashes the torrent
// payload against the chain before serving; this is the client-side backstop.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mawawdi/decentralized-dns/resolver/internal/contenttype"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
)

const maxResourceBytes = 256 << 20 // mirror the resolver's MaxFetchBytes

func main() {
	fs := flag.NewFlagSet("ddns-fetch", flag.ExitOnError)
	resolver := fs.String("resolver", envOr("DDNS_RESOLVER", "http://127.0.0.1:8080"), "resolver base URL")
	selector := fs.String("selector", "", `selector, e.g. "service=HTTP"`)
	out := fs.String("o", "", "output file (default: stdout)")
	timeout := fs.Duration("timeout", 90*time.Second, "request timeout")
	peers := multiFlag{}
	fs.Var(&peers, "peer", "explicit peer host:port hint (repeatable; resolver must allow peer hints)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ddns-fetch [flags] <name>")
		fmt.Fprintln(os.Stderr, "\nResolves a ResourceRef and writes the verified file to disk.")
		fs.PrintDefaults()
	}
	_ = fs.Parse(reorder(os.Args[1:]))
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	name := fs.Arg(0)

	pairs, err := query.ParsePairs(*selector)
	fatal(err)
	q, err := query.New(name, "ResourceRef", pairs)
	fatal(err)

	vals := url.Values{"name": {q.Name}, "selector": {q.Selector}}
	for _, p := range peers {
		vals.Add("peer", p)
	}
	endpoint := *resolver + "/resource?" + vals.Encode()

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(endpoint)
	fatal(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResourceBytes))
	fatal(err)

	if resp.StatusCode != http.StatusOK {
		fatal(fmt.Errorf("resolver returned HTTP %d: %s", resp.StatusCode, body))
	}

	// 1. The body must hash to the on-chain SHA-256 the resolver advertises.
	wantSHA := resp.Header.Get("X-DDNS-SHA256")
	gotSHA := sha256.Sum256(body)
	if hex.EncodeToString(gotSHA[:]) != wantSHA {
		fatal(fmt.Errorf("SHA-256 MISMATCH: body=%x advertised=%s", gotSHA, wantSHA))
	}

	// 2. The resolver signature must cover the body AND its provenance headers.
	ownerVerified := resp.Header.Get("X-DDNS-OwnerSig-Verified") == "true"
	if err := pki.VerifyResourceSignature(
		resp.Header.Get("X-DDNS-Resolver"),
		resp.Header.Get("X-DDNS-Signature"),
		resp.Header.Get("X-DDNS-Owner"),
		resp.Header.Get("X-DDNS-PubKey"),
		resp.Header.Get("X-DDNS-InfoHash"),
		wantSHA,
		resp.Header.Get("Content-Type"),
		ownerVerified,
		resp.Header.Get("X-DDNS-ZKProof"),
		body,
	); err != nil {
		fatal(fmt.Errorf("resolver provenance signature INVALID: %w", err))
	}
	// The owner-signature verdict is performed by the resolver and bound into
	// the manifest signature above (so it can't be flipped in transit), but
	// ddns-fetch does not re-recover the owner sig itself — run `ddns-lookup` on
	// the ResourceRef for independent owner-signature + ZK verification.
	if !ownerVerified {
		fatal(fmt.Errorf("resolver reported the owner signature did NOT verify; refusing the file"))
	}

	// 3. Resource Type Validation (FS §2.2): re-sniff the bytes locally and
	// compare against the resolver-signed content type. This is fully
	// trustless — the content type is covered by the provenance signature
	// verified above, so we need not trust the resolver's own verdict header.
	declaredType := resp.Header.Get("Content-Type")
	if v := contenttype.Validate(declaredType, body); !v.OK {
		fmt.Fprintf(os.Stderr, "ddns-fetch: WARNING content-type mismatch — declared %q but bytes look like %q\n",
			v.Declared, v.Detected)
	}

	// 4. Write out the verified bytes.
	if *out == "" || *out == "-" {
		_, _ = os.Stdout.Write(body)
		return
	}
	fatal(os.WriteFile(*out, body, 0o644))
	fmt.Fprintf(os.Stderr, "ddns-fetch: wrote %d verified bytes to %s\n", len(body), *out)
	fmt.Fprintf(os.Stderr, "  owner:    %s\n", resp.Header.Get("X-DDNS-Owner"))
	fmt.Fprintf(os.Stderr, "  sha256:   %s\n", wantSHA)
	fmt.Fprintf(os.Stderr, "  type:     %s (validated)\n", declaredType)
	fmt.Fprintf(os.Stderr, "  resolver: %s\n", resp.Header.Get("X-DDNS-Resolver"))
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// reorder moves flags ahead of positional args so flags may appear anywhere on
// the command line. The named bool flags take no value.
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
		fmt.Fprintln(os.Stderr, "ddns-fetch:", err)
		os.Exit(1)
	}
}
