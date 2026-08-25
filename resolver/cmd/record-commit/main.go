// Command record-commit computes the MiMC record commitment (HLD §3.5)
// for a record described as JSON on stdin and prints it as 0x-hex.
//
// It exists so non-Go tooling (contracts/scripts/seed.ts, demos) can anchor
// commitments that exactly match the gnark circuit; the ddns CLI uses
// zk.Commitment directly. Records over zk.MaxPayload print the zero hash
// (no commitment — proofs are not available for oversized payloads).
//
// Input:  {"name","type","selector","ttl","generation","fieldNames","fieldValues"}
// Output: 0x… (32 bytes)
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/zk"
)

type input struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Selector    string   `json:"selector"`
	TTL         uint32   `json:"ttl"`
	Generation  uint64   `json:"generation"`
	FieldNames  []string `json:"fieldNames"`
	FieldValues []string `json:"fieldValues"`
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "record-commit: bad input:", err)
		os.Exit(1)
	}
	if len(in.FieldNames) != len(in.FieldValues) {
		fmt.Fprintln(os.Stderr, "record-commit: fieldNames/fieldValues length mismatch")
		os.Exit(1)
	}
	msg := pki.RecordMessage(in.Name, chain.Record{
		Type:       in.Type,
		Selector:   in.Selector,
		FieldNames: in.FieldNames,
		FieldVals:  in.FieldValues,
		TTL:        in.TTL,
		Generation: in.Generation,
	})
	com, err := zk.Commitment(msg)
	if errors.Is(err, zk.ErrPayloadTooLarge) {
		fmt.Println(hexutil.Encode(make([]byte, 32)))
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "record-commit:", err)
		os.Exit(1)
	}
	fmt.Println(hexutil.Encode(com[:]))
}
