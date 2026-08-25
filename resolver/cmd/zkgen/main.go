// zkgen performs the dev Groth16 setup for the record-commitment circuit:
// compiles the circuit, runs groth16.Setup (single-party — NOT a
// production trusted setup), writes the artifacts embedded by the
// resolver, exports the Solidity verifier into contracts/, and emits a
// proof fixture for the hardhat on-chain verification test.
//
// Run from repo root: make zk-setup
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/zk"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	resolverDir, err := moduleRoot()
	if err != nil {
		return err
	}
	repoRoot := filepath.Dir(resolverDir)
	artifactsDir := filepath.Join(resolverDir, "internal", "zk", "artifacts")
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		return err
	}

	fmt.Println("compiling record-commitment circuit…")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &zk.RecordCommitmentCircuit{})
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("constraints: %d\n", ccs.GetNbConstraints())

	fmt.Println("running Groth16 setup (dev ceremony)…")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	write := func(name string, wt io.WriterTo) error {
		var buf bytes.Buffer
		if _, err := wt.WriteTo(&buf); err != nil {
			return err
		}
		path := filepath.Join(artifactsDir, name)
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, buf.Len())
		return nil
	}
	if err := write("record_v1.ccs", ccs); err != nil {
		return err
	}
	if err := write("record_v1.pk", pk); err != nil {
		return err
	}
	if err := write("record_v1.vk", vk); err != nil {
		return err
	}

	// Solidity verifier
	var sol bytes.Buffer
	if err := vk.ExportSolidity(&sol); err != nil {
		return fmt.Errorf("export solidity: %w", err)
	}
	verifierPath := filepath.Join(repoRoot, "contracts", "contracts", "ZKVerifier.sol")
	if err := os.WriteFile(verifierPath, sol.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", verifierPath)

	// Proof fixture for the hardhat test: the seeded A record.
	rec := chain.Record{
		Type: "A", Selector: "", TTL: 3600,
		FieldNames: []string{"address"}, FieldVals: []string{"93.184.216.34"},
	}
	msg := pki.RecordMessage("example", rec)
	commitment, err := zk.Commitment(msg)
	if err != nil {
		return err
	}
	assignProof := func() ([]byte, error) {
		w, err := frontend.NewWitness(mustAssign(msg), ecc.BN254.ScalarField())
		if err != nil {
			return nil, err
		}
		proof, err := groth16.Prove(ccs, pk, w)
		if err != nil {
			return nil, err
		}
		pubW, _ := w.Public()
		if err := groth16.Verify(proof, vk, pubW); err != nil {
			return nil, fmt.Errorf("self-check verify: %w", err)
		}
		return zk.SolidityCalldata(proof)
	}
	calldata, err := assignProof()
	if err != nil {
		return err
	}
	fixture := map[string]string{
		"payloadHex":    "0x" + hex.EncodeToString(msg),
		"commitment":    "0x" + hex.EncodeToString(commitment[:]),
		"commitmentDec": new(big.Int).SetBytes(commitment[:]).String(),
		"proofCalldata": "0x" + hex.EncodeToString(calldata),
	}
	fixDir := filepath.Join(repoRoot, "contracts", "test", "fixtures")
	if err := os.MkdirAll(fixDir, 0o755); err != nil {
		return err
	}
	fixBytes, _ := json.MarshalIndent(fixture, "", "  ")
	fixPath := filepath.Join(fixDir, "zkproof.json")
	if err := os.WriteFile(fixPath, append(fixBytes, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", fixPath)
	return nil
}

// mustAssign rebuilds the witness assignment (zkgen cannot use the
// embedded artifacts, which it is in the middle of generating).
func mustAssign(msg []byte) *zk.RecordCommitmentCircuit {
	elements, err := zk.PackMessage(msg)
	if err != nil {
		log.Fatal(err)
	}
	commitment, err := zk.Commitment(msg)
	if err != nil {
		log.Fatal(err)
	}
	var c zk.RecordCommitmentCircuit
	c.Length = elements[0]
	for i := 0; i < zk.MaxChunks; i++ {
		c.Chunks[i] = elements[i+1]
	}
	c.Commitment = new(big.Int).SetBytes(commitment[:])
	return &c
}

// moduleRoot locates the resolver module directory from cwd.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
	}
}
