package zk

import (
	"bytes"
	"testing"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
)

func testMessage() []byte {
	return pki.RecordMessage("example", chain.Record{
		Type: "A", Selector: "", TTL: 3600,
		FieldNames: []string{"address"}, FieldVals: []string{"93.184.216.34"},
	})
}

func TestPackMessage(t *testing.T) {
	msg := testMessage()
	elements, err := PackMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(elements) != 1+MaxChunks {
		t.Fatalf("len = %d", len(elements))
	}
	if elements[0].Int64() != int64(len(msg)) {
		t.Errorf("length element = %v", elements[0])
	}
	if _, err := PackMessage(make([]byte, MaxPayload+1)); err == nil {
		t.Error("oversized payload accepted")
	}
	if _, err := PackMessage(make([]byte, MaxPayload)); err != nil {
		t.Errorf("max payload rejected: %v", err)
	}
}

func TestCommitmentDeterminismAndBinding(t *testing.T) {
	msg := testMessage()
	c1, err := Commitment(msg)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := Commitment(msg)
	if c1 != c2 {
		t.Error("commitment not deterministic")
	}

	altered := append([]byte(nil), msg...)
	altered[len(altered)-1] ^= 1
	c3, _ := Commitment(altered)
	if c1 == c3 {
		t.Error("payload change did not change commitment")
	}

	// zero-padding must not collide thanks to the length element
	padded := append([]byte(nil), msg...)
	padded = append(padded, 0)
	c4, _ := Commitment(padded)
	if c1 == c4 {
		t.Error("length binding failed: padded message collides")
	}
}

func TestProveVerifyRoundTrip(t *testing.T) {
	if err := loadArtifacts(); err != nil {
		t.Skipf("zk artifacts not generated yet: %v", err)
	}
	msg := testMessage()
	proof, err := Prove(msg)
	if err != nil {
		t.Fatal(err)
	}
	commitment, _ := Commitment(msg)
	if err := Verify(proof, commitment); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	// wrong public input must fail
	var wrong [32]byte
	wrong[31] = 1
	if err := Verify(proof, wrong); err == nil {
		t.Error("proof verified against wrong commitment")
	}

	// Solidity calldata round-trip
	calldata, err := SolidityCalldata(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(calldata) != 256 {
		t.Fatalf("calldata = %d bytes, want 256", len(calldata))
	}
	back, err := ProofFromSolidityCalldata(calldata)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(back, commitment); err != nil {
		t.Fatalf("round-tripped proof rejected: %v", err)
	}
	back2, _ := SolidityCalldata(back)
	if !bytes.Equal(calldata, back2) {
		t.Error("calldata round-trip not byte-identical")
	}
}
