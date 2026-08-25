package pki

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
)

func TestIdentityLoadOrCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "resolver.key")

	id1, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 600", info.Mode().Perm())
	}

	id2, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id1.PublicKey(), id2.PublicKey()) {
		t.Error("reload produced a different identity")
	}

	if err := os.WriteFile(path, []byte("not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateIdentity(path); err == nil {
		t.Error("corrupt keystore should fail to load")
	}
}

func testRecord() chain.Record {
	return chain.Record{
		Type:       "SVC",
		Selector:   "port=25&service=SMTP&transport=TCP",
		FieldNames: []string{"target", "service", "transport", "port"},
		FieldVals:  []string{"mail.example", "SMTP", "TCP", "25"},
		TTL:        300,
		Generation: 7,
		Exists:     true,
	}
}

func TestRecordMessageDeterminism(t *testing.T) {
	r := testRecord()
	m1 := RecordMessage("example", r)

	// field order must not matter (sorted by name)
	r2 := r
	r2.FieldNames = []string{"port", "service", "target", "transport"}
	r2.FieldVals = []string{"25", "SMTP", "mail.example", "TCP"}
	if !bytes.Equal(m1, RecordMessage("example", r2)) {
		t.Error("message depends on field order")
	}

	// any content change must change the message
	r3 := r
	r3.TTL = 301
	if bytes.Equal(m1, RecordMessage("example", r3)) {
		t.Error("ttl change did not alter message")
	}
	if bytes.Equal(m1, RecordMessage("other", r)) {
		t.Error("name change did not alter message")
	}

	// generation is bound: a record signed under a different generation
	// (e.g. after a transfer or expiry re-registration) must not collide.
	r4 := r
	r4.Generation = r.Generation + 1
	if bytes.Equal(m1, RecordMessage("example", r4)) {
		t.Error("generation change did not alter message")
	}
}

func TestOwnerSignVerifyRoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	owner := crypto.PubkeyToAddress(key.PublicKey)
	pubKey := crypto.FromECDSAPub(&key.PublicKey)

	r := testRecord()
	sig, err := SignRecord("example", r, key)
	if err != nil {
		t.Fatal(err)
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Errorf("V byte = %d, want 27/28 (ethers convention)", sig[64])
	}
	r.OwnerSig = sig

	if err := VerifyOwnerSig("example", r, owner, pubKey); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// tampered record content
	bad := r
	bad.FieldVals = []string{"evil.example", "SMTP", "TCP", "25"}
	if err := VerifyOwnerSig("example", bad, owner, pubKey); err == nil {
		t.Error("tampered record accepted")
	}

	// replay across a generation bump: same record + signature, but the
	// domain has since been transferred/re-registered (generation moved on).
	stale := r
	stale.Generation = r.Generation + 1
	if err := VerifyOwnerSig("example", stale, owner, pubKey); err == nil {
		t.Error("signature replayed across a generation bump was accepted")
	}

	// wrong on-chain pubKey
	otherKey, _ := crypto.GenerateKey()
	if err := VerifyOwnerSig("example", r, owner, crypto.FromECDSAPub(&otherKey.PublicKey)); err == nil {
		t.Error("mismatched pubKey accepted")
	}

	// wrong owner address
	if err := VerifyOwnerSig("example", r, crypto.PubkeyToAddress(otherKey.PublicKey), pubKey); err == nil {
		t.Error("mismatched owner accepted")
	}

	// malformed signature length
	short := r
	short.OwnerSig = sig[:64]
	if err := VerifyOwnerSig("example", short, owner, pubKey); err == nil {
		t.Error("short signature accepted")
	}

	// mismatched field arrays (malformed chain data) must error, not panic
	mismatch := r
	mismatch.FieldNames = []string{"target", "service", "transport", "port"}
	mismatch.FieldVals = []string{"mail.example"}
	if err := VerifyOwnerSig("example", mismatch, owner, pubKey); err == nil {
		t.Error("field-array length mismatch accepted")
	}
}

func TestEnvelopeSealVerify(t *testing.T) {
	id, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := id.SealEnvelope(map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(env); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	tampered := *env
	tampered.Data = []byte(`{"hello":"evil"}`)
	if err := VerifyEnvelope(&tampered); err == nil {
		t.Error("tampered envelope accepted")
	}

	badKey := *env
	badKey.Resolver = "0x1234"
	if err := VerifyEnvelope(&badKey); err == nil {
		t.Error("bad resolver key accepted")
	}
}
