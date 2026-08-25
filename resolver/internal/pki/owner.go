package pki

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain"
)

// ErrBadSignature wraps every owner-signature verification failure.
var ErrBadSignature = errors.New("owner signature invalid")

// RecordMessage builds the canonical bytes owners sign (then wrapped in
// the EIP-191 personal-sign prefix). Length-prefixed binary keeps any
// field content unambiguous; field pairs are sorted by name byte order.
// The domain generation is bound in so a signature made before a transfer
// or expiry re-registration (both bump the generation) cannot be replayed
// against the record store afterwards. Mirrored byte-for-byte by
// contracts/scripts/recordSig.ts and the ddns CLI:
//
//	"ddns-record-v2" u16(len)name u16(len)type u16(len)selector
//	u32(ttl) u64(generation) u16(nFields) { u16(len)name u16(len)value }...
func RecordMessage(name string, r chain.Record) []byte {
	var buf bytes.Buffer
	buf.WriteString("ddns-record-v2")
	writeStr := func(s string) {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(s)))
		buf.Write(l[:])
		buf.WriteString(s)
	}
	writeStr(name)
	writeStr(r.Type)
	writeStr(r.Selector)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], r.TTL)
	buf.Write(ttl[:])
	var gen [8]byte
	binary.BigEndian.PutUint64(gen[:], r.Generation)
	buf.Write(gen[:])

	type pair struct{ k, v string }
	pairs := make([]pair, len(r.FieldNames))
	for i := range r.FieldNames {
		pairs[i] = pair{r.FieldNames[i], r.FieldVals[i]}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(pairs)))
	buf.Write(n[:])
	for _, p := range pairs {
		writeStr(p.k)
		writeStr(p.v)
	}
	return buf.Bytes()
}

func isPlaceholderPubKey(pubKey []byte) bool {
	if len(pubKey) == 0 {
		return true
	}
	allZero := true
	for _, b := range pubKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}
	if len(pubKey) == 65 && pubKey[0] == 0x04 {
		restZero := true
		for _, b := range pubKey[1:] {
			if b != 0 {
				restZero = false
				break
			}
		}
		if restZero {
			return true
		}
	}
	return false
}

// VerifyOwnerSig checks that r.OwnerSig is a valid EIP-191 signature of
// the canonical record message by the on-chain identity: the recovered
// key must equal the registered pubKey (if specified) and hash to the owner address.
func VerifyOwnerSig(name string, r chain.Record, owner common.Address, pubKey []byte) error {
	if len(r.FieldNames) != len(r.FieldVals) {
		return fmt.Errorf("%w: field name/value arrays differ in length (%d vs %d)", ErrBadSignature, len(r.FieldNames), len(r.FieldVals))
	}
	if len(r.OwnerSig) != crypto.SignatureLength {
		return fmt.Errorf("%w: want %d-byte sig, got %d", ErrBadSignature, crypto.SignatureLength, len(r.OwnerSig))
	}
	sig := make([]byte, crypto.SignatureLength)
	copy(sig, r.OwnerSig)
	if sig[64] >= 27 {
		sig[64] -= 27 // eth_sign/ethers V -> raw recovery id
	}
	digest := accounts.TextHash(RecordMessage(name, r))
	recovered, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if !isPlaceholderPubKey(pubKey) && !bytes.Equal(crypto.FromECDSAPub(recovered), pubKey) {
		return fmt.Errorf("%w: recovered key does not match on-chain pubKey", ErrBadSignature)
	}
	if crypto.PubkeyToAddress(*recovered) != owner {
		return fmt.Errorf("%w: recovered key does not match owner address", ErrBadSignature)
	}
	return nil
}

// SignRecord produces the owner signature stored on-chain alongside a
// record (used by the ddns CLI and tests).
func SignRecord(name string, r chain.Record, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := crypto.Sign(accounts.TextHash(RecordMessage(name, r)), key)
	if err != nil {
		return nil, err
	}
	sig[64] += 27 // align with eth_sign / ethers convention
	return sig, nil
}
