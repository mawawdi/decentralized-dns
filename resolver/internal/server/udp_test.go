package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/mawawdi/decentralized-dns/resolver/internal/pki"
	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
)

// startUDP boots the server's UDP listener on a random port and returns a
// client socket dialed to it.
func startUDP(t *testing.T, s *Server) net.Conn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn := s.listenUDP(ctx)
	if conn == nil {
		t.Fatal("listenUDP returned nil")
	}
	t.Cleanup(func() { conn.Close() })
	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func roundTrip(t *testing.T, client net.Conn, req []byte) (byte, map[byte][][]byte) {
	t.Helper()
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	status, tlvs, err := decodeUDPResponse(buf[:n])
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return status, tlvs
}

func TestUDPQueryRoundTrip(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)
	client := startUDP(t, s)

	q, err := query.New("example", "A", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, tlvs := roundTrip(t, client, encodeUDPQuery(q))
	if status != udpStatusOK {
		t.Fatalf("status = %d, want OK", status)
	}
	envs := tlvs[udpTLVEnvelope]
	if len(envs) != 1 {
		t.Fatalf("want 1 envelope TLV, got %d", len(envs))
	}
	var env pki.Envelope
	if err := json.Unmarshal(envs[0], &env); err != nil {
		t.Fatal(err)
	}
	if err := pki.VerifyEnvelope(&env); err != nil {
		t.Fatalf("UDP response envelope did not verify: %v", err)
	}
	if env.Resolver != s.identity.PublicKeyHex() {
		t.Fatalf("envelope signed by %s", env.Resolver)
	}
	var body map[string]any
	if err := json.Unmarshal(env.Data, &body); err != nil {
		t.Fatal(err)
	}
	if body["found"] != true {
		t.Fatalf("found = %v", body["found"])
	}
	rec := body["record"].(map[string]any)
	if rec["fieldValues"].([]any)[0] != "93.184.216.34" {
		t.Fatalf("record = %v", rec)
	}
	if body["ownerSigVerified"] != true {
		t.Fatalf("ownerSigVerified = %v", body["ownerSigVerified"])
	}
}

func TestUDPSelectorQuery(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)
	client := startUDP(t, s)

	q, err := query.New("example", "SVC", map[string]string{"service": "http", "transport": "quic", "port": "443"})
	if err != nil {
		t.Fatal(err)
	}
	status, tlvs := roundTrip(t, client, encodeUDPQuery(q))
	if status != udpStatusOK {
		t.Fatalf("status = %d", status)
	}
	var env pki.Envelope
	if err := json.Unmarshal(tlvs[udpTLVEnvelope][0], &env); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(env.Data, &body); err != nil {
		t.Fatal(err)
	}
	if body["found"] != true {
		t.Fatalf("selector query not found: %v", body)
	}
}

func TestUDPMalformedPacketReturnsTypedError(t *testing.T) {
	s := newTestServer(t, seededFake(t), 100, 100)
	client := startUDP(t, s)

	status, tlvs := roundTrip(t, client, []byte("this is not a ddns packet"))
	if status != udpStatusBadQuery {
		t.Fatalf("status = %d, want bad_query", status)
	}
	if len(tlvs[udpTLVError]) != 1 {
		t.Fatalf("expected an error TLV, got %v", tlvs)
	}
	var body errorBody
	if err := json.Unmarshal(tlvs[udpTLVError][0], &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "invalid_query" {
		t.Fatalf("error = %q", body.Error)
	}
}

func TestUDPRateLimited(t *testing.T) {
	s := newTestServer(t, seededFake(t), 1, 1) // 1 rps, burst 1
	client := startUDP(t, s)
	q, _ := query.New("example", "A", nil)

	// First packet is allowed; the immediate second is rate limited.
	if status, _ := roundTrip(t, client, encodeUDPQuery(q)); status != udpStatusOK {
		t.Fatalf("first packet status = %d, want OK", status)
	}
	if status, _ := roundTrip(t, client, encodeUDPQuery(q)); status != udpStatusRateLimited {
		t.Fatalf("second packet status = %d, want rate_limited", status)
	}
}

func TestDecodeUDPQueryRejectsMalformed(t *testing.T) {
	good := encodeUDPQuery(query.Query{Name: "example", Type: "A"})
	cases := map[string][]byte{
		"too short":            {'D', 'D'},
		"bad magic":            append([]byte("XXXX"), good[4:]...),
		"truncated TLV header": append(append([]byte(nil), udpMagic[:]...), udpVersion, 0, udpTLVName, 0),
	}
	// length larger than remaining bytes
	overflow := append(append([]byte(nil), udpMagic[:]...), udpVersion, 0, udpTLVName, 0xff, 0xff)
	cases["TLV length overflow"] = overflow

	for name, pkt := range cases {
		if _, err := decodeUDPQuery(pkt); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}

	// A well-formed packet must still decode.
	if _, err := decodeUDPQuery(good); err != nil {
		t.Errorf("well-formed packet rejected: %v", err)
	}

	// Duplicate name TLV is rejected.
	dup := append([]byte(nil), good...)
	var nameTLV [3]byte
	nameTLV[0] = udpTLVName
	binary.BigEndian.PutUint16(nameTLV[1:], uint16(len("example")))
	dup = append(dup, nameTLV[0], nameTLV[1], nameTLV[2])
	dup = append(dup, []byte("example")...)
	if _, err := decodeUDPQuery(dup); err == nil {
		t.Error("duplicate name TLV accepted")
	}
}
