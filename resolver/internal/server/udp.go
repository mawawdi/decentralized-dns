package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/mawawdi/decentralized-dns/resolver/internal/query"
)

const (
	udpVersion     = 1
	udpMaxPacket   = 8192  // request read buffer (queries are tiny)
	udpMaxResp     = 65000 // responses larger than this fall back to REST
	udpMaxInFlight = 256   // bound concurrent query handlers

	udpTLVName     = 1
	udpTLVType     = 2
	udpTLVSelector = 3
	udpTLVEnvelope = 100
	udpTLVError    = 101

	udpStatusOK          = 0
	udpStatusBadQuery    = 1
	udpStatusChain       = 2
	udpStatusInternal    = 3
	udpStatusRateLimited = 4
	udpStatusTooLarge    = 5
)

var udpMagic = [4]byte{'D', 'D', 'N', 'S'}

type udpTLV struct {
	typ byte
	val []byte
}

func (s *Server) listenUDP(ctx context.Context) net.PacketConn {
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", s.cfg.UDPPort))
	if err != nil {
		s.log.Warn("UDP listener disabled", "port", s.cfg.UDPPort, "err", err)
		return nil
	}
	s.log.Info("UDP listening", "port", s.cfg.UDPPort)
	go s.serveUDP(ctx, conn)
	return conn
}

func (s *Server) serveUDP(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, udpMaxPacket)
	sem := make(chan struct{}, udpMaxInFlight) // bound concurrent handlers
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("UDP read", "err", err)
			continue
		}
		// Apply the same per-IP rate limit as the REST front end so a UDP flood
		// cannot spawn unbounded chain-calling goroutines.
		if s.limiter != nil && !s.limiter.allow(udpHost(addr)) {
			_, _ = conn.WriteTo(encodeUDPError(udpStatusRateLimited, "rate_limited", "too many requests from this address"), addr)
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default: // at capacity — shed load instead of growing without bound
			_, _ = conn.WriteTo(encodeUDPError(udpStatusInternal, "busy", "resolver is busy, retry shortly"), addr)
			continue
		}
		go func() {
			defer func() { <-sem }()
			queryCtx, cancel := context.WithTimeout(ctx, chainCallTimeout)
			defer cancel()
			resp := s.handleUDPPacket(queryCtx, packet)
			if _, err := conn.WriteTo(resp, addr); err != nil && ctx.Err() == nil {
				s.log.Warn("UDP write", "err", err)
			}
		}()
	}
}

// udpHost extracts the host part of a UDP source address for rate limiting.
func udpHost(addr net.Addr) string {
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

func (s *Server) handleUDPPacket(ctx context.Context, packet []byte) []byte {
	q, err := decodeUDPQuery(packet)
	if err != nil {
		return encodeUDPError(udpStatusBadQuery, "invalid_query", err.Error())
	}
	resp, err := s.resolveResponse(ctx, q)
	if err != nil {
		return encodeUDPError(udpStatusChain, "chain_error", err.Error())
	}
	env, err := s.identity.SealEnvelope(resp)
	if err != nil {
		return encodeUDPError(udpStatusInternal, "sign_error", err.Error())
	}
	data, err := json.Marshal(env)
	if err != nil {
		return encodeUDPError(udpStatusInternal, "marshal_error", err.Error())
	}
	// A response that would not fit in a single TLV (or a sane datagram) is
	// reported as a typed error so the client falls back to REST, rather than
	// being silently dropped by encodeUDPResponse and read as an empty OK.
	if len(data) > udpMaxResp {
		return encodeUDPError(udpStatusTooLarge, "response_too_large", "response exceeds UDP limit; retry over REST")
	}
	return encodeUDPResponse(udpStatusOK, udpTLV{typ: udpTLVEnvelope, val: data})
}

func decodeUDPQuery(packet []byte) (query.Query, error) {
	if len(packet) < 6 {
		return query.Query{}, fmt.Errorf("packet too short")
	}
	if string(packet[:4]) != string(udpMagic[:]) {
		return query.Query{}, fmt.Errorf("bad magic")
	}
	if packet[4] != udpVersion {
		return query.Query{}, fmt.Errorf("unsupported version %d", packet[4])
	}
	if packet[5] != 0 {
		return query.Query{}, fmt.Errorf("unsupported flags %d", packet[5])
	}
	fields := map[byte]string{}
	for i := 6; i < len(packet); {
		if len(packet)-i < 3 {
			return query.Query{}, fmt.Errorf("truncated TLV header")
		}
		typ := packet[i]
		length := int(binary.BigEndian.Uint16(packet[i+1 : i+3]))
		i += 3
		if length > len(packet)-i {
			return query.Query{}, fmt.Errorf("truncated TLV value")
		}
		if typ == udpTLVName || typ == udpTLVType || typ == udpTLVSelector {
			if _, dup := fields[typ]; dup {
				return query.Query{}, fmt.Errorf("duplicate TLV %d", typ)
			}
			fields[typ] = string(packet[i : i+length])
		}
		i += length
	}
	pairs, err := query.ParsePairs(fields[udpTLVSelector])
	if err != nil {
		return query.Query{}, err
	}
	return query.New(fields[udpTLVName], fields[udpTLVType], pairs)
}

func encodeUDPQuery(q query.Query) []byte {
	return encodeUDPResponse(0,
		udpTLV{typ: udpTLVName, val: []byte(q.Name)},
		udpTLV{typ: udpTLVType, val: []byte(q.Type)},
		udpTLV{typ: udpTLVSelector, val: []byte(q.Selector)},
	)
}

func encodeUDPError(status byte, code, msg string) []byte {
	data, _ := json.Marshal(errorBody{Error: code, Message: msg})
	return encodeUDPResponse(status, udpTLV{typ: udpTLVError, val: data})
}

func encodeUDPResponse(status byte, tlvs ...udpTLV) []byte {
	out := make([]byte, 0, 6)
	out = append(out, udpMagic[:]...)
	out = append(out, udpVersion, status)
	for _, tlv := range tlvs {
		if len(tlv.val) > 0xffff {
			continue
		}
		out = append(out, tlv.typ, 0, 0)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(tlv.val)))
		out = append(out, tlv.val...)
	}
	return out
}

func decodeUDPResponse(packet []byte) (byte, map[byte][][]byte, error) {
	if len(packet) < 6 {
		return 0, nil, fmt.Errorf("packet too short")
	}
	if string(packet[:4]) != string(udpMagic[:]) {
		return 0, nil, fmt.Errorf("bad magic")
	}
	if packet[4] != udpVersion {
		return 0, nil, fmt.Errorf("unsupported version %d", packet[4])
	}
	status := packet[5]
	values := map[byte][][]byte{}
	for i := 6; i < len(packet); {
		if len(packet)-i < 3 {
			return 0, nil, fmt.Errorf("truncated TLV header")
		}
		typ := packet[i]
		length := int(binary.BigEndian.Uint16(packet[i+1 : i+3]))
		i += 3
		if length > len(packet)-i {
			return 0, nil, fmt.Errorf("truncated TLV value")
		}
		values[typ] = append(values[typ], append([]byte(nil), packet[i:i+length]...))
		i += length
	}
	return status, values, nil
}
