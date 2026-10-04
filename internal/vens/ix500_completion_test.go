package vens

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Synthetic peers use the locally observed status fields. Continuation payloads
// exercise command order; they are not recordings of the physical acceptance run.
type ix500Reply struct {
	opcode byte
	body   []byte
}

func ix500Response(n int) []byte {
	b := make([]byte, n)
	binary.BigEndian.PutUint32(b, uint32(n))
	copy(b[4:], "VENS")
	return b
}
func ix500Status(flags uint32) []byte {
	b := ix500Response(72)
	binary.BigEndian.PutUint32(b[40:], flags)
	binary.BigEndian.PutUint32(b[44:], 0x12000)
	return b
}
func ix500Wait(status uint32) []byte {
	b := ix500Response(16)
	binary.BigEndian.PutUint32(b[12:], status)
	return b
}
func ix500Image() []byte {
	b := ix500Response(43)
	binary.BigEndian.PutUint32(b[12:], PageTypeFinal)
	b[42] = 1
	return b
}
func ix500Peer(t *testing.T, replies []ix500Reply) *ScanSession {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(3 * time.Second))
		for _, reply := range replies {
			req, err := readResponse(server)
			if err != nil {
				done <- err
				return
			}
			if len(req) <= 48 || req[48] != reply.opcode {
				done <- fmt.Errorf("command %x, want opcode %x", req, reply.opcode)
				return
			}
			if _, err = server.Write(reply.body); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	t.Cleanup(func() {
		client.Close()
		if err := <-done; err != nil {
			t.Errorf("synthetic peer: %v", err)
		}
	})
	return &ScanSession{dc: &DataChannel{model: ix500Model}, conn: client, sidesPerSheet: 2, physicalSheet: 1, transferSheet: 2}
}
func TestIX500BoundaryContinuesBeforeSense(t *testing.T) {
	for _, flags := range []uint32{0, 0x80, 0x8000, 0x8080} {
		t.Run(fmt.Sprintf("flags_%x", flags), func(t *testing.T) {
			s := ix500Peer(t, []ix500Reply{{0xc2, ix500Status(flags)}, {0xe0, ix500Wait(0)}, {0x28, ix500Image()}, {0x03, buildPcapSenseNoError()}})
			p, err := s.NextPage()
			if err != nil || len(p.JPEG) != 1 {
				t.Fatalf("page=%+v err=%v", p, err)
			}
		})
	}
}
func TestIX500BoundaryGateRejectsUnknownStates(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ScanSession, []byte)
	}{
		{"other_model", func(s *ScanSession, b []byte) { s.dc.model = "other" }},
		{"unacknowledged", func(s *ScanSession, b []byte) { s.transferSheet = 1 }},
		{"mid_sheet", func(s *ScanSession, b []byte) { s.sideIdx = 1 }},
		{"first_sheet", func(s *ScanSession, b []byte) { s.physicalSheet = 0 }},
		{"cover", func(s *ScanSession, b []byte) { binary.BigEndian.PutUint32(b[40:], 0x8020) }},
		{"unknown_flag", func(s *ScanSession, b []byte) { binary.BigEndian.PutUint32(b[40:], 0x180) }},
		{"other_word", func(s *ScanSession, b []byte) { binary.BigEndian.PutUint32(b[44:], 0x22000) }},
		{"multifeed", func(s *ScanSession, b []byte) { binary.BigEndian.PutUint32(b[44:], 0x10155) }},
		{"bad_envelope", func(s *ScanSession, b []byte) { b[4] = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ScanSession{dc: &DataChannel{model: ix500Model}, sidesPerSheet: 2, physicalSheet: 1, transferSheet: 2}
			b := ix500Status(0x80)
			tc.change(s, b)
			if s.ix500Boundary(b) {
				t.Fatal("invalid boundary accepted")
			}
		})
	}
}
func TestIX500CompletionRequiresTerminalSense(t *testing.T) {
	cases := []struct {
		name  string
		wait  uint32
		sense []byte
		eof   bool
	}{
		{"complete", 2, buildPcapSenseScanComplete(), true},
		{"page_ack_is_not_completion", 2, buildPcapSenseNoError(), false},
		{"zero_sense", 2, ix500Response(58), false},
		{"unknown_wait", 1, buildPcapSenseScanComplete(), false},
	}
	for _, q := range []byte{ASCQPaperJam, ASCQCoverOpen, ASCQMultiFeed, 0xff} {
		b := buildPcapSenseScanComplete()
		b[53] = q
		cases = append(cases, struct {
			name  string
			wait  uint32
			sense []byte
			eof   bool
		}{fmt.Sprintf("fault_%x", q), 2, b, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ix500Peer(t, []ix500Reply{{0xc2, ix500Status(0x80)}, {0xe0, ix500Wait(tc.wait)}, {0x03, tc.sense}})
			_, err := s.NextPage()
			if err == nil || (err == io.EOF) != tc.eof {
				t.Fatalf("err=%v want EOF=%v", err, tc.eof)
			}
		})
	}
}
func TestIX500MalformedPageAckStopsCapture(t *testing.T) {
	s := ix500Peer(t, []ix500Reply{{0xc2, ix500Status(0x80)}, {0xe0, ix500Wait(0)}, {0x28, ix500Image()}, {0x03, ix500Response(58)}})
	if _, err := s.NextPage(); err == nil || err == io.EOF {
		t.Fatalf("malformed acknowledgement: %v", err)
	}
	if s.transferSheet != 2 || !s.done {
		t.Fatal("unacknowledged side advanced capture")
	}
}
func TestIX500VariableLengthDuplexBatches(t *testing.T) {
	for _, sheets := range []int{1, 2, 3, 6} {
		t.Run(fmt.Sprint(sheets), func(t *testing.T) {
			var replies []ix500Reply
			for sheet := 0; sheet < sheets; sheet++ {
				if sheet > 0 {
					replies = append(replies, ix500Reply{0xc2, ix500Status([]uint32{0x80, 0x8000, 0, 0x8080}[sheet%4])}, ix500Reply{0xe0, ix500Wait(0)})
				}
				for side := 0; side < 2; side++ {
					replies = append(replies, ix500Reply{0x28, ix500Image()}, ix500Reply{0x03, buildPcapSenseNoError()})
				}
			}
			replies = append(replies, ix500Reply{0xc2, ix500Status(0x8080)}, ix500Reply{0xe0, ix500Wait(2)}, ix500Reply{0x03, buildPcapSenseScanComplete()})
			s := ix500Peer(t, replies)
			s.physicalSheet = 0
			s.transferSheet = 0
			for n := 0; n < sheets*2; n++ {
				p, err := s.NextPage()
				if err != nil || p.Sheet != n/2 || p.Side != n%2 {
					t.Fatalf("side %d: %+v %v", n, p, err)
				}
			}
			if _, err := s.NextPage(); err != io.EOF {
				t.Fatalf("terminal: %v", err)
			}
		})
	}
}

func TestIX500UnexpectedStatusDoesNotCompleteOrWait(t *testing.T) {
	for _, flags := range []uint32{0x20, 0x100, 0x8020} {
		t.Run(fmt.Sprintf("flags_%x", flags), func(t *testing.T) {
			s := ix500Peer(t, []ix500Reply{{0xc2, ix500Status(flags)}})
			_, err := s.NextPage()
			if err == nil || err == io.EOF {
				t.Fatalf("unexpected status accepted: %v", err)
			}
		})
	}
}
