package vens

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const ix500Model = "FUJITSU ScanSnap iX500"

// The full status word and flag combinations were observed between acknowledged
// sheets on iX500 firmware 0U00. They permit the ordinary WAIT, not an EOF shortcut
// or a general suppression of scanner errors. Idle ADF handling is unchanged.
func (s *ScanSession) ix500Boundary(resp []byte) bool {
	if s.dc.model != ix500Model || len(resp) != 72 ||
		binary.BigEndian.Uint32(resp[:4]) != 72 || string(resp[4:8]) != "VENS" ||
		binary.BigEndian.Uint32(resp[44:48]) != 0x00012000 ||
		s.physicalSheet <= 0 || s.sideIdx != 0 ||
		(s.sidesPerSheet != 1 && s.sidesPerSheet != 2) ||
		s.transferSheet != s.physicalSheet*s.sidesPerSheet {
		return false
	}
	switch binary.BigEndian.Uint32(resp[40:44]) {
	case 0, ADFPaperMask, ADFJamMask, ADFPaperMask | ADFJamMask:
		return true
	default:
		return false
	}
}

func ix500FixedSense(resp []byte) bool {
	return len(resp) == 58 && binary.BigEndian.Uint32(resp[:4]) == 58 &&
		string(resp[4:8]) == "VENS" && resp[40]&0x7f == 0x70 && resp[47] == 0x0a
}

func ix500PageAck(resp []byte) bool {
	return ix500FixedSense(resp) && resp[42] == 0x60 && resp[52] == 0 && resp[53] == 0
}

// A nonzero WAIT is not by itself successful completion. Read SENSE on the
// existing connection, preserving actual jam/cover/multifeed errors.
func (s *ScanSession) ix500Completion(status uint32) error {
	s.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.conn.Write(MarshalGetPageMetadata(s.token)); err != nil {
		return fmt.Errorf("completion sense: %w", err)
	}
	resp, err := readResponse(s.conn)
	if err != nil {
		return fmt.Errorf("completion sense recv: %w", err)
	}
	if fault := parseSenseError(resp); fault != nil {
		return fault
	}
	if status == 2 && ix500FixedSense(resp) && resp[42]&0x0f == SenseKeyMediumError && resp[52] == VendorASC && resp[53] == ASCQScanComplete {
		return io.EOF
	}
	return fmt.Errorf("unconfirmed iX500 scan completion (WAIT=%d)", status)
}
