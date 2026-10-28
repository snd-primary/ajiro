package collector

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"

	"github.com/snd-primary/ajiro/internal/webpot"
)

// Reasons are fixed strings so that nothing from the input reaches our logs.
var (
	errMalformed = errors.New("malformed json or unknown field")
	errTrailing  = errors.New("trailing data after event")
	errID        = errors.New("bad id")
	errTime      = errors.New("missing ts")
	errSensor    = errors.New("unknown sensor")
	errEventType = errors.New("unknown event_type")
	errShape     = errors.New("fields do not match event_type")
	errSrcIP     = errors.New("bad src_ip")
	errPort      = errors.New("bad port")
	errHTTP      = errors.New("bad http")
	errRaw       = errors.New("bad raw")
	errDropped   = errors.New("bad dropped")
)

// parseEvent decodes exactly one webpot event from line and checks it against
// what webpot can actually produce. Unknown fields are rejected.
func parseEvent(line []byte) (*webpot.Event, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var ev webpot.Event
	if err := dec.Decode(&ev); err != nil {
		return nil, errMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errTrailing
	}
	if err := validate(&ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

func validate(ev *webpot.Event) error {
	if !isUUID(ev.ID) {
		return errID
	}
	if ev.Time.IsZero() {
		return errTime
	}
	if ev.Sensor != "web" {
		return errSensor
	}
	if !validPort(ev.SrcPort) || !validPort(ev.DstPort) {
		return errPort
	}

	switch ev.EventType {
	case webpot.EventHTTPRequest:
		if ev.HTTP == nil || ev.Dropped != nil {
			return errShape
		}
		if err := validateHTTP(ev.HTTP); err != nil {
			return err
		}
	case webpot.EventConnNoRequest:
		if ev.HTTP != nil || ev.Dropped != nil || ev.Raw == nil {
			return errShape
		}
	case webpot.EventRateLimited:
		if ev.Dropped == nil || ev.HTTP != nil || ev.Raw != nil {
			return errShape
		}
		if ev.Dropped.Count < 1 || ev.Dropped.Since.IsZero() {
			return errDropped
		}
	default:
		return errEventType
	}

	// webpot reports "_overflow" when its rate-limit table is full.
	overflow := ev.EventType == webpot.EventRateLimited && ev.SrcIP == "_overflow"
	if _, err := netip.ParseAddr(ev.SrcIP); err != nil && !overflow {
		return errSrcIP
	}

	if ev.Raw != nil {
		if err := validateRaw(ev.Raw); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTP(h *webpot.HTTPInfo) error {
	if h.Method == "" || h.Status < 100 || h.Status > 599 || h.BodyLen < 0 {
		return errHTTP
	}
	if h.BodySHA256 != "" && !isHex(h.BodySHA256, 64) {
		return errHTTP
	}
	return nil
}

func validateRaw(r *webpot.RawCapture) error {
	b, err := base64.StdEncoding.DecodeString(r.B64)
	if err != nil || len(b) != r.Len || int64(r.Len) > r.Total {
		return errRaw
	}
	return nil
}

func validPort(p int) bool { return p >= 0 && p <= 65535 }

// isUUID accepts the 8-4-4-4-12 lowercase hex form that webpot emits.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexByte(s[i]) {
				return false
			}
		}
	}
	return true
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isHexByte(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' }
