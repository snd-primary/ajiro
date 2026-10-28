package shipper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// Target is the only address the shipper ever connects to (HANDOFF.md §4.1:
// egress is limited to the ingest endpoint, by IP, without DNS).
type Target struct {
	URL  *url.URL
	Addr string // canonical ip:port the dialer is pinned to
}

// ParseTarget accepts https://IP[:port]/path, or http:// to a loopback IP for
// local testing. Host names are refused so that no DNS lookup ever happens.
func ParseTarget(raw string) (*Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("shipper: bad url: %w", err)
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("shipper: url must not have userinfo, query or fragment")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.Zone() != "" {
		return nil, errors.New("shipper: host must be an IP address (no DNS)")
	}
	ip = ip.Unmap()

	port := u.Port()
	switch u.Scheme {
	case "https":
		if port == "" {
			port = "443"
		}
	case "http":
		if !ip.IsLoopback() {
			return nil, errors.New("shipper: plain http is only allowed to a loopback address")
		}
		if port == "" {
			port = "80"
		}
	default:
		return nil, errors.New("shipper: scheme must be https")
	}

	addr := net.JoinHostPort(ip.String(), port)
	u.Host = addr
	return &Target{URL: u, Addr: addr}, nil
}

// NewClient returns an HTTP client that can only reach t: it ignores proxy
// environment variables, refuses to dial any other address and does not
// follow redirects. For https, roots must hold the collector's certificate
// (or the CA that issued it); the system roots are never used.
func NewClient(t *Target, roots *x509.CertPool) (*http.Client, error) {
	if t.URL.Scheme == "https" && roots == nil {
		return nil, errors.New("shipper: https needs a pinned certificate")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // never honour HTTP_PROXY and friends
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != t.Addr {
				return nil, fmt.Errorf("shipper: refusing to dial %s", addr)
			}
			return dialer.DialContext(ctx, "tcp", t.Addr)
		},
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          1,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
