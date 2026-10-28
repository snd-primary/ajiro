// Command shipper tails webpot's JSON Lines output (-in) and pushes it to the
// collector (-url). The bearer token is read from SHIPPER_TOKEN. -url must be
// an IP address; for https, -ca pins the collector's certificate.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/snd-primary/ajiro/internal/shipper"
)

func main() {
	cfg := shipper.DefaultConfig()
	flag.StringVar(&cfg.Input, "in", "", "webpot JSON Lines file to tail")
	flag.StringVar(&cfg.StatePath, "state", "", "file that records how far -in has been shipped")
	rawURL := flag.String("url", "", "collector ingest URL, e.g. https://203.0.113.10:8443/ingest (IP only)")
	caPath := flag.String("ca", "", "PEM certificate to trust for the collector (required for https)")
	flag.IntVar(&cfg.BatchBytes, "batch-bytes", cfg.BatchBytes, "request body bytes per batch")
	flag.IntVar(&cfg.MaxLine, "max-line", cfg.MaxLine, "input lines longer than this are dropped")
	flag.DurationVar(&cfg.Poll, "poll", cfg.Poll, "how often to check -in for new lines")
	flag.Parse()

	cfg.Token = os.Getenv("SHIPPER_TOKEN")
	if cfg.Token == "" {
		slog.Error("SHIPPER_TOKEN is not set")
		os.Exit(1)
	}

	target, err := shipper.ParseTarget(*rawURL)
	if err != nil {
		slog.Error("url", "err", err)
		os.Exit(1)
	}
	var roots *x509.CertPool
	if *caPath != "" {
		pem, err := os.ReadFile(*caPath)
		if err != nil {
			slog.Error("read ca", "err", err)
			os.Exit(1)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			slog.Error("no certificate found in -ca")
			os.Exit(1)
		}
	}
	client, err := shipper.NewClient(target, roots)
	if err != nil {
		slog.Error("client", "err", err)
		os.Exit(1)
	}

	s, err := shipper.New(cfg, target, client)
	if err != nil {
		slog.Error("shipper", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("shipping", "in", cfg.Input, "to", target.Addr)
	if err := s.Run(ctx); err != nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
