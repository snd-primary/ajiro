// Command webpot runs the low-interaction HTTP honeypot and writes one JSON
// Lines event per request to -log. Send SIGHUP to reopen the log after
// rotation.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/snd-primary/ajiro/internal/webpot"
)

func main() {
	cfg := webpot.DefaultConfig()
	addr := flag.String("addr", ":8080", "listen address")
	logPath := flag.String("log", "-", `JSON Lines output path ("-" = stdout)`)
	flag.IntVar(&cfg.DstPort, "dst-port", 0, "destination port to record (set when a firewall/NAT redirects to -addr); 0 = listening port")
	flag.Int64Var(&cfg.MaxBody, "max-body", cfg.MaxBody, "request body bytes kept per request")
	flag.IntVar(&cfg.MaxConns, "max-conns", cfg.MaxConns, "max concurrent connections")
	flag.Float64Var(&cfg.RatePerMinute, "rate", cfg.RatePerMinute, "new connections per minute per source (IPv6 per /64)")
	flag.IntVar(&cfg.RateBurst, "burst", cfg.RateBurst, "rate limit burst")
	flag.StringVar(&cfg.ServerHeader, "server-header", cfg.ServerHeader, `Server response header ("" to omit)`)
	flag.StringVar(&cfg.PoweredBy, "powered-by", cfg.PoweredBy, `X-Powered-By response header, e.g. "PHP/8.3.12" ("" to omit)`)
	flag.Parse()

	logger, err := webpot.OpenLogger(*logPath)
	if err != nil {
		slog.Error("open log", "err", err)
		os.Exit(1)
	}
	defer logger.Close()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := logger.Reopen(); err != nil {
				slog.Error("reopen log", "err", err)
			}
		}
	}()

	slog.Info("webpot listening", "addr", ln.Addr().String(), "log", *logPath)
	if err := webpot.New(cfg, logger).Serve(ctx, ln); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
