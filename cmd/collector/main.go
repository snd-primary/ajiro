// Command collector receives event batches from shippers on POST /ingest and
// appends the validated events to -out as JSON Lines and, with -db, to a
// DuckDB database. The bearer token is read from COLLECTOR_TOKEN. Send SIGHUP
// to reopen -out after rotation.
//
// With -query-addr it also serves the read-only query API for the dashboard,
// authenticated by COLLECTOR_QUERY_TOKEN (see collector.QueryAPI).
//
// With -import FILE it instead loads a JSON Lines archive into -db and exits,
// e.g. to rebuild the database.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/snd-primary/ajiro/internal/collector"
)

func main() {
	cfg := collector.DefaultConfig()
	addr := flag.String("addr", "127.0.0.1:9000", "listen address")
	outPath := flag.String("out", "-", `JSON Lines archive path ("-" = stdout)`)
	flag.Int64Var(&cfg.MaxBatch, "max-batch", cfg.MaxBatch, "request body bytes per batch")
	flag.IntVar(&cfg.MaxLine, "max-line", cfg.MaxLine, "bytes per event line")
	tlsCert := flag.String("tls-cert", "", "PEM certificate; with -tls-key, serve https")
	tlsKey := flag.String("tls-key", "", "PEM private key for -tls-cert")
	dbPath := flag.String("db", "", "DuckDB database path (empty = JSON Lines only)")
	importPath := flag.String("import", "", "load this JSON Lines archive into -db and exit")
	queryAddr := flag.String("query-addr", "", "listen address for the read-only query API, e.g. 127.0.0.1:9100 (empty = off; non-loopback requires -tls-cert)")
	flag.Parse()

	var db *collector.DB
	if *dbPath != "" {
		var err error
		if db, err = collector.OpenDB(*dbPath); err != nil {
			slog.Error("open db", "err", err)
			os.Exit(1)
		}
		defer db.Close()
	}
	if *importPath != "" {
		if db == nil {
			slog.Error("-import needs -db")
			os.Exit(1)
		}
		runImport(db, *importPath, cfg.MaxLine)
		return
	}

	if (*tlsCert == "") != (*tlsKey == "") {
		slog.Error("-tls-cert and -tls-key must be given together")
		os.Exit(1)
	}

	// From the environment, not a flag: flags are visible in ps.
	cfg.Token = os.Getenv("COLLECTOR_TOKEN")
	if cfg.Token == "" {
		slog.Error("COLLECTOR_TOKEN is not set")
		os.Exit(1)
	}

	var queryAPI *collector.QueryAPI
	if *queryAddr != "" {
		if db == nil {
			slog.Error("-query-addr needs -db")
			os.Exit(1)
		}
		if !isLoopback(*queryAddr) && *tlsCert == "" {
			slog.Error("-query-addr off loopback needs -tls-cert")
			os.Exit(1)
		}
		// A separate token: the ingest token lives on the honeypot host.
		qtok := os.Getenv("COLLECTOR_QUERY_TOKEN")
		if qtok == "" || qtok == cfg.Token {
			slog.Error("COLLECTOR_QUERY_TOKEN must be set and differ from COLLECTOR_TOKEN")
			os.Exit(1)
		}
		var err error
		if queryAPI, err = collector.NewQueryAPI(db, qtok); err != nil {
			slog.Error("query api", "err", err)
			os.Exit(1)
		}
	}

	store, err := collector.OpenStore(*outPath)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	h, err := collector.NewHandler(cfg, store, db)
	if err != nil {
		slog.Error("handler", "err", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.Handle("/ingest", h)
	servers := []*http.Server{newServer(*addr, mux, 60*time.Second)}
	if queryAPI != nil {
		servers = append(servers, newServer(*queryAddr, queryAPI, 30*time.Second))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := store.Reopen(); err != nil {
				slog.Error("reopen store", "err", err)
			}
		}
	}()

	// Serve until a signal arrives or a server fails, then let in-flight
	// requests finish before the store and database are closed.
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		go func() {
			var err error
			if *tlsCert != "" {
				err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
			} else {
				err = srv.ListenAndServe()
			}
			errs <- err
		}()
	}
	slog.Info("collector listening", "addr", *addr, "query_addr", *queryAddr, "out", *outPath, "db", *dbPath, "tls", *tlsCert != "")

	failed := false
	select {
	case <-ctx.Done():
	case err := <-errs:
		slog.Error("serve", "err", err)
		failed = true
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutCtx)
	}
	if failed {
		os.Exit(1)
	}
}

func newServer(addr string, h http.Handler, timeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		MaxHeaderBytes:    16 << 10,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func runImport(db *collector.DB, path string, maxLine int) {
	f, err := os.Open(path)
	if err != nil {
		slog.Error("open archive", "err", err)
		os.Exit(1)
	}
	defer f.Close()
	n, rejected, err := collector.Import(context.Background(), f, db, maxLine)
	slog.Info("import", "inserted_or_skipped", n, "rejected", rejected)
	if err != nil {
		slog.Error("import", "err", err)
		os.Exit(1)
	}
}
