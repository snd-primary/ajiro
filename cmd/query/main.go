// Command query runs one SQL query against the collector's DuckDB database,
// opened read-only, and prints the result as tab-separated text. Stop the
// collector first: DuckDB allows no other process while it is writing.
//
// Every value may contain attacker-written bytes, so control characters and
// escape sequences are printed escaped (e.g. \x1b), never raw.
//
//	go run ./cmd/query -db data/ajiro.duckdb "SELECT http_path, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/snd-primary/ajiro/internal/collector"
)

func main() {
	dbPath := flag.String("db", "", "DuckDB database path")
	flag.Parse()
	if *dbPath == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, `usage: query -db PATH "SQL"`)
		os.Exit(2)
	}

	db, err := collector.OpenDBReadOnly(*dbPath)
	if err != nil {
		slog.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.SQL().Query(flag.Arg(0))
	if err != nil {
		slog.Error("query", "err", err)
		os.Exit(1)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		slog.Error("columns", "err", err)
		os.Exit(1)
	}
	fmt.Println(strings.Join(cols, "\t"))
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			slog.Error("scan", "err", err)
			os.Exit(1)
		}
		out := make([]string, len(vals))
		for i, v := range vals {
			out[i] = display(v)
		}
		fmt.Println(strings.Join(out, "\t"))
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows", "err", err)
		os.Exit(1)
	}
}

// display renders a value with every non-printable character escaped. Tabs
// and newlines are escaped too, so one row stays one line.
func display(v any) string {
	if v == nil {
		return "NULL"
	}
	var s string
	switch x := v.(type) {
	case []byte:
		s = string(x)
	case string:
		s = x
	default:
		s = fmt.Sprint(x)
	}
	q := strconv.QuoteToGraphic(s)
	return q[1 : len(q)-1]
}
