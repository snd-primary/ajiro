package guardrail

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/snd-primary/ajiro"

// root is the repository root; go test runs in the package directory.
const root = "../.."

// Packages that run on the honeypot VPS (HANDOFF.md §3). They are assumed to
// be compromised one day, so they get the strictest rules.
var honeypotPkgs = []string{
	module + "/cmd/webpot",
	module + "/internal/webpot",
	module + "/cmd/shipper",
	module + "/internal/shipper",
}

// Imports no package may pull in, even indirectly.
//   - os/exec, plugin: running something received (guardrail 6)
//   - net/http/httputil: home of ReverseProxy, i.e. forwarding (guardrail 2)
var bannedImports = []string{"os/exec", "plugin", "net/http/httputil"}

// Identifiers that open outbound connections or resolve names, as
// "importpath.Name". A trailing "*" matches any name with that prefix.
var outbound = []string{
	"net.Dial*", "net.Dialer", "net.Lookup*", "net.Resolver", "net.DefaultResolver",
	"crypto/tls.Dial*", "crypto/tls.Dialer",
	"net/http.Client", "net/http.Transport", "net/http.DefaultClient", "net/http.DefaultTransport",
	"net/http.Get", "net/http.Head", "net/http.Post", "net/http.PostForm", "net/http.NewRequest*",
	"net/http.ProxyFromEnvironment", "net/http.ProxyURL",
}

// Guardrails 1, 2 and 6: nothing in the module can exec, load plugins or
// reverse-proxy.
func TestNoBannedImports(t *testing.T) {
	for pkg, deps := range depsOf(t, module+"/...") {
		if strings.HasPrefix(pkg, module+"/internal/guardrail") {
			continue
		}
		for _, d := range deps {
			if slices.Contains(bannedImports, d.path) {
				t.Errorf("%s depends on %s", pkg, d.path)
			}
		}
	}
}

// The honeypot binaries use the standard library only. Every third-party
// module would be code running on a host attackers are poking at.
func TestHoneypotIsStdlibOnly(t *testing.T) {
	for _, pkg := range honeypotPkgs {
		for _, d := range depsOf(t, pkg)[pkg] {
			if !d.std && !strings.HasPrefix(d.path, module+"/") {
				t.Errorf("%s depends on non-standard package %s", pkg, d.path)
			}
		}
	}
}

// Guardrail 1: webpot only listens. It never dials, resolves names or builds
// an HTTP client, so a proxy request cannot turn into a forwarded one.
func TestWebpotHasNoOutbound(t *testing.T) {
	for _, dir := range []string{"cmd/webpot", "internal/webpot"} {
		for _, u := range uses(t, dir) {
			if matchAny(u.name, outbound) {
				t.Errorf("%s: %s (webpot must not open outbound connections)", u.pos, u.name)
			}
		}
	}
}

// Guardrail 1: the shipper talks to one IP and nothing else. Name resolution
// and proxies are banned outright; building a dialer or client is allowed
// only in target.go, where NewClient pins it to the collector address.
func TestShipperOutboundIsConfined(t *testing.T) {
	never := []string{
		"net.Lookup*", "net.Resolver", "net.DefaultResolver",
		"net/http.ProxyFromEnvironment", "net/http.ProxyURL",
		"net/http.DefaultClient", "net/http.DefaultTransport",
		"net/http.Get", "net/http.Head", "net/http.Post", "net/http.PostForm",
	}
	onlyInTarget := []string{"net.Dial*", "net.Dialer", "crypto/tls.Dial*", "crypto/tls.Dialer", "net/http.Transport"}
	for _, dir := range []string{"cmd/shipper", "internal/shipper"} {
		for _, u := range uses(t, dir) {
			switch {
			case matchAny(u.name, never):
				t.Errorf("%s: %s (shipper must not resolve names or use proxies)", u.pos, u.name)
			case matchAny(u.name, onlyInTarget) && u.file != "internal/shipper/target.go":
				t.Errorf("%s: %s (dialing belongs in internal/shipper/target.go)", u.pos, u.name)
			}
		}
	}
}

// Guardrail 5: the collector and query tool only answer; they never reach
// out (no probing attackers, no fetching URLs found in the logs).
func TestCollectorHasNoOutbound(t *testing.T) {
	for _, dir := range []string{"cmd/collector", "cmd/query", "internal/collector"} {
		for _, u := range uses(t, dir) {
			if matchAny(u.name, outbound) {
				t.Errorf("%s: %s (collector must not open outbound connections)", u.pos, u.name)
			}
		}
	}
}

// CLAUDE.md: the dashboard never renders attacker strings as HTML or code.
func TestDashboardHasNoRawHTML(t *testing.T) {
	banned := regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|srcdoc|\beval\s*\(|new\s+Function\b`)
	src := filepath.Join(root, "dashboard", "src")
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".ts" && ext != ".tsx" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			if m := banned.FindString(sc.Text()); m != "" {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d: %s", rel, n, m)
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The checker itself: make sure it sees through import aliases, so the
// tests above cannot pass by being blind.
func TestUsesFindsAliasedCalls(t *testing.T) {
	const src = `package x
import (
	n "net"
	"net/http"
)
var _ = http.DefaultClient
func f() { n.Dial("tcp", "1.2.3.4:80") }
`
	got := usesInFile(t, "x.go", src)
	var names []string
	for _, u := range got {
		names = append(names, u.name)
	}
	for _, want := range []string{"net.Dial", "net/http.DefaultClient"} {
		if !slices.Contains(names, want) {
			t.Errorf("missed %s; got %v", want, names)
		}
	}
}

type dep struct {
	path string
	std  bool
}

// depsOf returns, for each package matching pattern, every package it
// depends on (directly or not), excluding tests.
func depsOf(t *testing.T, pattern string) map[string][]dep {
	t.Helper()
	out := map[string][]dep{}
	pkgs := goList(t, "-f", "{{.ImportPath}}", pattern)
	for _, pkg := range pkgs {
		for _, line := range goList(t, "-deps", "-f", "{{.ImportPath}} {{.Standard}}", pkg) {
			path, std, _ := strings.Cut(line, " ")
			if path != pkg {
				out[pkg] = append(out[pkg], dep{path, std == "true"})
			}
		}
	}
	return out
}

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = root
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

type use struct {
	file string // relative to the repository root
	pos  string // file:line
	name string // "importpath.Name"
}

// uses returns every pkg.Name selector in the non-test Go files of dir.
func uses(t *testing.T, dir string) []use {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var all []use
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		all = append(all, usesInFile(t, filepath.ToSlash(rel), string(src))...)
	}
	return all
}

func usesInFile(t *testing.T, name, src string) []use {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	// Map each import's local name to its path. Without an alias the local
	// name is the last path element (true for the standard library).
	imports := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		local := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		imports[local] = path
	}
	var out []use
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if path, ok := imports[id.Name]; ok {
			p := fset.Position(sel.Pos())
			out = append(out, use{
				file: name,
				pos:  name + ":" + strconv.Itoa(p.Line),
				name: path + "." + sel.Sel.Name,
			})
		}
		return true
	})
	return out
}

func matchAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if name == p {
			return true
		}
	}
	return false
}
