package parse

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const parsePkg = "github.com/DavidGodefroid/locklog/internal/parse"

// rawImporters are the only packages allowed to import raw events: the
// sources that produce them, the masker, the local index and the engine.
// Everything else (console, IPC, MCP) sees masked records only.
var rawImporters = []string{"internal/parse", "internal/source", "internal/mask", "internal/index", "internal/engine"}

// importViolations returns the files under root that import internal/parse
// from a package outside rawImporters.
func importViolations(t *testing.T, root string) []string {
	t.Helper()
	var bad []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); p != root && (n == "testdata" || strings.HasPrefix(n, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		rel = filepath.ToSlash(rel)
		for _, imp := range f.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			if ip != parsePkg && !strings.HasPrefix(ip, parsePkg+"/") {
				continue
			}
			if !allowedImporter(rel) {
				bad = append(bad, path.Join(rel, filepath.Base(p)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bad
}

func allowedImporter(dir string) bool {
	for _, a := range rawImporters {
		if dir == a || strings.HasPrefix(dir, a+"/") {
			return true
		}
	}
	return false
}

func TestRawEventsImportedOnlyByRawPackages(t *testing.T) {
	if bad := importViolations(t, filepath.Join("..", "..")); len(bad) > 0 {
		t.Fatalf("raw events imported outside %v: %v", rawImporters, bad)
	}
}

func TestImportLintCatchesPlantedImport(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	imp := "import _ \"" + parsePkg + "\"\n"
	write("internal/engine/ok.go", "package engine\n"+imp)
	write("internal/source/file/ok.go", "package file\n"+imp)
	write("internal/console/bad.go", "package console\n"+imp)
	write("internal/sourcex/bad.go", "package sourcex\n"+imp)
	bad := importViolations(t, root)
	if strings.Join(bad, ",") != "internal/console/bad.go,internal/sourcex/bad.go" {
		t.Fatalf("violations %v", bad)
	}
}
