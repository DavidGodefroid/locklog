package mcptools

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/product"
)

// The recipes of docs/recipes (#37) name what the code has: every
// locklog_* tool exists, the ids are the image's, the socket volume is lox
// run's (never a fixed one), and no removed verb is left.
func TestRecipesMatchTheCode(t *testing.T) {
	paths, err := filepath.Glob("../../docs/recipes/*.md")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no recipe: %v", err)
	}
	setup, err := os.ReadFile("../../docs/setup.md")
	if err != nil {
		t.Fatal(err)
	}
	toolRe := regexp.MustCompile(`\blocklog_[a-z_]+\b`)
	idRe := regexp.MustCompile(`\b1005[0-9]\b`)
	ids := []string{strconv.Itoa(product.ClientsGID), strconv.Itoa(product.ConsoleUID), strconv.Itoa(product.AgentUID)}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		doc := strings.ReplaceAll(string(b), "\r\n", "\n")
		for _, tool := range toolRe.FindAllString(doc, -1) {
			if !slices.Contains(Names(), tool) {
				t.Errorf("%s: no tool %s", p, tool)
			}
		}
		for _, id := range idRe.FindAllString(doc, -1) {
			if !slices.Contains(ids, id) {
				t.Errorf("%s: id %s is none of the image's %v", p, id, ids)
			}
		}
		for _, stale := range []string{"locklog setup", "`locklog console", "\nlocklog console", "locklog-run:", "--agent container"} {
			if strings.Contains(doc, stale) {
				t.Errorf("%s: names %q, gone with hub mode", p, stale)
			}
		}
		if !strings.Contains(doc, "lockfamily-<hash>_") || !strings.Contains(doc, "-run:/run/locklog:ro") {
			t.Errorf("%s: not lox run's socket volume, read-only on /run/locklog", p)
		}
		if strings.Contains(doc, "setup.md#the-own-container-recipe") && !strings.Contains(strings.ReplaceAll(string(setup), "\r\n", "\n"), "\n## The own-container recipe\n") {
			t.Errorf("%s: links a section setup.md does not have", p)
		}
	}
}
