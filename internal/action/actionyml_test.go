package action

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// action.yml is the contract the runner enforces: an input the code reads but the file does not declare is never populated by a `with:` block, and an output the file does not declare is invisible to the rest of the workflow. Neither mistake fails at build time and neither is obvious in review, so both are checked here as well as in CI.

var (
	inputCallRE  = regexp.MustCompile(`input\("([a-z-]+)"\)`)
	sectionKeyRE = regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):`)
)

// section extracts the keys declared directly under a top-level mapping in action.yml. It is a deliberately small parser rather than a YAML dependency: the file's shape is fixed, CI validates it properly, and the module otherwise has no dependencies at all.
func section(t *testing.T, doc, name string) map[string]bool {
	t.Helper()
	start := strings.Index(doc, "\n"+name+":\n")
	if start < 0 {
		t.Fatalf("action.yml has no top-level `%s:` section", name)
	}
	body := doc[start+len(name)+2:]
	// The section ends at the next line starting in column zero.
	if end := regexp.MustCompile(`(?m)^[a-z]`).FindStringIndex(body); end != nil {
		body = body[:end[0]]
	}
	keys := map[string]bool{}
	for _, m := range sectionKeyRE.FindAllStringSubmatch(body, -1) {
		keys[m[1]] = true
	}
	if len(keys) == 0 {
		t.Fatalf("action.yml section `%s` declares nothing", name)
	}
	return keys
}

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

func TestEveryInputTheCodeReadsIsDeclaredInActionYML(t *testing.T) {
	declared := section(t, repoFile(t, "action.yml"), "inputs")

	src := repoFile(t, filepath.Join("internal", "action", "config.go"))
	matches := inputCallRE.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatal("found no input reads in config.go; this check would silently pass forever")
	}
	for _, m := range matches {
		if !declared[m[1]] {
			t.Errorf("the code reads input %q but action.yml does not declare it, so a `with:` value would never reach it", m[1])
		}
	}
}

func TestEveryDeclaredInputIsReadByTheCode(t *testing.T) {
	src := repoFile(t, filepath.Join("internal", "action", "config.go"))
	read := map[string]bool{}
	for _, m := range inputCallRE.FindAllStringSubmatch(src, -1) {
		read[m[1]] = true
	}
	// A declared input nothing reads is documentation for behaviour that does not exist.
	for name := range section(t, repoFile(t, "action.yml"), "inputs") {
		if !read[name] {
			t.Errorf("action.yml declares input %q but no code reads it", name)
		}
	}
}

func TestDeclaredOutputsMatchTheCode(t *testing.T) {
	declared := section(t, repoFile(t, "action.yml"), "outputs")

	written := map[string]bool{}
	for _, o := range Outputs(Result{}) {
		written[o.Name] = true
		if !declared[o.Name] {
			t.Errorf("the code writes output %q but action.yml does not declare it, so nothing downstream can read it", o.Name)
		}
	}
	for name := range declared {
		if !written[name] {
			t.Errorf("action.yml declares output %q but the code never writes it", name)
		}
	}
}

// Every default is resolved in LoadConfig so the ARTEFACTFLOW_ variables stay reachable. A `default:` in action.yml would make the runner substitute one first, leaving the environment fallback dead code.
func TestNoInputDeclaresADefault(t *testing.T) {
	doc := repoFile(t, "action.yml")
	inputs := doc[strings.Index(doc, "\ninputs:\n"):strings.Index(doc, "\noutputs:\n")]
	// Match the property key at its own indentation rather than the bare word, so the input named `is-default` is not mistaken for one.
	if m := regexp.MustCompile(`(?m)^\s+default:`).FindString(inputs); m != "" {
		t.Error("an input in action.yml declares a `default:`, which would shadow its ARTEFACTFLOW_ environment variable")
	}
}
