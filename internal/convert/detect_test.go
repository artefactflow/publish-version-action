package convert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDetectRecognisesEachFormat(t *testing.T) {
	cases := map[string]Format{
		"trivy.input.json":     FormatTrivy,
		"grype.input.json":     FormatGrype,
		"cyclonedx.input.json": FormatCycloneDX,
	}
	for name, want := range cases {
		got, err := Detect(fixture(t, name), "")
		if err != nil {
			t.Errorf("Detect(%s): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("Detect(%s) = %q, want %q", name, got, want)
		}
	}
}

func TestDetectNativeShapes(t *testing.T) {
	for _, doc := range []string{
		`{"vulnerabilities":[{"id":"CVE-1","source":{"name":"NVD"}}]}`,
		`[{"id":"CVE-1","source":{"name":"NVD"}}]`,
		`   [ ]`,
	} {
		got, err := Detect([]byte(doc), "")
		if err != nil {
			t.Errorf("Detect(%s): %v", doc, err)
			continue
		}
		if got != FormatNative {
			t.Errorf("Detect(%s) = %q, want native", doc, got)
		}
	}
}

// A mis-set format flag must not silently reinterpret a document: the whole point of detection is that it cannot upload garbage.
func TestDetectOverrideThatDoesNotMatchIsAnError(t *testing.T) {
	_, err := Detect(fixture(t, "trivy.input.json"), "grype")
	if err == nil {
		t.Fatal("Detect accepted a Trivy report declared as Grype")
	}
	if !strings.Contains(err.Error(), "does not look like a grype") {
		t.Errorf("error = %v, want it to say the document is not Grype", err)
	}
}

func TestDetectHonoursAMatchingOverride(t *testing.T) {
	got, err := Detect(fixture(t, "trivy.input.json"), "trivy")
	if err != nil || got != FormatTrivy {
		t.Fatalf("Detect with matching override = %q, %v", got, err)
	}
}

func TestDetectUnknownOverride(t *testing.T) {
	_, err := Detect([]byte(`{}`), "snyk")
	if err == nil || !strings.Contains(err.Error(), "unknown `vulnerabilities-format`") {
		t.Fatalf("error = %v, want it to reject the unknown format", err)
	}
}

// An unrecognised document is an error, never a best-effort parse.
func TestDetectUnrecognisedDocumentFails(t *testing.T) {
	_, err := Detect([]byte(`{"unrelated":"json"}`), "")
	if err == nil || !strings.Contains(err.Error(), "could not recognise") {
		t.Fatalf("error = %v, want it to refuse an unrecognised document", err)
	}
}

func TestDetectRejectsInvalidJSON(t *testing.T) {
	if _, err := Detect([]byte(`{not json`), ""); err == nil {
		t.Fatal("Detect accepted invalid JSON")
	}
}
