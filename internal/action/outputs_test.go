package action

import (
	"bytes"
	"strings"
	"testing"
)

func TestOutputs(t *testing.T) {
	got := Outputs(Result{
		Version:                 "1.4.2",
		VersionURL:              "https://api.artefactflow.app/v1/artefacts/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/versions/1.4.2",
		Created:                 true,
		VulnerabilitiesUploaded: false,
	})

	want := map[string]string{
		"version":                        "1.4.2",
		"version-url":                    "https://api.artefactflow.app/v1/artefacts/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/versions/1.4.2",
		"created":                        "true",
		"vulnerabilities-uploaded":       "false",
		"converted-vulnerabilities-file": "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d outputs, want %d", len(got), len(want))
	}
	for _, o := range got {
		if w, ok := want[o.Name]; !ok {
			t.Errorf("unexpected output %q", o.Name)
		} else if o.Value != w {
			t.Errorf("output %s = %q, want %q", o.Name, o.Value, w)
		}
	}
}

// A workflow branching on `created` reads a string, so the booleans have to render as the literals GitHub expressions compare against.
func TestBooleanOutputsRenderAsTrueAndFalse(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteOutputs(&buf, Outputs(Result{Created: false, VulnerabilitiesUploaded: true})); err != nil {
		t.Fatalf("WriteOutputs: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "created=false\n") || !strings.Contains(got, "vulnerabilities-uploaded=true\n") {
		t.Errorf("outputs = %q", got)
	}
}

func TestWriteOutputsUsesTheRunnerFormat(t *testing.T) {
	var buf bytes.Buffer
	err := WriteOutputs(&buf, []Output{{"version", "1.4.2"}, {"created", "true"}})
	if err != nil {
		t.Fatalf("WriteOutputs: %v", err)
	}
	if got := buf.String(); got != "version=1.4.2\ncreated=true\n" {
		t.Errorf("outputs = %q", got)
	}
}

// A newline in $GITHUB_OUTPUT is how a value would forge additional outputs, so one is refused rather than written.
func TestWriteOutputsRejectsLineBreaks(t *testing.T) {
	var buf bytes.Buffer
	err := WriteOutputs(&buf, []Output{{"version", "1.4.2\nadmin=true"}})
	if err == nil {
		t.Fatal("WriteOutputs accepted a value containing a line break")
	}
	if buf.Len() != 0 {
		t.Errorf("wrote %q despite the error", buf.String())
	}
}
