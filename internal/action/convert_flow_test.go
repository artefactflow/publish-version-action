package action

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artefactflow/publish-version-action/internal/afclient"
	"github.com/artefactflow/publish-version-action/internal/convert"
)

// writeNamed writes content to a uniquely-named file in a temp dir and returns its path, for tests that need more than one report on disk at once.
func writeNamed(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const trivyReport = `{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "image (alpine 3.19)",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-44487",
          "PkgName": "libnghttp2",
          "PkgIdentifier": {"PURL": "pkg:apk/alpine/libnghttp2@1.58.0-r0"},
          "InstalledVersion": "1.58.0-r0",
          "Severity": "HIGH",
          "SeveritySource": "nvd",
          "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "V3Score": 7.5}}
        }
      ]
    }
  ]
}`

// A Trivy report is accepted wherever a native one is, detected by shape, and converted to findings the upload can carry.
func TestLoadAndConvertTrivyReport(t *testing.T) {
	prepared, err := LoadAndConvert(writeNamed(t, "trivy.json", trivyReport), "", "")
	if err != nil {
		t.Fatalf("LoadAndConvert: %v", err)
	}
	if prepared.Format != convert.FormatTrivy {
		t.Errorf("format = %q, want trivy", prepared.Format)
	}
	if len(prepared.Body.Vulnerabilities) != 1 {
		t.Fatalf("converted %d findings, want 1", len(prepared.Body.Vulnerabilities))
	}
	if !strings.Contains(string(prepared.Body.Vulnerabilities[0]), `"CVE-2023-44487"`) {
		t.Errorf("converted finding = %s", prepared.Body.Vulnerabilities[0])
	}
}

// A native report is still forwarded verbatim through the same entry point.
func TestLoadAndConvertNativeIsForwarded(t *testing.T) {
	native := `{"vulnerabilities":[{"id":"CVE-1","source":{"name":"NVD"},"ratings":[{"score":0,"severity":"none"}]}]}`
	prepared, err := LoadAndConvert(writeNamed(t, "native.json", native), "", "")
	if err != nil {
		t.Fatalf("LoadAndConvert: %v", err)
	}
	if prepared.Format != convert.FormatNative {
		t.Errorf("format = %q, want native", prepared.Format)
	}
	// Forwarded verbatim: the 0.0 score is preserved because the bytes are not re-encoded.
	if !strings.Contains(string(prepared.Body.Vulnerabilities[0]), `"score":0`) {
		t.Errorf("native finding lost its zero score: %s", prepared.Body.Vulnerabilities[0])
	}
}

// A VEX file overlaid onto a scan attaches its analysis and reports assessments that matched nothing.
func TestLoadAndConvertOverlaysVEX(t *testing.T) {
	vex := `{"bomFormat":"CycloneDX","vulnerabilities":[
		{"id":"CVE-2023-44487","analysis":{"state":"not_affected","justification":"code_not_reachable"}},
		{"id":"CVE-9999-0000","analysis":{"state":"exploitable"}}
	]}`
	prepared, err := LoadAndConvert(writeNamed(t, "trivy.json", trivyReport), "", writeNamed(t, "vex.json", vex))
	if err != nil {
		t.Fatalf("LoadAndConvert: %v", err)
	}
	if !strings.Contains(string(prepared.Body.Vulnerabilities[0]), `"not_affected"`) {
		t.Errorf("VEX analysis was not merged: %s", prepared.Body.Vulnerabilities[0])
	}
	if len(prepared.UnmatchedVEX) != 1 || prepared.UnmatchedVEX[0] != "CVE-9999-0000" {
		t.Errorf("unmatched = %v, want CVE-9999-0000 reported", prepared.UnmatchedVEX)
	}
}

// A VEX file cannot be overlaid onto a native report: a native report already carries analysis inline.
func TestLoadAndConvertRefusesVEXOnNative(t *testing.T) {
	native := `{"vulnerabilities":[{"id":"CVE-1","source":{"name":"NVD"}}]}`
	vex := `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"exploitable"}}]}`
	_, err := LoadAndConvert(writeNamed(t, "native.json", native), "", writeNamed(t, "vex.json", vex))
	if err == nil || !strings.Contains(err.Error(), "native report already carries") {
		t.Fatalf("error = %v, want native+VEX refused", err)
	}
}

// A format override that does not match the document fails during configuration, before any request.
func TestLoadConfigRejectsMismatchedFormatOverride(t *testing.T) {
	vars := validEnv()
	vars["INPUT_UPLOAD-VULNERABILITIES"] = "true"
	vars["INPUT_VULNERABILITIES-FILE"] = writeNamed(t, "trivy.json", trivyReport)
	vars["INPUT_VULNERABILITIES-FORMAT"] = "grype"
	if _, err := LoadConfig(getenvFrom(vars)); err == nil {
		t.Fatal("LoadConfig accepted a Trivy report declared as Grype")
	}
}

// A VEX file with nothing to attach it to is a misconfiguration worth naming.
func TestLoadConfigVEXWithoutScanOrApplyIsAnError(t *testing.T) {
	vex := `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"exploitable"}}]}`
	vars := validEnv()
	vars["INPUT_VEX-FILE"] = writeNamed(t, "vex.json", vex)
	if _, err := LoadConfig(getenvFrom(vars)); err == nil || !strings.Contains(err.Error(), "vex-file") {
		t.Fatalf("error = %v, want vex-file with no target refused", err)
	}
}

// The converted set can be written out for a workflow to inspect, matching exactly what will be uploaded.
func TestWriteConvertedOutput(t *testing.T) {
	body := afclient.VulnerabilitiesInput{Vulnerabilities: []json.RawMessage{json.RawMessage(`{"id":"CVE-1","source":{"name":"NVD"}}`)}}
	path := filepath.Join(t.TempDir(), "converted.json")
	if err := WriteConvertedOutput(path, body); err != nil {
		t.Fatalf("WriteConvertedOutput: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var round afclient.VulnerabilitiesInput
	if err := json.Unmarshal(got, &round); err != nil {
		t.Fatalf("converted output is not valid JSON: %v", err)
	}
	if len(round.Vulnerabilities) != 1 {
		t.Errorf("converted output has %d findings, want 1", len(round.Vulnerabilities))
	}
}
