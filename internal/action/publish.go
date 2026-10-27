package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// API is the slice of the ArtefactFlow client this action drives, named as an interface so the sequencing below can be exercised without a server.
type API interface {
	CreateVersion(ctx context.Context, artefactID string, in afclient.VersionInput) (*afclient.Version, string, error)
	ReplaceVulnerabilities(ctx context.Context, artefactID, versionValue string, in afclient.VulnerabilitiesInput) error
	UpdateVulnerabilityAnalysis(ctx context.Context, artefactID, versionValue, vulnerabilityID string, in afclient.VulnerabilityAnalysisInput) error
}

// Result is what the run produced, and what becomes the action's outputs.
type Result struct {
	Version    string
	VersionURL string
	// Created is false when the version already existed and `if-exists` was `skip`.
	Created bool
	// VulnerabilitiesUploaded reports whether the second call ran and succeeded.
	VulnerabilitiesUploaded bool
	// AnalysesApplied counts the VEX assessments applied on the standalone path.
	AnalysesApplied int
	// ConvertedFile is the path the converted native JSON was written to, when `converted-output-file` was set.
	ConvertedFile string
}

// Publish creates the version and, when configured, replaces its recorded vulnerabilities.
//
// The ordering is not negotiable: vulnerabilities are keyed by the version's SemVer string, so the version has to exist before they can be attached. The failure this guards against is a version created but vulnerabilities not uploaded, reported as one vague error, so when the second call fails, the message says plainly that the version exists and only the upload needs re-running, and the result still describes what happened.
//
// log receives the progress lines that go to the step log; a failed run returns both the partial result and the error.
func Publish(ctx context.Context, cfg Config, artefactID string, api API, log io.Writer) (Result, error) {
	res := Result{Version: cfg.Version.Version}

	created, location, err := api.CreateVersion(ctx, artefactID, cfg.Version)
	switch {
	case err == nil, afclient.CreatedByOwnRetry(err):
		res.Created = true
		res.VersionURL = location
		if created.Version != "" {
			res.Version = created.Version
		}
		fmt.Fprintf(log, "Created version %s of %s\n", res.Version, cfg.ArtefactName)
		if afclient.CreatedByOwnRetry(err) {
			// Worth saying out loud: the create was retried and the version was already there when the retry arrived. Treating it as this run's own work is the right call, but someone reading a log after an incident should not have to infer that.
			fmt.Fprintf(log, "::warning::The create was retried after a transient failure and the version already existed on the retry. It has been treated as created by this run, which is the likeliest explanation: a version published earlier would have conflicted on the first attempt. Check the version if you need certainty.\n")
		}

	case errors.Is(err, afclient.ErrVersionExists) && cfg.IfExists == IfExistsSkip:
		fmt.Fprintf(log, "Version %s of %s already exists; continuing because `if-exists` is `skip`. No fields on the existing version were changed.\n", res.Version, cfg.ArtefactName)

	case errors.Is(err, afclient.ErrVersionExists):
		// A 409 means the version is there, so its URL is still worth reporting: it is where someone will go to see what is already recorded.
		res.VersionURL = versionURL(cfg.APIURL, artefactID, res.Version, "")
		return res, fmt.Errorf("version %s of %s already exists. Set `if-exists: skip` to treat this as success on a re-run: %w", res.Version, cfg.ArtefactName, err)

	default:
		return res, err
	}

	res.VersionURL = versionURL(cfg.APIURL, artefactID, res.Version, res.VersionURL)

	if !cfg.UploadVulnerabilities {
		return res, nil
	}
	// The converted set is written before this point, so report its path even if the upload below fails.
	res.ConvertedFile = cfg.ConvertedOutputFile

	for _, note := range cfg.ConversionNotes {
		fmt.Fprintf(log, "%s\n", note)
	}
	if len(cfg.UnmatchedVEX) > 0 {
		fmt.Fprintf(log, "::warning::%d VEX assessment(s) matched no finding in the scan and were not applied: %s. This usually means the scan and the VEX document are from different builds.\n", len(cfg.UnmatchedVEX), strings.Join(cfg.UnmatchedVEX, ", "))
	}

	vulns := cfg.Vulnerabilities
	n := len(vulns.Vulnerabilities)
	fmt.Fprintf(log, "Replacing the recorded vulnerabilities of version %s with %d finding(s) from %s\n", res.Version, n, cfg.VulnerabilitiesFile)
	if err := api.ReplaceVulnerabilities(ctx, artefactID, res.Version, vulns); err != nil {
		// Nothing is left half-applied (the endpoint swaps the whole set in one call), so the only thing outstanding is the upload itself.
		return res, fmt.Errorf("version %s %s, but the vulnerability upload failed. Nothing was partially recorded: the upload replaces the whole set in one call. Re-run this step to retry the upload alone: %w", res.Version, existedOrCreated(res), err)
	}
	res.VulnerabilitiesUploaded = true
	fmt.Fprintf(log, "Recorded %d vulnerability finding(s) on version %s\n", n, res.Version)
	return res, nil
}

// CheckVEXScope stops the standalone VEX path before its first call when the token cannot do what that path needs. apply-vex-only re-triages recorded findings, which needs vulnerability:write, and ArtefactFlow does not grant that scope to service accounts: triage is kept to people. One clear error up front replaces one 403 per finding. A token whose scopes cannot be read is left to the API to judge.
func CheckVEXScope(cfg Config, token string) error {
	if !cfg.ApplyVEXOnly {
		return nil
	}
	if granted, known := afclient.TokenGrants(token, "vulnerability:write"); known && !granted {
		return fmt.Errorf("apply-vex-only needs the vulnerability:write scope, which ArtefactFlow does not grant to service accounts: changing the triage of recorded findings is kept to people. To record VEX from a workflow, send it with the scan (`upload-vulnerabilities: true`): as `vex-file` beside a Trivy, Grype or CycloneDX report, or as `analysis` inside a native report. Either way it travels in the upload, which version:write covers")
	}
	return nil
}

// ApplyVEX is the standalone VEX path: it applies each assessment to a finding already recorded against the version, via PATCH, touching only the findings named. It creates no version and uploads no scan: it operates on the set already there.
//
// The path is not atomic across findings, so a partial failure is reported as one: the assessments that applied stand, and the run fails naming those that did not, rather than reporting success over a half-applied set. An assessment whose finding is not recorded (a 404) is a mismatch, reported as a warning rather than a failure: it usually means the VEX and the recorded findings are from different builds.
func ApplyVEX(ctx context.Context, cfg Config, artefactID string, api API, log io.Writer) (Result, error) {
	res := Result{Version: cfg.Version.Version}
	res.VersionURL = versionURL(cfg.APIURL, artefactID, res.Version, "")

	var applied, unmatched, failed []string
	var firstErr error
	for _, e := range cfg.VEXEntries {
		in, err := e.AnalysisInput()
		if err != nil {
			// Guarded already at load time; treat a straggler as a hard failure rather than pressing on.
			failed = append(failed, e.ID)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		switch err := api.UpdateVulnerabilityAnalysis(ctx, artefactID, res.Version, e.ID, in); {
		case err == nil:
			applied = append(applied, e.ID)
		case afclient.IsNotFound(err):
			unmatched = append(unmatched, e.ID)
		default:
			failed = append(failed, e.ID)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	res.AnalysesApplied = len(applied)

	fmt.Fprintf(log, "Applied VEX analysis to %d of %d finding(s) on version %s of %s\n", len(applied), len(cfg.VEXEntries), res.Version, cfg.ArtefactName)
	if len(unmatched) > 0 {
		fmt.Fprintf(log, "::warning::%d VEX assessment(s) matched no finding recorded on version %s and were not applied: %s. This usually means the VEX and the recorded findings are from different builds.\n", len(unmatched), res.Version, strings.Join(unmatched, ", "))
	}
	if firstErr != nil {
		return res, fmt.Errorf("applied %d assessment(s) to version %s, but %d could not be applied (%s). Applying VEX is not atomic across findings, so the applied ones stand; re-run to retry the rest: %w", len(applied), res.Version, len(failed), strings.Join(failed, ", "), firstErr)
	}
	// Nothing applied at all. With entries to apply, this is not a success: the version is almost certainly wrong, or its findings were recorded from a different build. A warning alone would let a no-op run look clean.
	if len(applied) == 0 {
		return res, fmt.Errorf("none of the %d VEX assessment(s) matched a finding recorded on version %s of %s (%s). Check the version exists and that its findings were recorded from the same build the VEX describes", len(cfg.VEXEntries), res.Version, cfg.ArtefactName, strings.Join(unmatched, ", "))
	}
	return res, nil
}

// versionURL settles on the URL to report for a version. The API's Location header wins when it gave one, resolved against the base URL if it was relative; otherwise the URL is derived, because a workflow reading the output should never get an empty string back for a version that demonstrably exists.
func versionURL(apiURL, artefactID, version, location string) string {
	switch {
	case location == "":
		return fmt.Sprintf("%s/v1/artefacts/%s/versions/%s", apiURL, artefactID, version)
	case strings.HasPrefix(location, "http://"), strings.HasPrefix(location, "https://"):
		return location
	default:
		return apiURL + "/" + strings.TrimPrefix(location, "/")
	}
}

// existedOrCreated describes what happened to the version, for an error message that has to leave no doubt about the artefact's state.
func existedOrCreated(res Result) string {
	if res.Created {
		return "was created"
	}
	return "already existed"
}
