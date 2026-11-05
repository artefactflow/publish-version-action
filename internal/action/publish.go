package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// API is the slice of the ArtefactFlow client this action drives, named as an interface so the sequencing below can be exercised without a server.
type API interface {
	CreateVersion(ctx context.Context, artefactID string, in afclient.VersionInput) (*afclient.Version, string, error)
	ImportVulnerabilities(ctx context.Context, artefactID, versionValue string, in afclient.ImportRequest) (*afclient.ImportResult, error)
}

// Result is what the run produced, and what becomes the action's outputs.
type Result struct {
	Version    string
	VersionURL string
	// Created is false when the version already existed and `if-exists` was `skip`.
	Created bool
	// VulnerabilitiesUploaded reports whether the import ran and recorded the report.
	VulnerabilitiesUploaded bool
	// ConvertedFile is the path the converted document was written to, when `converted-output-file` was set and the dry run that produces it succeeded.
	ConvertedFile string
}

// Publish creates the version and, when configured, imports a scan report onto it.
//
// The ordering is not negotiable: vulnerabilities are keyed by the version's SemVer string, so the version has to exist before they can be attached, and ArtefactFlow can only judge a report against a version that exists. The failure this guards against is a version created but vulnerabilities not recorded, reported as one vague error, so when the import fails, the message says plainly that the version exists and how to retry the import alone, and the result still describes what happened.
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

	// A dry run first when the converted document was asked for: it answers with exactly what the import would record, and records nothing. Written before the import runs, so a workflow has it to inspect even if the import then fails.
	if cfg.ConvertedOutputFile != "" {
		dry := cfg.Import
		dry.DryRun = true
		preview, err := api.ImportVulnerabilities(ctx, artefactID, res.Version, dry)
		if err != nil {
			return res, importFailed(res, cfg, err)
		}
		if err := WriteConvertedOutput(cfg.ConvertedOutputFile, preview.Document); err != nil {
			return res, importFailed(res, cfg, err)
		}
		res.ConvertedFile = cfg.ConvertedOutputFile
		fmt.Fprintf(log, "Dry run: %s converts to %d finding(s) as producer %s, written to %s\n", cfg.VulnerabilitiesFile, preview.Findings, preview.Producer, cfg.ConvertedOutputFile)
	}

	fmt.Fprintf(log, "Importing %s onto version %s\n", cfg.VulnerabilitiesFile, res.Version)
	imported, err := api.ImportVulnerabilities(ctx, artefactID, res.Version, cfg.Import)
	if err != nil {
		return res, importFailed(res, cfg, err)
	}
	res.VulnerabilitiesUploaded = true

	if imported.Producer != "" {
		fmt.Fprintf(log, "Recorded the %s report as producer %s, replacing that producer's earlier findings; version %s now holds %d finding(s) from all producers\n", imported.Import.Format, producerLabel(imported), res.Version, imported.VersionFindings)
	} else {
		fmt.Fprintf(log, "Recorded %s on version %s\n", cfg.VulnerabilitiesFile, res.Version)
	}
	if skipped := imported.Import.SkippedRules; skipped > 0 {
		fmt.Fprintf(log, "Left out %d result(s) of the report that name no vulnerability (misconfiguration or code-scanning rules, entries without an advisory identifier)%s\n", skipped, skippedList(imported.Import))
	}
	if unmatched := imported.Import.VEXUnmatched; len(unmatched) > 0 {
		fmt.Fprintf(log, "::warning::%d VEX assessment(s) matched no finding in the scan and were not applied: %s. This usually means the scan and the VEX document are from different builds.\n", len(unmatched), unmatchedList(unmatched))
	}
	return res, nil
}

// importFailed describes a failed import so that the artefact's state is beyond doubt: the version exists, nothing of the report was recorded (the import replaces a producer's findings in one transaction, or not at all), and a re-run with `if-exists: skip` retries the import alone.
func importFailed(res Result, cfg Config, err error) error {
	retry := "re-run this step with `if-exists: skip`"
	if cfg.IfExists == IfExistsSkip {
		retry = "re-run this step"
	}
	return fmt.Errorf("version %s %s, but importing %s failed. Nothing of the report was recorded: the import records a report completely or not at all. Fix the cause and %s to retry the import alone: %w", res.Version, existedOrCreated(res), cfg.VulnerabilitiesFile, retry, err)
}

// producerLabel names the producer with the scanner version the report stated, when it stated one.
func producerLabel(r *afclient.ImportResult) string {
	if r.ProducerVersion == "" {
		return r.Producer
	}
	return r.Producer + " " + r.ProducerVersion
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

// skippedList names the skipped results the answer listed, noting when it listed only some of them. The ids are the report's own rule ids, so they go through logSafe.
func skippedList(s afclient.ImportSummary) string {
	if len(s.SkippedRuleIDs) == 0 {
		return ""
	}
	ids := make([]string, len(s.SkippedRuleIDs))
	for i, id := range s.SkippedRuleIDs {
		ids[i] = logSafe(id)
	}
	list := ": " + strings.Join(ids, ", ")
	if more := s.SkippedRules - len(s.SkippedRuleIDs); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	return list
}

// maxUnmatchedListed is how many unmatched VEX ids the warning names. The API lists every one, and a VEX document from another build can leave hundreds unmatched: the first few are enough to recognise the mistake, and an annotation that long is cut off on the run's summary page anyway.
const maxUnmatchedListed = 20

// unmatchedList names the VEX assessments that matched no finding, the first maxUnmatchedListed of them, noting how many more there were. The ids are copied from the workflow's VEX document and the API only bounds their length, so they go through logSafe.
func unmatchedList(unmatched []string) string {
	shown := unmatched[:min(len(unmatched), maxUnmatchedListed)]
	ids := make([]string, len(shown))
	for i, id := range shown {
		ids[i] = logSafe(id)
	}
	list := strings.Join(ids, ", ")
	if more := len(unmatched) - len(shown); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	return list
}

// logSafe drops control characters from a value a report supplied before it reaches the step log. The runner reads every line of the log for workflow commands, so a line break inside an id would let the report start one of its own (`::add-mask::`, `::stop-commands::`) on the next line.
func logSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
