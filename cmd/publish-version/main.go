// Command publish-version is the entry point of the ArtefactFlow publish-version GitHub Action. It reads the action inputs from the environment, creates a version of one artefact from the workflow's build metadata, optionally replaces that version's recorded vulnerabilities, and writes the results to $GITHUB_OUTPUT for later steps to consume.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/artefactflow/publish-version-action/internal/action"
	"github.com/artefactflow/publish-version-action/internal/afclient"
)

// version is stamped at build time with -ldflags. It is only used for the summary line in the step log.
var version = "dev"

func main() {
	afclient.UserAgent = "publish-version-action/" + version
	// Every failure surfaces as an ::error:: annotation so it lands on the workflow run's summary page, not only in the collapsed step log.
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "::error::%s\n", sanitiseAnnotation(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	// The runner cancels a job by signalling the container; honouring that stops an in-flight retry loop promptly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cfg, err := action.LoadConfig(os.Getenv)
	if err != nil {
		return err
	}

	// Mask the client secret before it is used for anything. The runner masks a value it was given through `secrets.`, but the action also accepts its credentials from a plain `env:` block, and a secret arriving that way is registered with the runner nowhere. Without this, a later step running under `set -x`, or any debug dump, prints it in the clear.
	underRunner := os.Getenv("GITHUB_ACTIONS") == "true"
	if underRunner {
		fmt.Printf("::add-mask::%s\n", cfg.ClientSecret)
	}

	// The service account presents its client credentials and gets a short-lived token back. It is used for the calls below and never stored, logged, or emitted as an output.
	token, err := afclient.Authenticate(ctx, cfg.APIURL, cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		return err
	}
	// Mask it before it is used anywhere: the runner only masks values it was given as secrets, and a minted token is not one of them. Without this, a later step running with debug logging could print it in the clear.
	//
	// Only under a runner, though. Off a runner nothing interprets the workflow command, so it would print the token verbatim to a terminal or a captured log, the opposite of the intent. The same applies to the secret masked above.
	if underRunner {
		fmt.Printf("::add-mask::%s\n", token)
	}
	fmt.Printf("Authenticated service account %s\n", cfg.ClientID)

	client, err := afclient.New(cfg.APIURL, token)
	if err != nil {
		return err
	}

	// The write endpoints address an artefact by id, so the name is resolved first. The id is never asked for or emitted: a workflow only ever deals in names.
	artefactID, err := client.ResolveArtefactID(ctx, cfg.ArtefactName)
	if err != nil {
		return err
	}
	fmt.Printf("Resolved artefact %s to %s\n", cfg.ArtefactName, artefactID)

	// The standalone VEX path applies assessments to an already-recorded set; it neither creates a version nor uploads a scan.
	if cfg.ApplyVEXOnly {
		res, applyErr := action.ApplyVEX(ctx, cfg, artefactID, client, os.Stdout)
		if err := writeOutputs(action.Outputs(res)); err != nil {
			if applyErr != nil {
				return fmt.Errorf("%w (additionally, writing the action outputs failed: %v)", applyErr, err)
			}
			return err
		}
		if applyErr != nil {
			return applyErr
		}
		fmt.Printf("publish-version %s: applied %d VEX assessment(s) to %s of %s\n", version, res.AnalysesApplied, res.Version, cfg.ArtefactName)
		return nil
	}

	// Write the converted set before publishing, so a workflow that asked to inspect it has it even if the upload later fails. Only meaningful when a set was actually prepared.
	if cfg.UploadVulnerabilities {
		if err := action.WriteConvertedOutput(cfg.ConvertedOutputFile, cfg.Vulnerabilities); err != nil {
			return err
		}
	}

	res, publishErr := action.Publish(ctx, cfg, artefactID, client, os.Stdout)

	// The outputs are written even when the run failed. A version created before the vulnerability upload failed is still a fact the rest of the workflow has to be able to see.
	if err := writeOutputs(action.Outputs(res)); err != nil {
		if publishErr != nil {
			return fmt.Errorf("%w (additionally, writing the action outputs failed: %v)", publishErr, err)
		}
		return err
	}
	if publishErr != nil {
		return publishErr
	}

	// A one-line summary makes the common "did it publish, and where?" question answerable without expanding anything.
	fmt.Printf("publish-version %s: %s %s of %s at %s\n", version, createdOrExisted(res), res.Version, cfg.ArtefactName, res.VersionURL)
	return nil
}

// writeOutputs appends the outputs to the file the runner points $GITHUB_OUTPUT at. Running outside a runner (a local smoke test) is not an error: the outputs go to stdout instead.
func writeOutputs(outputs []action.Output) error {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		fmt.Fprintln(os.Stdout, "GITHUB_OUTPUT is not set; printing outputs instead:")
		return action.WriteOutputs(os.Stdout, outputs)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("open GITHUB_OUTPUT: %w", err)
	}
	// Closed explicitly on both paths rather than deferred, so a failure to flush the outputs is reported rather than discarded.
	if err := action.WriteOutputs(f, outputs); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close GITHUB_OUTPUT: %w", err)
	}
	return nil
}

// sanitiseAnnotation flattens an error onto one line. A workflow command is line-oriented, so an embedded newline would truncate the annotation and leak the remainder as raw log text.
func sanitiseAnnotation(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func createdOrExisted(res action.Result) string {
	if res.Created {
		return "created"
	}
	return "found existing"
}
