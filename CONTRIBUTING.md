# Contributing

Thanks for taking the time. Bug reports, documentation fixes, and pull requests are all welcome.

## Getting started

The action is a small Go program shipped as a container action. You need Go (the version in [go.mod](go.mod)) and, to build the image, Docker.

```sh
go build ./...
go test ./...
```

## Running it locally

The binary reads the same environment the runner gives it, so you can exercise it without a workflow. With `GITHUB_OUTPUT` unset it prints the outputs to stdout instead of writing them to a file. The `ARTEFACTFLOW_` variables are the convenient way in — unlike the `INPUT_` ones they contain no hyphens, so a shell accepts them as an assignment prefix:

```sh
ARTEFACTFLOW_API_URL=https://api.artefactflow.app \
ARTEFACTFLOW_CLIENT_ID=... \
ARTEFACTFLOW_CLIENT_SECRET=... \
ARTEFACTFLOW_ARTEFACT_NAME=acme-payment-service \
ARTEFACTFLOW_VERSION=1.4.2 \
go run ./cmd/publish-version
```

Set `ARTEFACTFLOW_API_URL` deliberately. Left unset it defaults to the hosted API, and this action writes — running it by accident against production creates a real version.

To exercise the `with:` path instead, set the `INPUT_` variables the runner would set. Those do contain hyphens, so they have to go through `env`:

```sh
env 'INPUT_ARTEFACT-NAME=acme-payment-service' 'INPUT_VERSION=1.4.2' 'INPUT_CLIENT-ID=...' 'INPUT_CLIENT-SECRET=...' go run ./cmd/publish-version
```

Against the stub, with no ArtefactFlow instance and no credentials at all. [`testdata/stub-api.py`](testdata/stub-api.py) implements the four endpoints the action calls, and it is the same stub CI uses:

```sh
python3 testdata/stub-api.py 8099 &
until curl -sf -o /dev/null -X POST -H 'Content-Type: application/json' \
  -d '{"client_id":"507f191e810c19729de860ed","client_secret":"afsa_stub-client-secret"}' \
  http://localhost:8099/v1/auth/token; do sleep 0.2; done

ARTEFACTFLOW_API_URL=http://localhost:8099 \
ARTEFACTFLOW_CLIENT_ID=507f191e810c19729de860ed \
ARTEFACTFLOW_CLIENT_SECRET=afsa_stub-client-secret \
ARTEFACTFLOW_ARTEFACT_NAME=acme-payment-service \
ARTEFACTFLOW_VERSION=1.4.2 \
ARTEFACTFLOW_UPLOAD_VULNERABILITIES=true \
ARTEFACTFLOW_VULNERABILITIES_FILE=examples/vulnerabilities.json \
go run ./cmd/publish-version
```

The stub rejects any request that does not present the token it minted, so a change that breaks the authentication wiring fails there rather than passing quietly. It also refuses to create the same version twice and refuses to attach vulnerabilities to a version that does not exist — run the command again to see the `if-exists` behaviour, and add `ARTEFACTFLOW_IF_EXISTS=skip` to watch a re-run succeed. Publishing version `9.9.9` against it always fails the vulnerability upload, which is how the two-call failure path is exercised.

## Before opening a pull request

CI runs these, so running them first saves a round trip:

```sh
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
docker build .    # the action is a container action; the image has to build
```

CI additionally runs a smoke test that executes the action end to end against a stub API, which covers the wiring the unit tests cannot reach.

## Conventions

- Keep the input mapping covered by tests. The runner exposes an input named `artefact-name` as `INPUT_ARTEFACT-NAME` — it uppercases the name and replaces spaces with underscores, but it does not touch hyphens. Reading the underscored spelling would make every `with:` value invisible while every unit test still passed, so there is a test pinning this.
- The two API calls happen in a fixed order, and the failure between them is the one that matters: if the version is created and the upload then fails, the error has to say so plainly and the outputs still have to be written. There are tests asserting this; keep them passing.
- The vulnerability upload replaces the version's whole recorded set. Anything that could send a partial list is a data-loss bug, not a formatting one. Findings are validated against the typed model and then forwarded as the raw JSON they were read from — never re-encoded from the structs, which would drop any value Go treats as empty.
- Everything knowable before a request is made is checked before the first one is: the report is read and validated during configuration, not between the two calls. A version must never be published only for the run to discover the report was unusable all along.
- `internal/afclient/types.go` must model the vulnerability schema completely. Reports are decoded with unknown fields rejected, so a field the API accepts but the model omits turns a valid report into a hard failure.
- Scanner reports (Trivy, Grype, CycloneDX) are converted in `internal/convert`. They are decoded *leniently* — a scanner carries far more than the action reads, and rejecting an unknown field would break on the next release — but the converted output is re-validated against the schema strictly before it is uploaded. Conversion is confident-or-fail: a report that cannot be fully mapped is an error naming the offending entry, never a partial upload, because the endpoint is a full replace. Converters build the typed model and re-encode it, so a rating's score is a pointer — a genuine `0.0` must not be dropped.
- The converters are covered by golden fixtures under `internal/convert/testdata`. After a deliberate change to a mapping, regenerate them with `go test ./internal/convert -update` and review the diff — the golden *is* the specification of what a converter emits. The `scanner-drift` workflow re-runs the latest Trivy and Grype against a fixed target on a schedule, so a scanner changing its output shape fails there rather than in a consumer's pipeline.
- The client secret and the minted token must never reach a log line, an error message, or an output. There are tests asserting this; keep them passing.
- Every default is applied in `LoadConfig`, never as a `default:` in `action.yml` — the runner substitutes a declared default before the action runs, which would make the `ARTEFACTFLOW_` fallback dead code. CI fails a pull request that adds one.
- Failures surface as `::error::` annotations with a non-zero exit, so they land on the run summary rather than only in the step log.
- Prose in Markdown is written as one unwrapped line per paragraph — do not hard-wrap at a column.
- `action.yml` stays at the repository root; that is a Marketplace requirement.
- Do not edit `CHANGELOG.md`.

## Releasing

Releases are cut by maintainers from the `Release` workflow. It re-runs the tests from the tag, builds and pushes the multi-architecture image to GHCR, creates the GitHub release, and repoints the moving major tag (`v1`) at it — skipping that last step for pre-releases.

`action.yml` references **one exact image version**, for example `docker://ghcr.io/artefactflow/publish-version-action:1.2.3`, and that reference is part of the release commit. A floating `:1` would be less work, but it would mean someone who pins `uses: ...@v1.2.0` or a commit SHA silently gets a newer image on your next release — pinning has to actually pin. The release workflow refuses to publish when the reference and the tag disagree.

So each release is:

1. Update `runs.image` in `action.yml` to the version being released, and commit.
2. Tag that commit (`git tag v1.2.3`) and push the tag.
3. Run the `Release` workflow against the tag, with **dry-run off**.

Between steps 2 and 3 the tag exists but its image does not, so the action is briefly unusable at that ref. Nothing consumes a tag before its release exists, so this is safe — but do not leave the gap open longer than necessary.

### The first release

The first release is the exception: no image exists yet, so `action.yml` stays on `image: 'Dockerfile'` and the workflow emits a notice rather than failing. That release builds on the runner for anyone who uses it. Immediately afterwards:

1. Confirm the package is **public** — GHCR packages are not reliably public just because the repository is, and a private image fails for every consumer with an unauthorized pull. Check under the organisation's Packages settings.
2. Switch `action.yml` to `docker://ghcr.io/artefactflow/publish-version-action:<that version>` and cut the next release normally.

Listing on the Marketplace is a manual step on the first release only: open the release, choose **Edit**, and tick **Publish this Action to the GitHub Marketplace**.

### Why CI stages a copy of the action

Because `action.yml` points at a published image, `uses: ./` in the smoke job would pull that image and test the last release rather than the pull request. The job therefore copies the action into `ci-local-action/` with the image reference rewritten to `Dockerfile`, and runs that. If you add a file the container build needs, add it to that copy step too.

Note that the copy covers only what the **image build** needs (`go.mod`, `cmd`, `internal`, and the Dockerfile). A container action still runs with the repository root as its working directory, so a path passed to `vulnerabilities-file` resolves against the real checkout rather than the staged copy — which is why the smoke job can point at `examples/vulnerabilities.json` without it being copied.
