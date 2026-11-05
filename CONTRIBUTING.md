# Contributing

Thanks for taking the time. Bug reports, documentation fixes, and pull requests are all welcome.

## Getting started

The action is a small Go program shipped as a container action. You need Go (the version in [go.mod](go.mod)) and, to build the image, Docker.

```sh
go build ./...
go test ./...
```

## Running it locally

The binary reads the same environment the runner gives it, so you can exercise it without a workflow. With `GITHUB_OUTPUT` unset it prints the outputs to stdout instead of writing them to a file. The `ARTEFACTFLOW_` variables are the convenient way in: unlike the `INPUT_` ones they contain no hyphens, so a shell accepts them as an assignment prefix:

```sh
ARTEFACTFLOW_API_URL=https://api.artefactflow.app \
ARTEFACTFLOW_CLIENT_ID=... \
ARTEFACTFLOW_CLIENT_SECRET=... \
ARTEFACTFLOW_ARTEFACT_NAME=acme-payment-service \
ARTEFACTFLOW_VERSION=1.4.2 \
go run ./cmd/publish-version
```

Set `ARTEFACTFLOW_API_URL` deliberately. Left unset it defaults to the hosted API, and this action writes, so running it by accident against production creates a real version.

To exercise the `with:` path instead, set the `INPUT_` variables the runner would set. Those do contain hyphens, so they have to go through `env`:

```sh
env 'INPUT_ARTEFACT-NAME=acme-payment-service' 'INPUT_VERSION=1.4.2' 'INPUT_CLIENT-ID=...' 'INPUT_CLIENT-SECRET=...' go run ./cmd/publish-version
```

Against the stub, with no ArtefactFlow instance and no credentials at all. [`testdata/stub-api.py`](testdata/stub-api.py) implements the four endpoints the action calls, and it is the same stub CI uses:

```sh
python3 testdata/stub-api.py 8099 &
until curl -sf -o /dev/null -X POST -H 'Content-Type: application/json' \
  -d '{"client_id":"0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0","client_secret":"afsa_stub-client-secret"}' \
  http://localhost:8099/v1/auth/token; do sleep 0.2; done

ARTEFACTFLOW_API_URL=http://localhost:8099 \
ARTEFACTFLOW_CLIENT_ID=0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0 \
ARTEFACTFLOW_CLIENT_SECRET=afsa_stub-client-secret \
ARTEFACTFLOW_ARTEFACT_NAME=acme-payment-service \
ARTEFACTFLOW_VERSION=1.4.2 \
ARTEFACTFLOW_UPLOAD_VULNERABILITIES=true \
ARTEFACTFLOW_VULNERABILITIES_FILE=examples/vulnerabilities.json \
go run ./cmd/publish-version
```

The stub rejects any request that does not present the token it minted, so a change that breaks the authentication wiring fails there rather than passing quietly. It also refuses to create the same version twice and refuses to attach vulnerabilities to a version that does not exist. Run the command again to see the `if-exists` behaviour, and add `ARTEFACTFLOW_IF_EXISTS=skip` to watch a re-run succeed. Publishing version `9.9.9` against it always fails the import, which is how the two-call failure path is exercised. The stub does not convert reports (that is ArtefactFlow's job): it recognises the format and lists the identifiers, which is enough to exercise the dry run and the converted-output file.

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

- Keep the input mapping covered by tests. The runner exposes an input named `artefact-name` as `INPUT_ARTEFACT-NAME`: it uppercases the name and replaces spaces with underscores, but it does not touch hyphens. Reading the underscored spelling would make every `with:` value invisible while every unit test still passed, so there is a test pinning this.
- The two API calls happen in a fixed order, and the failure between them is the one that matters: if the version is created and the import then fails, the error has to say so plainly, say how to retry the import alone, and the outputs still have to be written. There are tests asserting this; keep them passing.
- The action converts nothing. It sends the scan report and VEX document as the files were written, as multipart form data, to ArtefactFlow's import endpoint, which detects the format, converts, validates and records the report. Keep it that way: the conversion lives in one place, so every CI system records the same findings from the same report, and a scanner changing its output is fixed there once. What the action checks itself is only what needs no knowledge of the formats (the file exists, is not empty, is JSON, and fits in one request), so those mistakes fail before the version is created.
- The import replaces its producer's findings. Anything that could send a different report from the one read is a data-loss bug, not a formatting one: the file's bytes are sent as they were read.
- Everything knowable before a request is made is checked before the first one is: the report is read and checked during configuration, not between the two calls. A version must never be published only for the run to discover the file was missing, empty or not JSON all along. Whether the report converts is for ArtefactFlow to say, and it can only say so once the version exists.
- `converted-output-file` is a dry run of the same import, asked for before the real one. The document it writes is ArtefactFlow's answer with the import summary removed, kept as the raw JSON the API sent, never re-encoded from structs, which would drop any value Go treats as empty.
- The client secret and the minted token must never reach a log line, an error message, or an output. There are tests asserting this; keep them passing.
- Every default is applied in `LoadConfig`, never as a `default:` in `action.yml`. The runner substitutes a declared default before the action runs, which would make the `ARTEFACTFLOW_` fallback dead code. CI fails a pull request that adds one.
- Failures surface as `::error::` annotations with a non-zero exit, so they land on the run summary rather than only in the step log.
- Prose in Markdown is written as one unwrapped line per paragraph: do not hard-wrap at a column.
- `action.yml` stays at the repository root; that is a Marketplace requirement.
- Do not edit `CHANGELOG.md`.

## Releasing

Releases are cut by maintainers from the `Release` workflow. It re-runs the tests from the tag, builds and pushes the multi-architecture image to GHCR, creates the GitHub release, and repoints the moving major tag (`v1`) at it, skipping that last step for pre-releases.

`action.yml` references **one exact image version**, for example `docker://ghcr.io/artefactflow/publish-version-action:1.2.3`, and that reference is part of the release commit. A floating `:1` would be less work, but it would mean someone who pins `uses: ...@v1.2.0` or a commit SHA silently gets a newer image on your next release: pinning has to actually pin. The release workflow refuses to publish when the reference and the tag disagree.

So each release is:

1. Update `runs.image` in `action.yml` to the version being released, and commit.
2. Tag that commit (`git tag v1.2.3`) and push the tag. Pushing the tag starts the `Release` workflow.

Until the workflow finishes, the tag exists but its image does not, so the action is briefly unusable at that ref. Nothing consumes a tag before its release exists, so this is safe. To re-run a release, start the `Release` workflow by hand and choose the tag (not a branch) under **Use workflow from**.

### The first release

The first release follows the same steps. No image exists yet when you commit, but the release workflow pushes and tags the image before it creates the GitHub release and moves the major tag, so `action.yml` can already name the image of the version being released. Immediately after the first run:

1. Confirm the package is **public**: GHCR packages are not reliably public just because the repository is, and a private image fails for every consumer with an unauthorized pull. Check under the organisation's Packages settings.

Listing on the Marketplace is a manual step on the first release only: open the release, choose **Edit**, and tick **Publish this Action to the GitHub Marketplace**.

### Why CI stages a copy of the action

Because `action.yml` points at a published image, `uses: ./` in the smoke job would pull that image and test the last release rather than the pull request. The job therefore copies the action into `ci-local-action/` with the image reference rewritten to `Dockerfile`, and runs that. If you add a file the container build needs, add it to that copy step too.

Note that the copy covers only what the **image build** needs (`go.mod`, `cmd`, `internal`, and the Dockerfile). A container action still runs with the repository root as its working directory, so a path passed to `vulnerabilities-file` resolves against the real checkout rather than the staged copy, which is why the smoke job can point at `examples/vulnerabilities.json` without it being copied.
