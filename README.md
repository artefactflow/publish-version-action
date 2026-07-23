# Publish Version

[![CI](https://github.com/artefactflow/publish-version-action/actions/workflows/ci.yml/badge.svg)](https://github.com/artefactflow/publish-version-action/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## What is ArtefactFlow?

[ArtefactFlow](https://www.artefactflow.com) is a hosted platform for managing software artefacts and their Software Bills of Materials. It gives your team one source of truth for every application, library and image you ship: each artefact and its versions, the licenses and vulnerabilities they carry, the immutable CycloneDX SBOMs that describe them, and a record of which SBOM version is running in which environment. So when someone asks what is inside a release, whether it is vulnerable, or what exactly is in production right now, there is one answer rather than four.

Everything is available over a REST API, which is what makes integrations like this one possible. [Create an account](https://www.artefactflow.com) to get started, or read the [documentation](https://docs.artefactflow.com) for the full picture.

## What this action does

A GitHub Action that registers what your pipeline just built. It creates a version of an ArtefactFlow artefact from the build metadata your workflow already has — and, when you ask it to, records that version's vulnerabilities in the same step.

Most of what ArtefactFlow wants to know about a build is already in the workflow context: the commit, the branch, the run that produced it. So you name the artefact and the version, and the action derives the rest. It pairs with [suggest-version-action](https://github.com/artefactflow/suggest-version-action), which decides what that version should be.

```yaml
- name: Publish the version
  uses: artefactflow/publish-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    version: 1.4.2
```

That records `1.4.2` with the commit, branch, run id and run number of the workflow that created it, a link back to the run itself, and `github-actions` as its builder.

## Inputs

| Input | Required | Default | Environment variable | Description |
|---|---|---|---|---|
| `api-url` | no | `https://api.artefactflow.app` | `ARTEFACTFLOW_API_URL` | Base URL of the API. Override it if you self-host |
| `client-id` | yes | — | `ARTEFACTFLOW_CLIENT_ID` | A service account's client id — its 24-character hex id |
| `client-secret` | yes | — | `ARTEFACTFLOW_CLIENT_SECRET` | The service account's client secret. Pass it from a secret |
| `artefact-name` | yes | — | `ARTEFACTFLOW_ARTEFACT_NAME` | The artefact's name, 2 to 128 characters of letters, digits, `_` and `-` |
| `version` | yes | — | `ARTEFACTFLOW_VERSION` | The SemVer version to create, 4 to 50 characters, for example `1.4.2` |
| `commit-sha` | no | the triggering commit | `ARTEFACTFLOW_COMMIT_SHA` | Commit the build was produced from, 7 to 64 hex characters |
| `branch` | no | the triggering ref | `ARTEFACTFLOW_BRANCH` | Source branch the build came from |
| `build-id` | no | the workflow run id | `ARTEFACTFLOW_BUILD_ID` | Identifier of the build |
| `pipeline-id` | no | the workflow run number | `ARTEFACTFLOW_PIPELINE_ID` | Identifier of the pipeline |
| `lifecycle` | no | — | `ARTEFACTFLOW_LIFECYCLE` | One of `pre-alpha`, `alpha`, `beta`, `release`, `end-of-life` |
| `build-state` | no | — | `ARTEFACTFLOW_BUILD_STATE` | One of `pending`, `building`, `success`, `failed`, `cancelled` |
| `is-default` | no | `true` | `ARTEFACTFLOW_IS_DEFAULT` | Mark this version as the artefact's default |
| `note` | no | — | `ARTEFACTFLOW_NOTE` | Free-text note, at most 4096 characters |
| `bom-ref` | no | — | `ARTEFACTFLOW_BOM_REF` | CycloneDX `bom-ref` for this version |
| `hash` | no | — | `ARTEFACTFLOW_HASH` | Content digests, one `alg:content` pair per line |
| `properties` | no | — | `ARTEFACTFLOW_PROPERTIES` | Custom `name=value` pairs, one per line |
| `external-references` | no | — | `ARTEFACTFLOW_EXTERNAL_REFERENCES` | Typed links, one `type url [comment]` per line |
| `build-timestamp` | no | — | `ARTEFACTFLOW_BUILD_TIMESTAMP` | When the build ran, RFC 3339 |
| `purl` | no | — | `ARTEFACTFLOW_PURL` | Package URL for this version |
| `cpe` | no | — | `ARTEFACTFLOW_CPE` | CPE 2.3 identifier, at most 512 characters |
| `mime-type` | no | — | `ARTEFACTFLOW_MIME_TYPE` | MIME type of the artefact, at most 128 characters |
| `size` | no | — | `ARTEFACTFLOW_SIZE` | Size of the artefact in bytes |
| `download-url` | no | — | `ARTEFACTFLOW_DOWNLOAD_URL` | Direct download URL for the artefact |
| `upload-vulnerabilities` | no | `false` | `ARTEFACTFLOW_UPLOAD_VULNERABILITIES` | Upload vulnerabilities after creating the version |
| `vulnerabilities-file` | when uploading | — | `ARTEFACTFLOW_VULNERABILITIES_FILE` | Path to the report: Trivy, Grype, CycloneDX, or native — detected automatically |
| `vulnerabilities-format` | no | detected | `ARTEFACTFLOW_VULNERABILITIES_FORMAT` | Force the format: `native`, `trivy`, `grype`, or `cyclonedx` |
| `vex-file` | no | — | `ARTEFACTFLOW_VEX_FILE` | Path to a CycloneDX VEX document to attach to the findings |
| `apply-vex-only` | no | `false` | `ARTEFACTFLOW_APPLY_VEX_ONLY` | Apply a VEX document to already-recorded findings, creating no version |
| `converted-output-file` | no | — | `ARTEFACTFLOW_CONVERTED_OUTPUT_FILE` | Write the converted native JSON here before uploading it |
| `if-exists` | no | `fail` | `ARTEFACTFLOW_IF_EXISTS` | `fail` or `skip` when the version already exists |

Booleans take `true` or `false`. Anything else is an error rather than a silent `false`, so a typo in `upload-vulnerabilities` cannot quietly skip the upload.

Every derived field can be overridden, which is what you want when the build did not come from this commit or this run — a re-tag, or an artefact built elsewhere and published from here.

### Naming the artefact

Artefacts are addressed by name, never by id. The match is exact and case-sensitive, and a name is unique within your organisation — which organisation that is comes from your credentials, so nothing else is needed to disambiguate it.

The API addresses artefacts by id internally, so the action resolves the name first. That costs one extra call per run and needs the `artefact:read` scope alongside `version:write`.

### Recording content digests

The `hash` input takes one `alg:content` pair per line, so several digests are easy to pass:

```yaml
    hash: |
      sha256: 40436b8ce2524c748d95dd8ad223170aff624196bcfe689e13381d01d0d8efb6
      SHA-512: ...
```

The algorithm is matched case-insensitively and normalised to the spelling the API expects, so `sha256`, `SHA_256` and `SHA-256` are all the same thing. That also means the `sha256:<hex>` digest a container build step emits can be pasted in as it stands. An unknown algorithm, or a digest outside 32 to 128 characters, fails before anything is published.

### Linking to related resources

`external-references` records typed links, one per line as `type url [comment]` — everything after the URL is the comment, so it can be a sentence:

```yaml
    external-references: |
      release-notes https://docs.example.com/releases/1.4.2 Release notes
      distribution https://registry.example.com/payment-service
      documentation https://docs.example.com/payment-service
```

The type must be one the API accepts: `vcs`, `website`, `distribution`, `issue-tracker`, `license`, `mailing-list`, `bom`, `build-system`, `release-notes`, `vulnerability-disclosure`, `security-contact`, `social`, `chat`, `support`, `documentation`, or `other`.

A `build-system` link back to the workflow run is added for you, so every version points at the build that made it. Supply a `build-system` reference of your own and yours is used instead — a version carrying two different answers to "which build made this?" is worse than one that trusts what you said.

### Describing the artefact itself

For a container image, a tarball, or anything else with an identity of its own:

```yaml
    purl: pkg:docker/acme/payment-service@1.4.2
    cpe: "cpe:2.3:a:acme:payment-service:1.4.2:*:*:*:*:*:*:*"
    mime-type: application/vnd.oci.image.manifest.v1+json
    size: "52428800"
    download-url: https://registry.example.com/payment-service/1.4.2
    build-timestamp: "2026-06-15T10:30:00Z"
```

`build-timestamp` is when the build ran, which is not the same as when the version was recorded — worth setting when the two can drift apart.

### Recording anything else

`properties` records free-form `name=value` pairs for whatever the dedicated inputs do not cover:

```yaml
    properties: |
      image-digest = sha256-3f9a2c
      runner = ubuntu-latest
```

Between the inputs above and `properties`, every field the create endpoint accepts is reachable from a workflow. There is a test that fails the build if that stops being true.

### Configuring through the environment

Every input can come from an `ARTEFACTFLOW_`-prefixed environment variable instead of `with:`. A job-level `env:` block then configures every step at once — including [suggest-version-action](https://github.com/artefactflow/suggest-version-action), which reads the same variables:

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      ARTEFACTFLOW_CLIENT_ID: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
      ARTEFACTFLOW_CLIENT_SECRET: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
      ARTEFACTFLOW_ARTEFACT_NAME: acme-payment-service
    steps:
      - id: next
        uses: artefactflow/suggest-version-action@v1

      - uses: artefactflow/publish-version-action@v1
        with:
          version: ${{ steps.next.outputs.version }}   # a `with:` value always wins over the variable
```

`ARTEFACTFLOW_API_URL` is worth setting at the workflow or organisation level when you self-host, so no individual step has to name your instance.

## Outputs

| Output | Description |
|---|---|
| `version` | The SemVer version that was published |
| `version-url` | API URL of the version |
| `created` | `true` when this run created the version; `false` when it already existed and `if-exists` was `skip` |
| `vulnerabilities-uploaded` | `true` when a vulnerability set was uploaded in this run |
| `analyses-applied` | Number of VEX assessments applied on the `apply-vex-only` path; `0` otherwise |
| `converted-vulnerabilities-file` | Path the converted native JSON was written to, when `converted-output-file` was set |

Outputs are written even when the step fails. If the version is created and the vulnerability upload then fails, `created` is still `true` — the rest of your workflow should not have to guess what state the artefact is in.

## Uploading vulnerabilities

Point the action at a report and it uploads the findings straight after creating the version:

```yaml
- uses: artefactflow/publish-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    version: 1.4.2
    upload-vulnerabilities: true
    vulnerabilities-file: trivy.json
```

The report can be your scanner's own output — a **Trivy** JSON report, a **Grype** JSON report, or a **CycloneDX** document — or ArtefactFlow's [native format](examples/vulnerabilities.json). You do not convert it yourself: hand the action the file your scanner already writes and it converts and uploads in the same step. The example above passes Trivy JSON directly.

The upload **replaces the complete set** of vulnerabilities recorded for the version — it is not an append. A scanner's report is its complete view of the artefact, so this is exactly what a fresh scan expresses: whatever the report contains becomes the version's recorded set, and anything previously recorded and absent from it is removed.

A scan that genuinely found nothing clears the set. With the native format, `{"vulnerabilities": []}` is how you say that explicitly. A file that is empty, or that never mentions `vulnerabilities` at all, is refused instead — a scan step that failed soft and wrote a placeholder should not silently delete a version's findings. A scanner report that parses but converts to nothing, when it was not an affirmatively empty scan, is likewise an error rather than a silent wipe.

The upload needs the `vulnerability:write` scope on top of the other two.

### Scanner formats

| Format | Recognised by | Notes |
|---|---|---|
| Trivy | `SchemaVersion` + `Results` | Schema version 2. `Results[].Vulnerabilities` grouped by identifier |
| Grype | `matches` + `descriptor.name` | Related vulnerabilities are not split into separate findings |
| CycloneDX | `bomFormat` | The `vulnerabilities` array, ratings and any embedded `analysis` |
| native | a `vulnerabilities` array, or a bare `[...]` | Forwarded exactly as written |

The format is **detected, not declared** — the action recognises which of these you gave it, so a wrong flag cannot make it misread one report as another. If detection is ever ambiguous, or a future report needs forcing, `vulnerabilities-format` overrides it; a document that does not match the override is an error, not a silent fallback. An unrecognised document is always an error rather than a best-effort guess.

Converting is deliberate about a few things that a naive `jq` script gets wrong quietly:

- **One finding per identifier.** Scanners emit a result per (vulnerability × package); the recorded finding lists the affected components under `affects[]` instead of repeating the vulnerability.
- **Severity is mapped, never guessed.** A severity the API does not know becomes `unknown` rather than an invented level.
- **Ratings keep their order, NVD first.** Scanners score by vendor and the recorded rating carries no vendor field, so the order is the only provenance — NVD leads.
- **A missing source is filled deterministically.** Where a report names no advisory source, it is derived from the identifier (`CVE-` → NVD, `GHSA-` → GitHub Advisory Database), falling back to the scanner's name — never left empty, which the API rejects.
- **Over-long descriptions are truncated, not fatal**, and the truncation is noted in the step log.

Native reports are the exception to conversion: they are forwarded as the exact bytes you wrote, so a value the model would treat as empty — a CVSS score of `0.0` on an informational finding among them — is never dropped. Unrecognised fields in a native report are an error rather than being silently discarded.

To see exactly what will be uploaded, set `converted-output-file` and the converted native JSON is written there before the upload runs — useful for archiving alongside the build, or for debugging a scanner-format question. Give it a path inside the workspace (a relative path such as `converted.json`); the action runs in a container, and only the workspace is visible to later steps, so a file written elsewhere would not be readable by a subsequent `upload-artifact` step.

Supported scanner schemas are exercised against the latest Trivy and Grype releases by a scheduled job ([`.github/workflows/scanner-drift.yml`](.github/workflows/scanner-drift.yml)), so a scanner changing its output shape is caught here rather than in your pipeline.

### VEX: attaching triage to findings

A raw scan is noisy — many CVEs in your dependencies are not exploitable in the way you use them. A [CycloneDX VEX](https://docs.artefactflow.com/guides/vulnerabilities/) document records that judgement, and this action attaches it to the findings so they arrive triaged instead of as a wall of untriaged red.

VEX is a **separate input from the scan**, because it is an overlay rather than a scan of its own — a VEX document carries assessments and usually no severities, so treating it as a third report format would produce findings with no rating. Supply it alongside your scan and it is merged into the same upload:

```yaml
- uses: artefactflow/publish-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    version: 1.4.2
    upload-vulnerabilities: true
    vulnerabilities-file: trivy.json
    vex-file: vex.json
```

Each VEX entry is matched to a finding by vulnerability identifier and contributes its `state`, `justification`, `response`, and `detail`. A `state` or `justification` the API does not accept is an error naming the finding, not a silent drop. An assessment matching no finding is reported as a warning — it usually means the scan and the VEX are from different builds.

When findings are already recorded and you only want to re-triage them — no new scan, no new version — use `apply-vex-only`:

```yaml
- uses: artefactflow/publish-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    version: 1.4.2
    apply-vex-only: true
    vex-file: vex.json
```

This applies each assessment to the finding already recorded for that identifier, one at a time, and creates nothing. It is not atomic across findings: the action reports how many were applied, warns about any that matched no recorded finding, and fails the run — without reporting success — if any assessment could not be applied, so a half-applied set is never mistaken for a clean one. Applying VEX this way updates a finding's state, which the API requires, so a VEX entry carrying only a justification cannot be applied on its own.

## Re-runs, and versions that already exist

By default, creating a version that already exists fails — publishing the same version twice usually means something upstream went wrong, and quietly accepting it hides that. When a re-run is legitimate, say so:

```yaml
    if-exists: skip
```

With `skip`, an existing version is treated as success. The existing version is left exactly as it is and no fields are changed, but a configured vulnerability upload still runs — so re-running the job converges on the state you asked for. The `created` output tells you which happened.

## Examples

### Suggest the version, then publish it

The two actions are designed to be used together, and share the same credentials and artefact name:

```yaml
- id: next
  uses: artefactflow/suggest-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    bump: minor

- uses: artefactflow/publish-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    version: ${{ steps.next.outputs.version }}
```

### Publish an image with its digest and its scan

```yaml
- id: next
  uses: artefactflow/suggest-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service

- id: build
  uses: docker/build-push-action@v6
  with:
    push: true
    tags: ghcr.io/acme/payment-service:${{ steps.next.outputs.version }}

- uses: aquasecurity/trivy-action@master
  with:
    image-ref: ghcr.io/acme/payment-service:${{ steps.next.outputs.version }}
    format: json
    output: scan.json

- uses: artefactflow/publish-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    version: ${{ steps.next.outputs.version }}
    lifecycle: release
    build-state: success
    hash: ${{ steps.build.outputs.digest }}   # already of the form sha256:<hex>
    upload-vulnerabilities: true
    vulnerabilities-file: scan.json           # Trivy JSON, converted automatically
```

### Record pre-release builds without promoting them

A build off a feature branch is recorded, but should not become what the artefact resolves to:

```yaml
- id: next
  uses: artefactflow/suggest-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service

- uses: artefactflow/publish-version-action@v1
  with:
    client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
    client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
    artefact-name: acme-payment-service
    version: ${{ steps.next.outputs.rc }}
    lifecycle: beta
    is-default: false
    if-exists: skip
```

## Authentication

A service account is the only way the action authenticates. Create one in ArtefactFlow and give the action its **client id** and **client secret**; the action exchanges them for a short-lived token, uses it, and discards it. Nothing is cached between runs and no token is ever emitted as an output.

There is deliberately no way to hand the action an already-minted token. A token pasted into a workflow is usually a person's, which carries their full scope set, attributes every published version to them rather than to a machine identity, and stops working the day they leave. Requiring a service account keeps the credential least-privileged and auditable by construction.

The client id is the service account's own 24-character hex id — the same value shown as `id` when you create it. The secret starts with `afsa_` and is shown **once**, at creation and after a rotation. It cannot be retrieved later, and rotating invalidates the previous secret immediately, with no overlap — so update the repository secret in the same change.

Store both as encrypted secrets:

```yaml
with:
  client-id: ${{ secrets.ARTEFACTFLOW_CLIENT_ID }}
  client-secret: ${{ secrets.ARTEFACTFLOW_CLIENT_SECRET }}
```

The client id is not sensitive, so a repository or organisation **variable** is fine for it if you prefer (`${{ vars.ARTEFACTFLOW_CLIENT_ID }}`). The secret must be a secret.

### Scopes and team access

The service account needs `artefact:read` to resolve the name and `version:write` to create the version, plus `vulnerability:write` when the workflow uploads vulnerabilities or applies VEX.

A higher action on the same resource covers a lower one: `version:write` and `version:delete` both satisfy `version:read`, and likewise for `artefact:`. Its token will list only the highest action per resource, which is why a working account can show `version:write` and no `version:read` at all.

Scopes are fixed on the account when it is created and cannot be requested at token time; changing them means updating the account.

ArtefactFlow enforces a second axis alongside scopes: the account must belong to a team with **write** access to the artefact's group. A fresh service account with the right scopes but no team membership is still denied with a `403` — if you see one, check the team membership before the scopes.

A service account also carries its own expiry date, at most a year out. Once it passes, no new tokens can be minted and the action starts failing — extend it before it lapses.

The client secret is never logged, and it is redacted from every error the action produces. The minted token is masked in the workflow log as soon as it is issued, and scrubbed from any API response the action turns into an error. Note that secrets are not available to workflows triggered by pull requests from forks, so gate any step that needs one.

## Retries, timeouts, and what the action does on its own

A few behaviours are worth knowing about because they are invisible until they matter:

- **Transient failures are retried.** Connection errors, `429`, and `5xx` get up to three attempts with exponential backoff and jitter, honouring `Retry-After`. Permanent failures — anything else in the `4xx` range — fail immediately, because retrying them would only waste the job's time.
- **A retried create that then conflicts is treated as this run's own work.** If the first attempt failed transiently and the retry reports that the version already exists, the overwhelmingly likely explanation is that the first attempt did land and only its reply was lost. The action reports the version as created, uploads the vulnerabilities, and logs a warning saying so — failing there would break a pipeline that published correctly. A genuine duplicate conflicts on the first attempt and is not affected.
- **Each request times out after 60 seconds, and the whole run after 5 minutes.** A step that fails at around five minutes has hit the second of these.
- **`version-url` is derived when the API does not send a `Location` header**, and a relative `Location` is resolved against `api-url`, so the output is always usable as it stands.
- **The minted token and the client secret are both masked** with the runner before any request is made, and the token is scrubbed from any API response the action turns into an error.

## Permissions

The action itself only talks to the ArtefactFlow API and needs no GitHub token. Grant whatever the surrounding steps need.

## Requirements

This is a container action, so it runs on Linux runners only. Windows and macOS runners cannot run it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `service-account credentials are required` | `client-id`/`client-secret` were not set. Check the secret names — an unset secret expands to an empty string silently |
| ``input `client-id` must be the service account's 24-character hex id`` | The account's name was passed instead of its id |
| `HTTP 401: the client credentials were rejected` | Wrong client id or secret. The API cannot distinguish the two. A rotation invalidates the old secret immediately |
| `HTTP 401: the service account cannot mint tokens` | The account was deactivated, or its organisation is inactive |
| `HTTP 401: the service account has passed its expiry date` | Extend the account's expiry; it is capped at a year |
| `HTTP 402` | The organisation is over its plan limit. No retry or input change resolves it |
| `HTTP 403` | Missing `artefact:read`, `version:write`, or `vulnerability:write`, or the principal is not on a team with write access to the artefact's group |
| `resolve artefact "…": HTTP 404` | No artefact of that name in your organisation. The match is exact and case-sensitive |
| `upload vulnerabilities for version …: HTTP 404` | The version was deleted between the create and the upload |
| `version 1.4.2 ... already exists` | The version was published before. Set `if-exists: skip` if a re-run is expected |
| `version 1.4.2 was created, but the vulnerability upload failed` | The version is intact and nothing was partially recorded. Fix the cause and re-run the step to retry the upload alone |
| `parse vulnerabilities file …` | The report is not in the ArtefactFlow vulnerabilities format. Unknown fields are rejected on purpose |

Errors quote the API's own message and its log id, which is what to include when asking for help with a `403` or a `500`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

[Apache-2.0](LICENSE)
