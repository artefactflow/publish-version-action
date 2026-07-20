# Publish Version

[![CI](https://github.com/artefactflow/publish-version-action/actions/workflows/ci.yml/badge.svg)](https://github.com/artefactflow/publish-version-action/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A GitHub Action that registers what your pipeline just built. It creates a version of an ArtefactFlow artefact from the build metadata your workflow already has — and, when you ask it to, records that version's vulnerabilities in the same step.

Most of what ArtefactFlow wants to know about a build is already in the workflow context: the commit, the branch, the run that produced it. So you name the artefact and the version, and the action derives the rest.

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
| `upload-vulnerabilities` | no | `false` | `ARTEFACTFLOW_UPLOAD_VULNERABILITIES` | Upload vulnerabilities after creating the version |
| `vulnerabilities-file` | when uploading | — | `ARTEFACTFLOW_VULNERABILITIES_FILE` | Path to the vulnerability report |
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

### Recording anything else

`properties` records free-form `name=value` pairs for whatever the dedicated inputs do not cover:

```yaml
    properties: |
      image-digest = sha256-3f9a2c
      runner = ubuntu-latest
```

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
    vulnerabilities-file: scan-results.json
```

The upload **replaces the complete set** of vulnerabilities recorded for the version — it is not an append. Send your scanner's whole list every time; anything previously recorded and missing from the file is removed.

An explicitly empty list is therefore how you record a clean scan: `{"vulnerabilities": []}` clears whatever was recorded before. A file that is empty, or that never mentions `vulnerabilities` at all, is refused instead — a scan step that failed soft and wrote a placeholder should not silently delete a version's findings.

The file must be in ArtefactFlow's own vulnerabilities format, shown in [examples/vulnerabilities.json](examples/vulnerabilities.json) and documented under [Vulnerabilities & VEX](https://docs.artefactflow.app/guides/vulnerabilities/). The action does not translate scanner-native output; convert your scanner's report to this shape in an earlier step. A bare JSON array of findings is accepted as well as the `{"vulnerabilities": [...]}` wrapper. Unrecognised fields are an error rather than being silently dropped — a typo that quietly discards half a report matters far more when the upload replaces everything.

The upload needs the `vulnerability:write` scope on top of the other two.

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

# Convert scan.json into the ArtefactFlow vulnerabilities format shown below, writing vulnerabilities.json.

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
    vulnerabilities-file: vulnerabilities.json
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

The service account needs `artefact:read` to resolve the name and `version:write` to create the version, plus `vulnerability:write` when the workflow uploads vulnerabilities.

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
