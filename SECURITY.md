# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it through GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. That opens a private channel visible only to maintainers.

Include what you did, what happened, and what you expected — a minimal reproduction is worth more than anything else. You will get an acknowledgement, and we will keep you updated as the report is triaged and fixed. Please give us a chance to ship a fix before disclosing publicly.

## Supported versions

Fixes go onto the newest major release, and the moving major tag (for example `v1`) is repointed at it. Pin to the major tag to pick fixes up automatically, or to a full release tag if you would rather review each change.

## Handling of credentials

This action takes a service account's client id and client secret as inputs, and exchanges them for a short-lived access token. The secret is used for exactly one thing — that exchange — and it is never written to a log line, an error message, or an action output; the error path for the exchange is explicitly scrubbed of it, because that is the one request that carries a credential. The minted token is masked in the workflow log as soon as it is issued, is never emitted as an output, and is discarded when the action exits. It is also scrubbed from any API response the action turns into an error, so a service or proxy that echoes the request back cannot turn that into a leak.

The action deliberately does not accept an already-minted bearer token. That would make it easy to hand it a person's token, which carries far more scopes than the three this needs and attributes published versions to a human rather than a machine identity.

Pass the client secret from an encrypted secret rather than inlining it, so the runner masks it in the log if anything ever does print it.

## Scope of what the action writes

This action writes to ArtefactFlow: it creates a version, and when configured it replaces that version's recorded vulnerabilities. The vulnerability upload is a **full replace** — the set it sends becomes the complete recorded set for that version, and anything previously recorded and absent from the file is removed. A workflow that uploads a truncated or empty report therefore deletes findings. Give the service account write access only to the groups whose artefacts the workflow is meant to publish to.
