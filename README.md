# Platform Kubernetes infrastructure

Application GitOps composition for a Kubernetes homelab. This repository selects
verified application releases and defines their namespaced deployment policy.
The platform consumes signed Helm charts and images built in their source
repositories.

| Repository | Responsibility |
| --- | --- |
| `platform` | Host and cluster lifecycle, installed security controls, namespace prerequisites, controller authority, Git sources and recovery |
| `platform-k8s-infra` | Application composition, default-deny policies and verified chart selections |
| Application sources | Application code, image builds, Helm charts and signed releases |

The security model is a public configuration repository for a private,
single-owner homelab running trusted workloads. Only the owner merges protected
changes. Flux reads Git anonymously; selected OCI artifacts are digest-bound
and verified against each application's exact publisher identity.

## Application composition

Application manifests live in `kubernetes/websites/`. Each application has an
OCI chart source, a Helm release and a default-deny network policy. The active
applications are naranjo.online, lidersea.com and obsync. Their selected source,
chart and image bindings are recorded in the [acquisition receipt](docs/assurance/195-chart-acquisition-receipt.json).

`obsync` was composed pending and activated by this change: its publisher cut
v0.1.4, so the fail-closed sentinel is replaced by the acquired digest, the
release is unsuspended, and it holds a receipt record like any other active
application. Its `deploymentReady` value stays `false` — that one describes the
cluster, not this repository, and selecting a verified chart does not move it.
At `false` the selected chart still renders its object set and holds the
Deployment at zero application replicas; the operator's reconciler, created
suspended, is what keeps any of it from reaching the cluster.
`PENDING_APPLICATIONS` is now empty — the state is unused, not retired, and the
next application whose publisher has not cut a release enters it. The decision
admitting obsync is
[docs/decisions/2026-09-07-obsync-workload.md](docs/decisions/2026-09-07-obsync-workload.md).

The verifier checks the allowed manifest boundary and independently reproduces
the acquisition receipt from public artifacts. Verification covers chart and
image digests, publisher identities, provenance, immutable releases and
protected source history.

## Validate a change

```sh
python3 -I -B scripts/validate.py check   # offline manifest and receipt binding
python3 -I -B scripts/validate.py verify  # fresh public artifact verification
python3 -B -m unittest discover -s tests
```

Artifact verification requires the Cosign version pinned in
[the tool installer](scripts/ci/install-tools.sh) and configured GitHub CLI read
access. Registry reads use a separate empty Docker configuration.

CI runs composition, complete outgoing-history privacy and secret checks,
fresh artifact verification, and Python CodeQL. Artifact verification has no
path filter: a structurally valid selection is never sufficient for merge.
The publication hook accepts one author branch at a time and scans
every outgoing commit, including material removed before the final tree.
Use `git -c core.hooksPath=.githooks push origin <task-branch>` after local checks.

Between changes, **Selected artifact verification** runs daily at 07:19 UTC.
Its manual workflow dispatch accepts `main` only. It repeats `make verify`
against the manifests and acquisition receipts at the triggering main commit,
including older releases still selected for deployment. Failures remain failed
workflow runs. A second read-only check compares both selections with their
latest immutable final releases; missing inventory, malformed releases,
regressions and newer versions fail the run. The job never publishes or deploys.
This identity check does not rescan images for newly disclosed vulnerabilities.

Dependabot checks GitHub Actions updates every day at 07:31 UTC, including
weekends. CodeQL's paired actions are grouped for both version and security
updates. Proposals still need the repository's normal validation, independent
review and owner merge. GitHub's advisory-driven security updates are separate
from the scheduled version checks.

## Propose application updates

From a clean dedicated checkout at current protected `main`, choose a new
worktree outside that checkout:

```sh
python3 -I -B scripts/updates.py check-latest
python3 -I -B scripts/updates.py propose --worktree /absolute/new/worktree
```

`check-latest` returns `CURRENT`, `DRIFT` or a failed `UNKNOWN` check. The
scheduled workflow also verifies the currently selected artifacts; checking
which release is latest alone does not establish artifact authenticity.

`propose` independently acquires both applications' latest immutable releases,
reproduces unchanged selections, and refuses regressions or changing release
metadata. It creates a new worktree containing only changed chart versions and
digests plus the complete acquisition receipt. Existing checks and fresh
artifact verification run before signing and the mandatory publication hook
runs before the explicit branch push. GitHub CLI must already act as the owner;
exactly one owner-registered SSH signing public key must be loaded in the agent.
The helper checks Cosign 3.1.3 and ORAS 1.3.4 compatibility versions for receipt
metadata, using the existing Python client for registry reads. It neither
provisions credentials nor changes Git configuration. Origin must name this
repository and have no explicit push URL; the command supplies exactly one SSH
push URL for that invocation.

The result is one signed Draft PR. A distinct reviewer, successful required CI
and an independent Ready coordinator remain mandatory; only the owner merges.
A repository-local lock serializes proposal writers, and existing open update
proposals block another proposal. Changed bases and
partial publication fail closed: preserve the branch/worktree and inspect the
actual PR state before retrying. The helper never rewrites or deletes refs,
changes Ready state, installs a scheduled writer, or performs a deployment.
A scheduler must use this destination only after its source is activated and
must stop the previous composition writer first.

## Operation

`platform` defines which Git source the cluster consumes and owns the
application reconcilers. Merging here updates the declared composition;
deployment also depends on that source configuration and successful Flux
reconciliation. Repository checks establish artifact and configuration
properties; live health requires current cluster evidence.

The [source transition runbook](docs/runbooks/source-transition.md) covers
changing the cluster's Git source, including convergence and rollback checks.
The [platform architecture decisions](https://github.com/snaraj/platform/tree/main/docs/adr/)
describe the host, cluster and controller boundaries.

Start with [AGENTS.md](AGENTS.md) for contribution and authority rules, and
[SECURITY.md](SECURITY.md) for the publication and reporting boundary.
