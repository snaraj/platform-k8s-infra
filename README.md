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
OCI chart source, a Helm release and a default-deny network policy. The current
applications are naranjo.online and lidersea.com. Their selected source, chart
and image bindings are recorded in the [acquisition receipt](docs/assurance/195-chart-acquisition-receipt.json).

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
