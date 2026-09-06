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

## Initial composition

The first extraction preserves the existing application paths and all manifest
bytes. It contains naranjo.online and lidersea.com. Their acquisition receipt
records the currently selected source, chart and image bindings.

The standalone verifier checks the exact manifest boundary and independently
reproduces the selected artifact receipts. It retains chart/image digest,
publisher, provenance, immutable release and protected-source checks without
the platform source publisher, reviewer automation or cluster client.

```sh
python3 -I -B scripts/validate.py check   # offline manifest and receipt binding
python3 -I -B scripts/validate.py verify  # fresh public artifact verification
python3 -B -m unittest discover -s tests
```

Artifact verification requires the pinned Cosign version and configured GitHub
CLI read access. Registry reads use a separate empty Docker configuration and
do not consult an ambient registry credential helper. The receipt retains the
tool metadata from its original acquisition; ORAS is not required by this
verifier.

CI runs composition, complete outgoing-history privacy and secret checks,
fresh artifact verification, and Python CodeQL. Artifact verification has no
path filter: a structurally valid selection is never sufficient for merge.
The publication hook accepts one author branch at a time and scans
every outgoing commit, including material removed before the final tree.
Use `git -c core.hooksPath=.githooks push origin <task-branch>` after local checks.

This is a preparation scaffold. Hosted checks, repository protections and
independent review must pass before production can consume it.
The source move is a separate change in `platform`; the existing application
reconcilers and their ownership remain in place. Historical references in the
byte-preserved manifests point to the [platform architecture decisions](https://github.com/snaraj/platform/tree/main/docs/adr/).

Start with [AGENTS.md](AGENTS.md) for contribution and authority rules, and
[SECURITY.md](SECURITY.md) for the publication and reporting boundary.
