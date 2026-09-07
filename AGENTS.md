# Contribution contract

This repository owns application GitOps composition for a single-owner homelab.
Its public source is consumed anonymously. Application repositories own images
and Helm charts; `platform` owns host and cluster lifecycle, namespace
prerequisites, controller authority, Git sources, reconciliation and recovery.

## Authority and publication

- The owner alone merges or pushes `main`, creates tags, rewrites history or
  deletes remote refs. Agents author signed changes on isolated task branches.
- Open agent-authored PRs as Draft. A distinct reviewer inspects the exact head;
  an independent coordinator may mark Ready after checks and findings pass.
  Ready never grants merge authority.
- Security changes require focused negative tests and an independent security
  review. Documentation changes receive a proportionate review.
- Use the owner's verified noreply identity for both commit metadata fields and
  sign every outgoing commit with the owner-authorized signing key. Do not
  change shared Git identity settings or add co-author trailers.
- Keep credentials, inventory, private operational evidence and workstation
  details outside this repository, including commit messages and PR bodies.
- Before every push, scan the exact outgoing history and working tree for
  secrets and private data. Do not bypass hooks, scans, checks or review.

## Application boundary

- Only declared application directories may contribute manifests, and the
  declaration is two exact maps in `scripts/validate.py`, never a pattern.
  Each directory contains one default-deny NetworkPolicy, OCIRepository and
  HelmRelease. `APPLICATIONS` is the ACTIVE set: it has published releases,
  acquired artifacts, and the acquisition receipt must bind exactly it.
  `PENDING_APPLICATIONS` is the narrower set for a workload whose publisher
  has cut no release: its directory is inventoried and byte-pinned, its
  selection may be ONLY the fail-closed sentinel digest, its release must be
  suspended and not ready, it contributes no receipt record, and no proposal
  may write its paths. Promotion is one reviewed change that moves an entry
  between the maps and adds its receipt record; a place is never reserved.
- Preserve the complete application source/chart/image/publisher identity.
  Select immutable digests and independently verify acquisition evidence.
- Default-deny policies move with application composition. Namespace creation,
  RBAC, controller installation and reconciliation definitions stay in platform.
- Never add credentials to Git or give Flux a Git credential or write access.
- Reject public Kubernetes entry points, host networking, storage activation,
  unknown resources, cross-namespace references and arbitrary Helm values.
- Production changes use the reviewed source and the existing reconcilers.
  Repository creation does not activate it as a production source. A live
  source move requires reviewed platform changes and current convergence and
  rollback evidence; never introduce parallel application reconcilers.
- Adding a workload or expanding a trust boundary requires a new reviewed
  threat-model decision. Workloads are currently trusted and owner-operated.

## CI and evidence

PR jobs are secretless with read-only default permissions, pinned actions and
tools, disabled checkout credential persistence, and GitHub-hosted runners.
Required checks validate manifest boundaries, acquired artifact identities,
history and privacy. No source-release publisher or cluster credential belongs
here. Source activation requires current proof that acquisition verification,
CI and repository protections pass. Repository content alone does not prove
live reconciliation or workload health.

## Generated application proposals

`scripts/updates.py propose` may create signed Draft application updates from a
clean current protected checkout. Its generated commit uses the owner identity
and the final line `- Application update proposer`. Only chart selection fields
and the complete acquisition receipt may change. Generated proposals receive
independent exact-head review and the same required CI and coordinator Ready
check as authored changes; there is no machine-proof review exemption. Repair
helper or fixture defects in a normal authored PR, then regenerate from merged
protected code. Never patch a generated head into a mixed code/promotion PR.
