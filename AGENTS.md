# Contribution contract

This repository owns application GitOps composition for a single-owner homelab.
Its public source is consumed anonymously. Application repositories own images
and Helm charts; `platform` owns host and cluster lifecycle, namespace
prerequisites, controller authority, Git sources, reconciliation and recovery.

## Authority and publication

- The owner alone pushes `main`, creates tags, rewrites history or deletes
  remote refs. Agents author signed changes on isolated task branches.
- Open agent-authored PRs as Draft. A distinct reviewer inspects the exact head;
  the coordinator marks Ready and merges (squash) a PR current with `main`,
  green and App-approved at that head, then drives delivery (owner direction,
  2026-11-03). Authors and reviewers never merge.
- Re-cut a behind PR on current `main` (fresh branch and PR, never a rebase or
  force-push). It keeps its review only if the App's latest receipt approves a
  head GitHub recorded for the old PR, whole-file `git patch-id --verbatim` from
  each merge base matches, and every required check is green at the new head.
- Security changes require focused negative tests and an independent security
  review. Documentation changes receive a proportionate review.
- Use the owner's verified noreply identity for both commit metadata fields and
  sign every outgoing commit with the owner-authorized signing key. Do not
  change shared Git identity settings or add co-author trailers.
- Keep credentials, inventory, private evidence and workstation details out of
  the repository, commits and PR bodies, and scan the exact outgoing history and
  tree for them before every push. Never bypass hooks, scans, checks or review.

## Application boundary

- Only application directories declared in two exact maps in
  `scripts/validate.py`, never a pattern, may contribute manifests; each holds
  one default-deny NetworkPolicy, OCIRepository and HelmRelease. `APPLICATIONS`
  is the ACTIVE set, with published releases, acquired artifacts and a receipt
  binding exactly it. `PENDING_APPLICATIONS` holds a workload whose publisher
  has cut no release: inventoried, byte-pinned, selecting ONLY the fail-closed
  sentinel digest, release suspended and not ready, no receipt record, no
  proposal writing its paths. Promotion moves an entry between the maps with its
  receipt record in one reviewed change; no place is reserved.
- Preserve the complete application source/chart/image/publisher identity.
  Select immutable digests and independently verify acquisition evidence.
- Default-deny policies move with application composition. Namespace creation,
  RBAC, controller installation and reconciliation definitions stay in platform.
- Never add credentials to Git or give Flux a Git credential or write access.
- Reject public Kubernetes entry points, host networking, storage activation,
  unknown resources, cross-namespace references and arbitrary Helm values.
- Production changes use the reviewed source and the existing reconcilers. A
  live source move requires reviewed platform changes with current convergence
  and rollback evidence; never introduce parallel application reconcilers.
- Adding a workload or expanding a trust boundary requires a new reviewed
  threat-model decision. Workloads are currently trusted and owner-operated.

## CI and evidence

PR jobs are secretless, read-only by default and GitHub-hosted, with pinned
actions and tools and no persisted checkout credential. Required checks validate
manifest boundaries, artifact identities, history and privacy; no source-release
publisher or cluster credential belongs here. Activating a source requires
current proof that acquisition verification, CI and protections pass. Repository
content alone never proves live reconciliation or workload health.

## Generated application proposals

`scripts/updates.py propose` may create signed Draft application updates from a
clean current protected checkout. Its generated commit uses the owner identity
and the final line `- Application update proposer`. Only chart selection fields
and the complete acquisition receipt may change. Generated proposals receive
independent exact-head review and the same required CI and coordinator Ready
check as authored changes; there is no machine-proof review exemption. Repair
helper or fixture defects in a normal authored PR, then regenerate from merged
protected code. Never patch a generated head into a mixed code/promotion PR.
