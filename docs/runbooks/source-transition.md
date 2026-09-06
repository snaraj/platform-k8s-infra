# Change the application Git source

The Git source and application reconcilers belong to `platform`. Creating or
merging this repository does not change the source consumed by a cluster.
Use a reviewed platform change to move that source; keep each application's
existing reconciler and its ownership intact.

## Preconditions

- Record the current source revision, application selections, reconciler
  health and rollback target in private operational evidence.
- Validate the candidate composition and freshly verify its acquisition
  receipt. Required hosted checks and independent review must pass at the
  exact candidate revision.
- Verify repository protections, owner-only merge authority and anonymous Git
  reads. No Git write credential or cluster credential belongs here.
- Confirm that namespaces, RBAC, controller authority and recovery remain in
  platform. Preserve the complete application publisher and artifact identity.

## Transition and validation

1. Prepare a platform PR changing the existing source configuration. Compare
   the source and destination application manifests; a source-only move must
   preserve their bytes and paths.
2. Review the source change and its rollback before the owner merges it. Do
   not create parallel reconcilers or broaden controller permissions.
3. Observe the source revision, both application reconciler conditions,
   selected artifacts and workload health against the approved change.
4. Verify the relevant namespace and network controls and public application
   health. Keep private inventory and live evidence outside Git and PRs.

On unexpected divergence, stop further changes and follow the reviewed platform
rollback to the recorded source and selections. Recheck convergence and health;
a reverted commit alone does not prove recovery.
