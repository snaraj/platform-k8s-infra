# Obsync release tag and evidence transition

The obsync publisher's native-install contract keeps immutable releases through
0.1.10 on prefixed GitHub tags and `release-manifest/v1`. From 0.1.11, GitHub tags
are the bare version and evidence uses
`https://github.com/snaraj/obsync/schemas/release-manifest/v2`. Image tags remain
`vX.Y.Z`; Helm chart tags remain `X.Y.Z`. The acquisition and update detector
choose this contract from the exact source repository and version. An absent or
malformed v2 declaration never enables legacy fallback. Other publishers retain
their existing format.

Acquisition binds release, chart and image tags independently while preserving
digest, signer, annotated source tag and protected-main ancestry checks. For v2,
the native file map is exactly `main.js`, `manifest.json`, `styles.css`; each
record has a SHA-256 digest, positive bounded integer size and exact content
type. The retained bundle declaration has the versioned bare-tag filename and
three-file contents. The immutable release must carry exactly those five assets,
plus the two server archives from 1.1.4, with uploaded state, source-bound URLs
and metadata matching the evidence.

Amended 2026-09-29: from 1.1.4 the producer also publishes one server archive per
image platform and declares them under `artifacts.server_archives`, keyed by
exactly `linux/amd64` and `linux/arm64`, each record exactly `name`, `digest` and
`size`. Acquisition requires that declaration from 1.1.4 and refuses it before.
Each name is the producer's `obsync-server-X.Y.Z-linux-<arch>.tar.gz`, each size
a positive integer within the producer's 64 MiB ceiling, and each uploaded asset
carries `application/gzip` with the declared digest and size. As with the native
files, this consumer never downloads, unpacks or runs an archive; the cluster
runs the signed image.

This consumer verifies native asset metadata only. It does not download or
execute the native files, validate their archive contents, prove catalog
availability, or claim successful device installation. Those remain producer
and device acceptance gates. The composition receipt continues to record the
verified chart/image and release-evidence digest; its format is unchanged.

No workload version, digest or acquisition receipt changes with this repair.
The reserved-file storage selection remains staged with `deploymentReady: false`.
After independent review and owner merge, generate future application updates
from the protected helper using the normal signed Draft procedure. A revert
stops compatibility with future bare-tag releases; it does not alter any
selected or running application.
