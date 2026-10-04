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
plus the two server archives from 1.1.4 and four native CLI archives from 1.1.6, with uploaded
state, source-bound URLs and metadata matching the evidence.

Amended 2026-09-29: from 1.1.4 the producer also publishes one server archive per
image platform and declares them under `artifacts.server_archives`, keyed by
exactly `linux/amd64` and `linux/arm64`, each record exactly `name`, `digest` and
`size`. Acquisition requires that declaration from 1.1.4 and refuses it before.
Each name is the producer's `obsync-server-X.Y.Z-linux-<arch>.tar.gz`, each size
a positive integer within the producer's 64 MiB ceiling, and each uploaded asset
carries `application/gzip` with the declared digest and size. As with the native
files, this consumer never downloads, unpacks or runs an archive; the cluster
runs the signed image.

Amended 2026-10-03: the producer selected native Rust and a 1.1.x patch train.
From 1.1.6, `artifacts.cli_archives` contains exactly `linux-amd64`, `linux-arm64`,
`darwin-arm64` and `windows-amd64`. Each record has exactly `name`, `digest`,
`size`, `content_type`, `runtime` and `manifest_sha256`. Its name is
`obsync-cli-X.Y.Z-PLATFORM.zip`, digest a nonzero `sha256:` value, size a positive
integer at most the producer's 8 MiB limit, and content type `application/zip`.
The runtime object is exactly
`{"name":"native-rust","version":"1.98.0","delivery":"included"}`; the package
manifest hash is nonzero lowercase SHA-256 without a prefix. Before 1.1.6,
including legacy evidence, this declaration is refused. The superseded Node
`cli_bundle` proposal never shipped and is refused at every version.

The four uploaded ZIPs bring the closed Release inventory to eleven assets.
Each name, digest, size, content type and exact release URL must match. This
metadata describes the packaged native runtime; it does not prove installation.

This consumer verifies native asset metadata only. It does not download or
execute the native files or CLI ZIPs, validate their archive contents or native
attestations, prove catalog availability, or claim successful device
installation. Those remain producer
and device acceptance gates. The composition receipt continues to record the
verified chart/image and release-evidence digest; its format is unchanged.

No workload version, digest or acquisition receipt changes with this repair.
After independent review and owner merge, generate future application updates
from the protected helper using the normal signed Draft procedure. A revert
stops compatibility with future bare-tag releases; it does not alter any
selected or running application.
