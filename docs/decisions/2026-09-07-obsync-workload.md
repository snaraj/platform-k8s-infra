# Threat-model decision: admitting obsync as a third application

Date 2026-09-07. Status: reviewed decision required before activation; the
composition this document accompanies is committed **pending and inert**.

The contribution contract requires a new reviewed threat-model decision for
"adding a workload or expanding a trust boundary". This is that decision for
`obsync`, a personal live-sync server for the owner's notes, composed into
namespace `obsidian`.

## 1. What is being admitted, and what is not

Admitted: a third application directory, `kubernetes/websites/obsync/`, holding
the same four manifests the two existing applications hold — one default-deny
NetworkPolicy, one OCIRepository, one HelmRelease, one kustomization.

Not admitted, and each is a separate later decision:

- no active application (the entry is `PENDING_APPLICATIONS`, not
  `APPLICATIONS`, so it contributes no selection and no receipt record);
- no resolved chart digest (the selection is the all-zero sentinel, and a real
  digest is REFUSED while pending);
- no running workload (`suspend: true`, `deploymentReady: false`, both required
  by the validator rather than merely written);
- no storage activation (§4);
- no public entry point of any kind (§3).

## 2. Trust posture

The contract records that "workloads are currently trusted and owner-operated",
and this one does not change that: the server runs the owner's own notes for the
owner's own devices, and no other principal has an account on it. It is a larger
workload than the two websites rather than a differently trusted one.

Three properties keep it inside the existing posture rather than widening it:

- **The server is blind to content.** Vault data is encrypted on the device
  before it is sent, so a compromise of the server, its volumes, or a backup of
  either yields ciphertext. That is a property of the application, asserted by
  its own repository's tests, and this repository does not restate it as a
  guarantee it cannot check — it is recorded here because it is why a personal
  notes corpus on a homelab node is an acceptable risk at all.
- **The server authenticates every device itself.** Nothing in the transport is
  treated by the application as an authentication result.
- **The namespace is a separate policy and quota boundary**, with its own
  default-deny NetworkPolicy in this repository and its own RBAC, budget and
  Pod Security enforcement in `platform`.

## 3. Transport: private, with no public entry point

This workload is NOT public content. Its dashboard is an administrative surface
and its API is what the owner's devices speak. It is therefore reached over a
**private Cloudflare Tunnel route, from WARP-enrolled devices only** — no public
hostname, no public DNS record, no proxied CNAME, and no Access application in
front of a public origin. A device that is not enrolled has no endpoint to
reach, which is a stronger property than any policy evaluated after a request
arrives.

**The private hostname and the private route's address are operator inputs and
appear nowhere in this repository, in either half of the composition, or in any
commit message or pull-request body.** The application's `publicUrl` value is
therefore the empty string, not a placeholder hostname: the chart's closed
schema admits the empty string and the application treats an unset public URL as
unset, so the pairing page simply shows none and a device is given the address
by the person setting it up. A sentinel hostname would have been a habit of
carrying the real one later, and the index is public.

Two consequences are stated as values in the HelmRelease, and the wrong value in
either place fails closed but totally:

- `edge.mode: none`. The alternative makes the server REQUIRE Cloudflare's
  connecting-address and request-id headers on every request. Those are set by
  the HTTP edge on a public hostname path, which a private route never
  traverses, so that value would refuse every request from the owner's own
  device.
- `trustedProxyCidrs: []`. Empty is the strict setting: the server then
  believes only its peer's address, never a forwarded one.

**TLS terminates in the cluster**, in a dedicated proxy workload — a separate
platform workload, never a sidecar — because the server speaks plain HTTP. The
admitted edges are exactly: connector to proxy on the proxy's TLS port, proxy to
application on the application's HTTP port, and **no connector-to-application
edge in any contributing policy**. A connector-matching rule on the application
would hand the connector that cleartext listener, which is the specific
misconfiguration this design exists to prevent.

That proxy's exact identity arrives with the security lane's own reviewed
deployment change. Until then the application's `ingress.peer*` values name a
declared placeholder (`obsync-tls-proxy` / `obsync-tls-proxy-pending` in
`obsidian`) that no Pod carries, so the rendered ingress policy admits nothing
and the workload stays non-deployable. **That is the intended interim state.**
An absent matching proxy is a route that does not work; naming the connector
"temporarily" would have been a route that works and should not.

## 4. Storage: claim-backed volumes, and the admission decision this needs

Unlike the two websites, this workload is stateful. Its chart creates two
PersistentVolumeClaims at render time — a blob store and a journal — bound to
volumes an operator provisions out of band on local SSD.

### What actually makes it single-writer, since `ReadWriteOnce` does not

`ReadWriteOnce` excludes other NODES, not other Pods. On a single-node cluster
that exclusion is vacuous: two Pods scheduled to the same node may both mount
the same claim read-write and both write the journal. Any statement that the
access mode alone prevents a second writer is wrong, and this document does not
make one. `ReadWriteOncePod`, which WOULD express one-Pod exclusivity, needs a
CSI driver and is not available on the non-CSI local class this workload uses.

The boundary is three things, none of them the access mode, and they do not
divide the way the word "lock" suggests. Stated as it is:

1. **The server's own exclusive advisory lock on the journal root — refuses
   COOPERATIVE duplicates, and nothing more.** `Store::open` takes an exclusive
   advisory lock on `v1/lock` of the journal volume before reading a byte (Rust
   `File::try_lock`, flock semantics); a second `obsyncd` opening the same
   `v1/lock` refuses to start, logging
   `event=store_open decision=refused reason=journal_locked`, covered by
   `storage::tests::a_second_process_on_the_same_journal_refuses_to_start` and
   image-smoke property 7, which starts a second container on the same volumes
   beside a serving one and requires the refusal.

   What that buys is real but narrow: it stops this deployment colliding with
   ITSELF — a rollout surge that briefly overlaps two Pods, an operator running
   `check` or `export` beside a live `serve` (both refuse while `serve` holds
   the lock). Every one of those is a cooperative process that opens the path it
   is pointed at.

   It does NOT exclude an arbitrary Pod, and this document does not claim it
   does. Owning a directory IS rename authority: the volumes are owned by
   `65532`, so any process running as `65532` with the journal mounted — a
   second Pod of this same workload included — can rename `v1` aside, create a
   fresh `v1`, and take an uncontended lock on a different file. The lock holds;
   it holds on a file nobody else wanted. No in-process lock can close that,
   because the attacker and the holder have equal authority over the namespace
   the lock lives in.

   **Exclusion of an arbitrary Pod is therefore the PLATFORM's admission
   decision, not the application's lock**: `replicas: 1` and `strategy:
   Recreate` below, the platform's refusal to grant any other workload a claim
   on these volumes, and this repository's own refusal to let a composition
   value ask for a second Pod. The lock is the last line under those, not a
   substitute for them.

   The host-directory condition constrains OTHER accounts only — it keeps uids
   and gids that are not this workload off the path; it grants this workload's
   own uid nothing it did not already have:
   `/mnt/local-pie-ssd/obsidian/obsync-blobs` and
   `/mnt/local-pie-ssd/obsidian/obsync-journal` created `65532:65532`, mode
   `0700`, with root-owned parents that are not group- or world-writable
   (sticky is acceptable) and no symlink anywhere on the path.

   The first head to carry the lock, `snaraj/obsync` `9a5e96d`, left the
   CROSS-ACCOUNT path open as well: the chart still set `fsGroup` and the
   posture accepted a group-writable parent, so a process merely sharing a gid
   could perform the same rename. The candidate head `ef01d5d` (group write
   refused regardless of gid, canonical-path refusal, no `fsGroup`) repairs that
   cross-account path **only** — the same-uid rename above is out of its reach
   by construction. **This document cites `ef01d5d` as a CANDIDATE, not as an
   established control: it is under review as this is written, and no activation
   may rely on it until that review returns an APPROVE at an exact head.** The
   reviewed head replaces this paragraph in the change that records it.
2. **`replicas: 1` in the chart**, which is not overridable from here: the
   chart's values schema is closed and exposes no replica count, so no platform
   value can ask for two.
3. **`strategy: Recreate`**, so a rollout terminates the old Pod before
   creating the new one rather than briefly running both.

Items 2 and 3 are properties of the signed chart, so the platform asserts them
over the RENDERED Deployment rather than trusting this description — see the
`obsidian` workload rule in the platform's Conftest suite. Activation cannot
proceed on a chart that could run two Pods.

**This repository activates no storage, and this commit does not weaken the rule
that says so.** The contract's own line is: "Reject public Kubernetes entry
points, host networking, storage activation, unknown resources, cross-namespace
references and arbitrary Helm values." `scripts/validate.py` now asserts that
executably rather than by implication: no manifest in the closed application set
may declare a `PersistentVolume`, `PersistentVolumeClaim`, `StorageClass`,
`CSIDriver`, `CSIStorageCapacity` or `VolumeAttachment`, or mount a
`persistentVolumeClaim`, `ephemeral` or `csi` volume. A negative test proves
each refusal.

The claims themselves come from the signed chart, which this repository never
renders. The gap is on the PLATFORM side, and it is real rather than
theoretical: that repository's workload-volume control admits only `emptyDir`,
`configMap`, `secret`, `projected` and `downwardAPI` as Pod volume sources, and
its repository validator denies the three storage kinds outright in any live
manifest. Neither is weakened by this work either.

**Proposed narrowing, for the security lane to decide — not taken here.** Admit
`persistentVolumeClaim` as a Pod volume source ONLY in this one application, and
ONLY for the two claims its chart names. Not as a general source, not for a
namespace, and never for the `PersistentVolume`, `StorageClass`, node path or
provisioner behind them, which stay bootstrap and operator owned. The existing
`naranjo-online` usage-export claims sit in exactly the same position today, so
the decision is not unique to this workload.

Until that decision and the host-side activation evidence both exist, this
namespace's storage is a NO-GO regardless of what any budget says, and the
`deploymentReady: false` value above is what holds the line.

## 5. The contract state this introduces, and why it is a security review

`PENDING_APPLICATIONS` is a new state inside a security validator, so it is
named here rather than left as an implementation detail. It is a NARROWING in
both directions:

- a pending application's `source.yaml` may select ONLY the sentinel digest —
  the exact inverse of the active rule, where the sentinel is refused. Neither
  rule can be deleted without a red run, and a promotion cannot half-land;
- a pending application's `release.yaml` must be `suspend: true` with
  `deploymentReady: false`;
- the acquisition receipt stays exact over ACTIVE applications only, so no name
  enters the receipt closure that no ceremony resolved;
- `updates.py` proposals cannot write a pending path: the allowed-path set is
  derived from the active map, and a test targets that set specifically rather
  than the changed-equals-planned arm beside it;
- the publication surface's directory alternation stays exact, so an undeclared
  fourth directory is refused there as well as by the inventory.

Promotion out of this state is ONE reviewed change that moves the entry between
the two maps and adds its acquisition receipt record. It cannot be pre-opened to
reserve a place, and this document does not authorize it.

- Fable5.1
