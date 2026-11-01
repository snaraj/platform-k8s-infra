# Threat-model decision: admitting hospedajedonlolo.com as a pending application

Date 2026-11-01. Status: proposed with
[issue #81](https://github.com/snaraj/platform-k8s-infra/issues/81). The
composition it accompanies is **pending and inert**: the selection is the
fail-closed sentinel, the release is suspended, and nothing in this repository
can fetch, render or run this workload until a later reviewed change activates
it.

The contribution contract requires a new reviewed threat-model decision for
"adding a workload or expanding a trust boundary". This is that decision for
`hospedajedonlolo-com`: the public, static, bilingual brochure page of a family
farm-stay, read by visitors from several countries, composed into its own
namespace `hospedajedonlolo-com`.

## 1. What is being admitted, and what is not

Admitted: a fourth application directory,
`kubernetes/websites/hospedajedonlolo-com/`, holding the same four manifests the
other applications hold — one default-deny NetworkPolicy (Ingress and Egress,
every Pod in the namespace), one OCIRepository, one HelmRelease, one
kustomization — shaped byte for byte like `lidersea-com`'s apart from names and
the pending inversions below.

It enters `PENDING_APPLICATIONS`, not `APPLICATIONS`, exactly as obsync entered
before its first release. Its publisher, `snaraj/hospedajedonlolo.com`, has cut
no release, so there is no acquired artifact and no receipt record to bind, and
reserving a place in the receipt closure would put a name there that no
acquisition ceremony resolved. Membership means:

- the directory is inventoried and byte-pinned like any other;
- its selection may be ONLY the all-zero sentinel digest — a real digest is
  refused, alone or with a regenerated pin;
- its release must be `suspend: true` with `deploymentReady: false`;
- it contributes no selection and no receipt record, and no generated proposal
  may write its paths;
- the publication surface admits this one directory as a literal in its exact
  alternation, never as a pattern.

Not admitted, and each is a separate later decision:

- **No running workload.** The source selects a digest no registry resolves,
  so source-controller produces no artifact and the suspended release has
  nothing to install. What `deploymentReady: false` renders is a property of a
  chart that has not been published, so this document does not describe it;
  while pending, nothing renders at all. The reconciler that will select this
  directory is a `snaraj/platform` object and is not created here.
- **No storage activation.** This repository's manifests declare no volume,
  claim or class, and the existing executable refusal covers this directory as
  it covers the others. The site's media volume and its claim are provisioned
  by the operator out of band; the signed chart only mounts that claim
  read-only and creates none. Admitting that mount is a platform decision and
  is not taken here.
- **No public Kubernetes entry point** — no Ingress, NodePort, LoadBalancer,
  hostPort or host networking (§3).

## 2. Trust posture

The contract records that "workloads are currently trusted and owner-operated",
and this one does not change that. The owner operates the site and defines all
of its content; no other principal has an account, because there are no
accounts.

It is public, like naranjo.online and lidersea.com, and admits the same class of
untrusted principal those two admit — an anonymous visitor reading static
content — and no new one. The workload is one static page (HTML, CSS,
JavaScript and bundled fonts), photographs and one short video. **It accepts no
input on the server.** Its booking form is assembled in the visitor's browser
and handed to a messaging link or the visitor's own mail client; there is no
session, no cookie set by the origin, no database and no upload path. The
origin's only writes are request log lines, which carry no client address.

What a loss would cost, in rank order, and therefore what the controls protect:

1. the domain's trust with guests — a spoofed booking message or a hijacked page
   harms real people and the business;
2. the other tenants on the same node — this site must never become a step
   toward them;
3. availability for visitors planning trips from abroad;
4. content integrity — the text, photographs and video reach visitors unchanged;
5. visitor privacy — the third parties the page calls are declared by the
   site's own repository.

Item 2 is this repository's to hold. The namespace is its own policy and quota
boundary; the default-deny policy here denies every ingress and egress edge for
every Pod in it, and only the signed chart's own policy may then admit this
site's connector to the site's port. Restricted Pod Security, the quota, RBAC,
a workload without a service-account token, a read-only root and dropped
capabilities are `snaraj/platform` admission and source properties, asserted
there and in the source repository rather than restated here as guarantees
this repository can check. Mail, DNS, certificate and edge controls for items
1 and 4 are account-side and are proven by their own evidence, not by anything
in this repository.

## 3. Transport: public, through the site's own Tunnel

The site is reached publicly at hospedajedonlolo.com through **its own per-site
Cloudflare Tunnel** and its own connector, so neither the tunnel credential nor
the connector is shared with another site: a stolen credential or a compromised
connector serves this site's route and no other. TLS terminates at the edge.
The connector is a platform workload owned by `snaraj/platform`.

**Connector to origin is plain HTTP inside the cluster**, within the namespace's
default-deny boundary. This is the same accepted decision the two existing
sites carry, and it is accepted on the same terms: the hop never leaves the
node, the only admitted ingress edge is this site's connector to this site's
port, the content is public, and there is no credential, cookie or form body
on the wire to protect. There is no origin address, NodePort, LoadBalancer,
hostPort or Ingress; the tunnel is the only path in.

## 4. Supply chain and identity

The publisher contract is identical to naranjo.online's: a signed OCI chart at
`oci://ghcr.io/snaraj/charts/hospedajedonlolo-com`, the workload image
`ghcr.io/snaraj/hospedajedonlolo-com` carried only by that chart, and a keyless
cosign signature whose identity is that repository's `release-publisher.yml`
workflow on `refs/heads/main`, issued by GitHub Actions.

The source's verify matcher is closed whole, anchored end to end and
dot-escaped, so the three sibling publishers, another workflow in the same
repository, a run at any other ref and a look-alike host are all refused. The
identity tuples never couple: a test substitutes every other declared
application's publisher subject and chart repository into this source with a
regenerated pin and requires a refusal for each.

That `refs/heads/main` is gated by a ruleset with no bypass actors in the
source repository is a precondition of activation, proven then. It is not
asserted for a repository that has published nothing.

## 5. Activation sequence

1. **This change** — Ready and the owner's merge require source approval at the
   exact head and green checks, nothing live. It admits the pending directory
   and this decision.
2. **Platform prerequisites**, in `snaraj/platform` under their own review: the
   namespace, its quota and Pod Security, the `helm-reconciler` account and its
   RBAC, the reconciler that selects this directory (created suspended), the
   connector, and any admission the read-only media mount needs.
3. **Operator prerequisites** under their own authorization: the media volume
   and claim, and the tunnel credential.
4. **Activation is ONE later reviewed change in this repository**, made by the
   coordinator after the publisher's first release: it moves the slug from
   `PENDING_APPLICATIONS` to `APPLICATIONS`, replaces the sentinel with the
   acquired digest, adds the acquisition receipt record (chart and image
   digests, publisher, provenance, immutable release and protected-source
   ancestry, reproduced by fresh verification), unsuspends the release, and
   updates the tests that name this slug. The two rule sets are opposites, so it
   cannot half-land: the sentinel while active fails, and a real digest while
   pending fails.
5. **`deploymentReady: true`** is its own reviewed decision against proven
   prerequisites, never a side effect of selecting a chart.
6. **The operator lifts the reconciler's suspension**, and the public route is
   enabled last, under its own authorization.

## 6. Accepted risks

- Plain HTTP between the connector and the site inside the namespace's
  default-deny boundary, as for every site (§3).
- The video is not delivered. The platform keeps public video delivery a
  `NO-GO` (its ADR 0006 and safety invariant 13), so the site verifies the
  film on its volume but answers 404 for it until the owner lifts that
  boundary.
- HSTS does not protect a visitor's very first request, and preload is a
  one-way decision left to the owner.
- `PENDING_APPLICATIONS` gains its second-ever entry. The state itself is not
  new — it was reviewed with obsync — and none of its rules change; its tests
  now run against this declared entry as well as a synthetic fixture.

## 7. Activation record

Step 4 landed with issue #86 at the first release, v0.1.1. The chart is
`ghcr.io/snaraj/charts/hospedajedonlolo-com:0.1.1` at
`sha256:2cd06606dbd39bab83ce86ab3f0c432afe8380e1367a92de51131d3ee7280a61`, and
the image is `ghcr.io/snaraj/hospedajedonlolo-com:v0.1.1` at
`sha256:0f945357b61044aec9a52c9eedaa6b1d6f894f0d24b76aa867c7494d0731d42d`. The
chart signature, the image provenance, the immutable Release and its
manifest, and the annotated tag's protected-source ancestry were all
verified with the pinned cosign. The release is unsuspended and still
`deploymentReady: false`; step 5 is next.

- Opus5.5
