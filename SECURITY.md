# Security

Use [GitHub private vulnerability reporting](https://github.com/snaraj/platform-k8s-infra/security/advisories/new)
for security findings. Include the affected commit and a minimal description without
credentials, private inventory or live operational evidence.

This is public configuration for a private, single-owner homelab running trusted
workloads. Public visibility does not grant access to the homelab. The owner
alone can merge protected changes. Routine selection changes must pass both the
closed composition check and fresh artifact verification.

The platform repository retains host, cluster and controller authority. This
repository contains no cluster credentials, source publisher or deploy job.
Flux source changes require separate review in platform and anonymous Git access.

CI uses GitHub-hosted runners. Repository and artifact checks have read-only
permissions; CodeQL receives only the additional permission needed to upload
security analysis. PR code does not receive repository secrets. Required checks
must be bound to GitHub Actions, and branch protection must be enforced without
a bypass for the core checks. A separate owner update rule must permit only
the owner's pull-request merges. Verify those settings against GitHub when
assessing readiness; this source file is not proof of their live state.
