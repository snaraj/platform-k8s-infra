# Security

Once repository setup is complete, use its GitHub private vulnerability reporting form for security
findings. Include the affected commit and a minimal description without
credentials, private inventory or live operational evidence.

This is public configuration for a private, single-owner homelab running trusted
workloads. Public visibility does not grant access to the homelab. The owner
alone can merge protected changes. Routine selection changes must pass both the
closed composition check and fresh artifact verification.

The platform repository retains host, cluster and controller authority. This
repository contains no cluster credentials, source publisher or deploy job.
Flux consumes it anonymously only after a separately reviewed source transition.

CI uses GitHub-hosted runners. Repository and artifact checks have read-only
permissions; CodeQL receives only the additional permission needed to upload
security analysis. PR code does not receive repository secrets. Required checks
must be bound to GitHub Actions, and branch protection must be enforced without
a bypass for the core checks before production use. A separate owner update
rule must permit only the owner's pull-request merges. These settings are
verified during repository initialization; this source file is not proof of
their live state.
