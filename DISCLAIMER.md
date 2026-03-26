# Disclaimer

`redis-stig-audit` is an independent, community-built security assessment project.

## What this project is

- A Redis container security benchmark draft plus a runtime audit tool
- A community effort intended to help operators review Redis deployments in containerized environments
- A practical evidence-generation workflow for internal reviews, pilot assessments, and security improvement work

## What this project is not

- **Not an official CIS benchmark**
- **Not a DISA STIG**
- **Not a NIST publication**
- **Not certified, endorsed, or approved by CIS, DISA, NIST, Redis Ltd., or any cloud provider**
- **Not a guarantee of compliance, security, or certification readiness**

## Positioning for v1.0

The current v1.0 release should be described conservatively as a **validated community-draft benchmark + runtime audit prototype**.

That means:
- the tool is real and tested
- the Docker fixture workflow has been validated
- the repository includes repeatable output artifacts and evidence collection
- some broader topology and platform scenarios are intentionally deferred beyond v1.0

See `docs/V1_RELEASE_BOUNDARY.md` for the exact v1.0 boundary and deferred backlog.

## Standards and trademark attribution

References in this repository to CIS, DISA, NIST, CMMC, MITRE ATT&CK, MITRE D3FEND, Redis, Docker, Kubernetes, AWS, GCP, or similar frameworks/vendors are for descriptive and interoperability purposes only.

All product names, standards names, and trademarks remain the property of their respective owners.

## Operator responsibility

Users are responsible for:
- validating findings in their own environments
- confirming whether controls apply to their deployment model
- obtaining professional review where required for audits or compliance programs
- deciding whether optional integrations or broader validation are needed before production use
