# Syslog Home Assistant AddOn (applestoapples fork)

![Supports aarch64 Architecture][aarch64-shield] ![Supports amd64 Architecture][amd64-shield]

Fork of [UberKitten/ha-addon-syslog](https://github.com/UberKitten/ha-addon-syslog) (itself a fork of [mib1185/ha-addon-syslog](https://github.com/mib1185/ha-addon-syslog)).

Forwards HAOS journal entries to a remote syslog server. UDP and TCP transport supported, including TLS-encrypted transport. Defaults to RFC 5424 format for compatibility with modern log receivers (e.g., Datadog).

## How to use this repository

Navigate to **Settings** -> **Add-ons** -> **Add-on store** -> **3 dots top right corner** -> **Repositories**, then add `https://github.com/applestoapples/ha-addon-syslog` as a new repository.

Or use the *My Home Assistant* link:

[![Open your Home Assistant instance and show the add add-on repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fapplestoapples%2Fha-addon-syslog)

## How to configure this add-on

See the add-on [docs](syslog/DOCS.md).

[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg

## Maintenance and automatic updates

GitHub Actions rebuilds both supported architectures every Monday at 08:23 UTC
(04:23 Eastern daylight time / 03:23 Eastern standard time), and on main changes.
Every build pulls the current Home Assistant Bookworm base and refreshes package
layers without cache. Unit tests and a smoke test of each resulting image must pass
before that exact artifact is pushed. Base digest and source revision are recorded
in OCI labels. Application behavior and the Debian release remain unchanged.

A successful publication gets a unique numeric patch version (run number and attempt
plus a monotonic floor), immutable version tags, and `latest` tracking tags. Only
after both images are published does the workflow update `syslog/config.yaml` and
create a GitHub release. Home Assistant Supervisor detects the changed version and
uses its native per-app Auto update setting. Unraid's Docker updater does not manage
apps inside the HA VM. Keep rollback backups and previous version tags.

Dependabot checks GitHub Actions and the Dockerfile base weekly. The Dockerfile's
amd64 default is the canonical base track; CI substitutes the matching aarch64 name.
Base-release migration PRs require review; no automatic merge is configured.
Fresh builds follow new digests on Bookworm even when no Dependabot PR is needed.
`syslog/build.yaml` must remain aligned if the base branch changes. A successful
build proves freshness, not absence of CVEs or ongoing upstream support.

Datadog CI receives native GitHub workflow/job events. Email-only monitors:
- Build failure: https://app.datadoghq.com/monitors/336807423
- Missed weekly publication: https://app.datadoghq.com/monitors/336807424

The second monitor checks Tuesday at 08:23 UTC for successful catalog publication
in the preceding 48 hours, giving Monday's build a 24-hour grace period. It checks
published-release freshness, not installed-version lag. Both notify
`verysvayn@gmail.com`; neither pages nor stops containers. No host scheduler or
custom telemetry poller is installed.
