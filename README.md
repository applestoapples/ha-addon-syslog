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
