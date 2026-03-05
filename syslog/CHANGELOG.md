# Changelog

## 0.5.2

- Aggregate multiline journal entries (tracebacks) into a single syslog message

## 0.5.1

- Default syslog format changed to RFC 5424
- Default image registry switched to ghcr.io/applestoapples

## 0.5.0

- Fix journal reader in containers (boot ID mismatch with host journal)
- Add configurable syslog format: RFC 3164 (default) or RFC 5424
- Use proper RFC-compliant message formatting (timestamps, structured data)
- Use bounded wait timeout (30s) instead of infinite blocking
- Log send errors to stderr instead of silently swallowing them
- Drop deprecated architectures (armhf, armv7, i386)
- Switch image hosting from DockerHub to GHCR

## 0.4.1

- Fix tagging of containers

## 0.4.0

- Handle unavailable syslog server

## 0.3.0

- Add tls support

## 0.2.0

- Determine correct syslog level for ha core, supervisor and haos host messages

## 0.1.0

- Use pre-built images

## 0.0.2

- Make messages RFC3164 (bsd) compliant

## 0.0.1

- Initial version
