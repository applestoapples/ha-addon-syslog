# Syslog Home Assistant add-on

## How to use

This add-on allows you to send your HAOS logs to a remote syslog server.

## Configuration

Add-on configuration:

```yaml
syslog_host: syslog.local
syslog_port: 514
syslog_protocol: udp
syslog_format: rfc5424
syslog_ssl: false
syslog_ssl_verify: false
```

| key | name | description |
| --- | ---- | ----------- |
| `syslog_host` | Syslog host | The hostname or IP address of the remote syslog server to send HAOS logs to. |
| `syslog_port` | Syslog port | The port of the remote syslog server to send HAOS logs to. |
| `syslog_protocol` | Transfer protocol | The protocol to be used to send HAOS logs. |
| `syslog_format` | Syslog format | The syslog message format: `rfc3164` (default, BSD syslog) or `rfc5424` (ISO 8601 timestamps, structured data header). Use `rfc5424` for best compatibility with modern log receivers. |
| `syslog_ssl` | SSL encryption | Whether or not to use ssl encryption (only supported with tcp). |
| `syslog_ssl_verify` | SSL verify | Whether or not to verify ssl certificate. |

## Support

In case you've found a bug, please [open an issue on GitHub][issue].

[issue]: https://github.com/applestoapples/ha-addon-syslog/issues
