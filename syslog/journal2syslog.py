from __future__ import annotations

import logging
import logging.handlers
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from os import environ

from systemd import journal

SYSLOG_HOST = str(environ["SYSLOG_HOST"])
SYSLOG_PORT = int(environ["SYSLOG_PORT"])
SYSLOG_PROTO = str(environ["SYSLOG_PROTO"])
SYSLOG_SSL = True if environ["SYSLOG_SSL"] == "true" else False
SYSLOG_SSL_VERIFY = True if environ["SYSLOG_SSL_VERIFY"] == "true" else False
HAOS_HOSTNAME = str(environ["HAOS_HOSTNAME"])
SYSLOG_FORMAT = str(environ.get("SYSLOG_FORMAT", "rfc3164"))

LOGGING_NAME_TO_LEVEL_MAPPING = logging.getLevelNamesMapping()
LOGGING_JOURNAL_PRIORITY_TO_LEVEL_MAPPING = [
    logging.CRITICAL,  # 0 - emerg
    logging.CRITICAL,  # 1 - alert
    logging.CRITICAL,  # 2 - crit
    logging.ERROR,  # 3 - err
    logging.WARNING,  # 4 - warning
    logging.INFO,  # 5 - notice
    logging.INFO,  # 6 - info
    logging.DEBUG,  # 7 - debug
]
LOGGING_DEFAULT_LEVEL = logging.INFO
PATTERN_LOGLEVEL_HA = re.compile(
    r"^\S+ \S+ (?P<level>INFO|WARNING|DEBUG|ERROR|CRITICAL) "
)
CONTAINER_PATTERN_MAPPING = {
    "homeassistant": PATTERN_LOGLEVEL_HA,
    "hassio_supervisor": PATTERN_LOGLEVEL_HA,
}

# Syslog severity values (RFC 5424 Section 6.2.1)
JOURNAL_PRIORITY_TO_SYSLOG_SEVERITY = [
    0,  # 0 - emerg
    1,  # 1 - alert
    2,  # 2 - crit
    3,  # 3 - err
    4,  # 4 - warning
    5,  # 5 - notice
    6,  # 6 - info
    7,  # 7 - debug
]
LOGGING_LEVEL_TO_SYSLOG_SEVERITY = {
    logging.CRITICAL: 2,
    logging.ERROR: 3,
    logging.WARNING: 4,
    logging.INFO: 6,
    logging.DEBUG: 7,
}
SYSLOG_FACILITY_USER = 1
ANSI_COLOR_PATTERN = re.compile(r"\x1b\[\d+m")


class TlsSysLogHandler(logging.handlers.SysLogHandler):
    def __init__(
        self,
        address: tuple[str, int]
        | str = ("localhost", logging.handlers.SYSLOG_UDP_PORT),
        facility: str | int = logging.handlers.SysLogHandler.LOG_USER,
        socktype: logging.handlers.SocketKind | None = None,
        ssl: bool | ssl.SSLContext = False,
    ) -> None:
        self.ssl = ssl
        if ssl and socktype != socket.SOCK_STREAM:
            raise RuntimeError("TLS is only support for TCP connections")
        super().__init__(address, facility, socktype)

    def _wrap_sock_ssl(self, sock: socket.socket, host: str):
        """Wrap a tcp socket into a ssl context."""
        if isinstance(self.ssl, ssl.SSLContext):
            context = self.ssl
        else:
            context = ssl.create_default_context()

        return context.wrap_socket(sock, server_hostname=host)

    def handleError(self, record):
        """
        Log errors to stderr instead of silently swallowing them.
        Close failing socket so next emit will try to create a new socket.
        """
        print(f"Syslog send error for: {record.getMessage()[:100]}", file=sys.stderr)
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def createSocket(self):
        """
        Try to create a socket and, if it's not a datagram socket, connect it
        to the other end. This method is called during handler initialization,
        but it's not regarded as an error if the other end isn't listening yet
        --- the method will be called again when emitting an event,
        if there is no socket at that point.
        """
        address = self.address
        socktype = self.socktype

        if isinstance(address, str):
            self.unixsocket = True
            # Syslog server may be unavailable during handler initialisation.
            # C's openlog() function also ignores connection errors.
            # Moreover, we ignore these errors while logging, so it's not worse
            # to ignore it also here.
            try:
                self._connect_unixsocket(address)
            except OSError:
                pass
        else:
            self.unixsocket = False
            if socktype is None:
                socktype = socket.SOCK_DGRAM
            host, port = address
            ress = socket.getaddrinfo(host, port, 0, socktype)
            if not ress:
                raise OSError("getaddrinfo returns an empty list")
            for res in ress:
                af, socktype, proto, _, sa = res
                err = sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    if self.ssl:
                        sock = self._wrap_sock_ssl(sock, host)
                    if socktype == socket.SOCK_STREAM:
                        sock.connect(sa)
                    break
                except (OSError, ssl.SSLError) as exc:
                    err = exc
                    if sock is not None:
                        sock.close()
            if isinstance(err, ssl.SSLError):
                # only fail on ssl errors
                raise err
            self.socket = sock
            self.socktype = socktype


def parse_log_level(message: str, container_name: str) -> int:
    """
    Try to determine logging level from message.

    return: logging.<LEVELNAME> if determined
    return: logging.NOTSET if not determined
    """
    if pattern := CONTAINER_PATTERN_MAPPING.get(container_name):
        if (match := pattern.search(message)) is None:
            return logging.NOTSET
        return LOGGING_NAME_TO_LEVEL_MAPPING.get(
            match.group("level").upper(), logging.NOTSET
        )
    return logging.NOTSET


def _format_rfc5424(
    priority: int, timestamp: datetime, hostname: str, app_name: str, message: str
) -> str:
    """Format a syslog message per RFC 5424."""
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    # RFC 5424 requires ISO 8601 with timezone offset
    ts_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    # Insert colon in timezone offset (e.g., +0000 -> +00:00) for strict compliance
    if len(ts_str) >= 5 and ts_str[-5] in "+-" and ts_str[-4:].isdigit():
        ts_str = ts_str[:-2] + ":" + ts_str[-2:]
    return f"<{priority}>1 {ts_str} {hostname} {app_name} - - - {message}"


def _format_rfc3164(
    priority: int, timestamp: datetime, hostname: str, app_name: str, message: str
) -> str:
    """Format a syslog message per RFC 3164 (BSD syslog)."""
    # RFC 3164 timestamp: "Mmm dd HH:MM:SS" (space-padded day)
    ts_str = timestamp.strftime("%b %d %H:%M:%S")
    return f"<{priority}>{ts_str} {hostname} {app_name}: {message}"


def _determine_log_level(
    entry: dict,
    container_name: str | None,
    message: str,
    last_container_log_level: dict[str, int],
) -> int:
    """Determine the syslog log level for a journal entry."""
    if not container_name:
        return LOGGING_JOURNAL_PRIORITY_TO_LEVEL_MAPPING[
            entry.get("PRIORITY", 6)
        ]
    elif container_name not in CONTAINER_PATTERN_MAPPING:
        return LOGGING_DEFAULT_LEVEL
    elif log_level := parse_log_level(message, container_name):
        last_container_log_level[container_name] = log_level
        return log_level
    else:  # use last log level if it could not be parsed (eq. for tracebacks)
        return last_container_log_level.get(
            container_name, LOGGING_DEFAULT_LEVEL
        )


def main():
    """Main entry point."""
    # Start journal reader and seek to end of journal
    #
    # NOTE: Intentionally NOT calling jr.this_boot() here.
    # In containers (like HA add-ons), the boot ID from
    # /proc/sys/kernel/random/boot_id is the container's boot ID, which
    # doesn't match any boot ID in the host's journal (mounted from
    # /var/log/journal). this_boot() would silently filter out ALL entries,
    # causing the add-on to appear working but never forward any logs.
    jr = journal.Reader(path="/var/log/journal")
    jr.seek_tail()
    jr.get_previous()

    # Determine syslog format
    if SYSLOG_FORMAT == "rfc5424":
        format_fn = _format_rfc5424
    else:
        format_fn = _format_rfc3164

    # Set up transport
    if SYSLOG_PROTO.lower() == "udp":
        socktype = socket.SOCK_DGRAM
    else:
        socktype = socket.SOCK_STREAM

    use_ssl = SYSLOG_SSL
    if SYSLOG_SSL and not SYSLOG_SSL_VERIFY:
        use_ssl = ssl.create_default_context()
        use_ssl.check_hostname = False
        use_ssl.verify_mode = ssl.CERT_NONE

    syslog_handler = TlsSysLogHandler(
        address=(SYSLOG_HOST, SYSLOG_PORT), socktype=socktype, ssl=use_ssl
    )

    print(
        f"Forwarding journal to {SYSLOG_HOST}:{SYSLOG_PORT}/{SYSLOG_PROTO}"
        f" (format={SYSLOG_FORMAT})",
        flush=True,
    )

    last_container_log_level: dict[str, int] = {}
    sent = 0

    # Main loop: wait for new journal entries and forward them
    while True:
        jr.wait(timeout=30)
        for entry in jr:
            app_name = entry.get("SYSLOG_IDENTIFIER", "unknown")

            # Remove ANSI color codes from container messages
            if (container_name := entry.get("CONTAINER_NAME")) is not None:
                msg = ANSI_COLOR_PATTERN.sub("", entry.get("MESSAGE", ""))
            else:
                container_name = None
                msg = entry.get("MESSAGE", "")

            if not msg:
                continue

            # Determine log level
            log_level = _determine_log_level(
                entry, container_name, msg, last_container_log_level
            )

            # Build syslog priority value
            severity = LOGGING_LEVEL_TO_SYSLOG_SEVERITY.get(log_level, 6)
            priority = SYSLOG_FACILITY_USER * 8 + severity

            # Get timestamp from journal entry (or use current time)
            timestamp = entry.get(
                "_SOURCE_REALTIME_TIMESTAMP",
                entry.get("__REALTIME_TIMESTAMP", datetime.now(timezone.utc)),
            )
            if not isinstance(timestamp, datetime):
                timestamp = datetime.now(timezone.utc)

            # Format and send
            syslog_msg = format_fn(
                priority, timestamp, HAOS_HOSTNAME, app_name, msg
            )

            try:
                # Send directly via the handler's socket, bypassing
                # logging.Handler.emit() to use our own formatting.
                if syslog_handler.socket is None:
                    syslog_handler.createSocket()
                if syslog_handler.socket is not None:
                    encoded = syslog_msg.encode("utf-8", errors="replace")
                    if syslog_handler.socktype == socket.SOCK_DGRAM:
                        syslog_handler.socket.sendto(
                            encoded, (SYSLOG_HOST, SYSLOG_PORT)
                        )
                    else:
                        # TCP: add newline framing (RFC 6587)
                        syslog_handler.socket.sendall(encoded + b"\n")
                    sent += 1
            except Exception:
                # Socket error — close and retry on next message
                syslog_handler.handleError(
                    logging.LogRecord(
                        "syslog", log_level, "", 0, msg[:100], (), None
                    )
                )

            if sent > 0 and sent % 1000 == 0:
                print(f"Forwarded {sent} entries", flush=True)


if __name__ == "__main__":
    main()
