import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from dataclasses import dataclass

from sanitize_skill import __version__
from sanitize_skill.models import SanitizeError

_BLOCKED_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "metadata.google.com",
}


@dataclass
class FetchResult:
    data: bytes
    locator: str
    content_type: str | None


def fetch_url(url: str, *, timeout: float = 20, max_bytes: int = 15_000_000, max_redirects: int = 3) -> FetchResult:
    current = url
    for _ in range(max_redirects + 1):
        validate_public_url(current)
        status, headers, body = _request(current, timeout=timeout, max_bytes=max_bytes)
        if status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            if not location:
                raise SanitizeError("redirect without location")
            current = urllib.parse.urljoin(current, location)
            continue
        if status != 200:
            raise SanitizeError(f"http status {status}")
        return FetchResult(body, public_locator(current), headers.get("content-type"))
    raise SanitizeError("too many redirects")


def validate_public_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise SanitizeError("only http and https urls are allowed")
    if parts.username or parts.password:
        raise SanitizeError("urls with credentials are not allowed")
    host = parts.hostname
    if not host or any(char in host for char in " \t\r\n"):
        raise SanitizeError("url has no host")
    if host_is_blocked(host):
        raise SanitizeError("blocked address")


def public_locator(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = ""
    if parts.port and parts.port not in {80, 443}:
        port = f":{parts.port}"
    path = parts.path or "/"
    return f"{parts.scheme}://{host}{port}{path}"


def host_is_blocked(host: str) -> bool:
    name = host.lower().rstrip(".")
    if name in _BLOCKED_HOSTS or name.endswith(".localhost") or name.endswith(".local") or name.endswith(".internal"):
        return True
    address = _parse_ip(name)
    if address is not None:
        return not _is_public(address)
    return False


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if host.isdigit():
        try:
            return ipaddress.ip_address(int(host))
        except ValueError:
            return None
    return None


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _pick_public_ip(host: str) -> str:
    if host_is_blocked(host):
        raise SanitizeError("blocked address")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SanitizeError("dns failed") from exc
    chosen = ""
    for info in infos:
        ip = str(info[4][0])
        if not _is_public(ipaddress.ip_address(ip)):
            raise SanitizeError("blocked address")
        if not chosen:
            chosen = ip
    if not chosen:
        raise SanitizeError("dns failed")
    return chosen


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, ip: str, port: int, timeout: float, server_hostname: str):
        super().__init__(ip, port, timeout=timeout, context=ssl.create_default_context())
        self._sni = server_hostname

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)


def _request(url: str, *, timeout: float, max_bytes: int) -> tuple[int, dict[str, str], bytes]:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = _pick_public_ip(host)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(ip, port, timeout, host)
    else:
        connection = http.client.HTTPConnection(ip, port, timeout=timeout)
    name = f"[{host}]" if ":" in host else host
    default_port = 443 if parts.scheme == "https" else 80
    host_header = name if port == default_port else f"{name}:{port}"
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": f"sanitize/{__version__}",
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise SanitizeError("response exceeds size limit")
        headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, headers, body
    finally:
        connection.close()
