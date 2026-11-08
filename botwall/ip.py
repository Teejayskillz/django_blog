"""Client IP resolution and CIDR helpers.

Security model
--------------
``REMOTE_ADDR`` is authoritative unless the TCP peer is a *configured* trusted
proxy. ``X-Forwarded-For`` is parsed from the right (closest hop) and only when
the peer is trusted. ``CF-Connecting-IP`` is accepted only for Cloudflare
ranges and only when explicitly enabled. Malformed values never become an
identity - they fall back to ``REMOTE_ADDR`` and raise a spoofing signal.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from functools import lru_cache

from django.conf import settings

logger = logging.getLogger("botwall.ip")

# Published Cloudflare edge ranges (https://www.cloudflare.com/ips/).
_CF_NETWORKS = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

CLOUDFLARE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in _CF_NETWORKS)


@dataclass(frozen=True)
class ClientIP:
    """Result of a safe client-IP lookup."""

    address: str
    remote_addr: str
    source: str = "remote_addr"
    trusted_proxy: bool = False
    forwarded_chain: tuple[str, ...] = field(default_factory=tuple)
    spoof_suspect: bool = False

    @property
    def limit_key(self) -> str:
        return limit_key(self.address)


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------
def normalize_ip(value) -> str | None:
    """Return a canonical IP string or ``None`` for anything invalid."""
    if not value:
        return None
    text = str(value).strip()
    if not text or len(text) > 64:
        return None
    if text.startswith("[") and "]" in text:  # [2001:db8::1]:443
        text = text[1 : text.index("]")]
    elif text.count(":") == 1 and "." in text:  # 203.0.113.4:51234
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_unspecified or address.is_multicast:
        return None
    return str(address)


def normalize_network(value):
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except (ValueError, TypeError):
        return None


@lru_cache(maxsize=16)
def _parse_networks(values: tuple[str, ...]):
    networks = []
    for value in values:
        network = normalize_network(value)
        if network is not None:
            networks.append(network)
    return tuple(networks)


def trusted_proxy_networks():
    values = getattr(settings, "BOTWALL_TRUSTED_PROXIES", ()) or ()
    if isinstance(values, str):
        values = [part.strip() for part in values.split(",") if part.strip()]
    return _parse_networks(tuple(str(item).strip() for item in values if str(item).strip()))


def is_trusted_proxy(address: str) -> bool:
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in trusted_proxy_networks())


def is_cloudflare(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in CLOUDFLARE_NETWORKS)


def is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_private_or_reserved(address: str) -> bool:
    """Inverse of :func:`is_public_ip`; invalid input counts as private."""
    return not is_public_ip(address)


def _split_header(request, name: str):
    raw = request.META.get(name) or ""
    return [part.strip() for part in raw.split(",") if part.strip()]


def get_client_ip(request) -> ClientIP:
    """Resolve the real client address without blindly trusting headers."""
    remote = normalize_ip(request.META.get("REMOTE_ADDR")) or "0.0.0.0"
    chain_raw = _split_header(request, "HTTP_X_FORWARDED_FOR")
    chain = tuple(normalize_ip(item) or "" for item in chain_raw)
    trusted = is_trusted_proxy(remote)
    hops = int(getattr(settings, "BOTWALL_TRUSTED_PROXY_HOPS", 0) or 0)

    address = remote
    source = "remote_addr"
    spoof_suspect = False

    if trusted:
        # Cloudflare: an explicit, single-valued header we can trust when the
        # peer really is a Cloudflare edge server.
        if getattr(settings, "BOTWALL_TRUST_CF_HEADERS", False) and is_cloudflare(remote):
            cf_value = normalize_ip(request.META.get("HTTP_CF_CONNECTING_IP"))
            if cf_value:
                return ClientIP(
                    address=cf_value,
                    remote_addr=remote,
                    source="cf_connecting_ip",
                    trusted_proxy=True,
                    forwarded_chain=chain,
                    spoof_suspect=bool(chain_raw) and chain[:1] != (cf_value,),
                )

        if hops > 0:
            # XFF: client, proxy1, proxy2 ... walking from the right.
            if len(chain) >= hops:
                candidate = chain[-hops]
                if candidate:
                    address = candidate
                    source = "x_forwarded_for"
                else:
                    spoof_suspect = True
            elif chain_raw:
                spoof_suspect = True
        elif chain:
            candidate = chain[-1]
            if candidate:
                address = candidate
                source = "x_forwarded_for"
            else:
                spoof_suspect = True

        if source == "remote_addr" and chain_raw:
            spoof_suspect = True
        # A trusted proxy forwarding to us should never present private hops.
        if any(item and not is_public_ip(item) for item in chain):
            spoof_suspect = True

    return ClientIP(
        address=address,
        remote_addr=remote,
        source=source,
        trusted_proxy=trusted,
        forwarded_chain=chain,
        spoof_suspect=spoof_suspect,
    )


def limit_key(address: str) -> str:
    """Rate-limit bucket key: exact IPv4, /64 for IPv6 (stops /64 rotation)."""
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return "invalid"
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)
    return str(ip)


def mask_ip(address: str, binding: str) -> str:
    """Mask an IP for the verification cookie binding."""
    binding = (binding or "prefix").lower()
    if binding == "none":
        return ""
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return ""
    if binding == "exact":
        return str(ip)
    prefix = 24 if ip.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def parse_network_list(text: str):
    """Parse a newline separated CIDR list, ignoring blanks/comments."""
    networks = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        network = normalize_network(line)
        if network is not None:
            networks.append(network)
        else:
            logger.debug("botwall: ignoring invalid network %r", line)
    return tuple(networks)


def ip_in_networks(address: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    return any(ip in network for network in networks)
