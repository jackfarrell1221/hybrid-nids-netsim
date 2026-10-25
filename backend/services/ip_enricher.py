"""
services/ip_enricher.py — High-performance, non-blocking IP enrichment & reverse DNS resolution.

Provides non-blocking rDNS caching and cloud provider / subnet classification
(e.g., Google Services, Cloudflare, Microsoft Azure, Amazon AWS, Akamai, etc.).
"""

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

# Pre-compiled subnet mappings for rapid lookup
_PROVIDER_SUBNETS = [
    # Google & GCP
    (ipaddress.ip_network("8.8.8.0/24"), "Google DNS", "google"),
    (ipaddress.ip_network("8.8.4.0/24"), "Google DNS", "google"),
    (ipaddress.ip_network("142.250.0.0/15"), "Google Services", "google"),
    (ipaddress.ip_network("172.217.0.0/16"), "Google Services", "google"),
    (ipaddress.ip_network("216.58.192.0/19"), "Google Services", "google"),
    (ipaddress.ip_network("74.125.0.0/16"), "Google Services", "google"),
    (ipaddress.ip_network("34.64.0.0/10"), "Google Cloud (GCP)", "google"),
    (ipaddress.ip_network("35.184.0.0/13"), "Google Cloud (GCP)", "google"),

    # Cloudflare
    (ipaddress.ip_network("1.1.1.0/24"), "Cloudflare DNS", "cloudflare"),
    (ipaddress.ip_network("1.0.0.0/24"), "Cloudflare DNS", "cloudflare"),
    (ipaddress.ip_network("104.16.0.0/12"), "Cloudflare CDN / Edge", "cloudflare"),
    (ipaddress.ip_network("172.64.0.0/13"), "Cloudflare CDN / Edge", "cloudflare"),
    (ipaddress.ip_network("162.158.0.0/15"), "Cloudflare CDN / Edge", "cloudflare"),
    (ipaddress.ip_network("198.41.128.0/17"), "Cloudflare CDN / Edge", "cloudflare"),

    # Amazon Web Services (AWS)
    (ipaddress.ip_network("52.0.0.0/11"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("52.32.0.0/11"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("52.64.0.0/11"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("52.96.0.0/11"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("54.0.0.0/8"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("3.0.0.0/9"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("18.128.0.0/9"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("44.192.0.0/10"), "Amazon AWS", "aws"),
    (ipaddress.ip_network("99.80.0.0/15"), "Amazon AWS", "aws"),

    # Microsoft Azure / M365
    (ipaddress.ip_network("20.0.0.0/10"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("20.64.0.0/10"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("20.128.0.0/10"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("40.64.0.0/10"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("40.112.0.0/12"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("51.104.0.0/14"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("51.140.0.0/14"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("65.52.0.0/14"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("13.64.0.0/11"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("13.96.0.0/12"), "Microsoft Azure", "azure"),
    (ipaddress.ip_network("137.116.0.0/16"), "Microsoft Azure", "azure"),

    # Akamai
    (ipaddress.ip_network("23.0.0.0/12"), "Akamai Edge", "akamai"),
    (ipaddress.ip_network("104.64.0.0/10"), "Akamai Edge", "akamai"),
    (ipaddress.ip_network("96.16.0.0/15"), "Akamai Edge", "akamai"),
    (ipaddress.ip_network("184.24.0.0/13"), "Akamai Edge", "akamai"),

    # GitHub
    (ipaddress.ip_network("140.82.112.0/20"), "GitHub Infrastructure", "github"),
    (ipaddress.ip_network("192.30.252.0/22"), "GitHub Infrastructure", "github"),

    # Fastly
    (ipaddress.ip_network("151.101.0.0/16"), "Fastly CDN", "fastly"),
    (ipaddress.ip_network("199.232.0.0/16"), "Fastly CDN", "fastly"),

    # Apple
    (ipaddress.ip_network("17.0.0.0/8"), "Apple Cloud Services", "apple"),

    # Private / Local
    (ipaddress.ip_network("10.0.0.0/8"), "Private Network (RFC 1918)", "internal"),
    (ipaddress.ip_network("172.16.0.0/12"), "Private Network (RFC 1918)", "internal"),
    (ipaddress.ip_network("192.168.0.0/16"), "Local LAN (RFC 1918)", "internal"),
    (ipaddress.ip_network("127.0.0.0/8"), "Loopback Interface", "internal"),
    (ipaddress.ip_network("169.254.0.0/16"), "Link-Local / APIPA", "internal"),
]

import queue
import threading


class IPEnricher:
    """Singleton helper for enriching IP addresses with cloud provider tags and cached rDNS."""

    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._pending: set = set()
        self._queue = queue.Queue(maxsize=100)
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="nexus-rdns-worker")
        self._worker_thread.start()

    def _worker_loop(self):
        """Dedicated daemon background worker for non-blocking rDNS."""
        while True:
            try:
                ip_str = self._queue.get()
                self._do_rdns(ip_str)
                self._queue.task_done()
            except Exception:
                pass

    def _match_subnet(self, ip_str: str) -> tuple:
        """Rapid prefix and subnet checking."""
        # Fast prefix checks
        if ip_str.startswith("142.250.") or ip_str.startswith("172.217.") or ip_str.startswith("74.125.") or ip_str.startswith("216.58."):
            return "Google Services", "google"
        if ip_str.startswith("104.21.") or ip_str.startswith("104.16.") or ip_str.startswith("104.18.") or ip_str.startswith("1.1.1."):
            return "Cloudflare", "cloudflare"
        if ip_str.startswith("52.") or ip_str.startswith("54.") or ip_str.startswith("3.") or ip_str.startswith("18."):
            return "Amazon AWS", "aws"
        if ip_str.startswith("20.") or ip_str.startswith("40.") or ip_str.startswith("51.") or ip_str.startswith("13."):
            return "Microsoft Azure", "azure"
        if ip_str.startswith("192.168.") or ip_str.startswith("10.") or ip_str.startswith("127.") or ip_str.startswith("169.254."):
            return "Internal / Localhost", "internal"
        if ip_str.startswith("17."):
            return "Apple Cloud", "apple"

        try:
            addr = ipaddress.ip_address(ip_str)
            for net, name, tag in _PROVIDER_SUBNETS:
                if addr in net:
                    return name, tag
        except ValueError:
            pass

        return "Public Internet", "external"

    def _do_rdns(self, ip_str: str):
        """Worker function for async rDNS lookup."""
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.6)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
            finally:
                socket.setdefaulttimeout(old_timeout)

            if hostname:
                cached = self._cache.get(ip_str)
                if cached:
                    cached["hostname"] = hostname
                    lower_host = hostname.lower()
                    if "1e100.net" in lower_host or "google" in lower_host or "youtube" in lower_host:
                        cached["provider"] = "Google Services"
                        cached["provider_tag"] = "google"
                    elif "cloudflare" in lower_host:
                        cached["provider"] = "Cloudflare"
                        cached["provider_tag"] = "cloudflare"
                    elif "amazonaws" in lower_host or "aws" in lower_host:
                        cached["provider"] = "Amazon AWS"
                        cached["provider_tag"] = "aws"
                    elif "azure" in lower_host or "microsoft" in lower_host or "trafficmanager.net" in lower_host:
                        cached["provider"] = "Microsoft Azure"
                        cached["provider_tag"] = "azure"
                    elif "akamai" in lower_host or "akamaitechnologies" in lower_host:
                        cached["provider"] = "Akamai Edge"
                        cached["provider_tag"] = "akamai"
                    elif "fastly" in lower_host:
                        cached["provider"] = "Fastly CDN"
                        cached["provider_tag"] = "fastly"
                    elif "github" in lower_host:
                        cached["provider"] = "GitHub Infrastructure"
                        cached["provider_tag"] = "github"
        except Exception:
            pass
        finally:
            self._pending.discard(ip_str)

    def enrich(self, ip_str: Optional[str]) -> Dict[str, Any]:
        """
        Enriches an IP address non-blockingly.
        Returns cached dict: {'hostname': str, 'provider': str, 'provider_tag': str}
        """
        if not ip_str or ip_str in ("0.0.0.0", "::", "255.255.255.255", ""):
            return {"hostname": None, "provider": "Unspecified", "provider_tag": "internal"}

        if ip_str in self._cache:
            return self._cache[ip_str]

        provider, tag = self._match_subnet(ip_str)
        result = {
            "hostname": None,
            "provider": provider,
            "provider_tag": tag
        }
        if len(self._cache) > 2000:
            for k in list(self._cache.keys())[:500]:
                self._cache.pop(k, None)

        self._cache[ip_str] = result

        if tag != "internal" and ip_str not in self._pending:
            self._pending.add(ip_str)
            try:
                self._queue.put_nowait(ip_str)
            except Exception:
                self._pending.discard(ip_str)

        return result


# Global singleton instance
_enricher: Optional[IPEnricher] = None


def get_ip_enricher() -> IPEnricher:
    global _enricher
    if _enricher is None:
        _enricher = IPEnricher()
    return _enricher
