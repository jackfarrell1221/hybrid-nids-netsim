"""
tests/test_sniffer.py — Unit and integration tests for the Sniffer Engine and API routes.
"""

import pytest
from backend.services.sniffer_service import get_sniffer, generate_hex_dump, build_synthetic_frame
from backend.services.ip_enricher import get_ip_enricher


def test_ip_enricher_subnets():
    enricher = get_ip_enricher()
    # Google
    res_google = enricher.enrich("142.250.190.46")
    assert res_google["provider"] == "Google Services"
    assert res_google["provider_tag"] == "google"

    # Cloudflare
    res_cf = enricher.enrich("104.21.32.1")
    assert "Cloudflare" in res_cf["provider"]
    assert res_cf["provider_tag"] == "cloudflare"

    # AWS
    res_aws = enricher.enrich("52.95.120.1")
    assert "AWS" in res_aws["provider"]
    assert res_aws["provider_tag"] == "aws"

    # Azure
    res_azure = enricher.enrich("20.112.52.29")
    assert "Azure" in res_azure["provider"]
    assert res_azure["provider_tag"] == "azure"

    # Internal
    res_int = enricher.enrich("192.168.1.100")
    assert res_int["provider_tag"] == "internal"


def test_generate_hex_dump_format():
    test_bytes = b"Hello, Wireshark Hex Dissector 2026!"
    hex_dump = generate_hex_dump(test_bytes)
    assert "0000" in hex_dump
    assert "Hello," in hex_dump
    lines = hex_dump.splitlines()
    assert len(lines) >= 2
    # Ensure 16-byte offset formatting
    assert lines[0].startswith("0000   ")
    assert lines[1].startswith("0010   ")


def test_build_synthetic_frame():
    frame = build_synthetic_frame(
        src_ip="192.168.1.15",
        dst_ip="142.250.190.46",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        tcp_state="ESTABLISHED"
    )
    assert len(frame) >= 40
    # IPv4 header version is 4 (high nibble of first byte)
    assert (frame[0] >> 4) == 4
    # Protocol in IPv4 header at offset 9 should be 6 (TCP)
    assert frame[9] == 6


def test_sniffer_interfaces_enumeration():
    sniffer = get_sniffer()
    interfaces = sniffer.get_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0
    # At least one interface should have an IP
    assert any(i.get("ip") for i in interfaces)
    # The default interface should be sorted first
    assert interfaces[0]["is_default"] is True or not any(i["is_default"] for i in interfaces)


def test_sniffer_status_fields():
    sniffer = get_sniffer()
    status = sniffer.get_status()
    assert "is_sniffing" in status
    assert "is_elevated" in status
    assert "active_engine" in status
    assert "engine_display_name" in status
    assert "default_route_ip" in status
    assert "total_packets" in status


def test_sniffer_api_lifecycle(client):
    """Integration test checking Flask /api/sniffer/* endpoints."""
    # 1. Status
    res = client.get("/api/sniffer/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "active_engine" in data

    # 2. Interfaces
    res = client.get("/api/sniffer/interfaces")
    assert res.status_code == 200
    assert "interfaces" in res.get_json()

    # 3. Start sniffing
    res = client.post("/api/sniffer/start", json={})
    assert res.status_code == 200
    assert res.get_json()["is_sniffing"] is True

    # 4. Packets
    res = client.get("/api/sniffer/packets?limit=10")
    assert res.status_code == 200
    p_data = res.get_json()
    assert "packets" in p_data
    assert "is_sniffing" in p_data

    # 5. Metrics
    res = client.get("/api/sniffer/metrics")
    assert res.status_code == 200
    m_data = res.get_json()
    assert "metrics" in m_data
    assert len(m_data["metrics"]) > 0

    # 6. Stop sniffing
    res = client.post("/api/sniffer/stop")
    assert res.status_code == 200
    assert res.get_json()["is_sniffing"] is False

    # 7. Clear buffer
    res = client.post("/api/sniffer/clear")
    assert res.status_code == 200
    assert res.get_json()["status"] == "cleared"
