"""
routes/sniffer.py — Blueprint for Live NIC Sniffing, Wire Ingestion & Timeline Metrics.
"""

from flask import Blueprint, jsonify, request
from backend.services.sniffer_service import get_sniffer
from backend.utils.logger import get_logger

logger = get_logger("routes.sniffer")

sniffer_bp = Blueprint("sniffer", __name__, url_prefix="/api/sniffer")


@sniffer_bp.route("/status", methods=["GET"])
def get_status():
    """Return live sniffer operational state, active engine, and summary metrics."""
    try:
        status = get_sniffer().get_status()
        return jsonify(status), 200
    except Exception as exc:
        logger.error("Error retrieving sniffer status: %s", exc)
        return jsonify({"error": str(exc)}), 500


@sniffer_bp.route("/interfaces", methods=["GET"])
def get_interfaces():
    """List all available network interfaces prioritized by active internet gateway."""
    try:
        interfaces = get_sniffer().get_interfaces()
        return jsonify({"interfaces": interfaces}), 200
    except Exception as exc:
        logger.error("Error retrieving interfaces: %s", exc)
        return jsonify({"error": str(exc)}), 500


@sniffer_bp.route("/start", methods=["POST"])
def start_capture():
    """
    Start live wire capture on the selected or default interface.
    Auto-detects elevated raw sockets vs zero-admin connection telemetry.
    """
    try:
        body = request.get_json(silent=True) or {}
        interface_name = body.get("interface")
        status = get_sniffer().start_sniffing(interface_name=interface_name)
        return jsonify(status), 200
    except Exception as exc:
        logger.error("Error starting sniffer: %s", exc)
        return jsonify({"error": str(exc)}), 500


@sniffer_bp.route("/stop", methods=["POST"])
def stop_capture():
    """Stop active packet capture."""
    try:
        status = get_sniffer().stop_sniffing()
        return jsonify(status), 200
    except Exception as exc:
        logger.error("Error stopping sniffer: %s", exc)
        return jsonify({"error": str(exc)}), 500


@sniffer_bp.route("/packets", methods=["GET"])
def get_packets():
    """
    Retrieve captured packets with Wireshark-style decoded headers,
    raw hex dumps, and detection verdicts.
    """
    try:
        limit = min(500, max(1, request.args.get("limit", 100, type=int)))
        offset = max(0, request.args.get("offset", 0, type=int))
        result = get_sniffer().get_packets(limit=limit, offset=offset)
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Error fetching packets: %s", exc)
        return jsonify({"error": str(exc)}), 500


@sniffer_bp.route("/metrics", methods=["GET"])
def get_metrics():
    """Retrieve rolling 60-second throughput (KB/s In/Out) and PPS metrics."""
    try:
        metrics = get_sniffer().get_timeline_metrics()
        return jsonify({"metrics": metrics}), 200
    except Exception as exc:
        logger.error("Error fetching sniffer metrics: %s", exc)
        return jsonify({"error": str(exc)}), 500


@sniffer_bp.route("/clear", methods=["POST"])
def clear_packets():
    """Clear in-memory packet buffer."""
    try:
        get_sniffer().clear_packets()
        return jsonify({"status": "cleared"}), 200
    except Exception as exc:
        logger.error("Error clearing packets: %s", exc)
        return jsonify({"error": str(exc)}), 500
