"""
app.py — Flask application entry point for the Hybrid NIDS backend.

Why this exists:
  This is the top-level file that assembles all blueprints, configures 
  CORS (so the React frontend can call the API from localhost:5173), 
  and starts the development server.

How it connects to the NIDS architecture:
  1. Creates the Flask app.
  2. Registers all route blueprints.
  3. Ensures the database and model directory exist.
  4. Starts the server on the configured host:port.

Run with:
    python backend/app.py
"""

import os
import sys

# ── Make sure the project root is on the Python path ─────────────────────────
# This allows `from backend.config import ...` to work when running as:
#   python backend/app.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from flask_cors import CORS

from backend.config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
from backend.routes.prediction import prediction_bp
from backend.routes.training   import training_bp
from backend.routes.simulation import simulation_bp
from backend.routes.alerts     import alerts_bp
from backend.routes.dataset    import dataset_bp
from backend.routes.sniffer    import sniffer_bp
from backend.utils.logger      import setup_logging, get_logger
from backend.models.model_manager import get_alert_db   # initialises DB at import

# Set up logging before anything else
setup_logging("DEBUG" if FLASK_DEBUG else "INFO")
logger = get_logger("app")


def create_app() -> Flask:
    """Application factory — creates and configures the Flask app."""
    frontend_dist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist")
    if os.path.exists(frontend_dist):
        app = Flask(__name__, static_folder=frontend_dist, static_url_path="")
    else:
        app = Flask(__name__)

    # Allow cross-origin requests
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Register route blueprints
    app.register_blueprint(prediction_bp)
    app.register_blueprint(training_bp)
    app.register_blueprint(simulation_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(dataset_bp)
    app.register_blueprint(sniffer_bp)

    # If built frontend exists, serve index.html for root and SPA routes
    if os.path.exists(frontend_dist):
        from flask import send_from_directory

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def serve_frontend(path):
            if path and os.path.exists(os.path.join(frontend_dist, path)):
                return send_from_directory(frontend_dist, path)
            return send_from_directory(frontend_dist, "index.html")

    # Trigger DB initialisation
    get_alert_db()

    logger.info("Hybrid NIDS Flask application created.")
    return app


app = create_app()


if __name__ == "__main__":
    logger.info(
        "Starting Hybrid NIDS backend on http://%s:%d (debug=%s)",
        FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    )
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
