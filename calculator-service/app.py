"""
CalcAPI — A simple calculator with intentional bugs for testing Sentry.

Bugs:
  #1: config/settings.py — PRECISION=-1 causes ValueError in round()
  #2: routes/calculate.py — divide doesn't check for zero
  #3: routes/history.py — missing 'import json' causes NameError
  #4: routes/calculate.py — power uses ^ (XOR) instead of **
"""

import logging
import os
import sys

from flask import Flask

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import APP_NAME, APP_VERSION, LOG_FILE
from routes.health import health_bp
from routes.calculate import calc_bp
from routes.history import history_bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(health_bp)
    app.register_blueprint(calc_bp)
    app.register_blueprint(history_bp)
    return app


def setup_logging():
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, mode="a"),
            logging.StreamHandler(sys.stdout),
        ],
    )


if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    app = create_app()
    port = int(os.getenv("CALCAPI_PORT", "5002"))
    logger.info(f"CalcAPI listening on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
