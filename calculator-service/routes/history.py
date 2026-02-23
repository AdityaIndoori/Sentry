"""History endpoint — BUG #3: missing import json."""
import logging
from flask import Blueprint, jsonify

# BUG #3: json is NOT imported, but json.dumps() is used below.
# This causes NameError: name 'json' is not defined

history_bp = Blueprint("history", __name__)
logger = logging.getLogger(__name__)


@history_bp.route("/api/history")
def get_history():
    """Return calculation history. BUG #3 triggers here."""
    from routes.calculate import _history
    from config.settings import MAX_HISTORY

    logger.info(f"Fetching history ({len(_history)} entries)")

    # BUG #3: json is not imported — crashes with NameError
    formatted = json.dumps(_history[-MAX_HISTORY:], indent=2)
    return jsonify({"count": len(_history), "history": _history[-MAX_HISTORY:], "raw": formatted})
