"""Calculator endpoints with bugs #2 and #4."""
import logging
from flask import Blueprint, jsonify, request
from config.settings import PRECISION

calc_bp = Blueprint("calculate", __name__)
logger = logging.getLogger(__name__)

# In-memory history store
_history = []

OPERATIONS = {
    "add": lambda a, b: a + b,
    "subtract": lambda a, b: a - b,
    "multiply": lambda a, b: a * b,
    # BUG #2: No check for b==0 — causes ZeroDivisionError
    "divide": lambda a, b: a / b,
    # BUG #4: Uses ^ (bitwise XOR) instead of ** (exponentiation)
    # e.g. power(2, 8) returns 10 (2^8 XOR) instead of 256 (2**8)
    "power": lambda a, b: int(a) ^ int(b),
}


@calc_bp.route("/api/calculate", methods=["POST"])
def calculate():
    """Perform a calculation. Bugs #1, #2, #4 trigger here."""
    data = request.get_json() or {}
    op = data.get("operation", "")
    a = data.get("a", 0)
    b = data.get("b", 0)

    if op not in OPERATIONS:
        return jsonify({"error": f"Unknown operation: {op}"}), 400

    logger.info(f"Calculating: {a} {op} {b}")
    try:
        raw_result = OPERATIONS[op](a, b)
        # BUG #1: PRECISION is -1 from settings — round(x, -1) rounds
        # to nearest 10 which gives wrong answers for normal math
        result = round(raw_result, PRECISION)
        entry = {"operation": op, "a": a, "b": b, "result": result}
        _history.append(entry)
        logger.info(f"Result: {result}")
        return jsonify(entry)
    except ZeroDivisionError:
        logger.error(f"ERROR: ZeroDivisionError in {op}({a}, {b})")
        return jsonify({"error": "Division by zero"}), 400
    except Exception as e:
        logger.error(f"ERROR: {type(e).__name__}: {e} in {op}({a}, {b})")
        return jsonify({"error": str(e)}), 500
