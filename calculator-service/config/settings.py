"""CalcAPI settings."""
import os

APP_NAME = "CalcAPI"
APP_VERSION = "1.0.0"
LOG_FILE = os.getenv("LOG_FILE", "logs/calc.log")

# BUG #1: PRECISION is -1 (invalid). round(x, -1) rounds to nearest 10,
# but when combined with float results it causes unexpected ValueError.
# Should be 2 (two decimal places).
PRECISION = int(os.getenv("PRECISION", "-1"))

MAX_HISTORY = int(os.getenv("MAX_HISTORY", "100"))
