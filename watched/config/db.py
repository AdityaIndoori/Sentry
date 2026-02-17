"""
Database configuration for production application.
NOTE: This is a sample config file for Claude Sentry to investigate.
"""

import os

DATABASE_CONFIG = {
    "host": os.getenv("DB_HOST", "db-primary.internal"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "database": os.getenv("DB_NAME", "shopdb"),
    "user": os.getenv("DB_USER", "app_service"),
    "password": os.getenv("DB_PASSWORD", ""),  # Loaded from vault
    "pool": {
        "min_connections": 5,
        "max_connections": 50,  # WARNING: May need increase during peak traffic
        "max_idle_time": 300,
        "connection_timeout": 10,
        "statement_timeout": 30000,  # 30 seconds
    },
    "ssl": {
        "enabled": True,
        "ca_cert": "/etc/ssl/certs/rds-ca-2019-root.pem",
        "verify": True,
    },
    "replicas": [
        {"host": "db-replica-01.internal", "port": 5432, "weight": 50},
        {"host": "db-replica-02.internal", "port": 5432, "weight": 50},
    ],
}

REDIS_CONFIG = {
    "sentinel_hosts": [
        ("redis-sentinel.internal", 26379),
    ],
    "master_name": "mymaster",
    "password": os.getenv("REDIS_PASSWORD", ""),
    "db": 0,
    "socket_timeout": 5,
    "max_connections": 50,
    "retry_on_timeout": True,
}
