"""
database/db.py
SQLite database manager for the AI-Based Anomaly Detection project.
Handles connection management, table creation, and Flask app initialization.
"""

import sqlite3
import os
import logging
from flask import g

logger = logging.getLogger(__name__)

# Constant path for the SQLite database file
DB_PATH = 'database/anomaly_detection.db'

# Full DDL executed once on init
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS predictions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          TEXT    NOT NULL,
    duration           REAL,
    protocol_type      TEXT,
    service            TEXT,
    flag               TEXT,
    src_bytes          REAL,
    dst_bytes          REAL,
    prediction         INTEGER,
    label              TEXT,
    probability        REAL,
    if_anomaly_score   REAL,
    model_used         TEXT,
    ip_src             TEXT,
    ip_dst             TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    title            TEXT    NOT NULL,
    description      TEXT,
    prediction_id    INTEGER,
    status           TEXT    NOT NULL DEFAULT 'open',
    acknowledged_at  TEXT,
    resolved_at      TEXT,
    tags             TEXT,
    FOREIGN KEY (prediction_id) REFERENCES predictions(id)
);

CREATE TABLE IF NOT EXISTS traffic_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    protocol    TEXT,
    service     TEXT,
    bytes_in    REAL,
    bytes_out   REAL,
    is_anomaly  INTEGER,
    label       TEXT
);

CREATE TABLE IF NOT EXISTS traffic_analyses (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    filename           TEXT    NOT NULL,
    original_filepath  TEXT,
    result_filepath    TEXT,
    timestamp          TEXT    NOT NULL,
    total_rows         INTEGER NOT NULL DEFAULT 0,
    normal_count       INTEGER NOT NULL DEFAULT 0,
    attack_count       INTEGER NOT NULL DEFAULT 0,
    suspicious_count   INTEGER NOT NULL DEFAULT 0,
    has_ground_truth   INTEGER NOT NULL DEFAULT 0,
    metrics_json       TEXT,
    summary_json       TEXT
);

CREATE TABLE IF NOT EXISTS analysis_records (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id        INTEGER NOT NULL,
    row_index          INTEGER NOT NULL,
    src_ip             TEXT,
    dst_ip             TEXT,
    src_port           TEXT,
    dst_port           TEXT,
    protocol           TEXT,
    service            TEXT,
    flag               TEXT,
    prediction         TEXT    NOT NULL,
    ground_truth       TEXT,
    probability        REAL,
    if_score           REAL,
    severity           TEXT    NOT NULL,
    attack_type        TEXT,
    explanation        TEXT,
    raw_json           TEXT,
    FOREIGN KEY (analysis_id) REFERENCES traffic_analyses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS monitoring_sessions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         TEXT    UNIQUE NOT NULL,
    interface_name     TEXT    NOT NULL,
    start_time         TEXT    NOT NULL,
    end_time           TEXT,
    status             TEXT    NOT NULL DEFAULT 'running',
    packet_count       INTEGER NOT NULL DEFAULT 0,
    flow_count         INTEGER NOT NULL DEFAULT 0,
    anomaly_count      INTEGER NOT NULL DEFAULT 0,
    notes              TEXT
);

CREATE TABLE IF NOT EXISTS captured_flows (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         TEXT    NOT NULL,
    timestamp          TEXT    NOT NULL,
    src_ip             TEXT    NOT NULL,
    dst_ip             TEXT    NOT NULL,
    src_port           INTEGER,
    dst_port           INTEGER,
    protocol           TEXT    NOT NULL,
    service            TEXT    NOT NULL DEFAULT 'other',
    direction          TEXT    NOT NULL DEFAULT 'inbound',
    packet_count       INTEGER NOT NULL DEFAULT 1,
    bytes_count        INTEGER NOT NULL DEFAULT 0,
    flag               TEXT    NOT NULL DEFAULT 'SF',
    prediction         TEXT    NOT NULL DEFAULT 'Safe',
    probability        REAL    NOT NULL DEFAULT 0.0,
    severity           TEXT    NOT NULL DEFAULT 'Low',
    attack_category    TEXT    NOT NULL DEFAULT 'Normal Traffic',
    status             TEXT    NOT NULL DEFAULT 'evaluated',
    FOREIGN KEY (session_id) REFERENCES monitoring_sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_conversations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id    TEXT    NOT NULL,
    timestamp          TEXT    NOT NULL,
    sender             TEXT    NOT NULL,
    message            TEXT    NOT NULL,
    language           TEXT    DEFAULT 'en-US',
    context_meta       TEXT
);

CREATE TABLE IF NOT EXISTS agent_reports (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          TEXT    NOT NULL,
    report_title       TEXT    NOT NULL,
    report_content     TEXT    NOT NULL,
    threat_level       TEXT    NOT NULL DEFAULT 'Low',
    summary_stats      TEXT
);

CREATE INDEX IF NOT EXISTS idx_records_analysis_id ON analysis_records(analysis_id);
CREATE INDEX IF NOT EXISTS idx_flows_session_id ON captured_flows(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_conv_id ON agent_conversations(conversation_id);
"""


def get_db():
    """
    Return a SQLite connection for the current Flask application context.
    Opens a new connection if one does not already exist on ``flask.g``.
    Row factory is set to ``sqlite3.Row`` so columns are accessible by name.
    """
    if 'db' not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(
            DB_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL;")
        g.db.execute("PRAGMA foreign_keys=ON;")
    return g.db


def _close_db(error=None):
    """Teardown function: closes the per-request database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(app):
    """
    Bind database helpers to *app* and create all tables on first run.

    Call this once after creating the Flask application instance:
        init_db(app)
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    # Create tables outside of an app-context push (safe for init time)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
        logger.info("Database schema verified / created at '%s'.", DB_PATH)
    except sqlite3.Error as exc:
        logger.error("Failed to initialise database schema: %s", exc)
        raise
    finally:
        conn.close()

    # Register per-request teardown so connections are always closed
    if _close_db not in app.teardown_appcontext_funcs and not getattr(app, "_got_first_request", False):
        app.teardown_appcontext(_close_db)
