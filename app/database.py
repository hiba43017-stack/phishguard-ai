"""
PhishGuard AI - Database Layer
Handles all SQLite database operations using parameterized queries
to prevent SQL injection attacks.
"""
import sqlite3
import json
import os
from datetime import datetime


# -------------------------------------------------------------------
# Schema Definition
# -------------------------------------------------------------------
CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender      TEXT    NOT NULL,
    subject     TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    risk_score  INTEGER NOT NULL,
    risk_level  TEXT    NOT NULL,
    verdict     TEXT    NOT NULL,
    ai_verdict  TEXT,
    ai_confidence INTEGER,
    rule_score  INTEGER DEFAULT 0,
    ai_score    INTEGER DEFAULT 0,
    indicators  TEXT,   -- JSON array of rule-based findings
    evidence    TEXT,   -- JSON array of evidence snippets
    reasons     TEXT,   -- JSON array of AI reasons
    recommended_actions TEXT, -- JSON array
    ai_explanation TEXT,
    ollama_used INTEGER DEFAULT 0,
    scanned_at  TEXT    NOT NULL
);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    """
    Create and return a SQLite connection with row_factory set
    so rows behave like dictionaries.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """
    Initialize the database schema.
    Creates all required tables if they don't exist.
    Called once at application startup.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(CREATE_SCANS_TABLE)

        # Migration: ensure rule_score and ai_score columns exist if DB was created previously
        for col_def in ("rule_score INTEGER DEFAULT 0", "ai_score INTEGER DEFAULT 0"):
            try:
                cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                # Column already exists
                pass

        conn.commit()
    finally:
        conn.close()


# -------------------------------------------------------------------
# Write Operations
# -------------------------------------------------------------------
def save_scan(db_path: str, scan_data: dict) -> int:
    """
    Save a completed email scan to the database.

    Args:
        db_path: Path to the SQLite database file.
        scan_data: Dictionary containing all scan fields.

    Returns:
        The ID of the newly inserted row.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                sender, subject, body,
                risk_score, risk_level, verdict,
                ai_verdict, ai_confidence,
                rule_score, ai_score,
                indicators, evidence, reasons,
                recommended_actions, ai_explanation,
                ollama_used, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_data.get('sender', ''),
                scan_data.get('subject', ''),
                scan_data.get('body', ''),
                scan_data.get('risk_score', 0),
                scan_data.get('risk_level', 'LOW'),
                scan_data.get('verdict', 'Safe'),
                scan_data.get('ai_verdict'),
                scan_data.get('ai_confidence'),
                scan_data.get('rule_score', 0),
                scan_data.get('ai_score', 0),
                json.dumps(scan_data.get('indicators', []) if isinstance(scan_data.get('indicators'), list) else []),
                json.dumps(scan_data.get('evidence', []) if isinstance(scan_data.get('evidence'), list) else []),
                json.dumps(scan_data.get('reasons', []) if isinstance(scan_data.get('reasons'), list) else []),
                json.dumps(scan_data.get('recommended_actions', []) if isinstance(scan_data.get('recommended_actions'), list) else []),
                scan_data.get('ai_explanation', ''),
                1 if scan_data.get('ollama_used') else 0,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def delete_scan(db_path: str, scan_id: int) -> bool:
    """
    Delete a single scan by its ID.

    Returns:
        True if a row was deleted, False if the ID was not found.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def clear_all_scans(db_path: str) -> int:
    """
    Delete every scan from the database.

    Returns:
        Number of rows deleted.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


# -------------------------------------------------------------------
# Read Operations
# -------------------------------------------------------------------
def get_scan_by_id(db_path: str, scan_id: int) -> dict | None:
    """
    Fetch a single scan by its ID.

    Returns:
        A dictionary representing the scan row, or None if not found.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row:
            return _row_to_dict(row)
        return None
    finally:
        conn.close()


def get_all_scans(db_path: str, limit: int = 100, offset: int = 0) -> list[dict]:
    """
    Fetch scans ordered newest-first with optional pagination.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        return [_row_to_dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def search_scans(db_path: str, query: str = '', risk_level: str = '') -> list[dict]:
    """
    Search scans by sender/subject text and optionally filter by risk level.
    Uses parameterized queries for safety.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        sql = "SELECT * FROM scans WHERE 1=1"
        params = []

        if query:
            sql += " AND (sender LIKE ? OR subject LIKE ?)"
            like = f"%{query}%"
            params.extend([like, like])

        if risk_level and risk_level.upper() in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            sql += " AND risk_level = ?"
            params.append(risk_level.upper())

        sql += " ORDER BY scanned_at DESC"
        cursor.execute(sql, params)
        return [_row_to_dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_dashboard_stats(db_path: str) -> dict:
    """
    Compute aggregate statistics for the dashboard.

    Returns:
        Dictionary with counts and averages.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # Total scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        total = cursor.fetchone()[0]

        # Count by verdict
        cursor.execute("SELECT verdict, COUNT(*) FROM scans GROUP BY verdict")
        verdict_counts = {row[0]: row[1] for row in cursor.fetchall()}

        # Count by risk level
        cursor.execute("SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level")
        level_counts = {row[0]: row[1] for row in cursor.fetchall()}

        # Average risk score
        cursor.execute("SELECT AVG(risk_score) FROM scans")
        avg_score = cursor.fetchone()[0]

        # Recent 5 scans
        cursor.execute(
            "SELECT id, sender, subject, risk_score, risk_level, verdict, scanned_at "
            "FROM scans ORDER BY scanned_at DESC LIMIT 5"
        )
        recent = [dict(row) for row in cursor.fetchall()]

        return {
            'total': total,
            'safe': verdict_counts.get('Safe', 0),
            'suspicious': verdict_counts.get('Suspicious', 0),
            'malicious': verdict_counts.get('Malicious', 0),
            'avg_score': round(avg_score, 1) if avg_score else 0,
            'level_counts': {
                'LOW': level_counts.get('LOW', 0),
                'MEDIUM': level_counts.get('MEDIUM', 0),
                'HIGH': level_counts.get('HIGH', 0),
                'CRITICAL': level_counts.get('CRITICAL', 0),
            },
            'recent': recent
        }
    finally:
        conn.close()


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _row_to_dict(row: sqlite3.Row) -> dict:
    """
    Convert a sqlite3.Row to a plain dict and decode JSON fields safely.
    Guarantees list types for indicators, evidence, reasons, recommended_actions.
    Guarantees rule_score and ai_score are integer fields.
    """
    data = dict(row)
    for field in ('indicators', 'evidence', 'reasons', 'recommended_actions'):
        val = data.get(field)
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                data[field] = parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, TypeError):
                data[field] = []
        elif isinstance(val, list):
            data[field] = val
        else:
            data[field] = []

    # Ensure rule_score and ai_score are present as integers
    if 'rule_score' not in data or data['rule_score'] is None:
        data['rule_score'] = min(sum(
            ind.get('points', 0) for ind in data['indicators'] if isinstance(ind, dict)
        ), 60)
    else:
        try:
            data['rule_score'] = int(data['rule_score'])
        except (ValueError, TypeError):
            data['rule_score'] = 0

    if 'ai_score' not in data or data['ai_score'] is None:
        data['ai_score'] = max(0, data.get('risk_score', 0) - data['rule_score'])
    else:
        try:
            data['ai_score'] = int(data['ai_score'])
        except (ValueError, TypeError):
            data['ai_score'] = 0

    return data
