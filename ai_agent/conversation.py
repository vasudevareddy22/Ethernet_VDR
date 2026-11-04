"""
ai_agent/conversation.py
------------------------
Manages multi-turn conversation memory, database persistence,
and speech text clean-up for the AI SOC Agent.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from database.db import DB_PATH


def sanitize_markdown_for_speech(text: str) -> str:
    """
    Strips raw markdown syntax (bolding, headers, code fences, bullets, URLs)
    so speech synthesis sounds natural and clear through laptop speakers.
    """
    if not text:
        return ""

    # Remove code blocks ```...```
    cleaned = re.sub(r"```[\s\S]*?```", " Code snippet omitted for audio. ", text)
    # Remove inline code `...`
    cleaned = re.sub(r"`([^`]+)`", r"\1", cleaned)
    # Remove headers ###, ##, #
    cleaned = re.sub(r"#{1,6}\s*", "", cleaned)
    # Remove bullet markers like * or - or > (do this before bold/italic so bullet asterisks don't bleed across lines)
    cleaned = re.sub(r"^\s*[-*+>]\s+", "", cleaned, flags=re.MULTILINE)
    # Remove bold/italic asterisks and underscores on single lines
    cleaned = re.sub(r"\*{1,3}([^\n*]+)\*{1,3}", r"\1", cleaned)
    cleaned = re.sub(r"_{1,3}([^\n_]+)_{1,3}", r"\1", cleaned)
    # Remove bracketed links [text](url) -> text
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    # Remove table dividers |---|
    cleaned = re.sub(r"\|[-:\s|]+\|", "", cleaned)
    # Replace remaining pipes with comma
    cleaned = cleaned.replace("|", ", ")
    # Clean up any remaining asterisks or hashes
    cleaned = cleaned.replace("*", "").replace("#", "")
    # Squeeze duplicate spaces and newlines
    cleaned = re.sub(r"\n+", ". ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


class ConversationManager:
    """Stores and retrieves message history for active conversation sessions."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    def add_message(self, conversation_id: str, sender: str, message: str, language: str = "en-US", meta: str | None = None):
        """Append message to conversation history in SQLite."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                INSERT INTO agent_conversations (conversation_id, timestamp, sender, message, language, context_meta)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (conversation_id, datetime.now(timezone.utc).isoformat(), sender, message, language, meta),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            pass

    def get_history(self, conversation_id: str, limit: int = 30) -> list[dict[str, Any]]:
        """Retrieve recent turns for conversation context."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, conversation_id, timestamp, sender, message, language
                FROM agent_conversations
                WHERE conversation_id = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (conversation_id, limit),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def clear_history(self, conversation_id: str):
        """Clear conversation turns."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM agent_conversations WHERE conversation_id = ?", (conversation_id,))
            conn.commit()
            conn.close()
        except Exception:
            pass
