"""
ai_agent/agent.py
-----------------
Main orchestrator for the AI SOC Analyst and Voice Agent.
Coordinates context collection, conversation history, provider inference,
and audio speech preparation.
"""

from __future__ import annotations

import logging
from typing import Any

from ai_agent.context_builder import ContextBuilder
from ai_agent.conversation import ConversationManager, sanitize_markdown_for_speech
from ai_agent.provider import LLMProvider

logger = logging.getLogger(__name__)


class SOCAnalystAgent:
    """Core AI SOC Analyst Agent service."""

    def __init__(self):
        self.context_builder = ContextBuilder()
        self.conversation_manager = ConversationManager()
        self.provider = LLMProvider()

    def get_status(self) -> dict[str, Any]:
        """Return agent health, provider configuration, and conversation capabilities."""
        prov_status = self.provider.get_status()
        return {
            "status": "operational",
            "agent_role": "Cybersecurity SOC Analyst",
            "provider": prov_status["provider"],
            "model": prov_status["model"],
            "is_connected": prov_status["is_connected"],
            "status_text": prov_status["status_text"],
            "ai_mode": prov_status["ai_mode"],
            "supported_languages": [
                {"code": "en-US", "name": "English (US)"},
                {"code": "en-IN", "name": "English (India)"},
                {"code": "hi-IN", "name": "Hindi (हिंदी)"},
                {"code": "te-IN", "name": "Telugu (తెలుగు)"},
                {"code": "ta-IN", "name": "Tamil (தமிழ்)"},
            ],
            "capabilities": {
                "voice_input": True,
                "voice_output": True,
                "two_way_voice": True,
                "context_grounding": True,
                "live_monitoring_aware": True,
            },
        }

    def process_chat(
        self,
        message: str,
        conversation_id: str = "default_session",
        language: str = "en-US",
        analysis_id: int | None = None,
    ) -> dict[str, Any]:
        """
        Process user query, ground in live database context, query model,
        persist conversation turn, and return both formatted text and clean spoken text.
        """
        if not message or not message.strip():
            return {
                "error": "Empty message",
                "response": "Please enter or speak a valid cybersecurity inquiry.",
                "spoken_text": "Please enter or speak a valid inquiry.",
            }

        # 1. Store user message in history
        self.conversation_manager.add_message(conversation_id, "user", message, language=language)

        # 2. Gather factual database context
        context_data = self.context_builder.get_system_context(analysis_id=analysis_id)
        context_text = self.context_builder.format_context_for_prompt(context_data)

        # 3. Retrieve conversation memory
        history = self.conversation_manager.get_history(conversation_id)

        # 4. Generate AI response
        ai_response = self.provider.generate_response(message, context_text, history)

        # 5. Sanitize text for browser speech output
        spoken_text = sanitize_markdown_for_speech(ai_response)

        # 6. Store assistant turn in history
        self.conversation_manager.add_message(conversation_id, "assistant", ai_response, language=language)

        return {
            "conversation_id": conversation_id,
            "response": ai_response,
            "spoken_text": spoken_text,
            "language": language,
            "context_summary": {
                "active_analysis_id": context_data.get("active_analysis", {}).get("id") if context_data.get("active_analysis") else None,
                "open_alerts": len(context_data.get("open_alerts", [])),
                "live_session_active": bool(context_data.get("live_session")),
            },
        }

    def get_context(self, analysis_id: int | None = None) -> dict[str, Any]:
        """Direct inspection endpoint for current context data."""
        return self.context_builder.get_system_context(analysis_id=analysis_id)

    def get_history(self, conversation_id: str) -> list[dict[str, Any]]:
        return self.conversation_manager.get_history(conversation_id)

    def clear_history(self, conversation_id: str):
        self.conversation_manager.clear_history(conversation_id)
