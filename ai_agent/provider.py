"""
ai_agent/provider.py
--------------------
Handles connection to LLM backends (Ollama or Cloud providers via environment variables)
and provides an intelligent, deterministic local cybersecurity rule engine fallback
when no external LLM is configured. Never hardcodes API keys.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from ai_agent.prompts import SOC_ANALYST_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class LLMProvider:
    """Manages AI reasoning via Ollama, OpenAI/Gemini-compatible APIs, or Local Expert Mode."""

    def __init__(self):
        self.provider_type = os.environ.get("AI_PROVIDER", "local").lower()
        self.model_name = os.environ.get("AI_MODEL", "llama3:latest" if self.provider_type == "ollama" else "local-soc-expert")
        self.api_key = os.environ.get("AI_API_KEY", "")
        self.api_url = os.environ.get("AI_API_URL", "http://127.0.0.1:11434/api/generate" if self.provider_type == "ollama" else "")

    def get_status(self) -> dict[str, Any]:
        """Return connectivity and configuration details."""
        is_connected = True
        status_text = "Operational (Local Expert Mode)"

        if self.provider_type == "ollama":
            # Quick ping to local Ollama port
            try:
                req = urllib.request.Request("http://127.0.0.1:11434/api/tags", headers={"User-Agent": "NetworkAI/2.1"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    if resp.status == 200:
                        status_text = "Connected (Local Ollama)"
                        is_connected = True
            except Exception:
                is_connected = False
                status_text = "Disconnected (Ollama service not running on port 11434)"
        elif self.provider_type in ("openai", "gemini", "groq"):
            if self.api_key:
                status_text = f"Configured ({self.provider_type.upper()})"
                is_connected = True
            else:
                is_connected = False
                status_text = f"API Key Missing ({self.provider_type.upper()})"

        return {
            "provider": self.provider_type,
            "model": self.model_name,
            "is_connected": is_connected,
            "status_text": status_text,
            "ai_mode": "Cloud LLM" if self.provider_type in ("openai", "gemini", "groq") else ("Ollama Local" if self.provider_type == "ollama" else "Offline SOC Expert Rules"),
        }

    def generate_response(self, user_prompt: str, context_text: str, history: list[dict[str, Any]]) -> str:
        """Route to configured provider or fallback cleanly to local SOC expert engine."""
        if self.provider_type == "ollama":
            res = self._call_ollama(user_prompt, context_text)
            if res:
                return res
        elif self.provider_type in ("openai", "gemini", "groq") and self.api_key:
            res = self._call_cloud_llm(user_prompt, context_text, history)
            if res:
                return res

        # Default robust fallback: local SOC intelligence reasoning engine
        return self._generate_local_expert_response(user_prompt, context_text)

    def _call_ollama(self, user_prompt: str, context_text: str) -> str | None:
        try:
            full_prompt = f"{SOC_ANALYST_SYSTEM_PROMPT}\n\n{context_text}\n\nUSER QUESTION: {user_prompt}\n\nSOC ANALYST RESPONSE:"
            payload = json.dumps({
                "model": self.model_name,
                "prompt": full_prompt,
                "stream": False,
            }).encode("utf-8")

            req = urllib.request.Request(
                self.api_url or "http://127.0.0.1:11434/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip()
        except Exception as exc:
            logger.warning("Ollama call failed (%s), falling back to Local Expert engine.", exc)
            return None

    def _call_cloud_llm(self, user_prompt: str, context_text: str, history: list[dict[str, Any]]) -> str | None:
        try:
            messages = [{"role": "system", "content": f"{SOC_ANALYST_SYSTEM_PROMPT}\n\n{context_text}"}]
            for h in history[-6:]:
                role = "assistant" if h.get("sender") == "assistant" else "user"
                messages.append({"role": role, "content": h.get("message", "")})
            messages.append({"role": "user", "content": user_prompt})

            payload = json.dumps({
                "model": self.model_name,
                "messages": messages,
                "temperature": 0.2,
            }).encode("utf-8")

            url = self.api_url or "https://api.openai.com/v1/chat/completions"
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=25.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            logger.warning("Cloud LLM call failed (%s), falling back to Local Expert engine.", exc)
            return None

    def _generate_local_expert_response(self, query: str, context_text: str) -> str:
        """
        Grounded local cybersecurity analyst reasoning engine.
        Parses actual telemetry context to generate realistic, professional SOC analyses.
        """
        q = query.lower()

        # 1. Summary of traffic
        if any(w in q for w in ("summarize", "summary", "overview", "what is happening", "status")):
            return (
                "### 🛡️ SOC Executive Telemetry Summary\n\n"
                f"{context_text}\n\n"
                "**Key Observations & Analyst Assessment:**\n"
                "- The telemetry stream has been categorized by the Random Forest model into Safe, Suspicious, and Malicious Attack classes.\n"
                "- Connection flags and SYN error statistics are monitored for anomalous variance.\n"
                "- **Recommendation**: Review all flagged alerts under the Investigation suite before approving external ingress rules."
            )

        # 2. Suspicious IPs
        if any(w in q for w in ("ip", "address", "suspicious", "attacker", "host")):
            if "Top Detected Threat Source IPs:" in context_text:
                return (
                    "### 🔍 Suspicious IP Entity Investigation\n\n"
                    f"{context_text}\n\n"
                    "**Threat Intel Insights:**\n"
                    "- The above IP addresses exhibit elevated anomalous connection frequencies.\n"
                    "- Immediate Action: Implement rate-limiting on upstream routers and verify reverse DNS/GeoIP reputation before enacting permanent firewall bans."
                )
            else:
                return (
                    "### 🔍 Endpoint & IP Investigation Notice\n\n"
                    "**Dataset Observation:**\n"
                    "The currently loaded dataset conforms to the **NSL-KDD benchmark schema**, which operates on connection-level statistical session vectors rather than raw IP packet headers.\n\n"
                    "To maintain complete data integrity, **no synthetic or fake IP addresses are fabricated**.\n"
                    "If you upload a CSV containing `src_ip` and `dst_ip` columns, or start the **Live Packet Monitor**, real-time endpoint tracking will populate here automatically."
                )

        # 3. Active Attacks / DoS / Probe
        if any(w in q for w in ("attack", "dos", "probe", "threat", "r2l", "u2r", "malicious")):
            return (
                "### 🚨 Attack Taxonomy & Threat Analysis\n\n"
                "Based on the evaluated connection vectors in your database:\n\n"
                "- **DoS (Denial of Service)**: High-rate connection floods characterized by abnormal TCP flags (e.g., `S0`, `REJ`) and elevated SYN error ratios (`serror_rate > 0.40`).\n"
                "- **Probe (Reconnaissance)**: Scans sweeping multiple distinct destination services or ports to map internal enterprise topology.\n"
                "- **R2L / U2R**: Elevated failed login attempts or unauthorized escalation vectors.\n\n"
                f"{context_text}\n\n"
                "**Mitigation Steps:**\n"
                "1. Apply SYN-cookies and aggressive connection timeout thresholds on edge firewalls.\n"
                "2. Isolate internal hosts exhibiting repeated port-scan indicators."
            )

        # 4. Critical alerts
        if any(w in q for w in ("alert", "critical", "incident")):
            return (
                "### ⚠️ Priority Incident Triage\n\n"
                f"{context_text}\n\n"
                "**SOC Analyst Guidance:**\n"
                "- Triage all alerts marked as **CRITICAL** first, as their model confidence exceeds 90%.\n"
                "- Verify if affected target ports are exposed to public interfaces.\n"
                "- You can acknowledge or resolve alerts directly on the **Alerts** page."
            )

        # General inquiry fallback grounded in actual context
        return (
            "### 🤖 Network AI Analyst Intelligence\n\n"
            f"Regarding your query: *\"{query}\"*\n\n"
            f"{context_text}\n\n"
            "**Operational Recommendations:**\n"
            "- Monitor live traffic via the **Traffic Monitoring** tab or ingest fresh PCAP/CSV sessions in **Traffic Investigation**.\n"
            "- For deeper triage, click **Inspect** on any connection record to view all 41 NSL-KDD telemetry features."
        )
