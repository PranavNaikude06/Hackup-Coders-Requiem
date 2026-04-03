import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field

load_dotenv()

# ─────────── Output Schema ───────────
class PhishingVerdict(BaseModel):
    verdict: str = Field(description="One of: PHISHING, SUSPICIOUS, or SAFE")
    combined_score: int = Field(description="Integer from 0 to 100 indicating phishing risk. 0=completely safe, 100=definitive phishing.")
    human_explanation: str = Field(description="A 2-3 sentence plain-English explanation WHY this combination is safe or suspicious. No ML jargon.")
    escalate_to_phishing: bool = Field(description="True if a severe contextual mismatch is present that definitively indicates phishing intent.")

# ─────────── Prompt ───────────
SYSTEM_PROMPT = """You are ThreatLens, an expert AI cybersecurity analyst specializing in phishing detection.

A user submitted the following email and URL for analysis. Your job is to reason like a human analyst:
- Does the actual sender email address reasonably match the brand or service claimed in the email body or subject?
- Does the email's claimed purpose match what the URL actually does?
- Is the sender creating urgency or fear to pressure the user?
- Does the URL look suspicious (typosquatting, weird domain)?

Sender Address: {sender}
Email Subject: {subject}
Primary Extracted URL: {url}

Email Body:
{email}

Based on your analysis, return a JSON response using this schema:
{format_instructions}

Important scoring guide:
- 0-39: SAFE (everything checks out)
- 40-69: SUSPICIOUS (something feels off but not confirmed)
- 70-100: PHISHING (clear deception detected)"""

class LLMAnalyzer:
    def __init__(self):
        self.parser = JsonOutputParser(pydantic_object=PhishingVerdict)
        self.prompt = PromptTemplate(
            template=SYSTEM_PROMPT,
            input_variables=["url", "email", "sender", "subject"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()},
        )

        # Primary: Groq (Llama 3.3 70B)
        groq_key = os.getenv("GROQ_API_KEY")
        self.primary_llm = None
        if groq_key:
            try:
                self.primary_llm = ChatGroq(
                    model="llama-3.3-70b-versatile",
                    api_key=groq_key,
                    temperature=0.1
                )
                print("[LLM] Groq (Llama 3.3 70B) — primary ready")
            except Exception as e:
                print(f"[LLM] Groq init failed: {e}")

        # Fallback: OpenRouter (Gemma 3 27B)
        openrouter_key = os.getenv("OPENROUTER_API_KEY")
        self.fallback_llm = None
        if openrouter_key:
            try:
                self.fallback_llm = ChatOpenAI(
                    model="google/gemma-3-27b-it",
                    api_key=openrouter_key,
                    base_url="https://openrouter.ai/api/v1",
                    temperature=0.1,
                    default_headers={
                        "HTTP-Referer": "http://localhost:8765",
                        "X-Title": "ThreatLens"
                    }
                )
                print("[LLM] OpenRouter (Gemma 3 27B) — fallback ready")
            except Exception as e:
                print(f"[LLM] OpenRouter init failed: {e}")

    def _run_chain(self, llm, url: str, email: str, sender: str, subject: str) -> dict:
        chain = self.prompt | llm | self.parser
        return chain.invoke({"url": url, "email": email, "sender": sender, "subject": subject})

    def analyze(self, url: str, email: str, sender: str = "", subject: str = "") -> dict:
        """
        Priority chain:
          1. Groq (Llama 3.3 70B) — primary
          2. OpenRouter (Gemma 3 27B) — fallback
          3. Returns {"error": ...} if both fail → ScoringEngine falls back to ML
        """
        inputs_url = url or "No URL provided"
        inputs_email = email or "No email body provided"
        inputs_sender = sender or "No sender provided"
        inputs_subject = subject or "No subject provided"

        # ── Try Groq ──
        if self.primary_llm:
            try:
                result = self._run_chain(self.primary_llm, inputs_url, inputs_email, inputs_sender, inputs_subject)
                result["_provider"] = "groq"
                return result
            except Exception as e:
                err = str(e).lower()
                reason = "rate limited" if ("rate" in err or "429" in err) else str(e)
                print(f"[LLM] Groq failed ({reason}) — trying OpenRouter fallback")

        # ── Try OpenRouter ──
        if self.fallback_llm:
            try:
                result = self._run_chain(self.fallback_llm, inputs_url, inputs_email, inputs_sender, inputs_subject)
                result["_provider"] = "openrouter_gemma"
                return result
            except Exception as e:
                print(f"[LLM] OpenRouter failed ({e}) — falling back to ML pipeline")

        # ── Both failed ──
        return {"error": "Both LLM providers unavailable. ML pipeline will handle analysis."}
