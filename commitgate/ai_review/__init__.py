"""Public entry points for CommitGate's AI review package."""

from commitgate.ai_review.findings import parse_findings
from commitgate.ai_review.prompt import (
    SYSTEM_PROMPT,
    build_prompt,
    build_system_prompt,
)
from commitgate.ai_review.reviewer import review, review_staged
from commitgate.ai_review.transport import call_cli, call_llm

__all__ = [
    "SYSTEM_PROMPT",
    "build_prompt",
    "build_system_prompt",
    "call_cli",
    "call_llm",
    "parse_findings",
    "review",
    "review_staged",
]
