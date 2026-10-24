"""Structural prompt-injection patterns (defanged, defensive).

Rule shapes are drawn from the taxonomy in the reference knowledge base
(Prompt Injection & Jailbreak Techniques — Comprehensive Reference,
https://gist.github.com/kibotu/c06f54d6fbc4705e886a50fb2e59e6ae), which
maps to OWASP LLM01:2025 (Prompt Injection), LLM07 (System Prompt Leakage),
and MITRE ATLAS AML.T0051/AML.T0054.

These are *structural* detectors: they match the shape of an instruction
override, persona jailbreak, delimiter escape, or leak request — not
weaponized payloads. Any text (chat input, RAG document, tool output) can
be scanned locally.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    code: str
    title: str
    severity: str  # high | medium | low
    taxonomy: str  # e.g. "OWASP LLM01:2025"
    regex: re.Pattern


def _p(code, title, severity, taxonomy, expr, flags=re.IGNORECASE) -> Pattern:
    return Pattern(code, title, severity, taxonomy, re.compile(expr, flags))


PATTERNS: list[Pattern] = [
    _p(
        "instruction-override",
        "Instruction override",
        "high",
        "OWASP LLM01:2025 / MITRE AML.T0051",
        r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b"
        r".{0,30}\b(instructions?|prompts?|rules?|directives?)\b",
    ),
    _p(
        "end-of-prompt-marker",
        "Fake end-of-prompt / role boundary",
        "high",
        "OWASP LLM01:2025",
        r"(---+\s*(end|stop)\s*(of\s*)?(the\s*)?(system|admin|developer)?\s*prompt"
        r"|new\s+(admin|system)\s+instruction|now\s+acting\s+as\s+the\s+(system|admin))",
    ),
    _p(
        "persona-jailbreak",
        "Persona / role-play jailbreak",
        "medium",
        "MITRE AML.T0054",
        r"(you\s+are\s+now\s+(dan|a\s+new\s+ai|an?\s+unfiltered)"
        r"|developer\s+mode\s+(enabled|on)"
        r"|without\s+(any\s+)?(moral|ethical|safety)\s+(guidelines|restrictions|filtering)"
        r"|ignore\s+your\s+(safety|content)\s+policy)",
    ),
    _p(
        "forced-affirmation",
        "Forced affirmative prefix",
        "medium",
        "OWASP LLM01:2025",
        r"(start\s+your\s+response\s+with\s+(exactly\s+)?[\"']?(sure|certainly|of course)"
        r"|begin\s+(your\s+)?(reply|answer)\s+with\s+[\"']?sure"
        r"|respond\s+only\s+with\s+[\"']?sure)",
    ),
    _p(
        "system-prompt-extraction",
        "System prompt extraction attempt",
        "medium",
        "OWASP LLM07:2025",
        r"(repeat\s+(and\s+display|verbatim|exactly)\s+your\s+"
        r"((initial|first|hidden|current)\s+)?(system\s+)?(prompt|message|instructions?)\b"
        r".{0,25}\b(verbatim|exactly|word-for-word)"
        r"|print\s+your\s+(hidden|system)\s+(prompt|instructions?)"
        r"|what\s+(are|is)\s+your\s+(initial|first|system)\s+(prompt|instructions?)\b.{0,20}\b(verbatim|exactly))",
    ),
    _p(
        "delimiter-escape",
        "Delimiter escape / XML-style injection",
        "medium",
        "OWASP LLM01:2025",
        r"(</?\s*(system|instructions?|prompt)\s*>|<<\s*(sys|system)\s*>>|\[\s*\/?\s*system\s*\])",
    ),
    _p(
        "encoded-payload",
        "Encoded payload (base64/hex blob) in text",
        "low",
        "MITRE AML.T0051",
        r"[A-Za-z0-9+/]{120,}={0,2}",
    ),
    _p(
        "obfuscation-markers",
        "Homoglyph / zero-width obfuscation markers",
        "low",
        "MITRE AML.T0051",
        "[​‌‍⁠﻿­]|\b(?:​|\u200b)+",
    ),
    _p(
        "tool-escape-request",
        "Request to hide instructions from tools/guardrails",
        "medium",
        "OWASP LLM01:2025",
        r"(do\s+not\s+(show|reveal|tell)\s+this\s+to"
        r"|hide\s+(this|these)\s+(instruction|prompt)s?\s+from"
        r"|bypass\s+(the\s+)?(guardrails?|filters?|moderation|content\s+policy))",
    ),
]

# Severity order used for the worst-severity rollup.
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def scan(text: str) -> list[dict]:
    """Scan `text`; return one dict per matching pattern (with context)."""
    findings = []
    for pattern in PATTERNS:
        match = pattern.regex.search(text)
        if not match:
            continue
        start = max(0, match.start() - 30)
        end = min(len(text), match.end() + 30)
        context = text[start:end].replace("\n", " ")
        findings.append({
            "code": pattern.code,
            "title": pattern.title,
            "severity": pattern.severity,
            "taxonomy": pattern.taxonomy,
            "span": [match.start(), match.end()],
            "context": ("…" if start > 0 else "") + context + ("…" if end < len(text) else ""),
        })
    findings.sort(key=lambda f: -SEVERITY_RANK[f["severity"]])
    return findings


def worst_severity(findings: list[dict]) -> str:
    return findings[0]["severity"] if findings else "clean"


def score(findings: list[dict]) -> int:
    """0-100 risk score: capped sum over findings, high-severity weighted."""
    total = 0
    for f in findings:
        total += {"high": 40, "medium": 20, "low": 5}[f["severity"]]
    return min(100, total)