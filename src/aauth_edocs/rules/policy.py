"""Pluggable enforcement of natural-language policy rules.

The controller writes the policy; an enforcer (typically an LLM) only judges
whether one concrete, digest-verified function call satisfies it. Enforcers
must treat everything in the question except ``policy`` as untrusted data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from threading import Lock
from typing import Protocol

from ..edocs import Dataflow


def source_digest(source: str) -> str:
    """Digest a function's raw source the way function registration must."""
    return f"sha256:{hashlib.sha256(source.encode('utf-8')).hexdigest()}"


@dataclass(frozen=True)
class FunctionSource:
    runtime: str
    source: str


@dataclass(frozen=True)
class PolicyQuestion:
    policy: str
    proposal: Dataflow
    function_id: str
    function: FunctionSource


@dataclass(frozen=True)
class PolicyVerdict:
    allowed: bool
    reason: str


class PolicyEnforcer(Protocol):
    def judge(self, question: PolicyQuestion) -> PolicyVerdict: ...


class FailClosedEnforcer:
    """Turn every failure or malformed verdict from ``inner`` into a denial."""

    def __init__(self, inner: PolicyEnforcer) -> None:
        self._inner = inner

    def judge(self, question: PolicyQuestion) -> PolicyVerdict:
        try:
            verdict = self._inner.judge(question)

        # if error or malformed verdict, return a denial
        except Exception as error:
            return PolicyVerdict(False, f"policy enforcer failed: {type(error).__name__}")
        if not _well_formed(verdict):
            return PolicyVerdict(False, "policy enforcer returned a malformed verdict")
        return verdict


class CachingEnforcer:
    """Answer identical questions identically; failures are not cached."""

    def __init__(self, inner: PolicyEnforcer) -> None:
        self._inner = inner
        self._lock = Lock()
        self._verdicts: dict[PolicyQuestion, PolicyVerdict] = {}

    def judge(self, question: PolicyQuestion) -> PolicyVerdict:
        with self._lock:
            cached = self._verdicts.get(question)
        if cached is not None:
            return cached
        verdict = self._inner.judge(question)
        if _well_formed(verdict):
            # if well-formed, cache the verdict
            with self._lock:
                verdict = self._verdicts.setdefault(question, verdict)
        return verdict


def _well_formed(verdict: object) -> bool:
    return (
        isinstance(verdict, PolicyVerdict)
        and isinstance(verdict.allowed, bool)
        and isinstance(verdict.reason, str)
        and bool(verdict.reason.strip())
    )
