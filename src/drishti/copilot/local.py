from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Protocol

from drishti.copilot.models import CopilotProposal
from drishti.parsers.builtin import cef_firewall_pack, rfc5424_firewall_pack
from drishti.parsers.cef import CefParser
from drishti.parsers.common import ParseResult
from drishti.parsers.models import ParserFormat, SourceDefinitionPack
from drishti.parsers.rfc5424 import Rfc5424Parser


class UnsupportedFormat(ValueError):
    """The copilot refused to guess a format it could not prove."""


class Parser(Protocol):
    def parse(self, raw: bytes) -> ParseResult: ...


class AirGappedSchemaCopilot:
    """Local grammar induction with a fail-closed confidence boundary.

    This reference engine detects structural grammars without a network call.
    A future local LLM may propose labels, but output remains constrained to
    SourceDefinitionPack and must traverse the same human and qualification gates.
    """

    def propose(self, samples: list[bytes]) -> CopilotProposal:
        if not samples:
            raise ValueError("at least one raw sample is required")
        votes: Counter[ParserFormat] = Counter()
        parsers: dict[ParserFormat, Parser] = {
            ParserFormat.RFC5424: Rfc5424Parser(),
            ParserFormat.CEF: CefParser(),
        }
        successful: dict[ParserFormat, list[ParseResult]] = {key: [] for key in parsers}
        for sample in samples:
            for parser_format, parser in parsers.items():
                try:
                    parsed = parser.parse(sample)
                except ValueError:
                    continue
                votes[parser_format] += 1
                successful[parser_format].append(parsed)

        if not votes:
            raise UnsupportedFormat("no allowlisted grammar parsed any supplied sample")
        detected, matches = votes.most_common(1)[0]
        confidence = matches / len(samples)
        if confidence < 1.0:
            raise UnsupportedFormat(
                "sample set is heterogeneous or malformed; split it before proposing a parser"
            )
        pack = self._candidate_pack(detected).model_copy(
            update={"generated_by": "drishti.copilot.local-grammar@0.4.0"}
        )
        mapped = {rule.source_capture for rule in pack.rules if rule.source_capture}
        captures = {capture for parsed in successful[detected] for capture in parsed.captures}
        return CopilotProposal(
            detected_format=detected,
            confidence=confidence,
            rationale=(
                f"all {matches} samples satisfy the deterministic {detected.value} grammar",
                "candidate maps only through the transformation allowlist",
                "activation still requires independent human review and qualification",
            ),
            sample_fingerprints=tuple(self._fingerprint(sample) for sample in samples),
            unknown_captures=tuple(sorted(captures - mapped)),
            pack=pack,
        )

    @staticmethod
    def _candidate_pack(parser_format: ParserFormat) -> SourceDefinitionPack:
        if parser_format is ParserFormat.RFC5424:
            return rfc5424_firewall_pack()
        if parser_format is ParserFormat.CEF:
            return cef_firewall_pack()
        raise UnsupportedFormat(f"no candidate template for {parser_format}")

    @staticmethod
    def _fingerprint(sample: bytes) -> str:
        text = sample.decode("utf-8", errors="replace")
        skeleton = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", text)
        skeleton = re.sub(r"\b\d+\b", "<N>", skeleton)
        return hashlib.sha256(skeleton.encode()).hexdigest()
