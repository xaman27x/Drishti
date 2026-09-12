from __future__ import annotations

import pytest

from drishti.copilot.local import AirGappedSchemaCopilot, UnsupportedFormat
from drishti.parsers.builtin import CEF_FIREWALL_SAMPLE, RFC5424_FIREWALL_SAMPLE
from drishti.parsers.models import ParserFormat


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        (RFC5424_FIREWALL_SAMPLE, ParserFormat.RFC5424),
        (CEF_FIREWALL_SAMPLE, ParserFormat.CEF),
    ],
)
def test_copilot_proposes_but_does_not_activate(sample: bytes, expected: ParserFormat) -> None:
    proposal = AirGappedSchemaCopilot().propose([sample])
    assert proposal.detected_format is expected
    assert proposal.confidence == 1.0
    assert proposal.pack.generated_by.startswith("drishti.copilot")
    assert proposal.sample_fingerprints


def test_copilot_refuses_heterogeneous_samples() -> None:
    with pytest.raises(UnsupportedFormat, match="heterogeneous"):
        AirGappedSchemaCopilot().propose([RFC5424_FIREWALL_SAMPLE, b"unrecognized"])
