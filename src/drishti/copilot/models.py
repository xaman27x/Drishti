from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from drishti.parsers.models import ParserFormat, SourceDefinitionPack


class CopilotProposal(BaseModel):
    """Untrusted suggestion: this object can never activate itself."""

    model_config = ConfigDict(frozen=True)

    detected_format: ParserFormat
    confidence: float = Field(ge=0, le=1)
    rationale: tuple[str, ...]
    sample_fingerprints: tuple[str, ...]
    unknown_captures: tuple[str, ...]
    pack: SourceDefinitionPack
