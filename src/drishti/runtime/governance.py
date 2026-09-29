from __future__ import annotations

import json
import os
from pathlib import Path

from drishti.governance.audit import AuditEntry
from drishti.governance.crypto import ArtifactSigner, PublicKeyRing, SignatureEnvelope, sha256_json
from drishti.governance.qualification import QualificationGate
from drishti.governance.registry import ParserRegistry, RegistryRelease, ReviewDecision
from drishti.governance.workflow import ParserControlPlane, ParserProposal
from drishti.ocsf.catalog import OcsfCatalog
from drishti.parsers.builtin import cef_firewall_pack, rfc5424_firewall_pack
from drishti.runtime.state import State
from drishti.safety.release_history import ReleaseHistory


def keyring(signer: ArtifactSigner) -> PublicKeyRing:
    keys = PublicKeyRing()
    keys.add_base64(signer.key_id, signer.public_key_base64())
    return keys


class Governance:
    """Signed state snapshot. API is the only live governance writer.

    Demo keys share a local volume, NOT independent production key custody.
    Bootstrap is an explicit operator action, never automatic AI approval.
    """

    def __init__(self, state: State, catalog: OcsfCatalog, directory: Path) -> None:
        self.state = state
        self.catalog = catalog
        key_path = directory / "keys.json"
        directory.mkdir(parents=True, exist_ok=True)
        if not key_path.exists():
            keys = {
                role: ArtifactSigner.generate(role).private_key_base64()
                for role in (
                    "parser-authority",
                    "registry-root",
                    "demo-reviewer",
                    "replay-approver",
                )
            }
            # Bootstrap/startup runs serially. O_EXCL prevents accidental overwrite.
            try:
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "w") as stream:
                    json.dump(keys, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
        values = json.loads(key_path.read_text())
        self.signers = {
            role: ArtifactSigner.from_base64(role, value) for role, value in values.items()
        }
        self.reload()

    def reload(self) -> None:
        root = self.signers["registry-root"]
        self.history = ReleaseHistory(log_id="drishti-local-releases", checkpoint_signer=root)
        self.registry = ParserRegistry(
            registry_signer=root,
            parser_keys=keyring(self.signers["parser-authority"]),
            reviewer_keys=keyring(self.signers["demo-reviewer"]),
            release_history=self.history,
        )
        self.control = ParserControlPlane(
            registry=self.registry,
            qualification_gate=QualificationGate(self.catalog),
            parser_signer=self.signers["parser-authority"],
        )
        saved = self.state.get("governance")
        if saved is None:
            return
        signature = SignatureEnvelope.model_validate(saved["signature"])
        if signature.artifact_sha256 != sha256_json(saved["document"]) or not keyring(root).verify(
            signature, purpose="drishti.runtime-state/v1"
        ):
            raise ValueError("governance snapshot signature failed")
        document = saved["document"]
        self.registry.restore(
            [RegistryRelease.model_validate(item) for item in document["releases"]]
        )
        self.control.audit_log.restore(
            [AuditEntry.model_validate(item) for item in document["audit"]]
        )
        self.control.restore_proposals(
            [ParserProposal.model_validate(item) for item in document["proposals"]]
        )

    def save(self) -> None:
        document = {
            "releases": [item.model_dump(mode="json") for item in self.registry.history],
            "audit": [item.model_dump(mode="json") for item in self.control.audit_log.entries],
            "proposals": [item.model_dump(mode="json") for item in self.control.proposals],
        }
        signature = self.signers["registry-root"].sign_digest(
            sha256_json(document), purpose="drishti.runtime-state/v1"
        )
        self.state.set(
            "governance", {"document": document, "signature": signature.model_dump(mode="json")}
        )

    async def approve_builtins(self) -> None:
        for pack in (rfc5424_firewall_pack(), cef_firewall_pack()):
            if self.registry.active_release(pack.source_key):
                continue
            proposal = self.control.submit(pack=pack, proposed_by="builtin-maintainer")
            self.control.review(
                proposal_id=proposal.proposal_id,
                reviewer_id="demo-reviewer",
                reviewer_signer=self.signers["demo-reviewer"],
                decision=ReviewDecision.APPROVE,
                reason=(
                    "Operator explicitly approved built-in packs using bootstrap --approve-builtins"
                ),
            )
            qualified = self.control.qualify(
                proposal_id=proposal.proposal_id, actor_id="qualification-runner"
            )
            self.save()
            if qualified.qualification is None or not qualified.qualification.passed:
                raise ValueError(f"qualification failed: {qualified.model_dump_json()}")
            await self.control.activate(
                proposal_id=proposal.proposal_id, actor_id="local-bootstrap"
            )
            self.save()
