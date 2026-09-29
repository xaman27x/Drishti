"""Exercise the REAL running API, broker, object store and worker via HTTP."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from uuid import uuid4

from drishti.parsers.builtin import CEF_FIREWALL_SAMPLE, RFC5424_FIREWALL_SAMPLE


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--count", type=int, default=1, help="RFC5424 events; use 100 for upgrade comparison"
    )
    args = parser.parse_args()
    run_id = str(uuid4())

    def request(path: str, body: Mapping[str, object] | None = None) -> tuple[int, object]:
        req = urllib.request.Request(
            args.url + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    samples = [("generic.rfc5424-firewall", RFC5424_FIREWALL_SAMPLE, "normalized")] * args.count
    samples += [
        ("generic.cef-firewall", CEF_FIREWALL_SAMPLE, "normalized"),
        ("unknown", b"unknown format", "quarantined"),
        ("generic.rfc5424-firewall", b"bad syslog", "quarantined"),
    ]
    ids = []
    for index, (source, raw, expected) in enumerate(samples):
        body = {
            "tenant_id": "sih-demo",
            "source_id": f"demo-{source}",
            "source_type": source,
            "idempotency_key": f"{run_id}-{index}",
            "payload_base64": base64.b64encode(raw).decode(),
        }
        code, receipt = request("/v1/events", body)
        assert code == 202 and isinstance(receipt, dict), (code, receipt)
        event_id = receipt["event_id"]
        _, duplicate = request("/v1/events", body)
        assert (
            isinstance(duplicate, dict)
            and duplicate["duplicate"]
            and duplicate["trace_id"] == receipt["trace_id"]
        )
        code, _ = request(
            "/v1/events", {**body, "payload_base64": base64.b64encode(raw + b"different").decode()}
        )
        assert code == 409
        deadline = time.monotonic() + 60
        while True:
            _, status = request(f"/v1/events/{event_id}/status")
            assert isinstance(status, dict)
            if status["status"] == expected:
                break
            if time.monotonic() > deadline:
                raise TimeoutError(f"{event_id}: {status}")
            time.sleep(0.5)
        _, evidence = request(f"/v1/events/{event_id}/evidence")
        assert isinstance(evidence, dict)
        assert base64.b64decode(evidence["payload_base64"]) == raw
        assert evidence["raw_sha256"] == hashlib.sha256(raw).hexdigest()
        assert evidence["integrity_verified"]
        if expected == "normalized":
            code, normalized = request(f"/v1/events/{event_id}/normalized")
            assert code == 200 and isinstance(normalized, dict)
            assert normalized["certificate"]["raw_sha256"] == evidence["raw_sha256"]
            _, validation = request("/v1/ocsf/validate", {"event": normalized["ocsf_event"]})
            assert isinstance(validation, dict) and validation["valid"]
        if source == "generic.rfc5424-firewall" and expected == "normalized":
            ids.append(event_id)
        print(f"PASS {event_id} {source} -> {expected}")
    print("RFC5424 comparison event IDs:\n" + "\n".join(ids))


if __name__ == "__main__":
    main()
