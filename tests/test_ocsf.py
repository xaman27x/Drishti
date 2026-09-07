from typing import Any

from drishti.ocsf.catalog import get_ocsf_catalog


def network_event(**updates: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "activity_id": 1,
        "category_uid": 4,
        "class_uid": 4001,
        "metadata": {
            "product": {"name": "Drishti"},
            "version": "1.9.0",
        },
        "severity_id": 1,
        "src_endpoint": {"ip": "10.0.0.1", "uid": "10.0.0.1"},
        "time": 1_798_000_000_000,
        "type_uid": 400101,
    }
    event.update(updates)
    return event


def test_loads_pinned_air_gapped_contract() -> None:
    catalog = get_ocsf_catalog()

    assert catalog.identity.ocsf_version == "1.9.0"
    assert catalog.identity.drishti_extension_version == "0.1.0"
    assert len(catalog.identity.bundle_sha256) == 64
    assert catalog.class_name_for_uid(4001) == "network_activity"


def test_accepts_valid_network_activity() -> None:
    report = get_ocsf_catalog().validate(network_event())

    assert report.valid is True
    assert report.class_name == "network_activity"
    assert report.issues == ()


def test_rejects_semantically_inconsistent_identifiers() -> None:
    report = get_ocsf_catalog().validate(network_event(category_uid=5, type_uid=400199))

    assert report.valid is False
    assert {issue.code for issue in report.issues} >= {
        "category_uid_mismatch",
        "type_uid_mismatch",
    }


def test_rejects_invalid_nested_primitive_and_unknown_field() -> None:
    report = get_ocsf_catalog().validate(
        network_event(
            src_endpoint={"ip": "999.10.1.1", "uid": "999.10.1.1"},
            invented_field="unsafe",
        )
    )

    assert report.valid is False
    issues = {(issue.code, issue.path) for issue in report.issues}
    assert ("invalid_format", "src_endpoint.ip") in issues
    assert ("unknown_field", "invented_field") in issues
