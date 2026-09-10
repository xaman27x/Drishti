from __future__ import annotations

import base64

from drishti.parsers.models import (
    FieldRule,
    ParserFixture,
    ParserFormat,
    ResourceBudget,
    SourceDefinitionPack,
    Transform,
)

RFC5424_FIREWALL_SAMPLE = (
    b"<134>1 2026-09-26T14:00:00Z edge-fw-01 drishti-fw 1234 NETFLOW - "
    b"src=10.0.0.1 dst=10.0.0.2 spt=49152 dpt=443 proto=TCP action=allow"
)

CEF_FIREWALL_SAMPLE = (
    b"CEF:0|Acme|EdgeShield|1.2|100|Allowed TLS|5|"
    b"src=10.0.0.1 dst=10.0.0.2 spt=49152 dpt=443 proto=TCP rt=1790431200000"
)


def rfc5424_firewall_pack() -> SourceDefinitionPack:
    return SourceDefinitionPack(
        pack_uid="drishti.rfc5424-firewall",
        version="1.0.0",
        source_key="generic.rfc5424-firewall",
        display_name="Generic RFC5424 Perimeter Firewall",
        parser_format=ParserFormat.RFC5424,
        target_class_uid=4001,
        generated_by="drishti.builtin@0.3.0",
        budget=ResourceBudget(max_event_bytes=65_536, max_p95_parse_ms=10),
        rules=_network_rules(
            timestamp_capture="timestamp",
            timestamp_transform=Transform.RFC3339_TO_EPOCH_MS,
            severity_capture="pri",
            severity_transform=Transform.SYSLOG_PRI_TO_OCSF_SEVERITY,
            src_capture="msg.src",
            dst_capture="msg.dst",
            src_port_capture="msg.spt",
            dst_port_capture="msg.dpt",
            protocol_capture="msg.proto",
            product_name="Drishti RFC5424 Firewall",
        ),
        fixtures=(
            ParserFixture(
                name="rfc5424-firewall-allow",
                raw_base64=base64.b64encode(RFC5424_FIREWALL_SAMPLE).decode(),
                expected_fields={
                    "class_uid": 4001,
                    "type_uid": 400106,
                    "src_endpoint.ip": "10.0.0.1",
                    "dst_endpoint.port": 443,
                    "connection_info.protocol_name": "tcp",
                    "severity_id": 1,
                },
            ),
        ),
    )


def cef_firewall_pack() -> SourceDefinitionPack:
    rules = list(
        _network_rules(
            timestamp_capture="ext.rt",
            timestamp_transform=Transform.INTEGER,
            severity_capture="severity",
            severity_transform=Transform.CEF_SEVERITY_TO_OCSF,
            src_capture="ext.src",
            dst_capture="ext.dst",
            src_port_capture="ext.spt",
            dst_port_capture="ext.dpt",
            protocol_capture="ext.proto",
            product_name=None,
        )
    )
    rules.extend(
        (
            FieldRule(source_capture="device.product", target_path="metadata.product.name"),
            FieldRule(source_capture="device.vendor", target_path="metadata.product.vendor_name"),
            FieldRule(source_capture="device.version", target_path="metadata.product.version"),
        )
    )
    return SourceDefinitionPack(
        pack_uid="drishti.cef-firewall",
        version="1.0.0",
        source_key="generic.cef-firewall",
        display_name="Generic CEF Perimeter Firewall",
        parser_format=ParserFormat.CEF,
        target_class_uid=4001,
        generated_by="drishti.builtin@0.3.0",
        budget=ResourceBudget(max_event_bytes=65_536, max_p95_parse_ms=10),
        rules=tuple(rules),
        fixtures=(
            ParserFixture(
                name="cef-firewall-allow",
                raw_base64=base64.b64encode(CEF_FIREWALL_SAMPLE).decode(),
                expected_fields={
                    "class_uid": 4001,
                    "type_uid": 400106,
                    "metadata.product.name": "EdgeShield",
                    "src_endpoint.ip": "10.0.0.1",
                    "dst_endpoint.port": 443,
                    "connection_info.protocol_name": "tcp",
                    "severity_id": 3,
                },
            ),
        ),
    )


def _network_rules(
    *,
    timestamp_capture: str,
    timestamp_transform: Transform,
    severity_capture: str,
    severity_transform: Transform,
    src_capture: str,
    dst_capture: str,
    src_port_capture: str,
    dst_port_capture: str,
    protocol_capture: str,
    product_name: str | None,
) -> tuple[FieldRule, ...]:
    rules = [
        FieldRule(constant=6, target_path="activity_id"),
        FieldRule(constant=4, target_path="category_uid"),
        FieldRule(constant=4001, target_path="class_uid"),
        FieldRule(constant=0, target_path="connection_info.direction_id"),
        FieldRule(constant="1.9.0", target_path="metadata.version"),
        FieldRule(constant=400106, target_path="type_uid"),
        FieldRule(
            source_capture=timestamp_capture,
            target_path="time",
            transform=timestamp_transform,
            required=True,
        ),
        FieldRule(
            source_capture=severity_capture,
            target_path="severity_id",
            transform=severity_transform,
            required=True,
        ),
        FieldRule(
            source_capture=src_capture,
            target_path="src_endpoint.ip",
            transform=Transform.IP_ADDRESS,
        ),
        FieldRule(
            source_capture=dst_capture,
            target_path="dst_endpoint.ip",
            transform=Transform.IP_ADDRESS,
        ),
        FieldRule(
            source_capture=src_port_capture,
            target_path="src_endpoint.port",
            transform=Transform.INTEGER,
        ),
        FieldRule(
            source_capture=dst_port_capture,
            target_path="dst_endpoint.port",
            transform=Transform.INTEGER,
        ),
        FieldRule(
            source_capture=protocol_capture,
            target_path="connection_info.protocol_name",
            transform=Transform.LOWERCASE,
        ),
    ]
    if product_name is not None:
        rules.append(FieldRule(constant=product_name, target_path="metadata.product.name"))
    return tuple(rules)
