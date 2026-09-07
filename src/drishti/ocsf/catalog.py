from __future__ import annotations

import gzip
import hashlib
import json
import re
from collections.abc import Mapping
from functools import lru_cache
from importlib import resources
from typing import Any

from drishti.ocsf.models import SchemaIdentity, ValidationIssue, ValidationReport

JsonObject = dict[str, Any]


class OcsfCatalog:
    """Immutable runtime view of the exact OCSF contract shipped with Drishti."""

    def __init__(self, schema: JsonObject, identity: SchemaIdentity) -> None:
        self._schema = schema
        self.identity = identity
        self._classes_by_uid = {
            definition["uid"]: (name, definition) for name, definition in schema["classes"].items()
        }

    @classmethod
    def load_packaged(cls) -> OcsfCatalog:
        asset_root = resources.files("drishti.ocsf.assets")
        manifest = json.loads(asset_root.joinpath("bundle-manifest.json").read_text())
        compressed = asset_root.joinpath(manifest["asset"]).read_bytes()
        canonical = gzip.decompress(compressed)
        actual_sha256 = hashlib.sha256(canonical).hexdigest()
        if actual_sha256 != manifest["bundle_sha256"]:
            raise RuntimeError("packaged OCSF schema bundle failed its integrity check")
        schema: JsonObject = json.loads(canonical)
        identity = SchemaIdentity(
            ocsf_version=manifest["ocsf_version"],
            drishti_extension_version=manifest["drishti_extension_version"],
            bundle_sha256=actual_sha256,
        )
        if schema["version"] != identity.ocsf_version:
            raise RuntimeError("packaged OCSF version does not match its manifest")
        return cls(schema, identity)

    def class_name_for_uid(self, class_uid: int) -> str | None:
        resolved = self._classes_by_uid.get(class_uid)
        return None if resolved is None else resolved[0]

    def validate(
        self, event: Mapping[str, Any], *, reject_unknown: bool = True
    ) -> ValidationReport:
        value = dict(event)
        issues: list[ValidationIssue] = []
        class_uid = value.get("class_uid")
        if not self._is_integer(class_uid):
            issues.append(self._issue("invalid_class_uid", "class_uid", "must be an integer"))
            return self._report(value, None, issues)

        resolved = self._classes_by_uid.get(class_uid)
        if resolved is None:
            issues.append(
                self._issue("unknown_class_uid", "class_uid", f"{class_uid} is not in this bundle")
            )
            return self._report(value, None, issues)

        class_name, definition = resolved
        self._validate_record(
            value,
            definition,
            path="",
            issues=issues,
            reject_unknown=reject_unknown,
            depth=0,
        )
        expected_category_uid = definition["uid"] // 1000
        if value.get("category_uid") != expected_category_uid:
            issues.append(
                self._issue(
                    "category_uid_mismatch",
                    "category_uid",
                    f"expected {expected_category_uid} for class {class_name}",
                )
            )
        activity_id = value.get("activity_id")
        if self._is_integer(activity_id):
            expected_type_uid = definition["uid"] * 100 + activity_id
            if value.get("type_uid") != expected_type_uid:
                issues.append(
                    self._issue(
                        "type_uid_mismatch",
                        "type_uid",
                        f"expected {expected_type_uid} for activity_id {activity_id}",
                    )
                )
        return self._report(value, class_name, issues)

    def _validate_record(
        self,
        value: Mapping[str, Any],
        definition: JsonObject,
        *,
        path: str,
        issues: list[ValidationIssue],
        reject_unknown: bool,
        depth: int,
    ) -> None:
        if depth > 20:
            issues.append(self._issue("maximum_depth", path, "object nesting exceeds 20 levels"))
            return
        attributes: JsonObject = definition.get("attributes", {})
        for name, attribute in attributes.items():
            if attribute.get("requirement") == "required" and attribute.get("profile") is None:
                if name not in value or value[name] is None:
                    issues.append(
                        self._issue("required_field", self._join(path, name), "is required")
                    )

        if reject_unknown:
            for name in value:
                if name not in attributes:
                    issues.append(
                        self._issue(
                            "unknown_field",
                            self._join(path, name),
                            "is not in the class contract",
                        )
                    )

        for name, member in value.items():
            attribute = attributes.get(name)
            if attribute is None or member is None:
                continue
            self._validate_attribute(
                member,
                attribute,
                path=self._join(path, name),
                issues=issues,
                reject_unknown=reject_unknown,
                depth=depth + 1,
            )
        self._validate_constraints(value, definition.get("constraints"), path, issues)

    def _validate_attribute(
        self,
        value: Any,
        attribute: JsonObject,
        *,
        path: str,
        issues: list[ValidationIssue],
        reject_unknown: bool,
        depth: int,
    ) -> None:
        if attribute.get("is_array"):
            if not isinstance(value, list):
                issues.append(self._issue("invalid_type", path, "must be an array"))
                return
            item_attribute = dict(attribute)
            item_attribute["is_array"] = False
            for index, item in enumerate(value):
                self._validate_attribute(
                    item,
                    item_attribute,
                    path=f"{path}[{index}]",
                    issues=issues,
                    reject_unknown=reject_unknown,
                    depth=depth,
                )
            return

        type_name = attribute.get("type")
        objects: JsonObject = self._schema["objects"]
        if type_name in objects:
            if not isinstance(value, dict):
                issues.append(self._issue("invalid_type", path, f"must be a {type_name} object"))
                return
            self._validate_record(
                value,
                objects[type_name],
                path=path,
                issues=issues,
                reject_unknown=reject_unknown,
                depth=depth,
            )
        else:
            self._validate_primitive(value, str(type_name), path, issues)

        enum = attribute.get("enum")
        if enum is not None and str(value) not in enum:
            issues.append(self._issue("invalid_enum", path, f"{value!r} is not an allowed value"))

    def _validate_primitive(
        self, value: Any, type_name: str, path: str, issues: list[ValidationIssue]
    ) -> None:
        types: JsonObject = self._schema["types"]
        type_definition = types.get(type_name)
        if type_definition is None:
            issues.append(
                self._issue("unknown_type", path, f"schema type {type_name!r} is unknown")
            )
            return
        root_type = type_name
        seen: set[str] = set()
        while type_definition.get("type") and root_type not in seen:
            seen.add(root_type)
            root_type = type_definition["type"]
            type_definition = types[root_type]

        valid = True
        if root_type in {"integer_t", "long_t", "timestamp_t", "port_t"}:
            valid = self._is_integer(value)
        elif root_type == "float_t":
            valid = isinstance(value, (int, float)) and not isinstance(value, bool)
        elif root_type == "boolean_t":
            valid = isinstance(value, bool)
        elif root_type != "json_t":
            valid = isinstance(value, str)
        if not valid:
            issues.append(self._issue("invalid_type", path, f"must conform to {type_name}"))
            return

        definition = types[type_name]
        max_len = definition.get("max_len")
        if isinstance(value, str) and max_len is not None and len(value) > max_len:
            issues.append(
                self._issue("maximum_length", path, f"must not exceed {max_len} characters")
            )
        pattern = definition.get("regex")
        if isinstance(value, str) and pattern:
            try:
                matches = re.fullmatch(pattern, value) is not None
            except re.error:
                matches = True
            if not matches:
                issues.append(self._issue("invalid_format", path, f"must conform to {type_name}"))

    def _validate_constraints(
        self,
        value: Mapping[str, Any],
        constraints: JsonObject | None,
        path: str,
        issues: list[ValidationIssue],
    ) -> None:
        if not constraints:
            return
        at_least_one = constraints.get("at_least_one", [])
        if at_least_one and not any(value.get(field) is not None for field in at_least_one):
            issues.append(
                self._issue(
                    "at_least_one",
                    path,
                    f"at least one of {', '.join(at_least_one)} is required",
                )
            )
        just_one = constraints.get("just_one", [])
        if just_one and sum(value.get(field) is not None for field in just_one) != 1:
            issues.append(
                self._issue("just_one", path, f"exactly one of {', '.join(just_one)} is required")
            )

    def _report(
        self, event: JsonObject, class_name: str | None, issues: list[ValidationIssue]
    ) -> ValidationReport:
        return ValidationReport(
            valid=not any(issue.severity == "error" for issue in issues),
            schema_identity=self.identity,
            class_name=class_name,
            issues=tuple(issues),
            validated_event=event,
        )

    @staticmethod
    def _is_integer(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _join(parent: str, child: str) -> str:
        return child if not parent else f"{parent}.{child}"

    @staticmethod
    def _issue(code: str, path: str, message: str) -> ValidationIssue:
        return ValidationIssue(code=code, path=path or "$", message=message)


@lru_cache
def get_ocsf_catalog() -> OcsfCatalog:
    return OcsfCatalog.load_packaged()
