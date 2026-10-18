"""Read-only identities and references for static evidence, independent of claims.

An exported hash is provenance for an earlier observation, not a local ELF read.
Function names are display labels; paths, content identity and entries are keys.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


class EvidenceValidationError(ValueError):
    """Invalid static input or a reference that cannot be verified."""


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def rootfs_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or ":" in value or "\0" in value:
        raise EvidenceValidationError("rootfs_path: expected a nonempty rootfs path, not a host drive path")
    parts: list[str] = []
    for part in value.replace("\\", "/").split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise EvidenceValidationError("rootfs_path: path escapes rootfs")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise EvidenceValidationError("rootfs_path: binary path is empty")
    return "/".join(parts)


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def entry_key(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"(?:[A-Za-z_][\w.]*:)?(?:0x)?[0-9a-fA-F]+", value) is None:
        raise EvidenceValidationError("function_entry: expected an exported hexadecimal address")
    space, _, address = value.rpartition(":")
    return (space + ":" if space else "") + hex(int(address, 16))


@dataclass
class BinaryIdentity:
    rootfs_path: str
    export_task_id: str
    sha256: str | None = None
    sha256_origin: str | None = None
    architecture: str | None = None
    bitness: int | None = None
    endianness: str | None = None
    ghidra_project: str | None = None
    local_file_status: str = "unavailable"
    rootfs_path_origin: str | None = None
    limitations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.rootfs_path = rootfs_relative_path(self.rootfs_path)
        if not isinstance(self.export_task_id, str) or not self.export_task_id:
            raise EvidenceValidationError("export_task_id: an explicit task scope is required")
        if self.sha256 is not None and not _sha256(self.sha256):
            raise EvidenceValidationError("sha256: expected 64 lowercase hexadecimal characters")
        if self.sha256 is not None and (not isinstance(self.sha256_origin, str) or not self.sha256_origin):
            raise EvidenceValidationError("sha256_origin: exported hash needs provenance")
        if self.sha256 is None and self.sha256_origin is not None:
            raise EvidenceValidationError("sha256_origin: cannot describe a missing hash")
        for name in ("architecture", "ghidra_project", "rootfs_path_origin"):
            if getattr(self, name) is not None and (not isinstance(getattr(self, name), str) or not getattr(self, name)):
                raise EvidenceValidationError(f"{name}: expected a nonempty string or null")
        if self.bitness is not None and (type(self.bitness) is not int or self.bitness not in {16, 32, 64, 128}):
            raise EvidenceValidationError("bitness: invalid bit width")
        if self.endianness is not None and (not isinstance(self.endianness, str) or self.endianness not in {"little", "big"}):
            raise EvidenceValidationError("endianness: expected little, big or null")
        if self.local_file_status != "unavailable":
            raise EvidenceValidationError("local_file_status: this export-only reader does not attest local ELF bytes")
        if not isinstance(self.limitations, list) or not all(isinstance(item, str) for item in self.limitations):
            raise EvidenceValidationError("limitations: expected a string list")

    @property
    def identity_id(self) -> str:
        # A path without content identity is scoped to its explicit export task.
        return "BIN-" + _digest([self.rootfs_path, self.sha256, self.export_task_id if self.sha256 is None else None])

    def function_id(self, entry: str | None) -> str | None:
        return "FN-" + _digest([self.identity_id, entry_key(entry)]) if entry is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "identity_id": self.identity_id, "status": "partial",
                "field_status": {name: "observed" if getattr(self, name) is not None else "unavailable"
                                 for name in ("rootfs_path", "sha256", "architecture", "bitness", "endianness", "ghidra_project")}}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BinaryIdentity:
        if not isinstance(value, dict):
            raise EvidenceValidationError("binary_identity: expected an object")
        data = dict(value)
        declared = {key: data.pop(key) for key in ("identity_id", "status", "field_status") if key in data}
        try:
            identity = cls(**data)
        except TypeError as exc:
            raise EvidenceValidationError(f"binary_identity: {exc}") from exc
        if any(identity.to_dict()[key] != val for key, val in declared.items()):
            raise EvidenceValidationError("binary_identity: inconsistent derived identity/status")
        return identity

    @classmethod
    def from_export(cls, rootfs_path: str, summary: dict[str, Any], *, task_id: str, hash_origin: str,
                    path_origin: str | None = None) -> BinaryIdentity:
        if not isinstance(summary, dict):
            raise EvidenceValidationError("summary: expected an object")
        digest = summary.get("sha256")
        limitations = ["Local ELF not read by this export-only reader; exported SHA-256 has not been rehashed locally",
                       "Ghidra project identity unavailable"]
        if digest is not None and not _sha256(digest):
            raise EvidenceValidationError("summary.sha256: invalid exported hash")
        if digest is None:
            limitations.append("ELF SHA-256 unavailable; identity is scoped to path and export task")
        architecture = bitness = endianness = None
        language = summary.get("language")
        if language is not None:
            if not isinstance(language, str):
                raise EvidenceValidationError("summary.language: expected a string")
            match = re.fullmatch(r"([^:]+):(LE|BE):(16|32|64|128):.+", language)
            if match:
                architecture, order, bits = match.groups()
                bitness, endianness = int(bits), {"LE": "little", "BE": "big"}[order]
            else:
                limitations.append("Architecture, bitness and endianness unavailable from language ID")
        return cls(rootfs_path, task_id, digest, hash_origin if digest is not None else None,
                   architecture, bitness, endianness, rootfs_path_origin=path_origin, limitations=limitations)


def json_pointer(value: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise EvidenceValidationError("source_json_pointer: expected an RFC 6901 JSON pointer")
    if not pointer:
        return value
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise EvidenceValidationError("source_json_pointer: invalid escape")
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token) and int(token) < len(value):
            value = value[int(token)]
        else:
            raise EvidenceValidationError(f"source_json_pointer: {pointer!r} does not resolve")
    return value


class JsonEvidenceStore:
    """Read existing JSON only; never construct a workspace or run a generator."""

    def __init__(self, task_dir: str | Path, *, task_id: str | None = None):
        self.task_dir = Path(task_dir).resolve()
        self.task_id = task_id or self.task_dir.name

    def read(self, relative: str) -> tuple[Any, str]:
        if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
            raise EvidenceValidationError("source_artifact: expected a task-relative POSIX path")
        path = self.task_dir / relative
        if path.is_absolute() and (relative.startswith("/") or ".." in relative.split("/")):
            raise EvidenceValidationError("source_artifact: path must remain inside the task")
        if not path.resolve().is_relative_to(self.task_dir):
            raise EvidenceValidationError("source_artifact: path escapes the task")
        try:
            from fwagent.tools.bounded_io import read_beneath
            raw = read_beneath(self.task_dir, relative, limit=32*1024*1024)
            return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError, RuntimeError) as exc:
            raise EvidenceValidationError(f"source_artifact {relative}: {type(exc).__name__}: {exc}") from exc

    def reference(self, relative: str, pointer: str) -> tuple[dict[str, str], Any]:
        document, digest = self.read(relative)
        return {"source_artifact": relative, "source_artifact_sha256": digest,
                "source_json_pointer": pointer}, json_pointer(document, pointer)

    def resolve(self, reference: dict[str, Any]) -> Any:
        document, digest = self.read(reference.get("source_artifact"))
        if digest != reference.get("source_artifact_sha256"):
            raise EvidenceValidationError("source_artifact_sha256: content does not match the reference")
        return json_pointer(document, reference.get("source_json_pointer"))

    def bind_identity(self, reference: dict[str, Any], identity: BinaryIdentity, raw: Any) -> None:
        """A valid record hash alone cannot bind it to a different binary."""
        if identity.export_task_id != self.task_id:
            raise EvidenceValidationError('binary_identity: export task scope mismatch')
        origin = identity.sha256_origin or ''
        artifact, separator, pointer = origin.partition('#')
        suffix='/result/summary/sha256'
        if not separator or not pointer.endswith(suffix):
            raise EvidenceValidationError('binary_identity: record lacks a bound export envelope')
        prefix=pointer[:-len(suffix)]
        if identity.rootfs_path_origin != artifact+'#'+prefix+'/target/path':
            raise EvidenceValidationError('binary_identity: path and hash must share an export envelope')
        document,digest=self.read(artifact)
        if json_pointer(document,pointer) != identity.sha256 or rootfs_relative_path(json_pointer(document,prefix+'/target/path')) != identity.rootfs_path:
            raise EvidenceValidationError('binary_identity: export envelope mismatch')
        if isinstance(document,dict) and document.get('task_id',self.task_id) != self.task_id:
            raise EvidenceValidationError('binary_identity: declared export task mismatch')
        source=reference['source_artifact'];record_pointer=reference['source_json_pointer']
        if source == artifact:
            if digest != reference['source_artifact_sha256'] or not record_pointer.startswith(prefix+'/result/'):
                raise EvidenceValidationError('binary_identity: record belongs to another export envelope')
            return
        # Legacy separate arrays are usable only when the same envelope names
        # their directory AND its embedded collection exactly equals that file.
        envelope=json_pointer(document,prefix)
        metadata=envelope['result'].get('metadata',{})
        output=metadata.get('output_dir') if isinstance(metadata,dict) else None
        normalized=output.replace('\\','/') if isinstance(output,str) else ''
        if '/ghidra/outputs/' not in normalized:
            raise EvidenceValidationError('binary_identity: standalone record has no export provenance')
        directory='ghidra/outputs/'+normalized.split('/ghidra/outputs/',1)[1].rstrip('/')
        kind=Path(source).stem
        if kind not in {'functions','imports','exports','strings','callgraph'} or source != directory+'/'+kind+'.json':
            raise EvidenceValidationError('binary_identity: standalone artifact directory mismatch')
        standalone,standalone_digest=self.read(source)
        if standalone_digest != reference['source_artifact_sha256'] or standalone != envelope['result'].get(kind) or json_pointer(standalone,record_pointer) != raw:
            raise EvidenceValidationError('binary_identity: standalone artifact differs from bound export')


EVIDENCE_TYPES = {"source", "sink", "callsite", "parameter", "dataflow_edge"}
OBSERVATION_STATES = {"observed", "partial", "unavailable"}
FLOW_EDGE_KINDS = {"callgraph_edge", "argument_mapping", "intra_procedural_flow", "inter_procedural_flow"}


@dataclass
class StaticEvidence:
    """One serializable contract for the five static observation kinds.

    observed attests the stated observation only, never a vulnerability or an
    attacker-controlled input. None stays unavailable, including argument index.
    """
    evidence_type: str
    binary_identity: BinaryIdentity
    source_artifact: str | None = None
    source_artifact_sha256: str | None = None
    source_json_pointer: str | None = None
    function_entry: str | None = None
    function_name: str | None = None
    target_function_entry: str | None = None
    callsite_address: str | None = None
    parameter_index: int | None = None
    parameter_role: str | None = None
    input_value: str | None = None
    output_value: str | None = None
    edge_kind: str | None = None
    related_evidence_ids: list[str] = field(default_factory=list)
    observation: dict[str, Any] = field(default_factory=dict)
    status: str = "partial"
    limitations: list[str] = field(default_factory=list)
    evidence_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_type, str) or self.evidence_type not in EVIDENCE_TYPES:
            raise EvidenceValidationError("evidence_type: unknown static evidence kind")
        if not isinstance(self.binary_identity, BinaryIdentity):
            raise EvidenceValidationError("binary_identity: expected a BinaryIdentity")
        if not isinstance(self.status, str) or self.status not in OBSERVATION_STATES:
            raise EvidenceValidationError("status: expected observed, partial or unavailable")
        for key in ("source_artifact", "source_json_pointer", "function_entry", "function_name", "target_function_entry",
                    "callsite_address", "parameter_role", "input_value", "output_value"):
            value = getattr(self, key)
            if value is not None and (not isinstance(value, str) or (not value and key != "source_json_pointer")):
                raise EvidenceValidationError(f"{key}: expected a nonempty string or null")
        for key in ("function_entry", "target_function_entry", "callsite_address"):
            if getattr(self, key) is not None:
                entry_key(getattr(self, key))
        if self.source_artifact_sha256 is not None and not _sha256(self.source_artifact_sha256):
            raise EvidenceValidationError("source_artifact_sha256: invalid file hash")
        if self.parameter_index is not None and (type(self.parameter_index) is not int or self.parameter_index < 0):
            raise EvidenceValidationError("parameter_index: expected a nonnegative integer or null")
        if self.edge_kind is not None and (not isinstance(self.edge_kind, str) or self.edge_kind not in FLOW_EDGE_KINDS):
            raise EvidenceValidationError("edge_kind: invalid edge kind")
        if (self.evidence_type == "dataflow_edge") != (self.edge_kind is not None):
            raise EvidenceValidationError("edge_kind: required only for dataflow_edge")
        for key in ("related_evidence_ids", "limitations"):
            values = getattr(self, key)
            if not isinstance(values, list) or not all(isinstance(item, str) and item for item in values):
                raise EvidenceValidationError(f"{key}: expected a nonempty-string list")
        if not isinstance(self.observation, dict):
            raise EvidenceValidationError("observation: expected an object")
        try:
            json.dumps(self.observation, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise EvidenceValidationError(f"observation: not serializable: {exc}") from exc
        reference = (self.source_artifact, self.source_artifact_sha256, self.source_json_pointer)
        if any(value is not None for value in reference) and any(value is None for value in reference):
            raise EvidenceValidationError("source reference: artifact, SHA-256 and pointer must be supplied together")
        if self.status == "observed":
            required = [self.binary_identity.sha256, self.function_entry, self.source_artifact]
            if self.evidence_type in {"callsite", "parameter"} or self.edge_kind in {"argument_mapping", "inter_procedural_flow"}:
                required.append(self.callsite_address)
            if self.evidence_type == "parameter" or self.edge_kind == "argument_mapping":
                required += [self.parameter_index, self.parameter_role]
            if self.evidence_type == "dataflow_edge":
                required.append(self.target_function_entry)
                if self.edge_kind != "callgraph_edge":
                    required += [self.input_value, self.output_value]
            if any(value is None for value in required):
                raise EvidenceValidationError("observed: required identity, reference, callsite or parameter evidence missing")
        if self.status != "observed" and not self.limitations:
            raise EvidenceValidationError("limitations: partial/unavailable evidence needs an explicit reason")
        expected = "STE-" + _digest([self.evidence_type, self.binary_identity.identity_id, self.function_entry,
            self.target_function_entry, self.source_artifact_sha256, self.source_artifact, self.source_json_pointer,
            self.edge_kind, self.callsite_address, self.parameter_index, self.input_value, self.output_value])
        if self.evidence_id and self.evidence_id != expected:
            raise EvidenceValidationError("evidence_id: inconsistent with evidence identity")
        self.evidence_id = expected

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["schema_version"] = "firmxplore.static_evidence.v1"
        result["binary_identity"] = self.binary_identity.to_dict()
        result["field_status"] = {name: "observed" if getattr(self, name) is not None else "unavailable"
                                  for name in ("function_entry", "callsite_address", "source_artifact",
                                               "parameter_index", "parameter_role", "input_value", "output_value")}
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StaticEvidence:
        if not isinstance(value, dict):
            raise EvidenceValidationError("static_evidence: expected an object")
        data = dict(value)
        if data.pop("schema_version", "firmxplore.static_evidence.v1") != "firmxplore.static_evidence.v1":
            raise EvidenceValidationError("schema_version: unsupported static evidence contract")
        states = data.pop("field_status", None)
        data["binary_identity"] = BinaryIdentity.from_dict(data.get("binary_identity"))
        try:
            record = cls(**data)
        except TypeError as exc:
            raise EvidenceValidationError(f"static_evidence: {exc}") from exc
        if states is not None and states != record.to_dict()["field_status"]:
            raise EvidenceValidationError("field_status: inconsistent with the supplied fields")
        return record

    def validate_reference(self, store: JsonEvidenceStore, *, bind_identity: bool = True) -> None:
        if self.source_artifact is None:
            if self.status == "observed":
                raise EvidenceValidationError("source_artifact: observed evidence requires a reference")
            return
        raw = store.resolve(self.to_dict())
        if not isinstance(raw, dict):
            raise EvidenceValidationError("source_json_pointer: expected a record object")
        if self.function_entry is not None:
            entries = [raw.get(key) for key in ("address", "caller_address", "function_entry")]
            if self.function_entry not in entries:
                raise EvidenceValidationError("function_entry: not supported by the referenced record")
        if self.target_function_entry is not None and self.target_function_entry not in (raw.get("callee_address"), raw.get("target_function_entry")):
            raise EvidenceValidationError("target_function_entry: not supported by the referenced record")
        for key in ("callsite_address", "parameter_index", "parameter_role", "input_value", "output_value"):
            if getattr(self, key) is not None and (key not in raw or raw[key] != getattr(self, key)):
                raise EvidenceValidationError(f"{key}: not supported by the referenced record")
        if self.edge_kind == "callgraph_edge":
            if not all(isinstance(raw.get(key), str) and raw[key] for key in ("caller", "callee", "caller_address", "callee_address")):
                raise EvidenceValidationError("callgraph_edge: caller/callee identities missing")
        elif self.edge_kind is not None and raw.get("edge_kind") != self.edge_kind:
            raise EvidenceValidationError("edge_kind: call graph cannot be relabeled as parameter propagation")
        if bind_identity:
            store.bind_identity(self.to_dict(), self.binary_identity, raw)


def validate_evidence_bundle(records: list[StaticEvidence], store: JsonEvidenceStore) -> list[str]:
    """Resolve references and reject unsupported or dangling parameter-flow edges."""
    diagnostics: list[str] = []
    by_id = {item.evidence_id: item for item in records}
    if len(by_id) != len(records):
        diagnostics.append("evidence_id: duplicate evidence IDs")
    checked_identities = set()
    for item in records:
        try:
            # Revalidate serialized structure too, including any mutated fields.
            StaticEvidence.from_dict(item.to_dict())
            identity = item.binary_identity
            if identity.identity_id not in checked_identities:
                checked_identities.add(identity.identity_id)
                for origin, expected, normalizer in (
                    (identity.sha256_origin, identity.sha256, lambda value: value),
                    (identity.rootfs_path_origin, identity.rootfs_path, rootfs_relative_path),
                ):
                    if origin is not None:
                        artifact, separator, pointer = origin.partition("#")
                        if not separator:
                            raise EvidenceValidationError("binary_identity: origin needs an artifact and JSON pointer")
                        _, observed = store.reference(artifact, pointer)
                        if normalizer(observed) != expected:
                            raise EvidenceValidationError("binary_identity: identity does not match its export reference")
            item.validate_reference(store, bind_identity=False)
            related = []
            for key in item.related_evidence_ids:
                if key not in by_id:
                    raise EvidenceValidationError(f"related_evidence_ids: missing evidence {key}")
                related.append(by_id[key])
            if item.edge_kind == "inter_procedural_flow":
                mappings = [edge for edge in related if edge.edge_kind == "argument_mapping" and edge.status == "observed"
                            and edge.binary_identity.identity_id == item.binary_identity.identity_id
                            and edge.function_entry == item.function_entry and edge.target_function_entry == item.target_function_entry
                            and edge.callsite_address == item.callsite_address
                            and edge.input_value == item.input_value and edge.output_value == item.output_value]
                if not mappings:
                    raise EvidenceValidationError("inter_procedural_flow: matching observed argument_mapping required")
            if item.source_artifact is not None:
                raw = store.resolve(item.to_dict())
                store.bind_identity(item.to_dict(), identity, raw)
        except EvidenceValidationError as exc:
            diagnostics.append(f"{item.evidence_id}: {exc}")
    return diagnostics
