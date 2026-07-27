"""Strict, signed build-plane playbooks composed from fixed contracts.

Playbooks are compiled workflow DAGs, never tenant-authored macros. Runtime
cannot add nodes, resolve arbitrary tools, or substitute a Graph operation.
"""

from __future__ import annotations

import base64
import json
from importlib.resources import files
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_manifest import (
    AuthorizationMode,
    CompensationClass,
    ContractManifest,
    RiskTier,
    canonical_json,
    sha256_digest,
)
from .contract_trust import (
    PLAYBOOK_SIGNING_KEY_ID,
    PLAYBOOK_SIGNING_PUBLIC_KEY_B64,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PlaybookNode(StrictModel):
    """One fixed contract invocation in a build-time workflow DAG."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    depends_on: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("depends_on")
    @classmethod
    def dependencies_are_unique_and_sorted(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("playbook node dependencies must be unique and sorted")
        return value


class PlaybookSpec(StrictModel):
    """Tenant-neutral workflow contract compiled and signed at build time."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    tool_name: str = Field(pattern=r"^m365_[a-z0-9_]{3,96}$")
    description: str = Field(min_length=20, max_length=500)
    module: Literal["assurance"]
    nodes: list[PlaybookNode] = Field(min_length=2, max_length=20)
    output_fields: list[str] = Field(min_length=1, max_length=50)
    risk_tier: RiskTier
    authorization_mode: AuthorizationMode
    failure_mode: Literal["halt_not_evaluated"]
    writes_permitted: Literal[False]
    compensation: CompensationClass

    @field_validator("output_fields")
    @classmethod
    def output_fields_are_unique(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("playbook output fields must be unique and sorted")
        return value

    @model_validator(mode="after")
    def validate_dag(self) -> PlaybookSpec:
        if self.risk_tier is not RiskTier.T0:
            raise ValueError("initial playbooks must be read-only T0")
        if self.authorization_mode is not AuthorizationMode.AUTOMATIC_READ:
            raise ValueError("read-only T0 playbooks must use automatic_read")
        if self.compensation is not CompensationClass.NOT_APPLICABLE:
            raise ValueError("read-only playbooks cannot define compensation")
        node_ids = [node.id for node in self.nodes]
        contract_ids = [node.contract_id for node in self.nodes]
        if node_ids != sorted(set(node_ids)):
            raise ValueError("playbook node IDs must be unique and sorted")
        if len(contract_ids) != len(set(contract_ids)):
            raise ValueError("a contract may appear only once in a playbook")
        known = set(node_ids)
        for node in self.nodes:
            if node.id in node.depends_on:
                raise ValueError("playbook node cannot depend on itself")
            if set(node.depends_on) - known:
                raise ValueError("playbook dependency references an unknown node")

        visiting: set[str] = set()
        visited: set[str] = set()
        dependencies = {node.id: set(node.depends_on) for node in self.nodes}

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ValueError("playbook graph must be acyclic")
            if node_id in visited:
                return
            visiting.add(node_id)
            for dependency in dependencies[node_id]:
                visit(dependency)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in node_ids:
            visit(node_id)
        return self

    def ordered_nodes(self) -> list[PlaybookNode]:
        """Return a deterministic topological order without runtime discovery."""

        remaining = {node.id: node for node in self.nodes}
        completed: set[str] = set()
        ordered: list[PlaybookNode] = []
        while remaining:
            ready = sorted(
                (
                    node
                    for node in remaining.values()
                    if set(node.depends_on).issubset(completed)
                ),
                key=lambda node: node.id,
            )
            if not ready:
                raise RuntimeError("verified playbook unexpectedly contains a cycle")
            for node in ready:
                ordered.append(node)
                completed.add(node.id)
                del remaining[node.id]
        return ordered

    def validate_contracts(self, manifest: ContractManifest) -> None:
        """Prove every node is an exact compiled read-only contract."""

        for node in self.nodes:
            try:
                contract = manifest.contract(node.contract_id)
            except KeyError as exc:
                raise ValueError(
                    "playbook references an unknown compiled contract"
                ) from exc
            if (
                contract.graph.method != "GET"
                or contract.risk_tier is not RiskTier.T0
                or contract.authorization_mode is not AuthorizationMode.AUTOMATIC_READ
            ):
                raise ValueError(
                    "playbook nodes must reference automatic read-only T0 contracts"
                )

    def delegated_scope_closure(self, manifest: ContractManifest) -> list[str]:
        self.validate_contracts(manifest)
        return sorted(
            {
                scope
                for node in self.nodes
                for scope in manifest.contract(
                    node.contract_id
                ).permissions.delegated_scopes
            }
        )

    def operator_role_closure(self, manifest: ContractManifest) -> list[str]:
        self.validate_contracts(manifest)
        return sorted(
            {
                role
                for node in self.nodes
                for role in manifest.contract(
                    node.contract_id
                ).permissions.operator_roles
            }
        )


class PlaybookManifest(StrictModel):
    schema_version: Literal["1.0"]
    product: Literal["m365-secure-mcp"]
    playbooks: list[PlaybookSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_playbooks(self) -> PlaybookManifest:
        ids = [playbook.id for playbook in self.playbooks]
        tools = [playbook.tool_name for playbook in self.playbooks]
        if ids != sorted(set(ids)):
            raise ValueError("playbook IDs must be unique and sorted")
        if len(tools) != len(set(tools)):
            raise ValueError("playbook tool names must be unique")
        return self

    def playbook(self, playbook_id: str) -> PlaybookSpec:
        for playbook in self.playbooks:
            if playbook.id == playbook_id:
                return playbook
        raise KeyError(f"unknown compiled playbook: {playbook_id}")

    def validate_contracts(self, manifest: ContractManifest) -> None:
        for playbook in self.playbooks:
            playbook.validate_contracts(manifest)


class PlaybookManifestSignature(StrictModel):
    schema_version: Literal["1.0"]
    algorithm: Literal["ed25519"]
    key_id: str = Field(min_length=3, max_length=100)
    playbook_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(min_length=80, max_length=128)


def _data_bytes(name: str) -> bytes:
    return files("m365_secure_mcp.contract_data").joinpath(name).read_bytes()


def load_global_playbook_manifest(
    contract_manifest: ContractManifest,
) -> PlaybookManifest:
    """Load the package-pinned playbook manifest and fail closed on drift."""

    try:
        raw_manifest = json.loads(_data_bytes("global-playbooks.json"))
        raw_signature = json.loads(_data_bytes("global-playbooks.sig.json"))
        manifest = PlaybookManifest.model_validate(raw_manifest)
        signature = PlaybookManifestSignature.model_validate(raw_signature)
        public_key = base64.b64decode(
            PLAYBOOK_SIGNING_PUBLIC_KEY_B64,
            validate=True,
        )
        signature_bytes = base64.b64decode(signature.signature, validate=True)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("global playbook manifest is malformed") from exc

    digest = sha256_digest(manifest)
    if signature.key_id != PLAYBOOK_SIGNING_KEY_ID:
        raise RuntimeError("global playbook manifest signer is not trusted")
    if signature.playbook_manifest_digest != digest:
        raise RuntimeError("global playbook manifest digest mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes,
            canonical_json(manifest),
        )
    except (ValueError, InvalidSignature) as exc:
        raise RuntimeError("global playbook manifest signature is invalid") from exc
    try:
        manifest.validate_contracts(contract_manifest)
    except ValueError as exc:
        raise RuntimeError("global playbook contract closure is invalid") from exc
    return manifest
