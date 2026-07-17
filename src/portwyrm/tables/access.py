"""Access firewall control lists and identity membership."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
from copy import deepcopy
from enum import StrEnum
from typing import Any, Self

import bcrypt
from tigrbl import hook_ctx, op_ctx, schema_ctx
from tigrbl.types import (
    BaseModel,
    Boolean,
    CheckConstraint,
    Field,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from portwyrm.errors import DomainValidationError
from portwyrm.kernel_support import ConfigDict, delete, model_validator, select

from .base import READ_ONLY_PROFILE, ManagedPortwyrmTable, PortwyrmTable, acol
from .compat import extension_metadata, extensions, iso

_ACCESS_KNOWN = {
    "id",
    "name",
    "satisfy_any",
    "pass_auth",
    "items",
    "credentials",
    "clients",
    "identity_ids",
    "owner_user_id",
    "created_on",
    "modified_on",
    "created_at",
    "updated_at",
}


class AccessDirective(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AccessListStore(ManagedPortwyrmTable):
    __tablename__ = "access_lists"
    name = acol(String(255), nullable=False, index=True)
    satisfy_any = acol(Boolean, nullable=False, default=False)
    pass_auth = acol(Boolean, nullable=False, default=False)

    class RuntimeCredential(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid")

        username: str
        password_hash: str

        @model_validator(mode="after")
        def validate_credential(self) -> Self:
            if not self.username or ":" in self.username or "\n" in self.username:
                raise DomainValidationError("invalid basic-auth username")
            if not self.password_hash or "\n" in self.password_hash:
                raise DomainValidationError("invalid basic-auth password/hash")
            return self

    class RuntimeRule(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid", use_enum_values=True)

        address: str
        directive: AccessDirective

        @model_validator(mode="after")
        def validate_rule(self) -> Self:
            address = self.address.strip()
            if address != "all":
                try:
                    address = str(ipaddress.ip_network(address, strict=False))
                except ValueError as exc:
                    raise DomainValidationError(f"invalid access-list address: {address}") from exc
            object.__setattr__(self, "address", address)
            return self

    class RuntimeAccessList(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid")

        id: int
        name: str
        credentials: tuple[AccessListStore.RuntimeCredential, ...] = ()
        clients: tuple[AccessListStore.RuntimeRule, ...] = ()
        satisfy_any: bool = False
        pass_auth: bool = False
        meta: dict[str, Any] = Field(default_factory=dict)

        @model_validator(mode="after")
        def validate_access_list(self) -> Self:
            if self.id <= 0:
                raise DomainValidationError("access-list id must be positive")
            if not self.name.strip():
                raise DomainValidationError("access-list name is required")
            return self

    @schema_ctx(alias="runtime_list", kind="out")
    class RuntimeAccessListList(BaseModel):
        items: list[AccessListStore.RuntimeAccessList] = Field(default_factory=list)

    @hook_ctx(ops=("create", "update", "replace"), phase="PRE_HANDLER")
    async def prepare_aggregate(cls, ctx: dict[str, Any]) -> None:
        payload = dict(ctx.get("payload") or {})
        op = ctx.get("op") or ctx.get("alias") or ""
        alias = str(getattr(op, "alias", op)).casefold()
        if alias == "update":
            row = await _await(ctx["db"].get(cls, int(payload["id"])))
            if row is not None:
                payload = {
                    **(await cls._project(ctx["db"], row, include_hashes=True)),
                    **payload,
                }
        ctx.setdefault("temp", {})["access_aggregate"] = payload
        root = cls._values(payload)
        if payload.get("id") is not None:
            root["id"] = int(payload["id"])
        ctx["payload"] = root

    @hook_ctx(ops=("create", "update", "replace"), phase="POST_HANDLER")
    async def persist_aggregate(cls, ctx: dict[str, Any]) -> None:
        row = ctx["result"]
        payload = ctx.get("temp", {}).get("access_aggregate", {})
        await cls._replace_children(ctx["db"], row.id, payload)
        ctx["result"] = await cls._project(ctx["db"], row, include_hashes=False)

    @hook_ctx(ops=("read", "list"), phase="POST_HANDLER")
    async def project_aggregate(cls, ctx: dict[str, Any]) -> None:
        result = ctx["result"]
        if isinstance(result, list):
            ctx["result"] = [
                await cls._project(ctx["db"], row, include_hashes=False) for row in result
            ]
        else:
            ctx["result"] = await cls._project(ctx["db"], result, include_hashes=False)

    @hook_ctx(ops="delete", phase="PRE_HANDLER")
    async def delete_aggregate_children(cls, ctx: dict[str, Any]) -> None:
        await cls._replace_children(ctx["db"], int(ctx["payload"]["id"]), {})

    HOOKS = (prepare_aggregate, persist_aggregate, project_aggregate, delete_aggregate_children)

    @op_ctx(alias="runtime_list", target="custom", arity="collection")
    async def runtime_list(cls, ctx: Any) -> dict[str, Any]:
        """Return the private render projection; never mount this operation publicly."""

        lists = list((await _await(ctx["db"].execute(select(cls).order_by(cls.id)))).scalars())
        return {
            "items": [
                cls._runtime_projection(
                    row, await cls._project(ctx["db"], row, include_hashes=True)
                ).model_dump(mode="json")
                for row in lists
            ]
        }

    @staticmethod
    def _values(payload: dict[str, Any]) -> dict[str, Any]:
        compat = deepcopy(payload)
        credential_key = "items" if "items" in compat else "credentials"
        if credential_key in compat:
            compat[credential_key] = [
                {"username": str(item.get("username") or "")} for item in compat[credential_key]
            ]
        return {
            "name": str(payload.get("name") or ""),
            "satisfy_any": bool(payload.get("satisfy_any")),
            "pass_auth": bool(payload.get("pass_auth")),
            "metadata_json": extension_metadata(compat, _ACCESS_KNOWN),
        }

    @classmethod
    async def _project(cls, db: Any, access_list: Any, *, include_hashes: bool) -> dict[str, Any]:
        rules = list(
            (
                await _await(
                    db.execute(
                        select(AccessRuleStore)
                        .where(AccessRuleStore.access_list_id == access_list.id)
                        .order_by(AccessRuleStore.position)
                    )
                )
            ).scalars()
        )
        credentials = list(
            (
                await _await(
                    db.execute(
                        select(AccessCredentialStore)
                        .where(AccessCredentialStore.access_list_id == access_list.id)
                        .order_by(AccessCredentialStore.id)
                    )
                )
            ).scalars()
        )
        principals = list(
            (
                await _await(
                    db.execute(
                        select(AccessPrincipalStore.principal_id)
                        .where(AccessPrincipalStore.access_list_id == access_list.id)
                        .order_by(AccessPrincipalStore.id)
                    )
                )
            ).scalars()
        )
        result = extensions(access_list)
        result.update(
            {
                "id": access_list.id,
                "name": access_list.name,
                "satisfy_any": bool(access_list.satisfy_any),
                "pass_auth": bool(access_list.pass_auth),
                "items": [
                    {
                        "username": item.username,
                        **({"password": item.password_hash} if include_hashes else {}),
                    }
                    for item in credentials
                ],
                "clients": [
                    {"address": item.address, "directive": item.directive} for item in rules
                ],
                "identity_ids": principals,
                "created_on": iso(access_list.created_at),
                "modified_on": iso(access_list.updated_at),
            }
        )
        return result

    @staticmethod
    async def _replace_children(db: Any, access_list_id: int, payload: dict[str, Any]) -> None:
        existing_result = await _await(
            db.execute(
                select(AccessCredentialStore).where(
                    AccessCredentialStore.access_list_id == access_list_id
                )
            )
        )
        existing_credentials = {
            row.username: row.password_hash for row in existing_result.scalars().all()
        }
        for table in (AccessRuleStore, AccessCredentialStore, AccessPrincipalStore):
            await _await(db.execute(delete(table).where(table.access_list_id == access_list_id)))
        for position, rule in enumerate(payload.get("clients") or []):
            runtime_rule = AccessListStore.RuntimeRule.model_validate(rule)
            db.add(
                AccessRuleStore(
                    access_list_id=access_list_id,
                    position=position,
                    directive=str(runtime_rule.directive),
                    address=runtime_rule.address,
                )
            )
        for credential in payload.get("items", payload.get("credentials", [])) or []:
            username = str(credential.get("username") or "")
            supplied = str(credential.get("password_hash", credential.get("password", "")))
            if supplied and not supplied.startswith(("$2a$", "$2b$", "$2y$")):
                supplied = await asyncio.to_thread(_bcrypt_hash, supplied)
            password_hash = supplied or existing_credentials.get(username, "")
            if not username or not password_hash:
                raise ValueError("access credentials require a username and password")
            AccessListStore.RuntimeCredential(
                username=username,
                password_hash=password_hash,
            )
            db.add(
                AccessCredentialStore(
                    access_list_id=access_list_id,
                    username=username,
                    password_hash=password_hash,
                )
            )
        for principal_id in payload.get("identity_ids") or []:
            db.add(
                AccessPrincipalStore(
                    access_list_id=access_list_id,
                    principal_id=int(principal_id),
                )
            )

    @classmethod
    def _runtime_projection(cls, row: Any, projected: dict[str, Any]) -> RuntimeAccessList:
        return cls.RuntimeAccessList(
            id=row.id,
            name=row.name,
            credentials=[
                cls.RuntimeCredential(
                    username=str(item["username"]),
                    password_hash=str(item["password"]),
                )
                for item in projected.get("items") or []
            ],
            clients=[
                cls.RuntimeRule.model_validate(item) for item in projected.get("clients") or []
            ],
            satisfy_any=bool(row.satisfy_any),
            pass_auth=bool(row.pass_auth),
            meta=dict(row.metadata_json or {}),
        )


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _bcrypt_hash(value: str) -> str:
    return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()


class AccessRuleStore(PortwyrmTable):
    __tablename__ = "access_list_rules"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        CheckConstraint("directive IN ('allow','deny')", name="ck_access_rule_directive"),
        CheckConstraint("length(address) > 0", name="ck_access_rule_address"),
    )
    access_list_id = acol(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    position = acol(Integer, nullable=False, default=0)
    directive = acol(String(16), nullable=False)
    address = acol(String(255), nullable=False)


class AccessCredentialStore(PortwyrmTable):
    __tablename__ = "access_list_credentials"
    TABLE_PROFILE = READ_ONLY_PROFILE
    access_list_id = acol(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    username = acol(String(255), nullable=False)
    password_hash = acol(Text, nullable=False)


class AccessPrincipalStore(PortwyrmTable):
    __tablename__ = "access_list_principals"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        UniqueConstraint("access_list_id", "principal_id", name="uq_access_list_principal_edge"),
    )
    access_list_id = acol(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    principal_id = acol(Integer, ForeignKey("principals.id"), nullable=False, index=True)


AccessList = AccessListStore
AccessListRule = AccessRuleStore
AccessListCredential = AccessCredentialStore
AccessListPrincipal = AccessPrincipalStore
AccessListStore.RuntimeAccessList.model_rebuild(
    _types_namespace={"AccessListStore": AccessListStore}
)
AccessListStore.RuntimeAccessListList.model_rebuild(
    _types_namespace={"AccessListStore": AccessListStore}
)
RuntimeAccessList = AccessListStore.RuntimeAccessList
AccessClient = AccessListStore.RuntimeRule
RuntimeAccessCredential = AccessListStore.RuntimeCredential

__all__ = [
    "AccessClient",
    "AccessCredentialStore",
    "AccessDirective",
    "AccessList",
    "AccessListCredential",
    "AccessListPrincipal",
    "AccessListRule",
    "AccessListStore",
    "AccessPrincipalStore",
    "AccessRuleStore",
    "RuntimeAccessCredential",
    "RuntimeAccessList",
]
