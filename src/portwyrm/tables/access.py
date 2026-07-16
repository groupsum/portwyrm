"""Access firewall control lists and identity membership."""

from __future__ import annotations

import asyncio
import inspect
from copy import deepcopy
from typing import Any

import bcrypt
from sqlalchemy import delete, select
from tigrbl import op_ctx
from tigrbl.types import Boolean, Column, ForeignKey, Integer, String, Text, UniqueConstraint

from .base import ManagedPortwyrmTable, PortwyrmTable
from .compat import add_audit, extension_metadata, extensions, iso

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


class AccessListStore(ManagedPortwyrmTable):
    __tablename__ = "access_lists"
    name = Column(String(255), nullable=False, index=True)
    satisfy_any = Column(Boolean, nullable=False, default=False)
    pass_auth = Column(Boolean, nullable=False, default=False)

    @op_ctx(alias="create_compat", target="custom", arity="collection")
    async def create_compat(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        row = cls(**cls._values(payload))
        ctx["db"].add(row)
        await _await(ctx["db"].flush())
        await cls._replace_children(ctx["db"], row.id, payload)
        result = await cls._project(ctx["db"], row, include_hashes=False)
        await add_audit(
            ctx["db"],
            action="created",
            object_type="access_lists",
            object_id=row.id,
            details=result,
        )
        return result

    @op_ctx(alias="update_compat", target="custom", arity="collection")
    async def update_compat(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        access_list_id = int(payload.pop("id"))
        result = await _await(ctx["db"].execute(select(cls).where(cls.id == access_list_id)))
        row = result.scalar_one_or_none()
        if row is None:
            raise ValueError("access list not found")
        for key, value in cls._values(payload).items():
            setattr(row, key, value)
        await cls._replace_children(ctx["db"], row.id, payload)
        result = await cls._project(ctx["db"], row, include_hashes=False)
        await add_audit(
            ctx["db"],
            action="updated",
            object_type="access_lists",
            object_id=row.id,
            details=result,
        )
        return result

    @op_ctx(alias="delete_compat", target="custom", arity="collection")
    async def delete_compat(cls, ctx: Any) -> dict[str, Any]:
        access_list_id = int((ctx.get("payload") or {})["id"])
        await cls._replace_children(ctx["db"], access_list_id, {})
        result = await _await(ctx["db"].execute(delete(cls).where(cls.id == access_list_id)))
        if result.rowcount:
            await add_audit(
                ctx["db"], action="deleted", object_type="access_lists", object_id=access_list_id
            )
        return {"deleted": bool(result.rowcount), "id": access_list_id}

    @op_ctx(alias="compat_list", target="custom", arity="collection")
    async def compat_list(cls, ctx: Any) -> list[dict[str, Any]]:
        rows = list((await _await(ctx["db"].execute(select(cls).order_by(cls.id)))).scalars())
        return [await cls._project(ctx["db"], row, include_hashes=False) for row in rows]

    @op_ctx(alias="compat_read", target="custom", arity="collection")
    async def compat_read(cls, ctx: Any) -> dict[str, Any]:
        row = (
            await _await(
                ctx["db"].execute(
                    select(cls).where(cls.id == int((ctx.get("payload") or {})["id"]))
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise ValueError("access list not found")
        return await cls._project(ctx["db"], row, include_hashes=False)

    @op_ctx(alias="runtime_list", target="custom", arity="collection")
    async def runtime_list(cls, ctx: Any) -> list[dict[str, Any]]:
        """Return the private render projection; never mount this operation publicly."""

        lists = list((await _await(ctx["db"].execute(select(cls).order_by(cls.id)))).scalars())
        return [await cls._project(ctx["db"], row, include_hashes=True) for row in lists]

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
            db.add(
                AccessRuleStore(
                    access_list_id=access_list_id,
                    position=position,
                    directive=str(rule.get("directive") or "allow"),
                    address=str(rule.get("address") or ""),
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


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _bcrypt_hash(value: str) -> str:
    return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()


class AccessRuleStore(ManagedPortwyrmTable):
    __tablename__ = "access_list_rules"
    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    position = Column(Integer, nullable=False, default=0)
    directive = Column(String(16), nullable=False)
    address = Column(String(255), nullable=False)


class AccessCredentialStore(PortwyrmTable):
    __tablename__ = "access_list_credentials"
    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    username = Column(String(255), nullable=False)
    password_hash = Column(Text, nullable=False)


class AccessPrincipalStore(ManagedPortwyrmTable):
    __tablename__ = "access_list_principals"
    __table_args__ = (
        UniqueConstraint("access_list_id", "principal_id", name="uq_access_list_principal_edge"),
    )
    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)


AccessList = AccessListStore
AccessListRule = AccessRuleStore
AccessListCredential = AccessCredentialStore
AccessListPrincipal = AccessPrincipalStore

__all__ = [
    "AccessCredentialStore",
    "AccessList",
    "AccessListCredential",
    "AccessListPrincipal",
    "AccessListRule",
    "AccessListStore",
    "AccessPrincipalStore",
    "AccessRuleStore",
]
