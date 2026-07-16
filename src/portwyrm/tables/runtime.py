"""Durable Nginx generations, reconciliation attempts, and leases."""

from __future__ import annotations

import inspect
import time
from typing import Any, ClassVar

from sqlalchemy import delete, select, update
from tigrbl import op_ctx, schema_ctx
from tigrbl.types import (
    JSON,
    BaseModel,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from .base import ManagedPortwyrmTable


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class GenerationStore(ManagedPortwyrmTable):
    __tablename__ = "config_generations"
    __table_args__ = (UniqueConstraint("generation", name="uq_config_generation"),)

    generation = Column(String(64), nullable=False, index=True)
    previous_generation = Column(String(64), nullable=True)
    files = Column(JSON, nullable=False, default=dict)
    state = Column(String(32), nullable=False, default="staged", index=True)
    is_active = Column(Boolean, nullable=False, default=False, index=True)
    diagnostic = Column(Text, nullable=True)
    validated_at = Column(Integer, nullable=True)
    activated_at = Column(Integer, nullable=True)
    _runtime_controller: ClassVar[Any | None] = None

    @classmethod
    def configure_runtime(cls, controller: Any | None) -> None:
        cls._runtime_controller = controller

    @schema_ctx(alias="activate", kind="in")
    class ActivateRequest(BaseModel):
        generation: str

    @schema_ctx(alias="activate", kind="out")
    class ActivateResult(BaseModel):
        generation: str
        previous_generation: str | None

    @schema_ctx(alias="clear_active", kind="out")
    class ClearActiveResult(BaseModel):
        cleared: bool
        previous_generation: str | None

    @schema_ctx(alias="render", kind="out")
    class RenderResult(BaseModel):
        generation: str
        digest: str
        files: dict[str, str]

    @schema_ctx(alias="stage", kind="out")
    class StageResult(BaseModel):
        generation: str
        digest: str
        created: bool
        state: str = "staged"

    @schema_ctx(alias="diff", kind="in")
    class DiffRequest(BaseModel):
        base_generation: str | None = None
        target_generation: str | None = None

    @schema_ctx(alias="diff", kind="out")
    class DiffResult(BaseModel):
        base_generation: str | None
        target_generation: str
        files: list[dict[str, str]]

    @schema_ctx(alias="validate", kind="in")
    class ValidateRequest(BaseModel):
        generation: str

    @schema_ctx(alias="validate", kind="out")
    class ValidateResult(BaseModel):
        generation: str
        valid: bool

    @schema_ctx(alias="reload", kind="in")
    class ReloadRequest(BaseModel):
        generation: str | None = None

    @schema_ctx(alias="reload", kind="out")
    class ReloadResult(BaseModel):
        generation: str
        reloaded: bool

    @schema_ctx(alias="reconcile", kind="out")
    class ReconcileResult(BaseModel):
        generation: str
        previous_generation: str | None
        changed: bool
        applied: bool
        diagnostic: str | None = None

    @classmethod
    def _controller(cls) -> Any:
        if cls._runtime_controller is None:
            raise RuntimeError("generation runtime is not configured")
        return cls._runtime_controller

    @classmethod
    async def _render(cls) -> dict[str, Any]:
        rendered = await _await(cls._controller().render())
        files = dict(rendered.files)
        generation = cls._controller().reconciler.store.generation_id(files)
        return {"generation": generation, "digest": rendered.digest, "files": files}

    @op_ctx(alias="render", target="custom", arity="collection")
    async def render(cls, ctx: Any) -> dict[str, Any]:
        del ctx
        return await cls._render()

    @op_ctx(alias="stage", target="custom", arity="collection")
    async def stage(cls, ctx: Any) -> dict[str, Any]:
        rendered = await cls._render()
        staged = await _await(cls._controller().stage(rendered["files"]))
        table = cls.__table__
        row = (
            await _await(
                ctx["db"].execute(
                    select(cls).where(table.c.generation == rendered["generation"])
                )
            )
        ).scalar_one_or_none()
        if row is None:
            row = cls(
                generation=rendered["generation"],
                files=rendered["files"],
                state="staged",
                is_active=False,
            )
            ctx["db"].add(row)
        elif not row.is_active:
            row.files = rendered["files"]
            row.state = "staged"
        return {
            "generation": rendered["generation"],
            "digest": rendered["digest"],
            "created": bool(staged["created"]),
            "state": "active" if row.is_active else "staged",
        }

    @op_ctx(alias="diff", target="custom", arity="collection")
    async def diff(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        target_name = str(payload.get("target_generation") or "")
        if target_name:
            target = await cls._generation_files(ctx["db"], target_name)
            target_files = target["files"]
        else:
            target = await cls._render()
            target_name = target["generation"]
            target_files = target["files"]

        base_name = str(payload.get("base_generation") or "")
        if base_name:
            base_files = (await cls._generation_files(ctx["db"], base_name))["files"]
        else:
            active = (
                await _await(
                    ctx["db"].execute(
                        select(cls).where(cls.__table__.c.is_active.is_(True)).limit(1)
                    )
                )
            ).scalar_one_or_none()
            base_name = active.generation if active is not None else ""
            base_files = dict(active.files or {}) if active is not None else {}
        changes = [
            {
                "path": path,
                "before": str(base_files.get(path, "")),
                "after": str(target_files.get(path, "")),
            }
            for path in sorted(set(base_files) | set(target_files))
            if base_files.get(path) != target_files.get(path)
        ]
        return {
            "base_generation": base_name or None,
            "target_generation": target_name,
            "files": changes,
        }

    @classmethod
    async def _generation_files(cls, db: Any, generation: str) -> dict[str, Any]:
        row = (
            await _await(
                db.execute(select(cls).where(cls.__table__.c.generation == generation))
            )
        ).scalar_one_or_none()
        if row is None:
            raise ValueError(f"generation does not exist: {generation}")
        return {"generation": row.generation, "files": dict(row.files or {})}

    @op_ctx(alias="activate", target="custom", arity="collection")
    async def activate(cls, ctx: Any) -> dict[str, Any]:
        generation = str((ctx.get("payload") or {}).get("generation") or "")
        table = cls.__table__
        result = await _await(
            ctx["db"].execute(
                select(table.c.id, table.c.generation)
                .where(table.c.generation == generation)
                .limit(1)
            )
        )
        row = result.first()
        if row is None:
            raise ValueError(f"generation does not exist: {generation}")
        current = await _await(
            ctx["db"].execute(
                select(table.c.generation).where(table.c.is_active.is_(True)).limit(1)
            )
        )
        previous_generation = current.scalar_one_or_none()
        await _await(
            ctx["db"].execute(
                update(table).values(is_active=False).execution_options(synchronize_session=False)
            )
        )
        await _await(
            ctx["db"].execute(
                update(table)
                .where(table.c.id == row.id)
                .values(
                    is_active=True,
                    state="active",
                    previous_generation=previous_generation,
                    activated_at=int(time.time()),
                )
                .execution_options(synchronize_session=False)
            )
        )
        raw = getattr(ctx["db"], "raw", ctx["db"])
        if callable(getattr(raw, "expire_all", None)):
            raw.expire_all()
        return {"generation": row.generation, "previous_generation": previous_generation}

    @op_ctx(alias="clear_active", target="custom", arity="collection")
    async def clear_active(cls, ctx: Any) -> dict[str, Any]:
        table = cls.__table__
        current = await _await(
            ctx["db"].execute(
                select(table.c.id, table.c.generation).where(table.c.is_active.is_(True)).limit(1)
            )
        )
        row = current.first()
        if row is None:
            return {"cleared": False, "previous_generation": None}
        await _await(
            ctx["db"].execute(
                update(table)
                .where(table.c.id == row.id)
                .values(is_active=False, state="superseded")
                .execution_options(synchronize_session=False)
            )
        )
        raw = getattr(ctx["db"], "raw", ctx["db"])
        if callable(getattr(raw, "expire_all", None)):
            raw.expire_all()
        return {"cleared": True, "previous_generation": row.generation}

    @op_ctx(alias="validate", target="custom", arity="collection")
    async def validate(cls, ctx: Any) -> dict[str, Any]:
        result = cls._controller().validate(dict(ctx.get("payload") or {}))
        return await _await(result)

    @op_ctx(alias="reload", target="custom", arity="collection")
    async def reload(cls, ctx: Any) -> dict[str, Any]:
        result = cls._controller().reload(dict(ctx.get("payload") or {}))
        return await _await(result)

    @op_ctx(alias="reconcile", target="custom", arity="collection")
    async def reconcile(cls, ctx: Any) -> dict[str, Any]:
        del ctx
        result = await _await(cls._controller().reconcile())
        return {
            "generation": result.generation,
            "previous_generation": result.previous_generation,
            "changed": result.changed,
            "applied": result.applied,
            "diagnostic": result.diagnostic,
        }


class ReconcileStore(ManagedPortwyrmTable):
    __tablename__ = "reconcile_attempts"
    generation_id = Column(Integer, ForeignKey("config_generations.id"), nullable=True, index=True)
    previous_generation = Column(String(64), nullable=True)
    changed = Column(Boolean, nullable=False, default=False)
    applied = Column(Boolean, nullable=False, default=False)
    status = Column(String(32), nullable=False, index=True)
    diagnostic = Column(Text, nullable=True)

    @schema_ctx(alias="create", kind="out")
    class ReconcileResult(BaseModel):
        generation_id: int | None
        previous_generation: str | None
        changed: bool
        applied: bool
        status: str
        diagnostic: str | None = None


class LeaseStore(ManagedPortwyrmTable):
    __tablename__ = "runtime_leases"
    __table_args__ = (UniqueConstraint("name", name="uq_runtime_lease_name"),)
    name = Column(String(255), nullable=False, index=True)
    holder = Column(String(255), nullable=False)
    expires_at = Column(Integer, nullable=False, index=True)

    @schema_ctx(alias="acquire", kind="in")
    class AcquireRequest(BaseModel):
        name: str
        holder: str
        ttl_seconds: int = 60

    @op_ctx(alias="acquire", target="custom", arity="collection")
    async def acquire(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        name = str(payload["name"])
        holder = str(payload["holder"])
        now = int(time.time())
        result = await _await(
            ctx["db"].execute(select(cls).where(cls.name == name).with_for_update())
        )
        row = result.scalar_one_or_none()
        if row is not None and row.expires_at > now and row.holder != holder:
            return {
                "acquired": False,
                "name": name,
                "holder": row.holder,
                "expires_at": row.expires_at,
            }
        expires_at = now + max(1, int(payload.get("ttl_seconds") or 60))
        if row is None:
            row = cls(name=name, holder=holder, expires_at=expires_at)
            ctx["db"].add(row)
        else:
            row.holder = holder
            row.expires_at = expires_at
        return {"acquired": True, "name": name, "holder": holder, "expires_at": expires_at}

    @op_ctx(alias="renew", target="custom", arity="collection")
    async def renew(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        result = await _await(
            ctx["db"].execute(
                select(cls).where(
                    cls.name == str(payload["name"]), cls.holder == str(payload["holder"])
                )
            )
        )
        row = result.scalar_one_or_none()
        if row is None or row.expires_at <= int(time.time()):
            return {"renewed": False}
        row.expires_at = int(time.time()) + max(1, int(payload.get("ttl_seconds") or 60))
        return {"renewed": True, "expires_at": row.expires_at}

    @op_ctx(alias="release", target="custom", arity="collection")
    async def release(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        result = await _await(
            ctx["db"].execute(
                delete(cls).where(
                    cls.name == str(payload["name"]), cls.holder == str(payload["holder"])
                )
            )
        )
        return {"released": bool(result.rowcount)}


ReconcileResult = ReconcileStore.ReconcileResult
GenerationRenderResult = GenerationStore.RenderResult
GenerationStageResult = GenerationStore.StageResult
GenerationDiffResult = GenerationStore.DiffResult

__all__ = [
    "GenerationDiffResult",
    "GenerationRenderResult",
    "GenerationStageResult",
    "GenerationStore",
    "LeaseStore",
    "ReconcileResult",
    "ReconcileStore",
]
