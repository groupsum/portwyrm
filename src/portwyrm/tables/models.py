"""Normalized Tigrbl models for identity, routing, certificates, and operations."""

from __future__ import annotations

import inspect
from typing import Any

from tigrbl import TableBase, hook_ctx, op_ctx
from tigrbl.orm.mixins import Timestamped
from tigrbl.types import JSON, Boolean, Column, ForeignKey, Integer, String, Text, UniqueConstraint


class PortwyrmTable(TableBase, Timestamped):
    """Shared durable fields and post-commit control-plane notification."""

    __abstract__ = True
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)
    metadata_json = Column(JSON, nullable=False, default=dict)

    @hook_ctx(ops=("create", "update", "replace", "delete"), phase="POST_COMMIT")
    async def publish_change(cls, ctx: Any) -> None:
        app = getattr(ctx, "app", None)
        state = getattr(app, "state", None)
        callback = getattr(state, "tigrbl_after_commit", None)
        if not callable(callback):
            return
        result = callback(cls.__tablename__)
        if inspect.isawaitable(result):
            await result


class Principal(PortwyrmTable):
    __tablename__ = "principals"
    __table_args__ = (UniqueConstraint("email", name="uq_principals_email"),)

    email = Column(String(320), nullable=False, index=True)
    display_name = Column(String(255), nullable=False, default="")
    nickname = Column(String(255), nullable=False, default="")
    is_admin = Column(Boolean, nullable=False, default=False)
    is_disabled = Column(Boolean, nullable=False, default=False)
    is_deleted = Column(Boolean, nullable=False, default=False)
    visibility = Column(String(32), nullable=False, default="user")


class Credential(PortwyrmTable):
    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("principal_id", name="uq_credentials_principal"),)

    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    password_version = Column(Integer, nullable=False, default=1)


class Role(PortwyrmTable):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("name", name="uq_roles_name"),)

    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=False, default="")
    is_system = Column(Boolean, nullable=False, default=False)


class Permission(PortwyrmTable):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("key", name="uq_permissions_key"),)

    key = Column(String(255), nullable=False)
    section = Column(String(128), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    description = Column(Text, nullable=False, default="")


class PrincipalRole(PortwyrmTable):
    __tablename__ = "principal_roles"
    __table_args__ = (
        UniqueConstraint("principal_id", "role_id", name="uq_principal_roles_edge"),
    )

    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)


class RolePermission(PortwyrmTable):
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_edge"),
    )

    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False, index=True)


class PrincipalPermission(PortwyrmTable):
    __tablename__ = "principal_permissions"
    __table_args__ = (
        UniqueConstraint(
            "principal_id", "permission_id", name="uq_principal_permissions_edge"
        ),
    )

    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False, index=True)
    effect = Column(String(16), nullable=False, default="allow")


class PersonalAccessToken(PortwyrmTable):
    __tablename__ = "personal_access_tokens"
    __table_args__ = (UniqueConstraint("token_prefix", name="uq_pat_prefix"),)

    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    token_prefix = Column(String(64), nullable=False)
    token_digest = Column(String(255), nullable=False)
    scopes = Column(JSON, nullable=False, default=list)
    expires_at = Column(Integer, nullable=True)
    last_used_at = Column(Integer, nullable=True)
    revoked_at = Column(Integer, nullable=True)
    replaced_by_id = Column(Integer, ForeignKey("personal_access_tokens.id"), nullable=True)


class BrowserSession(PortwyrmTable):
    __tablename__ = "browser_sessions"
    __table_args__ = (UniqueConstraint("token_id", name="uq_browser_session_token_id"),)

    token_id = Column(String(64), nullable=False, index=True)
    token_digest = Column(String(255), nullable=False)
    principal_snapshot = Column(JSON, nullable=False)
    expires_at = Column(Integer, nullable=False, index=True)


class MFAEnrollment(PortwyrmTable):
    __tablename__ = "mfa_enrollments"
    __table_args__ = (UniqueConstraint("principal_id", name="uq_mfa_principal"),)

    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    method = Column(String(32), nullable=False, default="totp")
    encrypted_secret = Column(Text, nullable=False)
    confirmed = Column(Boolean, nullable=False, default=False)


class MFARecoveryCode(PortwyrmTable):
    __tablename__ = "mfa_recovery_codes"

    enrollment_id = Column(Integer, ForeignKey("mfa_enrollments.id"), nullable=False, index=True)
    code_digest = Column(String(255), nullable=False)
    used_at = Column(Integer, nullable=True)


class AccessList(PortwyrmTable):
    __tablename__ = "access_lists"

    name = Column(String(255), nullable=False, index=True)
    satisfy_any = Column(Boolean, nullable=False, default=False)
    pass_auth = Column(Boolean, nullable=False, default=False)


class AccessListRule(PortwyrmTable):
    __tablename__ = "access_list_rules"

    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    position = Column(Integer, nullable=False, default=0)
    directive = Column(String(16), nullable=False)
    address = Column(String(255), nullable=False)


class AccessListCredential(PortwyrmTable):
    __tablename__ = "access_list_credentials"

    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    username = Column(String(255), nullable=False)
    password_hash = Column(Text, nullable=False)


class AccessListPrincipal(PortwyrmTable):
    __tablename__ = "access_list_principals"
    __table_args__ = (
        UniqueConstraint(
            "access_list_id", "principal_id", name="uq_access_list_principal_edge"
        ),
    )

    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)


class Certificate(PortwyrmTable):
    __tablename__ = "certificates"

    nice_name = Column(String(255), nullable=False)
    provider = Column(String(64), nullable=False)
    challenge_type = Column(String(32), nullable=True)
    key_type = Column(String(32), nullable=False, default="rsa")
    material_ref = Column(String(1024), nullable=True)
    expires_at = Column(Integer, nullable=True)
    status = Column(String(32), nullable=False, default="pending")


class CertificateDomain(PortwyrmTable):
    __tablename__ = "certificate_domains"
    __table_args__ = (
        UniqueConstraint("certificate_id", "domain_name", name="uq_certificate_domain"),
    )

    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=False, index=True)
    domain_name = Column(String(253), nullable=False, index=True)


class RoutingHost(PortwyrmTable):
    __tablename__ = "routing_hosts"

    kind = Column(String(32), nullable=False, index=True)
    owner_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    enabled = Column(Boolean, nullable=False, default=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    force_ssl = Column(Boolean, nullable=False, default=False)
    hsts_enabled = Column(Boolean, nullable=False, default=False)
    hsts_subdomains = Column(Boolean, nullable=False, default=False)
    websocket_enabled = Column(Boolean, nullable=False, default=True)
    cache_enabled = Column(Boolean, nullable=False, default=False)
    block_exploits = Column(Boolean, nullable=False, default=True)
    advanced_config = Column(Text, nullable=False, default="")

    @op_ctx(alias="preview", target="custom", arity="member")
    def preview(cls, ctx: Any) -> dict[str, Any]:
        callback = getattr(getattr(getattr(ctx, "app", None), "state", None), "preview_host", None)
        return callback(ctx) if callable(callback) else {"status": "preview-unavailable"}


class RoutingSource(PortwyrmTable):
    __tablename__ = "routing_sources"
    __table_args__ = (
        UniqueConstraint("routing_host_id", "domain_name", name="uq_routing_source_domain"),
    )

    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    domain_name = Column(String(253), nullable=False, index=True)


class RoutingUpstream(PortwyrmTable):
    __tablename__ = "routing_upstreams"

    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    protocol = Column(String(16), nullable=False, default="http")
    target_kind = Column(String(16), nullable=False)
    target = Column(String(1024), nullable=False)
    port = Column(Integer, nullable=False)
    position = Column(Integer, nullable=False, default=0)
    weight = Column(Integer, nullable=False, default=1)


class RoutingHostAccessList(PortwyrmTable):
    __tablename__ = "routing_host_access_lists"
    __table_args__ = (
        UniqueConstraint(
            "routing_host_id", "access_list_id", name="uq_routing_host_access_list"
        ),
    )

    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)


class StreamRoute(PortwyrmTable):
    __tablename__ = "stream_routes"

    owner_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    protocol = Column(String(8), nullable=False)
    incoming_port = Column(Integer, nullable=False, index=True)
    target_kind = Column(String(16), nullable=False)
    target = Column(String(1024), nullable=False)
    target_port = Column(Integer, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)


class ConfigRevision(PortwyrmTable):
    __tablename__ = "config_revisions"
    __table_args__ = (
        UniqueConstraint("routing_host_id", "generation", name="uq_host_generation"),
    )

    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    generation = Column(String(64), nullable=False)
    config_text = Column(Text, nullable=False)
    config_digest = Column(String(64), nullable=False)
    applied = Column(Boolean, nullable=False, default=False)
    applied_at = Column(Integer, nullable=True)

    @op_ctx(alias="compare", target="custom", arity="member")
    def compare(cls, ctx: Any) -> dict[str, Any]:
        callback = getattr(
            getattr(getattr(ctx, "app", None), "state", None), "compare_revisions", None
        )
        return callback(ctx) if callable(callback) else {"status": "compare-unavailable"}


class Setting(PortwyrmTable):
    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("key", name="uq_settings_key"),)

    key = Column(String(255), nullable=False)
    value = Column(JSON, nullable=False)


class AuditEvent(PortwyrmTable):
    __tablename__ = "audit_events"

    actor_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    action = Column(String(255), nullable=False, index=True)
    object_type = Column(String(128), nullable=False, index=True)
    object_id = Column(String(255), nullable=False)
    details = Column(JSON, nullable=False, default=dict)


PORTWYRM_TABLES: tuple[type[TableBase], ...] = (
    Principal,
    Credential,
    Role,
    Permission,
    PrincipalRole,
    RolePermission,
    PrincipalPermission,
    PersonalAccessToken,
    BrowserSession,
    MFAEnrollment,
    MFARecoveryCode,
    AccessList,
    AccessListRule,
    AccessListCredential,
    AccessListPrincipal,
    Certificate,
    CertificateDomain,
    RoutingHost,
    RoutingSource,
    RoutingUpstream,
    RoutingHostAccessList,
    StreamRoute,
    ConfigRevision,
    Setting,
    AuditEvent,
)
