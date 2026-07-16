"""Role and fine-grained permission tables."""

from tigrbl.types import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint

from .base import READ_ONLY_PROFILE, PortwyrmTable, acol


class RoleStore(PortwyrmTable):
    __tablename__ = "roles"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (UniqueConstraint("name", name="uq_roles_name"),)
    name = acol(String(128), nullable=False)
    description = acol(Text, nullable=False, default="")
    is_system = acol(Boolean, nullable=False, default=False)


class PermissionStore(PortwyrmTable):
    __tablename__ = "permissions"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (UniqueConstraint("key", name="uq_permissions_key"),)
    key = acol(String(255), nullable=False)
    section = acol(String(128), nullable=False, index=True)
    action = acol(String(64), nullable=False)
    description = acol(Text, nullable=False, default="")


class PrincipalRoleStore(PortwyrmTable):
    __tablename__ = "principal_roles"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (UniqueConstraint("principal_id", "role_id", name="uq_principal_roles_edge"),)
    principal_id = acol(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    role_id = acol(Integer, ForeignKey("roles.id"), nullable=False, index=True)


class RolePermissionStore(PortwyrmTable):
    __tablename__ = "role_permissions"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_edge"),
    )
    role_id = acol(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    permission_id = acol(Integer, ForeignKey("permissions.id"), nullable=False, index=True)


class PrincipalPermissionStore(PortwyrmTable):
    __tablename__ = "principal_permissions"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        UniqueConstraint("principal_id", "permission_id", name="uq_principal_permissions_edge"),
    )
    principal_id = acol(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    permission_id = acol(Integer, ForeignKey("permissions.id"), nullable=False, index=True)
    effect = acol(String(16), nullable=False, default="allow")


Role = RoleStore
Permission = PermissionStore
PrincipalRole = PrincipalRoleStore
RolePermission = RolePermissionStore
PrincipalPermission = PrincipalPermissionStore

__all__ = [
    "Permission",
    "PermissionStore",
    "PrincipalPermission",
    "PrincipalPermissionStore",
    "PrincipalRole",
    "PrincipalRoleStore",
    "Role",
    "RolePermission",
    "RolePermissionStore",
    "RoleStore",
]
