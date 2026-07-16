"""Role and fine-grained permission tables."""

from tigrbl.types import Boolean, Column, ForeignKey, Integer, String, Text, UniqueConstraint

from .base import ManagedPortwyrmTable


class RoleStore(ManagedPortwyrmTable):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("name", name="uq_roles_name"),)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=False, default="")
    is_system = Column(Boolean, nullable=False, default=False)


class PermissionStore(ManagedPortwyrmTable):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("key", name="uq_permissions_key"),)
    key = Column(String(255), nullable=False)
    section = Column(String(128), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    description = Column(Text, nullable=False, default="")


class PrincipalRoleStore(ManagedPortwyrmTable):
    __tablename__ = "principal_roles"
    __table_args__ = (UniqueConstraint("principal_id", "role_id", name="uq_principal_roles_edge"),)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)


class RolePermissionStore(ManagedPortwyrmTable):
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_edge"),
    )
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False, index=True)


class PrincipalPermissionStore(ManagedPortwyrmTable):
    __tablename__ = "principal_permissions"
    __table_args__ = (
        UniqueConstraint("principal_id", "permission_id", name="uq_principal_permissions_edge"),
    )
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False, index=True)
    effect = Column(String(16), nullable=False, default="allow")


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
