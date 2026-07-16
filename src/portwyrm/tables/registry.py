"""The complete Portwyrm Tigrbl table inventory."""

from tigrbl import TableBase

from .access import AccessCredentialStore, AccessListStore, AccessPrincipalStore, AccessRuleStore
from .audit import AuditEventStore
from .certificates import CertificateChallengeStore, CertificateDomainStore, CertificateStore
from .mfa import MFAEnrollmentStore, MFARecoveryCodeStore
from .migrations import SchemaMigrationStore
from .principals import BrowserSessionStore, CredentialStore, PrincipalStore
from .rbac import (
    PermissionStore,
    PrincipalPermissionStore,
    PrincipalRoleStore,
    RolePermissionStore,
    RoleStore,
)
from .routing import (
    HostConfigRevisionStore,
    RoutingHostAccessListStore,
    RoutingHostStore,
    RoutingLocationStore,
    RoutingSourceStore,
    RoutingUpstreamStore,
    StreamRouteStore,
)
from .runtime import GenerationStore, LeaseStore, ReconcileStore
from .settings import SettingStore
from .tokens import PATStore

PORTWYRM_TABLES: tuple[type[TableBase], ...] = (
    PrincipalStore,
    CredentialStore,
    RoleStore,
    PermissionStore,
    PrincipalRoleStore,
    RolePermissionStore,
    PrincipalPermissionStore,
    PATStore,
    BrowserSessionStore,
    MFAEnrollmentStore,
    MFARecoveryCodeStore,
    AccessListStore,
    AccessRuleStore,
    AccessCredentialStore,
    AccessPrincipalStore,
    CertificateStore,
    CertificateDomainStore,
    CertificateChallengeStore,
    RoutingHostStore,
    RoutingSourceStore,
    RoutingUpstreamStore,
    RoutingLocationStore,
    RoutingHostAccessListStore,
    StreamRouteStore,
    HostConfigRevisionStore,
    GenerationStore,
    ReconcileStore,
    LeaseStore,
    SettingStore,
    AuditEventStore,
    SchemaMigrationStore,
)

__all__ = ["PORTWYRM_TABLES"]
