"""Compatibility exports for the focused identity, credential, and session tables."""

from .credentials import AuthenticatedPrincipal, Credential, CredentialStore
from .identities import Principal, PrincipalStore, SecurityPrincipal
from .sessions import BrowserSession, BrowserSessionStore

__all__ = [
    "AuthenticatedPrincipal",
    "BrowserSession",
    "BrowserSessionStore",
    "Credential",
    "CredentialStore",
    "Principal",
    "PrincipalStore",
    "SecurityPrincipal",
]
