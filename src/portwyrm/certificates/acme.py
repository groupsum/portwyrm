"""ACME protocol ports and failure-safe issuance orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol


class ChallengeType(StrEnum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"


@dataclass(frozen=True, slots=True)
class Challenge:
    type: ChallengeType
    identifier: str
    token: str
    value: str


@dataclass(frozen=True, slots=True)
class ACMEOrder:
    id: str
    domains: tuple[str, ...]
    challenges: tuple[Challenge, ...]


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    certificate: str
    private_key: str
    chain: str
    expires_at: datetime


class ACMEClient(Protocol):
    def create_order(
        self,
        domains: tuple[str, ...],
        *,
        challenge_type: ChallengeType,
        key_type: str,
    ) -> ACMEOrder: ...

    def validate_challenges(self, order: ACMEOrder) -> None: ...

    def finalize(self, order: ACMEOrder) -> IssuedCertificate: ...


class ChallengeHandler(Protocol):
    def present(self, challenge: Challenge) -> None: ...

    def cleanup(self, challenge: Challenge) -> None: ...


class CertificateLifecycle:
    """Issue certificates while guaranteeing challenge cleanup on every exit path."""

    def __init__(self, client: ACMEClient, handler: ChallengeHandler) -> None:
        self.client = client
        self.handler = handler

    def issue(
        self,
        domains: tuple[str, ...],
        *,
        challenge_type: ChallengeType = ChallengeType.HTTP_01,
        key_type: str = "rsa",
    ) -> IssuedCertificate:
        if not domains or len(domains) > 100:
            raise ValueError("ACME orders require between 1 and 100 domains")
        if key_type not in {"rsa", "ecdsa"}:
            raise ValueError("key_type must be rsa or ecdsa")
        wildcard = any(domain.startswith("*.") for domain in domains)
        if wildcard and challenge_type != ChallengeType.DNS_01:
            raise ValueError("wildcard certificates require DNS-01")

        order = self.client.create_order(
            domains,
            challenge_type=challenge_type,
            key_type=key_type,
        )
        presented: list[Challenge] = []
        try:
            for challenge in order.challenges:
                self.handler.present(challenge)
                presented.append(challenge)
            self.client.validate_challenges(order)
            return self.client.finalize(order)
        finally:
            for challenge in reversed(presented):
                self.handler.cleanup(challenge)

    @staticmethod
    def renewal_due(
        expires_at: datetime,
        *,
        now: datetime | None = None,
        renew_before: timedelta = timedelta(days=30),
    ) -> bool:
        instant = now or datetime.now(UTC)
        return expires_at <= instant + renew_before
