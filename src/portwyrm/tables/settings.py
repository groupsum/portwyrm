"""Global Portwyrm setting records."""

from tigrbl.types import JSON, String, UniqueConstraint

from .base import ManagedPortwyrmTable, acol


class SettingStore(ManagedPortwyrmTable):
    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("key", name="uq_settings_key"),)
    key = acol(String(255), nullable=False)
    value = acol(JSON, nullable=False)


Setting = SettingStore

__all__ = ["Setting", "SettingStore"]
