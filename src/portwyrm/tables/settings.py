"""Global Portwyrm setting records."""

from tigrbl.types import JSON, Column, String, UniqueConstraint

from .base import ManagedPortwyrmTable


class SettingStore(ManagedPortwyrmTable):
    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("key", name="uq_settings_key"),)
    key = Column(String(255), nullable=False)
    value = Column(JSON, nullable=False)


Setting = SettingStore

__all__ = ["Setting", "SettingStore"]
