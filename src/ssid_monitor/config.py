"""TOML configuration loader and validator."""

import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = "/etc/dpmb/config.toml"


@dataclass
class Config:
    """Application configuration."""
    device_id: str = field(default_factory=socket.gethostname)
    wifi_interface: str = ""
    scan_interval_sec: int = 10
    cooldown_min: int = 60
    webhook_url: str = ""
    heartbeat_hour: int = 8
    log_level: str = "info"
    db_path: str = "/var/lib/dpmb/events.db"

    def validate(self) -> list[str]:
        """Return list of validation errors, empty if valid."""
        errors = []
        # wifi_interface is optional — auto-discovery will find one at runtime
        # webhook_url is optional — notifications configured via dashboard settings
        if self.webhook_url and not self.webhook_url.startswith(("http://", "https://")):
            errors.append("webhook_url must start with http:// or https://")
        if self.scan_interval_sec < 1 or self.scan_interval_sec > 300:
            errors.append("scan_interval_sec must be between 1 and 300")
        if self.cooldown_min < 1:
            errors.append("cooldown_min must be >= 1")
        if self.heartbeat_hour < 0 or self.heartbeat_hour > 23:
            errors.append("heartbeat_hour must be 0-23")
        if self.log_level not in ("debug", "info", "warning", "error"):
            errors.append(f"log_level must be debug/info/warning/error, got '{self.log_level}'")
        return errors


def load_config(config_path: str | None = None) -> Config:
    """Load configuration from a TOML file.

    Args:
        config_path: Path to config file. Defaults to /etc/dpmb/config.toml.

    Returns:
        Config dataclass with loaded values.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config has validation errors.
    """
    path = Path(config_path or DEFAULT_CONFIG_PATH)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "rb") as f:
        raw = tomllib.load(f)

    section = raw.get("dpmb", raw.get("ssid-monitor", raw))

    config = Config(
        device_id=section.get("device_id", socket.gethostname()),
        wifi_interface=section.get("wifi_interface", ""),
        scan_interval_sec=section.get("scan_interval_sec", 10),
        cooldown_min=section.get("cooldown_min", 60),
        webhook_url=section.get("webhook_url", ""),
        heartbeat_hour=section.get("heartbeat_hour", 8),
        log_level=section.get("log_level", "info"),
        db_path=section.get("db_path", "/var/lib/dpmb/events.db"),
    )

    errors = config.validate()
    if errors:
        raise ValueError(f"Config validation failed: {'; '.join(errors)}")

    return config
