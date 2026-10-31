"""
SecureNet Backend — Configuration Management

Loads all environment variables and provides type-safe access
to configuration throughout the application.
"""

import sys
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from pydantic import ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ directory — every relative path in .env is resolved against it,
# so the server behaves the same no matter which directory it is started from.
BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "SecureNet"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # Server
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Database — the cloud PostgreSQL (Neon) database. Local databases are
    # refused so every installation shares the same real data; only the test
    # suite sets ALLOW_LOCAL_DATABASE=true for its throw-away SQLite file.
    DATABASE_URL: str
    ALLOW_LOCAL_DATABASE: bool = False
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Accounts that become admin when they register (comma-separated). Everyone
    # else is a normal user (viewer). Empty = the first account becomes admin.
    ADMIN_EMAILS: str = ""

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173"
    # Host names this backend answers to (anything else is refused: DNS-rebinding protection).
    # "*" turns the check off. SecureNet only listens on this computer (127.0.0.1).
    ALLOWED_HOSTS: str = "localhost,127.0.0.1,::1"

    @property
    def admin_emails(self) -> set[str]:
        return {e.strip().lower() for e in self.ADMIN_EMAILS.split(",") if e.strip()}

    @property
    def allowed_hosts_list(self) -> List[str]:
        return [h.strip() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins into a list"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    # OTP
    OTP_LENGTH: int = 6
    OTP_EXPIRE_MINUTES: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    OTP_MAX_ATTEMPTS: int = 5

    # Email
    EMAIL_ENABLED: bool = False
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""            # empty = SMTP_USER (Gmail requires the account address)
    SMTP_FROM_NAME: str = "SecureNet"

    # Alert emails: alerts are collected for this many seconds and sent as one
    # email per recipient (prevents an attack burst from flooding inboxes).
    ALERT_EMAIL_BATCH_SECONDS: int = 30
    # at most one attack email per this many seconds while the network stays abnormal
    ALERT_EMAIL_INTERVAL_SECONDS: int = 300
    ALERT_EMAIL_MAX_EVENTS: int = 50
    # Link placed in alert emails
    DASHBOARD_URL: str = "http://localhost:5173"

    # ML models — removed from this build (session 40): nothing is loaded unless ML_AUTOLOAD is true.
    # Either model (Isolation Forest, XGBoost) or both may be present.
    ML_AUTOLOAD: bool = False
    ML_MODELS_DIR: str = "./models"

    # Detection defaults (the Settings page overrides these at runtime)
    ANOMALY_THRESHOLD: float = 0.5
    CLASSIFICATION_CONFIDENCE_THRESHOLD: float = 0.7
    DETECTION_MODE: str = "monitor"
    # Additive behavioural rule layer (Zeek/Suricata-style threshold rules for scan/sweep/
    # brute-force/flood). OFF by owner's choice — only the model's trained labels are shown
    # (no "Reconnaissance"). Flip to true to re-enable the cross-flow rules.
    IDS_RULES_ENABLED: bool = False
    # Extra IPs Protection must NEVER block (comma-separated), on top of this PC's own
    # addresses + loopback/link-local, which are always protected. Keeps the host safe.
    PROTECTION_NEVER_BLOCK: str = ""

    # Packet capture / flow assembly
    CAPTURE_SOURCE: str = "scapy"        # "scapy" (built-in) or "local_csv" (our CICFlowMeter-4.0 pipeline)
    LIVE_CSV_DIR: str = r"F:\Intrusion_Detection-System\live_ids\csv"  # CsvFlowSource watches this (used when CAPTURE_SOURCE=local_csv)
    LIVE_CAPTURE_SPAWN: bool = True      # True = app launches WinDivert capture + CICFlowMeter convert itself (no terminals; needs admin)
    LIVE_PROJECT_DIR: str = r"F:\Intrusion_Detection-System"                      # holds live_ids/ + the capture scripts
    LIVE_PYTHON: str = r"F:\Intrusion_Detection-System\venv\Scripts\python.exe"   # project venv python (has pydivert + scapy)
    CAPTURE_INTERFACE: str = ""          # empty = Scapy default interface
    FLOW_IDLE_TIMEOUT_SECONDS: float = 15.0
    FLOW_ACTIVE_TIMEOUT_SECONDS: float = 120.0
    LIVE_SCORE_MAX_PER_SECOND: int = 20  # WebSocket throttle for benign scores

    # Logging
    LOG_LEVEL: str = "INFO"

    # Reports
    REPORTS_DIR: str = "./reports"

    # Security
    PASSWORD_MIN_LENGTH: int = 8
    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # Optional: serve a built frontend (used by the Electron shell)
    FRONTEND_DIST: str = ""

    # The IDS survives a shutdown: while it is ON its state is saved to
    # IDS_STATE_FILE and SecureNet is added to Windows start-up, so after the
    # computer restarts it turns itself back on and shows a desktop notice.
    # Turning it OFF removes both. (The test-suite switches all of this off.)
    IDS_AUTOSTART: bool = True
    IDS_ON_AT_STARTUP: bool = False
    # An attack storm must not flood the database, emails and dashboards: at most this many
    # incidents are stored per minute (and per source address); the rest are counted only.
    ALERT_STORE_MAX_PER_MINUTE: int = 120
    ALERT_STORE_MAX_PER_SOURCE_PER_MINUTE: int = 30       # live monitoring as soon as the backend starts
    IDS_STATE_FILE: str = "./data/ids-state.json"
    IDS_STARTUP_DIR: str = ""            # empty = the Windows Startup folder of this user
    DESKTOP_NOTIFICATIONS: bool = True

    @model_validator(mode="after")
    def _check(self) -> "Settings":
        if not self.ALLOW_LOCAL_DATABASE:
            url = urlsplit(self.DATABASE_URL)
            host = (url.hostname or "").lower()
            if url.scheme.startswith("sqlite") or host in ("", "localhost", "127.0.0.1", "::1", "0.0.0.0"):
                raise ValueError(
                    "DATABASE_URL points to a local database. SecureNet uses the cloud PostgreSQL "
                    "database (Neon): postgresql+asyncpg://USER:PASSWORD@HOST.neon.tech/DB?ssl=require"
                )
        if len(self.JWT_SECRET) < 32 or self.JWT_SECRET.startswith("replace-with"):
            raise ValueError(
                "JWT_SECRET must be a long random value (at least 32 characters) - run SETUP.bat, which "
                "creates one, or put your own random string in backend/.env"
            )
        if not self.SMTP_FROM_EMAIL.strip():
            self.SMTP_FROM_EMAIL = self.SMTP_USER.strip()
        # Serve the built dashboard by default, so opening the app shows the UI — not the API JSON —
        # no matter which launcher started the backend (Electron, the boot-monitor, or by hand).
        # Skipped when a FRONTEND_DIST is already given, or under the test suite (which sets it blank).
        if not self.FRONTEND_DIST and "pytest" not in sys.modules:
            default_dist = BACKEND_DIR.parent / "frontend" / "dist"
            if (default_dist / "index.html").is_file():
                self.FRONTEND_DIST = str(default_dist)
        return self

    def resolve_path(self, value: str) -> Path:
        """Resolve a possibly-relative path against the backend directory."""
        path = Path(value)
        return path if path.is_absolute() else (BACKEND_DIR / path).resolve()

    @property
    def models_dir(self) -> Path:
        return self.resolve_path(self.ML_MODELS_DIR)

    @property
    def reports_dir(self) -> Path:
        return self.resolve_path(self.REPORTS_DIR)

    @property
    def ids_state_file(self) -> Path:
        return self.resolve_path(self.IDS_STATE_FILE)


def _load() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        env_file = BACKEND_DIR / ".env"
        problems = "\n".join(
            f"  - {'.'.join(str(p) for p in err['loc']) or 'settings'}: {err['msg'].removeprefix('Value error, ')}"
            for err in exc.errors()
        )
        hint = ("" if env_file.exists() else
                f"\n{env_file} does not exist - copy .env.example to .env and fill it in "
                "(or copy .env from the original computer).")
        sys.exit(f"SecureNet cannot start - backend/.env is incomplete:\n{problems}{hint}")


# Global settings instance
settings = _load()
