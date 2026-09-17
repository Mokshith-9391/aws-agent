"""
Application settings and configuration management.

Loads configuration from environment variables and .env files,
providing validated settings for all application components.
"""

import os
from enum import Enum
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AZURE_OPENAI = "azure_openai"
    OLLAMA = "ollama"


class ExecutionMode(str, Enum):
    """Application execution modes."""
    DRY_RUN = "dry_run"
    LIVE = "live"


class Settings(BaseSettings):
    """Application configuration settings loaded from environment."""

    # --- Application ---
    APP_NAME: str = "AWS Provisioning Agent"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = "logs"

    # --- LLM Provider ---
    LLM_PROVIDER: LLMProvider = LLMProvider.GOOGLE
    LLM_MODEL: str = "gemini-2.0-flash"
    LLM_API_KEY: Optional[str] = Field(default=None, alias="API_KEY")
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 8192
    LLM_BASE_URL: Optional[str] = None

    # --- AWS ---
    AWS_PROFILE: str = "default"
    AWS_REGION: str = "ap-south-1"
    AWS_CLI_TIMEOUT: int = 120  # seconds
    AWS_CLI_PATH: str = "aws"

    # --- Execution ---
    DEFAULT_EXECUTION_MODE: ExecutionMode = ExecutionMode.DRY_RUN
    MAX_COMMANDS_PER_PLAN: int = 25
    COMMAND_TIMEOUT: int = 300  # seconds per command
    REQUIRE_APPROVAL_WRITE: bool = True
    REQUIRE_APPROVAL_DESTRUCTIVE: bool = True

    # --- Naming ---
    RESOURCE_NAME_PREFIX: str = "ai-agent"
    RESOURCE_NAME_SEPARATOR: str = "-"

    # --- History ---
    HISTORY_DIR: str = "history"
    MAX_HISTORY_ENTRIES: int = 500

    # --- Security ---
    ENABLE_PROMPT_INJECTION_PROTECTION: bool = True
    MAX_INPUT_LENGTH: int = 5000
    SECRET_PATTERNS: list[str] = [
        r"AKIA[0-9A-Z]{16}",           # AWS Access Key ID
        r"(?i)aws.*secret.*['\"][A-Za-z0-9/+=]{40}['\"]",  # AWS Secret
        r"(?i)password\s*[=:]\s*\S+",   # Passwords
        r"(?i)token\s*[=:]\s*\S+",      # Tokens
    ]

    # --- Testing & Integration ---
    AWS_INTEGRATION_TESTS: bool = False

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    @property
    def resource_prefix(self) -> str:
        """Get the resource naming prefix."""
        return self.RESOURCE_NAME_PREFIX

    def get_aws_env(
        self, profile: Optional[str] = None, region: Optional[str] = None
    ) -> dict[str, str]:
        """Get environment variables for AWS CLI subprocess calls with explicit profile and region overrides."""
        env = os.environ.copy()
        effective_profile = profile or self.AWS_PROFILE
        effective_region = region or self.AWS_REGION

        if effective_profile and effective_profile.strip():
            env["AWS_PROFILE"] = effective_profile.strip()
        if effective_region and effective_region.strip():
            env["AWS_DEFAULT_REGION"] = effective_region.strip()
            env["AWS_REGION"] = effective_region.strip()
        return env


# Singleton settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the application settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Force reload settings from environment."""
    global _settings
    _settings = Settings()
    return _settings
