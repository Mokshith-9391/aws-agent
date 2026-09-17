"""
Output sanitizer module to remove or mask sensitive data.
"""

import logging
import re
from typing import Any

from agent.models import CommandResult

# Using settings if available, otherwise fallback
try:
    from config.settings import Settings
    SECRET_PATTERNS = getattr(Settings, 'SECRET_PATTERNS', [])
except ImportError:
    SECRET_PATTERNS = []

logger = logging.getLogger(__name__)

# Fallback patterns if not in settings
DEFAULT_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), r"AKIA****************"),
    (re.compile(r"(?i)secret_?access_?key[=:\s]+[A-Za-z0-9/+=]{40}"), r"SECRET_ACCESS_KEY_MASKED"),
    (re.compile(r"(?i)session_?token[=:\s]+[A-Za-z0-9/+=]+"), r"SESSION_TOKEN_MASKED"),
    (re.compile(r"(?i)password[=:\s]+[^\s]+"), r"PASSWORD_MASKED"),
    (re.compile(r"(?i)api_?key[=:\s]+[A-Za-z0-9\-]+"), r"API_KEY_MASKED"),
]

ACCOUNT_ID_PATTERN = re.compile(r"\b(\d{8})(\d{4})\b")

class OutputSanitizer:
    """
    Sanitizer for removing or masking sensitive data from text outputs.
    """
    
    def __init__(self):
        self.patterns = SECRET_PATTERNS if SECRET_PATTERNS else DEFAULT_PATTERNS

    def sanitize(self, text: str) -> str:
        """
        Remove or mask sensitive data from text.
        
        Args:
            text (str): The input text to sanitize.
            
        Returns:
            str: The sanitized text.
        """
        if not text or not isinstance(text, str):
            return text
            
        sanitized_text = text
        
        try:
            # Apply configured or default patterns
            for pattern, replacement in self.patterns:
                sanitized_text = pattern.sub(replacement, sanitized_text)
                
            # Mask AWS Account IDs (show last 4 digits)
            sanitized_text = ACCOUNT_ID_PATTERN.sub(r"********\2", sanitized_text)
            
        except Exception as e:
            logger.error(f"Error during sanitization: {e}")
            return "<SANITIZATION_FAILED_OUTPUT_HIDDEN>"
            
        return sanitized_text

    def sanitize_command_output(self, result: CommandResult) -> CommandResult:
        """
        Sanitize stdout and stderr of a CommandResult.
        
        Args:
            result (CommandResult): The command result to sanitize.
            
        Returns:
            CommandResult: A CommandResult with sanitized outputs.
        """
        try:
            sanitized = result.model_copy()
            sanitized.stdout = self.sanitize(result.stdout or '')
            sanitized.stderr = self.sanitize(result.stderr or '')
            if result.error_message:
                sanitized.error_message = self.sanitize(result.error_message)
            return sanitized
                
        except Exception as e:
            logger.error(f"Error sanitizing command output: {e}")
            return result

    def is_safe_to_log(self, text: str) -> bool:
        """
        Check if text contains any sensitive patterns.
        
        Args:
            text (str): The text to check.
            
        Returns:
            bool: True if safe (no sensitive patterns), False otherwise.
        """
        if not text or not isinstance(text, str):
            return True
            
        try:
            for pattern, _ in self.patterns:
                if pattern.search(text):
                    return False
                    
            if ACCOUNT_ID_PATTERN.search(text):
                return False
                
        except Exception as e:
            logger.error(f"Error checking if safe to log: {e}")
            return False
            
        return True
