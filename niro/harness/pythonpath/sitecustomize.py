"""Harness-only Python startup settings."""

try:
    import email_validator

    email_validator.TEST_ENVIRONMENT = True
except Exception:
    pass
