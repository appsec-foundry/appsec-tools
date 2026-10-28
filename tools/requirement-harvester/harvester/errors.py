class HarvestError(Exception):
    """Only controlled messages, never remote bodies or credential values."""

    code = 4


class ConfigError(HarvestError):
    code = 2


class AuthError(HarvestError):
    code = 3


class OutputError(HarvestError):
    code = 5
