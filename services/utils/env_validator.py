"""
Environment variable validation for TENET AI services.

Services call ``validate_env_vars()`` once at startup so that a missing or
malformed setting fails fast with one readable error, instead of a bare
``ValueError`` or ``TypeError`` from somewhere deep in the code.
"""

import math
import os
from collections.abc import Callable, Mapping
from typing import Any

Converter = Callable[[str], Any]


class EnvValidationError(ValueError):
    """Raised when one or more environment variables are missing or invalid.

    Attributes:
        missing: Names of required variables that are unset or empty.
        invalid: Map of variable name to a short reason why its value was rejected.
    """

    def __init__(self, missing: list[str], invalid: dict[str, str]) -> None:
        self.missing = missing
        self.invalid = invalid

        lines = ["Invalid environment configuration:"]
        if missing:
            lines.append(f"  missing required variables: {', '.join(missing)}")
        for name, reason in invalid.items():
            lines.append(f"  {name}: {reason}")
        super().__init__("\n".join(lines))


class SafeValueError(ValueError):
    """A converter error whose message never contains the raw value.

    Only this type's message is shown in startup errors. Any other ``ValueError``
    from a custom converter is reported as "invalid value", because its message
    may include the raw (possibly secret) input.
    """


def port(value: str) -> int:
    """Convert a string to a TCP port number.

    Args:
        value: Raw value, e.g. ``"6379"``.

    Returns:
        The port as an int.

    Raises:
        ValueError: If the value is not an integer between 1 and 65535.
    """
    number = int(value)
    if not 1 <= number <= 65535:
        raise SafeValueError(f"port must be between 1 and 65535, got {number}")
    return number


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise SafeValueError("must be a finite number")
    return number


def positive_float(value: str) -> float:
    """Convert to a finite float greater than zero (e.g. a timeout)."""
    number = _finite_float(value)
    if number <= 0:
        raise SafeValueError("must be greater than 0")
    return number


def non_negative_float(value: str) -> float:
    """Convert to a finite float of at least zero."""
    number = _finite_float(value)
    if number < 0:
        raise SafeValueError("must be 0 or greater")
    return number


def probability(value: str) -> float:
    """Convert to a finite float between 0 and 1 inclusive."""
    number = _finite_float(value)
    if not 0 <= number <= 1:
        raise SafeValueError("must be between 0 and 1")
    return number


def positive_int(value: str) -> int:
    """Convert to an integer of at least 1 (e.g. a failure count)."""
    number = int(value)
    if number < 1:
        raise SafeValueError("must be at least 1")
    return number


# Friendly names for the built-in converters, used in error messages.
_EXPECTED = {
    int: "an integer",
    float: "a number",
    port: "a port number (1-65535)",
    positive_float: "a number greater than 0",
    non_negative_float: "a number of 0 or more",
    probability: "a number between 0 and 1",
    positive_int: "an integer of 1 or more",
}


def validate_env_vars(
    required_vars: list[str],
    optional_vars: Mapping[str, Any] | None = None,
    types: Mapping[str, Converter] | None = None,
) -> dict[str, Any]:
    """Read and validate environment variables, reporting every problem at once.

    Args:
        required_vars: Names that must be set to a non-empty value.
        optional_vars: Map of name to default value, used when the variable is unset.
            Defaults are returned as given and are not passed through ``types``.
        types: Map of name to a converter applied to the raw string, e.g.
            ``{"REDIS_PORT": port, "REDIS_TIMEOUT_S": float}``. Variables without
            a converter are returned as strings.

    Returns:
        Dict of variable name to its validated (and converted) value, covering
        every name in ``required_vars`` and ``optional_vars``.

    Raises:
        EnvValidationError: If any required variable is missing or any value
            fails its converter. The message lists all problems, not just the first.

    Examples:
        >>> from services.utils.env_validator import port, validate_env_vars
        >>> config = validate_env_vars(
        ...     ["API_KEY"],
        ...     optional_vars={"REDIS_HOST": "localhost", "REDIS_PORT": 6379},
        ...     types={"REDIS_PORT": port},
        ... )
    """
    optional_vars = optional_vars or {}
    types = types or {}

    values: dict[str, Any] = {}
    missing: list[str] = []
    invalid: dict[str, str] = {}

    for name in required_vars:
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            missing.append(name)
            continue
        _convert(name, raw, types.get(name), values, invalid)

    for name, default in optional_vars.items():
        if name in required_vars:
            continue
        raw = os.environ.get(name)
        if raw is None:
            values[name] = default
            continue
        _convert(name, raw, types.get(name), values, invalid)

    if missing or invalid:
        raise EnvValidationError(missing, invalid)
    return values


def _convert(
    name: str,
    raw: str,
    converter: Converter | None,
    values: dict[str, Any],
    invalid: dict[str, str],
) -> None:
    """Convert one raw value, storing the result or the reason it failed."""
    if converter is None:
        values[name] = raw
        return

    try:
        values[name] = converter(raw.strip())
    except (TypeError, ValueError) as exc:
        expected = _EXPECTED.get(converter)
        if expected:
            invalid[name] = f"expected {expected}, got {raw!r}"
        else:
            # Only SafeValueError text is shown; other messages may echo a secret.
            invalid[name] = str(exc) if isinstance(exc, SafeValueError) else "invalid value"
