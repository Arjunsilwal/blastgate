"""Policy engine for blastgate egress control.

Pure logic: No network, no subprocess, no filesystem beyond reading allowlists, no model calls.
"""

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set
import yaml


class PolicyError(Exception):
    """Base error for policy schema violations or configuration errors."""
    pass


class InvalidHostError(PolicyError):
    """Raised when a hostname fails syntactic validation or is an IP address."""
    pass


@dataclass(frozen=True)
class PolicyDecision:
    """Explicit result of a policy evaluation."""
    allowed: bool
    ecosystem: str
    host: str
    rule: Optional[str]
    reason: str
    matched_tier: Optional[str]


@dataclass(frozen=True)
class ExactRule:
    host: str
    reason: str


@dataclass(frozen=True)
class WildcardRule:
    pattern: str
    suffix: str
    reason: str


@dataclass(frozen=True)
class ConditionalRule:
    host: str
    condition: str
    reason: str


_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


class Policy:
    """Pure policy engine for ecosystem network egress evaluation."""

    def __init__(
        self,
        ecosystem: str,
        exact_rules: Sequence[ExactRule],
        wildcard_rules: Sequence[WildcardRule],
        conditional_rules: Sequence[ConditionalRule],
    ) -> None:
        self.ecosystem = ecosystem
        self.exact_rules = list(exact_rules)
        self.wildcard_rules = list(wildcard_rules)
        self.conditional_rules = list(conditional_rules)

        self._exact_map: Dict[str, ExactRule] = {r.host: r for r in self.exact_rules}
        self._conditional_map: Dict[str, ConditionalRule] = {r.host: r for r in self.conditional_rules}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        """Parse and validate policy data from a dictionary."""
        if not isinstance(data, dict):
            raise PolicyError("Policy definition must be a dictionary")

        ecosystem = data.get("ecosystem")
        if not ecosystem or not isinstance(ecosystem, str):
            raise PolicyError("Policy missing required 'ecosystem' string")

        for key in ("exact", "wildcard", "conditional"):
            if key not in data or not isinstance(data[key], list):
                raise PolicyError(f"Policy missing required list section '{key}'")

        exact_rules: List[ExactRule] = []
        for item in data["exact"]:
            if not isinstance(item, dict) or "host" not in item or "reason" not in item:
                raise PolicyError("Exact rule must contain 'host' and 'reason'")
            host = cls.normalize_host(item["host"])
            exact_rules.append(ExactRule(host=host, reason=str(item["reason"])))

        wildcard_rules: List[WildcardRule] = []
        for item in data["wildcard"]:
            if not isinstance(item, dict) or "pattern" not in item or "reason" not in item:
                raise PolicyError("Wildcard rule must contain 'pattern' and 'reason'")
            pattern = str(item["pattern"]).strip().lower()
            if not pattern.startswith("*.") or len(pattern) <= 2:
                raise PolicyError(f"Wildcard pattern '{pattern}' must start with '*.' followed by domain")
            suffix_host = cls.normalize_host(pattern[2:])
            wildcard_rules.append(
                WildcardRule(
                    pattern=f"*.{suffix_host}",
                    suffix=f".{suffix_host}",
                    reason=str(item["reason"]),
                )
            )

        conditional_rules: List[ConditionalRule] = []
        for item in data["conditional"]:
            if not isinstance(item, dict) or "host" not in item or "condition" not in item or "reason" not in item:
                raise PolicyError("Conditional rule must contain 'host', 'condition', and 'reason'")
            host = cls.normalize_host(item["host"])
            conditional_rules.append(
                ConditionalRule(
                    host=host,
                    condition=str(item["condition"]),
                    reason=str(item["reason"]),
                )
            )

        return cls(
            ecosystem=ecosystem,
            exact_rules=exact_rules,
            wildcard_rules=wildcard_rules,
            conditional_rules=conditional_rules,
        )

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        """Load policy from a YAML file."""
        if not path.is_file():
            raise PolicyError(f"Policy file not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise PolicyError(f"Failed to parse policy YAML at {path}: {e}") from e
        return cls.from_dict(data)

    @staticmethod
    def normalize_host(raw_host: str) -> str:
        """
        Normalize and validate a host string:
        - Rejects empty, whitespace, control characters, or injection characters
        - Strips scheme if passed (rejects paths/queries)
        - Strips and validates port numbers (1-65535)
        - Normalizes to lowercase
        - Strips single trailing dot (DNS root)
        - Rejects raw IP addresses (IPv4, IPv6, alternate encodings)
        - Validates DNS label syntax (RFC 1123)
        """
        if not isinstance(raw_host, str):
            raise InvalidHostError("Hostname must be a string")

        host = raw_host.strip()
        if not host:
            raise InvalidHostError("Hostname cannot be empty")

        # Reject control characters, whitespace, null bytes
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in host):
            raise InvalidHostError("Hostname contains invalid whitespace or control characters")

        # Reject URI injection characters
        for char in ("/", "?", "#", "@", ";", "|", "&", "$", "\\", "`"):
            if char in host:
                raise InvalidHostError(f"Hostname contains invalid character: {char!r}")

        # Strip standard scheme if erroneously passed (e.g. https://domain)
        if "://" in host:
            scheme, remainder = host.split("://", 1)
            if scheme.lower() not in ("http", "https"):
                raise InvalidHostError(f"Unsupported scheme: {scheme}")
            host = remainder

        # Port parsing & extraction
        if host.startswith("["):
            # Bracketed IPv6 notation, e.g. [::1] or [::1]:80
            closing_idx = host.find("]")
            if closing_idx == -1:
                raise InvalidHostError("Unclosed IPv6 bracket")
            ip_part = host[1:closing_idx]
            port_part = host[closing_idx + 1:]
            if port_part:
                if not port_part.startswith(":"):
                    raise InvalidHostError(f"Invalid characters after bracket: {port_part}")
                port_str = port_part[1:]
                if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
                    raise InvalidHostError(f"Invalid port: {port_str}")
            # Raw IPv6 address is not an allowed domain host
            raise InvalidHostError("Raw IPv6 addresses are not allowed as domain hosts")
        elif ":" in host:
            parts = host.split(":")
            if len(parts) > 2:
                # Unbracketed IPv6 or malformed host
                raise InvalidHostError("Raw IPv6 addresses or multiple colons are not allowed")
            host_part, port_str = parts
            if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
                raise InvalidHostError(f"Invalid port number: {port_str!r}")
            host = host_part

        host = host.lower()

        # Handle trailing dots (DNS root notation)
        if host.endswith("..") or host.startswith("."):
            raise InvalidHostError("Invalid dot placement in hostname")
        if host.endswith("."):
            host = host[:-1]

        if not host:
            raise InvalidHostError("Hostname is empty after normalization")

        # Check for raw IPv4 / IPv6 addresses
        try:
            ipaddress.ip_address(host)
            raise InvalidHostError(f"Raw IP addresses are not allowed: {host}")
        except ValueError:
            pass

        # Check for integer decimal IP encoding (e.g. 2130706433)
        if host.isdigit():
            try:
                ipaddress.ip_address(int(host))
                raise InvalidHostError(f"Raw integer IP addresses are not allowed: {host}")
            except (ValueError, OverflowError):
                pass

        # Check for hex/octal IP formats (e.g. 0x7f.1, 0177.0.0.1)
        if any(label.startswith("0x") for label in host.split(".")):
            raise InvalidHostError(f"Alternative hex IP encodings are not allowed: {host}")

        # Validate DNS label syntax (RFC 1123)
        if len(host) > 253:
            raise InvalidHostError("Hostname exceeds maximum length of 253 characters")

        labels = host.split(".")
        for label in labels:
            if not label or len(label) > 63:
                raise InvalidHostError(f"Invalid label length in hostname: {label!r}")
            if not _HOSTNAME_LABEL_RE.match(label):
                raise InvalidHostError(f"Invalid characters in DNS label: {label!r}")

        return host

    def evaluate(
        self,
        raw_host: str,
        enabled_conditions: Optional[Set[str]] = None,
    ) -> PolicyDecision:
        """
        Evaluate a target host against the ecosystem allowlist.
        Returns a PolicyDecision recording allow/deny status and matching rule.
        """
        try:
            normalized = self.normalize_host(raw_host)
        except InvalidHostError as e:
            return PolicyDecision(
                allowed=False,
                ecosystem=self.ecosystem,
                host=raw_host,
                rule=None,
                reason=f"invalid hostname: {e}",
                matched_tier=None,
            )

        # 1. Exact match tier
        if normalized in self._exact_map:
            rule = self._exact_map[normalized]
            return PolicyDecision(
                allowed=True,
                ecosystem=self.ecosystem,
                host=normalized,
                rule=f"exact:{rule.host}",
                reason=rule.reason,
                matched_tier="exact",
            )

        # 2. Wildcard suffix match tier
        for wrule in self.wildcard_rules:
            if normalized.endswith(wrule.suffix):
                # Ensure it is a strict subdomain (has a prefix before the suffix)
                prefix = normalized[: -len(wrule.suffix)]
                if prefix and not prefix.endswith("."):
                    return PolicyDecision(
                        allowed=True,
                        ecosystem=self.ecosystem,
                        host=normalized,
                        rule=f"wildcard:{wrule.pattern}",
                        reason=wrule.reason,
                        matched_tier="wildcard",
                    )

        # 3. Conditional match tier
        if normalized in self._conditional_map:
            crule = self._conditional_map[normalized]
            active_conditions = enabled_conditions or set()
            if crule.condition in active_conditions:
                return PolicyDecision(
                    allowed=True,
                    ecosystem=self.ecosystem,
                    host=normalized,
                    rule=f"conditional:{crule.host}",
                    reason=crule.reason,
                    matched_tier="conditional",
                )
            return PolicyDecision(
                allowed=False,
                ecosystem=self.ecosystem,
                host=normalized,
                rule=None,
                reason=f"conditional host requires condition '{crule.condition}': {crule.reason}",
                matched_tier="conditional",
            )

        # 4. Default Deny
        return PolicyDecision(
            allowed=False,
            ecosystem=self.ecosystem,
            host=normalized,
            rule=None,
            reason="default deny: host not in allowlist",
            matched_tier=None,
        )


def _get_default_allowlists_dir() -> Path:
    """Allowlists ship inside the package.

    They used to live at the repository root, which worked in a checkout and
    not at all once installed: the wheel contained the modules and nothing
    else, so `pip install blastgate` produced something that could not load a
    single policy. Keeping them in the package means the source tree and an
    installed copy resolve the same path.
    """
    return Path(__file__).resolve().parent / "allowlists"


def load_policy(ecosystem: str, allowlists_dir: Optional[Path] = None) -> Policy:
    """Load policy for the specified ecosystem (e.g. npm, pypi, cargo)."""
    base_dir = allowlists_dir if allowlists_dir is not None else _get_default_allowlists_dir()
    policy_file = base_dir / f"{ecosystem}.yaml"
    if not policy_file.is_file():
        raise PolicyError(f"No allowlist found for ecosystem '{ecosystem}' at {policy_file}")
    return Policy.from_file(policy_file)
