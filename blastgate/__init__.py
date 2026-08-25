"""Blastgate: Egress control and isolation for package managers."""

__version__ = "0.1.0"


class BlastgateError(Exception):
    """Base for every error blastgate raises deliberately.

    Exists so modules can define their own errors without importing each
    other's. Every one of these means blastgate stopped on purpose; nothing here
    is raised to signal that an install may proceed unprotected.
    """
