"""Exception hierarchy used across ReconLens."""


class ReconLensError(Exception):
    """Base class for all expected ReconLens errors."""


class InvalidTargetError(ReconLensError, ValueError):
    """The user supplied something that is not a valid domain or username."""


class TargetNotFoundError(ReconLensError):
    """The domain does not exist in DNS (NXDOMAIN)."""


class UnknownModuleError(ReconLensError, KeyError):
    """A module name passed on the command line is not registered."""


class ModuleError(ReconLensError):
    """A module could not complete; the message is shown to the user as-is."""
