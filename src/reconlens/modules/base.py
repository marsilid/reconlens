"""Base class every reconnaissance module inherits from."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from reconlens.context import ScanContext
from reconlens.models import ModuleResult


class Module(ABC):
    """A self-contained check.

    Subclasses set the three class attributes and implement :meth:`run`, filling
    ``result.data`` with raw facts and ``result.findings`` with conclusions.
    Raise :class:`reconlens.errors.ModuleError` for a clean, user-facing failure.
    """

    name: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]

    @abstractmethod
    async def run(self, ctx: ScanContext, result: ModuleResult) -> None: ...
