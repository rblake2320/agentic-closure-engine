"""Offline closure kernel. No model or deployment integration."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agentic-closure-engine")
except PackageNotFoundError:  # source checkout without an installed distribution
    __version__ = "0.3.1+src"
