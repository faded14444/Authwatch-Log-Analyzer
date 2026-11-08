"""Reporters present alerts: a terminal table and a machine-readable JSON file."""

from authwatch.reporters.console import render
from authwatch.reporters.json_report import build_report, write_json

__all__ = ["build_report", "render", "write_json"]
