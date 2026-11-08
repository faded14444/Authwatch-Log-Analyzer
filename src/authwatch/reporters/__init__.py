"""Reporters present alerts: terminal table, machine-readable JSON and an HTML report."""

from authwatch.reporters.console import render
from authwatch.reporters.html_report import build_html, write_html
from authwatch.reporters.json_report import build_report, write_json

__all__ = ["build_html", "build_report", "render", "write_html", "write_json"]
