"""Parsers turn raw log files into `AuthEvent` objects.

To support a new log source, add a module here that yields `AuthEvent`s -
detectors and reporters need no changes.
"""

from authwatch.parsers.evtx_parser import EvtxParseError, ParseStats, iter_evtx, parse_event_xml

__all__ = ["EvtxParseError", "ParseStats", "iter_evtx", "parse_event_xml"]
