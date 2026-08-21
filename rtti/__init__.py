"""Delphi metadata decoding and application.

`parser` is a pure decoder with no Binary Ninja dependency, so it can be run
and tested against a raw file. `apply` turns what it finds into types, names
and data variables; `sinks` is the thin layer that decides where those land,
which is what lets one decoder serve both delivery mechanisms.
"""
