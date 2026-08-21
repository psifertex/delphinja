"""Delphi support for Binary Ninja.

Delphi emits its published-symbol metadata -- class names, published method
and field names, message handler tables, property tables and full type
information -- straight into the code section. Linear sweep disassembles it
as garbage functions, and the names inside it never reach the analysis.

This plugin finds those tables, removes the bogus functions covering them,
turns the type records into real Binary Ninja types, and applies every name
the binary is carrying. It also demangles Borland symbols, and ships WARP
signature libraries built from the Delphi runtime so that the RTL and VCL
functions a binary statically links are named and typed too.

    rtti/          the decoder and everything that applies what it finds
    integration/   how that reaches Binary Ninja: workflow, debug info, WARP
    signatures/    the .warp libraries, registered at load
    tools/         how those libraries are built; not imported at load
"""

import json
import os

import binaryninja as bn
from binaryninja import BackgroundTaskThread, PluginCommand
from binaryninja.interaction import (get_choice_input, get_save_filename_input,
                                     show_message_box)

from . import demangler as D
from .integration import debuginfo as DI
from .integration import signatures as SIG
from .integration import workflow as WF
from .rtti import apply as A
from .rtti import parser as P

TAG = A.TAG


def _supported(bv, *_):
    return bv is not None and bv.arch is not None and bv.arch.address_size == 4


class _Task(BackgroundTaskThread):
    def __init__(self, bv, title, fn):
        BackgroundTaskThread.__init__(self, title, True)
        self.bv = bv
        self.fn = fn

    def run(self):
        try:
            self.fn(self)
        except Exception as exc:
            bn.log_error("%s failed: %s" % (self.progress or "task", exc), TAG)
            raise

    def scan(self, ranges=None):
        md = A.DelphiMetadata(self.bv)

        def progress(done, total):
            self.progress = "Delphi RTTI: scanning %d%%" % (100 * done // max(total, 1))
            return not self.cancelled

        md.scan(ranges, progress)
        return md


# ------------------------------------------------------------------ commands

def cmd_report(bv):
    def work(task):
        md = task.scan()
        lines = ["# Delphi metadata in %s" % os.path.basename(bv.file.filename),
                 "",
                 "%d classes (VMTs), %d RTTI type records."
                 % (len(md.vmts), len(md.typeinfos)),
                 "", "## Regions", "",
                 "| start | end | size | contents |",
                 "| --- | --- | --- | --- |"]
        spans = md.spans()
        for start, end in md.regions():
            inside = [lbl for s, e, lbl in spans if s >= start and e <= end]
            kinds = sorted({lbl.split(" ")[0] for lbl in inside})
            lines.append("| 0x%x | 0x%x | 0x%x | %d records: %s |"
                         % (start, end, end - start, len(inside),
                            ", ".join(kinds)))

        lines += ["", "## Units", ""]
        units = {}
        for ti in md.typeinfos.values():
            units.setdefault(ti.unit or "(none)", []).append(ti.name)
        for unit in sorted(units):
            lines.append("- **%s** - %d types: %s"
                         % (unit, len(units[unit]),
                            ", ".join(sorted(units[unit])[:12])))

        lines += ["", "## Classes", "",
                  "| VMT | class | size | ancestry | published |",
                  "| --- | --- | --- | --- | --- |"]
        props = {}
        for ti in md.typeinfos.values():
            if ti.kind == 7 and ti.data.get("ClassType"):
                props[ti.data["ClassType"]] = ti
        for vmt in sorted(md.vmts.values(), key=lambda v: v.name):
            ti = props.get(vmt.addr)
            published = "%d methods, %d fields, %d dynamic, %d props" % (
                len(vmt.methods), len(vmt.fields), len(vmt.dynamic),
                len(ti.props) if ti else 0)
            lines.append("| 0x%x | %s | %s | %s | %s |"
                         % (vmt.addr, vmt.name, vmt.instance_size,
                            " &lt; ".join(v.name for v in
                                          reversed(md.class_chain(vmt))),
                            published))
        bv.show_markdown_report("Delphi metadata", "\n".join(lines))

    _Task(bv, "Delphi RTTI: scanning", work).start()


def cmd_apply(bv):
    choice = get_choice_input(
        "What should be applied?", "Delphi RTTI",
        ["Everything (undefine, types, data, names)",
         "Types and names only (leave functions alone)",
         "Undefine metadata regions only"])
    if choice is None:
        return
    options = [
        {},
        {"undefine": False},
        {"types": False, "data_vars": False, "comments": False,
         "rename_functions": False, "self_param": False},
    ][choice]

    def work(task):
        md = task.scan()
        task.progress = "Delphi RTTI: applying"
        stats = A.Applier(md, options).run()
        bv.update_analysis()
        show_message_box(
            "Delphi RTTI",
            "\n".join("%s: %d" % (k.replace("_", " "), v)
                      for k, v in sorted(stats.items())))

    _Task(bv, "Delphi RTTI: applying", work).start()


def cmd_undefine_range(bv, addr, length):
    """Undefine every function overlapping the selected address range."""
    removed = A.undefine_functions(bv, [(addr, addr + max(length, 1))],
                                   lambda m: bn.log_info(m, TAG))
    bn.log_info("removed %d functions in 0x%x-0x%x"
                % (len(removed), addr, addr + length), TAG)
    bv.update_analysis()


def cmd_scan_range(bv, addr, length):
    """Scan just the selection, then apply everything found in it."""
    def work(task):
        md = task.scan([(addr, addr + max(length, 1))])
        A.Applier(md).run()
        bv.update_analysis()

    _Task(bv, "Delphi RTTI: applying to selection", work).start()


def cmd_describe(bv, addr):
    md = A.DelphiMetadata(bv)
    vmt = P.parse_vmt(md.reader, addr) or P.parse_vmt(md.reader,
                                                      addr + P.VMT_HEADER_SIZE)
    if vmt:
        md.scan([(vmt.header, vmt.vtable_end)])
        bn.log_info("\n" + A.describe_vmt(md, vmt), TAG)
        return
    ti = P.parse_typeinfo(md.reader, addr) or P.parse_typeinfo(md.reader,
                                                               addr + 4)
    if ti:
        bn.log_info("\n" + A.describe_typeinfo(md, ti), TAG)
        return
    bn.log_warn("no Delphi RTTI record at 0x%x" % addr, TAG)


def cmd_export(bv):
    path = get_save_filename_input("Export Delphi metadata", "json",
                                   "delphi_metadata.json")
    if not path:
        return
    path = path.decode() if isinstance(path, bytes) else path

    def work(task):
        md = task.scan()
        with open(path, "w") as fh:
            fh.write(A.to_json(md))
        bn.log_info("wrote %s" % path, TAG)

    _Task(bv, "Delphi RTTI: exporting", work).start()


_SETTINGS = bn.Settings()
_SETTINGS.register_group("delphi", "Delphi")
for _key, _title, _desc in (
        ("demangler", "Borland Demangler",
         "Demangle Borland/Delphi symbol names."),
        ("commands", "Delphi Plugin Commands",
         "Register the Delphi menu commands."),
        ("signatures", "Bundled WARP Signatures",
         "Register the Delphi runtime signature libraries that ship with "
         "this plugin. Turn off to use only the signatures installed in the "
         "user and install signature directories.")):
    _SETTINGS.register_setting("delphi.%s" % _key, json.dumps({
        "title": _title, "type": "boolean", "default": True,
        "description": _desc}))

# Registered separately and each behind its own switch, so a performance or
# correctness problem can be attributed to one or the other without editing
# code or moving files.
if _SETTINGS.get_bool("delphi.demangler"):
    D.register()

# Registered into WARP's container cache rather than copied into the user's
# signature directory, so the libraries travel with the plugin.
if _SETTINGS.get_bool("delphi.signatures"):
    SIG.register(TAG)
# One decoder, two delivery mechanisms. Both drive the same parser, scanner
# and type construction through sinks; they differ only in where the results
# are written and when. Switchable at runtime so the two can be compared on
# the same binary without swapping builds.
_SETTINGS.register_setting("delphi.mechanism", json.dumps({
    "title": "Delphi Metadata Recovery",
    "type": "string",
    "default": "workflow",
    "enum": ["workflow", "debugInfo", "off"],
    "enumDescriptions": [
        "Workflow activities: also removes sweep-created functions and sets "
        "comments, neither of which the debug info API can express.",
        "A DebugInfoParser: contributes types, data variables and names only.",
        "Recover nothing automatically; the commands still work.",
    ],
    "description": "How recovered Delphi metadata reaches the analysis."}))

_MECHANISM = _SETTINGS.get_string("delphi.mechanism")
if _MECHANISM == "workflow":
    WF.register()
elif _MECHANISM == "debugInfo":
    DI.register()

# A plugin command's is_valid callback is invoked by the UI whenever menus are
# built, so six registered commands means six Python calls -- each taking the
# GIL -- on a path the UI walks often. Gated so that cost can be isolated.
if _SETTINGS.get_bool("delphi.commands"):
    PluginCommand.register(
        "Delphi\\Report metadata regions",
        "Scan for Delphi RTTI/VMT metadata and show what was found",
        cmd_report, _supported)
    PluginCommand.register(
        "Delphi\\Apply metadata (types, symbols, names)",
        "Recover Delphi types, class layouts and published names",
        cmd_apply, _supported)
    PluginCommand.register(
        "Delphi\\Export metadata to JSON",
        "Write every parsed RTTI/VMT record to a JSON file",
        cmd_export, _supported)
    PluginCommand.register_for_range(
        "Delphi\\Undefine functions in selection",
        "Remove every function overlapping the selected range",
        cmd_undefine_range, _supported)
    PluginCommand.register_for_range(
        "Delphi\\Apply metadata in selection",
        "Scan and apply Delphi metadata found in the selected range only",
        cmd_scan_range, _supported)
    PluginCommand.register_for_address(
        "Delphi\\Describe record at address",
        "Decode the VMT or RTTI record here into the log",
        cmd_describe, _supported)
