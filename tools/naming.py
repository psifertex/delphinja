"""One naming convention for everything this project emits.

Binary Ninja's QualifiedName uses `::`, and the Borland demangler in the
delphi_rtti plugin already produces `Unit::Class::Member`, so signatures use
the same form.  Names generated here end up on the public WARP server next to
libraries from every other toolchain, which is the other reason to look like
the rest of Binary Ninja rather than like Pascal source.
"""

SEP = "::"


def qualify(unit, cls, member):
    """Unit::Class::Member, dropping whichever parts are unknown."""
    parts = [p for p in (unit, cls, member) if p]
    return SEP.join(parts)


def split_kb_name(raw):
    """KB procedure names arrive as 'Proc', 'TClass.Method' or '@Helper'.

    The dot is Delphi's own class qualifier, not a namespace separator, so it
    becomes `::` too; compiler helpers like `@LStrCat` have no class part.
    """
    if "." in raw:
        cls, _, member = raw.partition(".")
        return cls, member
    return None, raw


def proc_name(unit, raw):
    cls, member = split_kb_name(raw)
    return qualify(unit, cls, member)
