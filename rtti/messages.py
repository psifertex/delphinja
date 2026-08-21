"""Names for the message ids stored in Delphi dynamic-method tables.

A dynamic method table entry is a SmallInt.  Delphi assigns plain (non-message)
dynamic methods negative indices counting down from -1, while a `message`
directive stores the message id itself.  Read as unsigned 16-bit:

    0x0000..0x7FFF   Windows message (WM_*, and WM_USER/WM_APP ranges)
    0xB000..0xBBFF   VCL component message, CM_BASE + n
    0xBC00..0xBFFF   VCL control notification, CN_BASE + the WM_ it wraps
    anything else    a negative dynamic-method index, not a message

Edit the tables below freely -- every name applied by the plugin is also
written into a comment together with the raw id, so a wrong guess here is
always visible and never destroys information.
"""

CM_BASE = 0xB000
CN_BASE = 0xBC00

WM = {
    0x0000: "WM_NULL", 0x0001: "WM_CREATE", 0x0002: "WM_DESTROY",
    0x0003: "WM_MOVE", 0x0005: "WM_SIZE", 0x0006: "WM_ACTIVATE",
    0x0007: "WM_SETFOCUS", 0x0008: "WM_KILLFOCUS", 0x000A: "WM_ENABLE",
    0x000B: "WM_SETREDRAW", 0x000C: "WM_SETTEXT", 0x000D: "WM_GETTEXT",
    0x000E: "WM_GETTEXTLENGTH", 0x000F: "WM_PAINT", 0x0010: "WM_CLOSE",
    0x0011: "WM_QUERYENDSESSION", 0x0012: "WM_QUIT", 0x0013: "WM_QUERYOPEN",
    0x0014: "WM_ERASEBKGND", 0x0015: "WM_SYSCOLORCHANGE",
    0x0016: "WM_ENDSESSION", 0x0018: "WM_SHOWWINDOW",
    0x001A: "WM_WININICHANGE", 0x001B: "WM_DEVMODECHANGE",
    0x001C: "WM_ACTIVATEAPP", 0x001D: "WM_FONTCHANGE",
    0x001E: "WM_TIMECHANGE", 0x001F: "WM_CANCELMODE", 0x0020: "WM_SETCURSOR",
    0x0021: "WM_MOUSEACTIVATE", 0x0022: "WM_CHILDACTIVATE",
    0x0023: "WM_QUEUESYNC", 0x0024: "WM_GETMINMAXINFO",
    0x0026: "WM_PAINTICON", 0x0027: "WM_ICONERASEBKGND",
    0x0028: "WM_NEXTDLGCTL", 0x002A: "WM_SPOOLERSTATUS",
    0x002B: "WM_DRAWITEM", 0x002C: "WM_MEASUREITEM", 0x002D: "WM_DELETEITEM",
    0x002E: "WM_VKEYTOITEM", 0x002F: "WM_CHARTOITEM", 0x0030: "WM_SETFONT",
    0x0031: "WM_GETFONT", 0x0032: "WM_SETHOTKEY", 0x0033: "WM_GETHOTKEY",
    0x0037: "WM_QUERYDRAGICON", 0x0039: "WM_COMPAREITEM",
    0x0041: "WM_COMPACTING", 0x0046: "WM_WINDOWPOSCHANGING",
    0x0047: "WM_WINDOWPOSCHANGED", 0x0048: "WM_POWER",
    0x004A: "WM_COPYDATA", 0x004B: "WM_CANCELJOURNAL", 0x004E: "WM_NOTIFY",
    0x0050: "WM_INPUTLANGCHANGEREQUEST", 0x0051: "WM_INPUTLANGCHANGE",
    0x0052: "WM_TCARD", 0x0053: "WM_HELP", 0x0054: "WM_USERCHANGED",
    0x0055: "WM_NOTIFYFORMAT", 0x007B: "WM_CONTEXTMENU",
    0x007C: "WM_STYLECHANGING", 0x007D: "WM_STYLECHANGED",
    0x007E: "WM_DISPLAYCHANGE", 0x007F: "WM_GETICON", 0x0080: "WM_SETICON",
    0x0081: "WM_NCCREATE", 0x0082: "WM_NCDESTROY", 0x0083: "WM_NCCALCSIZE",
    0x0084: "WM_NCHITTEST", 0x0085: "WM_NCPAINT", 0x0086: "WM_NCACTIVATE",
    0x0087: "WM_GETDLGCODE", 0x00A0: "WM_NCMOUSEMOVE",
    0x00A1: "WM_NCLBUTTONDOWN", 0x00A2: "WM_NCLBUTTONUP",
    0x00A3: "WM_NCLBUTTONDBLCLK", 0x00A4: "WM_NCRBUTTONDOWN",
    0x00A5: "WM_NCRBUTTONUP", 0x00A6: "WM_NCRBUTTONDBLCLK",
    0x00A7: "WM_NCMBUTTONDOWN", 0x00A8: "WM_NCMBUTTONUP",
    0x00A9: "WM_NCMBUTTONDBLCLK", 0x0100: "WM_KEYDOWN", 0x0101: "WM_KEYUP",
    0x0102: "WM_CHAR", 0x0103: "WM_DEADCHAR", 0x0104: "WM_SYSKEYDOWN",
    0x0105: "WM_SYSKEYUP", 0x0106: "WM_SYSCHAR", 0x0107: "WM_SYSDEADCHAR",
    0x0108: "WM_KEYLAST", 0x010D: "WM_IME_STARTCOMPOSITION",
    0x010E: "WM_IME_ENDCOMPOSITION", 0x010F: "WM_IME_COMPOSITION",
    0x0110: "WM_INITDIALOG", 0x0111: "WM_COMMAND", 0x0112: "WM_SYSCOMMAND",
    0x0113: "WM_TIMER", 0x0114: "WM_HSCROLL", 0x0115: "WM_VSCROLL",
    0x0116: "WM_INITMENU", 0x0117: "WM_INITMENUPOPUP",
    0x011F: "WM_MENUSELECT", 0x0120: "WM_MENUCHAR", 0x0121: "WM_ENTERIDLE",
    0x0132: "WM_CTLCOLORMSGBOX", 0x0133: "WM_CTLCOLOREDIT",
    0x0134: "WM_CTLCOLORLISTBOX", 0x0135: "WM_CTLCOLORBTN",
    0x0136: "WM_CTLCOLORDLG", 0x0137: "WM_CTLCOLORSCROLLBAR",
    0x0138: "WM_CTLCOLORSTATIC", 0x0200: "WM_MOUSEMOVE",
    0x0201: "WM_LBUTTONDOWN", 0x0202: "WM_LBUTTONUP",
    0x0203: "WM_LBUTTONDBLCLK", 0x0204: "WM_RBUTTONDOWN",
    0x0205: "WM_RBUTTONUP", 0x0206: "WM_RBUTTONDBLCLK",
    0x0207: "WM_MBUTTONDOWN", 0x0208: "WM_MBUTTONUP",
    0x0209: "WM_MBUTTONDBLCLK", 0x020A: "WM_MOUSEWHEEL",
    0x0210: "WM_PARENTNOTIFY", 0x0211: "WM_ENTERMENULOOP",
    0x0212: "WM_EXITMENULOOP", 0x0213: "WM_NEXTMENU", 0x0214: "WM_SIZING",
    0x0215: "WM_CAPTURECHANGED", 0x0216: "WM_MOVING",
    0x0218: "WM_POWERBROADCAST", 0x0219: "WM_DEVICECHANGE",
    0x0220: "WM_MDICREATE", 0x0221: "WM_MDIDESTROY", 0x0222: "WM_MDIACTIVATE",
    0x0223: "WM_MDIRESTORE", 0x0224: "WM_MDINEXT", 0x0225: "WM_MDIMAXIMIZE",
    0x0226: "WM_MDITILE", 0x0227: "WM_MDICASCADE", 0x0228: "WM_MDIICONARRANGE",
    0x0229: "WM_MDIGETACTIVE", 0x0230: "WM_MDISETMENU",
    0x0231: "WM_ENTERSIZEMOVE", 0x0232: "WM_EXITSIZEMOVE",
    0x0233: "WM_DROPFILES", 0x0234: "WM_MDIREFRESHMENU",
    0x0300: "WM_CUT", 0x0301: "WM_COPY", 0x0302: "WM_PASTE",
    0x0303: "WM_CLEAR", 0x0304: "WM_UNDO", 0x0305: "WM_RENDERFORMAT",
    0x0306: "WM_RENDERALLFORMATS", 0x0307: "WM_DESTROYCLIPBOARD",
    0x0308: "WM_DRAWCLIPBOARD", 0x0309: "WM_PAINTCLIPBOARD",
    0x030A: "WM_VSCROLLCLIPBOARD", 0x030B: "WM_SIZECLIPBOARD",
    0x030C: "WM_ASKCBFORMATNAME", 0x030D: "WM_CHANGECBCHAIN",
    0x030E: "WM_HSCROLLCLIPBOARD", 0x030F: "WM_QUERYNEWPALETTE",
    0x0310: "WM_PALETTEISCHANGING", 0x0311: "WM_PALETTECHANGED",
    0x0312: "WM_HOTKEY", 0x0317: "WM_PRINT", 0x0318: "WM_PRINTCLIENT",
    0x0400: "WM_USER", 0x8000: "WM_APP",
}

# CM_BASE + n, from Controls.pas.  Only the range this plugin is confident
# about is listed; anything past the end is reported as CM_BASE_<n>.
CM = [
    "CM_ACTIVATE", "CM_DEACTIVATE", "CM_GOTFOCUS", "CM_LOSTFOCUS",
    "CM_CANCELMODE", "CM_DIALOGKEY", "CM_DIALOGCHAR", "CM_FOCUSCHANGED",
    "CM_PARENTFONTCHANGED", "CM_PARENTCOLORCHANGED", "CM_HITTEST",
    "CM_VISIBLECHANGED", "CM_ENABLEDCHANGED", "CM_COLORCHANGED",
    "CM_FONTCHANGED", "CM_CURSORCHANGED", "CM_CTL3DCHANGED",
    "CM_PARENTCTL3DCHANGED", "CM_TEXTCHANGED", "CM_MOUSEENTER",
    "CM_MOUSELEAVE", "CM_MENUCHANGED", "CM_APPKEYDOWN", "CM_APPSYSCOMMAND",
    "CM_BUTTONPRESSED", "CM_SHOWINGCHANGED", "CM_ENTER", "CM_EXIT",
    "CM_DESIGNHITTEST", "CM_ICONCHANGED", "CM_WANTSPECIALKEY",
    "CM_INVOKEHELP", "CM_WINDOWHOOK", "CM_RELEASE", "CM_SHOWHINTCHANGED",
    "CM_PARENTSHOWHINTCHANGED", "CM_SYSCOLORCHANGE", "CM_WININICHANGE",
    "CM_FONTCHANGE", "CM_TIMECHANGE", "CM_TABSTOPCHANGED", "CM_UIACTIVATE",
    "CM_UIDEACTIVATE",
]
# Stops at CM_BASE + 42 deliberately. Everything up to here was checked
# against real binaries -- TCustomEdit's handlers at 14/16/18/26 decode as
# CM_FONTCHANGED / CM_CTL3DCHANGED / CM_TEXTCHANGED / CM_ENTER, which is
# exactly what TCustomEdit declares. Beyond 42 an earlier version of this
# table was wrong: it listed CM_DOCKCLIENT at 43, where Controls.pas has
# CM_DOCWINDOWACTIVATE and puts CM_DOCKCLIENT at 56. Rather than swap one
# unverified table for another, ids past the checked range are reported as
# CM_BASE_<n> until each name is confirmed against a source.

MSG_KIND_MESSAGE = "message"
MSG_KIND_INDEX = "index"


def classify(raw_id):
    """(kind, name) for a raw dynamic-table SmallInt.

    kind is "message" (name is the WM_/CM_/CN_ constant) or "index" (a plain
    dynamic method, name is DynMethod_<n>).
    """
    u = raw_id & 0xFFFF
    if u <= 0x7FFF:
        return MSG_KIND_MESSAGE, WM.get(u) or _user_msg(u)
    if CM_BASE <= u < CN_BASE:
        n = u - CM_BASE
        return MSG_KIND_MESSAGE, CM[n] if n < len(CM) else "CM_BASE_%d" % n
    if CN_BASE <= u < CN_BASE + 0x400:
        wm = WM.get(u - CN_BASE)
        return MSG_KIND_MESSAGE, "CN_" + wm[3:] if wm else "CN_%04X" % (u - CN_BASE)
    return MSG_KIND_INDEX, "DynMethod_m%d" % (0x10000 - u)


def _user_msg(u):
    if u >= 0x8000:
        return "WM_APP_%d" % (u - 0x8000)
    if u >= 0x0400:
        return "WM_USER_%d" % (u - 0x0400)
    return "WM_%04X" % u


def handler_name(raw_id):
    """Identifier fragment used when naming the handler function.

    The message constant is kept verbatim rather than re-camel-cased into the
    Delphi source spelling: CM_FONTCHANGED carries no record of where the word
    boundary was, and an invented CMFontchanged would be wrong in a way that
    is hard to notice.  The constant is unambiguous and greppable.
    """
    return classify(raw_id)[1]
