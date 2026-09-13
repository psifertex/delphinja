# Delphi MAP debug information

Delphinja registers a `Delphi MAP` Binary Ninja `DebugInfoParser` for detailed
text MAP files. Set a MAP file as the binary's external debug file and enable
debug-info analysis. This path is independent of the RTTI workflow/debug-info
setting: the MAP is explicit input, while the RTTI parser discovers metadata
inside the executable.

The pure parser retains the section table, `Publics by Value`, source-line
records, and entry point. The Binary Ninja API currently used here has no
source-line contribution entry point, so only public symbols in executable
sections are contributed as functions. Data publics and parsed line records
remain deliberately unapplied rather than being misrepresented.

## Safety and address mapping

- Input is capped at 64 MiB, lines at 64 KiB, names at 4 KiB, and retained
  records at one million. NUL-containing and structurally invalid input fails
  closed.
- `Publics by Name` is ignored because it duplicates `Publics by Value`.
- A segment number is resolved through the MAP section name to the matching
  BinaryView section. This preserves correctness for rebased views and for
  `.text`, `.itext`, and data sections whose offsets have different origins.
  The link-time section address is only a validated fallback.
- Only publics landing in executable BinaryView segments become functions.
  Multiple different names at one address are left unresolved.
- Existing user symbols and user-named functions are never overwritten.

## Evidence and fixture

Embarcadero documents MAP files as plain text containing global symbols,
source files, and source line numbers, with the section and value-sorted public
tables used here:

- https://docwiki.embarcadero.com/RADStudio/Florence/en/Map_Debug_File
- https://docwiki.embarcadero.com/RADStudio/Athens/en/Detailed-Segments_Map_File
- https://docwiki.embarcadero.com/RADStudio/Sydney/en/Debug_information_%28Delphi%29

The parser was cross-checked against the mature JCL parser and actual Delphi
Win32/Win64 XE2 maps. The latter demonstrate that Win64 still uses
segment-relative offsets, so address width must not be used to infer the
architecture:

- https://github.com/project-jedi/jcl/blob/master/jcl/source/windows/JclDebug.pas
- https://github.com/Eden5Wu/dbxoodbc/blob/c314e1a4e81f63dd57390fd7cd1d2a4bfab30cb2/lib/delphi-2012(16)XE2/win32/dbxoodbc160.map
- https://github.com/Eden5Wu/dbxoodbc/blob/c314e1a4e81f63dd57390fd7cd1d2a4bfab30cb2/lib/delphi-2012(16)XE2/win64/dbxoodbc160.map

The isolated tests use an unmodified, BSD-2-Clause Delphi-generated Compiler
Explorer fixture. Its pinned provenance and license are in
`tests/fixtures/README.md`.
