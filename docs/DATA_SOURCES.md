# Debug and artifact data-source roadmap

There are two different source tracks. MAP/JDBG/TDS attach facts to one linked
binary. BPL/DCU/DCP are principally offline inputs for building signature
libraries. Treating the latter as executable sidecars would ignore linker
relocation, folding, and dead-code removal.

## Recommended order

1. **JCL JDBG / embedded JCLDEBUG** — next direct-import source. JDBG is a
   compact deployment form derived from MAP, not a richer format, but is often
   shipped when MAP is not. JCL defines the `JDBG` version-1 header, checksums,
   bounded tables, and delta/varint streams, plus sidecar and PE-resource forms.
   Implement with checked offsets/varints and module identity validation, then
   differential-test against the MAP importer and JCL scanner. Feasibility and
   testability: high.
   Source: https://github.com/project-jedi/jcl/blob/master/jcl/source/windows/JclDebug.pas

2. **TD32/TDS, Win32 first** — a separate debug-info parser for modules, code
   ranges, procedure/data symbols, and source lines. Embarcadero documents TDS
   as 32-bit-Windows output; do not present it as the Win64 successor. JCL's
   FB09/FB0A implementation is the best public structural oracle, but its type
   analysis is incomplete, so defer types. Require project-owned fixtures from
   at least two compiler generations, including mismatched and truncated
   sidecars. Feasibility: medium; fixture availability is the blocker.
   Sources: https://docwiki.embarcadero.com/RADStudio/Florence/en/TDS_Debug_File
   and https://github.com/project-jedi/jcl/blob/master/jcl/source/windows/JclTD32.pas

3. **BPL corpus expansion** — the lowest-risk signature improvement because
   the repository already parses and evaluates BPL exports. Add PE32+ handling,
   current-release local inputs, Win64 fixtures, and retain the existing
   reproducibility/correctness gates. BPL exports cover public interfaces, not
   private implementation routines. Inputs and redistribution of derived
   artifacts require an explicit Embarcadero-license assessment.
   Source: https://docwiki.embarcadero.com/RADStudio/Florence/en/Package_Files_Created_by_Compiling

4. **DCU core, then DCP** — DCUs offer the largest payoff (private
   declarations, types, code, fixups, and sometimes lines), but are
   reverse-engineered, compiler/platform-versioned formats. DCP is mainly a
   package header plus concatenated DCUs, so implementing it first adds little.
   Build a pure offline reader and generate WARP inputs; validate a matrix of
   project-owned units against DCU32INT and linked MAP/BPL output. Do not ship
   proprietary RTL DCU/DCP files. Feasibility: low-medium for a narrow
   prototype, low for complete multi-version support.
   Sources: https://docwiki.embarcadero.com/RADStudio/Athens/en/Delphi_Compiled_Unit_File_%28%2A.dcu%29,
   https://docwiki.embarcadero.com/RADStudio/Sydney/en/Delphi_Compiled_Package_File_%28%2A.dcp%29,
   and https://github.com/VoSs2o0o/dcu32int

5. **RSM reconnaissance for Win64** — current documentation says the Win64
   LLDB-based debugger consumes RSM information. Public layout and parser
   evidence was not established in this audit, so this is research, not an
   implementation promise.
   Source: https://docwiki.embarcadero.com/RADStudio/Florence/en/64-bit_IDE

JCL source is MPL-1.1; implement cleanly from documented structures/behavior
rather than porting code without honoring file-level obligations. DCU32INT's
parser license does not grant redistribution rights for proprietary compiler
artifacts. Fixture provenance and input rights are separate concerns.
