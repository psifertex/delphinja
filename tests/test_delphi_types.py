import unittest


class _KnowledgeBase(object):
    def __init__(self, records, modules=None):
        self.records = records
        self.modules = modules or []
        self.sections = {
            "types": (len(records), 0, 0),
            "modules": (len(self.modules), 0, 0),
        }

    def type_(self, index):
        return self.records[index]

    def module(self, index):
        return self.modules[index]


def _record(name, decl, module_id=1):
    return {"kind": ord("H"), "name": name, "decl": decl,
            "module_id": module_id}


class DelphiProceduralTypeTests(unittest.TestCase):
    def setUp(self):
        import binaryninja as bn

        self.bn = bn
        self.arch = bn.Architecture["x86"]

    def _map(self, records, modules=None):
        from tools.delphitypes import TypeMap

        view = type("View", (), {"arch": self.arch})()
        return TypeMap(view, kb=_KnowledgeBase(records, modules))

    def test_plain_function_alias_becomes_concrete_function_pointer(self):
        from binaryninja.enums import TypeClass

        types = self._map([_record(
            "TThreadFunc", "function(val Parameter:Pointer):Integer")])
        resolved = types.resolve("System.TThreadFunc")

        self.assertEqual(resolved.type_class, TypeClass.PointerTypeClass)
        self.assertEqual(resolved.target.type_class,
                         TypeClass.FunctionTypeClass)
        self.assertEqual(resolved.target.return_value.width, 4)
        self.assertEqual(resolved.target.calling_convention.name, "register")
        self.assertEqual(len(resolved.target.parameters), 1)
        self.assertEqual(resolved.target.parameters[0].name, "Parameter")
        self.assertEqual(resolved.target.parameters[0].type.type_class,
                         TypeClass.PointerTypeClass)

    def test_generated_callee_parameter_contains_function_pointer(self):
        from binaryninja.enums import TypeClass

        types = self._map([_record(
            "TThreadFunc", "function(val Parameter:Pointer):Integer")])
        proc = {
            "args": [{"type": "System.TThreadFunc", "tag": 0x21,
                      "name": "ThreadFunc"}],
            "typedef": "", "call_kind": 0,
        }

        callback = types.function_type(proc).parameters[0].type
        self.assertEqual(callback.type_class, TypeClass.PointerTypeClass)
        self.assertEqual(callback.target.type_class,
                         TypeClass.FunctionTypeClass)

    def test_no_argument_procedure_can_carry_an_explicit_convention(self):
        types = self._map([_record("TDone", "procedure stdcall")])

        target = types.resolve("TDone").target
        self.assertEqual(target.calling_convention.name, "stdcall")
        self.assertEqual(target.parameters, [])

    def test_safecall_callback_uses_hresult_and_hidden_result(self):
        types = self._map([_record(
            "TGetter", "function(val Context:Pointer):Integer safecall")])

        target = types.resolve("TGetter").target
        self.assertEqual(target.calling_convention.name, "stdcall")
        self.assertEqual(target.return_value.width, 4)
        self.assertEqual([p.name for p in target.parameters],
                         ["Context", "Result"])
        self.assertEqual(target.parameters[1].type.target.width, 4)

    def test_explicit_convention_and_reference_parameter_are_preserved(self):
        from binaryninja.enums import TypeClass

        types = self._map([_record(
            "TCallback",
            "procedure(val Context:Pointer;var Result:Integer) stdcall")])
        target = types.resolve("TCallback").target

        self.assertEqual(target.return_value.type_class,
                         TypeClass.VoidTypeClass)
        self.assertEqual(target.calling_convention.name, "stdcall")
        self.assertEqual([p.name for p in target.parameters],
                         ["Context", "Result"])
        self.assertEqual(target.parameters[1].type.type_class,
                         TypeClass.PointerTypeClass)
        self.assertEqual(target.parameters[1].type.target.width, 4)

    def test_qualified_alias_wins_over_duplicate_bare_name(self):
        types = self._map(
            [_record("TCallback", "function:Integer", 1),
             _record("TCallback", "procedure", 2)],
            [{"id": 1, "name": "First"},
             {"id": 2, "name": "Second"}])

        self.assertEqual(str(types.resolve("First.TCallback").target),
                         "int32_t()")
        self.assertEqual(str(types.resolve("Second.TCallback").target),
                         "void()")
        self.assertEqual(str(types.resolve("TCallback").target), "int32_t()")

    def test_forwarding_alias_resolves_to_function_pointer(self):
        from binaryninja.enums import TypeClass

        types = self._map([
            _record("PFNLVCOMPARE",
                    "function(val Left:Integer;val Right:Integer):Integer "
                    "stdcall"),
            _record("TLVCompare", "PFNLVCOMPARE"),
        ])

        resolved = types.resolve("TLVCompare")
        self.assertEqual(resolved.type_class, TypeClass.PointerTypeClass)
        self.assertEqual(resolved.target.type_class,
                         TypeClass.FunctionTypeClass)
        self.assertEqual(resolved.target.calling_convention.name, "stdcall")

    def test_forwarding_alias_to_method_closure_remains_void_pointer(self):
        from binaryninja.enums import TypeClass

        types = self._map([
            _record("TOnManagerEvent",
                    "procedure(val Sender:System.TObject) of object"),
            _record("TOnCreateEvent", "TOnManagerEvent"),
        ])

        resolved = types.resolve("TOnCreateEvent")
        self.assertEqual(resolved.type_class, TypeClass.PointerTypeClass)
        self.assertEqual(resolved.target.type_class, TypeClass.VoidTypeClass)

    def test_forwarding_alias_cycle_falls_back_without_recursing(self):
        from binaryninja.enums import TypeClass

        types = self._map([
            _record("TFirst", "TSecond"),
            _record("TSecond", "TFirst"),
        ])

        resolved = types.resolve("TFirst")
        self.assertEqual(resolved.type_class, TypeClass.PointerTypeClass)
        self.assertEqual(resolved.target.type_class, TypeClass.VoidTypeClass)

    def test_method_closure_does_not_become_a_code_pointer(self):
        from binaryninja.enums import TypeClass

        types = self._map([_record(
            "TNotifyEvent",
            "procedure(val Sender:System.TObject) of object")])

        resolved = types.resolve("TNotifyEvent")
        self.assertEqual(resolved.type_class, TypeClass.PointerTypeClass)
        self.assertEqual(resolved.target.type_class, TypeClass.VoidTypeClass)


if __name__ == "__main__":
    unittest.main()
