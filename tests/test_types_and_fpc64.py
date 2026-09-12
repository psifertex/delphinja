import json
import unittest
from unittest import mock


class _Arch(object):
    def __init__(self, address_size):
        self.address_size = address_size


class _View(object):
    def __init__(self, address_size=4, view_type="PE"):
        self.arch = _Arch(address_size)
        self.view_type = view_type


class _TypeView(_View):
    def __init__(self):
        import binaryninja as bn

        self.arch = bn.Architecture["x86"]
        self.view_type = "PE"


class _Sink(object):
    def __init__(self):
        self.types = []

    def add_type(self, name, ty):
        self.types.append((name, ty))


class _Metadata(object):
    def __init__(self, units):
        self.bv = _TypeView()
        self.units = units
        self.vmts = {}

    def unit_for(self, record):
        unit = self.units.get(record.addr) or getattr(record, "unit", None)
        return (unit, "rtti") if unit else (None, None)

    def qualified(self, record):
        from delphinja.rtti.apply import DelphiMetadata

        return DelphiMetadata.qualified(self, record)


class TypeIdentityTests(unittest.TestCase):
    def _factory(self, units):
        from delphinja.rtti.apply import TypeFactory

        metadata = _Metadata(units)
        sink = _Sink()
        return metadata, sink, TypeFactory(metadata, sink=sink)

    def test_same_named_classes_in_different_units_get_distinct_references(self):
        from delphinja.rtti.parser import TypeInfo, Vmt

        metadata, sink, factory = self._factory({0x1000: "Alpha.Unit",
                                                 0x2000: "Beta.Unit"})
        first = Vmt(0x1000)
        first.name, first.instance_size = "TShared", 8
        second = Vmt(0x2000)
        second.name, second.instance_size = "TShared", 12
        metadata.vmts = {first.addr: first, second.addr: second}

        self.assertEqual(factory.class_type(first, {}),
                         "Alpha.Unit_TShared")
        self.assertEqual(factory.class_type(second, {}),
                         "Beta.Unit_TShared")

        first_info = TypeInfo(0x3000)
        first_info.kind = 7
        first_info.name = "TShared"
        first_info.data["ClassType"] = first.addr
        second_info = TypeInfo(0x4000)
        second_info.kind = 7
        second_info.name = "TShared"
        second_info.data["ClassType"] = second.addr

        self.assertEqual(str(factory.rtti_type(first_info).target.name),
                         "Alpha.Unit_TShared")
        self.assertEqual(str(factory.rtti_type(second_info).target.name),
                         "Beta.Unit_TShared")
        from delphinja.rtti.sinks import self_pointer
        self.assertEqual(str(self_pointer(metadata.bv, factory,
                                          second).target.name),
                         "Beta.Unit_TShared")
        self.assertEqual([name for name, _ty in sink.types],
                         ["Alpha.Unit_TShared", "Beta.Unit_TShared"])

    def test_same_named_records_in_different_units_get_distinct_definitions(self):
        from delphinja.rtti.parser import TypeInfo

        _metadata, sink, factory = self._factory({})
        first = TypeInfo(0x5000)
        first.kind, first.name, first.unit = 14, "TState", "One"
        first.data["Size"] = 8
        second = TypeInfo(0x6000)
        second.kind, second.name, second.unit = 14, "TState", "Two"
        second.data["Size"] = 16

        first_ref = factory.rtti_type(first)
        second_ref = factory.rtti_type(second)

        self.assertEqual(str(first_ref.name), "One_TState")
        self.assertEqual(str(second_ref.name), "Two_TState")
        self.assertEqual(first_ref.width, 8)
        self.assertEqual(second_ref.width, 16)
        self.assertEqual([name for name, _ty in sink.types],
                         ["One_TState", "Two_TState"])

    def test_unqualified_and_structural_type_names_stay_unchanged(self):
        from delphinja.rtti.parser import TypeInfo

        _metadata, sink, factory = self._factory({})
        anonymous = TypeInfo(0x7000)
        anonymous.kind, anonymous.name = 14, ".74"
        anonymous.data["Size"] = 4

        record = factory.record_type(anonymous)
        method = factory.method_type()

        self.assertEqual(str(record.name), "anon_74")
        self.assertEqual(str(method.name), "TMethod")
        self.assertEqual([name for name, _ty in sink.types],
                         ["anon_74", "TMethod"])


class FpcWin64Tests(unittest.TestCase):
    def test_shipped_win64_library_is_selected_from_fpc_evidence(self):
        from delphinja.integration import signatures

        view = _View(8)
        with mock.patch.object(signatures, "fpc_version",
                               return_value="3.2.2"):
            self.assertEqual(signatures.fpc_tags(view), ["3.2.2-win64"])
        self.assertIsNotNone(signatures.fpc_library("3.2.2-win64"))
        with mock.patch.object(signatures, "register",
                               return_value=["3.2.2-win64"]) as register:
            signatures.register_fpc(view, version="3.2.2")
        register.assert_called_once_with(["3.2.2-win64"], "Delphinja",
                                         kind="fpc")

    def test_x64_eligibility_requires_fpc_evidence(self):
        from delphinja.integration import debuginfo, workflow

        view = _View(8)
        with mock.patch.object(workflow.signatures, "fpc_version",
                               return_value=None), \
                mock.patch.object(debuginfo.signatures, "fpc_version",
                                  return_value=None), \
                mock.patch.object(workflow.A, "DelphiMetadata") as workflow_md, \
                mock.patch.object(debuginfo.A, "DelphiMetadata") as debug_md:
            self.assertFalse(workflow.probe(view))
            self.assertFalse(debuginfo.is_valid(view))
            workflow_md.assert_not_called()
            debug_md.assert_not_called()

        with mock.patch.object(workflow.signatures, "fpc_version",
                               return_value="3.2.2"), \
                mock.patch.object(debuginfo.signatures, "fpc_version",
                                  return_value="3.2.2"):
            self.assertTrue(workflow.probe(view))
            self.assertTrue(debuginfo.is_valid(view))

    def test_workflow_win64_recovery_registers_fpc_without_rtti_scan(self):
        from delphinja.integration import workflow

        context = mock.Mock(view=_View(8))
        with mock.patch.object(workflow.signatures, "fpc_version",
                               return_value="3.2.2"), \
                mock.patch.object(workflow.signatures,
                                  "register_fpc") as register, \
                mock.patch.object(workflow.A, "DelphiMetadata") as metadata:
            workflow._recover(context)

        register.assert_called_once_with(context.view, workflow.TAG,
                                         version="3.2.2")
        metadata.assert_not_called()

    def test_debug_info_win64_parse_registers_fpc_without_rtti_scan(self):
        from delphinja.integration import debuginfo

        view = _View(8)
        with mock.patch.object(debuginfo.signatures, "fpc_version",
                               return_value="3.2.2"), \
                mock.patch.object(debuginfo.signatures,
                                  "register_fpc") as register, \
                mock.patch.object(debuginfo.A, "DelphiMetadata") as metadata:
            result = debuginfo.parse_info(None, view, None, None)

        self.assertTrue(result)
        register.assert_called_once_with(view, debuginfo.TAG,
                                         version="3.2.2")
        metadata.assert_not_called()

    def test_registered_workflow_admits_win64_only_for_recovery(self):
        from delphinja.integration import workflow

        activities = []

        class FakeWorkflow(object):
            def clone(self):
                return self

            def register_activity(self, activity):
                activities.append(activity)

            def insert(self, *_args):
                pass

            def insert_after(self, *_args):
                pass

            def register(self):
                pass

        fake = FakeWorkflow()
        activity = lambda **kwargs: kwargs
        with mock.patch.object(workflow, "Workflow", return_value=fake), \
                mock.patch.object(workflow, "Activity", side_effect=activity):
            workflow.register()

        configs = {json.loads(item["configuration"])["name"]:
                   json.loads(item["configuration"]) for item in activities}
        recovery = configs[workflow.ACTIVITY]["eligibility"]["predicates"][0]
        cleanup = configs[workflow.CLEANUP]["eligibility"]["predicates"][0]
        self.assertEqual(recovery["value"],
                         ["windows-x86", "windows-x86_64"])
        self.assertEqual(cleanup["value"], ["windows-x86"])


if __name__ == "__main__":
    unittest.main()
