import types
import unittest
from unittest import mock

import binaryninja as bn


def _value(value=None, constant=True):
    kind = (bn.RegisterValueType.ConstantPointerValue if constant else
            bn.RegisterValueType.UndeterminedValue)
    return types.SimpleNamespace(type=kind, value=value)


def _function_type(*parameter_types):
    parameters = [types.SimpleNamespace(type=ty) for ty in parameter_types]
    return types.SimpleNamespace(parameters=parameters)


def _callback_type():
    target = types.SimpleNamespace(
        type_class=bn.TypeClass.FunctionTypeClass)
    return types.SimpleNamespace(
        type_class=bn.TypeClass.PointerTypeClass, target=target)


def _plain_pointer_type():
    target = types.SimpleNamespace(type_class=bn.TypeClass.VoidTypeClass)
    return types.SimpleNamespace(
        type_class=bn.TypeClass.PointerTypeClass, target=target)


def _named_type(type_id):
    return types.SimpleNamespace(
        type_class=bn.TypeClass.NamedTypeReferenceClass, type_id=type_id)


class _Caller(object):
    def __init__(self, parameters):
        self.parameters = parameters
        self.queries = []
        self.callees = {}

    def get_parameter_at(self, address, function_type, index, arch):
        self.queries.append((address, function_type, index, arch))
        return self.parameters[index]


class _Reference(object):
    def __init__(self, callee, caller, address=0x2000):
        self.address = address
        self.function = caller
        self.arch = mock.sentinel.arch
        self.llil = mock.Mock(spec=bn.Call)
        caller.callees[address] = [callee]


class _View(object):
    analysis_is_aborted = False

    def __init__(self, functions, refs, executable=(), type_defs=None):
        self.functions = functions
        self.refs = refs
        self.executable = set(executable)
        self.existing = {}
        self.containing = {}
        self.added = []
        self.removed = []
        self.type_defs = dict(type_defs or {})
        self.type_queries = []

    def get_code_refs(self, address, max_items=None):
        return iter(self.refs.get(address, ())[:max_items])

    def is_offset_executable(self, address):
        return address in self.executable

    def is_valid_offset(self, address):
        return address in self.executable

    def get_callees(self, address, function, arch):
        return function.callees.get(address, ())

    def get_type_by_id(self, type_id):
        self.type_queries.append(type_id)
        return self.type_defs.get(type_id)

    def get_function_at(self, address):
        return self.existing.get(address)

    def get_functions_containing(self, address):
        return self.containing.get(address, ())

    def add_function(self, address, *args, **kwargs):
        function = types.SimpleNamespace(start=address)
        self.added.append((address, args, kwargs))
        self.existing[address] = function
        return function

    def remove_function(self, function):
        self.removed.append(function)
        self.existing.pop(function.start, None)


class CallbackDiscoveryTests(unittest.TestCase):
    def test_creates_deduplicated_auto_functions_from_declared_parameters(self):
        from delphinja.integration import workflow

        function_type = _function_type(
            _plain_pointer_type(), _callback_type(), _callback_type())
        callee = types.SimpleNamespace(start=0x1000, type=function_type)
        first = _Caller([_value(0), _value(0x3000), _value(0x3100)])
        duplicate = _Caller([_value(0), _value(0x3000), _value(0x3200)])
        view = _View(
            [callee],
            {callee.start: [
                _Reference(callee.start, first),
                _Reference(callee.start, duplicate, 0x2010),
            ]},
            executable={0x3000, 0x3100, 0x3200})

        self.assertEqual(workflow.discover_callbacks(view), 3)
        self.assertEqual(view.added, [
            (0x3000, (), {}),
            (0x3100, (), {}),
            (0x3200, (), {}),
        ])
        self.assertEqual(
            [(query[0], query[2]) for query in first.queries],
            [(0x2000, 1), (0x2000, 2)])

    def test_rejects_noncode_metadata_existing_and_unknown_targets(self):
        from delphinja.integration import workflow

        function_type = _function_type(
            _callback_type(), _callback_type(), _callback_type(),
            _callback_type())
        callee = types.SimpleNamespace(start=0x1000, type=function_type)
        caller = _Caller([
            _value(0x3000),              # not executable
            _value(0x4004),              # Delphi metadata
            _value(0x5000),              # already a function
            _value(constant=False),       # not statically known
        ])
        view = _View(
            [callee], {callee.start: [_Reference(callee.start, caller)]},
            executable={0x4004, 0x5000})
        view.existing[0x5000] = mock.sentinel.existing

        self.assertEqual(
            workflow.discover_callbacks(view, [(0x4000, 0x4010)]), 0)
        self.assertEqual(view.added, [])

    def test_ignores_plain_pointers_and_references_that_are_not_calls(self):
        from delphinja.integration import workflow

        untyped = types.SimpleNamespace(
            start=0x1000, type=_function_type(_plain_pointer_type()))
        typed = types.SimpleNamespace(
            start=0x1100, type=_function_type(_callback_type()))
        caller = _Caller([_value(0x3000)])
        wrong_destination = _Reference(0x1200, caller, 0x2000)
        caller.callees[wrong_destination.address] = [0x1200]
        not_a_call = _Reference(typed.start, caller, 0x2010)
        not_a_call.llil = object()
        view = _View(
            [untyped, typed],
            {untyped.start: [_Reference(untyped.start, caller)],
             typed.start: [wrong_destination, not_a_call]},
            executable={0x3000})

        self.assertEqual(workflow.discover_callbacks(view), 0)
        self.assertEqual(caller.queries, [])

    def test_preserves_annotations_but_accepts_unannotated_boundaries(self):
        from delphinja.integration import workflow

        callee = types.SimpleNamespace(
            start=0x1000,
            type=_function_type(_callback_type(), _callback_type()))
        caller = _Caller([_value(0x3000), _value(0x3100)])
        view = _View(
            [callee], {callee.start: [_Reference(callee.start, caller)]},
            executable={0x3000, 0x3100})
        view.containing[0x3000] = [types.SimpleNamespace(
            auto=False, has_user_annotations=False)]
        view.containing[0x3100] = [types.SimpleNamespace(
            auto=True, has_user_annotations=True)]

        self.assertEqual(workflow.discover_callbacks(view), 1)
        self.assertEqual(view.added, [(0x3000, (), {})])

    def test_resolves_platform_typedefs_around_pointer_and_function(self):
        from delphinja.integration import workflow

        pointer = types.SimpleNamespace(
            type_class=bn.TypeClass.PointerTypeClass,
            target=_named_type("callback-function"))
        callee = types.SimpleNamespace(
            start=0x1000,
            type=_function_type(_named_type("callback-pointer")))
        caller = _Caller([_value(0x3000)])
        view = _View(
            [callee], {callee.start: [_Reference(callee.start, caller)]},
            executable={0x3000},
            type_defs={
                "callback-pointer": pointer,
                "callback-function": types.SimpleNamespace(
                    type_class=bn.TypeClass.FunctionTypeClass),
            })

        self.assertEqual(workflow.discover_callbacks(view), 1)
        self.assertEqual(view.added, [(0x3000, (), {})])
        self.assertEqual(view.type_queries,
                         ["callback-pointer", "callback-function"])

    def test_recursive_named_typedef_is_ignored(self):
        from delphinja.integration import workflow

        callee = types.SimpleNamespace(
            start=0x1000, type=_function_type(_named_type("first")))
        caller = _Caller([_value(0x3000)])
        view = _View(
            [callee], {callee.start: [_Reference(callee.start, caller)]},
            executable={0x3000},
            type_defs={"first": _named_type("second"),
                       "second": _named_type("first")})

        self.assertEqual(workflow.discover_callbacks(view), 0)
        self.assertEqual(view.added, [])
        self.assertEqual(view.type_queries, ["first", "second"])

    def test_analysis_abort_rolls_back_functions_created_in_this_pass(self):
        from delphinja.integration import workflow

        callee = types.SimpleNamespace(
            start=0x1000,
            type=_function_type(_callback_type(), _callback_type()))
        caller = _Caller([_value(0x3000), _value(0x3100)])

        class AbortingView(_View):
            @property
            def analysis_is_aborted(self):
                return bool(self.added)

        view = AbortingView(
            [callee], {callee.start: [_Reference(callee.start, caller)]},
            executable={0x3000, 0x3100})

        self.assertEqual(workflow.discover_callbacks(view), 0)
        self.assertEqual([function.start for function in view.removed],
                         [0x3000])
        self.assertEqual(view.existing, {})


class WorkflowPlacementTests(unittest.TestCase):
    def test_cleanup_discovers_callbacks_before_discarding_metadata_state(self):
        from delphinja.integration import workflow

        metadata = mock.Mock()
        metadata.spans.return_value = [(0x4000, 0x4010, "TypeInfo")]
        view = types.SimpleNamespace(session_data={
            "delphinja": {"md": metadata, "pending_self": (), "cc": None}
        })
        context = types.SimpleNamespace(view=view)
        with mock.patch.object(workflow.A, "undefine_functions",
                               return_value=[]), \
                mock.patch.object(workflow, "discover_callbacks",
                                  return_value=2) as discover, \
                mock.patch.object(workflow.bn, "log_info"):
            workflow._cleanup(context)

        discover.assert_called_once_with(view, [(0x4000, 0x4010)])
        self.assertEqual(view.session_data["delphinja"], {})

    def test_cleanup_activity_remains_after_unused_function_deletion(self):
        from delphinja.integration import workflow

        registered = mock.Mock()
        workflow_factory = mock.Mock()
        workflow_factory.return_value.clone.return_value = registered
        with mock.patch.object(workflow, "Workflow", workflow_factory), \
                mock.patch.object(workflow, "Activity", return_value=mock.Mock()):
            workflow.register()

        registered.insert_after.assert_called_once_with(
            "core.module.deleteUnusedAutoFunctions", [workflow.CLEANUP])


if __name__ == "__main__":
    unittest.main()
