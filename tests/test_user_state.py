import unittest


class _Range(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end


class _Function(object):
    def __init__(self, start, end, auto):
        self.start = start
        self.name = "sub_%x" % start
        self.auto = auto
        self.address_ranges = [_Range(start, end)]
        self.basic_blocks = []


class _FunctionView(object):
    def __init__(self, functions):
        self.functions = functions
        self.removed_auto = []
        self.removed_user = []

    def remove_function(self, function):
        self.removed_auto.append(function)

    def remove_user_function(self, function):
        self.removed_user.append(function)


class _CommentView(object):
    def __init__(self, comments=None):
        self.comments = dict(comments or {})
        self.writes = []

    def get_comment_at(self, addr):
        return self.comments.get(addr)

    def set_comment_at(self, addr, text):
        self.writes.append((addr, text))
        self.comments[addr] = text


class CleanupTests(unittest.TestCase):
    def test_only_automatic_functions_are_removed_over_metadata(self):
        from delphinja.rtti.apply import undefine_functions

        automatic = _Function(0x1000, 0x1010, True)
        user = _Function(0x2000, 0x2010, False)
        unrelated = _Function(0x3000, 0x3010, True)
        view = _FunctionView([automatic, user, unrelated])

        victims = undefine_functions(
            view, [(0x1008, 0x100c), (0x2008, 0x200c)])

        self.assertEqual(victims, [automatic])
        self.assertEqual(view.removed_auto, [automatic])
        self.assertEqual(view.removed_user, [])


class AutomaticCommentTests(unittest.TestCase):
    def _sink(self, view):
        from delphinja.rtti.sinks import AutoSink

        sink = AutoSink.__new__(AutoSink)
        sink.bv = view
        return sink

    def test_existing_comment_is_preserved(self):
        view = _CommentView({0x1000: "analyst note"})
        sink = self._sink(view)

        self.assertFalse(sink.set_comment(0x1000, "recovered metadata"))
        self.assertEqual(view.comments[0x1000], "analyst note")
        self.assertEqual(view.writes, [])

    def test_refused_comment_is_not_counted_as_a_write(self):
        from delphinja.rtti.apply import Applier

        view = _CommentView({0x1000: "analyst note"})
        applier = Applier.__new__(Applier)
        applier.opt = {"comments": True}
        applier.sink = self._sink(view)
        applier.stats = {"comments": 0}

        applier._comment(0x1000, "recovered metadata")

        self.assertEqual(applier.stats["comments"], 0)
        self.assertEqual(view.comments[0x1000], "analyst note")

    def test_empty_address_receives_automatic_comment(self):
        view = _CommentView()
        sink = self._sink(view)

        self.assertTrue(sink.set_comment(0x1000, "recovered metadata"))
        self.assertEqual(view.comments[0x1000], "recovered metadata")
        self.assertEqual(view.writes,
                         [(0x1000, "recovered metadata")])


if __name__ == "__main__":
    unittest.main()
