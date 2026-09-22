"""Host-side checks for the optional IDA wait-dialog companion."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest


def load_plugin():
    dbg = types.ModuleType("ida_dbg")
    dbg.DSTATE_RUN = 1
    dbg.get_process_state = lambda: dbg.DSTATE_RUN
    sys.modules["ida_dbg"] = dbg

    idaapi = types.ModuleType("ida_idaapi")
    idaapi.plugin_t = type("plugin_t", (), {})
    idaapi.PLUGIN_FIX = 1
    idaapi.PLUGIN_KEEP = 1
    sys.modules["ida_idaapi"] = idaapi

    idd = types.ModuleType("ida_idd")
    idd.dbg_get_name = lambda: "Remote GDB debugger"
    sys.modules["ida_idd"] = idd

    kernwin = types.ModuleType("ida_kernwin")
    kernwin.register_timer = lambda interval, callback: object()
    kernwin.unregister_timer = lambda timer: None
    sys.modules["ida_kernwin"] = kernwin

    path = Path(__file__).with_name("memdbg_ida_ui.py")
    spec = importlib.util.spec_from_file_location("memdbg_ida_ui", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, dbg


class Label:
    def __init__(self, text):
        self.value = text

    def text(self):
        return self.value


class Dialog:
    def __init__(self, title, label):
        self.title = title
        self.label = Label(label)
        self.visible = True
        self.hide_count = 0

    def isVisible(self):
        return self.visible

    def windowTitle(self):
        return self.title

    def findChildren(self, cls):
        return [self.label]

    def hide(self):
        self.hide_count += 1
        self.visible = False


class IdaUiTest(unittest.TestCase):
    def test_only_running_wait_box_is_hidden_once_per_run(self):
        plugin, dbg = load_plugin()
        unrelated = Dialog("Please wait...", "Exporting database")
        running = Dialog("Please wait...", "Running")
        other = Dialog("Confirm", "Running")
        app = types.SimpleNamespace(topLevelWidgets=lambda: [unrelated, running, other])
        qt = types.SimpleNamespace(QApplication=types.SimpleNamespace(instance=lambda: app), QLabel=Label)
        plugin._qt_widgets = lambda: qt
        suppressor = plugin._WaitBoxSuppressor()

        suppressor._tick()
        suppressor._tick()
        self.assertEqual(running.hide_count, 1)
        self.assertEqual(unrelated.hide_count, 0)
        self.assertEqual(other.hide_count, 0)

        dbg.get_process_state = lambda: 0
        suppressor._tick()
        dbg.get_process_state = lambda: dbg.DSTATE_RUN
        running.visible = True
        suppressor._tick()
        self.assertEqual(running.hide_count, 2)


if __name__ == "__main__":
    unittest.main()
