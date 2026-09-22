# MemDBG IDA companion: suppress IDA's all-stop "Please wait... / Running" box.
# Copy this file to IDA's plugins directory. Requires IDAPython.

import ida_dbg
import ida_idaapi
import ida_idd
import ida_kernwin


_POLL_MS = 50


def _qt_widgets():
    # IDA 9 uses PySide6; older supported releases use PyQt5.
    try:
        from PySide6 import QtWidgets
        return QtWidgets
    except ImportError:
        try:
            from PyQt5 import QtWidgets
            return QtWidgets
        except ImportError:
            return None


def _debugger_name():
    try:
        name = ida_idd.dbg_get_name()
        if name:
            return str(name)
    except Exception:
        pass
    try:
        dbg = ida_idd.get_dbg()
        return str(getattr(dbg, "name", "")) if dbg is not None else ""
    except Exception:
        return ""


def _is_gdb_debugger():
    # The helper is intentionally limited to GDB-family IDD modules. Installing
    # this MemDBG-specific plugin opts the user into suppressing the all-stop
    # wait box for those sessions only.
    return "gdb" in _debugger_name().lower()


class _WaitBoxSuppressor:
    def __init__(self):
        self.timer = None
        self.hidden_for_run = False

    def start(self):
        if self.timer is None:
            self.timer = ida_kernwin.register_timer(_POLL_MS, self._tick)

    def stop(self):
        if self.timer is not None:
            try:
                ida_kernwin.unregister_timer(self.timer)
            except Exception:
                pass
            self.timer = None
        self.hidden_for_run = False

    def _running_wait_box(self):
        # IDA's get_active_modal_widget() explicitly excludes its wait box,
        # and find_widget() only searches IDA TWidgets. Inspect Qt's top-level
        # dialogs instead, then require the debugger's Running label so an
        # unrelated progress dialog is never hidden.
        qt = _qt_widgets()
        app = qt.QApplication.instance() if qt is not None else None
        if app is None:
            return None
        for widget in app.topLevelWidgets():
            if not widget.isVisible():
                continue
            if not widget.windowTitle().strip().lower().startswith("please wait"):
                continue
            labels = widget.findChildren(qt.QLabel)
            if any("running" in label.text().lower() for label in labels):
                return widget
        return None

    def _tick(self):
        try:
            state = ida_dbg.get_process_state()
            if state != ida_dbg.DSTATE_RUN or not _is_gdb_debugger():
                self.hidden_for_run = False
                return _POLL_MS

            if not self.hidden_for_run:
                wait_box = self._running_wait_box()
                if wait_box is not None:
                    # Preserve IDA's own wait-box stack. IDA will pop it when
                    # the process stops; only its Qt window is hidden here.
                    wait_box.hide()
                    self.hidden_for_run = True
        except Exception:
            self.hidden_for_run = False
        return _POLL_MS


class MemDBGIdaUiPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "MemDBG Remote GDB UI companion"
    help = "Suppress IDA's automatic all-stop Running wait box for GDB sessions."
    wanted_name = "MemDBG GDB UI Companion"
    wanted_hotkey = ""

    def init(self):
        self.suppressor = _WaitBoxSuppressor()
        self.suppressor.start()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        del arg
        # PLUGIN_FIX auto-loads this helper; no interactive action is needed.
        pass

    def term(self):
        if getattr(self, "suppressor", None) is not None:
            self.suppressor.stop()
            self.suppressor = None


def PLUGIN_ENTRY():
    return MemDBGIdaUiPlugin()
