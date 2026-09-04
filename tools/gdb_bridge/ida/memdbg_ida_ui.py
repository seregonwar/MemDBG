# MemDBG IDA companion: suppress IDA's all-stop "Please wait... / Running" box.
# Copy this file to IDA's plugins directory. Requires IDAPython.

import ida_dbg
import ida_idaapi
import ida_idd
import ida_kernwin


_POLL_MS = 50


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

    def _wait_box_visible(self):
        try:
            get_modal = getattr(ida_kernwin, "get_active_modal_widget", None)
            if callable(get_modal):
                widget = get_modal()
                if widget is not None:
                    title = ida_kernwin.get_widget_title(widget) or ""
                    if str(title).lower().startswith("please wait"):
                        return True
        except Exception:
            pass
        for caption in ("Please wait...", "Please wait…"):
            try:
                if ida_kernwin.find_widget(caption) is not None:
                    return True
            except Exception:
                pass
        return False

    def _tick(self):
        try:
            state = ida_dbg.get_process_state()
            if state != ida_dbg.DSTATE_RUN or not _is_gdb_debugger():
                self.hidden_for_run = False
                return _POLL_MS

            if not self.hidden_for_run and self._wait_box_visible():
                # One hide per RUN transition: never blindly pop IDA's global
                # wait-box stack when the debugger dialog is not visible.
                ida_kernwin.hide_wait_box()
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
