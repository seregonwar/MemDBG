/*
 * memDBG - Tracer screen for frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Real-time syscall tracing and crash detection GUI.
 * Connects to the daemon's tracer service via protocol commands.
 */

#include "app_state.hpp"
#include "core/client/memdbg_client.hpp"
#include "locale/locale.hpp"
#include "memdbg/tracer/memdbg_tracer.h"
#include "ui/ui_icons.hpp"
#include "ui/ui_widgets.hpp"

#include "imgui.h"

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace memdbg::frontend {

extern void request_tracer_attach_async(AppState &state);
extern void request_tracer_detach_async(AppState &state);

/* ---- Syscall Viewer (reference table) ---- */

struct SyscallRefEntry {
  int number;
  const char *name;
};

static const SyscallRefEntry kPs4Syscalls[] = {
  {0, "syscall"}, {1, "exit"}, {2, "fork"}, {3, "read"}, {4, "write"},
  {5, "open"}, {6, "close"}, {7, "wait4"}, {8, "link"}, {9, "unlink"},
  {10, "chdir"}, {11, "fchdir"}, {12, "mknod"}, {13, "chmod"},
  {14, "chown"}, {15, "break"}, {16, "getfsstat"}, {17, "lseek"},
  {18, "getpid"}, {19, "mount"}, {20, "unmount"}, {21, "setuid"},
  {22, "getuid"}, {23, "geteuid"}, {24, "ptrace"}, {25, "recvmsg"},
  {26, "sendmsg"}, {27, "recvfrom"}, {28, "accept"}, {29, "getpeername"},
  {30, "getsockname"}, {31, "access"}, {32, "chflags"}, {33, "fchflags"},
  {34, "sync"}, {35, "kill"}, {36, "stat"}, {37, "getppid"},
  {38, "lstat"}, {39, "dup"}, {40, "pipe"}, {41, "getegid"},
  {42, "profil"}, {43, "ktrace"}, {44, "sigaction"}, {45, "getgid"},
  {46, "sigprocmask"}, {47, "getlogin"}, {48, "setlogin"}, {49, "acct"},
  {50, "sigpending"}, {51, "sigaltstack"}, {52, "ioctl"}, {53, "reboot"},
  {54, "revoke"}, {55, "symlink"}, {56, "readlink"}, {57, "execve"},
  {58, "umask"}, {59, "chroot"}, {60, "msync"}, {61, "vfork"},
  {62, "sbrk"}, {63, "sstk"}, {64, "ovadvise"}, {65, "munmap"},
  {66, "mprotect"}, {67, "madvise"}, {68, "mincore"}, {69, "getgroups"},
  {70, "setgroups"}, {71, "getpgrp"}, {72, "setpgid"}, {73, "setitimer"},
  {74, "swapon"}, {75, "getitimer"}, {76, "sysarch"}, {77, "sendto"},
  {78, "shutdown"}, {79, "socketpair"}, {80, "mkdir"}, {81, "rmdir"},
  {82, "utimes"}, {83, "adjtime"}, {84, "setsid"}, {85, "quotactl"},
  {86, "nlm_syscall"}, {87, "nfssvc"}, {88, "lgetfh"}, {89, "getfh"},
  {90, "sysarch1"}, {91, "semctl"}, {92, "semget"}, {93, "semop"},
  {94, "msgctl"}, {95, "msgget"}, {96, "msgsnd"}, {97, "msgrcv"},
  {98, "shmat"}, {99, "shmctl"}, {100, "shmdt"}, {101, "shmget"},
  {102, "clock_gettime"}, {103, "clock_settime"}, {104, "clock_getres"},
  {105, "timer_create"}, {106, "timer_delete"}, {107, "timer_settime"},
  {108, "timer_gettime"}, {109, "timer_getoverrun"}, {110, "nanosleep"},
  {111, "ffclock_getcounter"}, {112, "ffclock_setestimate"},
  {113, "ffclock_getestimate"}, {116, "cap_enter"}, {117, "cap_getmode"},
  {118, "faccessat"}, {119, "fchmodat"}, {120, "fchownat"},
  {121, "fexecve"}, {122, "fstatat"}, {123, "futimesat"},
  {124, "linkat"}, {125, "mkdirat"}, {126, "mkfifoat"},
  {127, "mknodat"}, {128, "openat"}, {129, "readlinkat"},
  {130, "renameat"}, {131, "symlinkat"}, {132, "unlinkat"},
  {133, "utimensat"}, {134, "umtx"}, {135, "posix_fadvise"},
  {136, "posix_fallocate"}, {138, "sctp_peeloff"}, {139, "sctp_generic_sendmsg_iov"},
  {140, "sctp_generic_recvmsg_iov"}, {141, "preadv"}, {142, "pwritev"},
  {143, "sendfile"}, {150, "cpuset_getid"}, {151, "cpuset_getaffinity"},
  {152, "cpuset_setaffinity"}, {153, "fspacctl"}, {154, "procctl"},
  {155, "sigfastblock"}, {166, "__realpathat"}, {180, "aio_read"},
  {181, "aio_write"}, {182, "lio_listio"}, {183, "aio_error"},
  {184, "aio_return"}, {185, "aio_cancel"}, {186, "aio_suspend"},
  {187, "aio_waitcomplete"}, {188, "aio_fsync"}, {189, "aio_mlock"},
  {190, "mq_open"}, {191, "mq_setattr"}, {192, "mq_timedreceive"},
  {193, "mq_timedsend"}, {194, "mq_notify"}, {195, "mq_unlink"},
  {196, "mq_receive"}, {197, "mq_send"}, {202, "__sysctl"},
  {209, "kqueue"}, {210, "kevent"}, {211, "lchmod"},
  {224, "extattrctl"}, {225, "extattr_get_file"}, {226, "extattr_set_file"},
  {227, "extattr_get_fd"}, {228, "extattr_set_fd"}, {229, "extattr_get_link"},
  {230, "extattr_set_link"}, {231, "extattr_delete_file"}, {232, "extattr_delete_fd"},
  {233, "extattr_delete_link"}, {234, "extattr_list_file"}, {235, "extattr_list_fd"},
  {236, "extattr_list_link"}, {240, "nfssvc"}, {250, "minherit"},
  {255, "poll"}, {256, "select"}, {272, "getdirentries"},
  {274, "issetugid"}, {289, "getvfsstat"}, {290, "fstatfs"},
  {291, "statfs"}, {292, "getrlimit"}, {293, "setrlimit"},
  {294, "__getcwd"}, {297, "getpid"}, {298, "getppid"},
  {299, "getuid"}, {300, "getgid"}, {301, "geteuid"}, {302, "getegid"},
  {304, "getlogin"}, {310, "fpathconf"}, {311, "pathconf"},
  {312, "getdtablesize"}, {313, "dup2"}, {321, "sysctl"},
  {322, "mlock"}, {323, "munlock"}, {324, "mlockall"}, {325, "munlockall"},
  {326, "undelete"}, {327, "futimes"}, {328, "getpgid"}, {329, "reboot"},
  {330, "shm_open"}, {331, "shm_unlink"}, {334, "getppid"},
  {336, "__getcwd"}, {337, "issetugid"}, {340, "sctp_generic_sendmsg"},
  {341, "sctp_generic_recvmsg"}, {343, "pread"}, {344, "pwrite"},
  {347, "shm_open"}, {348, "shm_unlink"}, {350, "futimens"},
  {351, "utimensat"}, {356, "kldload"}, {357, "kldunload"},
  {358, "kldfind"}, {359, "kldnext"}, {360, "kldstat"},
  {361, "kldfirstmod"}, {362, "kldsym"}, {363, "__getcwd"},
  {364, "__realpathat"}, {370, "__sysctl"}, {371, "mlockall"},
  {372, "munlockall"}, {375, "sigqueue"}, {378, "nmount"},
  {380, "wait6"}, {383, "ppoll"}, {390, "__specialfd"},
  {394, "fdatasync"}, {395, "fstat"}, {396, "fstatat"},
  {397, "fhstat"}, {398, "getdirentries"}, {400, "kmq_open"},
  {401, "kmq_setattr"}, {402, "kmq_timedreceive"}, {403, "kmq_timedsend"},
  {404, "kmq_notify"}, {405, "kmq_unlink"}, {408, "kldsym"},
  {410, "sched_get_priority_min"}, {411, "sched_get_priority_max"},
  {412, "sched_getscheduler"}, {413, "sched_setscheduler"},
  {414, "sched_setparam"}, {415, "sched_getparam"},
  {416, "sched_yield"}, {419, "thr_self"}, {420, "sched_rr_get_interval"},
  {421, "thr_kill"}, {422, "thr_set_name"}, {430, "thr_exit"},
  {431, "thr_new"}, {432, "thr_suspend"}, {433, "thr_wake"},
  {454, "_umtx_op"}, {460, "cap_ioctls_limit"}, {461, "cap_ioctls_get"},
  {462, "cap_rights_limit"}, {472, "abort2"}, {477, "sigprocmask"},
  {478, "sigaction"}, {480, "sigreturn"}, {490, "socket"},
  {491, "bind"}, {492, "listen"}, {493, "connect"}, {494, "accept"},
  {495, "socketpair"}, {496, "sendto"}, {497, "recvfrom"},
  {498, "sendmsg"}, {499, "recvmsg"}, {500, "shutdown"},
  {501, "getsockopt"}, {502, "setsockopt"}, {503, "getpeername"},
  {504, "getsockname"}, {510, "mmap"}, {511, "munmap"},
  {512, "mprotect"}, {513, "madvise"}, {514, "mincore"},
  {520, "kqueue"}, {521, "kevent"}, {530, "pipe2"},
  {540, "dup3"}, {541, "accept4"}, {560, "pdfork"},
  {561, "pdkill"}, {562, "pdgetpid"}, {570, "aio_read"},
  {571, "aio_write"}, {572, "lio_listio"}, {573, "aio_error"},
  {574, "aio_return"}, {575, "aio_cancel"}, {576, "aio_suspend"},
  {577, "aio_waitcomplete"}, {578, "aio_fsync"}, {579, "aio_mlock"},
  {600, "closefrom"}, {601, "getrlimit"}, {602, "setrlimit"},
};

static void draw_syscall_viewer(AppState &state, ImVec2 avail) {
  (void)state;
  static char syscall_search[64] = "";

  ImGui::SetNextItemWidth(200);
  ImGui::InputTextWithHint("##syscall_search",
                           locale::tr("tracer.syscall_search_hint"),
                           syscall_search, sizeof(syscall_search));
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().dim, "%s",
                     locale::tr("tracer.syscalls_indexed"));
  ImGui::SameLine();
  ImGui::TextColored(ui::colors().primary2, "%zu",
                     std::size(kPs4Syscalls));
  ImGui::Spacing();

  const ImVec2 table_size(avail.x - 16, avail.y - 80);
  const ImGuiTableFlags flags =
      ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders |
      ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable;

  if (ImGui::BeginTable("##syscall_table", 3, flags, table_size)) {
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn(locale::tr("tracer.syscall_col_num"),
                            ImGuiTableColumnFlags_WidthFixed, 70);
    ImGui::TableSetupColumn(locale::tr("tracer.syscall_col_number"),
                            ImGuiTableColumnFlags_WidthFixed, 80);
    ImGui::TableSetupColumn(locale::tr("tracer.syscall_col_name"));
    ImGui::TableHeadersRow();

    std::string filter;
    if (syscall_search[0] != '\0') {
      filter = syscall_search;
      std::transform(filter.begin(), filter.end(), filter.begin(),
                     [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                     });
    }

    for (size_t i = 0; i < std::size(kPs4Syscalls); i++) {
      std::string name_lower = kPs4Syscalls[i].name;
      std::transform(name_lower.begin(), name_lower.end(),
                     name_lower.begin(),
                     [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                     });

      if (!filter.empty() && name_lower.find(filter) == std::string::npos) {
        char num_buf[16];
        snprintf(num_buf, sizeof(num_buf), "%d", kPs4Syscalls[i].number);
        if (filter != num_buf) continue;
      }

      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::Text("%zu", i + 1);
      ImGui::TableSetColumnIndex(1);
      ImGui::TextColored(ui::colors().primary2, "%d",
                         kPs4Syscalls[i].number);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(kPs4Syscalls[i].name);
    }

    ImGui::EndTable();
  }
}

void draw_tracer(AppState &state, ImVec2 avail) {
  static int tracer_tab = 0; // 0=events, 1=syscall reference

  /* Auto-populate PID from the global process selection. */
  if (state.selected_pid > 0 && state.tracer.pid_input[0] == '\0')
    std::snprintf(state.tracer.pid_input, sizeof(state.tracer.pid_input),
                  "%d", state.selected_pid);

  ui::begin_panel("TracerPanel", locale::tr("tracer.title"), avail);

  /* ── Tab bar ── */
  if (ImGui::BeginTabBar("TracerTabs")) {
    if (ImGui::BeginTabItem(locale::tr("tracer.title"))) {
      tracer_tab = 0;
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem(locale::tr("tracer.syscall_reference"))) {
      tracer_tab = 1;
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }

  if (tracer_tab == 1) {
    draw_syscall_viewer(state, avail);
    ui::end_panel();
    return;
  }

  /* ── Status bar ── */
  {
    ImGui::BeginGroup();
    ImGui::Text("%s %s", icons::kOnline, locale::tr("tracer.status"));
    ImGui::SameLine();
    const char *status_icon = state.tracer.status.state == MEMDBG_TRACER_STATE_RUNNING ? u8"\uf04b"   /* play  */
                            : state.tracer.status.state == MEMDBG_TRACER_STATE_CRASHED ? u8"\uf071"   /* warning */
                            : state.tracer.status.state == MEMDBG_TRACER_STATE_IDLE   ? u8"\uf04d"   /* stop */
                            : u8"\uf023";                                                              /* lock */
    ImGui::TextColored(
        state.tracer.status.state == MEMDBG_TRACER_STATE_RUNNING ? ImVec4(0.2f, 0.9f, 0.2f, 1) :
        state.tracer.status.state == MEMDBG_TRACER_STATE_CRASHED ? ImVec4(1, 0.3f, 0.3f, 1) :
        ImVec4(0.7f, 0.7f, 0.7f, 1),
        "%s  %s", status_icon,
        state.tracer.status_text[0] ? state.tracer.status_text : "Idle");
    if (state.tracer.status.state != MEMDBG_TRACER_STATE_IDLE) {
      ImGui::SameLine();
      ImGui::TextDisabled("(%s)", locale::tr("tracer.events_total"));
      ImGui::SameLine();
      ImGui::Text("%u", state.tracer.status.events_total);
    }
    if (state.tracer.status.state == MEMDBG_TRACER_STATE_CRASHED && !state.tracer.crash_dump_path.empty()) {
      ImGui::SameLine();
      ImGui::TextColored(ImVec4(1, 0.5f, 0, 1), " %s %s: %s",
                         u8"\uf071", locale::tr("tracer.dump"), state.tracer.crash_dump_path.c_str());
    }
    ImGui::EndGroup();
  }

  ImGui::Spacing();
  ImGui::TextColored(ui::colors().warning, "%s",
                     "Tracer owns the target while active. Detach resumes it before using Debugger.");
  if (!state.tracer.error.empty())
    ImGui::TextColored(ui::colors().danger, "%s", state.tracer.error.c_str());

  /* ── Controls ── */
  {
    ImGui::AlignTextToFramePadding();
    ImGui::Text("%s", locale::tr("tracer.pid"));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    ImGui::InputText("##pid_input", state.tracer.pid_input, sizeof(state.tracer.pid_input),
                     ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ui::soft_button(locale::tr("tracer.use_global_pid"), ImVec2(0, 0))) {
      if (state.selected_pid > 0)
        std::snprintf(state.tracer.pid_input, sizeof(state.tracer.pid_input),
                      "%d", state.selected_pid);
      else
        set_status(state, locale::tr("tracer.select_pid_global"));
    }
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip("PID %d from topbar", state.selected_pid);

    ImGui::SameLine();
    bool is_idle  = (state.tracer.status.state == MEMDBG_TRACER_STATE_IDLE ||
                     state.tracer.status.state == MEMDBG_TRACER_STATE_STOPPED ||
                     state.tracer.status.state == MEMDBG_TRACER_STATE_EXITED);
    const bool attaching = state.tracer.pending && !state.tracer.detach_pending;
    const bool detaching = state.tracer.detach_pending;

    if (is_idle && !attaching && !detaching) {
      ImGui::BeginDisabled(client_async_busy(state));
      if (ui::primary_button(locale::tr("tracer.attach"), ImVec2(140, 0))) {
        int pid = atoi(state.tracer.pid_input);
        if (pid > 0) {
          state.tracer.target_pid = pid;
          request_tracer_attach_async(state);
        } else {
          set_status(state, locale::tr("tracer.select_pid"));
        }
      }
      ImGui::EndDisabled();
    } else {
      const char *detach_label = detaching ? "Detaching..." :
          (attaching ? "Cancel Attach" : "Detach & Resume");
      ImGui::BeginDisabled(detaching);
      if (ui::danger_button(detach_label, ImVec2(140, 0))) {
        request_tracer_detach_async(state);
      }
      ImGui::EndDisabled();
    }

    if (attaching || detaching) {
      ImGui::SameLine();
      ImGui::TextDisabled("%s", detaching ? "Releasing target..." :
                                           locale::tr("tracer.busy"));
    }
  }

  ImGui::Separator();

  /* ── Event log ── */
  {
    const ImVec2 table_size(avail.x - 16, avail.y - 160);
    if (ImGui::BeginTable("##tracer_events", 7,
                           ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders |
                           ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable,
                           table_size)) {
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableSetupColumn("#",        ImGuiTableColumnFlags_WidthFixed, 48);
      ImGui::TableSetupColumn(locale::tr("tracer.col_type"), ImGuiTableColumnFlags_WidthFixed, 80);
      ImGui::TableSetupColumn(locale::tr("tracer.col_syscall"), ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableSetupColumn(locale::tr("tracer.col_args"),  ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableSetupColumn(locale::tr("tracer.col_thread"),ImGuiTableColumnFlags_WidthFixed, 60);
      ImGui::TableSetupColumn(locale::tr("tracer.col_ret"),   ImGuiTableColumnFlags_WidthFixed, 80);
      ImGui::TableSetupColumn(locale::tr("tracer.col_signal"),ImGuiTableColumnFlags_WidthFixed, 60);
      ImGui::TableHeadersRow();

      /* Show most recent events at the bottom — scroll down. */
      size_t total = state.tracer.events.size();
      size_t start = (total > 500) ? total - 500 : 0;

      /* Track if we need to scroll to bottom. */
      bool at_bottom = false;
      if (total > 0 && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2)
        at_bottom = true;

      for (size_t i = start; i < total; i++) {
        const auto &ev = state.tracer.events[i];
        ImGui::TableNextRow();

        /* # */
        ImGui::TableNextColumn();
        ImGui::Text("%zu", i + 1);

        /* Type */
        ImGui::TableNextColumn();
        const char *type_str =
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY ? u8"\uf054"  /* arrow-right (entry) */ :
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT  ? u8"\uf053"  /* arrow-left (exit)  */ :
            ev.event_type == MEMDBG_TRACER_EVENT_CRASH         ? u8"\uf071"  /* warning            */ :
            u8"\uf0a9";                                                         /* arrow (signal)    */
        ImVec4 type_col =
            ev.event_type == MEMDBG_TRACER_EVENT_CRASH         ? ImVec4(1, 0.3f, 0.3f, 1) :
            ev.event_type == MEMDBG_TRACER_EVENT_SIGNAL        ? ImVec4(1, 0.7f, 0, 1) :
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY ? ImVec4(0.5f, 0.8f, 1, 1) :
            ImVec4(0.7f, 0.7f, 0.7f, 1);
        ImGui::TextColored(type_col, "%s", type_str);

        /* Syscall name */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY ||
            ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT) {
          ImGui::Text("%s", memdbg_tracer_syscall_name((int)ev.syscall_no));
        } else {
          ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1), "—");
        }

        /* Args / ret */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_ENTRY) {
          char buf[128];
          int n = snprintf(buf, sizeof(buf), "%llx", (unsigned long long)ev.args[0]);
          for (int j = 1; j < 6 && ev.args[j] != 0; j++)
            n += snprintf(buf + n, sizeof(buf) - (size_t)n, ", %llx",
                         (unsigned long long)ev.args[j]);
          ImGui::Text("%s", buf);
        } else if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT) {
          ImGui::Text("%lld", (long long)ev.syscall_ret);
        } else if (ev.event_type == MEMDBG_TRACER_EVENT_CRASH) {
          ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "CRASH");
        } else {
          ImGui::Text("—");
        }

        /* Thread */
        ImGui::TableNextColumn();
        ImGui::Text("%u", ev.lwp);

        /* Return value (for exit events) */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SYSCALL_EXIT) {
          ImGui::Text("%lld", (long long)ev.syscall_ret);
        } else {
          ImGui::Text("—");
        }

        /* Signal */
        ImGui::TableNextColumn();
        if (ev.event_type == MEMDBG_TRACER_EVENT_SIGNAL ||
            ev.event_type == MEMDBG_TRACER_EVENT_CRASH) {
          ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                             "SIG%d", ev.signal);
        } else {
          ImGui::Text("—");
        }
      }

      if (total > 0 && at_bottom)
        ImGui::SetScrollHereY(1.0f);

      ImGui::EndTable();
    }
  }

  /* ── Summary bar ── */
  {
    size_t entry_count = state.tracer.events.size();
    size_t crash_count = 0;
    for (size_t i = 0; i < entry_count; i++)
      if (state.tracer.events[i].event_type == MEMDBG_TRACER_EVENT_CRASH)
        crash_count++;
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1),
                       "%s %zu %s  |  %s %zu %s",
                       locale::tr("tracer.events_shown"), entry_count,
                       locale::tr("tracer.events"),
                       locale::tr("tracer.crashes"), crash_count,
                       crash_count == 1 ? "" : locale::tr("tracer.events"));
  }

  ui::end_panel();
}

} // namespace memdbg::frontend
