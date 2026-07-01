
"""
Whole detection Agent (somewhat intelligent agent logic is written here gng)

C++ etw session regex:
    [YYYY-MM-DD HH:MM:SS] , Opcode=N, Parent ID=N, PID=N, Process=<path>, TID=N
    [YYYY-MM-DD HH:MM:SS] , Opcode=10, ..., TID=N, Path=<dll_path>

Opcode meanings
    1   Process start
    2   Process end
    10  Image(dll/exe) load 
⚠ Educational project only fam. Run in a controlled / lab environment that is only in windowsOS. Kernel tracker runs from
windows version XP to W11.

Usage
    # Live mode — tails EventLog.txt as the C++ agent writes it
    python detection_agent.py

    # Live mode with an explicit path
    python detection_agent.py path/to/EventLog.txt

    # Batch mode — process the file once, then exit and print a summary
    python detection_agent.py --batch

    # Optional: adjust the poll interval (seconds, default 0.5)
    python detection_agent.py --poll 1.0

Outputs
-------
    AlertLog.txt  — persistent record of every alert (always written)
    stdout        — coloured real-time alert stream

Requirements: Python 3.9+, no third-party packages.


"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# colouring (taken from stack overflow don't know about this part much)
# ---------------------------------

def _enable_ansi() -> bool:
    """Return True when the terminal understands ANSI escape codes."""
    if sys.platform == "win32":
        try:                                    # Windows 10+ virtual terminal
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOUR = _enable_ansi()

_SEV_FG = {
    "LOW":      "\033[94m",   #blu
    "MEDIUM":   "\033[93m",   #yellow
    "HIGH":     "\033[91m",   #red
    "CRITICAL": "\033[95m",   #purple
}
_RESET = "\033[0m" if _COLOUR else ""
_BOLD  = "\033[1m" if _COLOUR else ""
_DIM   = "\033[2m" if _COLOUR else ""


def _col(text: str, sev: str) -> str:
    if not _COLOUR:
        return text
    return f"{_SEV_FG.get(sev, '')}{text}{_RESET}"



# Data structures
#-----------------------------

@dataclass
class ProcessEvent:
    #this is the exact structure used in ETW regex
    timestamp:    datetime      # process time stamp
    opcode:       int           # 1 = start, 2 = end, 10 = image load
    parent_pid:   int           #id of process' parent
    pid:          int           # process' id
    process_path: str           #path of the process execuated
    tid:          int           #id of procesess' thread if dll/exe is ran (for more compherensive analysis of multi-threaded enviroments)
    dll_path:     Optional[str] = None   # only present on opcode 10

    @property
    def process_name(self) -> str: #making sure everything is properly lowercased.
        if not self.process_path or self.process_path == "<unknown>":
            return "<unknown>"
        return os.path.basename(self.process_path).lower()
    @property
    def dll_name(self) -> str:
        return os.path.basename(self.dll_path).lower() if self.dll_path else ""


@dataclass
class Alert: # this represents the proper structure of detection properities.
    timestamp:   datetime
    rule:        str
    severity:    str      
    pid:         int
    parent_pid:  int
    process:     str
    description: str




_LOG_RE = re.compile(
    # Exact log format produced example:
    #   [2024-05-01 13:45:02] , Opcode=1, Parent ID=1234, PID=5678,
    #       Process=C:\Windows\System32\cmd.exe, TID=9012
    #   [2024-05-01 13:45:02] , Opcode=10, ..., TID=9012, Path=C:\Windows\System32\ntdll.dll
    r"\[(?P<ts>[^\]]+)\]"
    r"\s*,\s*Opcode=(?P<opcode>\d+)"
    r",\s*Parent ID=(?P<ppid>\d+)"
    r",\s*PID=(?P<pid>\d+)"
    r",\s*Process=(?P<proc>[^,]+)"   # path ends at the next comma
    r",\s*TID=(?P<tid>\d+)"
    r"(?:,\s*Path=(?P<path>.+?))?"   # dll path — optional, rest of line
    r"\s*$"
)


def parseLine(line: str) -> Optional[ProcessEvent]:
    m = _LOG_RE.match(line.rstrip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts").strip(), "%Y-%m-%d %H:%M:%S")
        raw_path = (m.group("path") or "").strip()
        return ProcessEvent(
            timestamp    = ts,
            opcode       = int(m.group("opcode")),
            parent_pid   = int(m.group("ppid")),
            pid          = int(m.group("pid")),
            process_path = m.group("proc").strip(),
            tid          = int(m.group("tid")),
            dll_path     = raw_path or None,
        )
    except (ValueError, TypeError):
        return None



_LOLBINS = frozenset([
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "cmstp.exe",
])

# Parents that should NEVER spawn shells / scripting engines
_SUSPICIOUS_PARENT_CHILD: dict[str, frozenset[str]] = {
    "winword.exe":  _LOLBINS,
    "excel.exe":    _LOLBINS,
    "outlook.exe":  _LOLBINS,
    "powerpnt.exe": _LOLBINS,
    "onenote.exe":  _LOLBINS,
    "acrord32.exe": _LOLBINS,
    "acrobat.exe":  _LOLBINS,
    "chrome.exe":   frozenset(["cmd.exe", "powershell.exe", "pwsh.exe"]),
    "firefox.exe":  frozenset(["cmd.exe", "powershell.exe", "pwsh.exe"]),
    "msedge.exe":   frozenset(["cmd.exe", "powershell.exe", "pwsh.exe"]),
    # Script engines spawning further shells = double red flag
    "mshta.exe":    _LOLBINS,
    "wscript.exe":  _LOLBINS,
    "cscript.exe":  _LOLBINS,
}

# Parents we consider normal/expected for PowerShell
_POWERSHELL_SAFE_PARENTS = frozenset([
    "explorer.exe", "svchost.exe", "taskeng.exe", "taskhostw.exe",
    "cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe",
    "<unknown>",    # process whose start we didn't catch — avoid false positives
])

# Windows system processes and the path suffix they must run from
_EXPECTED_PATHS: dict[str, list[str]] = {
    "lsass.exe":    ["system32\\lsass.exe"],
    "svchost.exe":  ["system32\\svchost.exe"],
    "services.exe": ["system32\\services.exe"],
    "winlogon.exe": ["system32\\winlogon.exe"],
    "csrss.exe":    ["system32\\csrss.exe"],
    "smss.exe":     ["system32\\smss.exe"],
    "wininit.exe":  ["system32\\wininit.exe"],
    "explorer.exe": ["windows\\explorer.exe"],
    "taskhost.exe": ["system32\\taskhost.exe"],
    "taskhostw.exe":["system32\\taskhostw.exe"],
}

# Substrings in a path that are suspicious for executables or DLLs
_SUSPICIOUS_PATH_SUBSTRINGS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\$recycle.bin\\",
    "\\windows\\fonts\\",     # classic DLL-hijacking target
]

# Extensions sometimes used in persistence (double-extension trick)
_DOC_LIKE_EXTENSIONS = frozenset([
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip", "rar", "txt",
])
_EXE_EXTENSIONS = frozenset(["exe", "com", "scr", "bat", "cmd", "pif"])

# DLL names tied to well-known offensive tools
_MALICIOUS_DLL_NAMES = frozenset([
    "mimikatz.dll", "mimilib.dll",
    "inject.dll", "injector.dll",
    "reflective_dll.dll",
    "meterpreter.dll",
])

# Rapid-process-creation thresholds
_RAPID_WINDOW_SECS   = 5     # sliding window length
_RAPID_THRESHOLD     = 20    # max new processes before alert
_RAPID_COOLDOWN_SECS = 10    # minimum gap between repeated rapid-creation alerts



# Detection engine part

class DetectionEngine:
    """
    Feed every ParsedEvent through process_event(); it returns the list of
    Alert(as object we defined earlier).

    Predifenied rules, please change to your heart's desire folk
        1. SUSPICIOUS_PARENT_CHILD
        2. POWERSHELL_UNUSUAL_PARENT
        3. PROCESS_MASQUERADING
        4. RAPID_PROCESS_CREATION
        5. DOUBLE_EXTENSION_EXECUTABLE
        6. EXECUTABLE_FROM_SUSPICIOUS_PATH
        7. MALICIOUS_DLL_LOADED this alst three is about image load
        8. DLL_FROM_SUSPICIOUS_PATH
        9. POSSIBLE_DLL_HIJACKING
    """

    def __init__(self) -> None:
        self._proc_map: dict[int, ProcessEvent] = {}
        # sliding window of process-creation timestamps (Rule 4)
        self._creation_ts: list[datetime] = []
        self._last_rapid_alert: Optional[datetime] = None

    # ------------------------------------------------------------------ public

    def process_event(self, ev: ProcessEvent) -> list[Alert]:
        """Evaluate *ev* against all rules; return any new alerts."""
        alerts: list[Alert] = []

        if ev.opcode == 1:
            self._proc_map[ev.pid] = ev
            alerts.extend(self._on_process_start(ev))
        elif ev.opcode == 2:
            self._proc_map.pop(ev.pid, None)
        elif ev.opcode == 10:
            alerts.extend(self._on_image_load(ev))
        # Thread-start/end events (other opcodes) are silently ignored, causing too many false positives and personally I find them annoying notifications
        return alerts

    # ----------------------------------------- process-start rules (opcode 1)

    def _on_process_start(self, ev: ProcessEvent) -> list[Alert]:
        alerts: list[Alert] = []
        proc     = ev.process_name
        parent_e = self._proc_map.get(ev.parent_pid)
        parent   = parent_e.process_name if parent_e else "<unknown>"
        path_l   = ev.process_path.lower()

        #Rule 1: Sus parent  child 
        if parent in _SUSPICIOUS_PARENT_CHILD and proc in _SUSPICIOUS_PARENT_CHILD[parent]:
            alerts.append(self._make(
                ev, "SUSPICIOUS_PARENT_CHILD", "HIGH",
                f"'{parent}' (ppid={ev.parent_pid}) spawned '{proc}' (pid={ev.pid}) — "
                f"office/browser/script-engine should not launch shells or LOLBins"
            ))

        # Rule 2:PowerShell from an unexpected parent
        if proc in ("powershell.exe", "pwsh.exe") and parent not in _POWERSHELL_SAFE_PARENTS:
            alerts.append(self._make(
                ev, "POWERSHELL_UNUSUAL_PARENT", "MEDIUM",
                f"PowerShell (pid={ev.pid}) spawned by unusual parent '{parent}' (ppid={ev.parent_pid})"
            ))

        #Rule 3:System process masquerading
        if proc in _EXPECTED_PATHS and ev.process_path != "<unknown>":
            expected = _EXPECTED_PATHS[proc]
            if not any(path_l.endswith(suf) for suf in expected):
                alerts.append(self._make(
                    ev, "PROCESS_MASQUERADING", "CRITICAL",
                    f"'{proc}' running from unexpected path '{ev.process_path}' "
                    f"(expected suffix: {expected})"
                ))

        #Rule 4: Rapid process creation
        now = ev.timestamp
        self._creation_ts = [
            t for t in self._creation_ts
            if (now - t).total_seconds() <= _RAPID_WINDOW_SECS
        ]
        self._creation_ts.append(now)
        if len(self._creation_ts) > _RAPID_THRESHOLD:
            cooldown_ok = (
                self._last_rapid_alert is None or
                (now - self._last_rapid_alert).total_seconds() > _RAPID_COOLDOWN_SECS
            )
            if cooldown_ok:
                self._last_rapid_alert = now
                alerts.append(self._make(
                    ev, "RAPID_PROCESS_CREATION", "HIGH",
                    f"{len(self._creation_ts)} processes started within {_RAPID_WINDOW_SECS} s "
                    f"— possible process-hollowing or fork-bomb"
                ))

        #Rule 5: Double-extension executable
        parts = path_l.rsplit(".", 2)   # keep at most 2 splits from the right
        if len(parts) == 3:
            if parts[2] in _EXE_EXTENSIONS and parts[1] in _DOC_LIKE_EXTENSIONS:
                alerts.append(self._make(
                    ev, "DOUBLE_EXTENSION_EXECUTABLE", "HIGH",
                    f"Double-extension executable detected: '{ev.process_path}'"
                ))

        #Rule 6: Executable launched from a suspicious path
        for sp in _SUSPICIOUS_PATH_SUBSTRINGS:
            if sp in path_l:
                alerts.append(self._make(
                    ev, "EXECUTABLE_FROM_SUSPICIOUS_PATH", "MEDIUM",
                    f"Process launched from suspicious location: '{ev.process_path}'"
                ))
                break

        return alerts

    # img laod

    def _on_image_load(self, ev: ProcessEvent) -> list[Alert]:
        alerts: list[Alert] = []
        dll_name = ev.dll_name
        dll_l    = (ev.dll_path or "").lower()

        #Rule 7: Known malicious DLL name
        if dll_name in _MALICIOUS_DLL_NAMES:
            alerts.append(self._make(
                ev, "MALICIOUS_DLL_LOADED", "CRITICAL",
                f"Known offensive-tool DLL '{ev.dll_path}' loaded into "
                f"pid={ev.pid} ({ev.process_name})"
            ))

        #Rule 8: DLL from a suspicious path
        for sp in _SUSPICIOUS_PATH_SUBSTRINGS:
            if sp in dll_l:
                alerts.append(self._make(
                    ev, "DLL_FROM_SUSPICIOUS_PATH", "HIGH",
                    f"DLL '{ev.dll_path}' loaded from a suspicious path "
                    f"into pid={ev.pid} ({ev.process_name})"
                ))
                break

        #Rule 9: DLL loaded with a relative / non-absolute path
        if ev.dll_path and not os.path.isabs(ev.dll_path):
            alerts.append(self._make(
                ev, "POSSIBLE_DLL_HIJACKING", "MEDIUM",
                f"DLL '{ev.dll_path}' loaded without an absolute path in "
                f"pid={ev.pid} ({ev.process_name}) — possible DLL hijacking"
            ))

        return alerts

    @staticmethod
    def _make(ev: ProcessEvent, rule: str, sev: str, desc: str) -> Alert:
        return Alert(
            timestamp   = ev.timestamp,
            rule        = rule,
            severity    = sev,
            pid         = ev.pid,
            parent_pid  = ev.parent_pid,
            process     = ev.process_path,
            description = desc,
        )


# OutputModule

class OutputModule:
    def __init__(self, log_path: str = "AlertLog.txt") -> None:
        self._log_path = log_path
        self._counts: dict[str, int] = defaultdict(int)
        self._alert_serial = 0

        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write(
                f"EDR Alert Log — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"{'=' * 80}\n\n"
            )

    # ------------------------------------------------------------------ public
    #Severe retardation for output. High and  unnecessary amount of time and effort is spent here. I still doubt it works properly.
    #Please try to make it suitible for yourself.
    def emit(self, alert: Alert) -> None:
        self._alert_serial += 1
        self._counts[alert.severity] += 1

        ts_str  = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        sev_tag = f"[{alert.severity}]"
        serial  = f"#{self._alert_serial:04d}"

        print(
            f"{_DIM}{ts_str}{_RESET}  "
            f"{_BOLD}{_col(sev_tag, alert.severity)}{_RESET}  "
            f"{_BOLD}{alert.rule}{_RESET}  {_DIM}{serial}{_RESET}"
        )
        print(f"   {alert.description}")
        print(
            f"   {_DIM}pid={alert.pid}  ppid={alert.parent_pid}  "
            f"process={alert.process}{_RESET}\n"
        )

        with open(self._log_path, "a", encoding="utf-8") as fh:
            fh.write(
                f"[{ts_str}] [{alert.severity}] {alert.rule}  {serial}\n"
                f"  {alert.description}\n"
                f"  pid={alert.pid}  ppid={alert.parent_pid}  process={alert.process}\n\n"
            )

    def summary(self) -> None:
        total = sum(self._counts.values())
        sep   = "=" * 60
        print(f"\n{sep}")
        print(f"{_BOLD}Detection Summary{_RESET}")
        print(sep)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = self._counts.get(sev, 0)
            label = _col(f"  {sev:<10}", sev)
            print(f"{label}: {count}")
        print(f"  {'TOTAL':<10}: {total}")
        print(f"\n  Alert log written  {self._log_path}\n")



# Agent runner functions

def _open_log(path: str):
    return open(path, "r", encoding="utf-8", errors="replace")


def run_live(log_path: str, poll: float = 0.5) -> None:
    """
    Live mode tail *log_path* and run detection on every new line.
    Ctrl-C prints the summary and exits cleanly.
    """
    engine = DetectionEngine()
    output = OutputModule()
    file_pos = 0

    print(f"\n{_BOLD}EDR Detection Agent{_RESET}   live monitoring '{log_path}'")
    print("Ctrl-C to stop.\n")

    try:
        while True:
            if not os.path.exists(log_path):
                time.sleep(poll)
                continue

            with _open_log(log_path) as fh:
                fh.seek(file_pos)
                lines    = fh.readlines()
                file_pos = fh.tell()

            for line in lines:
                ev = parseLine(line)
                if ev is None:
                    continue
                for alert in engine.process_event(ev):
                    output.emit(alert)

            time.sleep(poll)

    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    finally:
        output.summary()


def run_batch(log_path: str) -> None:
    """
    Batch mode  analyse *log_path* in full, print all alerts, then exit.
    """
    if not os.path.exists(log_path):
        sys.exit(f"[!] File not found: {log_path}")

    engine = DetectionEngine()
    output = OutputModule()

    print(f"\n{_BOLD}EDR Detection Agent{_RESET}   batch analysis of '{log_path}'\n")

    with _open_log(log_path) as fh:
        for line in fh:
            ev = parseLine(line)
            if ev is None:
                continue
            for alert in engine.process_event(ev):
                output.emit(alert)

    output.summary()



# CLI


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detection_agent.py",
        description=(
            "EDR Detection Agent — Python companion to the BurakTreaty/EDR-Project C++ agent.\n"
            "Reads EventLog.txt produced by the ETW session and applies rule-based detection."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Rules implemented:\n"
            "  [opcode 1]  SUSPICIOUS_PARENT_CHILD        — Office/browser spawning shells\n"
            "  [opcode 1]  POWERSHELL_UNUSUAL_PARENT      — PowerShell from odd parent\n"
            "  [opcode 1]  PROCESS_MASQUERADING            — System binary from wrong path\n"
            "  [opcode 1]  RAPID_PROCESS_CREATION          — Burst of >20 processes / 5 s\n"
            "  [opcode 1]  DOUBLE_EXTENSION_EXECUTABLE     — e.g. invoice.pdf.exe\n"
            "  [opcode 1]  EXECUTABLE_FROM_SUSPICIOUS_PATH — EXE in Temp/Downloads/etc.\n"
            "  [opcode 10] MALICIOUS_DLL_LOADED            — Known offensive-tool DLL\n"
            "  [opcode 10] DLL_FROM_SUSPICIOUS_PATH        — DLL from Temp/AppData/etc.\n"
            "  [opcode 10] POSSIBLE_DLL_HIJACKING          — DLL with relative path\n"
        ),
    )
    p.add_argument(
        "log", nargs="?", default="EventLog.txt", metavar="LOG_FILE",
        help="Path to the ETW event log (default: EventLog.txt)",
    )
    p.add_argument(
        "--batch", action="store_true",
        help="Process the log file once and exit (default: tail continuously)",
    )
    p.add_argument(
        "--poll", type=float, default=0.5, metavar="SECS",
        help="Polling interval in live mode (default: 0.5 s)",
    )
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    if args.batch:
        run_batch(args.log)
    else:
        run_live(args.log, poll=args.poll)


