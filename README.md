# 🛡️ OmniSIAH :Windows Endpoint Detection and Response

> A lightweight, educational **Endpoint Detection and Response (EDR)** agent for Windows, demonstrating low-level defensive security engineering across C/C++ and Python.

---

## ⚠️ Disclaimer

This project is **strictly for educational purposes**. It is designed to demonstrate EDR architecture and defensive security concepts in a controlled lab setting.

- **Do not** deploy on production systems.
- **Do not** use against systems you do not own or have explicit permission to test.
- Virtual machine testing is strongly recommended.
- All detection rules are illustrative and not production-grade.

---

## Overview

This project implements a functional EDR agent pipeline from raw kernel telemetry through to human-readable security alerts. It is split into two layers:

- **C++ Collection Layer** — uses Windows Event Tracing (ETW) and the Toolhelp API to capture kernel-level process, thread, and image-load events in real time.
- **Python Detection Layer** — consumes the ETW log, maintains a process context map, and evaluates nine rule-based detections, outputting coloured alerts and a persistent log.

The architecture mirrors how real-world EDR products are structured: a low-level collection agent feeds telemetry to a higher-level detection engine, which applies rules without blocking or quarantining (observe-only mode).

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Windows Kernel (ETW)                │
│  NT Kernel Logger — Process / Thread / Image Load│
└───────────────────┬──────────────────────────────┘
                    │  EVENT_RECORD callbacks
┌───────────────────▼──────────────────────────────┐
│           C++ Collection Layer                   │
│                                                  │
│  ┌─────────────┐   ┌──────────────────────────┐  │
│  │ EtwSession  │   │     processScanner       │  │
│  │ (real-time  │   │  (Toolhelp32 snapshot)   │  │
│  │  consumer)  │   └────────────┬─────────────┘  │
│  └──────┬──────┘                │                │
│         │  EventLog.txt         │  SysLog0.txt   │
│         │  (opcode, PIDs,       │  (PID, Parent, │
│         │   process paths,      │   Name)        │
│         │   DLL paths)          │                │
│  ┌──────▼──────┐   ┌────────────▼─────────────┐  │
│  │ ProcOrganizer│  │       main.cpp           │  │
│  │ (process tree│  │  (menu-driven orchestr.) │  │
│  │  + SysLog    │  └──────────────────────────┘  │
│  │  reader)    │                                  │
│  └─────────────┘                                  │
└───────────────────┬──────────────────────────────┘
                    │  EventLog.txt
┌───────────────────▼──────────────────────────────┐
│           Python Detection Layer                 │
│                                                  │
│  ┌──────────────┐   ┌───────────────────────────┐ │
│  │  Log Parser  │──▶│     DetectionEngine       │ │
│  │  (regex,     │   │  9 rules across opcode    │ │
│  │  live tail   │   │  1 (proc start) and       │ │
│  │  or batch)   │   │  10 (image load)          │ │
│  └──────────────┘   └────────────┬──────────────┘ │
│                                  │                │
│                     ┌────────────▼──────────────┐ │
│                     │      OutputModule         │ │
│                     │  stdout (coloured) +      │ │
│                     │  AlertLog.txt (persistent)│ │
│                     └───────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

---

## Features

### C++ Collection Layer

| Feature | Description |
|---|---|
| **Real-time process monitoring** | Subscribes to the NT Kernel Logger via ETW; captures process creation and termination with parent/child PID relationships |
| **DLL / image-load monitoring** | Logs every DLL and EXE load with full path resolution via TDH |
| **System snapshot** | Uses `CreateToolhelp32Snapshot` to enumerate all running processes at a point in time and writes them to `SysLog<n>.txt` |
| **Process tree view** | Builds and prints a parent/child tree from snapshot data using `ProcOrganizer` |
| **Privilege management** | Automatically acquires `SeSystemProfilePrivilege` and `SeDebugPrivilege` required to start the kernel logger |
| **Background threading** | ETW consumer runs on a dedicated thread; the menu stays responsive |

### Python Detection Layer

| Rule | Opcode | Severity | Description |
|---|---|---|---|
| `SUSPICIOUS_PARENT_CHILD` | 1 | HIGH | Office apps, browsers, or script engines spawning `cmd.exe`, `powershell.exe`, LOLBins, etc. |
| `POWERSHELL_UNUSUAL_PARENT` | 1 | MEDIUM | PowerShell spawned by any process not in the expected parent whitelist |
| `PROCESS_MASQUERADING` | 1 | CRITICAL | A known system binary (e.g. `lsass.exe`, `svchost.exe`) running from an unexpected path |
| `RAPID_PROCESS_CREATION` | 1 | HIGH | More than 20 new processes created within any 5-second window |
| `DOUBLE_EXTENSION_EXECUTABLE` | 1 | HIGH | Executable with a deceptive double extension, e.g. `invoice.pdf.exe` |
| `EXECUTABLE_FROM_SUSPICIOUS_PATH` | 1 | MEDIUM | Process launched from `Temp`, `Downloads`, `AppData\Roaming`, `$Recycle.Bin`, etc. |
| `MALICIOUS_DLL_LOADED` | 10 | CRITICAL | DLL whose name matches a known offensive tool (Mimikatz, Meterpreter, etc.) |
| `DLL_FROM_SUSPICIOUS_PATH` | 10 | HIGH | DLL loaded from a user-writable or temporary directory |
| `POSSIBLE_DLL_HIJACKING` | 10 | MEDIUM | DLL loaded with a relative (non-absolute) path — common DLL hijacking indicator |

---

## Project Structure

```
EDR-Project/
│
├── EtwSession.h / .cpp        # ETW provider + consumer session management
├── processScanner.h / .cpp    # Toolhelp32 process snapshot
├── ProcOrganizer.h / .cpp     # Process tree builder and renderer
├── Libs.h                     # Shared Windows / STL headers
├── main.cpp                   # Menu-driven entry point
│
├── detection_agent.py         # Python detection engine + output module
│
├── EventLog.txt               # [generated] Raw ETW event stream (C++ → Python)
├── AlertLog.txt               # [generated] Detection alerts (Python output)
├── SysLog<n>.txt              # [generated] Process snapshots
│
├── EDRProject.sln             # Visual Studio solution
└── EDRProject.vcxproj         # MSVC project file
```

---

## Requirements

### C++ Agent

| Requirement | Detail |
|---|---|
| OS | Windows 10 / 11 (x64) |
| Compiler | MSVC (Visual Studio 2019 or later) |
| SDK | Windows SDK 10.0+ |
| Libraries | `advapi32.lib`, `tdh.lib` (linked via `#pragma comment`) |
| Privileges | Must be run **as Administrator** (ETW kernel session requires it) |

### Python Detection Agent

| Requirement | Detail |
|---|---|
| Python | 3.9 or later |
| Packages | None — standard library only |
| OS | Any OS that can read the `EventLog.txt` file |

---

## Build & Run

### 1. Build the C++ agent

Open `EDRProject.sln` in Visual Studio, set the configuration to **Release x64**, and build. Or from a Developer Command Prompt:

```bat
msbuild EDRProject.sln /p:Configuration=Release /p:Platform=x64
```

### 2. Run the C++ agent (as Administrator)

```
EDRProject.exe
```

The interactive menu offers:

```
1. Start ETW process monitor     — begins writing EventLog.txt
2. Take system snapshot          — writes SysLog<n>.txt and prints process tree
3. Stop ETW
5. Exit
```

### 3. Run the Python detection agent

In a second terminal, alongside the running C++ agent:

```bash
# Live mode — tails EventLog.txt as events arrive
python detection_agent.py

# Batch mode — analyse an existing log and exit
python detection_agent.py --batch EventLog.txt

# Custom log path or poll interval
python detection_agent.py C:\path\to\EventLog.txt --poll 0.2
```

Alerts are printed to the console in real time and appended to `AlertLog.txt`.

---

## Log Formats

### EventLog.txt (written by C++ ETW session)

```
[2024-05-01 13:45:02] , Opcode=1, Parent ID=1234, PID=5678, Process=C:\Windows\System32\cmd.exe, TID=9012
[2024-05-01 13:45:03] , Opcode=10, Parent ID=1234, PID=5678, Process=C:\Windows\System32\cmd.exe, TID=9012, Path=C:\Windows\System32\ntdll.dll
[2024-05-01 13:45:04] , Opcode=2, Parent ID=1234, PID=5678, Process=C:\Windows\System32\cmd.exe, TID=9012
```

Opcode reference: `1` = process start, `2` = process end, `10` = image/DLL load.

### SysLog\<n\>.txt (written by processScanner)

```
PID=4, Parent=0, Name=System
PID=872, Parent=724, Name=services.exe
PID=1204, Parent=872, Name=svchost.exe
```

### AlertLog.txt (written by Python detection agent)

```
[2024-05-01 13:45:10] [HIGH] SUSPICIOUS_PARENT_CHILD  #0001
  'winword.exe' (ppid=2048) spawned 'powershell.exe' (pid=5678) — office/browser/script-engine should not launch shells or LOLBins
  pid=5678  ppid=2048  process=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

---

## Known Limitations

- **No command-line capture** — ETW kernel process events do not expose command-line arguments; only the executable path is available.
- **Race condition on process start** — for very short-lived child processes the parent's start event may not yet be in the process map when the child event arrives, causing `<unknown>` parent labels.
- **Observe-only** — the detection engine flags events but does not block, quarantine, or terminate any process. This is by design for an educational tool.
- **Windows-only collection** — the C++ agent uses Windows-specific APIs. The Python detection agent is cross-platform but requires an `EventLog.txt` produced on Windows.

---

## Technologies Used

- **C++17** — core agent implementation
- **Windows ETW (Event Tracing for Windows)** — kernel-level telemetry
- **TDH API (Trace Data Helper)** — structured event field extraction
- **Toolhelp32 API** — process enumeration and snapshots
- **Python 3.9+** — detection engine and output module (stdlib only)
- **Calude Sonnet 4.6** - Created this entire documentation. I hate documentations.

---

## License

TBH I don't know anything about license, make use of this at your heart's desire this is just a student project.Credit would be nice tho.
