# Mini Windows EDR Agent (Educational Project)

## Overview
This project demonstrates how an Endpoint Detection and Response (EDR) agent for Windows can collect security-relevant events, process telemetry, and apply detection logic.  
The goal is to showcase low-level defensive security engineering skills using **C/C++**, **Windows API**, and **event tracing mechanisms**.

⚠️ **Disclaimer**: This project is for educational purposes only. It should only be run in a controlled lab environment. Do not deploy on production systems.

---

## Features
- **Process Monitoring**  
  - Capture process creation and termination events.
  - Collect parent/child relationship data.
- **File Activity Logging**  
  - Monitor file create/delete/modify events.
- **Registry Monitoring**  
  - Detect suspicious registry changes (e.g., persistence mechanisms).
- **Detection Logic**  
  - Simple rule engine (e.g., alert if process spawns PowerShell or modifies `Run` registry keys).
- **Logging and Alerting**  
  - Write structured logs (JSON) for further analysis.
  - Optional: send events to a local REST API for visualization.

---

## Architecture
- **Kernel/User Interaction**  
  - Use Windows Event Tracing (ETW) and/or native API hooks for telemetry.
- **Components**  
  1. **Event Collector** – subscribes to ETW providers or uses `CreateToolhelp32Snapshot` for process info.
  2. **Detection Engine** – evaluates collected events against defined rules.
  3. **Output Module** – logs events to file or forwards them via HTTP.

---

## Technologies
- **Language**: C/C++
- **APIs**:  
  - [Windows API](https://learn.microsoft.com/en-us/windows/win32/api/)
  - [Event Tracing for Windows (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-)
