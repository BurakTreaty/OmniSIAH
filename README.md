# Mini Windows EDR Agent (Educational Project)

## Overview
This project demonstrates how an Endpoint Detection and Response (EDR) agent for Windows can collect security-relevant events, process telemetry, and apply detection logic.  
The goal is to showcase low-level defensive security engineering skills using **C/C++**, **Windows API**, and **event tracing mechanisms**.

⚠️ **Disclaimer**: This project is for educational purposes only. It should only be run in a controlled lab environment. Do not deploy on production systems.Virtual enviroment testing recommended, use at your own risk.

---

## Features
- **Process Monitoring**  
  - Capture process creation and termination events.
  - Collect parent/child relationship data.
  - Monitor dll loads and executions.
  - View system snapshot.
- **File Activity Logging**  
  - Monitor file create/delete/modify events.
- **Registry Monitoring**  
  - Detect suspicious registry changes (e.g., persistence mechanisms).
- **Detection Logic**  (Not complated)
  - Simple rule engine (e.g., alert if process spawns PowerShell or modifies `Run` registry keys).

---

## Architecture
- **Kernel/User Interaction**  
  - Use Windows Event Tracing (ETW) hooks for telemetry and TDH api for event inspection.
- **Components**  
  1. **Event Collector** – subscribes to ETW providers and uses `TDH` for process info writes logged event into raw data.
  2. **Detection Engine** – evaluates collected events against defined rules. Does not quarantine nor remove, simply marks as alert. 
  3. **Output Module** – Reads logged events and creates UI for user readablity.

---

- **Language**: C/C++
