<img width="1253" height="210" alt="image" src="https://github.com/user-attachments/assets/3a9a3c26-adcb-420c-ae09-aa20e6263175" />

&nbsp;

**Genesis EDR is an open-source Endpoint Detection and Response system for x64 Windows.** Designed for security researchers and learners; it serves as an **educational tool** and case study, but can also be used to test red team tooling.

You can find **detailed documentation** about the architectural design and implementation [here](https://emryll.gitbook.io/byte4byte/genesis).

>The project is currently in **early development**, alpha version is set to release in February/March 2026.

## Overview
The system runs off of patterns in a custom YAML-based DSL to describe behavior as a timeline of events. In addition YARA rules are used for YARA-X scans of memory and files.

The system is seperated into various different components, each with a distinct purpose. At the core of each endpoint is **the agent**; it centralizes telemetry collection, handles most of scans and their scheduling, manages the storage lifetime of data, and ultimately makes the decisions.

The rest of the components are purely for information that the agent can work with to make decisions. These include a **telemetry DLL**, **ETW consumer**, and a **kernel driver**

A sort of **swiss-cheese model** is implemented; there are various different tests and scans that can affect the score of a process or file. The idea is that one approach alone is not going to detect all malware, but when there are many approaches taken, it is far more likely that atleast one of these layers will catch malicious behavior.

### Features
- **System configuration files**
	- Configure system logic, scan intervals, define behavioral allow- and blocklists. 
- **Static analysis engine**
	- Automatically scans loaded files, scoring how likely it is to be malicious.
	- Supports manual scanning of arbitrary files.
- **Behavioral analysis engine**
	- Analyzes telemetry data and other metrics to detect malicious behavior patterns.
	- Uses a custom domain-specific language to describe arbitrary behavior flexibly and accurately.
- **API hooking**
	- Monitors system API usage, providing valuable visibility into process behavior.
	- *The system is designed with the assumption that these hooks could be bypassed.* 
- **Event Tracing for Windows**
	- Receives kernel events about file system activity, registry activity, and other critical behavior.
- **Kernel Callbacks**
	- Provides reliable, real-time telemetry about events such as process creation, thread creation, and opened handles.
- **Memory scanning**
	- Various types of memory scans targeting different portions of memory.
	- System automatically schedules memory scanning, along with allowing the operator to manually query scans of any usermode memory.
- **Thread scans**
	- Detect code injection by inspecting threads at creation and during global scans.
- **Handle-based detection**
	- Inspects handles to identify malicious activity both in real time and retrospectively.
- **Code injection detection**
	- Collection of mechanisms to detect various types of code injection.
- **Anti-tampering mechanisms**
	- Various mechanisms to prevent malware tampering with the detection system.
	- Heartbeat mechanisms to detect loss of critical components, particularly the ETW consumer or a telemetry DLL.
	- IAT and inline hook detection, which includes monitoring of own hooks.
	- Integrity checks of module memory via hashing

## How to use
> **Disclaimer!** Currently the project is a **work-in-progress**. It is **not yet ready for use** as a whole system. _There are many functional parts at this point, so parts of the system can be tested, but you will need to know what you're doing

To get started using the system, clone this repo and run the installer. To build from source, you will need C, C++, and Golang compilers and OpenSSL installed on your machine.
```bash
git clone https://github.com/emryll/edr.git
cd ./edr
go run installer.go
cd ./build
./agent.exe
```
