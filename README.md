<img width="750" height="150" alt="image" src="https://github.com/user-attachments/assets/3150a309-cb07-4165-ad4b-84db2fdbf00a" />


**Genesis EDR is an open-source EDR system for x64 Windows**. The project is currently in **early-development**, alpha version is scheduled to release in February/March 2026. This project serves as an **educational** tool and case-study. You can find **detailed documentation** at https://emryll.gitbook.io/byte-for-byte/genesis

The system runs off of patterns in a custom YAML-based DSL to describe behavior as a timeline of events. In addition YARA rules are used for YARA-X scans of memory and files.

The system is seperated into various different components, each with a distinct purpose. At the core of each endpoint is **the agent**; it centralizes telemetry collection, handles most of scans and their scheduling, manages the storage lifetime of data, and ultimately makes the decisions.

The rest of the components are purely for information that the agent can work with to make decisions. These include a **telemetry DLL**, **ETW consumer**, and a **kernel driver**

A sort of **swiss-cheese model** is implemented; there are various different tests and scans that can affect the score of a process or file. The idea is that one approach alone is not going to detect all malware, but when there are many approaches taken, it is far more likely that atleast one of these layers will catch malicious behavior.

## How to use
> Currently the project is a work-in-progress. It is not yet ready for use as a whole system. _There are many functional parts at this point, so parts of the system can be tested, but you will need to know what you're doing

To get started using the system, clone this repo and run the installer. To build from source, you will need C, C++, and Golang compilers and OpenSSL installed on your machine. 
```
git clone https://emryll/edr.git
cd ./edr
go run installer.go
cd ./build
./agent.exe
```
