# Ghost Anti-Debugger

<p align="center">
<img src="https://i.pinimg.com/736x/53/a4/f3/53a4f382ab8d8a997edf2566fa726e54.jpg", width="500", height="500">
</p>

## Overview

Ghost Anti-Debugger is a Python-based tool designed to detect debugging environments and virtual machines (VMs) that may be used for reverse engineering or malicious analysis. This tool employs various techniques to identify the presence of debuggers and VMs, and it can trigger specific actions, such as logging the event or simulating a blue screen crash.

## Features

- **Debugger Detection**: Identifies common debuggers like OllyDbg, Wireshark, Fiddler, and others using process checks.
- **Virtual Machine Detection**: Detects if the program is running inside a virtual machine, including VMware and VirtualBox.
- **HWID Blacklist**: Checks the hardware ID against a blacklist to prevent execution on known malicious or compromised systems.
- **Logging**: Logs debugger detection events to a file for further analysis.
- **Internet Connectivity Check**: Ensures the program has internet access before proceeding with execution.
- **Blue Screen Simulation**: Triggers a simulated blue screen of death (BSOD) in case of debugger detection.

## Requirements

- Python 3.x
- Windows operating system (due to the use of Windows-specific APIs)

## Important Notes

- **Ethical Use**: This tool is intended for educational purposes and should be used 
ethically. Do not use it against systems without proper authorization.
- **False Positives**: The tool may produce false positives in certain environments. Always verify the results manually.
- **Customization**: You can modify the list of processes and actions taken when a debugger or VM is detected according to your needs.
