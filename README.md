# SeRestoreAbuse Exploit Modification

This is a modified version of @xct_de's SecLogon exploit (https://github.com/xct/SeRestoreAbuse).

## Table of Contents

- [Demo](#demo)
- [Prerequisites](#prerequisites)
- [Tested On](#tested-on)
- [Usage](#usage)
- [Build](#build)
- [Original Implementation](#original-implementation)
- [Current Implementation](#current-implementation)
  - [Code Smell](#code-smell)
  - [Functional Changes](#functional-changes)

<br>

## Demo

**1. Initial state — confirm `SeRestorePrivilege` is present:**

![Initial State](README_Images/InitialState.png)

<br>

**2. Running the exploit:**

![Attack](README_Images/Attack.png)

**Note:** The program's error output in the screenshot above is normal. This just means that the current user does not have permission to start services (or at least they do not have permission to start the `seclogon` service).

**Note:** The `seclogon` service is triggered to start by running a `runas` command. When `SeRestoreAbuse.exe` modifies the `ImagePath` registry key, the next time `seclogon` starts it will execute the binary — and a `runas` command is what causes it to start. If `seclogon` is already running when the exploit is attempted, the `runas` command will not have an effect because all it does is trigger service start. In that case, restart the workstation and run the `runas` command again after executing `SeRestoreAbuse.exe` (The service is manual start and must be triggered, it is not automatic start type by default).

<br>

**3. End state — `attacker` user created with password `password123` and added to Administrators:**

![End State](README_Images/EndState.png)

<br>

## Prerequisites

The running user must hold `SeRestorePrivilege`. Verify with:
```cmd
whoami /priv
```
The `seclogon` service must not be disabled (it defaults to **Manual** start on Windows).

<br>

## Tested On

Windows 10 Pro and Windows 11 Pro w/ Windows Defender and no AV/EDR.

<br>

## Usage

Run the compiled executable from an account that holds `SeRestorePrivilege`:

```cmd
SeRestoreAbuse.exe
```

On success, a local user `attacker` with password `password123` is added to the **Administrators** group and the `seclogon` `ImagePath` is restored to its default value.

<br>

## Original Implementation

### Description

The exploit works by using the user's SeRestorePrivilege (enabled or not) to update `seclogon`'s registry key in order to run malicious script as `SYSTEM`.

The original implementation allowed the user's command line arguments to be entered into the seclogon (a secondary logon service that is always running on Windows). The program would then run the following command which would restart the service:
```PowerShell
powershell -ep bypass -enc ZwBlAHQALQBzAGUAcgB2AGkAYwBlACAAcwBlAGMAbABvAGcAbwBuACAAfAAgAHMAdABhAHIAdAAtAHMAZQByAHYAaQBjAGUA
```

<br>

Which, when decoded, is translated to:
```PowerShell
get-service seclogon | start-service
```

<br>

### Limitations

When I tested this on a Windows 11 Pro workstation, the program did update the registry key's `ImagePath` data but when `seclogon` was restarted, the service control manager (SCM) wasn't able to finish running the command. For instance, when running:
```cmd
cmd /c "whoami > C:\yeet.txt"
```

<br>

The file would be created but not filled. And when creating a user using different variations of the command below, they were not successfully created. It's possible that this was due to my environment and is a race condition for the exploit.
```cmd
cmd /c "net user /add attacker password123"
```

<br>

## Current Implementation

The current implementation does a couple of things differently.

### Code Smell

1. The language was changed from C++ to C.
1. The runtime library was changed to /MT and /MTd for Release and Debug versions, respectively. This allows for execution on systems that do not have Visual Studio dlls.
1. Each API call will print status information to the screen on failure in both Release and Debug builds.

<br>

### Functional Changes

1. On success, the `ImagePath` will be reset follow command completion. This will allow `seclogon` to run normally after the program is done.
1. The service is started using Win32 API calls instead of a single system() API call.
1. The program does not take command line arguments. It will create a user, `attacker` with a password, `password123` regardless of command line arguments used. These commands are run as SYSTEM and can be customized by modifying `COMMAND_1` and `COMMAND_2` at the top of `SeRestoreAbuse.c`.

<br>

## Build

Open `SeRestoreAbuse.sln` in Visual Studio and build the **Release** or **Debug** configuration for **x64**. The Release build uses `/MT` (static CRT), producing a standalone executable with no Visual Studio DLL dependencies.

To customize the commands run as SYSTEM, edit `COMMAND_1` and `COMMAND_2` at the top of `SeRestoreAbuse.c` before building.

<br>

**End of file**
