/**

    @file      SeRestoreAbuse.h
    @author    @rhymenaucerous
        @brief     This is a modified version of the original SeRestoreAbuse PoC
               by @xct_de. The original code can be found here:
               https://github.com/xct/SeRestoreAbuse

    Exploit SeRestorePrivilege by modifying Seclogon ImagePath
    Author: @xct_de

**/
#pragma once

// Standard C includes
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

// Print error message with GetLastError()
#define PRINT_ERROR(fmt, ...)                                                  \
    DWORD error_code = GetLastError();                                         \
    char  error_message[256];                                                  \
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
                   NULL,                                                       \
                   error_code,                                                 \
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),                  \
                   error_message,                                              \
                   sizeof(error_message),                                      \
                   NULL);                                                      \
    fprintf_s(stderr,                                                          \
              "DEBUG: %s(): Line %d:\nError %lu: %sNote: " fmt "\n",           \
              __func__,                                                        \
              __LINE__,                                                        \
              error_code,                                                      \
              error_message,                                                   \
              __VA_ARGS__);

// End of file
