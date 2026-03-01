# SeRestoreAbuse Modification

The previous version of this privilege escalation exploit utilized the SeRestorePrivilege to modify the registry key for the seclogon service. 

Executes a command as SYSTEM when SeRestorePrivilege is assigned. In case it's disabled, the program will enable it for you.

Usage: SeRestoreAbuse.exe "cmd /c ..."
