# Microsoft Entra

# Purpose
Scripts provided are intended to assist administrators in auditing and managing their Microsoft Windows environment.


# Scripts
- EnableCommandLineAuditing: Enable PowerShell and CMD line auditing on local machine. Requires sufficient permissions (Local Administrator) on the current device.

```
# Execution Example:
.\EnableCommandLineAuditing.ps1
```
- PC-Info: Menu-driven interactive script that enables IT staff to check and return a series of information and queries about any machine.

```
<# Functions in this script do the following:
Function Name		Description
------------        ------------
Online              Checks for connectivty to the device and ensures that the WSMan services are running. If not, directs you to select another host
GetInfo				Gathers information about the target device - OS Version, Physical/Logical Disks, Mapped Drives, Current User and Active Remote Sessions
Winlog				Checks for AutoLogin configuration
Printers			Checks for all installed printers both system wide and for the current logged in user
NetPrint            Checks for installed network priters - is called in the Printers Function and not run by itself
localadmins		    Gets the full list of local admins on the target device
Hotfix				Gets installation status of a specified hotfix, or gets all installed Hotfixes/Patches on the target system
MappedDrive         Lists all mapped drives for the current user
RemoteSessions      Checks for and lists all Active Remote Sessions on the device
hostsFile           Reads the hosts file on the target machine
RSOP				Gets Resultant Set of Policy on the currently logged in user
Lookup              Prompts for the Computer Name or IP address to lookup
ExecutionPolicy		Returns the value of the PowerShell ExecutionPolicy configuration - Only works when explicit credentials are provided, or when using hostname (not IP Address)
listAllUsers		Lists all User Profiles on the machine under C:\Users
Extensions          Lists all browser extensions for the currently logged on user
AllFunction         Runs all functions in the script
InstalledSoftware   Gathers and displays list of all installed software on the machine
ProcessList         Lists all processes on the machine - Pops out in new window
Show-Menu           Displays the menu options
Help                Shows this block of information
#>

# Execution Example:
.\PC-Info.ps1
```