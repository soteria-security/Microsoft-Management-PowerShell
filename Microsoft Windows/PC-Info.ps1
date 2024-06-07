<#
.SYNOPSIS
    Gather information about a machine
.DESCRIPTION
    Check and return a series of information and queries about any machine
.EXAMPLE
    .\PC-Info.ps1
.INPUTS
    Computer name is required
.COMPONENT
    PowerShell and WMI
.ROLE
    None
.FUNCTIONALITY
    Gather information about a machine
#>

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


function Show-Menu
{
     param (
           [string]$Title = 'PC Lookup Tool'
     )
     Clear-Host
     Write-Host "              ================ $Title ================"
	 
 	 Write-Host "             ________________________________________________ "
 	 Write-Host "            /                                                \ "
 	 Write-Host "           |    _________________________________________     | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |  C:\> _                                 |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   | Author - ThoughtContagion/Carl Littrell |    | "
 	 Write-Host "           |   | Title - Button Masher                   |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |                                         |    | "
 	 Write-Host "           |   |_________________________________________|    | "
 	 Write-Host "           |                                                  | "
 	 Write-Host "            \_________________________________________________/ "
 	 Write-Host "                   \___________________________________/ "
 	 Write-Host "                ___________________________________________ "
 	 Write-Host "             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_ "
 	 Write-Host "          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_ "
 	 Write-Host "       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_ "
 	 Write-Host "    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_ "
 	 Write-Host " _-'.-.-.-.-.-. .---.-. .-------------------------. .-.---. .---.-.-.-.`-_ "
 	 Write-Host ":-------------------------------------------------------------------------: "
 	 Write-Host "`---._.-------------------------------------------------------------._.---' "   
     Write-Host ""
     Write-Host ""
     Write-Host ""
     Write-Host ""
     Write-Host "Press '1' to gather information about the device including the currently logged on user."
     Write-Host "Press '2' to see if the device is configure for autologon."
     Write-Host "Press '3' to see all mapped drives for the currently logged on user."
	 Write-Host "Press '4' to find all active remote sessions on the device."
	 Write-Host "Press '5' to view all installed printers - local and network."
	 Write-Host "Press '6' to find all members of local admin groups."
	 Write-Host "Press '7' to view the hosts file of the machine."
	 Write-Host "Press '8' to return the PowerShell Execution Policy configuration."
	 Write-Host "Press '9' to view hotfixes (patches) on the machine. Allows for individual search or all installed patches."
	 Write-Host "Press '10' to return Resultant Set of Policy for the currently logged on user."
	 Write-Host "Press '11' to list all User Profiles on the machine."
     Write-Host "Press '12' to list all installed software on the machine"
     Write-Host "Press '13' to list all processes on the machine"
     Write-Host "Press '14' to list Firefox and Chrome Browser extensions for the currently logged on user."
     Write-Host "Press '15' for All Modules."
     Write-Host "Press '16' to lookup another computer."
     Write-Host "Press 'H' to Show Help."
     Write-Host "Press 'Q' to quit."
}

function Lookup {
    $global:compName = Read-Host -Prompt "Enter PC Name or IP Address"
    Online
    }

function Winlog{
	$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $compName)
	$RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
	$enabled = $RegKey.GetValue("AutoAdminLogon")
	$name = $RegKey.GetValue("DefaultUserName")
	$pass = $RegKey.GetValue("DefaultPassword")
	$domain = $RegKey.GetValue("DefaultDomainName")
	##Check to see if Autologon is enabled
	if ($enabled -eq "1"){
			$ans = "Yes"}
	else{
			$ans = "No"}

	write-host "Autologin Enabled: $ans" 
		##Get information
		if ($ans -eq "Yes"){
				write-host "Login Name: $name" 
				write-host "Login Password: $pass" 
				write-host "Login Domain: $domain"}
		else{
				write-host "$compName is not configured for Autologin."}
		}

Function NetPrint{
	$currentusersid = Get-WmiObject -ComputerName $compName -Class win32_computersystem |
	Select-Object -ExpandProperty Username |
	ForEach-Object { ([System.Security.Principal.NTAccount]$_).Translate([System.Security.Principal.SecurityIdentifier]).Value }
	$netPrint = REG QUERY "\\$compName\HKU\$currentusersid\Printers\Connections"
	$np = $netPrint | Out-String
	$pos = $np.IndexOf(",,")
	$NPrinters = $np.Substring($pos+1)
	Write-Host "Installed Network Printers `r`n"
	ForEach ($print in $NPrinters){
	Write-Host "$print"}
	}

function Printers{	
		Get-WMIObject Win32_Printer -ComputerName $compName | Select-Object name
		NetPrint
	}

function GetInfo {
		Get-WmiObject -Class Win32_ComputerSystem -ComputerName $compName
		
		#Get OS Version
		Get-WMIObject -Class Win32_OperatingSystem -ComputerName $compName | Select-Object Description
		Get-WMIObject -Class Win32_OperatingSystem -ComputerName $compName | Select-Object Caption
		Get-WMIObject -Class Win32_OperatingSystem -ComputerName $compName | Select-Object OSArchitecture
		Get-WMIObject -Class Win32_OperatingSystem -ComputerName $compName | Select-Object ServicePackMajorVersion
		$version = Reg Query "\\$compName\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ReleaseId
		$verInfo = $version | out-string
		$pos = $verInfo | select-string -pattern '....'
		$verid = $pos -match '[0-9][0-9][0-9][0-9]'
		Write-Host "OS Version ID :" $matches[0]
		Write-Host " "
		
		
		#Get currently logged on user
        try{
		    $loggedinUser = Get-WmiObject -Class Win32_ComputerSystem -Property UserName -ComputerName $compName | Select-Object -ExpandProperty UserName
		    Write-Host "Username: $loggedinUser"
            Write-Host ""
       
            #Trim Domain from the returned username
            $loggedinUser = $loggedinUser.substring(3)
		
            #Query Active Directory for the Users Name property 
            $currentUser = get-aduser $loggedinuser | Select-Object -ExpandProperty name
            Write-Host "DisplayName: $($currentUser)"
            Write-Host ""
            Write-Host ""
            }
       catch {
            Write-Host "No Currently logged on user"
            Write-Host ""
            Write-Host ""
            }


		Write-Host ""

		$colItems = Get-WmiObject -class "Win32_NetworkAdapterConfiguration" -computername $compName | Where {$_.IPEnabled -Match "True"}
			foreach ($objItem in $colItems) {
				#Clear-Host
				Write-Host "MAC Address: " $objItem.MACAddress
				Write-Host "IPAddress: " $objItem.IPAddress
				Write-Host "IPEnabled: " $objItem.IPEnabled
				Write-Host "DNS Servers: " $objItem.DNSServerSearchOrder
				Write-Host "DNS Suffixes:" $objItem.DNSDomainSuffixSearchOrder
				Write-Host ""
			}
        
        $disks = Get-WmiObject -query "select * from Win32_LogicalDisk where DriveType='3'" -ComputerName $compName

		#Get disk information
		foreach ($disk in $disks)
			{
			$diskname = $disk.caption
			"$compName $diskname drive has {0:#.0}GB free of {1:#.0}GB Total Disk Space " -f ($disk.FreeSpace/1GB),($disk.Size/1GB) | write-output 
			}
			
	}

function MappedDrive{
	gwmi win32_mappedlogicaldisk -ComputerName $compName | Select-Object SystemName,Name,ProviderName,SessionID | ForEach-Object { 
    	$mapdisk = $_
	    $user = gwmi Win32_LoggedOnUser -ComputerName $compName | Where-Object { ($_.Dependent.split("=")[-1] -replace '"') -eq $mapdisk.SessionID} | ForEach-Object {$_.Antecedent.split("=")[-1] -replace '"'}
    	$mapdisk | Select-Object Name,ProviderName,@{n="MappedTo";e={$user} }
		}
	}

function RemoteSessions {
    #Check for Remote Sessions
    Write-Host "Checking for Remote Sessions..."
    #Code in the try/catch below borrowed from https://gallery.technet.microsoft.com/scriptcenter/Get-LoggedOnUser-Gathers-7cbe93ea - All credit to Jaap Brasser
	try {
	    quser /server:$compName 2>&1 | Select-Object -Skip 1 | ForEach-Object {
		    $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s'
			$HashProps = @{
				UserName = $CurrentLine[0]
				ComputerName = $compName
			}

		# If session is disconnected different fields will be selected
		if ($CurrentLine[2] -eq 'Disc') {
			$HashProps.SessionName = $null
			$HashProps.Id = $CurrentLine[1]
			$HashProps.State = $CurrentLine[2]
			$HashProps.IdleTime = $CurrentLine[3]
			$HashProps.LogonTime = $CurrentLine[4..6] -join ' '
			$HashProps.LogonTime = $CurrentLine[4..($CurrentLine.GetUpperBound(0))] -join ' '
			} 
         else {
			$HashProps.SessionName = $CurrentLine[1]
			$HashProps.Id = $CurrentLine[2]
			$HashProps.State = $CurrentLine[3]
			$HashProps.IdleTime = $CurrentLine[4]
			$HashProps.LogonTime = $CurrentLine[5..($CurrentLine.GetUpperBound(0))] -join ' '
			}

		    New-Object -TypeName PSCustomObject -Property $HashProps |
		    Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
		    }
	    } 
    catch {
		New-Object -TypeName PSCustomObject -Property @{
			ComputerName = $compName
			Error = $_.Exception.Message
			} | Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
			Write-Host "No Remote Sessions Detected."
	    }
}

function Hotfix{
	$hfix = read-host -prompt "Would you like to check for a specific installed Hotfix? (Y/N)"
	if ($hfix -eq "Y" -or $hfix -eq "y"){
    	$kb = Read-Host -Prompt "Enter the KB you wish to search for: (Include the KB in the name)"
        try {
		    Get-Hotfix -ComputerName $compName -id $kb -ErrorAction Stop
            }
        catch [System.Management.Automation.RuntimeException] {
            Write-Host "Hotfix does not appear to be installed."
            }
        Continue
		Write-Host ""}
	elseif ($hfix -eq "N" -or $hfix -eq "n"){
	$allKB = Read-Host -prompt "Would you like to see all installed hotfixes? (Y/N)"
		if ($allKB -eq "Y" -or $allKB -eq "y"){
			Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $compName}
			}
	}

function RSOP{
		Get-GPResultantSetOfPolicy -ReportType Html -Path $psscriptroot\RSOP\$compName-rsop.html
	}	

function localadmins{
  $group = get-wmiobject win32_group -ComputerName $compName -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
  $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
  $list = Get-WmiObject win32_groupuser -ComputerName $compName -Filter $query
  $list | ForEach-Object{$_.PartComponent} | ForEach-Object {$_.substring($_.lastindexof("Domain=") + 7).replace("`",Name=`"","\")}
    }

function hostsFile{
	#Credit to brendanevans from Discord channel Coding Community

	$File = "\\$compName\c$\Windows\System32\Drivers\etc\hosts"

	(Get-Content -Path $File) | ForEach-Object {
		If ($_ -match '^(?<IP>\d{1,3}(\.\d{1,3}){3})\s+(?<Host>.+)$') {
		Write-Output "$($Matches.IP),$($Matches.Host)"
			}
		}
	}

function ExecutionPolicy{
    Invoke-Command -ComputerName $compName -ScriptBlock {
        try {
            Get-ExecutionPolicy 
	        Write-Host ""
            }
        catch {
            Write-Host "WinRM is not enabled on this machine."
            }
	    }
}

function listAllUsers {
	Get-ChildItem "\\$compName\c$\Users\" -Attributes directory | Select-Object name | Write-Host
    }

function ProcessList {
    try{
        Get-Service -ComputerName $compName | Select-Object name, displayname, status | Format-Table -auto
    }catch{
        [System.Windows.MessageBox]::Show($_.exception.message,"Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
    }
}

function Extensions {
    try {
        $loggedinUser = Get-WmiObject -Class Win32_ComputerSystem -Property UserName -ComputerName $compName | Select-Object -ExpandProperty UserName
        Write-host "Getting the current user..."
        #Trim Domain from the returned username
        $User = $loggedinUser.substring(3)
        Write-Host ""
        Write-Host "Current logged in User: $User"
        Write-Host ""
        }
    catch {
        Write-Host "No Currently logged on user"
        }


if ($user -ne $null){

    write-host "Getting FireFox Extensions..."

    Get-ChildItem \\$compName\c$\users\$user\AppData\Roaming\Mozilla\Firefox\Profiles -Recurse -Filter Addons.json | ForEach-Object {(Get-Content $_.FullName | ConvertFrom-Json).addons | Select  name, description, sourceURI, id, version | fl}

    sleep 2

    Write-host "Getting Chrome Extensions..."

    Get-ChildItem "\\$compName\c$\users\$user\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Recurse -Filter Manifest.json | ForEach-Object { Get-content $_.FullName -Raw | ConvertFrom-Json | select name, container, description, version | fl}

    }
else {
    Write-Host "No logged in user to query"
    Write-Host ""
    Write-Host ""
    }
}

function InstalledSoftware {
    #Invoke-Command -cn $compName -ScriptBlock {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | select DisplayName, Publisher, InstallDate}
    wmic /node:$compName product get name,version,vendor,installdate
    }

function AllFunction{
	GetInfo
	Winlog
    MappedDrive
    RemoteSessions
	Printers
	localadmins
    hostsFile
    ExecutionPolicy
    Extensions
    InstalledSoftware
    ProcessList
	Hotfix
	RSOP
	listAllUsers
	}

function Help {
    Write-Host "
        Functions in this script do the following:

        Function Name       Description
        ------------        ------------
        GetInfo             Gathers information about the target device - OS Version, Physical/Logical Disks, Mapped Drives, Current User and Active Remote Sessions
        Winlog              Checks for AutoLogin configuration
        Printers            Checks for all installed printers both system wide and for the current logged in user
        NetPrint            Checks for installed network priters - is called in the Printers Function and not run by itself
        get-localadmins     Gets the full list of local admins on the target device
        Hotfix              Gets installation status of a specified hotfix, or gets all installed Hotfixes/Patches on the target system
        MappedDrive         Lists all mapped drives for the current user
        RemoteSessions      Checks for and lists all Active Remote Sessions on the device
        hostsFile           Reads the hosts file on the target machine
        RSOP                Gets Resultant Set of Policy on the currently logged in user
        Lookup              Prompts for the Computer Name or IP address to lookup
        ExecutionPolicy     Returns the value of the PowerShell ExecutionPolicy configuration - Only works when explicit credentials are provided, or when using hostname (not IP Address)
        listAllUsers        Lists all User Profiles on the machine under C:\Users
        Extensions          Lists all installed Firefox and Chrome browser extensions for the currently logged on user
        AllFunction         Runs all functions in the script
        InstalledSoftware   Lists all installed software on the machine
        ProcessList         Lists all processes on the machine - Pops out in new window
        Show-Menu           Displays the menu options
        Help                Shows this block of information
        "
        }

function online {
    if (Test-Connection -ComputerName $compName -quiet){
        Write-Host "$compName is online. Checking for Remote Management capabilities..."
        if (Test-WSMan -ComputerName $compName -ErrorAction SilentlyContinue){
            Write-Host ""
            Write-Host "WSMan is enabled."
            Write-Host ""
            }
        else {
            Write-Host ""
            Write-Host "WSMan is not enabled."
            $choose = Read-Host -Prompt "Continue anyway? (Y|N)"
            Start-Sleep 3
            Write-Host ""
            Write-Host "Launching Menu..."
            Start-Sleep 1
            Write-Host ""
            if ($choose -eq 'Y' -or $choose -eq 'y'){
                }
            else {
                Write-Host "Pick another Target."
                Start-Sleep 1
                Lookup
            }
        }
    else {
        Write-Host $compName "is not online."
        Write-Host ""
        Lookup
            }
        }
    }


Lookup

do
 {

    Show-Menu
    
    $selection = Read-Host "Please make a selection"
    
    switch ($selection)
        {
          '1' {
        'Gathering Info'
        GetInfo
        } '2' {
        'Checking for Autolog configuration'
        Winlog
        } '3' {
        'Checking Mapped Drvies'
        MappedDrive
        } '4' {
        'Checking for Remote Sessions'
        RemoteSessions
        } '5' {
        'Gathering installed printers'
        Printers
        } '6' {
        'Enumerating Local Admins'
        localadmins
        } '7' {
        'Reading Hosts file'
        hostsfile
        } '8' {
        'Reading PowerShell ExecutionPolicy'
        ExecutionPolicy
        } '9' {
        'Gathering installed hotfixes'
        Hotfix
        } '10' {
        'Getting RSOP of current user'
        RSOP
        } '11' {
        'Listing User Profiles'
        listAllUsers
         } '12' {
        'Gathering all installed software'
        InstalledSoftware
         } '13' {
        'Gathering all Processes on the machine'
        ProcessList
        } '14' {
        'Getting installed Browser Extensions'
        Extensions
        } '15' {
        'Running all modules'
        AllFunction
        } '16' {
        Lookup
        } 'H' {
        Help
        }
        }
        pause
 }
 until ($selection -eq 'q')