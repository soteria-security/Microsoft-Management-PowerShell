<#
.SYNOPSIS
    Enable PowerShell and CMD line auditing on local machine
.DESCRIPTION
    This script sets the required values for enabling PowerShell and CMD line auditing
.EXAMPLE
    .\EnableCommandLineAuditing.ps1
.INPUTS
    None
.COMPONENT
    PowerShell and sufficient rights to change Registry items
.ROLE
    Administrator
.FUNCTIONALITY
    Gather information about Active Directory newly created accounts for the Monthly Dashboard
#>


​param([switch]$Elevated)
function Check-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }

if ((Check-Admin) -eq $false)  {
    if ($elevated)
        {
        # could not elevate, quit
    }
    else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}


#Enable Transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableTranscripting -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name OutputDirectory -Value "$env:USERPROFILE\Documents\PowerShell\Transcripts"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableInvocationHeader -Value 1

#Enable Module Logging
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -Value 1

#Enable Module Logging for all modules
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\" -Name * -Value *

#Enable CMD logging
Set-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1