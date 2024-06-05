<#
.SYNOPSIS
    Emergency Active Directory Password Reset - All users, Built-In Admin, Guest and Kerberos accounts included.
.DESCRIPTION
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change for standard users, reset passwords for Built-In accounts
.INPUTS
    None
.COMPONENT
    PowerShell Active Directory Module
.ROLE
    Sufficient AD rights to manage user objects
.FUNCTIONALITY
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change for standard users, reset passwords for Built-In accounts
#>

Function Invoke-EmergencyReset {
    param (
        [Parameter(Mandatory = $false,
            HelpMessage = 'Exclude the Specified Inspectors and run all others')]
        [string[]] $ExcludedUsers = @()
    )

    $builtin = @()
        
    $SIDs = @("-501", "-500", "-502")

    Foreach ($SID in $SIDs) {
        $domainSID = (Get-ADDomain).DomainSID.Value

        $builtin += Get-AdUser -LDAPFilter "(&(objectSID=$($domainSID + $SID)))"

        If ($SID -eq "-501") {
            $guest = Get-AdUser -LDAPFilter "(&(objectSID=$($domainSID + $SID)))"

            If ($guest.enabled) {
                Write-Host "Guest account is enabled. Disabling..."
                Set-ADUser $guest.samaccountName -Enabled:$false
            }
            Else {
                Write-Host "Guest Account is disabled. (Recommended) `nContinuing..."
            }
        }
    }
    Function Kerberos-Set {
        Foreach ($account in $builtin.samaccountName) {
            function Pass { 
                #Generate Password
                Add-Type -AssemblyName 'System.Web'
                $minLength = 120 ## characters
                $maxLength = 128 ## characters
                $length = Get-Random -Minimum $minLength -Maximum $maxLength
                $nonAlphaChars = 5
                $password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
                
                Write-Host "New password for $($account) is $password"

                $password2 = ConvertTo-SecureString -AsPlainText $password -Force
                
                Return $password2
                
            }

            Set-ADAccountPassword -Identity $account -NewPassword (Pass)
        }
    }


        
    Function User-Set {
        $users = @()

        $min = Read-Host -Prompt "Enter the minimum number of characters"
        $max = Read-Host -Prompt "Enter the maximum number of characters"

        $allUsers = Get-AdUser -Filter *
            
        ForEach ($acct in $allUsers) {
            If (($SIDs -notcontains $acct.SID) -and ($ExcludedUsers -notcontains $acct.SamAccountName)) {
                $users += $acct
            }
            
        
            ForEach ($user in $users) {
                function Pass { 
                    #Generate Password
                    Add-Type -AssemblyName 'System.Web'
                    $minLength = $min
                    $maxLength = $max
                    $length = Get-Random -Minimum $minLength -Maximum $maxLength
                    $nonAlphaChars = 5
                    $password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
                    
                    Write-Host "New Password for $($user.samaccountName) is $password"

                    $password2 = convertto-securestring $password -AsPlainText -Force
                    
                    Return $password2
                    
                }

                Set-ADAccountPassword -Identity $user.samaccountName -NewPassword (Pass)

                Set-ADUser $user.samaccountName -PasswordNeverExpires $false

                Set-ADUser $user.samaccountName -ChangePasswordAtLogon $true
            }
        }
    }

    User-Set

    Kerberos-Set
}

Function Write-Banner {
    Write-Host @'                                                                                                                                         

    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒██░░░░░░░░░░░░
    ░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░
    ░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░
    ░░░░░░░░██░░░░██████░░░░████░░░░░░██░░██░░██████░░██░░░░████░░░░██░░██░░░░░░██░░░░░░
    ░░░░████░░░░░░██░░██░░░░██████░░░░██░░██░░░░██░░░░██░░██░░░░██░░██░░██░░░░░░░░██░░░░
    ░░████░░░░░░░░██░░░░░░░░██████░░░░██░░██░░░░██░░░░██░░██░░░░██░░██████░░░░░░░░░░██░░
    ░░██░░░░░░░░░░██░░░░░░░░██░░██░░░░██░░██░░░░██░░░░██░░██░░░░██░░██████░░░░░░░░░░░░██
    ░░██░░░░░░░░░░██░░░░░░████░░████░░██░░██░░░░██░░░░██░░██░░░░██░░██████░░░░░░░░░░░░██
    ░░██░░░░░░░░░░██░░░░░░██████████░░██░░██░░░░██░░░░██░░██░░░░██░░██████░░░░░░░░░░██░░
    ░░░░██░░░░░░░░██░░██░░██░░░░▒▒██░░██░░██░░░░██░░░░██░░██░░░░██░░██░░██░░░░░░░░██░░░░
    ░░░░░░██▒▒░░░░██████░░██░░░░░░██░░██████░░░░██░░░░██░░████████░░██░░██░░░░░░██░░░░░░
    ░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░
    ░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░
    ░░░░░░░░░░░░░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░
    ░░░░░░░░░░░░░░██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░██▒▒░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░██▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░▓▓██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░▓▓██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

   _____ _   _ ___ ____    ____   ____ ____  ___ ____ _____   __  __    _ __   __  ____  _____   ____  _____ ____ _____ ____  _   _  ____ _____ _____     _______ _ 
  |_   _| | | |_ _/ ___|  / ___| / ___|  _ \|_ _|  _ \_   _| |  \/  |  / \\ \ / / | __ )| ____| |  _ \| ____/ ___|_   _|  _ \| | | |/ ___|_   _|_ _\ \   / / ____| |
    | | | |_| || |\___ \  \___ \| |   | |_) || || |_) || |   | |\/| | / _ \\ V /  |  _ \|  _|   | | | |  _| \___ \ | | | |_) | | | | |     | |  | | \ \ / /|  _| | |
    | | |  _  || | ___) |  ___) | |___|  _ < | ||  __/ | |   | |  | |/ ___ \| |   | |_) | |___  | |_| | |___ ___) || | |  _ <| |_| | |___  | |  | |  \ V / | |___|_|
   _|_| |_|_|_|___|____/__|____/ \____|_|_\_\___|_|    |_|___|_|__|_/_/ _ \_\_|__ |____/|_____|_|____/|_____|____/_|_| |_| \_\\___/ \____| |_| |___|  \_/  |_____(_)
  |  _ \|  _ \ / _ \ / ___| ____| ____|  _ \  \ \      / /_ _|_   _| | | |  / ___|  / \ | | | |_   _|_ _/ _ \| \ | | |                                              
  | |_) | |_) | | | | |   |  _| |  _| | | | |  \ \ /\ / / | |  | | | |_| | | |     / _ \| | | | | |  | | | | |  \| | |                                              
  |  __/|  _ <| |_| | |___| |___| |___| |_| |   \ V  V /  | |  | | |  _  | | |___ / ___ \ |_| | | |  | | |_| | |\  |_|                                              
  |_|   |_| \_\\___/ \____|_____|_____|____/     \_/\_/  |___| |_| |_| |_|  \____/_/   \_\___/  |_| |___\___/|_| \_(_)                                              
                                                                                                                
'@
}

Clear-Host

Write-Banner

Do {
    Write-Host "This script is designed to perform a complete reset of all account passwords in the event of an Active Directory Compromise.`nOnly proceed if you understand this will have a tremendous impact on the environment.`n`nSCRIPT IS PROVIDED AS-IS AND WE ASSUME NO LIABILTY OR RESPONSIBILITY FOR THE USE OR MISUSE OF THIS SCRIPT OR ANY PART OF THIS SCRIPT.`n`n"
    $acknowledge = Read-Host "Type 'I AGREE' to proceed (case sensitive) or Q to quit "

    If ($acknowledge -ceq 'I AGREE') {
        Clear-Host
        Invoke-EmergencyReset
    }
    ElseIf ($acknowledge -eq 'Q') {
        Break
    }
    Else {
        Write-Warning "Input was incorrect."
    }
}
Until ($acknowledge -ceq 'I AGREE')