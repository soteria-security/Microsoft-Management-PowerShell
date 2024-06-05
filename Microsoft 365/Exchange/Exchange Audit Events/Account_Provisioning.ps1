param (
    [Parameter(Mandatory = $true,
        HelpMessage = 'First Name')]
    [string] $firstName,
    [Parameter(Mandatory = $true,
        HelpMessage = 'Last Name')]
    [string] $lastName,
    [Parameter(Mandatory = $true,
        HelpMessage = 'Mail Domain')]
    [string] $domain,
    [Parameter(Mandatory = $true,
        HelpMessage = 'Start Date')]
    [datetime] $startDate,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Department')]
    [string] $department,
    [Parameter(Mandatory = $false,
        HelpMessage = "User's Manager (email format)")]
    [string]$userManager
)

Connect-MgGraph -ContextScope Process -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "GroupMember.ReadWrite.All", "Group.ReadWrite.All", "Directory.AccessAsUser.All"
Connect-ExchangeOnline

$email = "$($firstName[0])$lastName@$domain"

add-type -AssemblyName System.Web

Function Generate-Password {
    Function Get-RandomCharacters($length, $characters) {
        $random = 3..$length | ForEach-Object { Get-Random -Maximum $characters.length }
        $private:ofs = ""
        return [String]$characters[$random]
    }
     
    Function Scramble-String([string]$inputString) {     
        $characterArray = $inputString.ToCharArray()   
        $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
        $outputString = -join $scrambledStringArray
        return $outputString 
    }
    
    $pwrange = 14..25
    $newRange = Get-Random $pwrange
    
    $password = Get-RandomCharacters -length $newRange -characters 'abcdefghiklmnoprstuvwxyz'
    $password += Get-RandomCharacters -length 6 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $password += Get-RandomCharacters -length 4 -characters '1234567890'
    $password += Get-RandomCharacters -length 3 -characters '!$%&=?@#+'
    
    $password = Scramble-String $password

    Write-Host "New account is: " -NoNewline
    Write-Host "$email" -ForegroundColor Red
    Write-Host "`nNew account password is: " -NoNewline
    Write-Host "$password" -ForegroundColor Red
    Write-Host "`nRemember to save these credentials to 1Password!" -ForegroundColor Yellow
	
    return $Password
}

$password = Generate-Password

Function Set-ExchangeAuditLogs {
    $AuditAdmin = @('AddFolderPermissions', 'ApplyPriorityCleanup', 'ApplyRecord', 'AttachmentAccess', 'Copy', 'Create', 'FolderBind', 'HardDelete', 'MailItemsAccessed', 'ModifyFolderPermissions', 'Move', 'MoveToDeletedItems', 'PriorityCleanupDelete', 'RecordDelete', 'RemoveFolderPermissions', 'Send', 'SendAs', 'SendOnBehalf', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateComplianceTag', 'UpdateFolderPermissions', 'UpdateInboxRules')

    $AuditDelegate = @('AddFolderPermissions', 'ApplyPriorityCleanup', 'ApplyRecord', 'AttachmentAccess', 'Create', 'FolderBind', 'HardDelete', 'MailItemsAccessed', 'ModifyFolderPermissions', 'Move', 'MoveToDeletedItems', 'PriorityCleanupDelete', 'RecordDelete', 'RemoveFolderPermissions', 'SendAs', 'SendOnBehalf', 'SoftDelete', 'Update', 'UpdateComplianceTag', 'UpdateFolderPermissions', 'UpdateInboxRules')

    $AuditOwner = @('AddFolderPermissions', 'ApplyPriorityCleanup', 'ApplyRecord', 'AttachmentAccess', 'Create', 'HardDelete', 'MailboxLogin', 'MailItemsAccessed', 'ModifyFolderPermissions', 'Move', 'MoveToDeletedItems', 'PriorityCleanupDelete', 'RecordDelete', 'RemoveFolderPermissions', 'SearchQueryInitiated', 'Send', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateComplianceTag', 'UpdateFolderPermissions', 'UpdateInboxRules')

    Set-Mailbox -Identity $email -AuditEnabled $true -AuditLogAgeLimit 365 -AuditAdmin @{add = $AuditAdmin } -AuditDelegate @{add = $AuditDelegate } -AuditOwner @{add = $AuditOwner }
}

Function New-MSUser {
    
    If ($userManager) {
        $manager = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/users?Filter=userPrincipalName eq '$userManager'").value.id

        $body = @{
            accountEnabled    = $true
            displayName       = "$firstname $lastname"
            givenName         = $firstname
            surname           = $lastname
            mailNickname      = $(($email -split '@')[0])
            userPrincipalName = $email
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $true
                password                      = $password
            }
            usageLocation     = "US"
            userType          = "Member"
            department        = $Department
            Mail              = $email
        }

        Invoke-GraphRequest -Method Post -Uri "https://graph.microsoft.com/beta/users" -ContentType "application/json" -Body ($body | ConvertTo-Json)

        Invoke-GraphRequest -Method PUT -Uri "https://graph.microsoft.com/beta/users/$email/manager/`$ref" -ContentType "application/json" -Body "{`"@odata.id`": `"https://graph.microsoft.com/beta/users/$manager`"}"
    }
    Else {
        $body = @{
            accountEnabled    = $true
            displayName       = "$firstname $lastname"
            givenName         = $firstname
            surname           = $lastname
            mailNickname      = ($email -split '@')[0]
            userPrincipalName = $email
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $true
                password                      = $password
            }
            usageLocation     = "US"
            userType          = "Member"
            department        = $Department
            Mail              = $email
        }

        Invoke-GraphRequest -Method Post -Uri "https://graph.microsoft.com/beta/users" -ContentType "application/json" -Body ($body | ConvertTo-Json)
    }

    Set-ExchangeAuditLogs
}

New-MSUser