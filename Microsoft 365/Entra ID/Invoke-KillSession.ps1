<#
.DESCRIPTION
    Terminate all sessions for targeted user
.INPUTS
    Target user's UserPrincipalName, Mail, or Display Name
.PARAMETER targetUser
    The value for the target user, can be mail, UPN, or display name
.PARAMETER lookupType
    The type of value entered for targetUser
.EXAMPLE
    .\Invoke-KillSession -lookupType Mail -targetUser user@company.com
.EXAMPLE
    .\Invoke-KillSession -lookupType UPN -targetUser user@company.onmicrosoft.com
.EXAMPLE
    .\Invoke-KillSession -lookupType DisplayName -targetUser "First Last"
#>

param (
    [Parameter(Mandatory = $true,
        HelpMessage = 'UserPrincipalName')]
    [string] $targetUser,
    [Parameter(Mandatory = $true,
        HelpMessage = "User Lookup Method")]
    [ValidateSet("Mail", "UPN", "DisplayName",
        IgnoreCase = $true)]
    [string] $lookupType = "UPN"
)


Connect-MgGraph -ContextScope Process -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"

$user = ''

If ($lookupType -eq 'UPN') {
    $user = $targetUser
}
ElseIf ($lookupType -eq 'Mail') {
    $user = (Get-MgUser -Filter "mail eq '$targetUser'").UserPrincipalName
}
ElseIf ($lookupType -eq 'DisplayName') {
    $user = (Get-MgUser -Filter "displayName eq '$targetUser'").UserPrincipalName
}

Invoke-GraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/users/$user/revokeSIgnInSessions"