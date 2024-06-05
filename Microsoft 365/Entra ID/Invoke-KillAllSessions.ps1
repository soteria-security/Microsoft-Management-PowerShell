<#
.DESCRIPTION
    Terminate all sessions for all users
.EXAMPLE
    .\Invoke-KillAllSessions
#>

Connect-MgGraph -ContextScope Process -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"

$users = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users").UserPrincipalName

Foreach ($user in $users) {
    Invoke-GraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/users/$user/revokeSIgnInSessions"
}