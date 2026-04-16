<#
  .SYNOPSIS 
    Block sign-in to shared mailboxes.
  .DESCRIPTION
    Following Microsoft guidance, industry best-practice, and CIS Microsoft 365 Foundations Benchmarks, this script discovers all shared mailboxes where sign-in is enabled and blocks sign-in to the shared mailbox resource.
    CIS Microsoft 365 Foundations Benchmark 1.2.2 (L1) Ensure sign-in to shared mailboxes is blocked.
  .INPUTS
    None.
  .OUTPUTS
    None
  .EXAMPLE
    ./Invoke-BlockSharedMailboxSignIn.ps1
#>

Function Block-SharedMailboxSignIn {
    $sharedMailboxes = Get-EXOMailbox -Filter { recipienttypedetails -eq "SharedMailbox" }

    ForEach ($mailbox in $sharedMailboxes) {
        $mbx = Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/users/$($mailbox.UserPrincipalName)"

        If ($mbx.accountEnabled -eq $true) {
            Write-Host "Blocking Sign-in for Shared Mailbox $($mbx.mail)"
            Update-MgUser -UserId $mbx.id -AccountEnabled:$false
        }
    }
}

Block-SharedMailboxSignIn