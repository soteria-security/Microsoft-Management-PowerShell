# Microsoft Azure

# Purpose
Scripts provided are intended to assist administrators in auditing and managing their Microsoft Azure environment.


# Scripts
- Rotate-AllKeys: __WARNING!__ This script forces password/key resets on ALL Azure Storage Accounts. Regular key rotation is recommended and may be automated via [Azure Key Vaults](https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation). Requires an already authenticated Azure PowerShell (Az PowerShell Module) session with sufficient permissions on the current subscription.

```
# Execution Example:
.\Rotate-AllKeys.ps1
```