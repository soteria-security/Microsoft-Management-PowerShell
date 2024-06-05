New-TransportRule "Block Auto-Forwarding" -FromScope InOrganization -SentToScope NotInOrganization -MessageTypeMatches AutoForward -RejectMessageReasonText "Forwarding to external domains is not allowed."