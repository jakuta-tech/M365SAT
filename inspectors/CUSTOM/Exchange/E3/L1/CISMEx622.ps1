# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx622
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx622"
        ID               = "6.2.2"
        Title            = "(L1) Ensure mail transport rules do not whitelist specific domains"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "None"
        ExpectedValue    = "None"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Whitelisting domains in transport rules bypasses regular malware and phishing scanning, allowing attackers to exploit trusted domains for malicious activity."
        Impact           = "Potential for malware or phishing attacks due to bypassed scanning."
        Remediation	 	 = 'Get-TransportRule | Where-Object {($_.SetSCL -eq -1 -and $_.SenderDomainIs -ne $null)} | ForEach-Object {Remove-TransportRule -Identity $_.Name}'
        References       = @(
            @{ 'Name' = 'Best practices for configuring mail flow rules in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/configuration-best-practices" },
            @{ 'Name' = 'Mail flow rules (transport rules) in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules" }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx622
{
	Try
	{
		
		$domainwlrules = Get-TransportRule | Where-Object { ($_.setscl -eq -1 -and $null -ne $_.SenderDomainIs) } | Select-Object Name, SenderDomainIs
		
		If ($domainwlrules.Count -ne 0)
		{
			$domainwlrules | Format-List | Out-File -FilePath "$path\CISMEx622-SenderDomainIs.txt"
			$endobject = Build-CISMEx622 -ReturnedValue ($domainwlrules) -Status "FAIL" -RiskScore "4" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx622 -ReturnedValue "No Transport Rules containing Domain Whitelisting" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx622 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx622


