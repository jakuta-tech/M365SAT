# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure MailTips are enabled for end users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)


function Build-CISMEx654($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx654"
		FindingName	     = "CIS MEx 6.5.4 - SMTP AUTH is enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "8"
		Description	     = "SMTP AUTH is a legacy protocol. Disabling it at the organization level supports the principle of least functionality and serves to further back additional controls that block legacy protocols, such as in Conditional Access. Virtually all modern email clients that connect to Exchange Online mailboxes in Microsoft 365 can do so without using SMTP AUTH."
		Remediation	     = "Run the PowerShell Command to disable SMTP AUTH"
		PowerShellScript = 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
		DefaultValue	 = "SmtpClientAuthenticationDisabled : True"
		ExpectedValue    = "SmtpClientAuthenticationDisabled : True"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "4"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Enable or disable authenticated client SMTP submission (SMTP AUTH) in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission" })
	}
	return $inspectorobject
}

function Audit-CISMEx654
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$ExchangeSetting = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
		if ($ExchangeSetting.SmtpClientAuthenticationDisabled -ne $true)
		{
			$AffectedOptions += "SmtpClientAuthenticationDisabled is set to : $($ExchangeSetting.SmtpClientAuthenticationDisabled)"
		}

		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$ExchangeSetting | Format-List | Out-File -FilePath "$path\CISMEx654-OrganizationConfig.txt"
			$finalobject = Build-CISMEx654($AffectedOptions)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx654