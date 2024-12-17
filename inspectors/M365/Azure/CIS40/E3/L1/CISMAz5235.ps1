#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5235($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5235"
		FindingName	     = "CISM MAz 5.2.3.5 - Weak authentication methods are not disabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "The SMS and Voice call methods are vulnerable to SIM swapping which could allow an attacker to gain access to your Microsoft 365 account."
		Remediation	     = "You can manually change the settings for the Password Protection Policy to enable on-prem protection."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection'
		DefaultValue	 = "SMS : Disabled \n Voice Call : Disabled \n Email OTP : Enabled"
		ExpectedValue    = "SMS : Disabled \n Voice Call : Disabled \n Email OTP : Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Manage authentication methods for Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage' },
			@{ 'Name' = 'Email one-time passcode authentication for B2B guest users'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/one-time-passcode' },
			@{ 'Name' = 'What is SIM swapping & how does the hijacking scam work?'; 'URL' = 'https://www.microsoft.com/en-us/microsoft-365-life-hacks/privacy-and-safety/what-is-sim-swapping' })
	}
	return $inspectorobject
}

function Audit-CISMAz5235
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$AuthenticationMethodPolicy = [PSCustomObject]@{}
		(Get-MgBetaPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations | ForEach-Object {$AuthenticationMethodPolicy | Add-Member -NotePropertyName $_.Id -NotePropertyValue $_.State }
		# Validation
		if ($AuthenticationMethodPolicy.Sms -ne 'disabled')
		{
			$AffectedOptions += "Sms: $($AuthenticationMethodPolicy.Sms)"
		}
		if ($AuthenticationMethodPolicy.Voice -eq 'disabled')
		{
			$AffectedOptions += "Voice: $($AuthenticationMethodPolicy.Voice)"
		}
		if ($AuthenticationMethodPolicy.Email -eq 'disabled')
		{
			$AffectedOptions += "Email: $($AuthenticationMethodPolicy.Email)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMAz5235-PasswordPolicy.txt"
			$finalobject = Build-CISMAz5235($AffectedOptions)
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

return Audit-CISMAz5235