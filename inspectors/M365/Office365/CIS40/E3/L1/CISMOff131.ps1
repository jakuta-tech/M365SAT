# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft 365
# Purpose: Ensure the 'Password expiration policy' is set to 'Set passwords to never expire
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff131($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff131"
		FindingName	     = "CIS MOff 1.3.1 - 'Password expiration policy' is not set to 'Set passwords to never expire'"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "15"
		Description	     = "Organizations such as NIST and Microsoft have updated their password policy recommendations to not arbitrarily require users to change their passwords after a specific amount of time, unless there is evidence that the password is compromised or the user forgot it. They suggest this even for single factor (Password Only) use cases, with a reasoning that forcing arbitrary password changes on users actually make the passwords less secure. Other recommendations within this Benchmark suggest the use of MFA authentication for at least critical accounts (at minimum), which makes password expiration even less useful as well as password protection for Azure AD.."
		Remediation	     = "Use the PowerShell Script to enable Modern Authentication for Microsoft Exchange Online."
		PowerShellScript = '$Domains = Get-MgDomain; ForEach($Domain in $Domains){Update-MgDomain -DomainId $Domain.Id -PasswordValidityPeriodInDays 2147483647 -PasswordNotificationWindowInDays 30 }'
		DefaultValue	 = "90"
		ExpectedValue    = "2147483647"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'NIST Special Publication 800-63B'; 'URL' = 'https://pages.nist.gov/800-63-3/sp800-63b.html' },
		@{ 'Name' = 'CIS Password Policy Guide'; 'URL' = 'https://www.cisecurity.org/insights/white-papers/cis-password-policy-guide' },
		@{ 'Name' = 'Set user password to never expire'; 'URL' = 'https://learn.microsoft.com/en-US/microsoft-365/admin/add-users/set-password-to-never-expire?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Audit-CISMOff131
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$Domains = Get-MgDomain;
		ForEach ($Domain in $Domains)
		{
			$GetSettings = Get-MgDomain -DomainId $Domain.Id
			if ($GetSettings.PasswordValidityPeriodInDays -ne 2147483647 -and $GetSettings.PasswordNotificationWindowInDays -ne 30)
			{
				$AffectedOptions += "Domain: $($GetSettings.Id): PasswordValidityPeriodInDays is $($GetSettings.PasswordValidityPeriodInDays)"
			}
		}
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$finalobject = Build-CISMOff131($AffectedOptions)
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
return Audit-CISMOff131