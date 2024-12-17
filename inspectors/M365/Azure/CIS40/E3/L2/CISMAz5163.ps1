# Date: 8-11-2024
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that guest user access is restricted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5163($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5163"
		FindingName	     = "CIS MAz 5.1.6.3 - Guest user access is not restricted!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Restricting who can invite guests limits the exposure the organization might face from unauthorized accounts."
		Remediation	     = "Use the PowerShell setting to remediate the issue."
		PowerShellScript = 'Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom "adminsAndGuestInviters"'
		DefaultValue	 = "PowerShell: everyone"
		ExpectedValue    = "PowerShell: adminsAndGuestInviters or more restrictive"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure external collaboration settings for B2B in Microsoft Entra External ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure' },
		@{ 'Name' = 'Microsoft Entra Built-In Role: Guest Inviter'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#guest-inviter' })
	}
	return $inspectorobject
}

function Audit-CISMAz5163
{
	try
	{
		# Actual Script
		$AuthPolicy = Get-MgPolicyAuthorizationPolicy
		
		
		# Validation
		if ($AuthPolicy.AllowInvitesFrom -eq 'everyone')
		{
			$AuthPolicy | Format-List | Out-File "$path\CISMAz5163-AuthorizationPolicy.txt"
			$finalobject = Build-CISMAz5163("Anyone in the organization can invite guest users including guests and non-admins (most inclusive)")
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
return Audit-CISMAz5163