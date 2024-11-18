# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Purpose: Enable Azure AD Identity Protection sign-in risk policies
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMAz52211($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz52211"
		FindingName	     = "CIS MAz 5.2.2.10 - Managed devices are not required for MFA registration"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Requiring registration on a managed device significantly reduces the risk of bad actors using stolen credentials to register security information. Accounts that are created but never registered with an MFA method are particularly vulnerable to this type of attack. Enforcing this requirement will both reduce the attack surface for fake registrations and ensure that legitimate users register using trusted devices which typically have additional security measures in place already."
		Remediation	     = "Please verify if the settings are configured correctly in the Conditional Access Policy pane."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Correctly Configured Policy"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Require device to be marked as compliant'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant' },
		@{ 'Name' = 'Microsoft Entra hybrid joined devices'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join' },
		@{ 'Name' = 'Enrollment guide: Microsoft Intune enrollment'; 'URL' = 'https://learn.microsoft.com/en-us/mem/intune/fundamentals/deployment-guide-enrollment' },
		@{ 'Name' = 'User actions'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#user-actions' })
	}
	return $inspectorobject
}

function Audit-CISMAz52211
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeUsers -eq "All") -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeUserActions -eq 'urn:user:registersecurityinfo') -and ($_.GrantControls.BuiltInControls -contains "domainJoinedDevice") -and $Policy.GrantControls.Operator -eq "OR"}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz52211-CompliantDevicesConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -eq "disabled")
				{
					$Violation += $Policy.Id
				}		
			}
		}
		else
		{
			$Violation += "No Conditional Access Policy (Correctly) Configured!"
		}
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISMAz52211($Violation)
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
return Audit-CISMAz52211