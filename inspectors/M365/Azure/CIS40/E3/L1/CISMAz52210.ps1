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

function Build-CISMAz52210($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz52210"
		FindingName	     = "CIS MAz 5.2.2.10 - Managed devices are not required for authentication"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Managed-devices are considered more secure because they often have additional configuration hardening enforced through centralized management such as Intune or Group Policy. These devices are also typically equipped with MDR/EDR, managed patching and alerting systems. As a result, they provide a safer environment for users to authenticate and operate from. This policy also ensures that attackers must first gain access to a compliant or trusted device before authentication is permitted, reducing the risk posed by compromised account credentials. When combined with other distinct Conditional Access (CA) policies, such as requiring multi-factor authentication, this adds one additional factor before authentication is permitted."
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
		@{ 'Name' = 'Enrollment guide: Microsoft Intune enrollment'; 'URL' = 'https://learn.microsoft.com/en-us/mem/intune/fundamentals/deployment-guide-enrollment' })
	}
	return $inspectorobject
}

function Audit-CISMAz52210
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeUsers -eq "All") -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.GrantControls.BuiltInControls -contains "compliantDevice" -and $_.GrantControls.BuiltInControls -contains "domainJoinedDevice") -and $Policy.GrantControls.Operator -eq "OR"}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz52210-CompliantDevicesConditionalAccessPolicy.txt"
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
			$finalobject = Build-CISMAz52210($Violation)
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
return Audit-CISMAz52210