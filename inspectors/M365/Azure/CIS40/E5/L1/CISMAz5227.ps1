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

function Build-CISMAz5227($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5227"
		FindingName	     = "CIS MAz 5.2.2.7 - Verify if you have an Azure AD Identity Protection sign-in risk policy enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Turning on the sign-in risk policy ensures that suspicious sign-ins are challenged for multi-factor authentication. "
		Remediation	     = "Unfortunately we cannot accurately detect if a sign-in risk policy is enabled. If you have a sign-in risk policy. Please verify if the settings are configured correctly."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Correctly Configured Policy"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'How To: Give risk feedback in Azure AD Identity Protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-risk-feedback' },
		@{ 'Name' = 'What are risk detections?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks' })
	}
	return $inspectorobject
}

function Audit-CISMAz5227
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeUsers -eq "All") -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.Conditions.SignInRiskLevels -contains 'high' -and $_.Conditions.SignInRiskLevels -contains 'medium') -and $_.GrantControls.BuiltInControls -eq 'mfa' -and $_.SessionControls.SignInFrequency.FrequencyInterval -eq 'everyTime'}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5227-SignInRiskConditionalAccessPolicy.txt"
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
			$finalobject = Build-CISMAz5227($Violation)
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
return Audit-CISMAz5227