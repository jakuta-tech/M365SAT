# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5224($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5224"
		FindingName	     = "CIS MAz 5.2.2.4 - Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Forcing a time out for MFA will help ensure that sessions are not kept alive for an indefinite period of time, ensuring that browser sessions are not persistent will help in prevention of drive-by attacks in web browsers, this also prevents creation and saving of session cookies leaving nothing for an attacker to take."
		Remediation	     = "You can navigate to the Entry Portal and the Conditional Access blade to configure the policy."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No Policy and the default configuration for user sign-in frequency is a rolling window of 90 days."
		ExpectedValue    = "presistentBrowserMode: never and isEnabled: true | signInFrequencyValue: between 4 and 24 and timevalue: hours | clientAppTypes: All | applicationsIncludeApplications: All"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure adaptive session lifetime policies'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime' })
	}
	return $inspectorobject
}

function Audit-CISMAz5224
{
	try
	{
		# Actual Script
		$Violation = @()
		$DirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition
		$PrivilegedRoles = ($DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"}).TemplateId
		# This are the administrator roles and members that should be added to this policy

		# Here we should determine if the tenant is an E3 or E5 tenant. 
		$SignInFrequencyValue = 4

		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {((-not ($PrivilegedRoles | Compare-Object $_.Conditions.Users.IncludeRoles) -as [bool]) -eq $true) -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.SessionControls.SignInFrequency.IsEnabled -eq $true -and $_.SessionControls.SignInFrequency.Type -eq 'hours' -and $_.SessionControls.SignInFrequency.Value -ile $SignInFrequencyValue) -and $_.SessionControls.PersistentBrowser.IsEnabled -eq $true -and $_.SessionControls.PersistentBrowser.Mode -eq 'never'}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5224-SignInFrequencyConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -ne "enabled")
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
			$finalobject = Build-CISMAz5224($Violation)
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
return Audit-CISMAz5224