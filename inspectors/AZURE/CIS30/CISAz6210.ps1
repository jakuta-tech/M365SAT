# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Activity Log Alert exists for Delete Public IP Address rule
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz6210($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz6210"
		FindingName	     = "CIS Az 6.2.10 - Activity Log Alert does not exist for Delete Public IP Address rules"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Monitoring for Delete Public IP Address events gives insight into network access changes and may reduce the time it takes to detect suspicious activity."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzActivityLogAlert'
		DefaultValue	 = "By default, no monitoring alerts are created."
		ExpectedValue    = "an Activity Log Alert Rule for Microsoft.Network/publicIPAddresses/delete"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Classic alerts in Azure Monitor to retire in June 2019'; 'URL' = 'https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement/' },
		@{ 'Name' = 'Create or edit an activity log, service health, or resource health alert rule'; 'URL' = 'https://learn.microsoft.com/en-in/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule?tabs=activity-log' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' })
	}
	return $inspectorobject
}

function Audit-CISAz6210
{
	try
	{
		$Violation = @()
		# There is no script available at this moment to verify this clause
		$Subscriptions = Get-AzSubscription

		foreach ($Subscription in $Subscriptions){
			$LogAlert = Get-AzActivityLogAlert -SubscriptionId $Subscription.Id | Where-Object {$_.ConditionAllOf.Equal -match "Microsoft.Network/publicIPAddresses/delete"} | Select-Object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
			if ([string]::IsNullOrEmpty($LogAlert)){
				$violation = $Subscription.Name
			}
		}

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz6210($violation)
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
return Audit-CISAz6210