#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft 365
# Purpose: Ensure 'Idle session timeout' is set to '3 hour (or less)' for unmanaged devices
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff132
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    #Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMOff132"
        ID               = "1.3.2"
        Title            = "(L1) Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices"
        ProductFamily    = "Microsoft Office 365"
        DefaultValue     = "TimeoutString: Never TimeoutValue: 0"
        ExpectedValue    = "TimeoutString: NOT Never TimeoutValue: <180"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Ending idle sessions through an automatic process can help protect sensitive company data, and will add another layer of security for end users who work on unmanaged devices that can potentially be accessed by the public. Unauthorized individuals onsite or remotely can take advantage of systems left unattended over time. Automatic timing out of sessions makes this more difficult."
        Impact           = "Ending idle sessions may require users to reauthenticate more frequently, potentially disrupting workflows for some users."
        Remediation      = 'https://admin.microsoft.com/Adminportal/Home#/Settings/SecurityPrivacy'
        References	     = @(@{ 'Name' = 'Idle session timeout for Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/admin/manage/idle-session-timeout-web-apps?view=o365-worldwide' })
    }
    return $inspectorobject
}

function Audit-CISMOff132
{
	try
	{
		# Actual Script
		$TimeoutSettings = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/settings/security/activitybasedtimeout" -Resource "https://admin.microsoft.com" -Method 'GET'
		
		# Validation
		if ($TimeoutSettings.TimeoutString -eq "Never" -or $TimeoutSettings.TimeoutValue -igt 180)
		{
			$finalobject = Build-CISMOff132 -ReturnedValue ("TimeoutString: $($TimeoutSettings.TimeoutString) TimeoutValue: $($TimeoutSettings.TimeoutValue)") -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $finalobject
		}
		else
		{
			$endobject = Build-CISMOff132 -ReturnedValue ("TimeoutString: $($TimeoutSettings.TimeoutString) TimeoutValue: $($TimeoutSettings.TimeoutValue)") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMOff132 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
function Invoke-MultiMicrosoftAPI
{
	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		[Parameter()]
		#Body if a POST or PUT
		[Object]$Body,
		[Parameter()]
		#Specify the HTTP Method you wish to use. Defaults to GET
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
	try
	{
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	catch
	{
		Connect-AzAccount -ErrorAction Stop
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	
	#Specify Resource
	$apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $Resource)
	
	# Creating the important header
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $apiToken.AccessToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	# URL Where PUT Request is being done. You can extract this from F12 
	
	$method = 'GET'
	
	#In Case your Method is PUT or POST to edit something. Change things here
	
	if ($method -eq 'PUT')
	{
		# Remediation Scripts HERE
		$contentpart1 = '{"restrictNonAdminUsers":false}'
		
		#Convert the content (DUMMY)
		$Body = $contentpart1
		
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
	return $Response
}

return Audit-CISMOff132