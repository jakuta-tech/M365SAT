#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Idle session timeout' is set to '1 hour (or less)' for unmanaged devices
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-O365003($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-O365003"
		FindingName	     = "CSTM-O365003 - Not Recommended Settings Found"
		ProductFamily    = "Microsoft Office 365"
		CVS			     = ""
		Description	     = "Ending idle sessions through an automatic process can help protect sensitive company data, and will add another layer of security for end users who work on unmanaged devices that can potentially be accessed by the public. Unauthorized individuals onsite or remotely can take advantage of systems left unattended over time. Automatic timing out of sessions makes this more difficult."
		Remediation	     = "Manually change the value to 1 hour and enable the checkbox if not done in the portal."
		PowerShellScript = 'https://admin.microsoft.com/Adminportal/Home#/Settings/'
		DefaultValue	 = "Never and 0"
		ExpectedValue    = "Value: 60 or Less"
		ReturnedValue    = "$findings"
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Set user password to never expire'; 'URL' = 'https://learn.microsoft.com/en-US/microsoft-365/admin/add-users/set-password-to-never-expire?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Audit-CSTM-O365003
{
	try
	{
		# Actual Script,
		$SearchAdminAPI = Invoke-MultiMicrosoftAPI -Url 'https://admin.microsoft.com/admin/api/settings/security/o365guestuser' -Resource "https://admin.microsoft.com" -Method 'GET'
		
		# Validation
		if ($SearchAdminAPI.TimeoutString -eq "Never" -or $TimeoutSettings.TimeoutValue -igt 60)
		{
			$finalobject = Build-CSTM-O365003("TimeoutString: $($TimeoutSettings.TimeoutString) TimeoutValue: $($TimeoutSettings.TimeoutValue)")
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog "Warning message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-VerboseLog "Write to log"
		Write-ErrorLog "$scriptname : $message" -Exception $exception
		Write-VerboseLog "Errors written to log"
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
return Audit-CSTM-O365003