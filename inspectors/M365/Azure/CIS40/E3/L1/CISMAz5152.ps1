# Date: 08-11-2024
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure user consent to apps accessing company data on their behalf is not allowed
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5152($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5152"
		FindingName	     = "CISMAz 5.1.5.2 - Admin consent workflow is disabled!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "The admin consent workflow (Preview) gives admins a secure way to grant access to applications that require admin approval. When a user tries to access an application but is unable to provide consent, they can send a request for admin approval. The request is sent via email to admins who have been designated as reviewers. A reviewer acts on the request, and the user is notified of the action."
		Remediation	     = "There is no PowerShell script available"
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings'
		DefaultValue	 = "EnableAdminConsentRequests: False \n notificationsEnabled: True \n remindersEnabled: True \n approvers: null \n approversv2: null \n requestExpiresInDays: 30"
		ExpectedValue    = "EnableAdminConsentRequests: True \n notificationsEnabled: True \n remindersEnabled: True \n approvers: at least 1 \n approversv2: at least 1 \n requestExpiresInDays: 30"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure the admin consent workflow'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow'})
	}
	return $inspectorobject
}

function Audit-CISMAz5152
{
	try
	{
		# Actual Script
		$Violation = @()
		$ConsentPolicySettings = Get-MgBetaDirectorySetting | Where-Object {$_.TemplateId -eq 'dffd5d46-495d-40a9-8e21-954ff55e198a'}
		$Setting = $ConsentPolicySettings.Values | Where-Object {$_.Name -eq 'EnableAdminConsentRequests'}
		if ($Setting.Value -ne $true){
			$Violation += "EnableAdminConsentRequests: False"
		}
		else{
			$AdvancedSettings = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/RequestApprovals/V2/PolicyTemplates?type=AdminConsentFlow' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
			if ($AdvancedSettings.notificationsEnabled -ne $True){
				$Violation += "AdminConsentPolicy: NotificationsEnabled: $($AdvancedSettings.notificationsEnabled)"
			}
		}
		
		# Validation
		if (-not [string]::IsNullOrEmpty($UserConsentSetting) -and $UserConsentSetting -eq "ManagePermissionGrantsForSelf.microsoft-user-default-low")
		{
			$UserConsentSetting | Format-Table -AutoSize | Out-File "$path\CISMAz5152-AdminConsentPolicy.txt"
			$finalobject = Build-CISMAz5152($UserConsentSetting)
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

return Audit-CISMAz5152