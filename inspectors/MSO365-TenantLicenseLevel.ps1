# This is an TenantLicenseLevel Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks the tenant license levels to see what features are available within the tenant.
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-TenantLicenseLevel($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMO3650005"
		FindingName	     = "Tenant License Level"
		ProductFamily    = "Microsoft Office 365"
		CVS			     = "0.0"
		Description	     = "Export of current Tenant license level's. This information can be used to determine what features and options are available currently for the Tenant, and to determine what licenses may be most beneficial for future use upgrades."
		Remediation	     = "None."
		DefaultValue	 = "None"
		ExpectedValue    = "Not applicable"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		PowerShellScript = 'Unavailable'
		References	     = @(@{ 'Name' = 'Understand subscriptions and licenses in Microsoft 365 for business'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/commerce/licenses/subscriptions-and-licenses?view=o365-worldwide' },
			@{ 'Name' = 'About Microsoft 365'; 'URL' = 'https://www.microsoft.com/en-us/licensing/product-licensing/microsoft-365' })
	}
}


$MicrosoftSKUS = @{
	'604ec28a-ae18-4bc6-91b0-11da94504ba9'  = 'Microsoft 365 Advanced Communications'
	'a7c70a41-5e02-4271-93e6-d9b4184d83f5'  = 'AI Builder capacity add-on'
	'113feb6c-3fe4-4440-bddc-54d774bf0318'  = 'Exchange Foundation'
	'0bfc98ed-1dbc-4a97-b246-701754e48b17'  = 'APP CONNECT'
	'3e26ee1f-8a5f-4d52-aee2-b81ce45c8f40'  = 'Microsoft 365 Audio Conferencing'
	'c4da7f8a-5ee2-4c99-a7e1-87d2df57f6fe'  = 'MICROSOFT AZURE ACTIVE DIRECTORY BASIC'
	'41781fb2-bc02-4b7c-bd55-b576c07bb09d'  = 'AZURE ACTIVE DIRECTORY PREMIUM P1'
	'932ad362-64a8-4783-9106-97849a1a30b9'  = 'CLOUD APP SECURITY DISCOVERY'
	'8a256a2b-b617-496d-b51b-e76466e88db0'  = 'MICROSOFT AZURE MULTI-FACTOR AUTHENTICATION'
	'eec0eb4f-6444-4f95-aba0-50c24d67f998'  = 'AZURE ACTIVE DIRECTORY PREMIUM P2'
	'bea4c11e-220a-4e6d-8eb8-8ea15d019f90'  = 'AZURE INFORMATION PROTECTION PREMIUM P1'
	'6c57d4b6-3b23-47a5-9bc9-69f17b4947b3'  = 'MICROSOFT AZURE ACTIVE DIRECTORY RIGHTS'
	'39b5c996-467e-4e60-bd62-46066f572726'  = 'Microsoft Invoicing'
	'199a5c09-e0ca-4e37-8f7c-b05d533e1ea2'  = 'Microsoft Bookings'
	'4828c8ec-dc2e-4779-b502-87ac9ce28ab7'  = 'MICROSOFT 365 PHONE SYSTEM'
	'57ff2da0-773e-42df-b2af-ffb7a2317929'  = 'MICROSOFT TEAMS'
	'0feaeb32-d00e-4d66-bd5a-43b5b83db82c'  = 'SKYPE FOR BUSINESS ONLINE (PLAN 2)'
	'db23fce2-a974-42ef-9002-d78dd42a0f22'  = 'Microsoft 365 Phone System for Government'
	'304767db-7d23-49e8-a945-4a7eb65f9f28'  = 'Microsoft Teams for Government'
	'a31ef4a2-f787-435e-8335-e47eb0cafc94'  = 'Skype for Business Online (Plan 2) for Government'
	'360bcc37-0c11-4264-8eed-9fa7a3297c9b'  = 'Common Data Service for Apps Database Capacity'
	'dc48f5c5-e87d-43d6-b884-7ac4a59e7ee9'  = 'Common Data Service for Apps Log Capacity'
	'505e180f-f7e0-4b65-91d4-00d670bbd18c'  = 'COMMUNICATIONS CREDITS'
	'77866113-0f3e-4e6e-9666-b1e25c6f99b0'  = 'Microsoft Dynamics CRM Online Storage Add-On'
	'eeea837a-c885-4167-b3d5-ddde30cbd85f'  = 'Microsoft Dynamics CRM Online Instance'
	'a98b7619-66c7-4885-bdfc-1d9c8c3d279f'  = 'Microsoft Dynamics CRM Online Additional Test Instance'
	'90467813-5b40-40d4-835c-abd48009b1d9'  = 'Asset Maintenance Add-in'
	'd397d6c6-9664-4502-b71c-66f39c400ca4'  = 'Dynamics 365 Business Central Additional Environment Addon'
	'ae6b27b3-fe31-4e77-ae06-ec5fabbc103a'  = 'Dynamics 365 Business Central Database Capacity'
	'920656a2-7dd8-4c83-97b6-a356414dbd36'  = 'Dynamics 365 for Business Central Essentials'
	'7e6d7d78-73de-46ba-83b1-6d25117334ba'  = 'Flow for Dynamics 365'
	'874fc546-6efe-4d22-90b8-5c4e7aa59f4b'  = 'PowerApps for Dynamics 365'
	'170991d7-b98e-41c5-83d4-db2052e1795f'  = 'Dynamics 365 Business Central External Accountant'
	'3f2afeed-6fb5-4bf9-998f-f2912133aead'  = 'Dynamics 365 Business Central for IWs'
	'8e9002c0-a1d8-4465-b952-817d2948e6e2'  = 'Dynamics 365 Business Central Premium'
	'1412cdc1-d593-4ad1-9050-40c30ad0b023'  = 'Dynamics 365 Customer Service Insights for CE Plan'
	'd56f3deb-50d8-465a-bedb-f079817ccac1'  = 'Dynamics 365 P1'
	'69f07c66-bee4-4222-b051-195095efee5b'  = 'Dynamics 365 Project Operations'
	'18fa3aba-b085-4105-87d7-55617b8585e6'  = 'Dynamics 365 Project Operations CDS'
	'b650d915-9886-424b-a08d-633cede56f57'  = 'Flow for Dynamics 365'
	'97f29a83-1a20-44ff-bf48-5e4ad11f3e51'  = 'Microsoft Dynamics 365 Customer Voice for Customer Engagement Plan'
	'03acaee3-9492-4f40-aed4-bcb6b32981b6'  = 'Microsoft Social Engagement Enterprise'
	'e95bec33-7c88-4a70-8e19-b10bd9d0c014'  = 'Office for the web'
	'0b03f40b-c404-40c3-8651-2aceb74365fa'  = 'Power Apps for Dynamics 365'
	'0a05d977-a21a-45b2-91ce-61c240dbafa2'  = 'Project for Project Operations'
	'fafd7243-e5c1-4a3a-9e40-495efcb1d3c3'  = 'Project Online Desktop Client'
	'fe71d6c3-a2ea-4499-9778-da042bf08063'  = 'Project Online Service'
	'5dbe027f-2339-4123-9542-606e4d348a72'  = 'SharePoint (Plan 2)'
	'4ade5aa6-5959-4d2c-bf0a-f4c9e2cc00f2'  = 'Dynamics 365 AI for Customer Service Trial'
	'363430d1-e3f7-43bc-b07b-767b6bb95e4b'  = 'Common Data Service'
	'17efdd9f-c22c-4ad8-b48e-3b1f3ee1dc9a'  = 'Dynamics 365 Customer Voice'
	'e212cbc7-0961-4c40-9825-01117710dcb1'  = 'Microsoft Forms (Plan E5)'
	'57a0746c-87b8-4405-9397-df365a9db793'  = 'Power Automate for Dynamics 365 Customer Voice'
	'6929f657-b31b-4947-b4ce-5066c3214f54'  = 'Dynamics 365 for Customer Service Pro'
	'c507b04c-a905-4940-ada6-918891e6d3ad'  = 'Power Apps for Customer Service Pro'
	'0368fc9c-3721-437f-8b7d-3d0f888cdefc'  = 'Power Automate for Customer Service Pro'
	'1259157c-8581-4875-bca7-2ffb18c51bda'  = 'Project Online Essentials'
	'90a816f6-de5f-49fd-963c-df490d73b7b5'  = 'Microsoft Dynamics 365 Customer Voice Add-on'
	'e6e35e2d-2e7f-4e71-bc6f-2f40ed062f5d'  = 'Dynamics Customer Voice Add-On'
	'e9830cfd-e65d-49dc-84fb-7d56b9aa2c89'  = 'Common Data Service'
	'3ca0766a-643e-4304-af20-37f02726339b'  = 'Microsoft Dynamics 365 Customer Voice USL'
	'1d4e9cb1-708d-449c-9f71-943aa8ed1d6a'  = 'Microsoft Dynamics CRM Online - Portal Add-On'
	'e95d7060-d4d9-400a-a2bd-a244bf0b609e'  = 'Common Data Service for Dynamics 365 Finance'
	'c7657ae3-c0b0-4eed-8c1d-6a7967bd9c65'  = 'Dynamics 365 for Finance and Operations Enterprise edition - Regulatory Service'
	'9f0e1b4e-9b33-4300-b451-b2c662cd4ff7'  = 'Microsoft Dynamics 365 for Finance'
	'99340b49-fb81-4b1e-976b-8f2ae8e9394f'  = 'MICROSOFT SOCIAL ENGAGEMENT - SERVICE DISCONTINUATION'
	'2da8e897-7791-486b-b08f-cc63c8129df7'  = 'DYNAMICS 365 FOR SALES'
	'88d83950-ff78-4e85-aa66-abfc787f8090'  = 'Dynamics 365 for Sales Professional'
	'6f9f70ce-138d-49f8-bb8b-2e701b7dde75'  = 'Power Apps for Sales Pro'
	'f944d685-f762-4371-806d-a1f48e5bea13'  = 'Project Online Essentials'
	'065f3c64-0649-4ec7-9f47-ef5cf134c751'  = 'Dynamics 365 for Sales Pro Attach'
	'b6a8b974-2956-4e14-ae81-f0384c363528'  = 'COMMON DATA SERVICE FOR DYNAMICS 365 SUPPLY CHAIN MANAGEMENT'
	'1224eae4-0d91-474a-8a52-27ec96a63fe7'  = 'DYNAMICS 365 FOR SUPPLY CHAIN MANAGEMENT'
	'2d925ad8-2479-4bd8-bb76-5b80f1d48935'  = 'Common Data Service'
	'f815ac79-c5dd-4bcc-9b78-d97f7b817d0d'  = 'Dynamics 365 for Talent: Attract'
	'300b8114-8555-4313-b861-0c115d820f50'  = 'Dynamics 365 for Talent: Onboard'
	'5ed38b64-c3b7-4d9f-b1cd-0de18c9c4331'  = 'Dynamics 365 for HCM Trial'
	'643d201a-9884-45be-962a-06ba97062e5e'  = 'DYNAMICS 365 FOR TALENT - ATTRACT EXPERIENCE TEAM MEMBER'
	'f2f49eef-4b3f-4853-809a-a055c6103fe0'  = 'DYNAMICS 365 FOR TALENT - ONBOARD EXPERIENCE'
	'6a54b05e-4fab-40e7-9828-428db3b336fa'  = 'DYNAMICS 365 FOR TEAM MEMBERS'
	'f5aa7b45-8a36-4cd1-bc37-5d06dea98645'  = 'DYNAMICS 365 FOR OPERATIONS TEAM MEMBERS'
	'c0454a3d-32b5-4740-b090-78c32f48f0ad'  = 'DYNAMICS 365 FOR RETAIL TEAM MEMBERS'
	'd5156635-0704-4f66-8803-93258f8b2678'  = 'DYNAMICS 365 FOR TALENT TEAM MEMBERS'
	'1ec58c70-f69c-486a-8109-4b87ce86e449'  = 'FLOW FOR DYNAMICS 365'
	'52e619e2-2730-439a-b0d3-d09ab7e8b705'  = 'POWERAPPS FOR DYNAMICS 365'
	'1315ade1-0410-450d-b8e3-8050e6da320f'  = 'Common Data Service'
	'0b2c029c-dca0-454a-a336-887285d6ef07'  = 'Dynamics 365 Guides'
	'816971f4-37c5-424a-b12b-b56881f402e7'  = 'Power Apps for Guides'
	'ceb28005-d758-4df7-bb97-87a617b93d6c'  = 'Dynamics 365 for Retail Device'
	'2c9fb43e-915a-4d61-b6ca-058ece89fd66'  = 'Dynamics 365 for Operations Devices'
	'd8ba6fb2-c6b1-4f07-b7c8-5f2745e36b54'  = 'Dynamics 365 for Operations non-production multi-box instance for standard acceptance testing (Tier 2)'
	'f6b5efb1-1813-426f-96d0-9b4f7438714f'  = 'Dynamics 365 for Operations Enterprise Edition - Sandbox Tier 4:Standard Performance Testing'
	'056a5f80-b4e0-4983-a8be-7ad254a113c9'  = 'DYNAMICS 365 P1 TRIAL FOR INFORMATION WORKERS'
	'0850ebb5-64ee-4d3a-a3e1-5a97213653b5'  = 'Common Data Service for Remote Assist'
	'4f4c7800-298a-4e22-8867-96b17850d4dd'  = 'Microsoft Remote Assist'
	'3ae52229-572e-414f-937c-ff35a87d4f29'  = 'Dynamics 365 for Sales Enterprise Attach'
	'048a552e-c849-4027-b54c-4c7ead26150a'  = 'DYNAMICS 365 FOR TALENT: ONBOARD'
	'4092fdb5-8d81-41d3-be76-aaba4074530b'  = 'DYNAMICS 365 TEAM MEMBERS'
	'd1142cfd-872e-4e77-b6ff-d98ec5a51f66'  = 'COMMON DATA SERVICE'
	'65a1ebf4-6732-4f00-9dcb-3d115ffdeecd'  = 'DYNAMICS 365 FOR TALENT'
	'95d2cd7b-1007-484b-8595-5e97e63fe189'  = 'DYNAMICS 365 FOR_OPERATIONS'
	'a9e39199-8369-444b-89c1-5fe65ec45665'  = 'DYNAMICS 365 FOR RETAIL'
	'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'  = 'MICROSOFT INTUNE'
	'5689bec4-755d-4753-8b61-40975025187c'  = 'AZURE INFORMATION PROTECTION PREMIUM P2'
	'2e2ddb96-6af9-4b1d-a3f0-d6ecfd22edb2'  = 'MICROSOFT CLOUD APP SECURITY'
	'14ab5db5-e6c4-4b20-b4bc-13e36fd2227f'  = 'MICROSOFT DEFENDER FOR IDENTITY'
	'922ba911-5694-4e99-a794-73aed9bfeec8'  = 'Exchange Foundation for Government'
	'75badc48-628e-4446-8460-41344d73abd6'  = 'Exchange Enterprise CAL Services (EOP DLP)'
	'9aaf7827-d63c-4b61-89c3-182f06f82e5c'  = 'Exchange Online (Plan 1)'
	'882e1d05-acd1-4ccb-8708-6ee03664b117'  = 'Mobile Device Management for Office 365'
	'5e62787c-c316-451f-b873-1d05acd4d12c'  = 'To-Do (Plan 1)'
	'efb87545-963c-4e0d-99df-69c6916d9eb0'  = 'EXCHANGE ONLINE (PLAN 2)'
	'176a09a6-7ec5-4039-ac02-b2791c6ba793'  = 'EXCHANGE ONLINE ARCHIVING FOR EXCHANGE ONLINE'
	'da040e0a-b393-4bea-bb76-928b3fa1cf5a'  = 'EXCHANGE ONLINE ARCHIVING FOR EXCHANGE SERVER'
	'1126bef5-da20-4f07-b45e-ad25d2581aa8'  = 'EXCHANGE ESSENTIALS'
	'4a82b400-a79f-41a4-b4e2-e94f5787b113'  = 'EXCHANGE ONLINE KIOSK'
	'90927877-dcff-4af6-b346-2332c0b15bb7'  = 'EXCHANGE ONLINE POP'
	'e2f705fd-2468-4090-8c58-fad6e6b1e724'  = 'Dynamics 365 Operations Trial Environment'
	'bf28f719-7844-4079-9c78-c1307898e192'  = 'Microsoft 365 Defender'
	'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'  = 'Microsoft Defender for Office 365 (Plan 1)'
	'8e0c0a52-6a6c-4d40-8370-dd62790dcd70'  = 'Microsoft Defender for Office 365 (Plan 2)'
	'3a3976ce-de18-4a87-a78e-5e9245e252df'  = 'Azure Active Directory for Education'
	'da24caf9-af8e-485c-b7c8-e73336da2693'  = 'Intune for Education'
	'a420f25f-a7b3-4ff5-a9d0-5d58f73b537d'  = 'Windows Store Service'
	'1d0f309f-fdf9-4b2a-9ae7-9c48b91f1426'  = 'Azure Active Directory Basic for Education'
	'4ff01e01-1ba7-4d71-8cf8-ce96c3bbcf14'  = 'Common Data Service - O365 P2'
	'95b76021-6a53-4741-ab8b-1d1f3d66a95a'  = 'Common Data Service for Teams_P2'
	'a9b86446-fa4e-498f-a92a-41b447e03337'  = 'Education Analytics'
	'2b815d45-56e4-4e3a-b65c-66cb9175b560'  = 'Information Protection and Governance Analytics - Standard'
	'5136a095-5cf0-4aff-bec3-e84448b38ea5'  = 'Information Protection for Office 365 - Standard'
	'33c4f319-9bdd-48d6-9c4d-410b750a4a5a'  = 'Insights by MyAnalytics'
	'43de0ff5-c92c-492b-9116-175376d08c38'  = 'Microsoft 365 Apps for Enterprise'
	'9b5de886-f035-4ff2-b3d8-c9127bea3620'  = 'Microsoft Forms (Plan 2)'
	'aebd3021-9f8f-4bf8-bbe3-0ed2f4f047a1'  = 'Microsoft Kaizala Pro Plan 3'
	'b737dad2-2f6c-4c65-90e3-ca563267e8b9'  = 'Microsoft Planner'
	'94065c59-bc8e-4e8b-89e5-5138d471eaff'  = 'Microsoft Search'
	'8c7d2df8-86f0-4902-b2ed-a0458298f3b3'  = 'Microsoft StaffHub'
	'9e700747-8b1d-45e5-ab8d-ef187ceec156'  = 'Microsoft Stream for O365 E3 SKU'
	'4c246bbc-f513-4311-beff-eba54c353256'  = 'Minecraft Education Edition'
	'8c098270-9dd4-4350-9b30-ba4703f3b36b'  = 'Office 365 Advanced Security Management'
	'e03c7e47-402c-463c-ab25-949079bedb21'  = 'Office for the Web for Education'
	'c68f8d98-5534-41c8-bf36-22fa496fa792'  = 'Power Apps for Office 365'
	'76846ad7-7776-4c40-a281-a386362dd1b9'  = 'Power Automate for Office 365'
	'041fe683-03e4-45b6-b1af-c0cdc516daee'  = 'Power Virtual Agents for Office 365 P2'
	'31b4e2fc-4cd6-4e7d-9c1b-41407303bd66'  = 'Project for Office (Plan E3)'
	'500b6a2a-7a50-4f40-b5f9-160e5b8c2f48'  = 'School Data Sync (Plan 2)'
	'63038b2c-28d0-45f6-bc36-33062963b498'  = 'SharePoint (Plan 2) for Education'
	'a23b959c-7ce8-4e57-9140-b90eb88a9e97'  = 'Sway'
	'c87f142c-d1e9-4363-8630-aaea9c4d9ae5'  = 'To-Do (Plan 2)'
	'795f6fe0-cc4d-4773-b050-5dde4dc704c9'  = 'Universal Print'
	'94a54592-cd8b-425e-87c6-97868b000b91'  = 'Whiteboard (Plan 2)'
	'e7c91390-7625-45be-94e0-e16907e03118'  = 'Windows 10 Enterprise (New)'
	'7bf960f6-2cd9-443a-8046-5dbff9558365'  = 'Windows Update for Business Deployment Service'
	'2078e8df-cff6-4290-98cb-5408261a760a'  = 'Yammer for Academic'
	'b67adbaf-a096-42c9-967e-5a84edbe0086'  = 'Universal Print Without Seeding'
	'8d77e2d9-9e28-4450-8431-0def64078fc5'  = 'Microsoft 365 Apps for enterprise (unattended)'
	'28b0fa46-c39a-4188-89e2-58e979a6b014'  = 'Common Data Service - O365 P3'
	'afa73018-811e-46e9-988f-f75d2b1b8430'  = 'Common Data Service for Teams_P3'
	'9f431833-0334-42de-a7dc-70aa40db46db'  = 'Customer Lockbox'
	'cd31b152-6326-4d1b-ae1b-997b625182e6'  = 'Data Classification in Microsoft 365'
	'c4801e8a-cb58-4c35-aca6-f2dcc106f287'  = 'Information Barriers'
	'd9fa6af4-e046-4c89-9226-729a0786685d'  = 'Information Protection and Governance Analytics -(Premium'
	'efb0351d-3b08-4503-993d-383af8de41e3'  = 'Information Protection for Office 365 - Premium'
	'2f442157-a11c-46b9-ae5b-6e39ff4e5849'  = 'Microsoft 365 Advanced Auditing'
	'a413a9ff-720c-4822-98ef-2f37c2a21f4c'  = 'Microsoft 365 Communication Compliance'
	'6dc145d6-95dd-4191-b9c3-185575ee6f6b'  = 'Microsoft Communications DLP'
	'6db1f1db-2b46-403f-be40-e39395f08dbb'  = 'Microsoft Customer Key'
	'46129a58-a698-46f0-aa5b-17f6586297d9'  = 'Microsoft Data Investigations'
	'871d91ec-ec1a-452b-a83f-bd76c7d770ef'  = 'Microsoft Defender for Endpoint'
	'64bfac92-2b17-4482-b5e5-a0304429de3e'  = 'Microsoft Endpoint DLP'
	'531ee2f8-b1cb-453b-9c21-d2180d014ca5'  = 'Microsoft Excel Advanced Analytics'
	'96c1e14a-ef43-418d-b115-9636cdaa8eed'  = 'Microsoft Forms (Plan 3)'
	'e26c2fcc-ab91-4a61-b35c-03cdc8dddf66'  = 'Microsoft Information Governance'
	'd587c7a3-bda9-4f99-8776-9bcf59c84f75'  = 'Microsoft Insider Risk Management'
	'0898bdbb-73b0-471a-81e5-20f1fe4dd66e'  = 'Microsoft Kaizala'
	'd2d51368-76c9-4317-ada2-a12c004c432f'  = 'Microsoft ML-Based Classification'
	'34c0d7a0-a70f-4668-9238-47f9fc208882'  = 'Microsoft MyAnalytics (Full)'
	'65cc641f-cccd-4643-97e0-a17e3045e541'  = 'Microsoft Records Management'
	'6c6042f5-6f01-4d67-b8c1-eb99d36eed3e'  = 'Microsoft Stream for O365 E5 SKU'
	'4de31727-a228-4ec3-a5bf-8e45b5ca48cc'  = 'Office 365 Advanced eDiscovery'
	'b1188c4c-1b36-4018-b48b-ee07604f6feb'  = 'Office 365 Privileged Access Management'
	'bf6f5520-59e3-4f82-974b-7dbbc4fd27c7'  = 'Office 365 SafeDocs'
	'9c0dab89-a30c-4117-86e7-97bda240acd2'  = 'Power Apps for Office 365 (Plan 3)'
	'07699545-9485-468e-95b6-2fca3738be01'  = 'Power Automate for Office 365'
	'70d33638-9c74-4d01-bfd3-562de28bd4ba'  = 'Power BI Pro'
	'ded3d325-1bdc-453e-8432-5bac26d7a014'  = 'Power Virtual Agents for Office 365 P3'
	'617b097b-4b93-4ede-83de-5f075bb5fb2f'  = 'Premium Encryption in Office 365'
	'b21a6b06-1988-436e-a07b-51ec6d9f52ad'  = 'Project for Office (Plan E5)'
	'41fcdd7d-4733-4863-9cf4-c65b83ce2df4'  = 'Microsoft Communications Compliance'
	'9d0c4ee5-e4a1-4625-ab39-d82b619b1a34'  = 'Microsoft Insider Risk Management'
	'3fb82609-8c27-4f7b-bd51-30634711ee67'  = 'To-Do (Plan 3)'
	'4a51bca5-1eff-43f5-878c-177680f191af'  = 'Whiteboard (Plan 3)'
	'159f4cd6-e380-449f-a816-af1a9ef76344'  = 'MICROSOFT FORMS (PLAN E1)'
	'094e7854-93fc-4d55-b2c0-3ab5369ebdc1'  = 'OFFICE 365 BUSINESS'
	'13696edf-5a08-49f6-8134-03083ed8ba30'  = 'ONEDRIVESTANDARD'
	'f544b08d-1645-4287-82de-8d91f37c02a1'  = 'MICROSOFT 365 AUDIO CONFERENCING FOR GOVERNMENT'
	'0f9b09cb-62d1-4ff4-9129-43f4996f83f4'  = 'FLOW FOR OFFICE 365'
	'c63d4d19-e8cb-460e-b37c-4d6c34603745'  = 'OFFICEMOBILE_SUBSCRIPTION'
	'92f7a6f3-b89b-4bbd-8c30-809e6da5ad1c'  = 'POWERAPPS FOR OFFICE 365'
	'c7699d2e-19aa-44de-8edf-1736da088ca1'  = 'SHAREPOINTSTANDARD'
	'7547a3fe-08ee-4ccb-b430-5077c5041653'  = 'YAMMER_ENTERPRISE'
	'41bf139a-4e60-409f-9346-a1361efc6dfb'  = 'YAMMER MIDSIZE'
	'5bfe124c-bbdc-4494-8835-f1297d457d79'  = 'OUTLOOK CUSTOMER MANAGER'
	'de377cbc-0019-4ec2-b77c-3f223947e102'  = 'AZURE ACTIVE DIRECTORY'
	'8e9ff0ff-aa7a-4b20-83c1-2f636b600ac2'  = 'MICROSOFT INTUNE'
	'743dd19e-1ce3-4c62-a3ad-49ba8f63a2f6'  = 'MICROSOFT STREAM FOR O365 E1 SKU'
	'8e229017-d77b-43d5-9305-903395523b99'  = 'WINDOWS 10 BUSINESS'
	'4ed3ff63-69d7-4fb7-b984-5aec7f605ca8'  = 'Microsoft 365 Domestic Calling Plan'
	'54a152dc-90de-4996-93d2-bc47e670fc06'  = 'MICROSOFT 365 DOMESTIC CALLING PLAN (120 min)'
	'3c8a8792-7866-409b-bb61-1b20ace0368b'  = 'Domestic Calling for Government'
	'2789c901-c14e-48ab-a76a-be334d9d793a'  = 'MICROSOFT FORMS (PLAN E3)'
	'21b439ba-a0ca-424f-a6cc-52f954a5b111'  = 'WINDOWS 10 ENTERPRISE'
	'6f23d6a9-adbf-481c-8538-b4c095654487'  = 'Microsoft 365 Lighthouse (Plan 1)'
	'd55411c9-cfff-40a9-87c7-240f14df7da5'  = 'Microsoft 365 Lighthouse (Plan 2)'
	'fd500458-c24c-478e-856c-a6067a8376cd'  = 'Microsoft Teams for DOD (AR)'
	'9953b155-8aef-4c56-92f3-72b0487fce41'  = 'Microsoft Teams for GCCHigh (AR)'
	'25689bec4-755d-4753-8b61-40975025187c' = 'Azure Information Protection Premium P2'
	'a6520331-d7d4-4276-95f5-15c0933bc757'  = 'Graph Connectors Search with Index'
	'db4d623d-b514-490b-b7ef-8885eee514de'  = 'Nucleus'
	'b76fb638-6ba6-402a-b9f9-83d28acb3d86'  = 'Viva Learning Seeded'
	'6a76346d-5d6e-4051-9fe3-ed3f312b5597'  = 'Azure Rights Management'
	'3ffba0d2-38e5-4d5e-8ec0-98f2b05c09d9'  = 'Microsoft Stream for O365 K SKU'
	'902b47e5-dcb2-4fdc-858b-c63a90a2bdb9'  = 'SharePoint Online Kiosk'
	'afc06cb0-b4f4-4473-8286-d644f70d8faf'  = 'Skype for Business Online (Plan 1)'
	'ca6e61ec-d4f4-41eb-8b88-d96e0e14323f'  = 'Common Data Service - O365 F1'
	'90db65a7-bf11-4904-a79f-ef657605145b'  = 'Common Data Service for Teams_F1'
	'f07046bd-2a3c-4b96-b0be-dea79d7cbfb8'  = 'Microsoft Forms (Plan F1)'
	'73b2a583-6a59-42e3-8e83-54db46bc3278'  = 'Microsoft Kaizala Pro Plan 1'
	'e0287f9f-e222-4f98-9a83-f379e249159a'  = 'Power Apps for Office 365 K1'
	'bd91b1a4-9f94-4ecf-b45b-3a65e5c8128a'  = 'Power Automate for Office 365 K1'
	'ba2fdb48-290b-4632-b46a-e4ecc58ac11a'  = 'Power Virtual Agents for Office 365 F1'
	'7f6f28c2-34bb-4d4b-be36-48ca2e77e1ec'  = 'Project for Office (Plan F)'
	'80873e7a-cd2a-4e67-b061-1b5381a676a5'  = 'To-Do (Firstline)'
	'36b29273-c6d0-477a-aca6-6fbe24f538e3'  = 'Whiteboard (Firstline)'
	'e041597c-9c7f-4ed9-99b0-2663301576f7'  = 'Windows 10 Enterprise E3 (local only)'
	'17ab22cd-a0b3-4536-910a-cb6eb12696c0'  = 'COMMON DATA SERVICE - VIRAL'
	'50e68c76-46c6-4674-81f9-75456511b170'  = 'FLOW FREE'
	'1b66aedf-8ca1-4f73-af76-ec76c6180f98'  = 'AZURE RIGHTS MANAGEMENT PREMIUM FOR GOVERNMENT'
	'06162da2-ebf9-4954-99a0-00fee96f95cc'  = 'COMMON DATA SERVICE - O365 P2 GCC'
	'a70bbf38-cdda-470d-adb8-5804b8770f41'  = 'COMMON DATA SERVICE FOR TEAMS_P2 GCC'
	'8c3069c0-ccdb-44be-ab77-986203a67df2'  = 'EXCHANGE PLAN 2G'
	'24af5f65-d0f3-467b-9f78-ea798c4aeffc'  = 'FORMS FOR GOVERNMENT (PLAN E3)'
	'6e5b7995-bd4f-4cbd-9d19-0e32010c72f0'  = 'INSIGHTS BY MYANALYTICS FOR GOVERNMENT'
	'de9234ff-6483-44d9-b15e-dca72fdd27af'  = 'MICROSOFT 365 APPS FOR ENTERPRISE G'
	'2c1ada27-dbaa-46f9-bda6-ecb94445f758'  = 'MICROSOFT STREAM FOR O365 FOR GOVERNMENT (E3)'
	'5b4ef465-7ea1-459a-9f91-033317755a51'  = 'OFFICE 365 PLANNER FOR GOVERNMENT'
	'8f9f0f3b-ca90-406c-a842-95579171f8ec'  = 'OFFICE FOR THE WEB (GOVERNMENT)'
	'0a20c815-5e81-4727-9bdc-2b5a117850c3'  = 'POWER APPS FOR OFFICE 365 FOR GOVERNMENT'
	'c537f360-6a00-4ace-a7f5-9128d0ac1e4b'  = 'POWER AUTOMATE FOR OFFICE 365 FOR GOVERNMENT'
	'153f85dd-d912-4762-af6c-d6e0fb4f6692'  = 'SHAREPOINT PLAN 2G'
	'ed777b71-af04-42ca-9798-84344c66f7c6'  = 'SKYPE FOR BUSINESS CLOUD PBX FOR SMALL AND MEDIUM BUSINESS'
	'f47330e9-c134-43b3-9993-e7f004506889'  = 'MICROSOFT 365 PHONE SYSTEM VIRTUAL USER'
	'0628a73f-3b4a-4989-bd7b-0f8823144313'  = 'Microsoft 365 Phone System Virtual User for Government'
	'9bec7e34-c9fa-40b7-a9d1-bd6d1165c7ed'  = 'Data Loss Prevention'
	'cca845f9-fd51-4df6-b563-976a37c56ce0'  = 'MICROSOFT BUSINESS CENTER'
	'bf36ca64-95c6-4918-9275-eb9f4ce2c04f'  = 'MICROSOFT DYNAMICS CRM ONLINE BASIC'
	'61d18b02-6889-479f-8f36-56e6e0fe5792'  = 'SecOps Investigation for MDI'
	'493ff600-6a2b-4db6-ad37-a7d4eb214516'  = 'Microsoft Defender for Office 365 (Plan 1) for Government'
	'900018f1-0cdb-4ecb-94d4-90281760fdc6'  = 'Microsoft Defender for Office 365 (Plan 2) for Government'
	'f9646fb2-e3b2-4309-95de-dc4833737456'  = 'MICROSOFT DYNAMICS CRM ONLINE PROFESSIONA'
	'3413916e-ee66-4071-be30-6f94d4adfeda'  = 'MICROSOFT DYNAMICS MARKETING SALES COLLABORATION - ELIGIBILITY CRITERIA APPLY'
	'3e58e97c-9abe-ebab-cd5f-d543d1529634'  = 'MICROSOFT SOCIAL ENGAGEMENT PROFESSIONAL - ELIGIBILITY CRITERIA APPLY'
	'd736def0-1fde-43f0-a5be-e3f8b2de6e41'  = 'MS IMAGINE ACADEMY'
	'd20bfa21-e9ae-43fc-93c2-20783f0840c3'  = 'Flow P2 Viral'
	'd5368ca3-357e-4acb-9c21-8495fb025d1f'  = 'PowerApps Trial'
	'6ea4c1ef-c259-46df-bce2-943342cd3cb2'  = 'Common Data Service - P2'
	'56be9436-e4b2-446c-bb7f-cc15d16cca4d'  = 'Power Automate (Plan 2)'
	'00527d7f-d5bc-4c2a-8d1e-6c0de2410c81'  = 'Power Apps (Plan 2)'
	'acffdce6-c30f-4dc2-81c0-372e33c515ec'  = 'MICROSOFT STREAM'
	'd3a458d0-f10d-48c2-9e44-86f3f684029e'  = 'Microsoft Stream Plan 2'
	'83bced11-77ce-4071-95bd-240133796768'  = 'Microsoft Stream Storage Add-On'
	'617d9209-3b90-4879-96e6-838c42b2701d'  = 'MCO FREE FOR MICROSOFT TEAMS (FREE)'
	'4fa4026d-ce74-4962-a151-8e96d57ea8e4'  = 'MICROSOFT TEAMS (FREE)'
	'bd6f2ac2-991a-49f9-b23c-18c96a02c228'  = 'TEAMS FREE SERVICE'
	'bed136c6-b799-4462-824d-fc045d3a9d25'  = 'COMMON DATA SERVICE FOR TEAMS_P1'
	'42a3ec34-28ba-46b6-992f-db53a675ac5b'  = 'MICROSOFT TEAMS'
	'0683001c-0492-4d59-9515-d9a6426b5813'  = 'POWER VIRTUAL AGENTS FOR OFFICE 365 P1'
	'b8afc642-032e-4de5-8c0a-507a7bba7e5d'  = 'WHITEBOARD (PLAN 1)'
	'b83a66d4-f05f-414d-ac0f-ea1c5239c42b'  = 'Microsoft Threat Experts - Experts on Demand'
	'897d51f1-2cfa-4848-9b30-469149f5e68e'  = 'Exchange Online Multi-Geo'
	'735c1d98-dd3f-4818-b4ed-c8052e18e62d'  = 'SharePoint Multi-Geo'
	'41eda15d-6b52-453b-906f-bc4a5b25a26b'  = 'Teams Multi-Geo'
	'bdaa59a3-74fd-4137-981a-31d4f84eb8a0'  = 'Meeting Room Managed Services'
	'e5bb877f-6ac9-4461-9e43-ca581543ab16'  = 'SHAREPOINTSTORAGE_GOV'
	'be5a7ed5-c598-4fcd-a061-5e6724c68a58'  = 'Office 365 Extra File Storage'
	'a361d6e2-509e-4e25-a8ad-950060064ef4'  = 'SHAREPOINT FOR DEVELOPER'
	'527f7cdd-0e86-4c47-b879-f5fd357a3ac6'  = 'OFFICE ONLINE FOR DEVELOPER'
	'27216c54-caf8-4d0d-97e2-517afb5c08f6'  = 'SKYPE FOR BUSINESS ONLINE (PLAN 3)'
	'31cf2cfc-6b0d-4adc-a336-88b724ed8122'  = 'Microsoft Azure Rights Management Service'
	'a7d3fb37-b6df-4085-b509-50810d991a39'  = 'DYN365_CDS_O365_P3_GCC'
	'bce5e5ca-c2fd-4d53-8ee2-58dfffed4c10'  = 'CDS_O365_P3_GCC'
	'89b5d3b1-3855-49fe-b46c-87c66dbc1526'  = 'LOCKBOX_ENTERPRISE_GOV'
	'843da3a8-d2cc-4e7a-9e90-dc46019f964c'  = 'FORMS_GOV_E5'
	'208120d1-9adb-4daf-8c22-816bd5d237e7'  = 'EXCHANGE_ANALYTICS_GOV'
	'92c2089d-9a53-49fe-b1a6-9e6bdf959547'  = 'STREAM_O365_E5_GOV'
	'd1cbfb67-18a8-4792-b643-630b7f19aad1'  = 'EQUIVIO_ANALYTICS_GOV'
	'0eacfc38-458a-40d3-9eab-9671258f1a3e'  = 'POWERAPPS_O365_P3_GOV'
	'8055d84a-c172-42eb-b997-6c2ae4628246'  = 'FLOW_O365_P3_GOV'
	'944e9726-f011-4353-b654-5f7d2663db76'  = 'BI_AZURE_P_2_GOV'
	'fc52cc4b-ed7d-472d-bbe7-b081c23ecc56'  = 'EXCHANGE ONLINE PLAN '
	'b2669e95-76ef-4e7e-a367-002f60a39f3e'  = 'SKYPE FOR BUSINESS ONLINE (PLAN 2) FOR MIDSIZ'
	'6b5b6a67-fc72-4a1f-a2b5-beecf05de761'  = 'SHAREPOINT PLAN 1'
	'd42bdbd6-c335-4231-ab3d-c8f348d5aff5'  = 'EXCHANGE ONLINE (P1)'
	'70710b6b-3ab4-4a38-9f6d-9f169461650a'  = 'SKYPE FOR BUSINESS ONLINE (PLAN P1)'
	'a1f3d0a8-84c0-4ae0-bae4-685917b8ab48'  = 'SHAREPOINTLITE'
	'8ca59559-e2ca-470b-b7dd-afd8c0dee963'  = 'OFFICE 365 SMALL BUSINESS SUBSCRIPTION'
	'afcafa6a-d966-4462-918c-ec0b4e0fe642'  = 'ONEDRIVEENTERPRISE'
	'0b4346bb-8dc3-4079-9dfc-513696f56039'  = 'LOGIC FLOWS'
	'2c4ec2dc-c62d-4167-a966-52a3e6374015'  = 'MICROSOFT POWER VIDEOS BASIC'
	'e61a2945-1d4e-4523-b6e7-30ba39d20f32'  = 'MICROSOFT POWERAPPS'
	'94a669d1-84d5-4e54-8462-53b0ae2c8be5'  = 'CDS Per app baseline access'
	'dd14867e-8d31-4779-a595-304405f5ad39'  = 'Flow per app baseline access'
	'35122886-cef5-44a3-ab36-97134eabd9ba'  = 'PowerApps per app baseline access'
	'9f2f00ad-21ae-4ceb-994b-d8bc7be90999'  = 'CDS PowerApps per app plan'
	'b4f657ff-d83e-4053-909d-baa2b595ec97'  = 'Power Apps per App Plan'
	'c539fa36-a64e-479a-82e1-e40ff2aa83ee'  = 'Power Automate for Power Apps per App Plan'
	'ea2cf03b-ac60-46ae-9c1d-eeaeb63cec86'  = 'Power Apps per User Plan'
	'dc789ed8-0170-4b65-a415-eb77d5bb350a'  = 'Power Automate for Power Apps per User Plan'
	'c84e52ae-1906-4947-ac4d-6fb3e5bf7c2e'  = 'Common data service for Flow per business process plan'
	'7e017b61-a6e0-4bdc-861a-932846591f6e'  = 'Flow per business process plan'
	'c5002c70-f725-4367-b409-f0eff4fee6c0'  = 'Flow per user plan'
	'3da2fd4c-1bee-4b61-a17f-94c31e5cab93'  = 'Common Data Service Attended RPA'
	'375cd0ad-c407-49fd-866a-0bff4f8a9a4d'  = 'Power Automate RPA Attended'
	'b475952f-128a-4a44-b82a-0b98a45ca7fb'  = 'Common Data Service Unattended RPA'
	'0d373a98-a27a-426f-8993-f9a425ae99c5'  = 'Power Automate Unattended RPA add-on'
	'fc0a60aa-feee-4746-a0e3-aecfe81a38dd'  = 'Microsoft Power BI Information Services Plan 1'
	'2125cfd7-2110-4567-83c4-c1cd5275163d'  = 'Microsoft Power BI Reporting and Analytics Plan 1'
	'2049e525-b859-401b-b2a0-e0a31c4b1fe4'  = 'Power BI (free)'
	'9da49a6d-707a-48a1-b44a-53dcde5267f8'  = 'Power BI Premium P'
	'0bf3c642-7bb5-4ccc-884e-59d09df0266c'  = 'Power BI Premium Per User'
	'0a0a23fa-fea1-4195-bb89-b4789cb12f7f'  = 'Common Data Service for Virtual Agent Base'
	'4b81a949-69a1-4409-ad34-9791a6ec88aa'  = 'Power Automate for Virtual Agent'
	'f6934f16-83d3-4f3b-ad27-c6e9c187b260'  = 'Virtual Agent Base'
	'cf7034ed-348f-42eb-8bbd-dddeea43ee81'  = 'Common Data Service for CCI Bots'
	'ce312d15-8fdf-44c0-9974-a25a177125ee'  = 'Dynamics 365 AI for Customer Service Virtual Agents Viral'
	'5d798708-6473-48ad-9776-3acc301c40af'  = 'Flow for CCI Bots'
	'a6f677b3-62a6-4644-93e7-2a85d240845e'  = 'COMMON DATA SERVICE FOR PROJECT P1'
	'00283e6b-2bd8-440f-a2d5-87358e4c89a1'  = 'POWER AUTOMATE FOR PROJECT P1'
	'4a12c688-56c6-461a-87b1-30d6f32136f9'  = 'PROJECT P1'
	'50554c47-71d9-49fd-bc54-42a2765c555c'  = 'Common Data Service for Project'
	'fa200448-008c-4acb-abd4-ea106ed2199d'  = 'Flow for Project'
	'818523f5-016b-4355-9be8-ed6944946ea7'  = 'Project P3'
	'45c6831b-ad74-4c7f-bd03-7c2b3fa39067'  = 'Project Online Desktop Client for Government'
	'e57afa78-1f19-4542-ba13-b32cd4d8f472'  = 'Project Online Service for Government'
	'7a39d7dd-e456-4e09-842a-0204ee08187b'  = 'Rights Management Adhoc'
	'a5f38206-2f48-4d83-9957-525f4e75e9c0'  = 'IoT Intelligence Add-in Additional Machines'
	'83dd9619-c7d5-44da-9250-dc4ee79fff7e'  = 'Iot Intelligence Add-in for D365 Supply Chain Management'
	'3069d530-e41b-421c-ad59-fb1001a23e11'  = 'Common Data Service for SharePoint Syntex'
	'f00bd55e-1633-416e-97c0-03684e42bc42'  = 'SharePoint Syntex'
	'fd2e7f90-1010-487e-a11b-d2b1ae9651fc'  = 'SharePoint Syntex - SPO type'
	'5a10155d-f5c1-411a-a8ec-e99aae125390'  = 'DOMESTIC AND INTERNATIONAL CALLING PLAN'
	'7861360b-dc3b-4eba-a3fc-0d323a035746'  = 'AUSTRALIA CALLING PLAN'
	'da792a53-cbc0-4184-a10d-e544dd34b3c1'  = 'OneDrive for business Basic'
	'2bdbaf8f-738f-4ac7-9234-3c3ee2ce7d0f'  = 'Visio web app'
	'663a804f-1c30-4ff0-9915-9db84f0d1cea'  = 'Visio Desktop App'
	'98709c2e-96b5-4244-95f5-a0ebe139fb8a'  = 'ONEDRIVE FOR BUSINESS BASIC FOR GOVERNMENT'
	'f85945f4-7a55-4009-bc39-6a5f14a8eac1'  = 'VISIO DESKTOP APP FOR Government'
	'8a9ecb07-cfc0-48ab-866c-f83c4d911576'  = 'VISIO WEB APP FOR GOVERNMENT'
	'b74d57b2-58e9-484a-9731-aeccbba954f0'  = 'Graph Connectors Search with Index (Viva Topics)'
	'c815c93d-0759-4bb8-b857-bc921a71be83'  = 'Viva Topics'
	'a790cd6e-a153-4461-83c7-e127037830b6'  = 'Windows 365 Business 2 vCPU 4 GB 64 GB'
	'1d4f75d3-a19b-49aa-88cb-f1ea1690b550'  = 'Windows 365 Business 4 vCPU 16 GB 128 GB'
	'23a25099-1b2f-4e07-84bd-b84606109438'  = 'Windows 365 Enterprise 2 vCPU 4 GB 64 GB'
	'f477b0f0-3bb1-4890-940c-40fcee6ce05f'  = 'Microsoft Workplace Analytics'
	'ff7b261f-d98b-415b-827c-42a3fdf015af'  = 'Microsoft Workplace Analytics Insights Backend'
	'b622badb-1b45-48d5-920f-4b27a2c0996c'  = 'Microsoft Workplace Analytics Insights User'
}

Function Get-TenantLicenseLevel
{
	Try
	{
		$licenses = Get-MgSubscribedSku
		
		$org_licenses = @()
		
		foreach ($license in $Licenses)
		{
			$used = $license.ConsumedUnits
			$total = $license.PrepaidUnits.Enabled
			$remaining = $total - $used
			
			
			$org_license = New-Object psobject
			$org_license | Add-Member -MemberType NoteProperty -name 'Name' -Value $license.SkuPartNumber
			$org_license | Add-Member -MemberType NoteProperty -name 'Consumed Licenses' -Value $used
			$org_license | Add-Member -MemberType NoteProperty -name 'Remaining Licenses' -Value $remaining
			$org_license | Add-Member -MemberType NoteProperty -name 'Total Licenses' -Value $total
			
			$org_licenses += $org_license
		}
		
		$org_licenses | Out-File "$path\TenantLicenseInfo.txt"
		
		$endobject = Build-TenantLicenseLevel($org_licenses.Name)
		Return $endobject
	}
	Catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}

Return Get-TenantLicenseLevel


