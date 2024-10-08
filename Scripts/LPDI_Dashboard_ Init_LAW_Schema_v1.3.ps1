<#
.SYNOPSIS
LPDI_Dashboard_ Init_LAW_Schema.ps1
	
.DESCRIPTION
This script create the schema for Log Analytics Workspace Custom Log tables
Provide Workspace ID & Key in the variables $CustomerId & $SharedKey
    	
.EXAMPLE
.\LPDI_Dashboard_ Init_LAW_Schema.ps1
Export Data to C:\Azure\AAD folder, execute all exports, and export Audit & Signin Logs since 5 days 

.OUTPUTS
None

.NOTES
Version 1.0
=============================================================================
                 - DISCLAIMER -
 This sample script is not supported under any Microsoft standard support 
 program or service. The sample script is provided AS IS without warranty of
 any kind. Microsoft further disclaims all implied warranties including, 
 without limitation, any implied warranties of merchantability or of fitness
 for a particular purpose. The entire risk arising out of the use or 
 performance of the sample scripts and documentation remains with you. In no
 event shall Microsoft, its authors, or anyone else involved in the creation,
 production, or delivery of the scripts be liable for any damages whatsoever
 (including, without limitation, damages for loss of business profits, business 
 interruption, loss of business information, or other pecuniary loss) arising
 out of the use of or inability to use the sample scripts or documentation,
 even if Microsoft has been advised of the possibility of such damages.
=============================================================================
                 - RELEASE NOTES -
 v2.0   2024.10.01 - New Realase
=============================================================================
#>

function Set-AadPimRoleMembers {
    param (

    )

    $LogType = "DashboardAAD_AADRoles"
    $DataObj = $null
    $DataObj = New-Object System.Object
    $DataObj | Add-Member -MemberType NoteProperty -Name AzureAD_RoleName -force -Value "User Administrator"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_DisplayName -force -Value "Jhon Do"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_UPN -force -Value "jdo@contoso.com"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_ObjectId -force -Value '11111111-aaaa-1111-aaaa-111111111111'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value 'N/A'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_DirSync -force -Value $true
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_PIMRoleAssignmentState -force -Value 'Active'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_RoleMemberType -force -Value 'Direct'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_RoleStartDateTime -force -Value '2000-01-01T12:00:00Z'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_RoleEndDateTime -force -Value '2000-01-01T12:00:00Z'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_GroupName -force -Value 'mygroup@contoso.com'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_LastSignins -force -Value '2000-01-01T12:00:00Z'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_MFA -force -Value "Set"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_Methods -force -Value "N/A"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_PhoneNumber -Force -Value '+33 999979999'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_AlternativePhoneNumber -force -Value '+33 999979999'
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_CreationDate -force -Value "2000-01-01T12:00:00Z"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_RefreshTokensValid -force -Value "2000-01-01T12:00:00Z"
	$DataObj | Add-Member -MemberType NoteProperty -Name Account_ExcServices -force -Value "N/A"
	$DataObj | Add-Member -MemberType NoteProperty -Name Account_TeamsServices -force -Value "N/A"
	$DataObj | Add-Member -MemberType NoteProperty -Name Account_SharepointServices -force -Value "N/A"
	$DataObj | Add-Member -MemberType NoteProperty -Name Account_YammerServices -force -Value "N/A"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_onPremisesDistinguishedName -force -Value "CN=Jhon Do,OU=Accounts,OU=IT,OU=Business Units,DC=contoso,DC=com"
    $DataObj | Add-Member -MemberType NoteProperty -Name cTimeStampField -force -Value "2000-01-01T12:00:00Z"
    $DataObj | Add-Member -MemberType NoteProperty -Name IsBuiltIn -force -Value $true
    $DataObj | Add-Member -MemberType NoteProperty -Name IsPrivileged -force -Value $true
    $DataObj | Add-Member -MemberType NoteProperty -Name RolePermissions -force -Value "N/A"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_NI_LastSignins -force -Value "2000-01-01T12:00:00Z"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_Success_LastSignins -force -Value "2000-01-01T12:00:00Z"
    $DataObj | Add-Member -MemberType NoteProperty -Name Account_Enabled -force -Value $true
    $DataObj | Add-Member -MemberType NoteProperty -Name RoleScope -force -Value "N/A"

    
    $json = $DataObj | ConvertTo-Json
    Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField
}
function Set-AADConditionalAccess {
    param (

    )
    $LogType = "DashboardAAD_CA"
    $InitLAW = New-Object -TypeName PSObject   
    $InitLAW | Add-Member -MemberType NoteProperty -Name Id -force -Value '11111111-aaaa-1111-aaaa-111111111111'
    $InitLAW | Add-Member -MemberType NoteProperty -Name DisplayName -force -Value 'CA to Initialize Log Analytics Workspace Custom Log'
    $InitLAW | Add-Member -MemberType NoteProperty -Name CreatedDateTime -force -Value (get-date).AddYears(-10).ToString("r")
    $InitLAW | Add-Member -MemberType NoteProperty -Name ModifiedDateTime -force -Value (get-date).AddYears(-10).ToString("r")
    $InitLAW | Add-Member -MemberType NoteProperty -Name State -force -Value 'enabled'
    $InitLAW | Add-Member -MemberType NoteProperty -Name SignInRiskLevels -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name UserRiskLevels -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name IncludeGroups -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name ExcludeGroups -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name IncludeRoles -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name ExcludeRoles -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name IncludeUsers -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name ExcludeUsers -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name IncludeApplications -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name ExcludeApplications -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name IncludeProtectionLevels -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name IncludeUserActions -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name IncludeDeviceStates -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name ExcludeDeviceStates -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name deviceStates -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name includeLocations -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name excludeLocations -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name ClientAppTypes -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name includePlatforms -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name excludePlatforms -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name GrantControls_Operator -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name GrantControls_BuiltInControls -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name CustomAuthenticationFactors -force -Value "N/A"
    $InitLAW | Add-Member -MemberType NoteProperty -Name TermsOfUse -force -Value "N/A" 
    $InitLAW | Add-Member -MemberType NoteProperty -Name ApplicationEnforcedRestrictions -force -Value $true  
    $InitLAW | Add-Member -MemberType NoteProperty -Name cloudAppSecurityType -force -Value 1
    $InitLAW | Add-Member -MemberType NoteProperty -Name CloudAppSecurity_isEnabled -force -Value $true
    $InitLAW | Add-Member -MemberType NoteProperty -Name PersistentBrowser_mode -force -Value 1
    $InitLAW | Add-Member -MemberType NoteProperty -Name PersistentBrowser_IsEnabled -force -Value $true
    $InitLAW | Add-Member -MemberType NoteProperty -Name SignInFrequency_value -force -Value 90
    $InitLAW | Add-Member -MemberType NoteProperty -Name SignInFrequency_type -force -Value 1
    $InitLAW | Add-Member -MemberType NoteProperty -Name SignInFrequency_isEnabled -force -Value $true
    $InitLAW | Add-Member -MemberType NoteProperty -Name cTimeStampField -force -Value $TimeStampField
    $json = $InitLAW | ConvertTo-Json
    Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField
}

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}
# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType, $TimeStampField)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    #Write-Host "LAW Header TimeStamp $TimeStampField" -ForegroundColor Cyan
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    #return $response.StatusCode

}

# Replace with your Workspace ID
$CustomerId     = "xxx"  
# Replace with your Primary Key
$SharedKey      = "xxx"

$TimeStampField = [DateTime]::UtcNow.ToString("r")
Write-Host "LAW TimeStamp $TimeStampField" -ForegroundColor Cyan

Write-Host "Init DashboardAAD_AADRoles Table Schema" -ForegroundColor Yellow
Set-AadPimRoleMembers
Write-Host "--> End of Init" -ForegroundColor Green 

Write-Host "Init DashboardAAD_CA Table Schema" -ForegroundColor Yellow
Set-AADConditionalAccess
Write-Host "--> EEnd of Init" -ForegroundColor Green


