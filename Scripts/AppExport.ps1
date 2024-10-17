<#
The script creates report files in the folder:
- CAPolicies.csv

.NOTES
Version 3.0
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

=============================================================================
#>

param (
        [string]$FilePath="C:\Azure\CAPExport" # + $(Get-Date -Format "yyyy-MM-dd") + "\",
    )

function Get-AadAppsConsents {
param(
    $ServicePrincipalid,
    $TimeStampField
)

    #*********************************************************
    #Review Application Permissions
    #*********************************************************
    try {
        $ServicePrincipal = Get-MgBetaServicePrincipal -ServicePrincipalId $ServicePrincipalId
        $appPermissions = Get-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId #| Where-Object DeletedDateTime -EQ $null
        
        $PSObjs = @()

        foreach ($appPermission in $appPermissions) {
            $objResource = Get-MgbetaDirectoryObjectById -Ids $apppermission.ResourceId
            $appRole = $objResource.AdditionalProperties.appRoles | Where-Object {$_.id -eq $apppermission.appRoleId}
            
            $PSObj =  [PSCustomObject]@{
                PermissionType = "Application"
                ClientObjectId = $apppermission.PrincipalId
                ClientDisplayName = $apppermission.PrincipalDisplayName
                ResourceObjectId = $apppermission.ResourceId
                ResourceDisplayName = $appPermission.ResourceDisplayName
                Permission = $appRole.value
                PermissionId = $appRole.id
                PermissionDisplayName = $appRole.displayName
                PermissionDescription = $appRole.description
                ConsentType = $appRole.origin
                PrincipalObjectId = ""
                PrincipalDisplayName = ""
                PrincipalUserPrincipalName = ""
                PrincipalUserType = ""
                PermissionGrantId = $appPermission.Id
                cTimeStampField = $TimeStampField
            }
            $PSObjs += $PSObj
        }

        #*********************************************************
        #Review Delegated Permissions
        #*********************************************************
        $delegatedPermissions = Get-MgBetaServicePrincipalOauth2PermissionGrant -ServicePrincipalId $ServicePrincipalId

        foreach ($permission in $delegatedPermissions) {
            $objResource = Get-MgbetaDirectoryObjectById -Ids $permission.ResourceId
            $principalDisplayName = ""
            if ($permission.PrincipalId) {
                $principal = Get-MgBetaDirectoryObjectById -Ids $permission.PrincipalId
                $principalDisplayName = $principal.AdditionalProperties.displayName
                $PrincipalUserPrincipalName = $principal.AdditionalProperties.userPrincipalName
                $PrincipalUserType = $principal.AdditionalProperties.userType
            }

            foreach ($scope in $permission.Scope.split(' ')) {
                if ($scope) {
                    try {
                        $appdelperm=Find-MgGraphPermission $scope -PermissionType Delegated -ExactMatch -ErrorAction SilentlyContinue
                    } catch {
                        $appdelperm = @{
                            $appdelperm.Id = ""
                            $appdelperm.DisplayName = ""
                            $appdelperm.Description = ""
                        }
                    }
                    $PSObj = [PSCustomObject]@{
                        PermissionType = "Delegated"
                        ClientObjectId = $ServicePrincipal.Id
                        ClientDisplayName = $ServicePrincipal.DisplayName
                        ResourceObjectId = $permission.ResourceId
                        ResourceDisplayName = $objResource.AdditionalProperties.displayName
                        Permission = $scope
                        PermissionId = $appdelperm.Id
                        PermissionDisplayName = $appdelperm.Name
                        PermissionDescription = $appdelperm.Description
                        ConsentType = $permission.ConsentType
                        PrincipalObjectId = $permission.PrincipalId
                        PrincipalDisplayName = $principalDisplayName
                        PrincipalUserPrincipalName = $PrincipalUserPrincipalName
                        PrincipalUserType = $PrincipalUserType
                        PermissionGrantId = $permission.Id
                        cTimeStampField = $TimeStampField
                    }
                    $PSObjs += $PSObj
                }

            }
        }
        return $PSObjs
    } catch {
        Write-Error "An error occurred: $_"    
    }
}


function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile,
        [string]$Type,  # Can be "INFO" or "ERROR"
        [string]$color,
        [string]$Category
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$Type] - $Message"

    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry

    # Write to console
    if ($Type -eq "ERROR") {
        Write-Error $logEntry -Category $Category
    } else {
        Write-Host $logEntry -ForegroundColor $color
    }
}

########################################################
#### Enter your environment information
########################################################
#Replace with your App ID
    $tenantId       = 'eda50e56-2453-45a2-8909-9138efe4ebca'
########################################################

$LogFile = "$FilePath\CAPExport.log"

If(!(test-path $FilePath))
{
      $result=New-Item -ItemType Directory -Force -Path $FilePath
      #Write-Host "Folder $FilePath created" -ForegroundColor Yellow
      Write-Log -Message "Folder $FilePath created" -color "Yellow" -LogFile $LogFile -Type "INFO"
}



Write-Log -Message " " -LogFile $LogFile -Type "INFO" -color "Green"
Write-Log -Message "Begining CAPExport Export" -LogFile $LogFile -Type "INFO" -color "Cyan"

$version = Get-InstalledModule Microsoft.Graph.beta -ErrorAction SilentlyContinue
if ($version -ne $null) {
    #Write-Host "$($version.name) Version : $($version.Version)" -ForegroundColor Green
    Write-Log -Message "$($version.name) Version : $($version.Version)" -LogFile $LogFile -Type "INFO" -color "Yellow"
}
else {
    #Write-Error "Install Microsoft Graph Beta Module : Install-Module Microsoft.Graph.Beta" -Category NotInstalled
    Write-Log -Message "Error / Install Microsoft Graph Beta Module : Install-Module Microsoft.Graph.Beta" -LogFile $LogFile -Type "ERROR" -color "Red" -Category NotInstalled
    exit
}

$version = Get-InstalledModule Microsoft.Graph -ErrorAction SilentlyContinue
if ($version -ne $null) {
    #Write-Host "$($version.name) Version : $($version.Version)" -ForegroundColor Green
    Write-Log -Message "$($version.name) Version : $($version.Version)" -LogFile $LogFile -Type "INFO" -color "Yellow" 
}
else {
    #Write-Error "Install Microsoft Graph Module : Install-Module Microsoft.Graph" -Category NotInstalled
    Write-Log -Message "Error / Install Microsoft Graph Module : Install-Module Microsoft.Graph" -LogFile $LogFile -Type "ERROR" -color "Red" -Category NotInstalled
    exit
}

Write-Log -Message "Connecting to Entra ID" -LogFile $LogFile -Type "INFO" -color "Cyan"
#Disconnect-MgGraph
$result = Connect-MgGraph -Scopes "Directory.Read.All"
Write-Log -Message "Connecting to Entra ID - $result" -LogFile $LogFile -Type "INFO" -color "Green"

Write-Log -Message "$env:USERNAME" -LogFile $LogFile -Type "INFO" -color "Cyan"

# Attempt to establish a connection to Microsoft Graph
try {    
    # Verify if the connection was successful by checking the context
    $MgContext = Get-MgContext
    if ($null -eq $MgContext) {
        #Write-Error "Failed to connect to Microsoft Graph" -Category ConnectionError
        Write-Log -Message "Failed to connect to Microsoft Graph" -LogFile $LogFile -Type "ERROR" -color "Red" -Category ConnectionError
        exit
    } else {
        #Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
        Write-Log -Message "Successfully connected to Microsoft Graph" -LogFile $LogFile -Type "INFO" -color "Green"
    }
} catch {
    #Write-Error "Error connecting to Microsoft Graph: $_" -Category ConnectionError
    Write-Log -Message "Error connecting to Microsoft Graph: $_" -LogFile $LogFile -Type "ERROR" -color "Red" -Category ConnectionError
}

#################
#Write-Host "Beginning App consents export" -ForegroundColor Yellow
Write-Log -Message "Beginning App consents export" -LogFile $LogFile -Type "INFO" -color "Yellow"
$ServicePrincipalIds = (Get-MgServicePrincipal -All).Id
$i=1
$total = $ServicePrincipalIds.Count
$AppConsentObjs = @()
$AppConsentObj = @()
ForEach ($ServicePrincipalId in $ServicePrincipalIds) {
    Write-Progress -Id 0 -Activity "Azure AD Apps Consents Export - $($ServicePrincipalId.DisplayName)" -Status ("Checked {0}/{1} Apps" -f $i++, $Total) -PercentComplete ((($i-1) / $Total) * 100)
    
    $percentComplete = [math]::Floor((($i-1) / $Total) * 100)

    # Log progress every 10%
    if ($percentComplete % 10 -eq 0) {
        Write-Log -Message "Processing items - $percentComplete%" -LogFile $LogFile -Type "INFO" -color "Yellow"
    }

    $AppConsentObj=Get-AadAppsConsents -ServicePrincipalid $ServicePrincipalId -TimeStampField $TimeStampField
    $AppConsentObjs+=$AppConsentObj
    
}
Write-Progress -Id 0 -Activity "Azure AD Apps Consents Export" -Completed
#Write-Host "--> End of App consents export" -ForegroundColor Green
Write-Log -Message "--> End of App consents export" -LogFile $LogFile -Type "INFO" -color "Green"

Clear-Content "$FilePath\AADAppsPermissionsV0.1.csv" -Force -ErrorAction SilentlyContinue
if($CSV){$AppConsentObjs | Export-Csv -Path "$FilePath\AADAppsPermissions.csv" -NoTypeInformation -Force}
    
# Specify the name of the record type that you'll be creating
$LogType = "DashboardAAD_AADAppConsents"
$json = $AppConsentObjs | ConvertTo-Json
if($SharedKey){Post-DataToLogAnalytics -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
#################
Write-Log -Message " " -LogFile $LogFile -Type "INFO" -color "Green"