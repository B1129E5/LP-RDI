<#
.SYNOPSIS
LPDI_Dashboard.ps1 - Export Azure AD & Azure RBAC informations
	
.DESCRIPTION
This script export Data from Azure AD & Azure to CSV files and/or a Log Analytics Workspace
To use export to the Workspace, provide Workspace ID & Key in the variables $CustomerId & $SharedKey
Leave BLANK to NOT use Workspace
    	
.PARAMETER FilePath
Export CSV files to this folder. It will be created if not exist  

.PARAMETER All
Execute all exports

.PARAMETER AzureAD_SP
Export all information about Service Principals & Consents

.PARAMETER AzureAD_Role
Export all information about Azure AD Roles

.PARAMETER AzureAD_CA
Export all information about conditional access policies

.PARAMETER AzureAD_Logs
Export all information about Azure AD Audit Logs & Signins Logs. Only exported when CSV is True

.PARAMETER Days
Define how many days to export for Azure AD Logs & Signins Logs. By default 7 days

.PARAMETER CSV
Export data to a CSV files

.EXAMPLE
.\LPDI_Dashboard.ps1 -FolderPath C:\Azure\LPDI -Days 5 -All -CSV
Export Data to C:\Azure\LPDI folder, execute all exports, and export Audit & Signin Logs for 5 days 

.EXAMPLE
.\LPDI_Dashboard.ps1 -All
Export Data to Log Analytics Workspace only (you should fill your Workspace Key in the variable), execute all exports 

.OUTPUTS
The script creates report files in the folder:
- AADAppsPermissions.csv
- AADRoleMembersPIM.csv
- CAPolicies.csv

.NOTES
Version 2.1
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
 v2.0 2022.01.28 - Add Export to Log Analytics + improvement
 v2.1 2022.02.24 - Remove Signin & Audit Logs export

=============================================================================
#>

param (
        [string]$FilePath="C:\Azure\LPDI", # + $(Get-Date -Format "yyyy-MM-dd") + "\",
        [switch]$All=$true,
        [switch]$AzureAD_SP,
        [switch]$AzureAD_Role,
        [switch]$AzureAD_CA,
        [switch]$CSV=$false
    )

function Get-AadAppsConsents {
param(
    $ServicePrincipalid,
    $TimeStampField
)

    #*********************************************************
    #Review Application Permissions
    #*********************************************************
    $ServicePrincipal = Get-MgBetaServicePrincipal -ServicePrincipalId $ServicePrincipalId
    $appPermissions = Get-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId #| Where-Object DeletedDateTime -EQ $null
    
    $PSObjs = @()

    foreach ($appPermission in $appPermissions) {
        $objResource = Get-MgbetaDirectoryObjectById -Ids $apppermission.ResourceId
        $appRole = $objResource.AdditionalProperties.appRoles | Where-Object {$_.id -eq $apppermission.appRoleId}
        
        $PSObj = New-Object System.Object
        $PSObj | Add-Member -MemberType NoteProperty -Name PermissionType -Force -Value "Application"
        $PSObj | Add-Member -MemberType NoteProperty -Name ClientObjectId -Force -Value $apppermission.PrincipalId
        $PSObj | Add-Member -MemberType NoteProperty -Name ClientDisplayName -Force -Value $apppermission.PrincipalDisplayName
        $PSObj | Add-Member -MemberType NoteProperty -Name ResourceObjectId -Force -Value $apppermission.ResourceId
        $PSObj | Add-Member -MemberType NoteProperty -Name ResourceDisplayName -Force -Value $appPermission.ResourceDisplayName
        $PSObj | Add-Member -MemberType NoteProperty -Name Permission -Force -Value $appRole.value
        $PSObj | Add-Member -MemberType NoteProperty -Name PermissionId -Force -Value $appRole.id
        $PSObj | Add-Member -MemberType NoteProperty -Name PermissionDisplayName -Force -Value $appRole.displayName
        $PSObj | Add-Member -MemberType NoteProperty -Name PermissionDescription -Force -Value $appRole.description
        $PSObj | Add-Member -MemberType NoteProperty -Name ConsentType -Force -Value $appRole.origin
        $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalObjectId -Force -Value ""
        $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Force -Value ""
        $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalUserPrincipalName -Force -Value ""
        $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalUserType -Force -Value ""
        $PSObj | Add-Member -MemberType NoteProperty -Name PermissionGrantId -Force -Value $appPermission.Id
        $PSObj | Add-Member -MemberType NoteProperty -Name cTimeStampField -Force -Value $TimeStampField
        $PSObjs += $PSObj
    }

    #*********************************************************
    #Review Delegated Permissions
    #*********************************************************
    $delegatedPermissions = Get-MgBetaServicePrincipalOauth2PermissionGrant -ServicePrincipalId $ServicePrincipalId

    foreach ($permission in $delegatedPermissions) {

        #$sp=(Get-MgServicePrincipal -ServicePrincipalId $permission.ResourceId).DisplayName
        #$permission.ResourceId --> Microsoft Graph or other

        $objResource = Get-MgbetaDirectoryObjectById -Ids $permission.ResourceId
        $principalDisplayName = ""
        if ($permission.PrincipalId) {
            $principal = Get-MgBetaDirectoryObjectById -Ids $permission.PrincipalId
            $principalDisplayName = $principal.AdditionalProperties.displayName
            $PrincipalUserPrincipalName = $principal.AdditionalProperties.userPrincipalName
            $PrincipalUserType = $principal.AdditionalProperties.userType
        }

        foreach ($scope in $permission.Scope.split(' ')) { #$scope }}
            if ($scope) {
                $PSObj = New-Object System.Object
                $PSObj | Add-Member -MemberType NoteProperty -Name PermissionType -Force -Value "Delegated"
                $PSObj | Add-Member -MemberType NoteProperty -Name ClientObjectId -Force -Value $ServicePrincipal.Id
                $PSObj | Add-Member -MemberType NoteProperty -Name ClientDisplayName -Force -Value $ServicePrincipal.DisplayName
                $PSObj | Add-Member -MemberType NoteProperty -Name ResourceObjectId -Force -Value $permission.ResourceId
                $PSObj | Add-Member -MemberType NoteProperty -Name ResourceDisplayName -Force -Value $objResource.AdditionalProperties.displayName
                $PSObj | Add-Member -MemberType NoteProperty -Name Permission -Force -Value $scope
                try {
                    $appdelperm=Find-MgGraphPermission $scope -PermissionType Delegated -ExactMatch -ErrorAction SilentlyContinue
                    $PSObj | Add-Member -MemberType NoteProperty -Name PermissionId -Force -Value $appdelperm.Id
                    $PSObj | Add-Member -MemberType NoteProperty -Name PermissionDisplayName -Force -Value $appdelperm.Name
                    $PSObj | Add-Member -MemberType NoteProperty -Name PermissionDescription -Force -Value $appdelperm.Description  
                }
                catch {
                    $PSObj | Add-Member -MemberType NoteProperty -Name PermissionId -Force -Value ""
                    $PSObj | Add-Member -MemberType NoteProperty -Name PermissionDisplayName -Force -Value ""
                    $PSObj | Add-Member -MemberType NoteProperty -Name PermissionDescription -Force -Value ""
                }
                
                $PSObj | Add-Member -MemberType NoteProperty -Name ConsentType -Force -Value $permission.ConsentType
                $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalObjectId -Force -Value $permission.PrincipalId
                $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Force -Value $principalDisplayName
                $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalUserPrincipalName -Force -Value $PrincipalUserPrincipalName
                $PSObj | Add-Member -MemberType NoteProperty -Name PrincipalUserType -Force -Value $PrincipalUserType
                $PSObj | Add-Member -MemberType NoteProperty -Name PermissionGrantId -Force -Value $permission.Id
                $PSObj | Add-Member -MemberType NoteProperty -Name cTimeStampField -Force -Value $TimeStampField
                $PSObjs += $PSObj
            }

        }
    
    }
    return $PSObjs
}
Function ObjPIMPermission {

    param (
      $Account_MFA,
      $Account_Methods,
      $AuthenPhoneNumber,
      $AlternateAuthenPhoneNumber,
      $role,
      $ObjDetails,
      $AccountLastSignins,
      $TimeStampField,
      $ObjUserID,
      $FromGroup,
      $ObjPermDetails,
      $PAG
  )
    if($ObjUserID) {
      $ObjUser = Get-MgBetaUser -UserId $ObjUserID -Property DisplayName,Id,UserPrincipalName,SignInActivity,AccountEnabled,CreatedDateTime,UserType,OnPremisesSyncEnabled,OnPremisesDistinguishedName,AccountEnabled,lastSuccessfulSignInDateTime
      $AccountLastSignins = $ObjUser.SignInActivity
      $UserAuthentificationMethods = (Get-MgUserAuthenticationMethod -UserId $ObjUserID ).AdditionalProperties
  
      if ($UserAuthentificationMethods.Count -gt 2) {
        for ($i=0;$i -lt $UserAuthentificationMethods.Count;++$i){
          $UserAuthentificationMethods[$i].'@odata.type' -match $regex | Out-Null  
          $userMethods +="$($matches[3]):$($UserAuthentificationMethods[$i].displayName)`r`n" #`r`n"
        }
        $Account_MFA = "Provided"
        $Account_Methods = $userMethods           
      }
      elseif ($UserAuthentificationMethods.Count -gt 1) {
        $UserAuthentificationMethods.'@odata.type' -match $regex | Out-Null  
        $userMethods ="$($matches[3]):$($UserAuthentificationMethods.displayName)`r`n"
      }
      else {
        $Account_MFA="Not Provided"
        $Account_Methods = ""
      }
  
      $AuthenPhoneNumber = $null
      $AlternateAuthenPhoneNumber = $null
      try {
          $uri = "https://graph.microsoft.com/beta/users/$($ObjUserID)/authentication/phoneMethods"
          $myexport = Invoke-MgGraphRequest -Method GET -Uri $URI
  
      }
      catch {
          $AuthenPhoneNumber = "API Error"
          $AlternateAuthenPhoneNumber = "API Error"
      }
      $result=$null
      $result=$myexport.value
      if ($result.id.count -ne 0) {
          for ($i=0;$i -lt $result.id.Count;++$i){
              if ($result[$i].id -eq 'b6332ec1-7057-4abe-9331-3d72feddfe41') {$AlternateAuthenPhoneNumber = $result[$i].phoneNumber}
              if ($result[$i].id -eq '3179e48a-750b-4051-897c-87b9720928f7') {$AuthenPhoneNumber = $result[$i].phoneNumber}  
          }
      }
    }
  
    if ($PAG) {
      $RoleMemberType = "PAG ($($PAG.AccessId))"
    }
    elseif ($FromGroup) {
      $RoleMemberType = "Group"
    }
    else {
      $RoleMemberType = "Direct"
    }
  
    
  
    $obj = [pscustomobject][ordered]@{
      "Account_MFA"                         = $Account_MFA
      "Account_Methods"                     = $Account_Methods
      "Account_PhoneNumber"                 = $AuthenPhoneNumber
      "Account_AlternativePhoneNumber"      = $AlternateAuthenPhoneNumber
      "AzureAD_RoleName"                    = $role.RoleDefinition.DisplayName
      "Account_DisplayName"                 = (&{if ($ObjUser) {$ObjUser.DisplayName} else {$ObjDetails.AdditionalProperties.displayName}})
      "Account_UPN"                         = (&{if ($ObjUser) {$ObjUser.UserPrincipalName} else {$ObjDetails.AdditionalProperties.userPrincipalName}})
      "Account_ObjectId"                    = (&{if ($ObjUser) {$ObjUser.Id} else {$role.PrincipalId}})
      "Account_CreationDate"                = (&{if ($ObjUser) {$ObjUser.CreatedDateTime} else {$ObjDetails.AdditionalProperties.createdDateTime}}) 
      "Account_Type"                        = (&{if ($ObjUser) {$ObjUser.UserType} else {$AccountType}})
      "Account_DirSync"                     = (&{if ($ObjUser) {$ObjUser.OnPremisesSyncEnabled} else {$ObjDetails.AdditionalProperties.onPremisesSyncEnabled}})
      "Account_PIMRoleAssignmentState"      = (&{if ($PAG) {"Eligible"} elseif ($role.status -eq "Provisioned") {"Eligible"} else {"Active"}})
      "Account_RoleMemberType"              = $RoleMemberType
      "Account_RoleStartDateTime"           = (&{if ($PAG) {$PAG.CreatedDateTime} else {$role.CreatedDateTime}})
      "Account_RoleEndDateTime"             = switch ($role.ScheduleInfo.Expiration.EndDateTime) {
        {$role.ScheduleInfo.Expiration.EndDateTime -match '20'} {$role.ScheduleInfo.Expiration.EndDateTime}
        {$role.ScheduleInfo.Expiration.EndDateTime -notmatch '20'} {"N/A"}}
      "Account_GroupName"                   = $FromGroup
      "Account_LastSignins"                 = $AccountLastSignins.LastSignInDateTime
      "Account_RefreshTokensValid"          = $ObjDetails.AdditionalProperties.refreshTokensValidFromDateTime
      "Account_onPremisesDistinguishedName" = (&{if ($ObjUser) {$ObjUser.OnPremisesDistinguishedName} else {$ObjDetails.AdditionalProperties.onPremisesDistinguishedName}})
      "cTimeStampField"                     = $TimeStampField
      "TimeGenerated"                       = $TimeStampField
      "IsBuiltIn"                           = (&{if ($role.roleDefinition.isBuiltIn) {$True} else {$False}})
      "IsPrivileged"                        = $role.roleDefinition.IsPrivileged
      "RolePermissions"                     = $ObjPermDetails
      "Account_NI_LastSignins"              = $AccountLastSignins.lastNonInteractiveSignInDateTime
      "Account_Success_LastSignins"         = $AccountLastSignins.LastSuccessfulSignInDateTime
      "Account_Enabled"                     = $ObjUser.AccountEnabled
      "RoleScope"                           = (&{if ($role.DirectoryScopeId -eq "/") {"/"} elseif ($role.DirectoryScopeId -like "/administrativeUnits*") {"Administrative Unit"} else {"Application"}})
    }
    Return $obj
  }
function Get-EntraIDPIMRole {

    Param (
        [string]$FolderPath,
        [string]$customerId,
        [string]$sharedKey
    )

# Specify the name of the record type that you'll be creating
$LogType = "DashboardAAD_AADRoles"

$ExportFilename = "$FolderPath\AADRoleMembersPIM.csv"

$roles = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty roleDefinition
$roles += Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty roleDefinition #,principal,DirectoryScope -Verbose:$false -ErrorAction Stop # | select id,principalId,directoryScopeId,roleDefinitionId,status,principal,@{n="roleDefinition1";e={$_.roleDefinition}})

$AllPIMPermissions = @()
$Total = $roles.count
$t=1

foreach ($role in $roles) {


  Write-Progress -Id 2 -Activity "Get Entra RBAC Information" -Status ("Checked {0}/{1} Accounts --> {2}" -f $t++, $Total, $ObjDetails.AdditionalProperties.displayName) -PercentComplete ((($t-1) / $Total) * 100)


  $regex = "^([^.]+)\.([^.]+)\.(.+)$"

  $ObjDetails = @()
  $ObjPerm = @()
  $ObjUser = @()
  $AccountLastSignins=$null
  $userMethods = $null

  $ObjDetails = Get-MgBetaDirectoryObject -DirectoryObjectId $role.PrincipalId
  $ObjDetails.AdditionalProperties.'@odata.type' -match $regex | out-null
  $AccountType = $Matches[3]

  $ObjPermDetails = $null
  $ObjPerm = $role.roleDefinition.RolePermissions.AllowedResourceActions
  


  for ($i=0;$i -lt $ObjPerm.Count;++$i){if (($i+1) -ne $ObjPerm.Count) {$ObjPermDetails += "$($ObjPerm[$i])`r`n"} else {$ObjPermDetails += "$($ObjPerm[$i])"}}
 
    if ($matches[3] -eq "Group") {
      $ObjMembers = Get-MgGroupMember -GroupId $role.PrincipalId -All
      foreach ($ObjMember in $ObjMembers) {
        $ObjMember.AdditionalProperties.'@odata.type' -match $regex | out-null
        if ($Matches[3] -eq 'user') {
          $result = ObjPIMPermission -Account_MFA $Account_MFA -Account_Methods $Account_Methods -AuthenPhoneNumber $AuthenPhoneNumber -AlternateAuthenPhoneNumber $AlternateAuthenPhoneNumber -role $role -ObjDetails $ObjDetails -AccountLastSignins $AccountLastSignins -TimeStampField $TimeStampField -ObjUserID $ObjMember.Id -FromGroup $ObjDetails.AdditionalProperties.displayName -ObjPermDetails $ObjPermDetails
          if ($result) {$AllPIMPermissions += $result}
        }
        else {
          $Account_MFA = "N/A --> SP"
          $Account_Methods = "N/A --> SP"
          $AuthenPhoneNumber = "N/A --> SP"
          $AlternateAuthenPhoneNumber = "N/A --> SP"
          $result = ObjPIMPermission -Account_MFA $Account_MFA -Account_Methods $Account_Methods -AuthenPhoneNumber $AuthenPhoneNumber -AlternateAuthenPhoneNumber $AlternateAuthenPhoneNumber -role $role -ObjDetails $ObjDetails -AccountLastSignins $AccountLastSignins -TimeStampField $TimeStampField -ObjUserID $null -FromGroup $ObjDetails.AdditionalProperties.displayName -ObjPermDetails $ObjPermDetails
          $AllPIMPermissions += $result
        }
      }

      $ObjRoleMembers = Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "groupId eq '$($role.principalId)'" -ExpandProperty principal
      if ($ObjRoleMembers) {
        foreach ($ObjRoleMember in $ObjRoleMembers) {
          $result = ObjPIMPermission -role $role -ObjDetails $ObjDetails -TimeStampField $TimeStampField -ObjUserID $ObjRoleMember.PrincipalId -ObjPermDetails $ObjPermDetails -PAG $ObjRoleMember -FromGroup $ObjDetails.AdditionalProperties.displayName
          if ($result) {$AllPIMPermissions += $result}  
        } 
      }
      $Account_MFA = "N/A --> GRP"
      $Account_Methods = "N/A --> GRP"
      $AuthenPhoneNumber = "N/A --> GRP"
      $AlternateAuthenPhoneNumber = "N/A --> GRP"
      $result = ObjPIMPermission -Account_MFA $Account_MFA -Account_Methods $Account_Methods -AuthenPhoneNumber $AuthenPhoneNumber -AlternateAuthenPhoneNumber $AlternateAuthenPhoneNumber -role $role -ObjDetails $ObjDetails -AccountLastSignins $AccountLastSignins -TimeStampField $TimeStampField -ObjUserID $null -FromGroup $null -ObjPermDetails $ObjPermDetails
      if ($result) {$AllPIMPermissions += $result}
    }
    #User specificity processing
    elseif (($matches[3] -eq "user")) {
      $result = ObjPIMPermission -Account_MFA $Account_MFA -Account_Methods $Account_Methods -AuthenPhoneNumber $AuthenPhoneNumber -AlternateAuthenPhoneNumber $AlternateAuthenPhoneNumber -role $role -ObjDetails $ObjDetails -AccountLastSignins $AccountLastSignins -TimeStampField $TimeStampField -ObjUserID $role.PrincipalId -FromGroup $null -ObjPermDetails $ObjPermDetails
      if ($result) {$AllPIMPermissions += $result}
    }
    else {
      $Account_MFA = "N/A --> SP"
      $Account_Methods = "N/A --> SP"
      $AuthenPhoneNumber = "N/A --> SP"
      $AlternateAuthenPhoneNumber = "N/A --> SP"

      $result = ObjPIMPermission -Account_MFA $Account_MFA -Account_Methods $Account_Methods -AuthenPhoneNumber $AuthenPhoneNumber -AlternateAuthenPhoneNumber $AlternateAuthenPhoneNumber -role $role -ObjDetails $ObjDetails -AccountLastSignins $AccountLastSignins -TimeStampField $TimeStampField -ObjUserID $null -FromGroup $null -ObjPermDetails $ObjPermDetails
      if ($result) {$AllPIMPermissions += $result}
    }
}





if($csv){
    
    Clear-Content $ExportFilename -Force -ErrorAction SilentlyContinue

}

if ($AllPIMPermissions) {
    if($CSV){
                  
        $output = $AllPIMPermissions | ConvertTo-Csv -Delimiter ";"
        $output | Out-File -FilePath $ExportFilename -Force

    }
    $json = $AllPIMPermissions | ConvertTo-Json
    if($SharedKey){Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
}
Write-Progress -Id 2 -Activity "Get AAD RBAC Information" -Completed




}
function Get-AadRoleMembers {
    param (
        [string]$FolderPath
    )

    $aadRoles=$null
    $aadRole=$null
    $aadRoleMembers=$null
    $aadRoleMember=$null
    $TotalGroupMembers=$null

    $Summary= New-Object System.Object
    $Summary = @()
    # Specify the name of the record type that you'll be creating
    $LogType = "DashboardAAD_AADRoles"
    $ExportFilename = "$FolderPath\AADRoleMembersPIM.csv"
    if($CSV){
        Clear-Content $ExportFilename -Force -ErrorAction SilentlyContinue
        $header = '"Account_MFA","Account_Methods","Account_PhoneNumber","Account_AlternativePhoneNumber","AzureAD_RoleName","Account_DisplayName","Account_UPN","Account_ObjectId","Account_CreationDate","Account_Type","Account_DirSync","Account_PIMRoleAssignmentState","Account_RoleMemberType","Account_RoleStartDateTime","Account_RoleEndDateTime","Account_GroupName","Account_LastSignins","Account_RefreshTokensValid","Account_onPremisesDistinguishedName","cTimeStampField","TimeGenerated"'
        $header | Out-File $ExportFilename
    }

    $aadRoles=Get-MgDirectoryRole
    foreach ($aadRole in $aadRoles) {
       
           $aadRoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $aadRole.Id
           foreach ($aadRoleMember in $aadRoleMembers) {
                $PSObj = New-Object System.Object
                $PSObj | Add-Member -MemberType NoteProperty -Name AzureAD_RoleName -force -Value $aadRole.DisplayName
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_DisplayName -force -Value $aadRoleMember.DisplayName
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_UPN -force -Value $aadRoleMember.UserPrincipalName
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_ObjectId -force -Value $aadRoleMember.ObjectId
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_CreationDate -force -Value $aadRoleMember.ExtensionProperty.createdDateTime

                if ($aadRoleMember.UserType -eq $null) {
                
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value "Group"
                    $aadgroupmembers = Get-MgGroup -Search $aadRoleMember.DisplayName | Get-MgGroupMember
                    if ($aadgroupmembers) {$PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value "Group"}
                    else {$PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value "ServicePrincipal"}
                    foreach ($aadgroupmember in $aadgroupmembers) {
                
                        $PSObj2 = New-Object System.Object
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name AzureAD_RoleName -force -Value $aadRole.DisplayName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_DisplayName -force -Value $aadgroupmember.DisplayName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_UPN -force -Value $aadgroupmember.UserPrincipalName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_ObjectId -force -Value $aadgroupmember.ObjectId
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_CreationDate -force -Value $aadgroupmember.ExtensionProperty.createdDateTime
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_UserType -force -Value $aadgroupmember.UserType
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_DirSync -force -Value $aadgroupmember.DirSyncEnabled
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_PIMRoleAssignmentState -force -Value "Active"
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RoleMemberType -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RoleStartDateTime -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RoleEndDateTime -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_GroupName -force -Value $aadRoleMember.DisplayName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_LastSignins -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RefreshTokensValid -force -Value $aadgroupmember.RefreshTokensValidFromDateTime
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_onPremisesDistinguishedName -force -Value $aadgroupmember.ExtensionProperty.onPremisesDistinguishedName

                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_MFA -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_Methods -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_PhoneNumber -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_AlternativePhoneNumber -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name cTimeStampField -force -Value $TimeStampField
                        if($CSV){$PSObj2 | Export-Csv -Append -NoTypeInformation -Path $ExportFilename -Force}
                        $json = $PSObj2 | ConvertTo-Json
                        if($sharedKey){Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
     
                    }
                    $TotalGroupMembers = $TotalGroupMembers + $aadgroupmembers.count 
                }
                else {
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value $aadRoleMember.UserType
                }
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_DirSync -force -Value $aadRoleMember.DirSyncEnabled
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_PIMRoleAssignmentState -force -Value "Active"
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_RoleMemberType -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_RoleStartDateTime -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_RoleEndDateTime -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_GroupName -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_LastSignins -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_RefreshTokensValid -force -Value $aadRoleMember.RefreshTokensValidFromDateTime
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_onPremisesDistinguishedName -force -Value $aadRoleMember.ExtensionProperty.onPremisesDistinguishedName

                $PSObj | Add-Member -MemberType NoteProperty -Name Account_MFA -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_Methods -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_PhoneNumber -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_AlternativePhoneNumber -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name cTimeStampField -force -Value $TimeStampField
                if($csv){$PSObj | Export-Csv -Append -NoTypeInformation -Path $ExportFilename -Force}
                $json = $PSObj | ConvertTo-Json
                if($sharedKey){Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
     
           }

           #Write-Host "$($aadRole.DisplayName) :`t" -NoNewline
           $total = $aadRoleMembers.count + $TotalGroupMembers
           #Write-Host "$($total)"

           $Summarytmp = New-Object System.Object
           $Summarytmp | Add-Member -MemberType NoteProperty -Name AzureAD_RoleName -force -Value $aadRole.DisplayName
           $Summarytmp | Add-Member -MemberType NoteProperty -Name Total -force -Value $total

           $Summary += $Summarytmp

           $TotalGroupMembers=$null
    }
    $Summary
}
function Get-AzureADCAPolicies {
    param (
        [string]$FolderPath
    )

    import-module Microsoft.Graph.Identity.SignIns
    #$CAPolicies=Get-AzureADMSConditionalAccessPolicy
    $CAPolicies=Get-MgIdentityConditionalAccessPolicy


    # Specify the name of the record type that you'll be creating
    $LogType = "DashboardAAD_CA"
    $DataArr = @()
    $x=1
    $Total = $CAPolicies.Count
    $AllAADRoles = Get-MgDirectoryRoleTemplate

    foreach ($CAPolicy in $CAPolicies) {

            Write-Progress -Id 1 -Activity "Process Conditional Access Policies" -Status ("Checked {0}/{1} CA Policy" -f $x++, $Total) -PercentComplete ((($x-1) / $Total) * 100)
            $DataObj = New-Object -TypeName PSObject
            
            $DataObj | Add-Member -MemberType NoteProperty -Name Id -force -Value $CAPolicy.id
            $DataObj | Add-Member -MemberType NoteProperty -Name DisplayName -force -Value $CAPolicy.displayName
            $DataObj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -force -Value ""
            $DataObj | Add-Member -MemberType NoteProperty -Name ModifiedDateTime -force -Value ""
            $DataObj | Add-Member -MemberType NoteProperty -Name State -force -Value $CAPolicy.State

            $Details = $null
            $CAData = $CAPolicy.Conditions.SignInRiskLevels
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name SignInRiskLevels -force -Value $Details

        
            $Details = $null
            $CAData = $CAPolicy.Conditions.UserRiskLevels
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name UserRiskLevels -force -Value $Details
        
            $Details = $null
            $CAData = $CAPolicy.Conditions.Users.IncludeGroups
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-mgGroup -GroupId $CAData[$i]).displayname
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name IncludeGroups -force -Value $Details

            $Details = $null
            $CAData = $CAPolicy.Conditions.Users.ExcludeGroups
            for ($i=0;$i -lt $CAData.Count;++$i){
                            if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-mgGroup -GroupId $CAData[$i]).displayname
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name ExcludeGroups -force -Value $Details
      
            $Details = $null
            $CAData = $CAPolicy.Conditions.Users.IncludeRoles
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $($AllAADRoles | Where-Object {$_.id -eq $CAData[$i]}).DisplayName
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name IncludeRoles -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.Conditions.Users.ExcludeRoles
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $($AllAADRoles | Where-Object {$_.id -eq $CAData[$i]}).DisplayName
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name ExcludeRoles -force -Value $Details
        
            $Details = $null
            $CAData = $CAPolicy.Conditions.Users.IncludeUsers
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-MgUser -UserId $CAData[$i]).UserPrincipalName
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name IncludeUsers -force -Value $Details
               
            $Details = $null
            $CAData = $CAPolicy.Conditions.Users.ExcludeUsers
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-MgUser -UserId $CAData[$i]).UserPrincipalName
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name ExcludeUsers -force -Value $Details
         
            $Details = $null
            $CAData = $CAPolicy.Conditions.Applications.IncludeApplications
            for ($i=0;$i -lt $CAData.Count;++$i){
            
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-mgServicePrincipal -Filter ("appId eq '{0}'" -f $CAData[$i])).displayname
                }
                else {
                    $Name = $CAData[$i]
                }
            
            
                if (($i+1) -ne $CAData.Count) {
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
                $name =$null
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name IncludeApplications -force -Value $Details
        
            $Details = $null
            $CAData = $CAPolicy.Conditions.Applications.ExcludeApplications
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-MgServicePrincipal -Filter ("appId eq '{0}'" -f $CAData[$i])).displayname
                }
                else {
                    $Name = $CAData[$i]
                }
            
            
                if (($i+1) -ne $CAData.Count) {
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
                $name =$null
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name ExcludeApplications -force -Value $Details

            $Details = $null
            $CAData = $CAPolicy.Conditions.Applications.IncludeProtectionLevels
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name IncludeProtectionLevels -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.Conditions.Applications.IncludeUserActions
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -eq "urn:user:registerdevice") {
                    $IncludeUserActions = "Register or join devices"    
                }
                elseif ($CAData[$i] -eq "urn:user:registersecurityinfo") {
                    $IncludeUserActions = "Register security information"
                }
                else {
                    $IncludeUserActions = $CAData[$i]
                }
                $Details += "$IncludeUserActions`r`n"
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name IncludeUserActions -force -Value $Details
                                
            $Details = $null
            $CAData = $CAPolicy.Conditions.Devices.IncludeDeviceStates
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name IncludeDeviceStates -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.Conditions.Devices.ExcludeDeviceStates
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name ExcludeDeviceStates -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.Conditions.deviceStates
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name deviceStates -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.Conditions.Locations.includeLocations
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $CAData[$i]).DisplayName
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name includeLocations -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.Conditions.Locations.excludeLocations
            for ($i=0;$i -lt $CAData.Count;++$i){
                if ($CAData[$i] -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                    $Name = $(Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $CAData[$i]).DisplayName
                }
                else {
                    $Name = $CAData[$i]
                }
            
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$Name`r`n"
                }
                else {
                    $Details += "$Name"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name excludeLocations -force -Value $Details
        
            $Details = $null
            $CAData = $CAPolicy.Conditions.ClientAppTypes
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name ClientAppTypes -force -Value $Details
            
            $Details = $null
            $CAData = $CAPolicy.Conditions.Platforms.includePlatforms
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name includePlatforms -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.Conditions.Platforms.excludePlatforms
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name excludePlatforms -force -Value $Details

            $DataObj | Add-Member -MemberType NoteProperty -Name GrantControls_Operator -force -Value $CAPolicy.GrantControls._Operator
                
            $Details = $null
            $CAData = $CAPolicy.GrantControls.BuiltInControls
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name GrantControls_BuiltInControls -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.GrantControls.CustomAuthenticationFactors
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name CustomAuthenticationFactors -force -Value $Details
                
            $Details = $null
            $CAData = $CAPolicy.GrantControls.TermsOfUse
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name TermsOfUse -force -Value $Details

                
            $Details = $null
            $CAData = $CAPolicy.SessionControls.ApplicationEnforcedRestrictions
            for ($i=0;$i -lt $CAData.Count;++$i){
                if (($i+1) -ne $CAData.Count) { 
                    $Details += "$($CAData[$i])`r`n"
                }
                else {
                    $Details += "$($CAData[$i])"    
                }
            }
            $DataObj | Add-Member -MemberType NoteProperty -Name ApplicationEnforcedRestrictions -force -Value $Details
            
            $DataObj | Add-Member -MemberType NoteProperty -Name cloudAppSecurityType -force -Value $CAPolicy.SessionControls.CloudAppSecurity.cloudAppSecurityType
            $DataObj | Add-Member -MemberType NoteProperty -Name CloudAppSecurity_isEnabled -force -Value $CAPolicy.SessionControls.CloudAppSecurity.isEnabled
            $DataObj | Add-Member -MemberType NoteProperty -Name PersistentBrowser_mode -force -Value $CAPolicy.SessionControls.PersistentBrowser.Mode
            $DataObj | Add-Member -MemberType NoteProperty -Name PersistentBrowser_IsEnabled -force -Value $CAPolicy.SessionControls.PersistentBrowser.IsEnabled
            $DataObj | Add-Member -MemberType NoteProperty -Name SignInFrequency_value -force -Value $CAPolicy.SessionControls.SignInFrequency.value
            $DataObj | Add-Member -MemberType NoteProperty -Name SignInFrequency_type -force -Value $CAPolicy.SessionControls.SignInFrequency.type
            $DataObj | Add-Member -MemberType NoteProperty -Name SignInFrequency_isEnabled -force -Value $CAPolicy.SessionControls.SignInFrequency.isEnabled
            $DataObj | Add-Member -MemberType NoteProperty -Name cTimeStampField -force -Value $TimeStampField
            $DataArr += $DataObj
    }

    
    if($csv){
        $ExportFilename = "$FolderPath\CAPolicies.csv"
        Clear-Content $ExportFilename -Force -ErrorAction SilentlyContinue
        $header = '"Id","DisplayName","CreatedDateTime","ModifiedDateTime","State","SignInRiskLevels","UserRiskLevels","IncludeGroups","ExcludeGroups","IncludeRoles","ExcludeRoles","IncludeUsers","ExcludeUsers","IncludeApplications","ExcludeApplications","IncludeProtectionLevels","IncludeUserActions","IncludeDeviceStates","ExcludeDeviceStates","deviceStates","includeLocations","excludeLocations","ClientAppTypes","includePlatforms","excludePlatforms","GrantControls._Operator","GrantControls.BuiltInControls","CustomAuthenticationFactors","TermsOfUse","ApplicationEnforcedRestrictions","cloudAppSecurityType","CloudAppSecurity.isEnabled","PersistentBrowser.mode","PersistentBrowser.IsEnabled","SignInFrequency.value","SignInFrequency.type","SignInFrequency.isEnabled","cTimeStampField","TimeGenerated"'
        $header | Out-File $ExportFilename
    }
    if ($DataArr) {
        if($CSV){$DataArr | Export-Csv -Path $FolderPath\CAPolicies.csv -Delimiter "," -NoTypeInformation -Force}
        $json = $DataArr | ConvertTo-Json
        if($SharedKey){Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
     
    }
    Write-Progress -Id 1 -Completed -Activity "Process Conditional Access Policies"
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

#Replace with your Tenant ID
$tenantId       = 'xxxxxx'

#Replace with your App ID


$ClientID = "xxxxxx"
$spPassword = 'xxxxx'
$SecuredPassword = ConvertTo-SecureString $spPassword -AsPlainText -Force
$psCredentials = New-Object System.Management.Automation.PSCredential ($ClientID, $SecuredPassword)

$azureContext = Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $psCredentials
$azureContext = Set-AzContext -SubscriptionName $azureContext.context.Subscription -DefaultProfile $azureContext.context
$graphToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"
$aadToken = Get-AzAccessToken -ResourceUrl "https://graph.windows.net"
$token = (Get-AzAccessToken -ResourceTypeName MSGraph).token




# Replace with your Workspace ID
$CustomerId     = "xxxxxx"  
# Replace with your Primary Key
$SharedKey      = "xxxxxxx"
#$SharedKey      = $null

#$TimeStampField = [DateTime]::UtcNow.ToString("r")
$TimeStampField=get-date
Write-Host "LAW TimeStamp $TimeStampField" -ForegroundColor Cyan

if (($ClientID -eq "") -or ($Thumbprint -eq "")) {
        Write-Error "Create & set the App details in the script variables" -Category AuthenticationError
        exit 
}

#$result=Connect-MgGraph -identity #-scopes "SecurityEvents.Read.All","PrivilegedAccess.Read.AzureAD","Directory.Read.All","RoleManagement.Read.All","IdentityRiskyUser.Read.All","Organization.Read.All","IdentityRiskEvent.Read.All","AuditLog.Read.All","Policy.Read.All","PrivilegedEligibilitySchedule.Read.AzureADGroup","Application.Read.All"
Connect-MgGraph -AccessToken ($token |ConvertTo-SecureString -AsPlainText -Force)

# Get tenant details to test that Connect-AzureAD has been called
try {
    $tenant_details = Get-MgDomain

} catch {
    Write-Error "Failed to get Tenant Details" -Category AuthenticationError
    exit
}

if (($AzureAD_SP) -or ($All)) {
    $ServicePrincipalIds = (Get-MgServicePrincipal -All).Id
    $i=1
    $total = $ServicePrincipalIds.Count
    $AppConsentObjs = @()
    $AppConsentObj = @()

    Write-Host "Beginning App consents export" -ForegroundColor Yellow
    ForEach ($ServicePrincipalId in $ServicePrincipalIds) {
        Write-Progress -Id 0 -Activity "Azure AD Apps Consents Export - $($ServicePrincipalId.DisplayName)" -Status ("Checked {0}/{1} Apps" -f $i++, $Total) -PercentComplete ((($i-1) / $Total) * 100)
        
        $AppConsentObj=Get-AadAppsConsents -ServicePrincipalid $ServicePrincipalId -TimeStampField $TimeStampField
        $AppConsentObjs+=$AppConsentObj
        
    }
    Write-Progress -Id 0 -Activity "Azure AD Apps Consents Export" -Completed
    Write-Host "--> End of App consents export" -ForegroundColor Green

    Clear-Content "$FilePath\AADAppsPermissionsV0.1.csv" -Force -ErrorAction SilentlyContinue
    if($CSV){$AppConsentObjs | Export-Csv -Path "$FilePath\AADAppsPermissions.csv" -NoTypeInformation -Force}
        
    # Specify the name of the record type that you'll be creating
    $LogType = "DashboardAAD_AADAppConsents"
    $json = $AppConsentObjs | ConvertTo-Json
    if($SharedKey){Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}

}
#>
if (($AzureAD_Role) -or ($All)) {
    Write-Host "Beginning AAD Roles export" -ForegroundColor Yellow
    $AADTenantLicence = ""

    $AzureADLicenceSKUs = Get-MgSubscribedSku
    foreach ($AzureADLicenceSKU in $AzureADLicenceSKUs) {
        foreach ($plan in $AzureADLicenceSKU.ServicePlans) {
            if ($plan.ServicePlanName -eq "AAD_PREMIUM_P2") {
                $AADTenantLicence = "P2"
            }
        }
    }

    if ($AADTenantLicence -eq "P2") {
        Write-Host "P2 licences detected, use PIM cmdlet to export" -ForegroundColor Gray
        Get-EntraIDPIMRole -FolderPath $FilePath -customerId $CustomerId -sharedKey $SharedKey
    }
    else {
        Write-Host "NO P2 licences detected, use classic cmdlet to export" -ForegroundColor Yellow
        Get-AadRoleMembers -FolderPath $FilePath    
    }
    Write-Host "--> End of AAD Roles export" -ForegroundColor Green 
}


if (($AzureAD_CA) -or ($All)) {
    Write-Host "Beginning Conditional Access Policy export" -ForegroundColor Yellow
    Get-AzureADCAPolicies -FolderPath $FilePath
    Write-Host "--> End of Conditional Access Policy export" -ForegroundColor Green
}
#>
