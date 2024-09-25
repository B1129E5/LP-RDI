<#
.SYNOPSIS
LPDI_Dashboard.ps1 - Export Azure AD & Azure RBAC informations
	
.DESCRIPTION
This script export Data from Azure AD & Azure to CSV files and/or a Log Analytics Workspace
To use export to the Workspace, provide Workspace ID & Key in the variables $CustomerId & $SharedKey
Leave BLANK to NOT use Workspace
    	
.PARAMETER FilePath
Export CSV files to this folder. It will be created if not exist  

.PARAMETER CSV
Export data to a CSV files

.EXAMPLE
.\LPDI_Dashboard.ps1 -FolderPath C:\Azure\LPDI -CSV
Export Data to C:\Azure\LPDI folder 

.OUTPUTS
The script creates report files in the folder:
- AADAppsPermissions.csv
- AADRoleMembersPIM.csv
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
                 - RELEASE NOTES -
 v3.0 2024.09.30 - Full support with MS Graph

=============================================================================
#>

param (
        [string]$FilePath="C:\Azure\LPDI", # + $(Get-Date -Format "yyyy-MM-dd") + "\",
        [switch]$CSV=$true,
        [switch]$MI
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
          $userMethods +="$($matches[3]):$($UserAuthentificationMethods[$i].displayName)|" #`r`n"
        }
        $Account_MFA = "Provided"
        $Account_Methods = $userMethods           
      }
      elseif ($UserAuthentificationMethods.Count -gt 1) {
        $UserAuthentificationMethods.'@odata.type' -match $regex | Out-Null  
        $userMethods ="$($matches[3]):$($UserAuthentificationMethods.displayName)|"
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
 
    $percentComplete = [math]::Floor((($t-1) / $Total) * 100)
    # Log progress every 10%
    if ($percentComplete % 10 -eq 0) {
        Write-Log -Message "Processing items - $percentComplete%" -LogFile $LogFile -Type "INFO" -color "Yellow"
    }

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
    if($SharedKey){Post-DataToLogAnalytics -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
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

                $regex = "^([^.]+)\.([^.]+)\.(.+)$"
                $aadRoleMember.AdditionalProperties.'@odata.type' -match $regex | out-null
                $AccountType = $Matches[3]

                $ObjDetails = Get-MgBetaDirectoryObject -DirectoryObjectId $aadRoleMember.Id

                $PSObj | Add-Member -MemberType NoteProperty -Name AzureAD_RoleName -force -Value $aadRole.DisplayName
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_DisplayName -force -Value $ObjDetails.AdditionalProperties.displayName
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_UPN -force -Value $ObjDetails.AdditionalProperties.userPrincipalName
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_ObjectId -force -Value $aadRoleMember.Id
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_CreationDate -force -Value $ObjDetails.AdditionalProperties.createdDateTime

                if($AccountType -eq "user") {
                    $ObjUser = Get-MgBetaUser -UserId $aadRoleMember.Id -Property DisplayName,Id,UserPrincipalName,SignInActivity,AccountEnabled,CreatedDateTime,UserType,OnPremisesSyncEnabled,OnPremisesDistinguishedName,AccountEnabled,lastSuccessfulSignInDateTime
                    $AccountLastSignins = $ObjUser.SignInActivity
                    $UserAuthentificationMethods = (Get-MgUserAuthenticationMethod -UserId $aadRoleMember.Id).AdditionalProperties
                
                    if ($UserAuthentificationMethods.Count -gt 2) {
                      for ($i=0;$i -lt $UserAuthentificationMethods.Count;++$i){
                        $UserAuthentificationMethods[$i].'@odata.type' -match $regex | Out-Null  
                        $userMethods +="$($matches[3]):$($UserAuthentificationMethods[$i].displayName)|" #`r`n"
                      }
                      $Account_MFA = "Provided"
                      $Account_Methods = $userMethods           
                    }
                    elseif ($UserAuthentificationMethods.Count -gt 1) {
                      $UserAuthentificationMethods.'@odata.type' -match $regex | Out-Null  
                      $userMethods ="$($matches[3]):$($UserAuthentificationMethods.displayName)|"
                    }
                    else {
                      $Account_MFA="Not Provided"
                      $Account_Methods = ""
                    }
                
                    $AuthenPhoneNumber = $null
                    $AlternateAuthenPhoneNumber = $null
                    try {
                        $uri = "https://graph.microsoft.com/beta/users/$($aadRoleMember.Id)/authentication/phoneMethods"
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
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_LastSignins -force -Value $AccountLastSignins.LastSignInDateTime
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_RefreshTokensValid -force -Value $ObjDetails.AdditionalProperties.refreshTokensValidFromDateTime  
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_NI_LastSignins -force -Value $AccountLastSignins.lastNonInteractiveSignInDateTime
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Success_LastSignins -force -Value $AccountLastSignins.LastSuccessfulSignInDateTime
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Enabled -force -Value $ObjDetails.AdditionalProperties.accountEnabled
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_MFA -force -Value $Account_MFA
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Methods -force -Value $Account_Methods
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_PhoneNumber -force -Value $AuthenPhoneNumber
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_AlternativePhoneNumber -force -Value $AlternateAuthenPhoneNumber
                  }
                else {
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_LastSignins -force -Value "N/A"
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_RefreshTokensValid -force -Value "N/A"
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_NI_LastSignins -force -Value "N/A"
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Success_LastSignins -force -Value "N/A"
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Enabled -force -Value $null
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_MFA -force -Value "N/A"
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Methods -force -Value "N/A"
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_PhoneNumber -force -Value "N/A"
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_AlternativePhoneNumber -force -Value "N/A"

                }

                if ($AccountType -eq "serviceprincipal") {$PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value "ServicePrincipal"}

                if ($AccountType -eq "group") {
                
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value "Group"
 
                    $aadgroupmembers=Get-MgGroupMember -GroupId $aadRoleMember.Id

                    if ($aadgroupmembers) {$PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value "Group"}
                    
                    
                    foreach ($aadgroupmember in $aadgroupmembers) {
                        
                        $ObjUser2 = Get-MgBetaUser -UserId $aadgroupmember.Id -Property DisplayName,Id,UserPrincipalName,SignInActivity,AccountEnabled,CreatedDateTime,UserType,OnPremisesSyncEnabled,OnPremisesDistinguishedName,AccountEnabled,lastSuccessfulSignInDateTime
                        $AccountLastSignins = $ObjUser2.SignInActivity
                        $UserAuthentificationMethods = (Get-MgUserAuthenticationMethod -UserId $aadgroupmember.Id).AdditionalProperties
                    
                        if ($UserAuthentificationMethods.Count -gt 2) {
                        for ($i=0;$i -lt $UserAuthentificationMethods.Count;++$i){
                            $UserAuthentificationMethods[$i].'@odata.type' -match $regex | Out-Null  
                            $userMethods +="$($matches[3]):$($UserAuthentificationMethods[$i].displayName)|" #`r`n"
                        }
                        $Account_MFA = "Provided"
                        $Account_Methods = $userMethods           
                        }
                        elseif ($UserAuthentificationMethods.Count -gt 1) {
                        $UserAuthentificationMethods.'@odata.type' -match $regex | Out-Null  
                        $userMethods ="$($matches[3]):$($UserAuthentificationMethods.displayName)|"
                        }
                        else {
                        $Account_MFA="Not Provided"
                        $Account_Methods = ""
                        }
                    
                        $AuthenPhoneNumber = $null
                        $AlternateAuthenPhoneNumber = $null
                        try {
                            $uri = "https://graph.microsoft.com/beta/users/$($aadgroupmember.Id)/authentication/phoneMethods"
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


                        $PSObj2 = New-Object System.Object
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name AzureAD_RoleName -force -Value $aadRole.DisplayName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_DisplayName -force -Value $ObjUser2.DisplayName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_UPN -force -Value $ObjUser2.UserPrincipalName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_ObjectId -force -Value $ObjUser2.Id
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_CreationDate -force -Value $ObjUser2.createdDateTime
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_UserType -force -Value $ObjUser2.UserType
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_DirSync -force -Value $ObjUser2.DirSyncEnabled
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_PIMRoleAssignmentState -force -Value "Active"
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RoleMemberType -force -Value "Group"
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RoleStartDateTime -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RoleEndDateTime -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_GroupName -force -Value $aadRoleMember.AdditionalProperties.displayName
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_LastSignins -force -Value $AccountLastSignins.LastSignInDateTime
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_RefreshTokensValid -force -Value $ObjUser2.RefreshTokensValidFromDateTime
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_onPremisesDistinguishedName -force -Value $ObjUser2.onPremisesDistinguishedName

                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_MFA -force -Value $Account_MFA
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_Methods -force -Value $Account_Methods
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_PhoneNumber -force -Value $AuthenPhoneNumber
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_AlternativePhoneNumber -force -Value $AlternateAuthenPhoneNumber
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name cTimeStampField -force -Value $TimeStampField
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name TimeGenerated -force -Value $TimeStampField
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name IsBuiltIn -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name IsPrivileged -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name RolePermissions -force -Value ""
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_NI_LastSignins -force -Value $AccountLastSignins.lastNonInteractiveSignInDateTime
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_Success_LastSignins -force -Value $AccountLastSignins.LastSuccessfulSignInDateTime
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name Account_Enabled -force -Value $ObjUser2.accountEnabled
                        $PSObj2 | Add-Member -MemberType NoteProperty -Name RoleScope -force -Value ""
                        if($CSV){$PSObj2 | Export-Csv -Append -NoTypeInformation -Path $ExportFilename -Force}
                        $json = $PSObj2 | ConvertTo-Json
                        if($sharedKey){Post-DataToLogAnalytics -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
     
                    }
                    $TotalGroupMembers = $TotalGroupMembers + $aadgroupmembers.count 
                }
                else {
                    $PSObj | Add-Member -MemberType NoteProperty -Name Account_Type -force -Value $ObjDetails.AdditionalProperties.userType
                }

                $PSObj | Add-Member -MemberType NoteProperty -Name Account_DirSync -force -Value $ObjDetails.AdditionalProperties.onPremisesSyncEnabled
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_PIMRoleAssignmentState -force -Value "Active"
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_RoleMemberType -force -Value "Direct"
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_RoleStartDateTime -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_RoleEndDateTime -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_GroupName -force -Value ""
                
                
                $PSObj | Add-Member -MemberType NoteProperty -Name Account_onPremisesDistinguishedName -force -Value $ObjDetails.AdditionalProperties.onPremisesDistinguishedName


                $PSObj | Add-Member -MemberType NoteProperty -Name cTimeStampField -force -Value $TimeStampField
                $PSObj | Add-Member -MemberType NoteProperty -Name TimeGenerated -force -Value $TimeStampField
                $PSObj | Add-Member -MemberType NoteProperty -Name IsBuiltIn -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name IsPrivileged -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name RolePermissions -force -Value ""
                $PSObj | Add-Member -MemberType NoteProperty -Name RoleScope -force -Value ""


                if($csv){$PSObj | Export-Csv -Append -NoTypeInformation -Path $ExportFilename -Force}
                $json = $PSObj | ConvertTo-Json
                if($sharedKey){Post-DataToLogAnalytics -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
     
           }

           $total = $aadRoleMembers.count + $TotalGroupMembers

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

    Class clCAPolicy {
        #General
        [guid]$Id
        [string]$DisplayName
        [datetime]$CreatedDateTime                                     
        [datetime]$ModifiedDateTime                                    
        [bool]$State
        #Conditions
        [string]$IncludeUsers
        [string]$IncludeGuestsOrExternalUsers    
        [string]$ExcludeUsers
        [string]$ExcludeGuestsOrExternalUsers
        [string]$IncludeGroups
        [string]$ExcludeGroups
        [string]$IncludeRoles
        [string]$ExcludeRoles        
        [string]$IncludeApplications
        [string]$ExcludeApplications
        [string]$ApplicationFilterMode
        [string]$ApplicationFilterRule
        [string]$IncludeAuthenticationContextClassReferences
        [string]$IncludeUserActions
        [string]$IncludeDeviceStates
        [string]$ExcludeDeviceStates
        [string]$deviceStates
        [string]$includeLocations
        [string]$excludeLocations
        [string]$ClientAppTypes
        [string]$ClientApplicationsExcludeServicePrincipals
        [string]$ClientApplicationsIncludeServicePrincipals
        [string]$ClientApplicationsServicePrincipalFilterMode
        [string]$ClientApplicationsServicePrincipalFilterRule
        [string]$includePlatforms
        [string]$excludePlatforms
        [string]$SignInRiskLevels
        [string]$UserRiskLevels
        [string]$ServicePrincipalRiskLevels
        [string]$DeviceFilterMode
        [string]$DeviceFilterRule
 
        #GrantControls
        [string]$GrantControls_Operator
        [string]$GrantControls_BuiltInControls
        [string]$CustomAuthenticationFactors
        [string]$TermsOfUse
        [string]$AuthenticationStrengthName

        #SessionControls
        [bool]$ApplicationEnforcedRestrictions
        [string]$DisableResilienceDefaults   
        [string]$cloudAppSecurityType                                
        [string]$CloudAppSecurity_isEnabled                          
        [string]$PersistentBrowser_mode                              
        [string]$PersistentBrowser_IsEnabled                         
        [string]$SignInFrequency_value                               
        [string]$SignInFrequency_type                                
        [string]$SignInFrequency_isEnabled                                          
        [string]$cTimeStampField                                     
    }

    $CAPolicies=Get-MgBetaIdentityConditionalAccessPolicy -All
    $CAPolicies | Sort-Object DisplayName
 
    if (-not $CAPolicies) {
        Write-Host "No CA policies found ! " -ForegroundColor Red
        return
    }
    else {
        Write-Host "Found $($CAPolicies.Count) CA policies" -ForegroundColor Green
    }

    # Specify the name of the record type that you'll be creating
    $LogType = "DashboardAAD_CA"
    $DataArr = @()
    $CAExport = @()
    $x=1
    $Total = $CAPolicies.Count
    $AllAADRoles = Get-MgDirectoryRoleTemplate

    foreach ($CAPolicy in $CAPolicies) {

            Write-Progress -Id 1 -Activity "Process Conditional Access Policies" -Status ("Checked {0}/{1} CA Policy" -f $x++, $Total) -PercentComplete ((($x-1) / $Total) * 100)
            
            $percentComplete = [math]::Floor((($x-1) / $Total) * 100)

            # Log progress every 10%
            if ($percentComplete % 10 -eq 0) {
                Write-Log -Message "Processing items - $percentComplete%" -LogFile $LogFile -Type "INFO" -color "Yellow"
            }

            $tmpclCAPolicy = [clcapolicy]::new()

            $tmpclCAPolicy.Id = $CAPolicy.Id
            $tmpclCAPolicy.DisplayName = $CAPolicy.DisplayName
            $tmpclCAPolicy.CreatedDateTime = $CAPolicy.CreatedDateTime
            try {
                $tmpclCAPolicy.ModifiedDateTime = $CAPolicy.ModifiedDateTime    
            }
            catch {
                $result = "Error"
            }
            
            $tmpclCAPolicy.State = $CAPolicy.State

            try {
                $result = $CAPolicy.Conditions.SignInRiskLevels -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.SignInRiskLevels = $result
            $result = $null
            
            try {
                $result = $CAPolicy.Conditions.UserRiskLevels -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.UserRiskLevels = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.ServicePrincipalRiskLevels -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ServicePrincipalRiskLevels = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Users.IncludeUsers
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-MgDirectoryObjectById -ids $item).AdditionalProperties.displayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                    
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeUsers = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Users.ExcludeUsers
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-MgDirectoryObjectById -ids $item).AdditionalProperties.displayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ExcludeUsers = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Users.IncludeGuestsOrExternalUsers
                if (!$result.GuestOrExternalUserTypes) {
                    $result = "NotSet"
                }
                else {
                    if ($result.ExternalTenants.MembershipKind -eq "all") {
                            $result = "$($result.GuestOrExternalUserTypes) | Limited to Org: all)"    
                        }
                    else {
                            $result = "$($result.GuestOrExternalUserTypes) | Limited to Org: $($result.ExternalTenants.AdditionalProperties.members)"    
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeGuestsOrExternalUsers = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers
                if (!$result.GuestOrExternalUserTypes) {
                    $result = "NotSet"
                }
                else {
                    if ($result.ExternalTenants.AdditionalProperties.members) {
                        $result = "$($result.GuestOrExternalUserTypes) | Limited to Org: $($result.ExternalTenants.AdditionalProperties.members)"    
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ExcludeGuestsOrExternalUsers = $result
            $result = $null
        
            try {
                $result = $CAPolicy.Conditions.Users.IncludeGroups
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-MgDirectoryObjectById -ids $item).AdditionalProperties.displayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeGroups = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Users.ExcludeGroups
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-MgDirectoryObjectById -ids $item).AdditionalProperties.displayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ExcludeGroups = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Users.IncludeRoles
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $($AllAADRoles | Where-Object {$_.id -eq $item}).DisplayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeRoles = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Users.ExcludeRoles -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $($AllAADRoles | Where-Object {$_.id -eq $item}).DisplayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ExcludeRoles = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Applications.ApplicationFilter.Mode
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = $true
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ApplicationFilterMode = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Applications.ApplicationFilter.Rule
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ApplicationFilterRule = $result
            $result = $null

            

            try {
                $result = $CAPolicy.Conditions.Applications.IncludeAuthenticationContextClassReferences
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeAuthenticationContextClassReferences = $result
            $result = $null




            try {
                $result = $CAPolicy.Conditions.Applications.IncludeApplications
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-mgServicePrincipal -Filter ("appId eq '{0}'" -f $item)).displayname
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeApplications = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Applications.ExcludeApplications
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                             $Name = $(Get-mgServicePrincipal -Filter ("appId eq '{0}'" -f $item)).displayname
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ExcludeApplications = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Applications.IncludeUserActions -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
                else {

                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeUserActions = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Applications.ClientApplicationsExcludeServicePrincipals
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-mgServicePrincipal -Filter ("appId eq '{0}'" -f $item)).displayname
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ClientApplicationsExcludeServicePrincipals = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Applications.ClientApplicationsIncludeServicePrincipals
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                             $Name = $(Get-mgServicePrincipal -Filter ("appId eq '{0}'" -f $item)).displayname
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ClientApplicationsIncludeServicePrincipals = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Applications.ClientApplications.ServicePrincipalFilter.Mode
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = $true
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ClientApplicationsServicePrincipalFilterMode = $result
            $result = $null

            try {
                $result = $CAPolicy.ClientApplications.ServicePrincipalFilter.Rule
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ClientApplicationsServicePrincipalFilterRule = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Devices.DeviceFilter.Mode
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = $true
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.DeviceFilterMode = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Devices.DeviceFilter.Rule
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.DeviceFilterRule = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.DeviceStates.IncludeDeviceStates -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.IncludeDeviceStates = $result

            try {
                $result = $CAPolicy.Conditions.DeviceStates.ExcludeDeviceStates -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ExcludeDeviceStates = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.DeviceStates.deviceStates -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.deviceStates = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Locations.includeLocations
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $item).DisplayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
                
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.includeLocations = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Locations.excludeLocations
                if (!$result) {
                    $result = "NotSet"
                }
                else {
                    $result = foreach ($item in $result) {
                        if ($item -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                            $Name = $(Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $item).DisplayName
                        }
                        else {
                            $Name = $item
                        }
                        $Name
                    }
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.excludeLocations = $result -join "`r`n"
            $result = $null

            try {
                $result = $CAPolicy.Conditions.ClientAppTypes -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ClientAppTypes = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Platforms.includePlatforms -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.includePlatforms = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.Platforms.excludePlatforms -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.excludePlatforms = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.SignInFrequency.value -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.SignInFrequency_value = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.SignInFrequency.type -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.SignInFrequency_type = $result
            $result = $null

            try {
                $result = $CAPolicy.Conditions.SignInFrequency.isEnabled -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.SignInFrequency_isEnabled = $result
            $result = $null

            try {
                $result = $CAPolicy.GrantControls.Operator
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }  
            $tmpclCAPolicy.GrantControls_Operator = $result
            $result = $null

            try {
                $result = $CAPolicy.GrantControls.BuiltInControls -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.GrantControls_BuiltInControls = $result
            $result = $null

            try {
                $result = $CAPolicy.GrantControls.CustomAuthenticationFactors -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.CustomAuthenticationFactors = $result
            $result = $null

            try {
                $result = $CAPolicy.GrantControls.TermsOfUse -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.TermsOfUse = $result
            $result = $null

            

            try {
                $result = $CAPolicy.GrantControls.AuthenticationStrength
                if (!$result.Id) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.AuthenticationStrengthName = $result.DisplayName
            $result = $null


            try {
                $result = $CAPolicy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.ApplicationEnforcedRestrictions = $result
            $result = $null
            
            try {
                $result = $CAPolicy.SessionControls.DisableResilienceDefaults -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.DisableResilienceDefaults = $result
            $result = $null

            try {
                $result = $CAPolicy.SessionControls.cloudAppSecurityType -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.cloudAppSecurityType = $result
            $result = $null

            try {
                $result = $CAPolicy.SessionControls.CloudAppSecurity_isEnabled -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.CloudAppSecurity_isEnabled = $result
            $result = $null

            try {
                $result = $CAPolicy.SessionControls.PersistentBrowser_mode -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.PersistentBrowser_mode = $result
            $result = $null

            try {
                $result = $CAPolicy.SessionControls.PersistentBrowser_IsEnabled -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.PersistentBrowser_IsEnabled = $result
            $result = $null

            try {
                $result = $CAPolicy.SessionControls.SignInFrequency.value -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.SignInFrequency_value = $result
            $result = $null

            try {
                $result = $CAPolicy.SessionControls.SignInFrequency.type -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.SignInFrequency_type = $result
            $result = $null

            try {
                $result = $CAPolicy.SessionControls.SignInFrequency.isEnabled -join "`r`n"
                if (!$result) {
                    $result = "NotSet"
                }
            }
            catch {
                $result = "Error"
            }
            $tmpclCAPolicy.SignInFrequency_isEnabled = $result
            $result = $null

            $tmpclCAPolicy.cTimeStampField = $TimeStampField

            $CAExport += $tmpclCAPolicy
            
    }

    $DataArr=$CAExport
    
    if($csv){
        $ExportFilename = "$FolderPath\CAPolicies.csv"
        Clear-Content $ExportFilename -Force -ErrorAction SilentlyContinue
        $CAExport | Export-Csv -Path $ExportFilename -Delimiter "," -NoTypeInformation -Force 
    }
    if ($DataArr) {
        if($CSV){$DataArr | Export-Csv -Path $FolderPath\CAPolicies.csv -Delimiter "," -NoTypeInformation -Force}
        $json = $DataArr | ConvertTo-Json
        if($SharedKey){Post-DataToLogAnalytics -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType -TimeStampField $TimeStampField}
     
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
Function Post-DataToLogAnalytics($customerId, $sharedKey, $body, $logType, $TimeStampField)
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
 
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
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
# Replace with your Workspace ID
    $CustomerId     = "e15e150e-179a-4c47-ae6b-4d975ea8270c"  
# Replace with your Primary Key (Let empty if you dont have Log Analytics)
    $SharedKey      = "LAiBbzuQ6XbYglNPe9oTsySnETjnoF9az95jFch+Blqnf/iMtiNZ/GC97X604Vo9B7GSALS2U+tWn7bQDJkUoA=="

#### If you don't use Managed Identity
    $ClientID       = "95fd77b5-fd20-40cc-935d-0f7bee0b066b"
#Replace with your Certificat Name
    $CertificatName = "CN=MSGraph_RDIApps"
    $Thumbprint     = (Get-ChildItem cert:\CurrentUser\My\ | Where-Object {$_.Subject -eq $CertificatName}).Thumbprint 
########################################################

$LogFile = "$FilePath\LP-RDI.log"

If(!(test-path $FilePath))
{
      $result=New-Item -ItemType Directory -Force -Path $FilePath
      #Write-Host "Folder $FilePath created" -ForegroundColor Yellow
      Write-Log -Message "Folder $FilePath created" -color "Yellow" -LogFile $LogFile -Type "INFO"
}



Write-Log -Message " " -LogFile $LogFile -Type "INFO" -color "Green"
Write-Log -Message "Begining LP-RDI Export" -LogFile $LogFile -Type "INFO" -color "Cyan"

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

if (!$ClientID) {
        $result = Connect-MgGraph -identity
        Write-Log -Message "Connect with MI - $result" -LogFile $LogFile -Type "INFO" -color "Green"
}
else {
    if ($Thumbprint) {
        if ($ClientID) {
            $result = Connect-MgGraph -ClientId $ClientID -TenantId $tenantId -CertificateThumbprint $Thumbprint
            Write-Log -Message "Connect with SP" -LogFile $LogFile -Type "INFO" -color "Green"
        }
        else {
            #Write-Error "ClientID empty" -Category ConnectionError
            Write-Log -Message "ClientID empty" -LogFile $LogFile -Type "ERROR" -color "Red" -Category ConnectionError
            exit
        }
    }
    else {
        #Write-Error "Certificat not found" -Category InvalidResult
        Write-Log -Message "Certificat not found" -LogFile $LogFile -Type "ERROR" -color "Red" -Category InvalidResult
        exit
    }
}

$TimeStampField=get-date
#Write-Host "LAW TimeStamp $TimeStampField" -ForegroundColor Cyan
Write-Log -Message "LAW TimeStamp $TimeStampField" -LogFile $LogFile -Type "INFO" -color "Cyan"
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

#################
#Write-Host "Beginning AAD Roles export" -ForegroundColor Yellow
Write-Log -Message "Beginning AAD Roles export" -LogFile $LogFile -Type "INFO" -color "Yellow"
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
    #Write-Host "P2 licences detected, use PIM cmdlet to export" -ForegroundColor Gray
    Write-Log -Message "P2 licences detected, use PIM cmdlet to export" -LogFile $LogFile -Type "INFO" -color "Gray"
    Get-EntraIDPIMRole -FolderPath $FilePath -customerId $CustomerId -sharedKey $SharedKey
}
else {
    #Write-Host "NO P2 licences detected, use classic cmdlet to export" -ForegroundColor Yellow
    Write-Log -Message "NO P2 licences detected, use classic cmdlet to export" -LogFile $LogFile -Type "INFO" -color "Yellow"
    Get-AadRoleMembers -FolderPath $FilePath    
}
#Write-Host "--> End of AAD Roles export" -ForegroundColor Green 
Write-Log -Message "--> End of AAD Roles export" -LogFile $LogFile -Type "INFO" -color "Green"
#################

#################
#Write-Host "Beginning Conditional Access Policy export" -ForegroundColor Yellow
Write-Log -Message "Beginning Conditional Access Policy export" -LogFile $LogFile -Type "INFO" -color "Yellow"
    Get-AzureADCAPolicies -FolderPath $FilePath
#Write-Host "--> End of Conditional Access Policy export" -ForegroundColor Green
Write-Log -Message "--> End of Conditional Access Policy export" -LogFile $LogFile -Type "INFO" -color "Green"
#################
Write-Log -Message "End of LP-RDI export" -LogFile $LogFile -Type "INFO" -color "Green"
Write-Log -Message " " -LogFile $LogFile -Type "INFO" -color "Green"