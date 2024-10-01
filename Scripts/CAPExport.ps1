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
    

    $ExportFilename = "$FolderPath\CAPolicies.csv"
    Clear-Content $ExportFilename -Force -ErrorAction SilentlyContinue
    $CAExport | Export-Csv -Path $ExportFilename -Delimiter "," -NoTypeInformation -Force 

    if ($DataArr) {
        if($CSV){$DataArr | Export-Csv -Path $FolderPath\CAPolicies.csv -Delimiter "," -NoTypeInformation -Force}
    }
    Write-Progress -Id 1 -Completed -Activity "Process Conditional Access Policies"
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

$result = Connect-MgGraph -Scopes "Policy.Read.All,Directory.Read.All"
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
#Write-Host "Beginning Conditional Access Policy export" -ForegroundColor Yellow
Write-Log -Message "Beginning Conditional Access Policy export" -LogFile $LogFile -Type "INFO" -color "Yellow"
    Get-AzureADCAPolicies -FolderPath $FilePath
#Write-Host "--> End of Conditional Access Policy export" -ForegroundColor Green
Write-Log -Message "--> End of Conditional Access Policy export" -LogFile $LogFile -Type "INFO" -color "Green"
#################
Write-Log -Message " " -LogFile $LogFile -Type "INFO" -color "Green"