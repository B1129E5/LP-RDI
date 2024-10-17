$DashboardAAD_AADRoles_CL_tableParams = @'
{
    "properties": {
        "schema": {
            "name": "DashboardAAD_AADRoles_CL",
            "columns": [
                {
                    "name": "TimeGenerated",
                    "type": "datetime",
                    "description": "TimeGenerated"
                },            
                {
                    "name": "AzureAD_RoleName",
                    "type": "string",
                    "description": "AzureAD_RoleName"
                },
               {
                    "name": "Account_DisplayName",
                    "type": "string",
                    "description": "Account_DisplayName"
                },
                {
                    "name": "Account_UPN",
                    "type": "string",
                    "description": "Account_UPN"
                },
                {
                    "name": "Account_ObjectId",
                    "type": "string",
                    "description": "Account_ObjectId"
                },
                {
                    "name": "Account_Type",
                    "type": "string",
                    "description": "Account_Type"
                },
                {
                    "name": "Account_DirSync",
                    "type": "Boolean",
                    "description": "Account_DirSync"
                },
               {
                    "name": "Account_PIMRoleAssignmentState",
                    "type": "string",
                    "description": "Account_PIMRoleAssignmentState"
                },
                {
                    "name": "Account_RoleMemberType",
                    "type": "string",
                    "description": "Account_RoleMemberType"
                },
                {
                    "name": "Account_RoleStartDateTime",
                    "type": "Datetime",
                    "description": "Account_RoleStartDateTime"
                },
                {
                    "name": "Account_RoleEndDateTime",
                    "type": "Datetime",
                    "description": "Account_RoleEndDateTime"
                },
                {
                    "name": "Account_GroupName",
                    "type": "String",
                    "description": "Account_GroupName"
                },
                                {
                    "name": "Account_LastSignins",
                    "type": "Datetime",
                    "description": "Account_LastSignins"
                },
                {
                    "name": "Account_MFA",
                    "type": "String",
                    "description": "Account_MFA"
                },
                {
                    "name": "Account_Methods",
                    "type": "string",
                    "description": "Account_Methods"
                },
                {
                    "name": "Account_PhoneNumber",
                    "type": "String",
                    "description": "Account_PhoneNumber"
                },
               {
                    "name": "Account_AlternativePhoneNumber",
                    "type": "String",
                    "description": "Account_AlternativePhoneNumber"
                },
                                {
                    "name": "Account_CreationDate",
                    "type": "Datetime",
                    "description": "Account_CreationDate"
                },
                {
                    "name": "Account_RefreshTokensValid",
                    "type": "Datetime",
                    "description": "Account_RefreshTokensValid"
                },
                {
                    "name": "Account_ExcServices",
                    "type": "string",
                    "description": "Account_ExcServices"
                },
                {
                    "name": "Account_TeamsServices",
                    "type": "String",
                    "description": "Account_TeamsServices"
                },
                                {
                    "name": "Account_SharepointServices",
                    "type": "String",
                    "description": "Account_SharepointServices"
                },
               {
                    "name": "Account_YammerServices",
                    "type": "String",
                    "description": "Account_YammerServices"
                },
                {
                    "name": "Account_onPremisesDistinguishedName",
                    "type": "String",
                    "description": "Account_onPremisesDistinguishedName"
                },
                {
                    "name": "cTimeStampField",
                    "type": "Datetime",
                    "description": "cTimeStampField"
                },
                {
                    "name": "IsBuiltIn",
                    "type": "Boolean",
                    "description": "IsBuiltIn"
                },
                {
                    "name": "IsPrivileged",
                    "type": "Boolean",
                    "description": "IsPrivileged"
                },
                {
                    "name": "RolePermissions",
                    "type": "String",
                    "description": "RolePermissions"
                },
                {
                    "name": "Account_NI_LastSignins",
                    "type": "Datetime",
                    "description": "Account_NI_LastSignins"
                },
                {
                    "name": "Account_Success_LastSignins",
                    "type": "Datetime",
                    "description": "Account_Success_LastSignins"
                },
                {
                    "name": "Account_Enabled",
                    "type": "Boolean",
                    "description": "Account_Enabled"
                },
                {
                    "name": "RoleScope",
                    "type": "String",
                    "description": "RoleScope"
                }
            ]
        }
    }
}
'@

$DashboardAAD_CA_CL_tableParams = @'
{
    "properties": {
        "schema": {
            "name": "DashboardAAD_CA_CL",
            "columns": [
                {
                    "name": "TimeGenerated",
                    "type": "datetime",
                    "description": "TimeGenerated"
                },
                {
                    "name": "Id",
                    "type": "string",
                    "description": "Id"
                },
               {
                    "name": "DisplayName",
                    "type": "string",
                    "description": "DisplayName"
                },
                {
                    "name": "CreatedDateTime",
                    "type": "string",
                    "description": "CreatedDateTime"
                },
                {
                    "name": "ModifiedDateTime",
                    "type": "string",
                    "description": "ModifiedDateTime"
                },
                {
                    "name": "State",
                    "type": "string",
                    "description": "State"
                },
                {
                    "name": "SignInRiskLevels",
                    "type": "Boolean",
                    "description": "SignInRiskLevels"
                },
               {
                    "name": "UserRiskLevels",
                    "type": "string",
                    "description": "UserRiskLevels"
                },
                {
                    "name": "IncludeGroups",
                    "type": "string",
                    "description": "IncludeGroups"
                },
                {
                    "name": "ExcludeGroups",
                    "type": "String",
                    "description": "ExcludeGroups"
                },
                {
                    "name": "IncludeRoles",
                    "type": "String",
                    "description": "IncludeRoles"
                },
                {
                    "name": "ExcludeRoles",
                    "type": "String",
                    "description": "ExcludeRoles"
                },
                                {
                    "name": "IncludeUsers",
                    "type": "String",
                    "description": "IncludeUsers"
                },
                {
                    "name": "ExcludeUsers",
                    "type": "String",
                    "description": "ExcludeUsers"
                },
                {
                    "name": "IncludeApplications",
                    "type": "string",
                    "description": "IncludeApplications"
                },
                {
                    "name": "ExcludeApplications",
                    "type": "String",
                    "description": "ExcludeApplications"
                },
               {
                    "name": "IncludeProtectionLevels",
                    "type": "String",
                    "description": "IncludeProtectionLevels"
                },
                                {
                    "name": "IncludeUserActions",
                    "type": "String",
                    "description": "IncludeUserActions"
                },
                {
                    "name": "IncludeDeviceStates",
                    "type": "String",
                    "description": "IncludeDeviceStates"
                },
                {
                    "name": "ExcludeDeviceStates",
                    "type": "string",
                    "description": "ExcludeDeviceStates"
                },
                {
                    "name": "deviceStates",
                    "type": "String",
                    "description": "deviceStates"
                },
                {
                    "name": "includeLocations",
                    "type": "String",
                    "description": "includeLocations"
                },
               {
                    "name": "excludeLocations",
                    "type": "String",
                    "description": "excludeLocations"
                },
                {
                    "name": "ClientAppTypes",
                    "type": "String",
                    "description": "ClientAppTypes"
                },
                {
                    "name": "includePlatforms",
                    "type": "String",
                    "description": "includePlatforms"
                },
                {
                    "name": "excludePlatforms",
                    "type": "String",
                    "description": "excludePlatforms"
                },
                {
                    "name": "GrantControls_Operator",
                    "type": "String",
                    "description": "GrantControls_Operator"
                },
                {
                    "name": "GrantControls_BuiltInControls",
                    "type": "String",
                    "description": "GrantControls_BuiltInControls"
                },
                {
                    "name": "CustomAuthenticationFactors",
                    "type": "String",
                    "description": "CustomAuthenticationFactors"
                },
                {
                    "name": "TermsOfUse",
                    "type": "String",
                    "description": "TermsOfUse"
                },
                {
                    "name": "ApplicationEnforcedRestrictions",
                    "type": "Boolean",
                    "description": "ApplicationEnforcedRestrictions"
                },
                {
                    "name": "cloudAppSecurityType",
                    "type": "Real",
                    "description": "cloudAppSecurityType"
                },
                {
                    "name": "CloudAppSecurity_isEnabled",
                    "type": "Boolean",
                    "description": "CloudAppSecurity_isEnabled"
                },
                {
                    "name": "PersistentBrowser_mode",
                    "type": "Real",
                    "description": "PersistentBrowser_mode"
                },
                {
                    "name": "PersistentBrowser_IsEnabled",
                    "type": "Boolean",
                    "description": "PersistentBrowser_IsEnabled"
                },
                {
                    "name": "SignInFrequency_value",
                    "type": "Real",
                    "description": "SignInFrequency_value"
                },
                {
                    "name": "SignInFrequency_type",
                    "type": "Real",
                    "description": "SignInFrequency_type"
                },
                {
                    "name": "SignInFrequency_isEnabled",
                    "type": "Boolean",
                    "description": "SignInFrequency_isEnabled"
                },
                {
                    "name": "cTimeStampField",
                    "type": "String",
                    "description": "cTimeStampField"
                }
            ]
        }
    }
}
'@

# Create the tables in the Log Analytics workspace using the REST API
Invoke-AzRestMethod -Path "/subscriptions/5687c0c2-9f2c-4a6a-81f1-bbc347b748fc/resourceGroups/rg-lpdi/providers/microsoft.operationalinsights/workspaces/law-lpdi/tables/DashboardAAD_AADRoles_CL?api-version=2022-10-01" -Method PUT -payload $DashboardAAD_AADRoles_CL_tableParams
Invoke-AzRestMethod -Path "/subscriptions/5687c0c2-9f2c-4a6a-81f1-bbc347b748fc/resourceGroups/rg-lpdi/providers/microsoft.operationalinsights/workspaces/law-lpdi/tables/DashboardAAD_CA_CL?api-version=2022-10-01" -Method PUT -payload $DashboardAAD_CA_CL_tableParams

# Deploy the template to create Data Collection Rules and Data Collection Endpoint
New-AzResourceGroupDeployment -ResourceGroupName "rg-lpdi" -TemplateFile "..\DCR\lpdi-drc.json" 

