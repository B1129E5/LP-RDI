# Deploy RDI into Automation Account

##Create an Application

1. Install Microsoft.Graph Module
```
Install-Module Microsoft.Graph -Scope AllUsers
```

2. Execute this script with at least 'Application.ReadWrite.All' permission on the Microsoft Graph PowerShell. This will create a app name RDIApp with required permission for the script RDI
```powershell
Connect-MgGraph #-Scopes 'Application.ReadWrite.All'

$RDIAppID=New-MgApplication -DisplayName 'RDIApp' 
$SPID=New-MgServicePrincipal -AppId $RDIAppID.AppId

$Scopes=$null
$Scopes="38d9df27-64da-44fd-b7c5-a6fbac20248f","
bf394140-e372-4bf9-a898-299cfc7564e5","4cdc2547-9148-4295-8d11-be0db1391d6b","7ab1d382-f21e-4acd-a863-ba3e13f7da61","c7fbd983-d9aa-4fa7-84b8-17382c103bc4","dc5007c0-2d7d-4c42-879c-2dab87571379","498476ce-e0fe-48b0-b801-37ba7e2685c6","6e472fd1-ad78-48da-a0f0-97ab2c6b769e","b0afded3-3588-46d8-8b3d-9842eff778da","246dd0d5-5bd0-4def-940b-0421030a5b68","edb419d6-7edc-42a3-9345-509bfdf5d87c","9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"

foreach ($scope in $scopes) {
  $params = @{
    "PrincipalId" =$spid.Id
    "ResourceId" = "c8650178-33df-4d58-a998-91691f6bb421"
    "AppRoleId" = $scope
  }
  
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "c8650178-33df-4d58-a998-91691f6bb421" -BodyParameter $params | 
    Format-List Id, AppRoleId, CreatedDateTime, PrincipalDisplayName, PrincipalId, PrincipalType, ResourceDisplayName
}
```

## Create a Secret for the App
1. Execute these following commands to generate a secret (needed if you use RDI Automation script). Copy the $secret.SecretText, you need it for the RDI automation script.

```
$appObjectId = $RDIAppID.Id

$passwordCred = @{
   displayName = 'Created in PowerShell'
   endDateTime = (Get-Date).AddMonths(6)
}

$secret = Add-MgApplicationPassword -applicationId $appObjectId -PasswordCredential $passwordCred
$secret.SecretText

```

## Create an auto signed certificate for the App
1. Execute these following commands to generate an autosigned certificate for the App (needed if you use RDI stand alone)


```
$cert = New-SelfSignedCertificate -CertStoreLocation "cert:\CurrentUser\My" `
  -Subject "CN=MSGraph_RDIApps" `
  -KeySpec KeyExchange `
  -KeyLength 2048
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData()) 

```

![alt text](https://github.com/nlepagnez/ESI-PublicContent/blob/main/Documentations/Images/Image01.png "Connector Deployment")






```
```


```
```


```
```