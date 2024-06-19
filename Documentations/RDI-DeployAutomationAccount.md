# Deploy RDI into Automation Account

## Create an Application

1. Install Microsoft.Graph Module
```powershell
Install-Module Microsoft.Graph -Scope AllUsers
```

2. Execute this script with at least 'Application.ReadWrite.All' permission on the Microsoft Graph PowerShell. This will create a app name RDIApp with required permission for the script RDI
```powershell
Connect-MgGraph -Scopes 'Application.ReadWrite.All'
```
If asked, enter your credentials

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image17.png)

If the following windows is showing up, click Accept

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image18.png)


```powershell
$RDIAppID=New-MgApplication -DisplayName 'RDIApp'
$SPID=New-MgServicePrincipal -AppId $RDIAppID.AppId
 
$Scopes=$null
$Scopes="38d9df27-64da-44fd-b7c5-a6fbac20248f","
bf394140-e372-4bf9-a898-299cfc7564e5","4cdc2547-9148-4295-8d11-be0db1391d6b","7ab1d382-f21e-4acd-a863-ba3e13f7da61","c7fbd983-d9aa-4fa7-84b8-17382c103bc4","dc5007c0-2d7d-4c42-879c-2dab87571379","498476ce-e0fe-48b0-b801-37ba7e2685c6","6e472fd1-ad78-48da-a0f0-97ab2c6b769e","b0afded3-3588-46d8-8b3d-9842eff778da","246dd0d5-5bd0-4def-940b-0421030a5b68","edb419d6-7edc-42a3-9345-509bfdf5d87c","9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
 
$AppMsGraphId=(Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'").Id
 
foreach ($scope in $scopes) {
  $params = @{
    "PrincipalId" =$spid.Id
    "ResourceId" =$AppMsGraphId
    "AppRoleId" = $scope
  }
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AppMsGraphId -BodyParameter $params |
    Format-List Id, AppRoleId, CreatedDateTime, PrincipalDisplayName, PrincipalId, PrincipalType, ResourceDisplayName
}
```

## Create a Secret for the App
1. Execute these following commands to generate a secret (needed if you use RDI Automation script). 
**Copy the result of $secret.SecretText in notepad, you'll need it for the RDI automation script.**

```powershell
$appObjectId = $RDIAppID.Id

$passwordCred = @{
   displayName = 'Created in PowerShell'
   endDateTime = (Get-Date).AddMonths(6)
}

$secret = Add-MgApplicationPassword -applicationId $appObjectId -PasswordCredential $passwordCred
$secret.SecretText

```


## Create the Automation Account
1. In the Azure Portal (https://portal.azure.com) search Automation Account
   ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image03.png)
2. Click on **Create**

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image19.png)

1. Create the Automation Account with required information. Note: Due to permission sensitivity, this AA is Privileged and click Next
   ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image04.png)
2. Check **System Assigned** and click **Next**

   ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image05.png)

3. Depending of your network needs/requirements, choose **Public Access** or **Private access** (private access is more secure but more complex to deploy)

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image06.png)

4. Click **Review + Create**
5. Click **Create**
6. Once the Azure Automation account is created, click on **Go to resource**
![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image20.png)
7. To create the Runbok, two options
   1. In the Overview page Click **Create a Runbook**

      ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image21.png)
   2. In **Process Automation**, select **Runbook** and **Create**

      ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image07.png)

8. **Name** the Runbook 
9. In Runbook Type, choose **PowerShell**
10. Two options
   1. In **Runtime version**, choose **7.2**
    ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image08.png)

   2. In **Runtime Environment**, choose **Select from existing** and select **Powershell 7-2**
    ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image22.png)
    ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image23.png)

11.  Click **Review +  Create** and **Create**
12.  Copy/paste the PowerShell code form the file LPDI_Dashboard_v1.0_RunBook_AutomationAccount.ps1 located in the **Scripts** folder

https://github.com/B1129E5/LP-RDI/blob/main/Scripts/LPDI_Dashboard_v1.0_RunBook_AutomationAccount.ps1


**Don’t forget to update the following value:**
```powershell
$tenantId (ligne 982)

$ClientID (ligne 987)
It’s the App ID
```
You can find the App ID here
    ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image24.png)

```powershell
$spPassword (ligne 988)
It’s your App Secret, you retrieved in the previous step

$CustomerID (line 1002)
It’s your Log Analytic ID

$Sharekey (line 1004)
It’s your key of your Log Analytic
```

Both information can be find, here

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image25.png)


![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image09.png)

13.  Click on **Publish** button and click **Yes**

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image10.png)

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image27.png)


1.  To check if required modules are installed. Close the **Runbook** blade to go back to the **Azure Automation Account**. Two options depending of the GUI Experience you have :
     1. In **Shared Resources**, select to **Module**

      ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image11.png)
     2. In **Process Automation**, select **Runtime Environments (Preview)**
    ![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image28.png)

    List of excepted Modules :


15. Go to back to Powershell on your administration workstation.
16. If necessary, Install the AZ Module to import Module by PowerShell

```powershell
Install-Module -Name Az -Repository PSGallery -Force -Scope AllUsers
```
16.  Connect to Azure 

```powershell
Connect-AzAccount 
```
17.  Execute these PowerShell Commands with PowerShell 5.1 to add the required modules. **Change XXX by the the name of your Azure automation account and the name of the resource goup where the accound is located**
```powershell
$AAModules = "Microsoft.Graph","Microsoft.Graph.Authentication","Microsoft.Graph.Users","Microsoft.Graph.Applications","Microsoft.Graph.Identity.DirectoryManagement","Microsoft.Graph.Identity.SignIns","Microsoft.Graph.DirectoryObjects","Microsoft.Graph.Identity.Governance","Microsoft.Graph.Groups","Microsoft.Graph.Beta","Microsoft.Graph.Beta.Authentication","Microsoft.Graph.Beta.Users","Microsoft.Graph.Beta.Applications","Microsoft.Graph.Beta.Identity.DirectoryManagement","Microsoft.Graph.Beta.Identity.SignIns","Microsoft.Graph.Beta.DirectoryObjects","Microsoft.Graph.Beta.Identity.Governance","Microsoft.Graph.Beta.Groups"

foreach ($aaModule in $AAModules) {
    $moduleName = $aaModule
    $moduleVersion = '2.19.0'
    New-AzAutomationModule -AutomationAccountName 'XXXXXX' -ResourceGroupName 'XXXX' -Name $moduleName -ContentLinkUri "https://www.powershellgallery.com/api/v2/package/$moduleName/$moduleVersion" -RuntimeVersion 7.2
}
```
17. Check the availability. This can take some minutes !

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image12.png)

18. You can schedule the script execution. Click on the run book and add a schedule.

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image13.png)

19. You can run manually the script. Click on the run book and after click Run. You can follow the status by clicking on status.

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image14.png)


## If you want to use Managed Identity
1. Go to the AA and note the ID of the Managed Identity
![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentations/Images/Image15.png)

2. Install Microsoft.Graph Module
Execute these PowerShell commands to set permissions
Change < Managed Identity ID> by your Managed Identity ID
```powershell
Connect-MgGraph

$Scopes=$null
$Scopes="38d9df27-64da-44fd-b7c5-a6fbac20248f","
bf394140-e372-4bf9-a898-299cfc7564e5","4cdc2547-9148-4295-8d11-be0db1391d6b","7ab1d382-f21e-4acd-a863-ba3e13f7da61","c7fbd983-d9aa-4fa7-84b8-17382c103bc4","dc5007c0-2d7d-4c42-879c-2dab87571379","498476ce-e0fe-48b0-b801-37ba7e2685c6","6e472fd1-ad78-48da-a0f0-97ab2c6b769e","b0afded3-3588-46d8-8b3d-9842eff778da","246dd0d5-5bd0-4def-940b-0421030a5b68","edb419d6-7edc-42a3-9345-509bfdf5d87c","9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"

foreach ($scope in $scopes) {
  $params = @{
    "PrincipalId" =<Managed Identity ID>
    "ResourceId" = "c8650178-33df-4d58-a998-91691f6bb421"
    "AppRoleId" = $scope #"4cdc2547-9148-4295-8d11-be0db1391d6b bf394140-e372-4bf9-a898-299cfc7564e5 7ab1d382-f21e-4acd-a863-ba3e13f7da61 c7fbd983-d9aa-4fa7-84b8-17382c103bc4 dc5007c0-2d7d-4c42-879c-2dab87571379 498476ce-e0fe-48b0-b801-37ba7e2685c6 6e472fd1-ad78-48da-a0f0-97ab2c6b769e b0afded3-3588-46d8-8b3d-9842eff778da 246dd0d5-5bd0-4def-940b-0421030a5b68 edb419d6-7edc-42a3-9345-509bfdf5d87c 9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
  }
  
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "c8650178-33df-4d58-a998-91691f6bb421" -BodyParameter $params | 
    Format-List Id, AppRoleId, CreatedDateTime, PrincipalDisplayName, PrincipalId, PrincipalType, ResourceDisplayName
}
```
