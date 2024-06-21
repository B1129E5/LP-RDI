# Run the RDI script OnPrem

 ## Create an auto signed certificate for the App
1. Execute these following commands to generate an autosigned certificate for the App (needed if you use RDI stand alone)


```powershell
$cert = New-SelfSignedCertificate -CertStoreLocation "cert:\CurrentUser\My" `
  -Subject "CN=MSGraph_RDIApps" `
  -KeySpec KeyExchange `
  -KeyLength 2048
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData()) 

```

If you want the certificate in the local machine store (can be useful to create schedule tasks)
```powershell
$cert = New-SelfSignedCertificate -CertStoreLocation "cert:\LocalMachine\My" `
  -Subject "CN=MSGraph_RDIApps" `
  -KeySpec KeyExchange `
  -KeyLength 2048
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData()) 

```

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentation/Images/Image01.png)

2. Import it in your App

![alt text](https://github.com/B1129E5/LP-RDI/blob/main/Documentation/Images/Image02.png)

You can now create a scheduled tasks to run the task
