param(
    [Parameter(Mandatory)]
    [string]$appID,
    [Parameter(Mandatory)]
    [string]$appSecret,
    [Parameter(Mandatory)]
    [string]$field = 'title',
    [Parameter(Mandatory)]
    [string]$value= 'test'
)

$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
      
$url = "https://api.securitycenter.microsoft.com/api/indicators"


# Set the WebRequest headers
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token" 
}

# Send the webrequest and get the results. 
$response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop
$indicators =  ($response | ConvertFrom-Json).value 
$Selection = $indicators | where { $_.$field -eq $value } 

if ([int]$Selection.count -gt 0) {
    Write-Host "[*] Found" $selection.count "items to delete"
} else {
    Write-Host "[X] No IOCs found. Exiting ..."
    exit
}

foreach ($item in $Selection)
{
    $delurl = $url+"/"+$item.id
    Write-Host "[-] Deleting id:" $item.id "type:" $item.indicatorType "value:" $item.indicatorValue
   # $response = Invoke-WebRequest -Method Delete -Uri $delurl -Headers $headers -ErrorAction Stop
}

$delurl = "$url"+$item.id
$response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop
