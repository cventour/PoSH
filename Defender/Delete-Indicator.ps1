<#
 .Synopsis
  Deletes Indicators from MS Defender for Endpoint

 .Description
  Deletes IOCs from the MS Defender for Endpoint. You can define which IOCs will be deleted 
  based on simple criteria. This requires that you have access to the Defender for Endpoint 
  API and have created an app registration with appropriate rights to read/write indicators.

 .Parameter tenantID
 Your Defender for Endpoint Tenant ID

 .Parameter appID
  The appID that you have created to access the Defender API

 .Parameter appSecret
  The client secret that was generated once you created the app registration.

 .Parameter field
  The field that you want to filter on. This can be either of the values id , title or 
  createdByDisplayName

 .Parameter value
  The value of the field you are looking to delete indicators for.

 .Example
  Delete-Indicator -tenantID 4jflcl6l3-f45f-2j4j-cl5lf-e5vcxvcxv7 -appID cccccccc-aaaa-bbbb-dddd-ffgghhjjkkll -appSecret dlkjsdklfjds+_werkjewrewr3423 -field title -value blah

  This will delete all indicators under the title of "blah"
#>

param(
    [Parameter(Mandatory)]
     [string]$tenantID,
    [Parameter(Mandatory)]
    [string]$appID,
    [Parameter(Mandatory)]
    [string]$appSecret,
    [Parameter(Mandatory)]
    [ValidateSet("id","title","createdByDisplayName")]
    [string]$field ,
    [Parameter(Mandatory)]
    [string]$value
)

Write-Host "`n[@] Delete IOCs script for Microsoft Defender for Endpoint" -ForegroundColor Magenta
$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}

Write-Host "[A] Autenticating to the Defender API using tenant ID"$tenantId -ForegroundColor Green

$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
      
$url = "https://api.securitycenter.microsoft.com/api/indicators"


# Set the WebRequest headers
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token" 
}

# Get the indicators
$response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop
$indicators =  ($response | ConvertFrom-Json).value 
Write-Host "[*] Looking for indicator(s) with $field equal to $value" -ForegroundColor Green

$Selection = $indicators | Where-Object { $_.$field -eq $value } 
if ([int]$Selection.count -gt 0) {
    Write-Host "[*] Found" $selection.count "indicators to delete" -ForegroundColor Green
} else {
    Write-Host "[X] No IOCs found. Exiting ..." -ForegroundColor Yellow
    exit
}

foreach ($item in $Selection)
{
    $delurl = $url+"/"+$item.id
    Write-Host "[-] Deleting id:" $item.id "type:" $item.indicatorType "value:" $item.indicatorValue -ForegroundColor Cyan
    $response = Invoke-WebRequest -Method Delete -Uri $delurl -Headers $headers -ErrorAction Stop
}

Write-Host "`n"