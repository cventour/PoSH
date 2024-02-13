<#
 .Synopsis
  Converts eligible Microsoft XDR custom detections to Near Real Time schedule (NRT)

 .Description
  This script will access the Custom Detections created in Microsoft XDR , identify their eligibility 
  for being converted to Near Real Time (NRT) and if eligible, they will be converted to NRT.
  The script requires parameters to access the Microsoft XDR tenant and the  schedule frequency you
  are targeting for conversion. 

 .Parameter tenantID
  Your Defender for Endpoint Tenant ID

 .Parameter appID
  The appID that you have created to access the Defender API

 .Parameter appSecret
  The client secret that was generated once you created the app registration.

 .Parameter frequency
  The frequency that is targeted for conversion to NRT. Default is "1H"



 .Example
  ConvertTo-NRT r -tenantID 4jflcl6l3-f45f-2j4j-cl5lf-e5vcxvcxv7 -appID cccccccc-aaaa-bbbb-dddd-ffgghhjjkkll -appSecret dlkjsdklfjds+_werkjewrewr3423 -frequency 24H

  This will convert all eligible custom detections that have a current frequency of 24H to NRT
#>

param(
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$tenantID,
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$appID,
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$appSecret,
    #[ValidateSet("1H","3H","8H","24H")]
    [AllowEmptyString()]
    [string]$frequency = "1H"
)


$ErrorActionPreference = "Stop"
Function Update-NRT($id) {
     
     $apiUrl = "https://graph.microsoft.com/beta/security/rules/detectionRules/$id"
    

     # Define headers for the request
     $headers = @{
          'Authorization' = "Bearer $token"
          'Content-Type'  = 'application/json'
     }
     $body = @{
          'schedule' = @{'period' = "0"}
     }
     $patch_response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Body ($body|ConvertTo-Json) -Method Patch
     return  $patch_response
}

$global:token=""
# Here you can select which rules to convert to NRT 
# (usually the ones running every hour are the best candidates)

$graphResource='https://graph.microsoft.com/'

$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"

$authBody = [Ordered] @{
     resource = "$graphResource" # $graphResource or $resourceAppIdUri
     client_id = "$appId"
     client_secret = "$appSecret"
     grant_type = 'client_credentials'
}

Write-Host "[*] Mixrosoft XDR Custom Detections NRT convertor"
Write-Host "[A] Authenticating to tenant's $tenantId Graph API"
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token



$apiUrl = 'https://graph.microsoft.com/beta/security/rules/detectionRules'

# Define headers for the request
$headers = @{
    'Authorization' = "Bearer $token"
    'Content-Type'  = 'application/json'
}

Write-Host "[D] Getting all detection rules"
$response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get

# These are operators and Tables that are currently not supported for XDR NRT Custom Detections.

$BadOperators = @("join", "union","summarize","externaldata"
$BadTables = @("AlertInfo","AlertEvidence","BehaviorInfo","BehaviorEntities","IdentityInfo","IdentityLogonEvents","IdentityQueryEvents","IdentityDirectoryEvents",
               "CloudAppEvents","AADSignInEventsBeta","AADSpnSignInEventsBeta","DeviceTvm","DeviceInternetFacing","DeviceBaseline")

# Evaluate the table
Foreach ($customD in $response.value) { 
     
     Write-Host "[E] Evaluating Detection :" $customD.id "Name" $customD.displayName
    # Checking if the rule is already configured for NRT schedule
     Write-Host "[F] Checking Frequency"
     If ($customD.schedule.period -eq "0") {
          Write-Host -ForegroundColor Yellow "[!] Rule " $customD.id " is Already set to NRT"
          Continue
     }
     # Checking if the rule is in the desired scheduled to be converted from
     If ($customD.schedule.period -ne $frequency) {
        Write-Host -ForegroundColor Yellow "[!] Rule is not scheduled every " $ConvertIf
        Continue
    }
    # Checking for Not Supported Operators
     Write-Host "[O] Checking Operators"
     If ($null -ne ($BadOperators | ? { $customD.queryCondition.queryText -match $_ }))  {
          Write-Host -ForegroundColor Red "[X] Rule is Not Eligible for NRT due to Operator"
          #Write-Host $customD.queryCondition.queryText
          Continue
     }
     # Checking if the query has not supported Tables.
     Write-Host "[T] Checking Tables used"
     If ($null -ne ($BadTables | ? { $customD.queryCondition.queryText -match $_ })) {
          Write-Host -ForegroundColor Yellow "[X] Table not eligible for NRT"
          #Write-Host $customD.queryCondition.queryText
          Continue
     }
     # If all tests have passed, it is assumed the rule is eligible for NRT
     Write-Host -ForegroundColor Green "[Δ] Checks passed. Converting" $customD.id "to NRT"
     Update-NRT($customD.id)

}
