param(
    # [Parameter(Mandatory)]
    [string]$appID ='YOUR_APP_ID',
    [string]$appSecret = 'YOUR_MDE_APP_SECRET',
    [string]$TenantId = 'YOUR_TENANT_ID',
    [string]$IndicatorType = 'FileSha256',
    [string]$VTapiKey = 'YOUR_VIRUSTOTAL_API_KEY'
)
$ProgressPreference = 'SilentlyContinue' 

$url = "https://api.securitycenter.microsoft.com/api/indicators"
$Logfile = "MDEIndicators_$(get-date -Format "yyMMdd-hhmm")_$(hostname).log"

$VTtype = Switch (($IndicatorType.ToLower())) {
    'filesha256'    {'files'}
    'ipaddress'     {'ip_addresses'}
    'url'           {'urls'}
    'domainname'    {'domains'}
}

Function Write-Log {
   Param (
       [string]$logstring
    )
   Add-content $Logfile -value $logstring
}

function Get-VTIndicator {
    param (
        [string]$IOC
    )
    $VTurl = "https://www.virustotal.com/api/v3/$VTtype/$IOC"
    $headers = @{ 
     'x-apikey' = $VTapiKey
    }
    try {
        Do {
            $VTresponse = Invoke-WebRequest -Method Get -Uri $VTurl -Headers $headers 
            If ($VTresponse.StatusCode -eq 429){
                Write-Host "[O] Response 429 , Virustotal API limits reached ... waiting for 30 seconds"
                Sleep 30
            }
        }
        Until ($VTResponse.StatusCode -eq 200)
    } 
    catch {
        $Er = ConvertFrom-Json($Error[0])
    }
    if ($er.error.code -eq 'NotFoundError') {
        return "NotFound"
    }
    $VTdata = ($VTresponse.Content | convertfrom-json).data
    $VThits = $VTdata.attributes.last_analysis_stats.malicious
    $VTResults = [PSCustomObject]@{
        Hits        = $VThits
        Category    = $VTdata.attributes.last_analysis_results.Microsoft.category
        Result      = $VTdata.attributes.last_analysis_results.Microsoft.result
        Engine      = $VTdata.attributes.last_analysis_results.Microsoft.engine_version
    }
    return $VTResults
}
function Remove-Indicator {
    param (
        [string]$IOCid
    ) 
    $delurl = $url+"/"+$IOCid
    $response = Invoke-WebRequest -Method Delete -Uri $delurl -Headers $headers -ErrorAction Stop
    #return $response
}

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

# Set the WebRequest headers
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token" 
}


Write-Host "[L] Creating log file $Logfile"
Write-Log "Creating Log file on $(Get-Date -Format 'yyyy-MM-dd , hh:mm:ss')" 
Write-Log "IOCType,IOCValue,Result"
# Send the webrequest and get the results. 
$response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop

$indicators =  ($response | ConvertFrom-Json).value 
$Selection = $indicators | Where-Object { $_.indicatorType -eq $IndicatorType } 

if ([int]$Selection.count -gt 0) {
    Write-Host "[*] Found" $selection.count "of $IndicatorType indicators"
    foreach ($Indicator in $Selection) {
        Write-Host  "[?] Testing " $Indicator.indicatorValue "against the Virustotal API ..."
        $Detection = Get-VTIndicator($Indicator.indicatorValue)
        If ($Detection -eq "NotFound") {
            Write-Host "[X]" $Indicator.indicatorValue $Indicator.title "Not found in VT" -ForegroundColor Yellow
            $LogEntry = "$IndicatorType,"+$Indicator.indicatorValue+",Keep"
            Write-Log $LogEntry
            Continue
        }
        if ($Detection.Category -eq 'malicious') {
            Write-Host -NoNewline "[V]" $Indicator.indicatorValue $Indicator.title "is detected as " $Detection.Result -ForegroundColor DarkGreen
            Write-Host "[V] Deleting IOC" $Indicator.indicatorValue
            $RemovalStatus=Remove-Indicator($Indicator.id)
            $LogEntry = "$IndicatorType,"+$Indicator.indicatorValue+",Delete"
            Write-Log $LogEntry
        }
    }
} else {
    Write-Host "[X] No IOCs found. Exiting ..."
    exit
}

$ProgressPreference = 'Continue' 
