param(
    # [Parameter(Mandatory)]
    [string]$appID ='APPID',
    [string]$appSecret = 'APPSECRET',
    [string]$TenantId = 'TENANTID',
    [string]$IndicatorType = 'FileSha256',
    [string]$VTapiKey = 'VTAPIKEY'
)
$ProgressPreference = 'SilentlyContinue' 

$DeletedCount = 0
$url = "https://api.securitycenter.microsoft.com/api/indicators"
$Logfile = "MDEIndicators_$(get-date -Format "yyMMdd-hhmm")_$(hostname).log"

$VTtype = Switch (($IndicatorType.ToLower())) {
    'filesha256'    {'files'}
    'filesha1'      {'files'}
    'filemd5'       {'files'}
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
        $VTresponse = Invoke-WebRequest -Method Get -Uri $VTurl -Headers $headers 
        If ($VTresponse.StatusCode -eq 429){
             Write-Host "[O] Response 429 , Virustotal API limits reached ... waiting for 30 seconds"
            Sleep 30
        }
    } 
    catch {
        $Er = ConvertFrom-Json($Error[0])
        return $er.error.code 
    }

    # Try to convert from JSON
    $isErrorOnV3 = $FALSE
    try {
        $VTdata = ($VTresponse.Content | ConvertFrom-Json).data
    }
    catch {
        $isErrorOnV3 = $TRUE
    }
    
    if ($isErrorOnV3 -eq $TRUE) {
        # JSON convert error case rised on V3 API. Use V2 API response.
        try {
            $VTtypeV2 = Switch (($IndicatorType.ToLower())) {
                'filesha256'    {'file'}
                'filesha1'      {'file'}
                'filemd5'       {'file'}
                'ipaddress'     {'ip_addresses'}
                'url'           {'urls'}
                'domainname'    {'domains'}
            }
            $VTkeyV2 = Switch (($IndicatorType.ToLower())) {
                'filesha256'    {'resource'}
                'filesha1'      {'resource'}
                'filemd5'       {'resource'}
                'ipaddress'     {'ip'}
                'url'           {'resource'}
                'domainname'    {'domain'}
            }
            $VTurlv2 = "https://www.virustotal.com/vtapi/v2/$VTtypeV2/report?apikey=$VTapiKey&$VTkeyV2=$IOC&allinfo=true"
            $VTresponseV2 = Invoke-WebRequest -Uri $VTurlv2 -Method GET
            If ($VTresponseV2.StatusCode -eq 429){
                 Write-Host "[O] Response 429 , Virustotal API limits reached ... waiting for 30 seconds"
                Sleep 30
            }
        } 
        catch {
            $Er = ConvertFrom-Json($Error[0])
            return $er.error.code 
        }
        $VTdataV2 = ($VTresponseV2.Content | ConvertFrom-Json)
        $VThitsV2 = $VTdataV2.positives
        $VTv2Category = "Undetected"
        if ($VTdataV2.scans.Microsoft.detected -eq $TRUE) {
            $VTv2Category = "malicious"
        }
        $VTResultsV2 = [PSCustomObject]@{
            Hits        = $VThitsV2
            Category    = $VTv2Category
            Result      = $VTdataV2.scans.Microsoft.result
            Engine      = $VTdataV2.scans.Microsoft.version
        }
        return $VTResultsV2
    }
    else {
        $VThits = $VTdata.attributes.last_analysis_stats.malicious
        $VTResults = [PSCustomObject]@{
            Hits        = $VThits
            Category    = $VTdata.attributes.last_analysis_results.Microsoft.category
            Result      = $VTdata.attributes.last_analysis_results.Microsoft.result
            Engine      = $VTdata.attributes.last_analysis_results.Microsoft.engine_version
        }
        return $VTResults
    }
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
Write-Log "IOCType,IOCValue,Result,DetectionName"
# Send the webrequest and get the results. 
Write-Host "[W] Connecting to Microsoft Defender service to collect $IndicatorType indicators"

$response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop

$indicators =  ($response | ConvertFrom-Json).value 
$Selection = $indicators | Where-Object { $_.indicatorType -eq $IndicatorType } 

if ([int]$Selection.count -gt 0) {
    Write-Host "[*] Found" $selection.count "of $IndicatorType indicators"
    foreach ($Indicator in $Selection) {
        Write-Host  "[?] Testing " $Indicator.indicatorValue "against the Virustotal API ..."
        Do {
            $Detection = Get-VTIndicator($Indicator.indicatorValue)
            If ($Detection -eq "QuotaExceededError") {
                Write-Host "[Q] Quota Limit Exceeded... Retrying in 60 seconds"
                Start-Sleep -Seconds 60
            }
        }
        Until ($Detection -ne "QuotaExceededError")
        If ($Detection -eq "NotFoundError") {
            Write-Host "[X]" $Indicator.indicatorValue $Indicator.title "Not found in Virustotal" -ForegroundColor Yellow
            $LogEntry = "$IndicatorType,"+$Indicator.indicatorValue+",Keep,None"
            Write-Log $LogEntry
            Continue
        }
        if ($Detection.Category -eq 'malicious') {
            Write-Host -NoNewline "[V]" $Indicator.indicatorValue $Indicator.title "is detected as " $Detection.Result -ForegroundColor DarkGreen
            Write-Host "[V] Deleting IOC" $Indicator.indicatorValue
            $RemovalStatus=Remove-Indicator($Indicator.id)
            $DeletedCount += 1
            $LogEntry = "$IndicatorType,"+$Indicator.indicatorValue+",Delete,"+$Detection.Result
            Write-Log $LogEntry
        }
    }
} else {
    Write-Host "[X] No IOCs found. Exiting ..."
    exit
}

Write-Host "[E] $DeletedCount IOCs of $IndicatorType have been deleted ... Exiting"
$ProgressPreference = 'Continue' 
