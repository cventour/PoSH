function timer([int]$secs) {
    1..$secs | foreach {
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 1
    }
}   

# Your Virustotal API key must be located at the same folder as the script
# you can comment this line if you want to paste the API key, and uncomment the line after.
# $apikey = (Get-Content -Path 'apikey.txt') 
$apikey = 'YOUR_VIRUSTOTAL_API_KEY'

#Use this variable to display the detection type for a specific vendor
$vendor = "Microsoft"

$downloadFolder = [environment]::GetEnvironmentVariable("TEMP",$([EnvironmentVariableTarget]::Machine))+"\VT"
$ProgressPreference = 'SilentlyContinue' #this supresses the progress messages from Invoke-WebRequest

# TIP : Always remember to encode the '+' sign to %2b if you need to use it in a query
# Check virustotal.com on how to create queries for the API
$query = "type:peexe size:1500kb-"
$limit = 50 #limit of results per query
$url = "https://www.virustotal.com/api/v3/intelligence/search?limit=$limit&query=$query"
$headers = @{ 
     'x-apikey' = $apikey
}


Write-Host -NoNewline "$(get-date -f 'yyyy-MM-ddTHH:mm:ss.fffZ') [Search] Searching for files with query " -ForegroundColor Green
Write-Host $query -ForegroundColor DarkYellow
$response = Invoke-WebRequest -Method Get -Uri $url -Headers $headers 

# This if-then-else snippet checks for Powershell version. If <5 it will run a JavaScript deserialization. If >5 it will use Convertfrom-Json. 
# I have seen that for large data in the $response.data , I was getting this error :
#
#  convertfrom-json : Error during serialization or deserialization using the JSON JavaScriptSerializer.
#  The length of the string exceeds the value set on the maxJsonLength property.
If ([int]$(Get-Host).version.Major -lt 5) {
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
    $jsonserial = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
    $jsonserial.MaxJsonLength = [int]::MaxValue
    $VTdata = ($jsonserial.DeserializeObject($response.Content)).data
    $VTmeta = ($jsonserial.DeserializeObject($response.Content)).meta
} else {
    $VTdata = ($response.Content | convertfrom-json).data
    $VTmeta = ($response.Content | convertfrom-json).meta
} 

$VThits = [int]$VTmeta.total_hits
if ($VThits -gt 0) {
    Write-Host "$(get-date -f 'yyyy-MM-ddTHH:mm:ss.fffZ') [Hits] Found $VThits entries in Virustotal" -ForegroundColor Green
    New-Item -Path $downloadFolder -ItemType Directory -Force | Out-Null # create a temp folder to store the files
} else {
    Write-Host "$(get-date -f 'yyyy-MM-ddTHH:mm:ss.fffZ') [Result] :( No VT entries found for your query" -ForegroundColor Red
    Write-Host "[x] Exiting ..."
    exit
}

try {
#    [console]::TreatControlCAsInput = $true
    foreach ($VTitem in $VTdata) {
      $attrib = $VTitem.attributes #get the item attributes
      if ( !($attrib.meaningful_name) -or ($attrib.meaningful_name.Contains("\"))) {  
          $filename = ($downloadFolder+"\"+$attrib.sha1).Replace('?','')
          #Write-Host "[1]" $filename
      } else {
          $filename = ($downloadFolder+"\"+$attrib.sha1 +"_"+(Split-Path $attrib.meaningful_name -Leaf)).Replace('?','') #create the filename to be saved as from the attributes 
          #Write-Host "[2]" $filename
     }
     $detections = $attrib.last_analysis_stats.malicious #capture number of detections for the file
     $vendorResult = $attrib.last_analysis_results.$vendor.result
     $DLurl = $VTitem.links.self+"/download_url" #create the URL string for downloading the file
     Write-Host "$(get-date -f 'yyyy-MM-ddTHH:mm:ss.fffZ') [Download]" $filename "hash" $attrib.sha1 " Detections" $detections "$vendor detection :" $vendorResult
     # $key = [system.console]::readkey($true)
     if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
        break
     } 
     $file = Invoke-WebRequest -Method Get -Uri $DLurl -Headers $headers 
     If ($file.StatusDescription -eq "OK") {
         $fileURL= ($file.Content | convertfrom-json).data #extract the direct link for the URL
         # If you just want to test getting malware URLs and don't want to download then, comment the line below.
         #$DownloadFile = Invoke-WebRequest -Method Get -Uri $fileURL -OutFile $filename #download the file
     } else {
         Write-Host -NoNewline "[x] Request for file returned error" 
         Write-Host $file.StatusDescription -ForegroundColor Red
     }
    }
}   
finally {
#    [console]::TreatControlCAsInput = $false
}

# Wait for AV to detect 
try {
    Write-Host -NoNewline "$(get-date -f 'yyyy-MM-ddTHH:mm:ss.fffZ') [Wait] Waiting 90 Seconds for AV to detect and block "
    timer(90)
}
finally {
    # Clean the folder
  
    Write-Host "`r`n$(get-date -f 'yyyy-MM-ddTHH:mm:ss.fffZ') [Cleanup] Wiping the samples ..."
    Remove-Item -Path $downloadFolder -Force -Recurse | Out-Null
    Write-Host "$(get-date -f 'yyyy-MM-ddTHH:mm:ss.fffZ') [Exiting] Bye now ..." -ForegroundColor Green
    $ProgressPreference = 'Continue' #re-enables the progress messages from Invoke-WebRequest
}

