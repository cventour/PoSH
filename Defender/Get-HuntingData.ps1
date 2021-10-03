param(
  #  [Parameter(Mandatory)] 
    [string]$appID ='YOUR_APP_ID',
    [string]$appSecret = 'YOUR_APP_SECRET',
    [string]$TenantId = 'YOUR_TENANT_ID'
)

$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"


# Your Hunting Query Here - The below query is just an example
$huntingQuery = 
'let EvalTable = DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-91","scid-2000","scid-2001","scid-2001","scid-2002","scid-2003","scid-2010","scid-2011","scid-2012","scid-2013","scid-2014","scid-2016")
| summarize arg_max(Timestamp,IsCompliant, IsApplicable) by DeviceId, ConfigurationId,tostring(Context)
| extend Test = case(
ConfigurationId == "scid-2000" , "SensorEnabled",
ConfigurationId == "scid-2001" , "SensorDataCollection",
ConfigurationId == "scid-2002" , "ImpairedCommunications",
ConfigurationId == "scid-2003" , "TamperProtection",
ConfigurationId == "scid-2010" , "AntivirusEnabled",
ConfigurationId == "scid-2011" , "AntivirusSignatureVersion",
ConfigurationId == "scid-2012" , "RealtimeProtection",
ConfigurationId == "scid-91" , "BehaviorMonitoring",
ConfigurationId == "scid-2013" , "PUAProtection",
ConfigurationId == "scid-2014" , "AntivirusReporting" ,
ConfigurationId == "scid-2016" , "CloudProtection",
"N/A"),
Result = case(IsApplicable == 0,"N/A",IsCompliant == 1 , "GOOD", "BAD")
| extend packed = pack(Test,Result)
| summarize Tests = make_bag(packed) by DeviceId
| evaluate bag_unpack(Tests);
let DefUpdate = DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2011"
// | where isnotnull(Context)
| extend Definition = parse_json(Context[0][0])
| extend LastUpdated = parse_json(Context[0][2])
| project DeviceId,Definition,LastUpdated;
let DeviceInformation = DeviceInfo
| where isnotempty(OSPlatform)
| summarize arg_max(Timestamp,*) by DeviceId, DeviceName
| project DeviceId, DeviceName, MachineGroup;
let withNames = EvalTable
| join kind = inner DeviceInformation on DeviceId
| project-away DeviceId1
| project-reorder DeviceName, MachineGroup;
withNames | join kind = fullouter DefUpdate on DeviceId 
| project-away DeviceId1
'
#

$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
      
$url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

# Set the WebRequest headers
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token" 
}

$body = ConvertTo-Json -InputObject @{ 'Query' = $huntingQuery }

# Send the webrequest and get the results. 
$webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop

$response =  ($webResponse | ConvertFrom-Json)
$results = $response.Results | convertto-csv -NoTypeInformation | Set-Content query.csv
