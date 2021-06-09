# Get the latest Defender Engine/Version/Definition versions 
# as announced in https://www.microsoft.com/en-us/wdsi/defenderupdates
# Works on Powershell 5.1 on Windows

$wdsi = Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/wdsi/defenderupdates'
$wdsi.Content | Out-File a.txt
$versions = Select-String -Path a.txt -Pattern "<li>Version" -Context 0,3  | Out-String
$Round1 = ($versions -replace 'a.txt:[0-9][0-9][0-9]:\s+','') -replace '</?li>',''
$Round2 = $Round1 -replace '</?span>',''
$Round3 = $Round2 -replace '<span id="dateofrelease">',''
$Round4 = $Round3 -replace '>',''
$Round5 = $Round4 -replace '^ ',''
$Round6 = $Round5.Split("`r`n")
$List= @{}
ForEach ($Line in $Round6) {
    $Line=$Line.Trim(' ')
    If ($Line.Contains(":")) {
    $key=($Line.Split(':')[0]) #.Trim(' ')
    $value=$Line.Split(':')[1]
    If ($key.Contains('Released')) {
        $List.Add('ReleaseTime',$Line.Split(' ')[2]+' '+$Line.Split(' ')[3])
    }
    $List.Add($key,$value.Trim(' ').Split(' ')[0])
    }
}
$List
