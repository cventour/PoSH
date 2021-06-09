

$wdsi = Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/wdsi/defenderupdates'
$wdsi.Content | Out-File a.txt
$versions = Select-String -Path a.txt -Pattern "<li>Version" -Context 0,3 -NoEmphasis | Out-String
$Round1 = ($versions -replace 'a.txt:[0-9][0-9][0-9]:\s+','') -replace '</?li>',''
$Round2 = $Round1 -replace '</?span>',''
$Round3 = $Round2 -replace '<span id="dateofrelease">',''
$Round4 = $Round3 -replace '>',''
$Round5 = $Round4 -replace '^ ',''
$WDSIObject = $Round5 | ConvertFrom-StringData  -Delimiter ':'
