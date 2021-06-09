## Defender Scripts
Scripts that I've written to make my life easier with MS Defender for Endpoint


### Delete-Indicator.ps1
When you have imported a large number of indicators that you dont need anymore (and you haven't configured auto-expiration when importing them) you will need to multi-select and delete them in the portal or use the Defender API. I created this script to speed the up the deletion process for Indicators that I want to delete

Usage :

`Delete-Indicator.ps1 -tenantID [yourMDEtenantID] -clientID [yourAPIclientID] -appSecret [yourAPIappSecret] -type id|title -value [valueOfTheFieldYouWantToDelete]`

Preparation :

you will need to issue an API clientID and appSecret from your Azure portal to authenticate to the API. More info in the link https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro?view=o365-worldwide

### Get-WDSI5.ps1
This is a powershell script for Windows devices. You can use it when you want to query MS for the latest definitions and engine versions of Defender. Useful if you are checking device compliance against your current Defender definitions. Has been tested for PoSH version 5.1

### Get-WDSI5.ps1
This is a powershell script for Mac devices. You can use it when you want to query MS for the latest definitions and engine versions of Defender. Useful if you are checking device compliance against your current Defender definitions. Has been tested for PoSH version 7.1 on Mac

## DISCLAIMER
The scripts are shared as is. Use them at your own risk. I do not intentionaly share scripts that may be breaking something and I take no responsibility if the script breaks something you built.
