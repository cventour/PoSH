## Clean MDE File Indicators

### When do I need this tool ?

Are you in a situation where you have several hundreds or thousands of File Hash Indicators added in the Microsoft Defender for Endpoint portal and you do not know if you can delete some of them because Defender AV can already block them ? Well, this tool is for you.  It will

- use Defender APIs to get your File Indicators
- check them against Virustotal and find if the Defender AV engine knows about them
- Delete the indicators that are already known to Defender AV

### What do I need to get this script to run ?

You will need

- A Virustotal API key (premium or public , doesn't matter)
- An Azure App Registration that gives the API access to your MDE indicators. 
- A generated app secret and AppID for the API
- Your Azure Tenant ID

You can edit those parameters directly to the script or pass them to the script as you run it.

The script automatically creates a logfile in the format of MDEIndicators_[yyyyMMdd-hhmm][hostname].log with the following CSV format

IOCType - FileSha256 currently
IOCValue - The hash value of the IOC (any value of MD5, SHA1, SHA2)
Result - "Delete" if the IOC is deleted from the File Indicators list or "Keep" if it remains in the portal.

### Examples of Usage

`Clean-MDEIndicators.ps -appID ABCDEF -AppSecret APPSECRETHERE -TenantID TENANTID_GUID -VTapiKey YOURVIRUSTOTALAPIKEY`


