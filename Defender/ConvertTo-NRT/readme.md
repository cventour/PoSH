# .Synopsis
  Converts eligible M365D custom detections to Near Real Time schedule (NRT)

# .Description
  This script will access the Custom Detections created in M365D , identify their eligibility 
  for being converted to Near Real Time (NRT) and if eligible, they will be converted to NRT.
  The script requires parameters to access the M365D tenant and the  schedule frequency you
  are targeting for conversion. The script is using the Custom Detections API which has been 
  in Graph.

### .Parameter tenantID
  Your Defender for Endpoint Tenant ID

### .Parameter appID
  The appID that you have created to access the Defender API

### .Parameter appSecret
  The client secret that was generated once you created the app registration.

### .Parameter frequency
  The frequency that is targeted for conversion to NRT. Default is "1H"

### .Example
  ConvertTo-NRT r -tenantID 4jflcvcl3-f45f-2j4j-cl5lf-e5vcxvcxv7 -appID cccccccc-aaaa-bbbb-dddd-ffgghhjjkkll -appSecret cvcvcvcvcv+_werkjewrewr9999 -frequency 24H

  This will convert all eligible custom detections that have a current frequency of 24H to NRT
