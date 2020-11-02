# This script requires that you install Azure Powershell and Azure Security Modules as a prerequisite.
# Install-Module Az
# Install-Module Az.Security

$SubscriptionID ='YOUR AZURE SUBSCRIPTION ID'
$RG ='YOUR RESOURCE GROUP NAME'
$PublicIP = (Invoke-WebRequest -uri 'http://ifconfig.me/ip').Content.tostring()
[hashtable]$Ports = @{Windows=3389; Linux=22}


Connect-AzAccount
Set-AzContext -SubscriptionId $SubscriptionID
$RGVMs = $(Get-AzVM -ResourceGroupName $RG)
$JitArray = @()
ForEach($VM in $RGVMs) {
    $OSType=(Get-AzVM -Name $VM.Name).StorageProfile.OsDisk.OsType
    Write-Host '[*] Checking' $VM.Name 'state .. located in' $VM.Location
    $VMState = $(Get-AzVM -Name $VM.Name -Status).Powerstate
    if ($VMState -eq 'Info Not Available') { Write-Host '[-] Could not Start' $VM.Name '. Info not available'}
    if ($VMState -eq 'VM deallocated') {
        Write-Host "Starting" $VM.Name "..." $(Get-AzVM -Name $VM.Name).OsName
        try { Start-AzVM -ResourceGroupName $RG -Name $VM.Name }
        catch {
            Write-Host "[!] Error in Starting" $VM.name
            Write-Host "[!] Error Name " $Error[0] }
     }  
    if ($VMState -eq 'VM running') { 
        Write-Host '[J] Adding'$VM.Name'for JIT Request on port'$Ports["$OSType"]
        $JitResourceID = "/subscriptions/"+$SubscriptionID+"/resourceGroups/"+$RG+"/providers/Microsoft.Security/locations/"+$vm.location+"/jitNetworkAccessPolicies/default"
        $JitPolicyVm = (@{
            id="/subscriptions/"+$SubscriptionID+"/resourceGroups/"+$RG+"/providers/Microsoft.Compute/virtualMachines/"+$VM.name;
            ports=(@{
               number=$Ports["$OSType"];
               endTimeUtc=(Get-Date).AddHours(3) # .tostring("yyyy-MM-ddTHH:MM:SSZ")
               allowedSourceAddressPrefix=$PublicIP})})
        $JitArray=@($JitPolicyVm)
        Start-AzJitNetworkAccessPolicy -ResourceId $JitResourceID -VirtualMachine $JitArray | Format-Table

    }
}
