## PoSH
Random Powershell scripts that I create to automate tasks I am too lazy to click on.


### JitAuto.ps1
Working with Azure VMs and protecting them with JIT (Just In Time access) is great ! But when I have a lab of 5+ machines, its really daunting to go to the portal and Start all of them and then Request access one by one. I created this script to automate the process of starting a VM and then requesting access for it. You just need to edit the script to add your own Subscription ID and Resource Group for which you want to start the machines.

The script will

- Capture your public IP
- Iterate all machines in Resource Group
- Start them if they are down
- Create a JIT Access Request for the relevant tcp port depending on the OS, for your public IP


## DISCLAIMER
The scripts are shared as is. Use them at your own risk. I do not intentionaly share scripts that may be breaking something and I take no responsibility if the script breaks something you built.
