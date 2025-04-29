# Disabling LLMNR and mDNS in Active Directory via Group Policy

> **Note:** This guide demonstrates how to disable Link-Local Multicast Name Resolution (LLMNR) and Multicast DNS (mDNS) protocols in an Active Directory environment using Group Policy. These steps should be performed by a domain administrator.

## Introduction

Link-Local Multicast Name Resolution (LLMNR) and Multicast DNS (mDNS) are network protocols that allow name resolution without a DNS server. While convenient, they present security risks as they can be exploited for man-in-the-middle attacks, credential theft, and network reconnaissance.

This guide will show you how to disable these protocols using Group Policy Objects (GPOs) to enhance your network security posture.

## Prerequisites

* Domain Administrator privileges
* Access to a domain controller
* Group Policy Management Console (GPMC) installed
* Active Directory Module for Windows PowerShell

## Step-by-Step Guide

### Step 1: Log in to your Domain Controller

Log in to your domain controller with an account that has Domain Administrator privileges.

![Log in to the Domain Controller with administrator credentials](../images/step1_login.png)

### Step 2: Open Group Policy Management Console

Open the Group Policy Management Console:
1. Click on **Start**
2. Type "Group Policy Management" and click on the result
3. Or navigate to **Server Manager** → **Tools** → **Group Policy Management**

![Opening Group Policy Management Console](../images/step2_gpmc.png)

### Step 3: Create GPO for Domain Controllers

First, let's create a GPO to disable LLMNR and mDNS on Domain Controllers:
1. In the Group Policy Management Console, right-click on the "**Group Policy Objects**" folder under your domain
2. Select "**New**"
3. Name it "**Disable LLMNR and mDNS - Domain Controllers**"
4. Click "**OK**"

![Creating a new GPO for Domain Controllers](../images/step3_create_gpo.png)

### Step 4: Configure LLMNR settings in the GPO

1. Right-click the newly created GPO and select "**Edit**"
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Network** → **DNS Client**
3. Find the policy "**Turn off multicast name resolution**"
4. Double-click this policy to open it
5. Select "**Enabled**"
6. Click "**OK**"

![Enabling the "Turn off multicast name resolution" policy](../images/step4_llmnr_policy.png)

### Step 5: Configure mDNS settings in the GPO

We'll need to use registry settings to disable mDNS as there is no direct Group Policy setting for it:
1. In the GPO editor, navigate to **Computer Configuration** → **Preferences** → **Windows Settings** → **Registry**
2. Right-click on **Registry** and select **New** → **Registry Item**
3. Configure the registry item:
   - Action: **Update**
   - Hive: **HKEY_LOCAL_MACHINE**
   - Key Path: **SYSTEM\CurrentControlSet\Services\Dnscache\Parameters**
   - Value name: **EnableMDNS**
   - Value type: **REG_DWORD**
   - Value data: **0**
4. Click "**OK**"

![Creating a registry entry to disable mDNS](../images/step5_mdns_registry.png)

### Step 6: Link the GPO to the Domain Controllers OU

1. Back in the Group Policy Management Console, right-click on the "**Domain Controllers**" organizational unit
2. Select "**Link an Existing GPO**"
3. Select the "**Disable LLMNR and mDNS - Domain Controllers**" GPO
4. Click "**OK**"

![Linking the GPO to the Domain Controllers OU](../images/step6_link_gpo.png)

### Step 7: Create and Link GPO for Client Computers

Now repeat the process for client computers:
1. Create a new GPO named "**Disable LLMNR and mDNS - Client Computers**"
2. Configure the same settings as in Steps 4 and 5
3. Link this GPO to the OU containing your client computers (e.g., "Computers" OU)

![GPO linked to the Computers OU](../images/step7_client_gpo.png)

### Step 8: Force Group Policy Update

To apply the new policies immediately:
1. On each domain controller and client computer, open a Command Prompt or PowerShell as Administrator
2. Run the command: `gpupdate /force`
3. Wait for the update to complete

![Running gpupdate /force to apply the Group Policy changes](../images/step8_gpupdate.png)

### Step 9: Verify the Policy Application

To verify that the policies have been applied correctly:
1. On a client computer, open a Command Prompt as Administrator
2. Run the command: `gpresult /h C:\GPReport.html`
3. Open the generated HTML report and check for the applied policies
4. Alternatively, check the registry keys directly:
   - Open Registry Editor: `regedit`
   - Navigate to `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`
   - Verify that "**EnableMulticast**" is set to 0
   - Navigate to `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`
   - Verify that "**EnableMDNS**" is set to 0

![Verifying registry settings](../images/step9_verify.png)

## Using the PowerShell Script

Alternatively, you can use the provided PowerShell script to automate the entire process:

1. Log in to a domain controller with Domain Administrator privileges
2. Download the `disable_LLMNR_mDNS.ps1` script from the repository
3. Open PowerShell as Administrator
4. Navigate to the directory containing the script
5. Run the script: `.\disable_LLMNR_mDNS.ps1`
6. Follow the prompts in the script

```powershell
# Example execution:
PS C:\Scripts> .\disable_LLMNR_mDNS.ps1
Enter the Distinguished Name of the OU containing client computers: OU=Workstations,DC=contoso,DC=com
```

> **Warning:** Always test Group Policy changes in a non-production environment first. Disabling these protocols may affect applications that rely on them. Ensure you have tested thoroughly before implementing in production.

## Conclusion

By disabling LLMNR and mDNS through Group Policy, you've eliminated potential attack vectors in your Active Directory environment. These changes help prevent man-in-the-middle attacks and credential theft, significantly improving your organization's security posture.

> **Note:** Remember to monitor your environment after making these changes to ensure there are no unintended consequences or applications that rely on these protocols.

---

© 2025 - Active Directory Security Best Practices