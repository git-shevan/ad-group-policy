# Comprehensive Guide: Disabling LLMNR and mDNS in Active Directory

<div style="text-align: center;">
<h2>A Security Hardening Guide for Active Directory Environments</h2>
<h3>Version 1.0</h3>
<p>Prepared by: Domain Administrator</p>
<p>Last Updated: March 2025</p>
</div>

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Understanding the Security Risks](#understanding-the-security-risks)
   1. [What is LLMNR?](#what-is-llmnr)
   2. [What is mDNS?](#what-is-mdns)
   3. [Attack Vectors](#attack-vectors)
3. [Implementation Planning](#implementation-planning)
   1. [Prerequisites](#prerequisites)
   2. [Risk Assessment](#risk-assessment)
   3. [Testing Strategy](#testing-strategy)
4. [Implementation Steps](#implementation-steps)
   1. [Manual Configuration via Group Policy Management Console](#manual-configuration-via-group-policy-management-console)
   2. [Automated Deployment via PowerShell](#automated-deployment-via-powershell)
5. [Verification and Validation](#verification-and-validation)
6. [Troubleshooting](#troubleshooting)
7. [Appendices](#appendices)
   1. [Registry Settings Reference](#registry-settings-reference)
   2. [PowerShell Script Code](#powershell-script-code)
   3. [Additional Resources](#additional-resources)

## Executive Summary

This document provides detailed instructions for disabling Link-Local Multicast Name Resolution (LLMNR) and Multicast DNS (mDNS) protocols in an Active Directory environment using Group Policy. These two protocols, while designed to provide convenient name resolution in the absence of DNS servers, introduce significant security vulnerabilities that can be exploited by attackers to steal credentials and perform lateral movement within a network.

By implementing the controls described in this document, organizations can significantly reduce their attack surface and enhance protection against common network-based credential theft attacks.

## Understanding the Security Risks

### What is LLMNR?

Link-Local Multicast Name Resolution (LLMNR) is a protocol developed by Microsoft that allows both IPv4 and IPv6 hosts to perform name resolution for hosts on the same local link without requiring a DNS server. LLMNR is implemented in Windows operating systems and is enabled by default.

When a Windows system fails to resolve a hostname using DNS, it will attempt to use LLMNR. The system broadcasts a query to the local network asking if any host can resolve the name in question.

### What is mDNS?

Multicast DNS (mDNS) functions similarly to LLMNR but is used primarily in Apple environments and is part of the Bonjour protocol suite. Like LLMNR, mDNS allows hosts on a local network to resolve each other's names without a centralized DNS server.

Microsoft has implemented mDNS in Windows 10 and Windows Server 2016 and later versions to support interoperability with Apple devices and other non-Windows platforms that use mDNS for service discovery.

### Attack Vectors

These protocols pose significant security risks because they can be exploited for various attacks:

1. **Man-in-the-Middle Attacks**: An attacker on the same network can respond to LLMNR/mDNS broadcasts, impersonating the requested resource.

2. **Credential Theft**: When a malicious actor responds to these broadcasts, the victim's system may attempt to authenticate to what it believes is a legitimate resource, sending authentication hashes that can be captured.

3. **Hash Cracking**: The captured NTLM hashes can be cracked offline to reveal plaintext passwords.

4. **Lateral Movement**: Compromised credentials can be used to access other systems and resources on the network.

Common attack tools like Responder and Inveigh specifically target these protocols to harvest credentials.

## Implementation Planning

### Prerequisites

Before implementing this hardening measure, ensure you have:

* Domain Administrator privileges
* Access to a domain controller
* Group Policy Management Console (GPMC)
* Active Directory PowerShell Module
* A test environment (recommended)

### Risk Assessment

While disabling LLMNR and mDNS significantly improves security, consider these potential impacts:

* Some applications may rely on these protocols for name resolution
* Connectivity between Windows and Apple devices may be affected
* Legacy applications may experience issues

It's recommended to test this change in a non-production environment before full deployment.

### Testing Strategy

1. Create a test OU with representative systems
2. Apply GPOs to the test OU
3. Monitor for application issues for at least one week
4. Document any applications that require these protocols
5. Develop mitigation strategies for affected applications

## Implementation Steps

### Manual Configuration via Group Policy Management Console

#### For Domain Controllers

1. Log in to a domain controller with Domain Administrator credentials
2. Open Group Policy Management Console
3. Create a new GPO named "Disable LLMNR and mDNS - Domain Controllers"
4. Configure the following settings:
   * For LLMNR:
     * Computer Configuration → Policies → Administrative Templates → Network → DNS Client
     * Enable "Turn off multicast name resolution"
   * For mDNS:
     * Computer Configuration → Preferences → Windows Settings → Registry
     * Add registry entry:
       * HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0 (DWORD)
5. Link the GPO to the Domain Controllers OU

#### For Client Computers

1. Create a new GPO named "Disable LLMNR and mDNS - Client Computers"
2. Configure the same settings as for domain controllers
3. Link the GPO to the OU(s) containing client computers
4. Force Group Policy update with `gpupdate /force` or wait for normal refresh

### Automated Deployment via PowerShell

For larger environments, we've developed a PowerShell script that automates the creation and linking of GPOs:

1. Download the `disable_LLMNR_mDNS.ps1` script from our repository
2. Run the script on a domain controller with administrator privileges
3. When prompted, enter the distinguished name of the OU containing client computers
4. The script will create and link the GPOs to both the Domain Controllers OU and the specified client OU
5. Optionally, the script can force immediate policy updates

## Verification and Validation

After implementing the GPOs, verify they are working correctly:

1. **Using Group Policy Results**:
   * On a client, run `gpresult /h C:\GPReport.html`
   * Open the HTML report and verify the GPO is applied

2. **Checking Registry Settings**:
   * Verify HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0
   * Verify HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0

3. **Network Traffic Analysis**:
   * Use Wireshark to confirm no LLMNR or mDNS traffic is being generated

4. **Security Testing**:
   * Run a tool like Responder in passive mode to confirm no responses to LLMNR/mDNS

## Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|------------|
| GPO not applying | Incorrect WMI filters | Check WMI filters, ensure computer is in correct OU |
| Application connectivity issues | Application relies on LLMNR/mDNS | Add specific DNS entries for required resources |
| Apple device connectivity issues | Bonjour services affected | Consider implementing DNS Service Discovery as alternative |
| GPO conflicts | Multiple policies affecting same settings | Check GPO precedence and inheritance blocking |

## Appendices

### Registry Settings Reference

**LLMNR Settings**
* Path: HKLM\Software\Policies\Microsoft\Windows NT\DNSClient
* Value: EnableMulticast
* Type: DWORD
* Data: 0 (Disabled)

**mDNS Settings**
* Path: HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
* Value: EnableMDNS
* Type: DWORD
* Data: 0 (Disabled)

### PowerShell Script Code

The complete PowerShell script can be found in the repository at:
`scripts/disable_LLMNR_mDNS.ps1`

### Additional Resources

1. [Microsoft Documentation: Link-Local Multicast Name Resolution](https://docs.microsoft.com/en-us/windows/win32/dns/link-local-multicast-name-resolution)
2. [MITRE ATT&CK: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
3. [NSA Cybersecurity Information Sheet: Defending Against LLMNR and mDNS](https://media.defense.gov/2022/Mar/01/2002947937/-1/-1/0/CSI_DEFENDING_AGAINST_LLMNR_AND_MDNS.PDF)

---

<div style="text-align: center;">
<p>&copy; 2025 - Active Directory Security Best Practices</p>
<p>For internal use only</p>
</div>