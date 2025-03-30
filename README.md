# Active Directory Group Policy Security Scripts

This repository contains PowerShell scripts and documentation for implementing security best practices in Active Directory environments using Group Policy.

## Contents

### Scripts

- [Disable LLMNR and mDNS](scripts/disable_LLMNR_mDNS.ps1) - Script to disable Link-Local Multicast Name Resolution (LLMNR) and Multicast DNS (mDNS) via Group Policy for domain controllers and client computers.

### Documentation

- [Guide for Disabling LLMNR and mDNS](docs/disable_LLMNR_mDNS_guide.html) - Step-by-step instructions with screenshots for implementing LLMNR and mDNS disabling via Group Policy.

## Why Disable LLMNR and mDNS?

Link-Local Multicast Name Resolution (LLMNR) and Multicast DNS (mDNS) are network protocols that allow name resolution without a DNS server. While convenient, they present serious security risks:

1. **Man-in-the-Middle Attacks**: Attackers can exploit these protocols to intercept network traffic by responding to broadcast name resolution requests.

2. **Credential Theft**: When these protocols are used, password hashes can be captured and potentially cracked using tools like Responder and Hashcat.

3. **Network Reconnaissance**: These protocols can leak information about your internal network structure and naming conventions.

Disabling these protocols is a recommended security practice by many organizations including Microsoft and the NSA.

## Usage

### Requirements

- Windows Server with Active Directory Domain Services
- PowerShell 5.1 or higher
- Domain Administrator privileges
- Group Policy Management Console (GPMC)
- Active Directory PowerShell Module

### Running the Script

1. Download the script from this repository
2. Open PowerShell as Administrator on a Domain Controller
3. Run the script:
   ```powershell
   .\scripts\disable_LLMNR_mDNS.ps1
   ```
4. Follow the prompts to complete the implementation

Alternatively, follow the step-by-step guide in the documentation section to manually configure the necessary Group Policy settings.

## Contributing

Contributions to improve the scripts or documentation are welcome. Please submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.