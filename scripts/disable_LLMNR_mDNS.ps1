#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Script to disable LLMNR and mDNS via Group Policy for domain controllers and clients.

.DESCRIPTION
    This script creates and configures Group Policy Objects (GPOs) to disable Link-Local Multicast Name Resolution (LLMNR)
    and Multicast DNS (mDNS) on domain controllers and client computers. This is a security best practice to prevent 
    potential man-in-the-middle attacks that exploit these protocols.

.NOTES
    File Name  : disable_LLMNR_mDNS.ps1
    Author     : Domain Administrator
    Requires   : PowerShell 5.1
                 Active Directory PowerShell Module
                 Group Policy Management Module
                 Administrator rights
                 Domain Admin privileges

.EXAMPLE
    .\disable_LLMNR_mDNS.ps1
    Runs the script to create and apply GPOs to disable LLMNR and mDNS.
#>

# Function to check and import required modules
function Import-RequiredModules {
    [CmdletBinding()]
    param()
    
    process {
        $requiredModules = @("ActiveDirectory", "GroupPolicy")
        
        foreach ($module in $requiredModules) {
            if (!(Get-Module -Name $module -ListAvailable)) {
                Write-Host "Required module $module is not installed!" -ForegroundColor Red
                Write-Host "Please install the module using: Install-WindowsFeature -Name RSAT-AD-PowerShell,GPMC" -ForegroundColor Yellow
                exit 1
            } else {
                try {
                    Import-Module $module -ErrorAction Stop
                    Write-Host "Successfully imported module: $module" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to import module $module. Error: $_" -ForegroundColor Red
                    exit 1
                }
            }
        }
    }
}

# Function to verify domain admin privileges
function Test-DomainAdminRights {
    [CmdletBinding()]
    param()
    
    process {
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $windowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
            
            # Check if running with admin rights
            if (!$windowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Host "This script requires administrator privileges. Please run as administrator." -ForegroundColor Red
                return $false
            }
            
            # Check if user is a domain admin
            $domainName = (Get-ADDomain).NetBIOSName
            $domainAdminsSid = (Get-ADGroup "Domain Admins").SID
            
            if (!$windowsPrincipal.IsInRole($domainAdminsSid)) {
                Write-Host "This script requires Domain Admin privileges. Current user is not a Domain Admin." -ForegroundColor Red
                return $false
            }
            
            Write-Host "Verified: User has necessary Domain Admin privileges." -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "Error verifying domain admin rights: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Function to create GPO for disabling LLMNR
function New-LLMNRDisabledGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GPOName,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetOU
    )
    
    process {
        try {
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "GPO '$GPOName' already exists. Removing existing GPO before creating a new one." -ForegroundColor Yellow
                Remove-GPO -Name $GPOName -Confirm:$false
            }
            
            # Create new GPO
            Write-Host "Creating new GPO: $GPOName..." -ForegroundColor Cyan
            $newGPO = New-GPO -Name $GPOName -Comment "Disables LLMNR protocol for security hardening"
            
            # Configure registry settings to disable LLMNR
            $llmnrRegPath = "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient"
            $llmnrValueName = "EnableMulticast"
            $llmnrValue = 0
            
            Write-Host "Configuring LLMNR registry settings in GPO..." -ForegroundColor Cyan
            Set-GPRegistryValue -Name $GPOName -Key $llmnrRegPath -ValueName $llmnrValueName -Type DWord -Value $llmnrValue
            
            # Link GPO to target OU
            Write-Host "Linking GPO to target OU: $TargetOU..." -ForegroundColor Cyan
            New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes -Enforced Yes
            
            Write-Host "Successfully created and linked GPO '$GPOName' to disable LLMNR." -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "Error creating LLMNR GPO: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Function to create GPO for disabling mDNS
function New-MDNSDisabledGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GPOName,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetOU
    )
    
    process {
        try {
            # Check if GPO already exists
            $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
            if ($existingGPO) {
                Write-Host "GPO '$GPOName' already exists. Removing existing GPO before creating a new one." -ForegroundColor Yellow
                Remove-GPO -Name $GPOName -Confirm:$false
            }
            
            # Create new GPO
            Write-Host "Creating new GPO: $GPOName..." -ForegroundColor Cyan
            $newGPO = New-GPO -Name $GPOName -Comment "Disables mDNS protocol for security hardening"
            
            # Configure registry settings to disable mDNS - DNSClient policy
            # This policy might overlap with LLMNR policy, but we're keeping it for completeness
            $mdnsRegPath1 = "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient"
            $mdnsValueName1 = "EnableMulticast"
            $mdnsValue1 = 0
            
            # Configure registry settings to disable mDNS - Dnscache service parameters
            $mdnsRegPath2 = "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
            $mdnsValueName2 = "EnableMDNS"
            $mdnsValue2 = 0
            
            Write-Host "Configuring mDNS registry settings in GPO..." -ForegroundColor Cyan
            Set-GPRegistryValue -Name $GPOName -Key $mdnsRegPath1 -ValueName $mdnsValueName1 -Type DWord -Value $mdnsValue1
            Set-GPRegistryValue -Name $GPOName -Key $mdnsRegPath2 -ValueName $mdnsValueName2 -Type DWord -Value $mdnsValue2
            
            # Link GPO to target OU
            Write-Host "Linking GPO to target OU: $TargetOU..." -ForegroundColor Cyan
            New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes -Enforced Yes
            
            Write-Host "Successfully created and linked GPO '$GPOName' to disable mDNS." -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "Error creating mDNS GPO: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Function to force Group Policy update
function Invoke-GPUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetOU
    )
    
    process {
        try {
            Write-Host "Retrieving computers from target OU: $TargetOU..." -ForegroundColor Cyan
            $computers = Get-ADComputer -Filter * -SearchBase $TargetOU
            
            Write-Host "Found $($computers.Count) computers in the target OU." -ForegroundColor Cyan
            
            foreach ($computer in $computers) {
                Write-Host "Attempting to force Group Policy update on $($computer.Name)..." -ForegroundColor Cyan
                try {
                    Invoke-Command -ComputerName $computer.Name -ScriptBlock { gpupdate /force } -ErrorAction SilentlyContinue
                    Write-Host "Successfully updated Group Policy on $($computer.Name)." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to update Group Policy on $($computer.Name). Error: $_" -ForegroundColor Yellow
                }
            }
            
            Write-Host "Group Policy update process completed." -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "Error during Group Policy update: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Main script execution
function Start-Execution {
    [CmdletBinding()]
    param()
    
    process {
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "  LLMNR and mDNS Disabling Script via Group Policy" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        
        # Check prerequisites
        Write-Host "`nStep 1: Checking prerequisites..." -ForegroundColor Cyan
        Import-RequiredModules
        
        if (!(Test-DomainAdminRights)) {
            Write-Host "Prerequisites check failed. Exiting script." -ForegroundColor Red
            return
        }
        
        # Get domain information
        $domainDN = (Get-ADDomain).DistinguishedName
        $dcOU = "OU=Domain Controllers,$domainDN"
        $clientsOU = Read-Host "Enter the Distinguished Name of the OU containing client computers (e.g., 'OU=Computers,$domainDN')"
        
        # Verify OUs exist
        Write-Host "`nStep 2: Verifying target OUs..." -ForegroundColor Cyan
        try {
            $null = Get-ADOrganizationalUnit -Identity $dcOU
            Write-Host "Domain Controllers OU verified: $dcOU" -ForegroundColor Green
        }
        catch {
            Write-Host "Error: Domain Controllers OU not found. Exiting script." -ForegroundColor Red
            return
        }
        
        try {
            $null = Get-ADOrganizationalUnit -Identity $clientsOU
            Write-Host "Clients OU verified: $clientsOU" -ForegroundColor Green
        }
        catch {
            Write-Host "Error: Clients OU not found. Exiting script." -ForegroundColor Red
            return
        }
        
        # Create and link GPOs for Domain Controllers
        Write-Host "`nStep 3: Creating and linking GPOs for Domain Controllers..." -ForegroundColor Cyan
        $dcLLMNRGPO = New-LLMNRDisabledGPO -GPOName "Disable LLMNR - Domain Controllers" -TargetOU $dcOU
        $dcMDNSGPO = New-MDNSDisabledGPO -GPOName "Disable mDNS - Domain Controllers" -TargetOU $dcOU
        
        # Create and link GPOs for Clients
        Write-Host "`nStep 4: Creating and linking GPOs for Client computers..." -ForegroundColor Cyan
        $clientLLMNRGPO = New-LLMNRDisabledGPO -GPOName "Disable LLMNR - Client Computers" -TargetOU $clientsOU
        $clientMDNSGPO = New-MDNSDisabledGPO -GPOName "Disable mDNS - Client Computers" -TargetOU $clientsOU
        
        # Ask user if they want to force Group Policy update
        Write-Host "`nStep 5: Group Policy Update" -ForegroundColor Cyan
        $forceUpdate = Read-Host "Do you want to force a Group Policy update on all computers? (Y/N)"
        
        if ($forceUpdate -eq "Y" -or $forceUpdate -eq "y") {
            Write-Host "Forcing Group Policy update on Domain Controllers..." -ForegroundColor Cyan
            Invoke-GPUpdate -TargetOU $dcOU
            
            Write-Host "Forcing Group Policy update on Client computers..." -ForegroundColor Cyan
            Invoke-GPUpdate -TargetOU $clientsOU
        }
        else {
            Write-Host "Skipping Group Policy update. Remember to run 'gpupdate /force' on each computer or wait for the normal update cycle." -ForegroundColor Yellow
        }
        
        # Completion message
        Write-Host "`n==================================================" -ForegroundColor Green
        Write-Host "  LLMNR and mDNS Disabling Process Completed!" -ForegroundColor Green
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "`nSummary of actions:" -ForegroundColor Cyan
        Write-Host "- Created GPOs to disable LLMNR and mDNS for Domain Controllers" -ForegroundColor Cyan
        Write-Host "- Created GPOs to disable LLMNR and mDNS for Client computers" -ForegroundColor Cyan
        Write-Host "- Linked GPOs to respective Organizational Units" -ForegroundColor Cyan
        
        if ($forceUpdate -eq "Y" -or $forceUpdate -eq "y") {
            Write-Host "- Attempted to force Group Policy update on all computers" -ForegroundColor Cyan
        }
        
        Write-Host "`nVerification steps:" -ForegroundColor Yellow
        Write-Host "1. Verify GPO settings using Group Policy Management Console" -ForegroundColor Yellow
        Write-Host "2. Run 'gpresult /h C:\GPReport.html' on a target computer to verify applied policies" -ForegroundColor Yellow
        Write-Host "3. Check registry settings on target computers to confirm changes were applied:" -ForegroundColor Yellow
        Write-Host "   - HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast should be 0" -ForegroundColor Yellow
        Write-Host "   - HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS should be 0" -ForegroundColor Yellow
    }
}

# Execute the script
Start-Execution