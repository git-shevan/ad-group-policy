# Changelog

## Feature Branch Updates - March 30, 2025

### Fixed
- Improved the mDNS disabling function in the PowerShell script to properly distinguish between the two registry settings
- Added clearer variable names to avoid confusion between registry paths
- Updated comments in the New-MDNSDisabledGPO function to better explain the purpose of each registry setting
- Fixed the script filename in the .NOTES section to match the actual file name (disable_LLMNR_mDNS.ps1)

### Added
- More detailed comments in the script to improve maintainability

## Initial Version - March 30, 2025

### Added
- Initial PowerShell script to disable LLMNR and mDNS via Group Policy
- HTML documentation with step-by-step installation guide
- Repository README with overview of features and usage instructions