<#
TODO:
   - Automatic mapping updates from online sources
   - Email or Slack notifications for critical updates
   - Schedule script frequency beyond logon (daily/weekly)
#>

<#
.SYNOPSIS
    CVE-aware software auto-updater for Windows using Winget and Chocolatey

.DESCRIPTION
    This script automates the process of keeping installed software up to date
    with a focus on security vulnerabilities. On first run, it upgrades all
    installed packages and generates a baseline software list. It then installs
    itself to a specified directory and creates a Task Scheduler task to run at
    each user logon.

    On each execution, the script fetches the latest known vulnerabilities from
    CISA's KEV feed and the NVD database, compares them against the installed
    software, and automatically applies available updates via Winget or
    Chocolatey. Detailed logging is maintained for both software updates and
    vulnerability checks.
#>

# --- CONFIG ---
$InstallDir = "C:\ProgramData\WingetPatchManager"
$ScriptName = "WingetPatchManager.ps1"
$TaskName = "WingetPatchManager"
$SoftwareListFile = Join-Path $InstallDir "InstalledSoftware.csv"
$LogFile = Join-Path $InstallDir "update_log.txt"
$CVELogFile = Join-Path $InstallDir "cve_fetch_log.txt"
$PackageStatusLog = Join-Path $InstallDir "package_update_status.csv"

# CVE feed URLs
$CisaKEVFeed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
$NvdFeed = "https://services.nvd.nist.gov/rest/json/cves/1.1"  # can be customized for recent CVEs

# --- FUNCTIONS ---
# Most functions require PowerShell 7, so install PowerShell 7
function Ensure-PowerShell7 {
    $pwshPath = "$Env:ProgramFiles\PowerShell\7\pwsh.exe"

    if (-not (Test-Path $pwshPath)) {
        Write-Log "PowerShell 7 not found, downloading and installing..."
        $InstallerUrl = "https://github.com/PowerShell/PowerShell/releases/latest/download/PowerShell-7.4.5-win-x64.msi"
        $TempInstaller = Join-Path $env:TEMP "PowerShell7.msi"
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $TempInstaller
        Start-Process msiexec.exe -ArgumentList "/i `"$TempInstaller`" /quiet /norestart" -Wait
        Write-Log "PowerShell 7 installation complete."

        # Relaunch under PowerShell 7 after install
        if (Test-Path $pwshPath) {
            Write-Log "Relaunching script under PowerShell 7..."
            Start-Process -FilePath $pwshPath -ArgumentList "-ExecutionPolicy Bypass -File `"$InstallDir\$ScriptName`"" -Verb RunAs
            Exit
        } else {
            Write-Log "PowerShell 7 installation failed verification — continuing under legacy PowerShell."
        }
    } else {
        Write-Log "PowerShell 7 already installed at $pwshPath"
    }
}

function Write-Log {
    param($Message)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp - $Message" | Out-File -FilePath $LogFile -Append
}

function Write-CVELog {
    param($Message)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp - $Message" | Out-File -FilePath $CVELogFile -Append
}

function Log-PackageStatus {
    param($Package, $Manager, $Status)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$TimeStamp,$Package,$Manager,$Status" | Out-File -FilePath $PackageStatusLog -Append
}

function Ensure-Elevation {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
        Write-Log "Script is not running as Administrator. Exiting..."
        Write-Host "ERROR: This script must be run with administrative privileges."
        Exit 1
    } else {
        Write-Log "Script running with administrative privileges."
    }
}

function Ensure-Install {
    if (!(Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Write-Log "Created install directory at $InstallDir"
    }

    $CurrentScript = $MyInvocation.MyCommand.Path
    $DestScript = Join-Path $InstallDir $ScriptName

    if ($CurrentScript -ne $DestScript) {
        Copy-Item $CurrentScript -Destination $DestScript -Force
        Write-Log "Copied script to $DestScript"
    }
}

function Create-TaskScheduler {
    $pwshPath = "$Env:ProgramFiles\PowerShell\7\pwsh.exe"
    $TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    # Define task details
    $Action = if (Test-Path $pwshPath) {
        Write-Log "Using PowerShell 7 for scheduled task."
        New-ScheduledTaskAction -Execute $pwshPath -Argument "-ExecutionPolicy Bypass -File `"$InstallDir\$ScriptName`""
    } else {
        Write-Log "PowerShell 7 not found yet, using legacy PowerShell temporarily."
        New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$InstallDir\$ScriptName`""
    }

    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

    # If the task exists, check if it needs to be updated
    if ($TaskExists) {
        $OldAction = $TaskExists.Actions | Select-Object -First 1
        if ($OldAction.Execute -ne $pwshPath -and (Test-Path $pwshPath)) {
            Write-Log "Updating scheduled task to use PowerShell 7..."
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
            Write-Log "Scheduled task updated to PowerShell 7."
        } else {
            Write-Log "Scheduled task already up to date."
        }
    } else {
        Write-Log "Creating new scheduled task: $TaskName"
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
        Write-Log "Scheduled task created successfully."
    }
}

function FirstTimeSetup {
    if (!(Test-Path $SoftwareListFile)) {
        Write-Log "First run detected. Performing initial upgrades..."

        # Winget upgrade
        winget upgrade --all --accept-source-agreements --accept-package-agreements
        Write-Log "Winget initial upgrade completed."

        # Chocolatey upgrade if installed
        if (Detect-Chocolatey) {
            choco upgrade all -y
            Write-Log "Chocolatey initial upgrade completed."
        }

        # Export combined software list
        $InstalledSoftware = Get-InstalledSoftware
        $InstalledSoftware | Select-Object Id, Name, Version | Export-Csv -Path $SoftwareListFile -NoTypeInformation
        Write-Log "Baseline software list saved to $SoftwareListFile"
    }
}


function Get-LatestCVEs {
    Write-CVELog "Fetching latest CVEs from CISA KEV..."
    try {
        $CveData = Invoke-RestMethod -Uri $CisaKEVFeed -UseBasicParsing
        Write-CVELog "Fetched $($CveData.value.Count) CVEs from CISA KEV."
        return $CveData.value
    } catch {
        Write-CVELog "Failed to fetch CVEs: $_"
        return @()
    }
}

function Update-Software {
    param(
        [array]$Packages,
        [array]$InstalledSoftware,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySec = 5
    )

    # Create a lookup table for faster access
    $SoftwareMap = $InstalledSoftware | Group-Object -Property Id -AsHashTable

    foreach ($pkgId in $Packages) {
        $success = $false
        $attempt = 0
        
        # Find the package object from the master list
        $pkgObject = $SoftwareMap[$pkgId]
        
        if (-not $pkgObject) {
            Write-Log "Package ID $pkgId not found in installed software list. Skipping."
            continue
        }

        # Get the manager from the object
        $manager = $pkgObject.Manager

        while (-not $success -and $attempt -lt $MaxRetries) {
            $attempt++
            try {
                if ($manager -eq "Winget") {
                    Write-Log "[$attempt/$MaxRetries] Updating $pkgId via Winget..."
                    winget upgrade --id $pkgId --accept-source-agreements --accept-package-agreements
                    $success = $true
                } elseif ($manager -eq "Chocolatey") {
                    Write-Log "[$attempt/$MaxRetries] Updating $pkgId via Chocolatey..."
                    choco upgrade $pkgId -y
                    $success = $true
                } else {
                    Write-Log "Package $pkgId has unknown manager '$manager', skipping."
                    $success = $true # consider as success so it won't retry
                }
            } catch {
                Write-Log "Update attempt $attempt failed for $pkgId: $_"
                Start-Sleep -Seconds $RetryDelaySec
            }

            # Log attempt to CSV
            $status = if ($success) { "Success" } else { "Failed" }
            Log-PackageStatus -Package $pkgId -Manager $manager -Status "$status (Attempt $attempt)"
        }

        if (-not $success) {
            Write-Log "Update ultimately failed after $MaxRetries attempts: $pkgId"
        } else {
            Write-Log "Update completed: $pkgId ($manager)"
        }
    }
}


function Detect-Chocolatey {
    $ChocoInstalled = Get-Command choco -ErrorAction SilentlyContinue
    if ($ChocoInstalled) { 
        Write-Log "Chocolatey detected." 
        return $true
    } else { 
        Write-Log "Chocolatey not found, skipping." 
        return $false
    }
}

function Get-InstalledSoftware {
    $ChocoInstalled = Detect-Chocolatey

    # Winget
    $WingetSoftware = winget list --source winget | Select-Object Id, Name, Version | ForEach-Object {
        $_ | Add-Member -NotePropertyName Manager -NotePropertyValue 'Winget' -PassThru
    }

    # Chocolatey
    if ($ChocoInstalled) {
        $ChocoSoftware = choco list --local-only --no-color | ForEach-Object {
            $parts = $_ -split '\s'
            [PSCustomObject]@{ 
                Name    = $parts[0]
                Version = $parts[1]
                Id      = $parts[0] # Choco ID is the name
                Manager = 'Chocolatey' 
            }
        }
    } else {
        $ChocoSoftware = @()
    }

    # Merge lists
    return $WingetSoftware + $ChocoSoftware
}

function Ensure-PackageMapping {
    $MappingFile = Join-Path $InstallDir "PackageMapping.json"

    # Get installed software
    $InstalledSoftware = Get-InstalledSoftware

    # Load existing mapping if available
    $ExistingMapping = @{}
    if (Test-Path $MappingFile) {
        $ExistingMapping = (Get-Content $MappingFile | ConvertFrom-Json) | ForEach-Object { 
            @{ $_.Name = $_ } 
        } | ForEach-Object { $_.Keys | ForEach-Object { $_, $_ } } | ConvertFrom-Hashtable
    }

    $NewMapping = @{}

    foreach ($pkg in $InstalledSoftware) {
        $NewMapping[$pkg.Name] = [PSCustomObject]@{
            Name     = $pkg.Name
            WingetId = if ($pkg.Id) { $pkg.Id } else { "" }
            ChocoId  = if ($pkg.Name) { $pkg.Name } else { "" }
        }
    }

    # Save mapping
    $NewMapping.Values | ConvertTo-Json -Depth 3 | Out-File -FilePath $MappingFile -Encoding UTF8
    Write-Log "Package mapping updated: $MappingFile (removed stale entries)"
}

function Map-CVEsToInstalled {
    param($CVEs, $InstalledSoftware)

    $MappingFile = Join-Path $InstallDir "PackageMapping.json"
    if (-not (Test-Path $MappingFile)) {
        Write-Log "PackageMapping.json not found, skipping CVE mapping."
        return @()
    }

    # Load mapping as hashtable for O(1) lookups
    $Mapping = @{}
    (Get-Content $MappingFile | ConvertFrom-Json) | ForEach-Object { 
        $Mapping[$_.Name] = $_
    }

    # Build hashtable of installed software names for quick lookup
    $InstalledHash = @{}
    foreach ($pkg in $InstalledSoftware) {
        $InstalledHash[$pkg.Name] = $true
    }

    $UpdatesNeeded = @()

    foreach ($cve in $CVEs) {
        # Only iterate installed software
        foreach ($pkgName in $InstalledHash.Keys) {
            if ($Mapping.ContainsKey($pkgName)) {
                $entry = $Mapping[$pkgName]
                if ($entry.WingetId) { $UpdatesNeeded += $entry.WingetId }
                elseif ($entry.ChocoId) { $UpdatesNeeded += $entry.ChocoId }
            }
        }
    }

    return $UpdatesNeeded | Sort-Object -Unique
}

function Get-NVDCVEs {
    param(
        [Parameter(Mandatory=$true)]
        [array]$InstalledSoftware
    )

    Write-CVELog "Querying NVD for CVEs related to installed software..."
    
    # This list will hold the IDs of packages that have CVEs
    $PackagesToUpdate = [System.Collections.Generic.List[string]]::new()

    # Get date 30 days ago
    $StartDate = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $EndDate   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")


    foreach ($pkg in $InstalledSoftware) {
        # Skip packages that don't have a name to query
        if (-not $pkg.Name) { continue }

        $Query = [uri]::EscapeDataString($pkg.Name)
        $NvdUrl = "$NvdFeed?keyword=$Query&pubStartDate=$StartDate&pubEndDate=$EndDate"

        try {
            $NvdData = Invoke-RestMethod -Uri $NvdUrl -UseBasicParsing
            
            if ($NvdData.result.CVE_Items.Count -gt 0) {
                # SUCCESS: We found CVEs for this package.
                Write-Log "Found $($NvdData.result.CVE_Items.Count) recent CVE(s) for $($pkg.Name). Adding to update queue."
                
                # Add the package ID (e.g., "Google.Chrome") to the update list
                $PackagesToUpdate.Add($pkg.Id)
            }
        } catch {
            Write-Log "Failed to fetch NVD CVEs for $($pkg.Name): $_"
        }

        # Sleep 0.6s to respect NVD API rate limit (~1 request per 600ms)
        Start-Sleep -Milliseconds 600
    }

    $UniquePackages = $PackagesToUpdate | Sort-Object -Unique
    Write-CVELog "NVD query complete. Found $($UniquePackages.Count) packages with recent CVEs."
    return $UniquePackages
}

# --- MAIN ---
Ensure-Elevation
Ensure-PowerShell7
Ensure-Install
Create-TaskScheduler
FirstTimeSetup

# Get current installed software (Winget + Chocolatey)
$InstalledSoftware = Get-InstalledSoftware

# Update package mapping for current installed software
Ensure-PackageMapping

# --- CVE-Aware Update Logic ---

# 1. Fetch CISA KEV feed (for logging purposes)
# NOTE: This list is logged but NOT used to find packages,
# as we don't have a reliable way to map CISA products to package IDs.
$KEVCVEs = Get-LatestCVEs | ForEach-Object { $_.cveID }
Write-CVELog "Fetched $($KEVCVEs.Count) CVEs from CISA KEV feed."

# 2. Fetch NVD CVEs AND build the update list
# This function now returns a list of package IDs that have recent CVEs
$PackagesToUpdate = Get-NVDCVEs -InstalledSoftware $InstalledSoftware

# Initialize per-package status CSV log
if (!(Test-Path $PackageStatusLog)) {
    "Timestamp,Package,Manager,Status" | Out-File -FilePath $PackageStatusLog
}

# 3. Update only affected packages
if ($PackagesToUpdate.Count -gt 0) {
    Write-Log "Updating $($PackagesToUpdate.Count) packages found with recent CVEs via NVD..."
    
    # We pass $InstalledSoftware so the Update function can figure out
    # if a package is Winget or Chocolatey. (This requires the 
    # other minor fix I mentioned previously to work perfectly)
    Update-Software -Packages $PackagesToUpdate -InstalledSoftware $InstalledSoftware -MaxRetries 3 -RetryDelaySec 5
    
    Write-Log "Package updates completed."
} else {
    Write-Log "No updates needed. NVD scan found no installed packages with recent CVEs."
}


