<#
.SYNOPSIS
    FLEDGE - Forensic Live Evidence Data Gathering Engine

.DESCRIPTION
    PowerShell-based live-response forensic collector for Windows systems.

    FLEDGE - a structured acquisition of volatile and system-level artifacts from a live Windows environment.

    Collection is PASSIVE by default.

    Optional active network discovery may be enabled with:
        .\FLEDGE.ps1 -NetworkSweep

    Optional running-executable hashing/signature collection:
        .\FLEDGE.ps1 -HashRunningExecutables

    Optional clipboard collection (explicit authorization recommended):
        .\FLEDGE.ps1 -CollectClipboard

    Optional wireless BSSID discovery (may trigger/refresh a Wi-Fi scan):
        .\FLEDGE.ps1 -WirelessScan

    Optional Sysinternals EULA acceptance (may write EULA registry state):
        .\FLEDGE.ps1 -AcceptPsToolsEula

.PARAMETER NetworkSweep
    Performs active ICMP discovery on the primary IPv4 /24 and records post-sweep neighbor state.

.PARAMETER HashRunningExecutables
    Computes SHA-256 hashes and Authenticode signer information for unique running executable paths.

.PARAMETER CollectClipboard
    Captures current text clipboard content. Disabled by default because clipboard data may be sensitive and transient.

.PARAMETER WirelessScan
    Explicitly requests nearby Wi-Fi BSSID discovery. Disabled by default because requesting visible networks may trigger or refresh wireless scanning and therefore should not be treated as purely passive collection.

.PARAMETER AcceptPsToolsEula
    Allows bundled Sysinternals PsTools collectors to use -accepteula when the EULA has not already been accepted for the current user. This may write Sysinternals EULA acceptance registry values to the examined system. Disabled by default.

.PARAMETER OutputPath
    Optional parent directory for the FLEDGE_Nest_<timestamp> collection folder.
    For forensic work, prefer authorized external/removable evidence storage to reduce writes to the examined system.

.EXAMPLE
    .\FLEDGE.ps1
    Performs the default passive live-response collection.

.EXAMPLE
    .\FLEDGE.ps1 -HashRunningExecutables
    Performs passive collection plus SHA-256/signature triage of running executables.

.EXAMPLE
    .\FLEDGE.ps1 -NetworkSweep -HashRunningExecutables
    Performs passive collection, running executable triage, and explicitly requested active /24 discovery.

.EXAMPLE
    .\FLEDGE.ps1 -OutputPath E:\Evidence
    Writes the timestamped FLEDGE collection beneath E:\Evidence instead of beside the script.

.EXAMPLE
    .\FLEDGE.ps1 -WirelessScan
    Performs the standard collection plus explicitly requested nearby Wi-Fi BSSID discovery.

.EXAMPLE
    .\FLEDGE.ps1 -AcceptPsToolsEula
    Allows optional PsTools collectors to accept their EULA when necessary. This may write Sysinternals EULA registry state.

.NOTES
    Run with administrative privileges when authorized.

    Active network discovery modifies network state by generating ICMP traffic and populating the local neighbor/ARP cache.

    Wireless BSSID discovery may trigger or refresh a Wi-Fi scan and is therefore disabled unless -WirelessScan is explicitly supplied.

    Sysinternals PsTools dependencies are optional redundancy collectors. If absent, FLEDGE records them as skipped and continues with native/CIM sources. FLEDGE will not use -accepteula unless -AcceptPsToolsEula is explicitly supplied.

    When practical, write output to authorized external evidence media by using -OutputPath. Writing collection output to the examined system necessarily changes its state.

    Verify hashes after acquisition and after any subsequent copying.

.VERSION
    1.2.3
#>

[CmdletBinding()]
param (
    [switch]$NetworkSweep,

    [switch]$HashRunningExecutables,

    [switch]$CollectClipboard,

    [switch]$WirelessScan,

    [switch]$AcceptPsToolsEula,

    [string]$OutputPath
)

# ============================================================================
# FLEDGE CONFIGURATION
# ============================================================================

$FledgeName    = "FLEDGE"
$FledgeVersion = "1.2.3"

$CollectionStart = Get-Date
$timestamp       = $CollectionStart.ToString("yyyyMMdd_HHmmss")

try {
    $CollectionRoot = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $PSScriptRoot
    }
    else {
        [System.IO.Path]::GetFullPath($OutputPath)
    }

    if (-not (Test-Path $CollectionRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $CollectionRoot -Force -ErrorAction Stop | Out-Null
    }
}
catch {
    throw "Unable to initialize collection root '$OutputPath': $($_.Exception.Message)"
}

$outputDir       = Join-Path $CollectionRoot "FLEDGE_Nest_$timestamp"
$DependenciesDir = Join-Path $PSScriptRoot "Dependencies"

$SystemDriveRoot = if ($env:SystemRoot) {
    [System.IO.Path]::GetPathRoot($env:SystemRoot)
}
else {
    $null
}

$OutputDriveRoot = [System.IO.Path]::GetPathRoot($outputDir)
$OutputOnSystemDrive = (
    $SystemDriveRoot -and
    $OutputDriveRoot -and
    ($SystemDriveRoot.TrimEnd('\') -ieq $OutputDriveRoot.TrimEnd('\'))
)


$ExplicitActiveOptions = [System.Collections.Generic.List[string]]::new()
if ($NetworkSweep) { $ExplicitActiveOptions.Add("ICMP /24 network discovery") }
if ($WirelessScan) { $ExplicitActiveOptions.Add("Wi-Fi BSSID discovery") }
if ($AcceptPsToolsEula) { $ExplicitActiveOptions.Add("PsTools EULA acceptance") }

$CollectionModeDescription = if ($ExplicitActiveOptions.Count -gt 0) {
    "LIVE RESPONSE WITH EXPLICIT ACTIVE OPTIONS"
}
else {
    "PASSIVE LIVE RESPONSE"
}

# Output directories
$SystemDir      = Join-Path $outputDir "System"
$ProcessDir     = Join-Path $outputDir "Processes"
$NetworkDir     = Join-Path $outputDir "Network"
$UserDir        = Join-Path $outputDir "Users"
$ServicesDir    = Join-Path $outputDir "Services"
$PersistenceDir = Join-Path $outputDir "Persistence"
$WiFiDir        = Join-Path $outputDir "WiFi"
$HashesDir      = Join-Path $outputDir "Hashes"
$LogsDir        = Join-Path $outputDir "Logs"
$SecurityDir    = Join-Path $outputDir "Security"
$ReportDir      = Join-Path $outputDir "Report"

$Directories = @(
    $outputDir,
    $SystemDir,
    $ProcessDir,
    $NetworkDir,
    $UserDir,
    $ServicesDir,
    $PersistenceDir,
    $WiFiDir,
    $HashesDir,
    $LogsDir,
    $SecurityDir,
    $ReportDir
)

try {
    foreach ($directory in $Directories) {
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
    }
}
catch {
    throw "Unable to initialize FLEDGE output directories beneath '$outputDir': $($_.Exception.Message)"
}

$LogFile = Join-Path $LogsDir "FLEDGE_collection_$timestamp.log"

# Machine-readable collector audit trail.
$CollectorResults = [System.Collections.Generic.List[object]]::new()
$EvidenceSealed = $false
$StartupScriptHash = $null
$StartupDependencyHashes = @{}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-FledgeLog {
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    if ($script:EvidenceSealed) {
        # Once evidence is sealed, never mutate files beneath the evidence root.
        Write-Host ("{0:o} [{1}] {2}" -f (Get-Date), $Level, $Message) -ForegroundColor DarkGray
        return
    }

    $logEntry = "{0:o} [{1}] {2}" -f (Get-Date), $Level, $Message

    Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8

    switch ($Level) {
        "WARN" {
            Write-Host $logEntry -ForegroundColor DarkYellow
        }

        "ERROR" {
            Write-Host $logEntry -ForegroundColor Red
        }

        default {
            Write-Host $logEntry -ForegroundColor Gray
        }
    }
}


function Invoke-FledgeCollector {
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock
    )

    $start = Get-Date
    $status = "Success"
    $errorType = $null
    $errorMessage = $null

    Write-FledgeLog "Starting collector: $Name"

    try {
        & $ScriptBlock
    }
    catch {
        $status = "Failed"
        $errorType = $_.Exception.GetType().FullName
        $errorMessage = $_.Exception.Message

        Write-FledgeLog (
            "Collector failed: {0} - {1}" -f $Name, $errorMessage
        ) "ERROR"
    }
    finally {
        $end = Get-Date
        $duration = ($end - $start).TotalSeconds

        if ($status -eq "Success") {
            Write-FledgeLog (
                "Completed collector: {0} ({1:N2} seconds)" -f $Name, $duration
            )
        }

        $script:CollectorResults.Add([PSCustomObject]@{
            Collector       = $Name
            StartUTC        = $start.ToUniversalTime().ToString("o")
            EndUTC          = $end.ToUniversalTime().ToString("o")
            DurationSeconds = [math]::Round($duration, 2)
            Status          = $status
            ErrorType       = $errorType
            ErrorMessage    = $errorMessage
        })
    }
}

function Add-FledgeSkippedCollector {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Reason,
        [switch]$Informational
    )

    $now = (Get-Date).ToUniversalTime().ToString("o")
    $level = if ($Informational) { "INFO" } else { "WARN" }
    Write-FledgeLog "Collector skipped: $Name - $Reason" $level

    $script:CollectorResults.Add([PSCustomObject]@{
        Collector       = $Name
        StartUTC        = $now
        EndUTC          = $now
        DurationSeconds = 0
        Status          = "Skipped"
        ErrorType       = $null
        ErrorMessage    = $Reason
    })
}

function Export-FledgeText {
    param (
        [Parameter(Mandatory)]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $InputObject |
        Format-List * |
        Out-String -Width 4096 |
        Set-Content -Path $Path -Encoding UTF8
}


function Resolve-FledgeNativeCommand {
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($command -and $command.Source) {
        return $command.Source
    }

    if ($env:SystemRoot) {
        # A 32-bit PowerShell host on 64-bit Windows is subject to System32
        # redirection. Sysnative exposes the native 64-bit system directory.
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            $sysnativeCandidate = Join-Path $env:SystemRoot "Sysnative\$Name"
            if (Test-Path $sysnativeCandidate -PathType Leaf) {
                return $sysnativeCandidate
            }
        }

        $candidate = Join-Path $env:SystemRoot "System32\$Name"
        if (Test-Path $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

function Get-FledgeCsvRecordCount {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path -PathType Leaf)) {
        return 0
    }

    try {
        return (Import-Csv -Path $Path -ErrorAction Stop | Measure-Object).Count
    }
    catch {
        return 0
    }
}

function Get-FledgeTextPreview {
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxCharacters = 1000000
    )

    $reader = $null
    try {
        # StreamReader detects UTF BOMs and avoids splitting a multibyte character
        # at the preview boundary. FLEDGE-generated text uses UTF-8.
        $reader = [System.IO.StreamReader]::new($Path, [System.Text.Encoding]::UTF8, $true)
        $buffer = New-Object char[] $MaxCharacters
        $read = $reader.ReadBlock($buffer, 0, $buffer.Length)
        return [System.String]::new($buffer, 0, $read)
    }
    finally {
        if ($reader) { $reader.Dispose() }
    }
}


function Format-FledgeByteSize {
    param (
        [Parameter(Mandatory)]
        [long]$Bytes
    )

    if ($Bytes -ge 1GB) { return ("{0:N2} GB" -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ("{0:N2} KB" -f ($Bytes / 1KB)) }
    return ("{0} B" -f $Bytes)
}


function Test-FledgePsToolsEulaAccepted {
    param (
        [Parameter(Mandatory)]
        [string]$ToolPath
    )

    $toolName = [System.IO.Path]::GetFileNameWithoutExtension($ToolPath)
    $keyPath = "HKCU:\Software\Sysinternals\$toolName"

    try {
        $value = (Get-ItemProperty -Path $keyPath -Name EulaAccepted -ErrorAction Stop).EulaAccepted
        return ($value -eq 1)
    }
    catch {
        return $false
    }
}

function Invoke-FledgePsTool {
    param (
        [Parameter(Mandatory)]
        [string]$ToolPath,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    if ($script:AcceptPsToolsEula) {
        & $ToolPath -accepteula 2>&1 |
            Set-Content -Path $Destination -Encoding UTF8
    }
    else {
        & $ToolPath 2>&1 |
            Set-Content -Path $Destination -Encoding UTF8
    }
}

# ============================================================================
# ELEVATED PERMISSIONS CHECK
# ============================================================================

try {
    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $CurrentPrincipal = [Security.Principal.WindowsPrincipal]$CurrentIdentity

    $IsAdmin = $CurrentPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}
catch {
    $IsAdmin = $false
}


# ============================================================================
# STARTUP INTEGRITY / EXECUTION PROVENANCE
# ============================================================================

if ($PSCommandPath -and (Test-Path $PSCommandPath -PathType Leaf)) {
    try {
        $StartupScriptHash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        $StartupScriptHash = "UNAVAILABLE: $($_.Exception.Message)"
    }
}

# ============================================================================
# STARTUP BANNER
# ============================================================================

Clear-Host

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host " FLEDGE - Forensic Live Evidence Data Gathering Engine" -ForegroundColor DarkCyan
Write-Host " Version: $FledgeVersion" -ForegroundColor DarkCyan
Write-Host " Compiled 2026 by PARAS N." -ForegroundColor DarkCyan
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host ""

Write-Host "Host:              $env:COMPUTERNAME"
Write-Host "Collection Start:  $($CollectionStart.ToString('o'))"

if ($IsAdmin) {
    Write-Host "Administrator:     YES" -ForegroundColor Green
}
else {
    Write-Host "Administrator:     NO" -ForegroundColor DarkYellow
}

if ($ExplicitActiveOptions.Count -gt 0) {
    Write-Host ""
    Write-Host "Collection Mode:   $CollectionModeDescription" -ForegroundColor DarkYellow
    foreach ($activeOption in $ExplicitActiveOptions) {
        Write-Host "  - $activeOption" -ForegroundColor DarkYellow
    }

    if ($NetworkSweep) {
        Write-Host "WARNING: ICMP discovery generates network traffic and may modify the local ARP/neighbor cache." -ForegroundColor DarkYellow
    }
    if ($WirelessScan) {
        Write-Host "WARNING: Wireless BSSID discovery may trigger or refresh Wi-Fi scanning." -ForegroundColor DarkYellow
    }
    if ($AcceptPsToolsEula) {
        Write-Host "WARNING: PsTools -accepteula may write Sysinternals EULA registry state." -ForegroundColor DarkYellow
    }
}
else {
    Write-Host "Collection Mode:   $CollectionModeDescription" -ForegroundColor Green
}

Write-Host ""
Write-Host "Collecting live evidence...DO NOT DISTURB" `
    -ForegroundColor DarkYellow

Write-Host "Individual access-denied messages may occur. Collection will continue." `
    -ForegroundColor DarkGray

Write-Host "Saving evidence to: $outputDir"

if ($OutputOnSystemDrive) {
    Write-Host "FORENSIC NOTE: Output is being written to the system drive." -ForegroundColor DarkYellow
    Write-Host "Use -OutputPath with authorized external evidence media when practical." -ForegroundColor DarkYellow
}

Write-Host ""

Write-FledgeLog "FLEDGE collection initialized."
Write-FledgeLog "Version: $FledgeVersion"
Write-FledgeLog "Output directory: $outputDir"
Write-FledgeLog "Collection root: $CollectionRoot"
Write-FledgeLog "Output on system drive: $OutputOnSystemDrive"
if ($OutputOnSystemDrive) {
    Write-FledgeLog "Forensic note: collection output is being written to the examined system drive; external evidence media is preferred when practical." "WARN"
}
Write-FledgeLog "Administrative privileges: $IsAdmin"
Write-FledgeLog "Network sweep requested: $NetworkSweep"
Write-FledgeLog "Running executable hashing requested: $HashRunningExecutables"
Write-FledgeLog "Clipboard collection requested: $CollectClipboard"
Write-FledgeLog "Wireless scan requested: $WirelessScan"
Write-FledgeLog "PsTools EULA acceptance permitted: $AcceptPsToolsEula"
Write-FledgeLog "Collection mode: $CollectionModeDescription"
Write-FledgeLog "Startup script SHA256: $StartupScriptHash"


# ============================================================================
# DEPENDENCY VALIDATION
# ============================================================================

$Dependencies = @(
    "pslist.exe",
    "psservice.exe",
    "psfile.exe",
    "psloggedon.exe"
)

foreach ($dependency in $Dependencies) {

    $dependencyPath = Join-Path $DependenciesDir $dependency

    if (Test-Path $dependencyPath) {
        Write-FledgeLog "Dependency located: $dependency"
        try {
            $script:StartupDependencyHashes[$dependency] = (Get-FileHash -Path $dependencyPath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        catch {
            $script:StartupDependencyHashes[$dependency] = "UNAVAILABLE: $($_.Exception.Message)"
        }
    }
    else {
        Write-FledgeLog "Optional dependency not present: $dependencyPath"
    }
}


# ============================================================================
# 1. COLLECTION METADATA / TIME
# ============================================================================

Invoke-FledgeCollector "Collection Metadata" {

    $metadataPath = Join-Path $SystemDir "collection_metadata_$timestamp.txt"

    $metadata = [ordered]@{
        Tool                 = $FledgeName
        Version              = $FledgeVersion
        CollectionStartLocal = $CollectionStart.ToString("o")
        CollectionStartUTC   = $CollectionStart.ToUniversalTime().ToString("o")
        ComputerName         = $env:COMPUTERNAME
        Domain               = $env:USERDOMAIN
        CurrentUser          = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Administrator        = $IsAdmin
        PowerShellVersion    = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition    = $PSVersionTable.PSEdition
        ScriptPath           = $PSCommandPath
        CollectionRoot       = $CollectionRoot
        OutputDirectory      = $outputDir
        OutputOnSystemDrive  = [bool]$OutputOnSystemDrive
        NetworkSweepEnabled  = [bool]$NetworkSweep
        HashRunningExecutables = [bool]$HashRunningExecutables
        CollectClipboard       = [bool]$CollectClipboard
        WirelessScanEnabled    = [bool]$WirelessScan
        AcceptPsToolsEula      = [bool]$AcceptPsToolsEula
        CollectionMode         = $CollectionModeDescription
        ProcessId              = $PID
        ParentProcessId        = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue).ParentProcessId
        PowerShellHost         = $Host.Name
        PowerShellExecutable   = (Get-Process -Id $PID -ErrorAction SilentlyContinue).Path
        LanguageMode           = $ExecutionContext.SessionState.LanguageMode
        ProcessArchitecture    = if ([Environment]::Is64BitProcess) { "64-bit" } else { "32-bit" }
        OSArchitecture         = if ([Environment]::Is64BitOperatingSystem) { "64-bit" } else { "32-bit" }
        CurrentDirectory       = (Get-Location).Path
        ScriptSHA256AtStart    = $StartupScriptHash
    }

    $currentProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue
    $metadata["CommandLine"] = $currentProcess.CommandLine
    $metadata["ExecutionPolicy"] = ((Get-ExecutionPolicy -List | ForEach-Object { "$($_.Scope)=$($_.ExecutionPolicy)" }) -join "; ")

    $metadata.GetEnumerator() |
        ForEach-Object {
            "{0}: {1}" -f $_.Key, $_.Value
        } |
        Set-Content -Path $metadataPath -Encoding UTF8
}

Invoke-FledgeCollector "System Time Information" {

    $timeFile = Join-Path $SystemDir "time_information_$timestamp.txt"
    $w32tmPath = Resolve-FledgeNativeCommand "w32tm.exe"

    $timeOutput = [System.Collections.Generic.List[string]]::new()
    $timeOutput.Add("FLEDGE Time Acquisition")
    $timeOutput.Add("=======================")
    $timeOutput.Add("")
    $timeOutput.Add("Local Time: $((Get-Date).ToString('o'))")
    $timeOutput.Add("UTC Time:   $((Get-Date).ToUniversalTime().ToString('o'))")
    $timeOutput.Add("")
    $timeOutput.Add("TIME ZONE")
    $timeOutput.Add("---------")
    $timeOutput.Add((Get-TimeZone | Format-List * | Out-String -Width 4096))
    $timeOutput.Add("")
    $timeOutput.Add("WINDOWS TIME STATUS")
    $timeOutput.Add("-------------------")

    if ($w32tmPath) {
        $timeOutput.Add((& $w32tmPath /query /status 2>&1 | Out-String -Width 4096))
        $timeOutput.Add("")
        $timeOutput.Add("WINDOWS TIME CONFIGURATION")
        $timeOutput.Add("--------------------------")
        $timeOutput.Add((& $w32tmPath /query /configuration 2>&1 | Out-String -Width 4096))
    }
    else {
        $timeOutput.Add("w32tm.exe is unavailable on this Windows installation.")
    }

    $timeOutput | Set-Content -Path $timeFile -Encoding UTF8
}

# ============================================================================
# 2. LOGGED-ON USERS / ACTIVE SESSIONS
# ============================================================================

$tool = Join-Path $DependenciesDir "psloggedon.exe"
if (Test-Path $tool -PathType Leaf) {
    $eulaReady = $AcceptPsToolsEula -or (Test-FledgePsToolsEulaAccepted -ToolPath $tool)
    if ($eulaReady) {
        Invoke-FledgeCollector "Logged-On Users - PsLoggedOn" {
            Invoke-FledgePsTool -ToolPath $tool -Destination (Join-Path $UserDir "psloggedon_$timestamp.txt")
        }
    }
    else {
        Add-FledgeSkippedCollector -Name "Logged-On Users - PsLoggedOn" -Reason "PsLoggedOn is present, but its EULA is not already accepted. Skipped to avoid writing EULA registry state; use -AcceptPsToolsEula only when authorized." -Informational
    }
}
else {
    Add-FledgeSkippedCollector -Name "Logged-On Users - PsLoggedOn" -Reason "Optional dependency psloggedon.exe is not present; native/CIM session collection will continue." -Informational
}

Invoke-FledgeCollector "Interactive User Sessions" {

    $sessionNotes = [System.Collections.Generic.List[string]]::new()
    $nativeSessionCaptured = $false
    $cimSessionCaptured = $false

    $quserPath = Resolve-FledgeNativeCommand "quser.exe"
    $queryPath = Resolve-FledgeNativeCommand "query.exe"
    $qwinstaPath = Resolve-FledgeNativeCommand "qwinsta.exe"

    if ($quserPath) {
        try {
            & $quserPath 2>&1 |
                Set-Content -Path (Join-Path $UserDir "quser_$timestamp.txt") -Encoding UTF8
            $nativeSessionCaptured = $true
            $sessionNotes.Add("quser.exe: captured")
        }
        catch {
            $sessionNotes.Add("quser.exe: failed - $($_.Exception.Message)")
        }
    }
    elseif ($queryPath) {
        try {
            & $queryPath user 2>&1 |
                Set-Content -Path (Join-Path $UserDir "query_user_$timestamp.txt") -Encoding UTF8
            $nativeSessionCaptured = $true
            $sessionNotes.Add("query.exe user: captured (quser.exe unavailable)")
        }
        catch {
            $sessionNotes.Add("query.exe user: failed - $($_.Exception.Message)")
        }
    }
    else {
        $sessionNotes.Add("quser.exe/query.exe user: unavailable")
    }

    if ($qwinstaPath) {
        try {
            & $qwinstaPath 2>&1 |
                Set-Content -Path (Join-Path $UserDir "qwinsta_$timestamp.txt") -Encoding UTF8
            $nativeSessionCaptured = $true
            $sessionNotes.Add("qwinsta.exe: captured")
        }
        catch {
            $sessionNotes.Add("qwinsta.exe: failed - $($_.Exception.Message)")
        }
    }
    elseif ($queryPath) {
        try {
            & $queryPath session 2>&1 |
                Set-Content -Path (Join-Path $UserDir "query_session_$timestamp.txt") -Encoding UTF8
            $nativeSessionCaptured = $true
            $sessionNotes.Add("query.exe session: captured (qwinsta.exe unavailable)")
        }
        catch {
            $sessionNotes.Add("query.exe session: failed - $($_.Exception.Message)")
        }
    }
    else {
        $sessionNotes.Add("qwinsta.exe/query.exe session: unavailable")
    }

    # Always collect CIM-backed session context so useful session evidence is
    # available even when Remote Desktop Services command-line tools are absent.
    try {
        Get-CimInstance Win32_ComputerSystem -ErrorAction Stop |
            Select-Object Name, Domain, UserName, PartOfDomain |
            Export-Csv -Path (Join-Path $UserDir "interactive_user_context_$timestamp.csv") -NoTypeInformation -Encoding UTF8

        Get-CimInstance Win32_LogonSession -ErrorAction Stop |
            Select-Object LogonId, LogonType, StartTime, AuthenticationPackage, Caption, Description |
            Export-Csv -Path (Join-Path $UserDir "logon_sessions_$timestamp.csv") -NoTypeInformation -Encoding UTF8

        $loggedOnAssociations = Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    Domain  = $_.Antecedent.Domain
                    User    = $_.Antecedent.Name
                    LogonId = $_.Dependent.LogonId
                }
            }

        $loggedOnAssociations |
            Export-Csv -Path (Join-Path $UserDir "loggedon_user_associations_$timestamp.csv") -NoTypeInformation -Encoding UTF8

        $cimSessionCaptured = $true
        $sessionNotes.Add("CIM session context: captured")
    }
    catch {
        $sessionNotes.Add("CIM session context: failed - $($_.Exception.Message)")
    }

    $sessionNotes |
        Set-Content -Path (Join-Path $UserDir "session_collection_notes_$timestamp.txt") -Encoding UTF8

    if (-not $nativeSessionCaptured -and -not $cimSessionCaptured) {
        throw "No interactive-session source could be collected."
    }

    if (-not $nativeSessionCaptured -and $cimSessionCaptured) {
        Write-FledgeLog "Native session utilities were unavailable; CIM fallback session data was collected."
    }
}

# ============================================================================
# 3. RUNNING PROCESSES
# ============================================================================

Invoke-FledgeCollector "Process Details" {

    Get-CimInstance Win32_Process -ErrorAction Stop |
        Select-Object `
            ProcessId,
            ParentProcessId,
            Name,
            ExecutablePath,
            CommandLine,
            CreationDate,
            SessionId,
            HandleCount,
            ThreadCount |
        Export-Csv `
            -Path (Join-Path $ProcessDir "process_details_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}


$tasklistPath = Resolve-FledgeNativeCommand "tasklist.exe"
if ($tasklistPath) {
    Invoke-FledgeCollector "Tasklist" {
        & $tasklistPath /V 2>&1 |
            Set-Content -Path (Join-Path $ProcessDir "tasklist_$timestamp.txt") -Encoding UTF8
    }
}
else {
    Add-FledgeSkippedCollector -Name "Tasklist" -Reason "tasklist.exe is unavailable; CIM process collection remains available." -Informational
}

$tool = Join-Path $DependenciesDir "pslist.exe"
if (Test-Path $tool -PathType Leaf) {
    $eulaReady = $AcceptPsToolsEula -or (Test-FledgePsToolsEulaAccepted -ToolPath $tool)
    if ($eulaReady) {
        Invoke-FledgeCollector "PsList" {
            Invoke-FledgePsTool -ToolPath $tool -Destination (Join-Path $ProcessDir "pslist_$timestamp.txt")
        }
    }
    else {
        Add-FledgeSkippedCollector -Name "PsList" -Reason "PsList is present, but its EULA is not already accepted. Skipped to avoid writing EULA registry state; use -AcceptPsToolsEula only when authorized." -Informational
    }
}
else {
    Add-FledgeSkippedCollector -Name "PsList" -Reason "Optional dependency pslist.exe is not present; native/CIM process collection remains available." -Informational
}

# ============================================================================
# 4. TCP / UDP NETWORK CONNECTIONS
# ============================================================================

Invoke-FledgeCollector "TCP Connections" {

    Get-NetTCPConnection -ErrorAction Stop |
        Select-Object `
            LocalAddress,
            LocalPort,
            RemoteAddress,
            RemotePort,
            State,
            AppliedSetting,
            OwningProcess,
            CreationTime |
        Export-Csv `
            -Path (Join-Path $NetworkDir "tcp_connections_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

Invoke-FledgeCollector "Listening TCP Ports" {

    Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object `
            LocalAddress,
            LocalPort,
            State,
            OwningProcess,
            CreationTime |
        Export-Csv `
            -Path (Join-Path $NetworkDir "tcp_listeners_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

Invoke-FledgeCollector "UDP Endpoints" {

    Get-NetUDPEndpoint -ErrorAction Stop |
        Select-Object `
            LocalAddress,
            LocalPort,
            OwningProcess,
            CreationTime |
        Export-Csv `
            -Path (Join-Path $NetworkDir "udp_endpoints_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

# ============================================================================
# 5. NETWORK CONNECTION TO PROCESS MAPPING
# ============================================================================

Invoke-FledgeCollector "TCP Process Mapping" {

    $processLookup = @{}

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        ForEach-Object {
            $processLookup[[int]$_.ProcessId] = $_
        }

    Get-NetTCPConnection -ErrorAction Stop |
        ForEach-Object {

            $connection = $_
            $process = $processLookup[[int]$connection.OwningProcess]

            [PSCustomObject]@{
                PID           = $connection.OwningProcess
                ProcessName   = $process.Name
                Executable    = $process.ExecutablePath
                CommandLine   = $process.CommandLine
                LocalAddress  = $connection.LocalAddress
                LocalPort     = $connection.LocalPort
                RemoteAddress = $connection.RemoteAddress
                RemotePort    = $connection.RemotePort
                State         = $connection.State
                CreationTime  = $connection.CreationTime
            }
        } |
        Export-Csv `
            -Path (Join-Path $NetworkDir "tcp_process_mapping_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

Invoke-FledgeCollector "UDP Process Mapping" {

    $processLookup = @{}

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        ForEach-Object {
            $processLookup[[int]$_.ProcessId] = $_
        }

    Get-NetUDPEndpoint -ErrorAction Stop |
        ForEach-Object {

            $endpoint = $_
            $process = $processLookup[[int]$endpoint.OwningProcess]

            [PSCustomObject]@{
                PID          = $endpoint.OwningProcess
                ProcessName  = $process.Name
                Executable   = $process.ExecutablePath
                CommandLine  = $process.CommandLine
                LocalAddress = $endpoint.LocalAddress
                LocalPort    = $endpoint.LocalPort
                CreationTime = $endpoint.CreationTime
            }
        } |
        Export-Csv `
            -Path (Join-Path $NetworkDir "udp_process_mapping_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

# ============================================================================
# 6. DNS CACHE
# ============================================================================

Invoke-FledgeCollector "DNS Client Cache" {

    Get-DnsClientCache -ErrorAction Stop |
        Select-Object * |
        Export-Csv `
            -Path (Join-Path $NetworkDir "dns_cache_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

# ============================================================================
# 7. ARP / NEIGHBOR CACHE - BEFORE ANY ACTIVE NETWORK ACTIVITY
# ============================================================================

Invoke-FledgeCollector "Neighbor Cache - Pre Sweep" {

    Get-NetNeighbor -ErrorAction Stop |
        Select-Object `
            ifIndex,
            IPAddress,
            LinkLayerAddress,
            State,
            Store |
        Export-Csv `
            -Path (Join-Path $NetworkDir "neighbor_cache_pre_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

$arpPath = Resolve-FledgeNativeCommand "arp.exe"
if ($arpPath) {
    Invoke-FledgeCollector "ARP Table - Native" {
        & $arpPath -a 2>&1 |
            Set-Content -Path (Join-Path $NetworkDir "arp_native_pre_$timestamp.txt") -Encoding UTF8
    }
}
else {
    Add-FledgeSkippedCollector -Name "ARP Table - Native" -Reason "arp.exe is unavailable; Get-NetNeighbor output remains available." -Informational
}

# ============================================================================
# 8. NETWORK ROUTING
# ============================================================================

$DefaultRoute = $null
$Gateway = $null
$PrimaryInterfaceIndex = $null

Invoke-FledgeCollector "Routing Table" {

    Get-NetRoute -ErrorAction Stop |
        Sort-Object `
            AddressFamily,
            DestinationPrefix,
            RouteMetric |
        Export-Csv `
            -Path (Join-Path $NetworkDir "route_table_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8

    $routePath = Resolve-FledgeNativeCommand "route.exe"
    if ($routePath) {
        & $routePath print 2>&1 |
            Set-Content -Path (Join-Path $NetworkDir "route_print_$timestamp.txt") -Encoding UTF8
    }
    else {
        "route.exe unavailable; route_table CSV contains the PowerShell routing snapshot." |
            Set-Content -Path (Join-Path $NetworkDir "route_print_$timestamp.txt") -Encoding UTF8
    }
}

Invoke-FledgeCollector "Default Gateway" {

    $script:DefaultRoute = Get-NetRoute `
        -DestinationPrefix "0.0.0.0/0" `
        -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1

    if ($script:DefaultRoute) {

        $script:Gateway = $script:DefaultRoute.NextHop
        $script:PrimaryInterfaceIndex = $script:DefaultRoute.InterfaceIndex

        [PSCustomObject]@{
            Gateway        = $script:Gateway
            InterfaceIndex = $script:PrimaryInterfaceIndex
            RouteMetric    = $script:DefaultRoute.RouteMetric
            InterfaceMetric = $script:DefaultRoute.InterfaceMetric
        } |
        Export-Csv `
            -Path (Join-Path $NetworkDir "default_gateway_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
    }
}

# ============================================================================
# 9. NETWORK INTERFACE CONFIGURATION
# ============================================================================

Invoke-FledgeCollector "Network IP Configuration" {

    Get-NetIPConfiguration -ErrorAction Stop |
        Format-List * |
        Out-String -Width 4096 |
        Set-Content `
            (Join-Path $NetworkDir "net_ip_configuration_$timestamp.txt") `
            -Encoding UTF8
}

Invoke-FledgeCollector "Network Adapters" {

    Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Select-Object * |
        Export-Csv `
            -Path (Join-Path $NetworkDir "network_adapters_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

Invoke-FledgeCollector "IP Addresses" {

    Get-NetIPAddress -ErrorAction Stop |
        Select-Object * |
        Export-Csv `
            -Path (Join-Path $NetworkDir "ip_addresses_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

$ipconfigPath = Resolve-FledgeNativeCommand "ipconfig.exe"
if ($ipconfigPath) {
    Invoke-FledgeCollector "IPConfig All" {
        & $ipconfigPath /all 2>&1 |
            Set-Content -Path (Join-Path $NetworkDir "ipconfig_all_$timestamp.txt") -Encoding UTF8
    }
}
else {
    Add-FledgeSkippedCollector -Name "IPConfig All" -Reason "ipconfig.exe is unavailable; PowerShell network configuration collectors remain available." -Informational
}

# ============================================================================
# 10. OPEN FILES
# ============================================================================

$tool = Join-Path $DependenciesDir "psfile.exe"
if (Test-Path $tool -PathType Leaf) {
    $eulaReady = $AcceptPsToolsEula -or (Test-FledgePsToolsEulaAccepted -ToolPath $tool)
    if ($eulaReady) {
        Invoke-FledgeCollector "Open Files - PsFile" {
            Invoke-FledgePsTool -ToolPath $tool -Destination (Join-Path $SystemDir "open_files_$timestamp.txt")
        }
    }
    else {
        Add-FledgeSkippedCollector -Name "Open Files - PsFile" -Reason "PsFile is present, but its EULA is not already accepted. Skipped to avoid writing EULA registry state; use -AcceptPsToolsEula only when authorized." -Informational
    }
}
else {
    Add-FledgeSkippedCollector -Name "Open Files - PsFile" -Reason "Optional dependency psfile.exe is not present." -Informational
}

# ============================================================================
# 11. SERVICES
# ============================================================================

Invoke-FledgeCollector "Service Details" {

    Get-CimInstance Win32_Service -ErrorAction Stop |
        Select-Object `
            Name,
            DisplayName,
            State,
            StartMode,
            StartName,
            ProcessId,
            PathName,
            Description |
        Export-Csv `
            -Path (Join-Path $ServicesDir "services_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

$tool = Join-Path $DependenciesDir "psservice.exe"
if (Test-Path $tool -PathType Leaf) {
    $eulaReady = $AcceptPsToolsEula -or (Test-FledgePsToolsEulaAccepted -ToolPath $tool)
    if ($eulaReady) {
        Invoke-FledgeCollector "PsService" {
            Invoke-FledgePsTool -ToolPath $tool -Destination (Join-Path $ServicesDir "psservice_$timestamp.txt")
        }
    }
    else {
        Add-FledgeSkippedCollector -Name "PsService" -Reason "PsService is present, but its EULA is not already accepted. Skipped to avoid writing EULA registry state; use -AcceptPsToolsEula only when authorized." -Informational
    }
}
else {
    Add-FledgeSkippedCollector -Name "PsService" -Reason "Optional dependency psservice.exe is not present; native/CIM service collection remains available." -Informational
}

# ============================================================================
# 12. PERSISTENCE - SCHEDULED TASKS
# ============================================================================

Invoke-FledgeCollector "Scheduled Tasks" {

    Get-ScheduledTask -ErrorAction Stop |
        ForEach-Object {

            $task = $_

            [PSCustomObject]@{
                TaskName    = $task.TaskName
                TaskPath    = $task.TaskPath
                State       = $task.State
                Author      = $task.Author
                Description = $task.Description
                URI         = $task.URI
                Actions     = (
                    $task.Actions |
                    ForEach-Object {
                        "$($_.Execute) $($_.Arguments)"
                    }
                ) -join " | "
                Triggers    = (
                    $task.Triggers |
                    Out-String -Width 4096
                ).Trim()
                UserId      = $task.Principal.UserId
                RunLevel    = $task.Principal.RunLevel
            }
        } |
        Export-Csv `
            -Path (Join-Path $PersistenceDir "scheduled_tasks_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

# ============================================================================
# 13. COMMON RUN / RUNONCE PERSISTENCE LOCATIONS
# ============================================================================

Invoke-FledgeCollector "Registry Run Keys" {

    $RunKeyPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $results = foreach ($key in $RunKeyPaths) {

        if (Test-Path $key) {

            $values = Get-ItemProperty $key -ErrorAction SilentlyContinue

            foreach ($property in $values.PSObject.Properties) {

                if ($property.Name -notmatch "^PS") {

                    [PSCustomObject]@{
                        RegistryPath = $key
                        Name         = $property.Name
                        Value        = [string]$property.Value
                    }
                }
            }
        }
    }

    $results |
        Export-Csv `
            -Path (Join-Path $PersistenceDir "registry_run_keys_$timestamp.csv") `
            -NoTypeInformation `
            -Encoding UTF8
}

# ============================================================================
# 14. WI-FI INFORMATION
# ============================================================================

$netshPath = Resolve-FledgeNativeCommand "netsh.exe"
if ($netshPath) {
    Invoke-FledgeCollector "Wi-Fi Interface Information" {
        & $netshPath wlan show interfaces 2>&1 |
            Set-Content -Path (Join-Path $WiFiDir "wifi_interfaces_$timestamp.txt") -Encoding UTF8
    }

    if ($WirelessScan) {
        Invoke-FledgeCollector "Wi-Fi Networks - Active Scan" {
            & $netshPath wlan show networks mode=bssid 2>&1 |
                Set-Content -Path (Join-Path $WiFiDir "wifi_networks_$timestamp.txt") -Encoding UTF8
        }
    }
    else {
        Add-FledgeSkippedCollector -Name "Wi-Fi Networks - Active Scan" -Reason "Not requested. Use -WirelessScan when nearby BSSID discovery is authorized." -Informational
    }

    Invoke-FledgeCollector "Saved Wi-Fi Profiles" {
        & $netshPath wlan show profiles 2>&1 |
            Set-Content -Path (Join-Path $WiFiDir "wifi_profiles_$timestamp.txt") -Encoding UTF8
    }

    Invoke-FledgeCollector "Wi-Fi Drivers" {
        & $netshPath wlan show drivers 2>&1 |
            Set-Content -Path (Join-Path $WiFiDir "wifi_drivers_$timestamp.txt") -Encoding UTF8
    }
}
else {
    foreach ($collectorName in @("Wi-Fi Interface Information", "Wi-Fi Networks - Active Scan", "Saved Wi-Fi Profiles", "Wi-Fi Drivers")) {
        Add-FledgeSkippedCollector -Name $collectorName -Reason "netsh.exe is unavailable on this Windows installation." -Informational
    }
}

# ============================================================================
# 15. GENERAL SYSTEM INFORMATION
# ============================================================================

Invoke-FledgeCollector "Computer Information" {

    Get-ComputerInfo -ErrorAction Stop |
        Format-List * |
        Out-String -Width 4096 |
        Set-Content `
            (Join-Path $SystemDir "computer_info_$timestamp.txt") `
            -Encoding UTF8
}

$systemInfoPath = Resolve-FledgeNativeCommand "systeminfo.exe"
if ($systemInfoPath) {
    Invoke-FledgeCollector "SystemInfo Native" {
        & $systemInfoPath 2>&1 |
            Set-Content -Path (Join-Path $SystemDir "systeminfo_native_$timestamp.txt") -Encoding UTF8
    }
}
else {
    Add-FledgeSkippedCollector -Name "SystemInfo Native" -Reason "systeminfo.exe is unavailable; Get-ComputerInfo output remains available." -Informational
}

# ============================================================================
# 16. ENHANCED LIVE-RESPONSE / TRIAGE COLLECTION
# ============================================================================

Invoke-FledgeCollector "Process Owners and Signatures" {
    $processes = Get-CimInstance Win32_Process -ErrorAction Stop
    $lookup = @{}
    foreach ($proc in $processes) { $lookup[[int]$proc.ProcessId] = $proc }

    # Multiple processes commonly share the same executable. Cache signature and
    # version metadata once per path; this materially reduces collector runtime.
    $fileMetadataCache = @{}
    $ownerSidCache = @{}

    $rows = foreach ($proc in $processes) {
        $owner = $null
        $ownerSid = $null

        try {
            $ownerResult = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
            if ($ownerResult.ReturnValue -eq 0) {
                $owner = if ($ownerResult.Domain) { "$($ownerResult.Domain)\$($ownerResult.User)" } else { $ownerResult.User }
            }
        }
        catch {}

        if ($owner) {
            if ($ownerSidCache.ContainsKey($owner)) {
                $ownerSid = $ownerSidCache[$owner]
            }
            else {
                try {
                    $account = New-Object System.Security.Principal.NTAccount($owner)
                    $ownerSid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    try {
                        $sidResult = Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid -ErrorAction Stop
                        if ($sidResult.ReturnValue -eq 0) { $ownerSid = $sidResult.Sid }
                    }
                    catch {}
                }
                $ownerSidCache[$owner] = $ownerSid
            }
        }

        $parent = $lookup[[int]$proc.ParentProcessId]
        $grandparent = if ($parent) { $lookup[[int]$parent.ParentProcessId] } else { $null }

        $fileMeta = $null
        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath -PathType Leaf)) {
            $cacheKey = $proc.ExecutablePath.ToLowerInvariant()
            if ($fileMetadataCache.ContainsKey($cacheKey)) {
                $fileMeta = $fileMetadataCache[$cacheKey]
            }
            else {
                $signatureStatus = $null
                $signer = $null
                $company = $null
                $fileVersion = $null
                $productName = $null
                $fileDescription = $null
                $originalFileName = $null

                try {
                    $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction Stop
                    $signatureStatus = [string]$sig.Status
                    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
                }
                catch {}

                try {
                    $vi = (Get-Item $proc.ExecutablePath -ErrorAction Stop).VersionInfo
                    $company = $vi.CompanyName
                    $fileVersion = $vi.FileVersion
                    $productName = $vi.ProductName
                    $fileDescription = $vi.FileDescription
                    $originalFileName = $vi.OriginalFilename
                }
                catch {}

                $fileMeta = [PSCustomObject]@{
                    SignatureStatus = $signatureStatus
                    Signer = $signer
                    Company = $company
                    FileVersion = $fileVersion
                    ProductName = $productName
                    FileDescription = $fileDescription
                    OriginalFileName = $originalFileName
                }
                $fileMetadataCache[$cacheKey] = $fileMeta
            }
        }

        [PSCustomObject]@{
            PID              = $proc.ProcessId
            PPID             = $proc.ParentProcessId
            ProcessName      = $proc.Name
            Owner            = $owner
            OwnerSID         = $ownerSid
            ExecutablePath   = $proc.ExecutablePath
            CommandLine      = $proc.CommandLine
            CreationTimeUTC  = if ($proc.CreationDate) {
                if ($proc.CreationDate -is [datetime]) {
                    $proc.CreationDate.ToUniversalTime().ToString("o")
                }
                else {
                    ([Management.ManagementDateTimeConverter]::ToDateTime([string]$proc.CreationDate)).ToUniversalTime().ToString("o")
                }
            } else { $null }
            ParentProcess    = if ($parent) { $parent.Name } else { $null }
            GrandparentPID   = if ($parent) { $parent.ParentProcessId } else { $null }
            GrandparentName  = if ($grandparent) { $grandparent.Name } else { $null }
            SignatureStatus  = if ($fileMeta) { $fileMeta.SignatureStatus } else { $null }
            Signer           = if ($fileMeta) { $fileMeta.Signer } else { $null }
            Company          = if ($fileMeta) { $fileMeta.Company } else { $null }
            FileVersion      = if ($fileMeta) { $fileMeta.FileVersion } else { $null }
            ProductName      = if ($fileMeta) { $fileMeta.ProductName } else { $null }
            FileDescription  = if ($fileMeta) { $fileMeta.FileDescription } else { $null }
            OriginalFileName = if ($fileMeta) { $fileMeta.OriginalFileName } else { $null }
        }
    }

    $rows |
        Export-Csv -Path (Join-Path $ProcessDir "process_owners_tree_signatures_$timestamp.csv") -NoTypeInformation -Encoding UTF8
}

$dnsServerCmdlet = Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue
$dnsClientCmdlet = Get-Command Get-DnsClient -ErrorAction SilentlyContinue
if ($dnsServerCmdlet -or $dnsClientCmdlet) {
    Invoke-FledgeCollector "DNS Configuration" {
        if ($dnsServerCmdlet) {
            Get-DnsClientServerAddress -ErrorAction Stop |
                Select-Object InterfaceAlias, InterfaceIndex, AddressFamily,
                    @{Name="ServerAddresses";Expression={($_.ServerAddresses -join "; ")}} |
                Export-Csv -Path (Join-Path $NetworkDir "dns_server_addresses_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }

        if ($dnsClientCmdlet) {
            Get-DnsClient -ErrorAction Stop |
                Select-Object * |
                Export-Csv -Path (Join-Path $NetworkDir "dns_client_configuration_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
    }
}
else {
    Add-FledgeSkippedCollector -Name "DNS Configuration" -Reason "DNS client configuration cmdlets are unavailable." -Informational
}

$smbCommandNames = @("Get-SmbConnection", "Get-SmbMapping", "Get-SmbSession", "Get-SmbShare")
$smbAvailable = @{}
foreach ($commandName in $smbCommandNames) {
    $smbAvailable[$commandName] = [bool](Get-Command $commandName -ErrorAction SilentlyContinue)
}

if ($smbAvailable.Values -contains $true) {
    Invoke-FledgeCollector "SMB State" {
        if ($smbAvailable["Get-SmbConnection"]) {
            Get-SmbConnection -ErrorAction SilentlyContinue |
                Select-Object * |
                Export-Csv -Path (Join-Path $NetworkDir "smb_connections_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
        if ($smbAvailable["Get-SmbMapping"]) {
            Get-SmbMapping -ErrorAction SilentlyContinue |
                Select-Object * |
                Export-Csv -Path (Join-Path $NetworkDir "smb_mappings_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
        if ($smbAvailable["Get-SmbSession"]) {
            Get-SmbSession -ErrorAction SilentlyContinue |
                Select-Object * |
                Export-Csv -Path (Join-Path $NetworkDir "smb_sessions_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
        if ($smbAvailable["Get-SmbShare"]) {
            Get-SmbShare -ErrorAction SilentlyContinue |
                Select-Object * |
                Export-Csv -Path (Join-Path $NetworkDir "smb_shares_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
    }
}
else {
    Add-FledgeSkippedCollector -Name "SMB State" -Reason "SMB PowerShell cmdlets are unavailable on this installation." -Informational
}

Invoke-FledgeCollector "Proxy Configuration" {
    $proxyNetshPath = Resolve-FledgeNativeCommand "netsh.exe"
    if ($proxyNetshPath) {
        & $proxyNetshPath winhttp show proxy 2>&1 |
            Set-Content -Path (Join-Path $NetworkDir "winhttp_proxy_$timestamp.txt") -Encoding UTF8
    }
    else {
        "netsh.exe unavailable; registry proxy settings remain available below." |
            Set-Content -Path (Join-Path $NetworkDir "winhttp_proxy_$timestamp.txt") -Encoding UTF8
    }

    $proxyPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    )
    $proxyRows = foreach ($path in $proxyPaths) {
        if (Test-Path $path) {
            $v = Get-ItemProperty $path -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                RegistryPath = $path
                ProxyEnable  = $v.ProxyEnable
                ProxyServer  = $v.ProxyServer
                ProxyOverride = $v.ProxyOverride
                AutoConfigURL = $v.AutoConfigURL
            }
        }
    }
    $proxyRows | Export-Csv -Path (Join-Path $NetworkDir "internet_proxy_settings_$timestamp.csv") -NoTypeInformation -Encoding UTF8
}

Invoke-FledgeCollector "Startup Folders" {
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $rows = foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{
                    StartupPath      = $path
                    Name             = $_.Name
                    FullName         = $_.FullName
                    Length           = if (-not $_.PSIsContainer) { $_.Length } else { $null }
                    CreationTimeUTC  = $_.CreationTimeUtc.ToString("o")
                    LastWriteTimeUTC = $_.LastWriteTimeUtc.ToString("o")
                }
            }
        }
    }
    $rows | Export-Csv -Path (Join-Path $PersistenceDir "startup_folders_$timestamp.csv") -NoTypeInformation -Encoding UTF8
}

Invoke-FledgeCollector "Extended Registry Persistence" {
    $persistenceLocations = @(
        @{ Name="Winlogon"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" },
        @{ Name="AppInit"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" },
        @{ Name="LSA"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" },
        @{ Name="KnownDLLs"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" },
        @{ Name="IFEO"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" }
    )
    $rows = foreach ($location in $persistenceLocations) {
        if (Test-Path $location.Path) {
            $item = Get-ItemProperty -Path $location.Path -ErrorAction SilentlyContinue
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -notmatch '^PS') {
                    [PSCustomObject]@{ Category=$location.Name; RegistryPath=$location.Path; Name=$property.Name; Value=[string]$property.Value }
                }
            }
            if ($location.Name -eq "IFEO") {
                Get-ChildItem -Path $location.Path -ErrorAction SilentlyContinue | ForEach-Object {
                    $debugger = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
                    if ($debugger) { [PSCustomObject]@{ Category="IFEO-Debugger"; RegistryPath=$_.Name; Name="Debugger"; Value=[string]$debugger } }
                }
            }
        }
    }
    $rows | Export-Csv -Path (Join-Path $PersistenceDir "extended_registry_persistence_$timestamp.csv") -NoTypeInformation -Encoding UTF8
}

Invoke-FledgeCollector "Browser Extension Inventory" {
    $roots = @(
        @{ Browser="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data" },
        @{ Browser="Edge"; Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
        @{ Browser="Brave"; Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
    )
    $rows = foreach ($root in $roots) {
        if (Test-Path $root.Path) {
            Get-ChildItem -Path $root.Path -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } |
                ForEach-Object {
                    $profile = $_
                    $extRoot = Join-Path $profile.FullName 'Extensions'
                    if (Test-Path $extRoot) {
                        Get-ChildItem -Path $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                            [PSCustomObject]@{ Browser=$root.Browser; Profile=$profile.Name; ExtensionId=$_.Name; Path=$_.FullName; LastWriteTimeUTC=$_.LastWriteTimeUtc.ToString('o') }
                        }
                    }
                }
        }
    }
    $rows | Export-Csv -Path (Join-Path $PersistenceDir "browser_extensions_$timestamp.csv") -NoTypeInformation -Encoding UTF8
}

Invoke-FledgeCollector "Office Startup Locations" {
    $officePaths = @(
        "$env:APPDATA\Microsoft\Word\STARTUP",
        "$env:APPDATA\Microsoft\Excel\XLSTART",
        "$env:ProgramFiles\Microsoft Office\root\Office16\STARTUP",
        "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\STARTUP"
    ) | Where-Object { $_ }
    $rows = foreach ($path in $officePaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ Path=$path; Name=$_.Name; FullName=$_.FullName; Length=if(-not $_.PSIsContainer){$_.Length}else{$null}; LastWriteTimeUTC=$_.LastWriteTimeUtc.ToString('o') }
            }
        }
    }
    $rows | Export-Csv -Path (Join-Path $PersistenceDir "office_startup_locations_$timestamp.csv") -NoTypeInformation -Encoding UTF8
}

Invoke-FledgeCollector "WMI Permanent Event Subscriptions" {
    $ns = "root\subscription"
    Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue |
        Select-Object Name, Query, QueryLanguage, EventNamespace |
        Export-Csv -Path (Join-Path $PersistenceDir "wmi_event_filters_$timestamp.csv") -NoTypeInformation -Encoding UTF8

    Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Select-Object * |
        Export-Csv -Path (Join-Path $PersistenceDir "wmi_event_consumers_$timestamp.csv") -NoTypeInformation -Encoding UTF8

    Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Select-Object Filter, Consumer |
        Export-Csv -Path (Join-Path $PersistenceDir "wmi_filter_bindings_$timestamp.csv") -NoTypeInformation -Encoding UTF8
}

Invoke-FledgeCollector "PowerShell Environment and History" {
    Get-ExecutionPolicy -List |
        Export-Csv -Path (Join-Path $SystemDir "powershell_execution_policy_$timestamp.csv") -NoTypeInformation -Encoding UTF8

    $profiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost) |
        Select-Object -Unique
    $profileRows = foreach ($profilePath in $profiles) {
        [PSCustomObject]@{
            Path             = $profilePath
            Exists           = Test-Path $profilePath
            LastWriteTimeUTC = if (Test-Path $profilePath) { (Get-Item $profilePath).LastWriteTimeUtc.ToString("o") } else { $null }
        }
    }
    $profileRows | Export-Csv -Path (Join-Path $SystemDir "powershell_profiles_$timestamp.csv") -NoTypeInformation -Encoding UTF8

    $psReadLineCommand = Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue
    if ($psReadLineCommand) {
        $historyPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
        if ($historyPath -and (Test-Path $historyPath -PathType Leaf)) {
            Copy-Item -LiteralPath $historyPath -Destination (Join-Path $UserDir "powershell_console_history_$timestamp.txt") -Force -ErrorAction SilentlyContinue
        }
    }
}

if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    Invoke-FledgeCollector "Microsoft Defender State" {
        Get-MpComputerStatus |
            Select-Object * |
            Export-Csv -Path (Join-Path $SecurityDir "defender_status_$timestamp.csv") -NoTypeInformation -Encoding UTF8

        Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Select-Object * |
            Export-Csv -Path (Join-Path $SecurityDir "defender_threat_detections_$timestamp.csv") -NoTypeInformation -Encoding UTF8
    }
}
else {
    Add-FledgeSkippedCollector `
        -Name "Microsoft Defender State" `
        -Reason "Defender PowerShell cmdlets are not available on this system." `
        -Informational
}

$bitLockerCmdlet = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
$manageBdeCommand = Get-Command "manage-bde.exe" -ErrorAction SilentlyContinue

if ($bitLockerCmdlet -or $manageBdeCommand) {
    Invoke-FledgeCollector "BitLocker Status" {
        if ($bitLockerCmdlet) {
            Get-BitLockerVolume |
                Select-Object MountPoint, VolumeType, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod, LockStatus |
                Export-Csv -Path (Join-Path $SecurityDir "bitlocker_status_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
        else {
            & $manageBdeCommand.Source -status 2>&1 |
                Set-Content -Path (Join-Path $SecurityDir "bitlocker_manage_bde_$timestamp.txt") -Encoding UTF8
        }
    }
}
else {
    Add-FledgeSkippedCollector `
        -Name "BitLocker Status" `
        -Reason "Neither Get-BitLockerVolume nor manage-bde.exe is available." `
        -Informational
}

if ($CollectClipboard) {
    if (Get-Command Get-Clipboard -ErrorAction SilentlyContinue) {
        Invoke-FledgeCollector "Clipboard Content - Explicitly Requested" {
            Get-Clipboard -Raw -ErrorAction Stop |
                Set-Content -Path (Join-Path $UserDir "clipboard_$timestamp.txt") -Encoding UTF8
        }
    }
    else {
        Add-FledgeSkippedCollector -Name "Clipboard Content" -Reason "Clipboard collection was requested, but Get-Clipboard is unavailable." -Informational
    }
}
else {
    Add-FledgeSkippedCollector -Name "Clipboard Content" -Reason "Not requested. Use -CollectClipboard when collection is authorized and necessary." -Informational
}

# ============================================================================
# 17. OPTIONAL RUNNING EXECUTABLE HASHES
# ============================================================================

if ($HashRunningExecutables) {

    Invoke-FledgeCollector "Running Executable Hashes" {

        $uniqueExecutables = Get-CimInstance Win32_Process `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ExecutablePath -and
                (Test-Path $_.ExecutablePath -PathType Leaf)
            } |
            Select-Object -ExpandProperty ExecutablePath -Unique

        $hashResults = foreach ($path in $uniqueExecutables) {

            try {

                $hash = Get-FileHash `
                    -Path $path `
                    -Algorithm SHA256 `
                    -ErrorAction Stop

                $file = Get-Item $path -ErrorAction Stop
                $signature = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue

                [PSCustomObject]@{
                    FilePath     = $path
                    Length       = $file.Length
                    LastWriteTimeUTC = $file.LastWriteTimeUtc.ToString("o")
                    SHA256         = $hash.Hash
                    SignatureStatus = [string]$signature.Status
                    SignerSubject   = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
                    SignerIssuer    = if ($signature.SignerCertificate) { $signature.SignerCertificate.Issuer } else { $null }
                    SignerThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
                    Status         = "Success"
                }
            }
            catch {

                [PSCustomObject]@{
                    FilePath      = $path
                    Length        = $null
                    LastWriteTimeUTC = $null
                    SHA256        = $null
                    SignatureStatus = $null
                    SignerSubject = $null
                    SignerIssuer = $null
                    SignerThumbprint = $null
                    Status        = $_.Exception.Message
                }
            }
        }

        $hashResults |
            Export-Csv `
                -Path (
                    Join-Path `
                        $ProcessDir `
                        "running_executable_hashes_$timestamp.csv"
                ) `
                -NoTypeInformation `
                -Encoding UTF8
    }
}

# ============================================================================
# 18. OPTIONAL ACTIVE NETWORK DISCOVERY
# ============================================================================

if ($NetworkSweep) {

    if ($Gateway) {
        Invoke-FledgeCollector "Router Ping" {
            $pingResults = @(Test-Connection `
                -ComputerName $Gateway `
                -Count 3 `
                -ErrorAction SilentlyContinue)

            if ($pingResults.Count -gt 0) {
                $pingResults |
                    Format-Table -AutoSize |
                    Out-String -Width 4096 |
                    Set-Content -Path (Join-Path $NetworkDir "router_ping_$timestamp.txt") -Encoding UTF8
            }
            else {
                "No ICMP replies were received from the identified default gateway: $Gateway" |
                    Set-Content -Path (Join-Path $NetworkDir "router_ping_$timestamp.txt") -Encoding UTF8
            }
        }
    }
    else {
        Add-FledgeSkippedCollector `
            -Name "Router Ping" `
            -Reason "No IPv4 default gateway was identified." `
            -Informational
    }

    $primaryAddress = $null
    if ($PrimaryInterfaceIndex) {
        $primaryAddress = Get-NetIPAddress `
            -InterfaceIndex $PrimaryInterfaceIndex `
            -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "169.254.*" } |
            Select-Object -First 1
    }

    if (-not $PrimaryInterfaceIndex) {
        Add-FledgeSkippedCollector `
            -Name "Active Network Sweep" `
            -Reason "Primary interface could not be determined." `
            -Informational
    }
    elseif (-not $primaryAddress) {
        Add-FledgeSkippedCollector `
            -Name "Active Network Sweep" `
            -Reason "No usable IPv4 address was identified for the primary interface." `
            -Informational
    }
    elseif ($primaryAddress.PrefixLength -ne 24) {
        Add-FledgeSkippedCollector `
            -Name "Active Network Sweep" `
            -Reason ("Primary IPv4 prefix is /{0}, not /24. Automatic CIDR enumeration is intentionally not assumed." -f $primaryAddress.PrefixLength) `
            -Informational
    }
    else {
        Invoke-FledgeCollector "Active Network Sweep" {
            $octets = $primaryAddress.IPAddress.Split(".")
            $subnet = "{0}.{1}.{2}" -f $octets[0], $octets[1], $octets[2]
            $sweepFile = Join-Path $NetworkDir "active_network_sweep_$timestamp.csv"

            $results = foreach ($hostNumber in 1..254) {
                $ip = "$subnet.$hostNumber"
                $alive = Test-Connection `
                    -ComputerName $ip `
                    -Count 1 `
                    -Quiet `
                    -ErrorAction SilentlyContinue

                if ($alive) {
                    [PSCustomObject]@{
                        IPAddress = $ip
                        Status    = "Responded"
                    }
                }
            }

            $results |
                Export-Csv -Path $sweepFile -NoTypeInformation -Encoding UTF8
        }
    }

    # Capture post-activity neighbor state whenever active mode was requested.
    # Even a gateway ping can populate the neighbor/ARP cache.
    Invoke-FledgeCollector "Neighbor Cache - Post Active Discovery" {
        Get-NetNeighbor -ErrorAction Stop |
            Select-Object ifIndex, IPAddress, LinkLayerAddress, State, Store |
            Export-Csv -Path (Join-Path $NetworkDir "neighbor_cache_post_$timestamp.csv") -NoTypeInformation -Encoding UTF8

        $postArpPath = Resolve-FledgeNativeCommand "arp.exe"
        if ($postArpPath) {
            & $postArpPath -a 2>&1 |
                Set-Content -Path (Join-Path $NetworkDir "arp_native_post_$timestamp.txt") -Encoding UTF8
        }
        else {
            "arp.exe unavailable; neighbor_cache_post CSV contains the PowerShell neighbor snapshot." |
                Set-Content -Path (Join-Path $NetworkDir "arp_native_post_$timestamp.txt") -Encoding UTF8
        }
    }
}

# ============================================================================
# 19. COLLECTOR / DEPENDENCY HASHES
# ============================================================================

Invoke-FledgeCollector "Collector Integrity Hashes" {

    $collectorHashes = @()

    if ($PSCommandPath -and (Test-Path $PSCommandPath)) {

        $scriptHash = Get-FileHash `
            -Path $PSCommandPath `
            -Algorithm SHA256

        $scriptFile = Get-Item $PSCommandPath

        $collectorHashes += [PSCustomObject]@{
            FileName     = $scriptFile.Name
            RelativePath = $scriptFile.Name
            FullPath     = $scriptFile.FullName
            Length       = $scriptFile.Length
            SHA256AtStart = $StartupScriptHash
            SHA256AtEnd   = $scriptHash.Hash
            HashMatch     = ($StartupScriptHash -eq $scriptHash.Hash)
        }
    }

    foreach ($dependency in $Dependencies) {

        $path = Join-Path $DependenciesDir $dependency

        if (Test-Path $path -PathType Leaf) {

            try {

                $hash = Get-FileHash `
                    -Path $path `
                    -Algorithm SHA256 `
                    -ErrorAction Stop

                $file = Get-Item $path

                $collectorHashes += [PSCustomObject]@{
                    FileName     = $file.Name
                    RelativePath = "Dependencies\$($file.Name)"
                    FullPath     = $file.FullName
                    Length       = $file.Length
                    SHA256AtStart = $StartupDependencyHashes[$dependency]
                    SHA256AtEnd   = $hash.Hash
                    HashMatch     = ($StartupDependencyHashes[$dependency] -eq $hash.Hash)
                }
            }
            catch {
                Write-FledgeLog "Unable to hash dependency $dependency : $_" "WARN"
            }
        }
    }

    $collectorHashes |
        Export-Csv `
            -Path (
                Join-Path `
                    $HashesDir `
                    "collector_hashes_SHA256_$timestamp.csv"
            ) `
            -NoTypeInformation `
            -Encoding UTF8
}

# ============================================================================
# 20. FINAL ACQUISITION METADATA / AUDIT TRAIL
# ============================================================================

$AcquisitionEnd = Get-Date
$AcquisitionDuration = $AcquisitionEnd - $CollectionStart
$metadataPath = Join-Path $SystemDir "collection_metadata_$timestamp.txt"

$endingScriptHash = $null
if ($PSCommandPath -and (Test-Path $PSCommandPath -PathType Leaf)) {
    try {
        $endingScriptHash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        $endingScriptHash = "UNAVAILABLE: $($_.Exception.Message)"
    }
}

@(
    ""
    "AcquisitionEndLocal: $($AcquisitionEnd.ToString('o'))"
    "AcquisitionEndUTC: $($AcquisitionEnd.ToUniversalTime().ToString('o'))"
    "AcquisitionDurationSeconds: $([math]::Round($AcquisitionDuration.TotalSeconds, 2))"
    "ScriptSHA256AtEnd: $endingScriptHash"
    "ScriptHashMatch: $($StartupScriptHash -eq $endingScriptHash)"
) | Add-Content -Path $metadataPath -Encoding UTF8

$collectorStatusPath = Join-Path $LogsDir "collector_status_$timestamp.csv"
$CollectorResults |
    Export-Csv -Path $collectorStatusPath -NoTypeInformation -Encoding UTF8

# Key metrics used by both the JSON summary and HTML report. Measure-Object
# streams CSV records instead of retaining every row in memory.
$processCount = Get-FledgeCsvRecordCount (Join-Path $ProcessDir "process_details_$timestamp.csv")
$tcpCount = Get-FledgeCsvRecordCount (Join-Path $NetworkDir "tcp_connections_$timestamp.csv")
$udpCount = Get-FledgeCsvRecordCount (Join-Path $NetworkDir "udp_endpoints_$timestamp.csv")
$serviceCount = Get-FledgeCsvRecordCount (Join-Path $ServicesDir "services_$timestamp.csv")
$taskCount = Get-FledgeCsvRecordCount (Join-Path $PersistenceDir "scheduled_tasks_$timestamp.csv")
$runKeyCount = Get-FledgeCsvRecordCount (Join-Path $PersistenceDir "registry_run_keys_$timestamp.csv")

$successful = @($CollectorResults | Where-Object Status -eq "Success").Count
$failed = @($CollectorResults | Where-Object Status -eq "Failed").Count
$skipped = @($CollectorResults | Where-Object Status -eq "Skipped").Count

$summaryPath = Join-Path $ReportDir "collection_summary_$timestamp.json"
$summary = [ordered]@{
    Tool = $FledgeName
    Version = $FledgeVersion
    ComputerName = $env:COMPUTERNAME
    CollectionMode = $CollectionModeDescription
    Administrator = [bool]$IsAdmin
    CollectionStartUTC = $CollectionStart.ToUniversalTime().ToString("o")
    AcquisitionEndUTC = $AcquisitionEnd.ToUniversalTime().ToString("o")
    AcquisitionDurationSeconds = [math]::Round($AcquisitionDuration.TotalSeconds, 2)
    OutputDirectory = $outputDir
    OutputOnSystemDrive = [bool]$OutputOnSystemDrive
    ScriptSHA256AtStart = $StartupScriptHash
    ScriptSHA256AtEnd = $endingScriptHash
    ScriptHashMatch = ($StartupScriptHash -eq $endingScriptHash)
    Options = [ordered]@{
        NetworkSweep = [bool]$NetworkSweep
        HashRunningExecutables = [bool]$HashRunningExecutables
        CollectClipboard = [bool]$CollectClipboard
        WirelessScan = [bool]$WirelessScan
        AcceptPsToolsEula = [bool]$AcceptPsToolsEula
    }
    CollectorStatus = [ordered]@{
        Success = $successful
        Failed = $failed
        Skipped = $skipped
    }
    Counts = [ordered]@{
        Processes = $processCount
        TcpConnections = $tcpCount
        UdpEndpoints = $udpCount
        Services = $serviceCount
        ScheduledTasks = $taskCount
        RunRunOnceEntries = $runKeyCount
    }
    ExpectedSealingArtifacts = @(
        "Hashes\evidence_hashes_SHA256_$timestamp.csv",
        "Hashes\evidence_manifest_SHA256_$timestamp.txt"
    )
}

$summary |
    ConvertTo-Json -Depth 6 |
    Set-Content -Path $summaryPath -Encoding UTF8

# Write the final pre-report log entries now. After these calls, the log,
# metadata, collector-status, and summary files are frozen for report embedding.
Write-FledgeLog "Live-response acquisition and audit artifacts finalized."
Write-FledgeLog "Generating final HTML report; evidence sealing will immediately follow report generation."

# ============================================================================
# 21. PROFESSIONAL HTML REPORT
# ============================================================================

$reportStart = Get-Date
$reportPath = Join-Path $ReportDir "FLEDGE_Report_$timestamp.html"
$reportStatus = "Success"
$reportError = $null

try {
    $collectorRows = ($CollectorResults | ForEach-Object {
        $statusClass = switch ($_.Status) {
            "Success" { "ok" }
            "Failed"  { "bad" }
            default   { "warn" }
        }

        $searchValue = [System.Net.WebUtility]::HtmlEncode(($_.Collector + " " + $_.Status + " " + [string]$_.ErrorMessage))
        $collectorName = [System.Net.WebUtility]::HtmlEncode($_.Collector)
        $collectorStatus = [System.Net.WebUtility]::HtmlEncode($_.Status)
        $collectorError = [System.Net.WebUtility]::HtmlEncode([string]$_.ErrorMessage)

        "<tr class='collector-row' data-search='$searchValue'><td>$collectorName</td><td><span class='badge $statusClass'>$collectorStatus</span></td><td>$($_.DurationSeconds)</td><td>$collectorError</td></tr>"
    }) -join "`n"

    # Embed read-only artifact previews so the report remains portable over
    # file:// and does not depend on browser access to adjacent local files.
    $artifactIndex = 0
    $artifactPreviewMaxCharacters = 2000000
    $artifactCsvRowLimit = 1000

    $artifactRows = (Get-ChildItem -Path $outputDir -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $reportPath } |
        Sort-Object FullName |
        ForEach-Object {
            $artifactIndex++
            $file = $_
            $rel = $file.FullName.Substring($outputDir.Length).TrimStart('\')
            $ext = $file.Extension.ToLowerInvariant()
            $id = "artifact-$artifactIndex"
            $previewType = "text"
            $previewHtml = ""
            $previewNote = ""

            try {
                if ($ext -eq ".csv") {
                    $previewType = "table"

                    # Read at most limit + 1 records. The extra row tells us that
                    # the preview is truncated without enumerating the full CSV.
                    $csvProbe = @(Import-Csv -Path $file.FullName -ErrorAction Stop |
                        Select-Object -First ($artifactCsvRowLimit + 1))
                    $isTruncated = $csvProbe.Count -gt $artifactCsvRowLimit
                    $csvRows = @($csvProbe | Select-Object -First $artifactCsvRowLimit)

                    if ($csvRows.Count -gt 0) {
                        $properties = @($csvRows[0].PSObject.Properties.Name)
                        $head = ($properties | ForEach-Object {
                            "<th>$([System.Net.WebUtility]::HtmlEncode($_))</th>"
                        }) -join ""

                        $body = ($csvRows | ForEach-Object {
                            $row = $_
                            "<tr>" + (($properties | ForEach-Object {
                                "<td>$([System.Net.WebUtility]::HtmlEncode([string]$row.$_))</td>"
                            }) -join "") + "</tr>"
                        }) -join "`n"

                        if ($isTruncated) {
                            $previewNote = "CSV preview is limited to the first $artifactCsvRowLimit records. Review the original evidence file for complete content."
                        }

                        $previewHtml = "<div class='artifact-table-wrap'><table class='artifact-data-table'><thead><tr>$head</tr></thead><tbody>$body</tbody></table></div>"
                    }
                    else {
                        $previewHtml = "<div class='empty-state'>CSV artifact contains no data rows.</div>"
                    }
                }
                elseif ($ext -in @(".txt", ".log", ".json", ".xml", ".ps1", ".psm1", ".md")) {
                    $previewType = "text"
                    $content = Get-FledgeTextPreview -Path $file.FullName -MaxCharacters $artifactPreviewMaxCharacters
                    if ($file.Length -gt 2MB) {
                        $previewNote = "Text preview is limited for report performance. Review the original evidence file for complete content."
                    }
                    $previewHtml = "<pre class='artifact-text'>$([System.Net.WebUtility]::HtmlEncode([string]$content))</pre>"
                }
                elseif ($ext -eq ".html" -or $ext -eq ".htm") {
                    $previewType = "html-source"
                    $content = Get-FledgeTextPreview -Path $file.FullName -MaxCharacters $artifactPreviewMaxCharacters
                    $previewHtml = "<pre class='artifact-text'>$([System.Net.WebUtility]::HtmlEncode([string]$content))</pre>"
                    $previewNote = "HTML source is displayed as inert text so collected content cannot execute inside the forensic report."
                }
                else {
                    $previewType = "metadata"
                    $previewHtml = "<div class='empty-state'>Inline preview is not available for this file type. Review the original artifact for its complete contents.</div>"
                }
            }
            catch {
                $previewType = "error"
                $previewHtml = "<div class='empty-state'>Unable to create inline preview: $([System.Net.WebUtility]::HtmlEncode($_.Exception.Message))</div>"
            }

            $safeRel = [System.Net.WebUtility]::HtmlEncode($rel)
            $safeNote = [System.Net.WebUtility]::HtmlEncode($previewNote)
            $searchText = [System.Net.WebUtility]::HtmlEncode(($rel + " " + $ext))
            $typeLabel = if ($ext) { $ext.TrimStart('.').ToUpperInvariant() } else { "FILE" }
            $displaySize = Format-FledgeByteSize -Bytes $file.Length

            ('<tr class="artifact-row" data-search="{0}"><td><button type="button" class="artifact-link" onclick="openArtifact(''{1}'')">{2}</button><div id="{1}" class="artifact-payload" data-name="{2}" data-size="{3}" data-modified="{4}" data-type="{5}" data-note="{6}">{7}</div></td><td>{9}</td><td>{4}</td><td>{8}</td></tr>' -f `
                $searchText,
                $id,
                $safeRel,
                $file.Length,
                $file.LastWriteTimeUtc.ToString('o'),
                $previewType,
                $safeNote,
                $previewHtml,
                $typeLabel,
                $displaySize
            )
        }) -join "`n"

    $mode = $CollectionModeDescription
    $adminText = if ($IsAdmin) { "YES" } else { "NO" }
    $clipboardText = if ($CollectClipboard) { "Collected by explicit request" } else { "Not requested" }
    $safeComputerName = [System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)
    $safeCurrentUser = [System.Net.WebUtility]::HtmlEncode([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $safeCollectionRoot = [System.Net.WebUtility]::HtmlEncode($CollectionRoot)
    $safeScriptHash = [System.Net.WebUtility]::HtmlEncode([string]$StartupScriptHash)

    $html = @"
<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>FLEDGE Forensic Collection Report</title>
<style>
:root{
  --bg:#e9eef3;--workspace:#eef2f6;--surface:#ffffff;--surface2:#f8fafc;--surface3:#f3f6f9;
  --text:#17212b;--muted:#64748b;--line:#d8e0e8;--line2:#e7edf2;--navy:#102a43;--navy2:#163e63;
  --accent:#0e7490;--link:#075985;--hover:#f8fbfd;--notice:#eff6ff;--textpane:#fbfcfd;
  --ok:#166534;--okbg:#dcfce7;--warn:#92400e;--warnbg:#fef3c7;--bad:#991b1b;--badbg:#fee2e2;
  --overlay:rgba(15,23,42,.76);--shadow:rgba(15,23,42,.08);--modal-shadow:rgba(0,0,0,.38);
  --header-h:70px;--tabs-h:42px;--footer-h:30px
}
:root[data-theme="dark"]{
  --bg:#0b1118;--workspace:#0e1621;--surface:#121c27;--surface2:#172330;--surface3:#101a25;
  --text:#e5edf5;--muted:#9fb0c0;--line:#2a3a4a;--line2:#223242;--navy:#0b2438;--navy2:#103653;
  --accent:#38bdf8;--link:#7dd3fc;--hover:#182635;--notice:#102a43;--textpane:#0d1721;
  --ok:#86efac;--okbg:#143322;--warn:#fcd34d;--warnbg:#3a2b0d;--bad:#fca5a5;--badbg:#3b1717;
  --overlay:rgba(0,0,0,.82);--shadow:rgba(0,0,0,.28);--modal-shadow:rgba(0,0,0,.65)
}
*{box-sizing:border-box}
html,body{height:100%;margin:0;overflow:hidden}
body{font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:13px}
button,input{font:inherit}
.app{height:100vh;width:100vw;display:grid;grid-template-rows:var(--header-h) var(--tabs-h) minmax(0,1fr) var(--footer-h);overflow:hidden;background:var(--surface)}
header{display:flex;align-items:center;justify-content:space-between;gap:24px;padding:0 24px;background:linear-gradient(110deg,var(--navy),var(--navy2));color:#fff;overflow:hidden}
header h1{font-size:21px;margin:0;white-space:nowrap}
header p{font-size:11px;color:#d9e5ef;margin:4px 0 0}
.header-right{display:flex;align-items:center;gap:14px;text-align:right;font-size:11px;color:#d9e5ef;white-space:nowrap}
.header-meta{text-align:right}
.theme-toggle{height:30px;border:1px solid rgba(255,255,255,.45);border-radius:5px;background:rgba(255,255,255,.08);color:#fff;padding:0 10px;cursor:pointer;font-weight:600}
.theme-toggle:hover{background:rgba(255,255,255,.16)}
.tabs{display:flex;align-items:stretch;background:var(--surface3);border-bottom:1px solid var(--line);padding-left:18px;overflow:hidden}
.tab-button{border:0;border-right:1px solid var(--line);background:transparent;padding:0 18px;cursor:pointer;font-weight:600;color:var(--muted)}
.tab-button:first-child{border-left:1px solid var(--line)}
.tab-button:hover{background:var(--hover)}
.tab-button.active{background:var(--surface);color:var(--text);box-shadow:inset 0 -3px 0 var(--accent)}
.workspace{min-height:0;overflow:hidden;background:var(--workspace)}
.tab-pane{display:none;height:100%;min-height:0;overflow:hidden;padding:14px}
.tab-pane.active{display:block}
.panel{height:100%;min-height:0;background:var(--surface);border:1px solid var(--line);border-radius:7px;box-shadow:0 1px 3px var(--shadow);overflow:hidden}
.panel-head{height:46px;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 14px;background:var(--surface2);border-bottom:1px solid var(--line)}
.panel-head h2{font-size:14px;margin:0;color:var(--text)}
.panel-body{height:calc(100% - 46px);min-height:0;overflow:auto;padding:14px}
.overview-grid{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:10px;margin-bottom:12px}
.card{border:1px solid var(--line);background:var(--surface);border-radius:6px;padding:12px}
.card .n{font-size:24px;font-weight:700;color:var(--text)}
.card .l{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-top:3px}
.two-col{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px}
.subpanel{border:1px solid var(--line);border-radius:6px;overflow:hidden;background:var(--surface)}
.subpanel h3{font-size:12px;margin:0;padding:9px 11px;background:var(--surface2);border-bottom:1px solid var(--line);color:var(--text)}
.meta{display:grid;grid-template-columns:170px minmax(0,1fr);font-size:12px}
.meta div{padding:7px 10px;border-bottom:1px solid var(--line2);min-width:0;word-break:break-word}
.meta div:nth-child(odd){font-weight:600;background:var(--surface2)}
.notice{padding:11px 13px;background:var(--notice);border-left:4px solid var(--accent);font-size:12px;line-height:1.45}
.small{font-size:11px;color:var(--muted);line-height:1.45}
.toolbar{display:flex;gap:8px;align-items:center;min-width:0}
.search,.modal-tools input{color:var(--text);background:var(--surface);border:1px solid var(--line)}
.search{width:min(500px,42vw);height:30px;padding:5px 9px;border-radius:4px}
.table-shell{height:100%;min-height:0;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:11px;color:var(--text)}
th,td{padding:7px 9px;text-align:left;border-bottom:1px solid var(--line2);vertical-align:top}
th{position:sticky;top:0;z-index:3;background:var(--surface3);color:var(--text);font-size:10px;text-transform:uppercase;letter-spacing:.035em}
tbody tr:hover{background:var(--hover)}
.badge{display:inline-block;border-radius:999px;padding:2px 7px;font-size:10px;font-weight:700}
.badge.ok{background:var(--okbg);color:var(--ok)}
.badge.warn{background:var(--warnbg);color:var(--warn)}
.badge.bad{background:var(--badbg);color:var(--bad)}
.artifact-link{border:0;background:none;padding:0;color:var(--link);text-decoration:underline;cursor:pointer;text-align:left;font:inherit;font-weight:600;word-break:break-all}
.artifact-link:hover{color:var(--accent)}
.artifact-payload{display:none}
.empty-state{padding:26px;text-align:center;color:var(--muted);background:var(--surface2);border:1px dashed var(--line);border-radius:5px}
footer{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:0 18px;background:var(--surface3);border-top:1px solid var(--line);font-size:10px;color:var(--muted);white-space:nowrap;overflow:hidden}
.modal{display:none;position:fixed;z-index:9999;inset:0;background:var(--overlay);padding:24px}
.modal.open{display:flex;align-items:center;justify-content:center}
.modal-panel{width:min(96vw,1800px);height:calc(100vh - 48px);max-height:calc(100vh - 48px);display:grid;grid-template-rows:auto auto minmax(0,1fr);background:var(--surface);border-radius:8px;box-shadow:0 20px 70px var(--modal-shadow);overflow:hidden}
.modal-head{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;padding:13px 16px;background:var(--navy);color:#fff}
.modal-title{font-size:15px;font-weight:700;word-break:break-all}
.modal-meta{font-size:10px;color:#d6e3ec;margin-top:4px}
.modal-close{border:1px solid rgba(255,255,255,.5);background:transparent;color:#fff;border-radius:4px;padding:5px 10px;cursor:pointer}
.modal-close:hover{background:rgba(255,255,255,.1)}
.modal-tools{display:flex;align-items:center;gap:9px;padding:8px 12px;border-bottom:1px solid var(--line);background:var(--surface2)}
.modal-tools input{flex:1;height:31px;padding:5px 9px;border-radius:4px}
.result-count{font-size:10px;color:var(--muted);white-space:nowrap}
.modal-body{height:100%;min-height:0;overflow:hidden;padding:10px;background:var(--surface);display:flex;flex-direction:column}
.artifact-note{flex:0 0 auto;padding:7px 10px;background:var(--warnbg);color:var(--warn);border-left:4px solid var(--warn);margin-bottom:8px;font-size:11px}
.artifact-view{flex:1 1 auto;height:auto;min-height:0;overflow:hidden}
.artifact-text-wrap{height:100%;min-height:0;overflow:auto;border:1px solid var(--line);background:var(--textpane)}
.artifact-text{white-space:pre-wrap;word-break:break-word;margin:0;padding:11px;font:11px/1.45 Consolas,'Courier New',monospace;color:var(--text)}
.artifact-table-wrap{height:100%;min-height:0;overflow:auto;border:1px solid var(--line)}
.artifact-data-table{font-size:10px;min-width:100%}
.artifact-data-table thead th{position:sticky;top:0;z-index:4}
.artifact-data-table tr.hidden{display:none}
@media(max-width:900px){
  .overview-grid{grid-template-columns:repeat(2,minmax(130px,1fr))}
  .two-col{grid-template-columns:1fr}
  .search{width:45vw}
  .header-meta{display:none}
}
@media print{
  :root,:root[data-theme="dark"]{
    --bg:#fff;--workspace:#fff;--surface:#fff;--surface2:#fff;--surface3:#f4f6f8;
    --text:#111827;--muted:#64748b;--line:#d8e0e8;--line2:#e7edf2;--hover:#fff;--textpane:#fff
  }
  html,body{height:auto;overflow:visible;background:#fff}
  .app{height:auto;display:block}
  header,.tabs,footer{position:static}
  .theme-toggle{display:none}
  .workspace{overflow:visible}
  .tab-pane{display:block!important;height:auto;overflow:visible;padding:8px}
  .panel,.panel-body,.table-shell{height:auto;overflow:visible;box-shadow:none}
  .modal{display:none!important}
  th{position:static}
}
</style>
</head>
<body>
<div class="app">
<header>
  <div>
    <h1>FLEDGE Forensic Collection Report</h1>
    <p>Forensic Live Evidence Data Gathering Engine &nbsp;|&nbsp; Version $FledgeVersion</p>
  </div>
  <div class="header-right">
    <div class="header-meta">
      <div>$safeComputerName</div>
      <div>$mode</div>
    </div>
    <button id="themeToggle" class="theme-toggle" type="button" onclick="toggleTheme()" aria-label="Toggle dark mode" aria-pressed="false">Dark mode</button>
  </div>
</header>

<nav class="tabs" aria-label="Report sections">
  <button class="tab-button active" type="button" data-tab="overview" onclick="showTab('overview',this)">Overview</button>
  <button class="tab-button" type="button" data-tab="collectors" onclick="showTab('collectors',this)">Collector Status</button>
  <button class="tab-button" type="button" data-tab="artifacts" onclick="showTab('artifacts',this)">Artifacts ($artifactIndex)</button>
</nav>

<main class="workspace">
<section id="tab-overview" class="tab-pane active">
  <div class="panel">
    <div class="panel-head"><h2>Collection Overview</h2><span class="small">Fixed-screen report; panels scroll independently.</span></div>
    <div class="panel-body">
      <div class="overview-grid">
        <div class="card"><div class="n">$successful</div><div class="l">Successful Collectors</div></div>
        <div class="card"><div class="n">$failed</div><div class="l">Failed Collectors</div></div>
        <div class="card"><div class="n">$skipped</div><div class="l">Skipped / Optional</div></div>
        <div class="card"><div class="n">$processCount</div><div class="l">Processes</div></div>
        <div class="card"><div class="n">$tcpCount</div><div class="l">TCP Connections</div></div>
        <div class="card"><div class="n">$udpCount</div><div class="l">UDP Endpoints</div></div>
        <div class="card"><div class="n">$serviceCount</div><div class="l">Services</div></div>
        <div class="card"><div class="n">$taskCount</div><div class="l">Scheduled Tasks</div></div>
      </div>

      <div class="two-col">
        <div class="subpanel">
          <h3>Acquisition Metadata</h3>
          <div class="meta">
            <div>Computer</div><div>$safeComputerName</div>
            <div>Current User</div><div>$safeCurrentUser</div>
            <div>Collection Start UTC</div><div>$($CollectionStart.ToUniversalTime().ToString('o'))</div>
            <div>Acquisition End UTC</div><div>$($AcquisitionEnd.ToUniversalTime().ToString('o'))</div>
            <div>Collection Mode</div><div>$mode</div>
            <div>Administrator</div><div>$adminText</div>
            <div>PowerShell</div><div>$($PSVersionTable.PSVersion) / $($PSVersionTable.PSEdition)</div>
            <div>Script SHA-256 at Start</div><div style="font-family:Consolas,'Courier New',monospace">$safeScriptHash</div>
            <div>Collection Root</div><div>$safeCollectionRoot</div>
            <div>Output on System Drive</div><div>$OutputOnSystemDrive</div>
            <div>Running EXE Hashes</div><div>$HashRunningExecutables</div>
            <div>Clipboard</div><div>$clipboardText</div>
            <div>Wireless Scan</div><div>$WirelessScan</div>
            <div>PsTools EULA Write Allowed</div><div>$AcceptPsToolsEula</div>
            <div>Run / RunOnce Entries</div><div>$runKeyCount</div>
          </div>
        </div>

        <div class="subpanel">
          <h3>Forensic Integrity</h3>
          <div style="padding:11px">
            <div class="notice"><strong>Evidence sealing:</strong> Audit artifacts are finalized before this report is generated. After the report is written, FLEDGE creates the SHA-256 evidence manifest and detached manifest hash, then performs no further evidence-directory writes.</div>
            <p class="small">Verify the SHA-256 evidence manifest before analysis and after every copy or transfer. Embedded artifact previews are presentation conveniences; the original collected files remain the evidentiary artifacts.</p>
            <p class="small"><strong>Inventory scope:</strong> The embedded inventory is a snapshot of finalized pre-report artifacts. The report itself and the two sealing-manifest files are excluded by design to avoid circular report content.</p>
            <p class="small"><strong>Report isolation:</strong> Content Security Policy blocks network connections, frames, objects, and external resources. Collected HTML is rendered as source text rather than executed.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<section id="tab-collectors" class="tab-pane">
  <div class="panel">
    <div class="panel-head">
      <h2>Collector Status</h2>
      <div class="toolbar"><input id="collectorSearch" class="search" type="search" placeholder="Filter collectors, status, or notes..." oninput="filterCollectors()"></div>
    </div>
    <div class="panel-body" style="padding:0"><div class="table-shell"><table>
      <thead><tr><th>Collector</th><th>Status</th><th>Seconds</th><th>Error / Note</th></tr></thead>
      <tbody id="collectorBody">$collectorRows</tbody>
    </table></div></div>
  </div>
</section>

<section id="tab-artifacts" class="tab-pane">
  <div class="panel">
    <div class="panel-head">
      <h2>Interactive Artifact Inventory</h2>
      <div class="toolbar"><input id="artifactInventorySearch" class="search" type="search" placeholder="Filter artifacts by path or type..." oninput="filterArtifacts()"></div>
    </div>
    <div class="panel-body" style="padding:0"><div class="table-shell"><table>
      <thead><tr><th>Relative Path</th><th>Bytes</th><th>Last Write UTC</th><th>Type</th></tr></thead>
      <tbody id="artifactInventoryBody">$artifactRows</tbody>
    </table></div></div>
  </div>
</section>
</main>

<footer>
  <span>FLEDGE $FledgeVersion &nbsp;|&nbsp; Generated $((Get-Date).ToUniversalTime().ToString('o'))</span>
  <span>Read-only presentation layer - verify original artifacts and SHA-256 manifest.</span>
</footer>
</div>

<div id="artifactModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="artifactModalTitle" onclick="modalBackdrop(event)">
  <div class="modal-panel">
    <div class="modal-head">
      <div><div id="artifactModalTitle" class="modal-title"></div><div id="artifactModalMeta" class="modal-meta"></div></div>
      <button class="modal-close" type="button" onclick="closeArtifact()">Close</button>
    </div>
    <div class="modal-tools">
      <input id="artifactDataSearch" type="search" placeholder="Search within this artifact..." oninput="filterArtifactData()">
      <span id="artifactResultCount" class="result-count"></span>
    </div>
    <div id="artifactModalBody" class="modal-body"></div>
  </div>
</div>

<script>
let activeArtifact=null;

function preferredTheme(){
  try{
    const saved=localStorage.getItem('fledge-theme');
    if(saved==='dark'||saved==='light')return saved;
  }catch(e){}
  return (window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';
}

function applyTheme(theme){
  const next=(theme==='dark')?'dark':'light';
  document.documentElement.setAttribute('data-theme',next);
  const b=document.getElementById('themeToggle');
  if(b){
    const dark=next==='dark';
    b.textContent=dark?'Light mode':'Dark mode';
    b.setAttribute('aria-pressed',dark?'true':'false');
    b.setAttribute('aria-label',dark?'Switch to light mode':'Switch to dark mode');
  }
}

function toggleTheme(){
  const current=document.documentElement.getAttribute('data-theme')||'light';
  const next=current==='dark'?'light':'dark';
  applyTheme(next);
  try{localStorage.setItem('fledge-theme',next);}catch(e){}
}

function showTab(name,button){
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-button').forEach(b=>b.classList.remove('active'));
  const pane=document.getElementById('tab-'+name);
  if(pane)pane.classList.add('active');
  if(button)button.classList.add('active');
}

function filterCollectors(){
  const q=(document.getElementById('collectorSearch').value||'').toLowerCase();
  document.querySelectorAll('#collectorBody .collector-row').forEach(r=>{
    r.style.display=(r.dataset.search||'').toLowerCase().includes(q)?'':'none';
  });
}

function filterArtifacts(){
  const q=(document.getElementById('artifactInventorySearch').value||'').toLowerCase();
  document.querySelectorAll('#artifactInventoryBody .artifact-row').forEach(r=>{
    r.style.display=(r.dataset.search||'').toLowerCase().includes(q)?'':'none';
  });
}

function openArtifact(id){
  const src=document.getElementById(id);
  if(!src)return;
  activeArtifact=src;

  document.getElementById('artifactModalTitle').textContent=src.dataset.name||'Artifact';
  document.getElementById('artifactModalMeta').textContent=
    (src.dataset.type||'').toUpperCase()+' | '+src.dataset.size+
    ' bytes | Last Write UTC: '+src.dataset.modified;

  const body=document.getElementById('artifactModalBody');
  body.innerHTML='';

  if(src.dataset.note){
    const n=document.createElement('div');
    n.className='artifact-note';
    n.textContent=src.dataset.note;
    body.appendChild(n);
  }

  const view=document.createElement('div');
  view.className='artifact-view';
  const content=document.createElement('div');
  content.innerHTML=src.innerHTML;

  const pre=content.querySelector('.artifact-text');
  if(pre){
    const wrap=document.createElement('div');
    wrap.className='artifact-text-wrap';
    wrap.appendChild(pre);
    view.appendChild(wrap);
  }else{
    while(content.firstChild)view.appendChild(content.firstChild);
  }

  body.appendChild(view);
  document.getElementById('artifactDataSearch').value='';
  updateArtifactResultCount();
  document.getElementById('artifactModal').classList.add('open');
  document.getElementById('artifactDataSearch').focus();
}

function closeArtifact(){
  document.getElementById('artifactModal').classList.remove('open');
  activeArtifact=null;
}

function modalBackdrop(e){if(e.target.id==='artifactModal')closeArtifact();}

function updateArtifactResultCount(){
  const out=document.getElementById('artifactResultCount');
  const body=document.getElementById('artifactModalBody');
  const rows=body.querySelectorAll('.artifact-data-table tbody tr');
  if(rows.length){
    const visible=[...rows].filter(r=>!r.classList.contains('hidden')).length;
    out.textContent=visible+' / '+rows.length+' rows';
    return;
  }
  const pre=body.querySelector('.artifact-text');
  if(pre){
    const count=(pre.textContent||'').split('\n').length;
    out.textContent=count+' displayed lines';
    return;
  }
  out.textContent='';
}

function filterArtifactData(){
  const q=(document.getElementById('artifactDataSearch').value||'').toLowerCase();
  const body=document.getElementById('artifactModalBody');
  const rows=body.querySelectorAll('.artifact-data-table tbody tr');

  if(rows.length){
    rows.forEach(r=>r.classList.toggle('hidden',q && !r.textContent.toLowerCase().includes(q)));
    updateArtifactResultCount();
    return;
  }

  const pre=body.querySelector('.artifact-text');
  if(pre){
    const original=activeArtifact?activeArtifact.querySelector('.artifact-text'):null;
    if(!original)return;
    const text=original.textContent||'';
    if(!q){
      pre.textContent=text;
    }else{
      const lines=text.split('\n').filter(l=>l.toLowerCase().includes(q));
      pre.textContent=lines.length?lines.join('\n'):'No matching lines.';
    }
    updateArtifactResultCount();
  }
}

document.addEventListener('keydown',e=>{if(e.key==='Escape')closeArtifact();});
document.addEventListener('DOMContentLoaded',()=>applyTheme(preferredTheme()));
</script>
</body>
</html>
"@

    # PowerShell 5.1 writes UTF-8 with BOM. The document declares UTF-8 and the
    # report body intentionally uses ASCII punctuation for maximum portability.
    $html | Set-Content -Path $reportPath -Encoding UTF8
}
catch {
    $reportStatus = "Failed"
    $reportError = $_.Exception.Message
    # Pre-report audit files are intentionally frozen. Report-generation errors
    # are therefore emitted to the console only, rather than mutating the log.
    Write-Host ("HTML report generation failed: {0}" -f $reportError) -ForegroundColor Red
}

$reportEnd = Get-Date

# ============================================================================
# 22. EVIDENCE SEALING / SHA-256 MANIFEST
#
# This phase intentionally does not use Invoke-FledgeCollector or Write-FledgeLog.
# After the evidence manifest and detached manifest hash are written, no files
# beneath $outputDir are modified.
# ============================================================================

$script:EvidenceSealed = $true
$hashCsv = Join-Path $HashesDir "evidence_hashes_SHA256_$timestamp.csv"
$manifestHashPath = Join-Path $HashesDir "evidence_manifest_SHA256_$timestamp.txt"

$files = Get-ChildItem -Path $outputDir -File -Recurse |
    Where-Object { $_.FullName -ne $hashCsv -and $_.FullName -ne $manifestHashPath }

$rows = foreach ($file in $files) {
    try {
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop
        $relativePath = $file.FullName.Substring($outputDir.Length).TrimStart('\')
        [PSCustomObject]@{
            FileName     = $file.Name
            RelativePath = $relativePath
            Length       = $file.Length
            LastWriteUTC = $file.LastWriteTimeUtc.ToString("o")
            SHA256       = $hash.Hash
        }
    }
    catch {
        [PSCustomObject]@{
            FileName     = $file.Name
            RelativePath = $file.FullName.Substring($outputDir.Length).TrimStart('\')
            Length       = $file.Length
            LastWriteUTC = $file.LastWriteTimeUtc.ToString("o")
            SHA256       = "HASH_ERROR: $($_.Exception.Message)"
        }
    }
}

$rows | Export-Csv -Path $hashCsv -NoTypeInformation -Encoding UTF8
$manifestHash = Get-FileHash -Path $hashCsv -Algorithm SHA256
@(
    "FLEDGE EVIDENCE MANIFEST SHA256"
    "==============================="
    ""
    "Manifest: $($manifestHash.Path)"
    "SHA256:   $($manifestHash.Hash)"
    "SealedUTC: $((Get-Date).ToUniversalTime().ToString('o'))"
) | Set-Content -Path $manifestHashPath -Encoding UTF8

# No file writes beneath $outputDir after this point.
$FinalEnd = Get-Date
$TotalDuration = $FinalEnd - $CollectionStart

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host " COLLECTION COMPLETE / EVIDENCE SEALED" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "Evidence location:"
Write-Host " $outputDir" -ForegroundColor Cyan
Write-Host ""

if ($reportStatus -eq "Success") {
    Write-Host "HTML report:"
    Write-Host " $reportPath" -ForegroundColor Cyan
    Write-Host ""
}
else {
    Write-Host "HTML report: FAILED" -ForegroundColor Red
    Write-Host " $reportError" -ForegroundColor Red
    Write-Host ""
}

Write-Host "Duration:"
Write-Host (" {0:N2} seconds" -f $TotalDuration.TotalSeconds)
Write-Host ""

if (-not $IsAdmin) {
    Write-Host "WARNING: FLEDGE was not executed with administrative privileges." -ForegroundColor DarkYellow
    Write-Host "Some collected artifacts may be incomplete." -ForegroundColor DarkYellow
    Write-Host ""
}
if ($NetworkSweep) {
    Write-Host "NOTE: Active ICMP network discovery was enabled." -ForegroundColor DarkYellow
    Write-Host "The network sweep may have modified the local neighbor/ARP cache." -ForegroundColor DarkYellow
    Write-Host ""
}
if ($WirelessScan) {
    Write-Host "NOTE: Wireless BSSID discovery was enabled and may have refreshed Wi-Fi scan state." -ForegroundColor DarkYellow
    Write-Host ""
}
if ($AcceptPsToolsEula) {
    Write-Host "NOTE: PsTools EULA acceptance was permitted and may have written Sysinternals registry state." -ForegroundColor DarkYellow
    Write-Host ""
}
Write-Host "Verify the SHA256 evidence manifest before analysis or copying." -ForegroundColor DarkGray
Write-Host ""
