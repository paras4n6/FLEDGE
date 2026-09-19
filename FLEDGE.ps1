<#
.SYNOPSIS
    FLEDGE - Forensic Live Evidence Data Gathering Engine

.DESCRIPTION
    PowerShell-based live-response forensic collector for Windows systems.

    FLEDGE - a structured acquisition of volatile and system-level artifacts from a live Windows environment.

    Collection is PASSIVE by default.

    Optional active network discovery may be enabled with:
        .\FLEDGE.ps1 -NetworkSweep

.NOTES
    Run with administrative privileges when authorized.

    Active network discovery modifies network state by generating ICMP traffic and populating the local neighbor/ARP cache.

    Verify hashes after acquisition and after any subsequent copying.

.VERSION
    1.1.0-WIN-NET-LIVE
#>

[CmdletBinding()]
param (
    [switch]$NetworkSweep,

    [switch]$HashRunningExecutables
)

# ============================================================================
# FLEDGE CONFIGURATION
# ============================================================================

$FledgeName    = "FLEDGE"
$FledgeVersion = "1.1.0-WIN-NET-LIVE"

$CollectionStart = Get-Date
$timestamp       = $CollectionStart.ToString("yyyyMMdd_HHmmss")

$outputDir       = Join-Path $PSScriptRoot "FLEDGE_Nest_$timestamp"
$DependenciesDir = Join-Path $PSScriptRoot "Dependencies"

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
    $LogsDir
)

foreach ($directory in $Directories) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$LogFile = Join-Path $LogsDir "FLEDGE_collection_$timestamp.log"

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

    Write-FledgeLog "Starting collector: $Name"

    try {
        & $ScriptBlock

        $duration = ((Get-Date) - $start).TotalSeconds

        Write-FledgeLog (
            "Completed collector: {0} ({1:N2} seconds)" -f $Name, $duration
        )
    }
    catch {
        $duration = ((Get-Date) - $start).TotalSeconds

        Write-FledgeLog (
            "Collector failed: {0} ({1:N2} seconds) - {2}" -f `
                $Name,
                $duration,
                $_.Exception.Message
        ) "ERROR"
    }
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

if ($NetworkSweep) {
    Write-Host ""
    Write-Host "Collection Mode: ACTIVE NETWORK DISCOVERY ENABLED" `
        -ForegroundColor DarkYellow

    Write-Host "WARNING: Network discovery will generate network traffic and may" `
        -ForegroundColor DarkYellow

    Write-Host "modify the local ARP/neighbor cache." `
        -ForegroundColor DarkYellow
}
else {
    Write-Host "Collection Mode:   PASSIVE LIVE RESPONSE" -ForegroundColor Green
}

Write-Host ""
Write-Host "Collecting live evidence...DO NOT DISTURB" `
    -ForegroundColor DarkYellow

Write-Host "Individual access-denied messages may occur. Collection will continue." `
    -ForegroundColor DarkGray

Write-Host "Saving evidence to: $outputDir"
Write-Host ""

Write-FledgeLog "FLEDGE collection initialized."
Write-FledgeLog "Version: $FledgeVersion"
Write-FledgeLog "Output directory: $outputDir"
Write-FledgeLog "Administrative privileges: $IsAdmin"
Write-FledgeLog "Network sweep requested: $NetworkSweep"


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
    }
    else {
        Write-FledgeLog "Dependency missing: $dependencyPath" "WARN"
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
        OutputDirectory      = $outputDir
        NetworkSweepEnabled  = [bool]$NetworkSweep
        HashRunningEXEs      = [bool]$HashRunningExecutables
    }

    $metadata.GetEnumerator() |
        ForEach-Object {
            "{0}: {1}" -f $_.Key, $_.Value
        } |
        Set-Content -Path $metadataPath -Encoding UTF8
}

Invoke-FledgeCollector "System Time Information" {

    $timeFile = Join-Path $SystemDir "time_information_$timestamp.txt"

    @(
        "FLEDGE Time Acquisition"
        "======================="
        ""
        "Local Time: $((Get-Date).ToString('o'))"
        "UTC Time:   $((Get-Date).ToUniversalTime().ToString('o'))"
        ""
        "TIME ZONE"
        "---------"
        (Get-TimeZone | Format-List * | Out-String -Width 4096)
        ""
        "WINDOWS TIME STATUS"
        "-------------------"
        (& w32tm /query /status 2>&1 | Out-String -Width 4096)
        ""
        "WINDOWS TIME CONFIGURATION"
        "--------------------------"
        (& w32tm /query /configuration 2>&1 | Out-String -Width 4096)
    ) |
        Set-Content -Path $timeFile -Encoding UTF8
}

# ============================================================================
# 2. LOGGED-ON USERS / ACTIVE SESSIONS
# ============================================================================

Invoke-FledgeCollector "Logged-On Users - PsLoggedOn" {

    $tool = Join-Path $DependenciesDir "psloggedon.exe"

    if (Test-Path $tool) {
        & $tool -accepteula 2>&1 |
            Set-Content `
                (Join-Path $UserDir "psloggedon_$timestamp.txt") `
                -Encoding UTF8
    }
}

Invoke-FledgeCollector "Interactive User Sessions" {

    & quser 2>&1 |
        Set-Content `
            (Join-Path $UserDir "quser_$timestamp.txt") `
            -Encoding UTF8

    & qwinsta 2>&1 |
        Set-Content `
            (Join-Path $UserDir "qwinsta_$timestamp.txt") `
            -Encoding UTF8
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


Invoke-FledgeCollector "Tasklist" {

    & tasklist /V 2>&1 |
        Set-Content `
            (Join-Path $ProcessDir "tasklist_$timestamp.txt") `
            -Encoding UTF8
}

Invoke-FledgeCollector "PsList" {

    $tool = Join-Path $DependenciesDir "pslist.exe"

    if (Test-Path $tool) {
        & $tool -accepteula 2>&1 |
            Set-Content `
                (Join-Path $ProcessDir "pslist_$timestamp.txt") `
                -Encoding UTF8
    }
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

Invoke-FledgeCollector "ARP Table - Native" {

    & arp -a 2>&1 |
        Set-Content `
            (Join-Path $NetworkDir "arp_native_pre_$timestamp.txt") `
            -Encoding UTF8
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

    & route print 2>&1 |
        Set-Content `
            (Join-Path $NetworkDir "route_print_$timestamp.txt") `
            -Encoding UTF8
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

Invoke-FledgeCollector "IPConfig All" {

    & ipconfig /all 2>&1 |
        Set-Content `
            (Join-Path $NetworkDir "ipconfig_all_$timestamp.txt") `
            -Encoding UTF8
}

# ============================================================================
# 10. OPEN FILES
# ============================================================================

Invoke-FledgeCollector "Open Files - PsFile" {

    $tool = Join-Path $DependenciesDir "psfile.exe"

    if (Test-Path $tool) {
        & $tool -accepteula 2>&1 |
            Set-Content `
                (Join-Path $SystemDir "open_files_$timestamp.txt") `
                -Encoding UTF8
    }
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

Invoke-FledgeCollector "PsService" {

    $tool = Join-Path $DependenciesDir "psservice.exe"

    if (Test-Path $tool) {
        & $tool -accepteula 2>&1 |
            Set-Content `
                (Join-Path $ServicesDir "psservice_$timestamp.txt") `
                -Encoding UTF8
    }
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

Invoke-FledgeCollector "Wi-Fi Interface Information" {

    & netsh wlan show interfaces 2>&1 |
        Set-Content `
            (Join-Path $WiFiDir "wifi_interfaces_$timestamp.txt") `
            -Encoding UTF8
}

Invoke-FledgeCollector "Wi-Fi Networks" {

    & netsh wlan show networks mode=bssid 2>&1 |
        Set-Content `
            (Join-Path $WiFiDir "wifi_networks_$timestamp.txt") `
            -Encoding UTF8
}

Invoke-FledgeCollector "Saved Wi-Fi Profiles" {

    & netsh wlan show profiles 2>&1 |
        Set-Content `
            (Join-Path $WiFiDir "wifi_profiles_$timestamp.txt") `
            -Encoding UTF8
}

Invoke-FledgeCollector "Wi-Fi Drivers" {

    & netsh wlan show drivers 2>&1 |
        Set-Content `
            (Join-Path $WiFiDir "wifi_drivers_$timestamp.txt") `
            -Encoding UTF8
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

Invoke-FledgeCollector "SystemInfo Native" {

    & systeminfo 2>&1 |
        Set-Content `
            (Join-Path $SystemDir "systeminfo_native_$timestamp.txt") `
            -Encoding UTF8
}

# ============================================================================
# 16. OPTIONAL RUNNING EXECUTABLE HASHES
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

                [PSCustomObject]@{
                    FilePath     = $path
                    Length       = $file.Length
                    LastWriteTime = $file.LastWriteTime.ToString("o")
                    SHA256       = $hash.Hash
                    Status       = "Success"
                }
            }
            catch {

                [PSCustomObject]@{
                    FilePath      = $path
                    Length        = $null
                    LastWriteTime = $null
                    SHA256        = $null
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
# 17. OPTIONAL ACTIVE NETWORK DISCOVERY
# ============================================================================

if ($NetworkSweep) {

    Invoke-FledgeCollector "Router Ping" {

        if ($Gateway) {

            Test-Connection `
                -ComputerName $Gateway `
                -Count 3 `
                -ErrorAction Continue |
                Format-Table -AutoSize |
                Out-String -Width 4096 |
                Set-Content `
                    (Join-Path $NetworkDir "router_ping_$timestamp.txt") `
                    -Encoding UTF8
        }
        else {
            Write-FledgeLog "No IPv4 default gateway identified. Router ping skipped." "WARN"
        }
    }

    Invoke-FledgeCollector "Active Network Sweep" {

        if (-not $PrimaryInterfaceIndex) {
            throw "Primary interface could not be determined."
        }

        $primaryAddress = Get-NetIPAddress `
            -InterfaceIndex $PrimaryInterfaceIndex `
            -AddressFamily IPv4 `
            -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike "169.254.*"
            } |
            Select-Object -First 1

        if (-not $primaryAddress) {
            throw "No IPv4 address identified for primary interface."
        }

        if ($primaryAddress.PrefixLength -ne 24) {

            Write-FledgeLog (
                "Active network sweep skipped because the primary IPv4 " +
                "prefix is /$($primaryAddress.PrefixLength), not /24. " +
                "Automatic CIDR enumeration is intentionally not assumed."
            ) "WARN"
        }
        else {

            $octets = $primaryAddress.IPAddress.Split(".")

            $subnet = "{0}.{1}.{2}" -f `
                $octets[0],
                $octets[1],
                $octets[2]

            $sweepFile = Join-Path `
                $NetworkDir `
                "active_network_sweep_$timestamp.csv"

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
                Export-Csv `
                    -Path $sweepFile `
                    -NoTypeInformation `
                    -Encoding UTF8
        }
    }

    Invoke-FledgeCollector "Neighbor Cache - Post Sweep" {

        Get-NetNeighbor -ErrorAction Stop |
            Select-Object `
                ifIndex,
                IPAddress,
                LinkLayerAddress,
                State,
                Store |
            Export-Csv `
                -Path (
                    Join-Path `
                        $NetworkDir `
                        "neighbor_cache_post_$timestamp.csv"
                ) `
                -NoTypeInformation `
                -Encoding UTF8

        & arp -a 2>&1 |
            Set-Content `
                (Join-Path $NetworkDir "arp_native_post_$timestamp.txt") `
                -Encoding UTF8
    }
}

# ============================================================================
# 18. COLLECTOR / DEPENDENCY HASHES
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
            SHA256       = $scriptHash.Hash
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
                    SHA256       = $hash.Hash
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
# 19. COLLECTION END METADATA
# ============================================================================

$CollectionEnd = Get-Date
$CollectionDuration = $CollectionEnd - $CollectionStart

Invoke-FledgeCollector "Finalize Collection Metadata" {

    $metadataPath = Join-Path $SystemDir "collection_metadata_$timestamp.txt"

    @(
        ""
        "CollectionEndLocal: $($CollectionEnd.ToString('o'))"
        "CollectionEndUTC: $($CollectionEnd.ToUniversalTime().ToString('o'))"
        "CollectionDurationSeconds: $([math]::Round($CollectionDuration.TotalSeconds, 2))"
    ) |
        Add-Content `
            -Path $metadataPath `
            -Encoding UTF8
}


# ============================================================================
# 20. HASH ALL GENERATED EVIDENCE
#
# Must occur LAST! Completed artifacts contained in the hash manifest.
# ============================================================================

Invoke-FledgeCollector "Evidence SHA256 Manifest" {

    $hashCsv = Join-Path `
        $HashesDir `
        "evidence_hashes_SHA256_$timestamp.csv"

    $files = Get-ChildItem `
        -Path $outputDir `
        -File `
        -Recurse |
        Where-Object {
            $_.FullName -ne $hashCsv
        }

    $rows = foreach ($file in $files) {

        try {

            $hash = Get-FileHash `
                -Path $file.FullName `
                -Algorithm SHA256 `
                -ErrorAction Stop

            $relativePath = $file.FullName.Substring(
                $outputDir.Length
            ).TrimStart('\')

            [PSCustomObject]@{
                FileName     = $file.Name
                RelativePath = $relativePath
                Length       = $file.Length
                SHA256       = $hash.Hash
            }
        }
        catch {

            Write-FledgeLog (
                "Unable to hash evidence file: $($file.FullName) - " +
                $_.Exception.Message
            ) "ERROR"
        }
    }

    $rows |
        Export-Csv `
            -Path $hashCsv `
            -NoTypeInformation `
            -Encoding UTF8

    # Hash the completed hash manifest itself.
    $manifestHash = Get-FileHash `
        -Path $hashCsv `
        -Algorithm SHA256

    @(
        "SHA256"
        "======"
        ""
        "File: $($manifestHash.Path)"
        "Hash: $($manifestHash.Hash)"
    ) |
        Set-Content `
            -Path (
                Join-Path `
                    $HashesDir `
                    "evidence_manifest_SHA256_$timestamp.txt"
            ) `
            -Encoding UTF8
}

# ============================================================================
# COMPLETE
# ============================================================================

$FinalEnd = Get-Date
$TotalDuration = $FinalEnd - $CollectionStart

Write-FledgeLog "FLEDGE collection completed."
Write-FledgeLog (
    "Total runtime: {0:N2} seconds" -f $TotalDuration.TotalSeconds
)

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host " COLLECTION COMPLETE" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "Evidence location:"
Write-Host " $outputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Duration:"
Write-Host (" {0:N2} seconds" -f $TotalDuration.TotalSeconds)
Write-Host ""

if (-not $IsAdmin) {
    Write-Host "WARNING: FLEDGE was not executed with administrative privileges." `
        -ForegroundColor DarkYellow
    Write-Host "Some collected artifacts may be incomplete." `
        -ForegroundColor DarkYellow
    Write-Host ""
}

if ($NetworkSweep) {
    Write-Host "NOTE: Active network discovery was enabled." `
        -ForegroundColor DarkYellow
    Write-Host "The network sweep may have modified the local neighbor/ARP cache." `
        -ForegroundColor DarkYellow
    Write-Host ""
}

Write-Host "Verify the SHA256 manifest before analysis or copying." `
    -ForegroundColor DarkGray

Write-Host ""
