param(
    [Parameter(Position = 0)]
    [string]$Command = "",

    [Parameter(Position = 1)]
    [string]$Value = "",

    [int]$Threshold = 0,
    [int]$BanHours = 0,
    [int]$FindTimeMinutes = 0,
    [int]$TaskIntervalMinutes = 0,
    [int]$MinimumFailureIntervalSeconds = 0,
    [string]$IgnoreIPs = "",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BASE_DIR = Join-Path $env:ProgramData "Fail2BanWin"
$CONFIG_PATH = Join-Path $BASE_DIR "config.json"
$STATE_PATH = Join-Path $BASE_DIR "state.json"
$LOG_PATH = Join-Path $BASE_DIR "monitor.log"
$LOCK_PATH = Join-Path $BASE_DIR "monitor.lock"
$INSTALLED_SCRIPT_PATH = Join-Path $BASE_DIR "fail2ban.ps1"

$DEFAULT_CONFIG = [ordered]@{
    Threshold                     = 10
    BanHours                      = 8760
    FindTimeMinutes               = 60
    TaskIntervalMinutes           = 1
    MinimumFailureIntervalSeconds = 1
    LogName                       = "Security"
    EventId                       = 4625
    AllowedLogonTypes             = @("10")
    RuleGroup                     = "Fail2Ban Windows"
    RulePrefix                    = "Fail2BanWin-Block"
    TaskName                      = "Fail2BanWin-Monitor"
    IgnoreIPs                     = @("127.0.0.1", "::1")
    InstalledScriptPath           = $INSTALLED_SCRIPT_PATH
}

function SHOW_USAGE {
    Write-Host "powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 {install|uninstall|runlog|more}"
    Write-Host "powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 {start|stop|restart|status}"
    Write-Host "powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 {blocklist|bl|unlock|ul} [ip]"
    Write-Host "powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 whitelist {list|add|remove} [ip]"
    Write-Host "powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 config {show|set} [key] [value]"
    Write-Host ""
    Write-Host "Windows mode monitors failed RDP login events and blocks source IPs with Windows Firewall."
}

function ENSURE_BASE_DIR {
    if (-not (Test-Path -LiteralPath $BASE_DIR)) {
        New-Item -ItemType Directory -Path $BASE_DIR -Force | Out-Null
    }
}

function WRITE_LOG {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Level = "INFO",

        [switch]$Silent
    )

    ENSURE_BASE_DIR

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level.ToUpperInvariant(), $Message
    Add-Content -LiteralPath $LOG_PATH -Value $line

    if (-not $Silent) {
        Write-Host $line
    }
}

function ASSERT_ADMIN {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required for this command."
    }
}

function TEST_POSITIVE_INT {
    param(
        [string]$Candidate,
        [ref]$ParsedValue
    )

    $value = 0
    if ([int]::TryParse($Candidate, [ref]$value) -and $value -gt 0) {
        $ParsedValue.Value = $value
        return $true
    }

    return $false
}

function GET_NUMERIC_SETTING {
    param(
        [int]$ProvidedValue,
        [string]$Prompt,
        [int]$DefaultValue
    )

    if ($ProvidedValue -gt 0) {
        return $ProvidedValue
    }

    while ($true) {
        $inputValue = Read-Host "$Prompt, default $DefaultValue"
        if ([string]::IsNullOrWhiteSpace($inputValue)) {
            return $DefaultValue
        }

        $parsedValue = 0
        if (TEST_POSITIVE_INT -Candidate $inputValue -ParsedValue ([ref]$parsedValue)) {
            return $parsedValue
        }

        Write-Host "Error: please enter a positive integer."
    }
}

function CONVERT_TO_STRING_ARRAY {
    param(
        [string]$Value,
        [string[]]$DefaultValues = @()
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @($DefaultValues)
    }

    $items = $Value -split "[,\s;]+" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    return @($items | Select-Object -Unique)
}

function GET_LIST_SETTING {
    param(
        [string]$Prompt,
        [string[]]$DefaultValues,
        [string]$ProvidedValue
    )

    if (-not [string]::IsNullOrWhiteSpace($ProvidedValue)) {
        return CONVERT_TO_STRING_ARRAY -Value $ProvidedValue -DefaultValues $DefaultValues
    }

    $defaultText = ($DefaultValues -join ", ")
    $inputValue = Read-Host "$Prompt, default $defaultText"
    return CONVERT_TO_STRING_ARRAY -Value $inputValue -DefaultValues $DefaultValues
}

function ASSERT_VALID_IP_LIST {
    param(
        [string[]]$IPs
    )

    foreach ($ip in @($IPs)) {
        if (-not (TEST_IP_ADDRESS -Candidate $ip)) {
            throw "Invalid IP address: $ip"
        }
    }
}

function NEW_DEFAULT_STATE {
    return [pscustomobject]@{
        BlockedIPs      = @()
        RecentFailures  = @()
        LastScanAt      = $null
    }
}

function MERGE_WITH_DEFAULTS {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$SourceObject,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Defaults
    )

    $result = [ordered]@{}

    foreach ($key in $Defaults.Keys) {
        if ($SourceObject.PSObject.Properties.Name -contains $key -and $null -ne $SourceObject.$key) {
            $result[$key] = $SourceObject.$key
        }
        else {
            $result[$key] = $Defaults[$key]
        }
    }

    return [pscustomobject]$result
}

function LOAD_CONFIG {
    if (-not (Test-Path -LiteralPath $CONFIG_PATH)) {
        return [pscustomobject]$DEFAULT_CONFIG
    }

    $raw = Get-Content -LiteralPath $CONFIG_PATH -Raw
    $config = $raw | ConvertFrom-Json
    return MERGE_WITH_DEFAULTS -SourceObject $config -Defaults $DEFAULT_CONFIG
}

function GET_OPTIONAL_PROPERTY_VALUE {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function NORMALIZE_DATETIME_STRING {
    param(
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $parsed = $null
    if ([datetime]::TryParse($text, [ref]$parsed)) {
        return $parsed.ToString("o")
    }

    return $null
}

function NORMALIZE_BLOCK_ENTRY {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [object]$Entry
    )

    if ($null -eq $Entry) {
        return $null
    }

    $ip = if ($Entry -is [string]) {
        [string]$Entry
    }
    else {
        [string](GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "IP")
    }

    if (-not (TEST_IP_ADDRESS -Candidate $ip)) {
        return $null
    }

    $ruleName = [string](GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "RuleName")
    if ([string]::IsNullOrWhiteSpace($ruleName)) {
        $ruleName = GET_RULE_NAME -Config $Config -IP $ip
    }

    $blockedAt = NORMALIZE_DATETIME_STRING -Value (GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "BlockedAt")
    if ($null -eq $blockedAt) {
        $blockedAt = (Get-Date).ToString("o")
    }

    $expiresAt = NORMALIZE_DATETIME_STRING -Value (GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "ExpiresAt")
    if ($null -eq $expiresAt) {
        $expiresAt = NORMALIZE_DATETIME_STRING -Value (GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "Expires")
    }
    if ($null -eq $expiresAt) {
        $expiresAt = ([datetime]$blockedAt).AddHours([int]$Config.BanHours).ToString("o")
    }

    return [pscustomobject]@{
        IP        = $ip
        RuleName  = $ruleName
        BlockedAt = $blockedAt
        ExpiresAt = $expiresAt
    }
}

function NORMALIZE_FAILURE_ENTRY {
    param(
        [object]$Entry
    )

    if ($null -eq $Entry) {
        return $null
    }

    $ip = if ($Entry -is [string]) {
        [string]$Entry
    }
    else {
        [string](GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "IP")
    }

    if (-not (TEST_IP_ADDRESS -Candidate $ip)) {
        return $null
    }

    $occurredAt = NORMALIZE_DATETIME_STRING -Value (GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "OccurredAt")
    if ($null -eq $occurredAt) {
        $occurredAt = NORMALIZE_DATETIME_STRING -Value (GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "TimeCreated")
    }
    if ($null -eq $occurredAt) {
        return $null
    }

    return [pscustomobject]@{
        IP         = $ip
        OccurredAt = $occurredAt
        RecordId   = GET_OPTIONAL_PROPERTY_VALUE -Object $Entry -PropertyName "RecordId"
    }
}

function NORMALIZE_STATE {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    $normalizedBlocked = @()
    foreach ($entry in @($State.BlockedIPs)) {
        $normalizedEntry = NORMALIZE_BLOCK_ENTRY -Config $Config -Entry $entry
        if ($null -ne $normalizedEntry) {
            $normalizedBlocked += $normalizedEntry
        }
    }

    $normalizedFailures = @()
    foreach ($entry in @($State.RecentFailures)) {
        $normalizedEntry = NORMALIZE_FAILURE_ENTRY -Entry $entry
        if ($null -ne $normalizedEntry) {
            $normalizedFailures += $normalizedEntry
        }
    }

    $State.BlockedIPs = $normalizedBlocked
    $State.RecentFailures = $normalizedFailures
    $State.LastScanAt = NORMALIZE_DATETIME_STRING -Value $State.LastScanAt
}

function SAVE_CONFIG {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    ENSURE_BASE_DIR
    $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $CONFIG_PATH -Encoding UTF8
}

function UPDATE_SCHEDULED_TASK_IF_NEEDED {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    $task = GET_TASK -TaskName $Config.TaskName
    if ($null -ne $task) {
        REGISTER_MONITOR_TASK -Config $Config
    }
}

function LOAD_STATE {
    param(
        [psobject]$Config = $null
    )

    if (-not (Test-Path -LiteralPath $STATE_PATH)) {
        $state = NEW_DEFAULT_STATE
        SAVE_STATE -State $state
        return $state
    }

    $raw = Get-Content -LiteralPath $STATE_PATH -Raw
    $state = $raw | ConvertFrom-Json

    if (-not ($state.PSObject.Properties.Name -contains "BlockedIPs") -or $null -eq $state.BlockedIPs) {
        $state | Add-Member -NotePropertyName "BlockedIPs" -NotePropertyValue @() -Force
    }

    if (-not ($state.PSObject.Properties.Name -contains "RecentFailures") -or $null -eq $state.RecentFailures) {
        $state | Add-Member -NotePropertyName "RecentFailures" -NotePropertyValue @() -Force
    }

    if (-not ($state.PSObject.Properties.Name -contains "LastScanAt")) {
        $state | Add-Member -NotePropertyName "LastScanAt" -NotePropertyValue $null -Force
    }

    if ($null -eq $Config) {
        if (Test-Path -LiteralPath $CONFIG_PATH) {
            $Config = LOAD_CONFIG
        }
        else {
            $Config = [pscustomobject]$DEFAULT_CONFIG
        }
    }

    NORMALIZE_STATE -Config $Config -State $state

    return $state
}

function SAVE_STATE {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State,

        [psobject]$Config = $null
    )

    ENSURE_BASE_DIR

    if ($null -eq $Config) {
        if (Test-Path -LiteralPath $CONFIG_PATH) {
            $Config = LOAD_CONFIG
        }
        else {
            $Config = [pscustomobject]$DEFAULT_CONFIG
        }
    }

    NORMALIZE_STATE -Config $Config -State $State

    $blocked = @()
    if ($null -ne $State.BlockedIPs) {
        $blocked = @($State.BlockedIPs)
    }

    $recentFailures = @()
    if ($null -ne $State.RecentFailures) {
        $recentFailures = @($State.RecentFailures)
    }

    $normalizedState = [pscustomobject]@{
        BlockedIPs     = $blocked
        RecentFailures = $recentFailures
        LastScanAt     = $State.LastScanAt
    }

    $normalizedState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $STATE_PATH -Encoding UTF8
}

function ENSURE_MONITOR_LOG {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
}

function INSTALL_SCRIPT_BINARY {
    ENSURE_BASE_DIR

    $currentScriptPath = [System.IO.Path]::GetFullPath($PSCommandPath)
    $targetScriptPath = [System.IO.Path]::GetFullPath($INSTALLED_SCRIPT_PATH)

    if (-not $currentScriptPath.Equals($targetScriptPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $currentScriptPath -Destination $targetScriptPath -Force
    }
}

function GET_RULE_NAME {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [string]$IP
    )

    return "{0}-{1}" -f $Config.RulePrefix, $IP.Replace(":", "_")
}

function TEST_IP_ADDRESS {
    param(
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return $false
    }

    $address = $null
    return [System.Net.IPAddress]::TryParse($Candidate, [ref]$address)
}

function TEST_IGNORED_IP {
    param(
        [string]$IP,
        [string[]]$IgnoreList
    )

    foreach ($ignoredIP in $IgnoreList) {
        if ($IP -eq $ignoredIP) {
            return $true
        }
    }

    return $false
}

function GET_EVENT_DATA_MAP {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Event
    )

    $result = @{}

    try {
        $xml = [xml]$Event.ToXml()
        foreach ($node in @($xml.Event.EventData.Data)) {
            $name = [string]$node.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }

            $result[$name.ToLowerInvariant()] = [string]$node.'#text'
        }
    }
    catch {
    }

    return $result
}

function TEST_FAILURE_EVENT {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$Event,

        [Parameter(Mandatory = $true)]
        [hashtable]$EventData
    )

    if ($Event.Id -ne [int]$Config.EventId) {
        return $false
    }

    $logonType = ""
    if ($EventData.ContainsKey("logontype")) {
        $logonType = [string]$EventData["logontype"]
    }

    if (@($Config.AllowedLogonTypes) -notcontains $logonType) {
        return $false
    }

    return $true
}

function GET_REMOTE_IP_FROM_EVENT {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Event
    )

    $eventData = GET_EVENT_DATA_MAP -Event $Event
    foreach ($key in @("ipaddress", "address", "sourceaddress", "remoteaddress", "clientaddress")) {
        if ($eventData.ContainsKey($key)) {
            $candidate = $eventData[$key]
            if (TEST_IP_ADDRESS -Candidate $candidate) {
                return $candidate
            }
        }
    }

    return $null
}

function GET_RECENT_FAILURES {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    $windowStart = (Get-Date).AddMinutes(-1 * [int]$Config.FindTimeMinutes)
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = $Config.LogName
        StartTime = $windowStart
    } -ErrorAction SilentlyContinue

    if ($null -eq $events) {
        return @()
    }

    $failures = foreach ($event in $events) {
        $eventData = GET_EVENT_DATA_MAP -Event $event
        if (-not (TEST_FAILURE_EVENT -Config $Config -Event $event -EventData $eventData)) {
            continue
        }

        $ip = GET_REMOTE_IP_FROM_EVENT -Event $event
        if ([string]::IsNullOrWhiteSpace($ip)) {
            continue
        }

        if (TEST_IGNORED_IP -IP $ip -IgnoreList @($Config.IgnoreIPs)) {
            continue
        }

        [pscustomobject]@{
            IP         = $ip
            OccurredAt = $event.TimeCreated.ToString("o")
            RecordId   = $event.RecordId
        }
    }

    return @($failures)
}

function GET_FAILURE_KEY {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Failure
    )

    if ($Failure.PSObject.Properties.Name -contains "RecordId" -and $null -ne $Failure.RecordId -and [string]$Failure.RecordId -ne "") {
        return "record:{0}" -f $Failure.RecordId
    }

    return "fallback:{0}:{1}" -f $Failure.IP, $Failure.OccurredAt
}

function MERGE_RECENT_FAILURES {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State,

        [Parameter(Mandatory = $true)]
        [object[]]$NewFailures
    )

    $merged = @()
    $seen = @{}

    foreach ($failure in @($State.RecentFailures) + @($NewFailures)) {
        $key = GET_FAILURE_KEY -Failure $failure
        if ($seen.ContainsKey($key)) {
            continue
        }

        $seen[$key] = $true
        $merged += $failure
    }

    $State.RecentFailures = $merged
}

function REMOVE_EXPIRED_FAILURES {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    $windowStart = (Get-Date).AddMinutes(-1 * [int]$Config.FindTimeMinutes)
    $State.RecentFailures = @(
        $State.RecentFailures | Where-Object {
            [datetime]$_.OccurredAt -ge $windowStart
        }
    )
}

function GET_EFFECTIVE_FAILURE_COUNT {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [object[]]$Failures
    )

    $minimumSpacing = [timespan]::FromSeconds([int]$Config.MinimumFailureIntervalSeconds)
    $count = 0
    $lastCountedAt = $null

    foreach ($failure in @($Failures | Sort-Object { [datetime]$_.OccurredAt })) {
        $occurredAt = [datetime]$failure.OccurredAt
        if ($null -eq $lastCountedAt -or ($occurredAt - $lastCountedAt) -ge $minimumSpacing) {
            $count++
            $lastCountedAt = $occurredAt
        }
    }

    return $count
}

function PARSE_RULE_EXPIRATION {
    param(
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Description)) {
        return $null
    }

    $match = [regex]::Match($Description, "(?i)until\s+(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
    if (-not $match.Success) {
        return $null
    }

    $parsedValue = $null
    if ([datetime]::TryParse($match.Groups["ts"].Value, [ref]$parsedValue)) {
        return $parsedValue.ToString("o")
    }

    return $null
}

function GET_FIREWALL_BLOCK_ENTRIES {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    $entries = @()
    $rules = @(Get-NetFirewallRule -Group $Config.RuleGroup -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "$($Config.RulePrefix)-*"
    })

    foreach ($rule in $rules) {
        $remoteAddresses = @($rule | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress)

        foreach ($remoteAddress in $remoteAddresses) {
            if (-not (TEST_IP_ADDRESS -Candidate $remoteAddress)) {
                continue
            }

            $existingEntry = GET_BLOCK_ENTRY -State $State -IP $remoteAddress
            $expiresAt = PARSE_RULE_EXPIRATION -Description $rule.Description
            if ($null -eq $expiresAt) {
                if ($null -ne $existingEntry) {
                    $expiresAt = $existingEntry.ExpiresAt
                }
                else {
                    $expiresAt = (Get-Date).AddHours([int]$Config.BanHours).ToString("o")
                }
            }

            $blockedAt = if ($null -ne $existingEntry) {
                $existingEntry.BlockedAt
            }
            else {
                (Get-Date).ToString("o")
            }

            $entries += [pscustomobject]@{
                IP        = $remoteAddress
                RuleName  = $rule.DisplayName
                BlockedAt = $blockedAt
                ExpiresAt = $expiresAt
            }
        }
    }

    return @($entries | Group-Object IP | ForEach-Object { $_.Group | Select-Object -First 1 } | Sort-Object IP)
}

function SYNC_STATE_WITH_FIREWALL {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    $State.BlockedIPs = GET_FIREWALL_BLOCK_ENTRIES -Config $Config -State $State
}

function GET_BLOCK_ENTRY {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State,

        [Parameter(Mandatory = $true)]
        [string]$IP
    )

    foreach ($entry in @($State.BlockedIPs)) {
        if ($entry.IP -eq $IP) {
            return $entry
        }
    }

    return $null
}

function REMOVE_BLOCK_ENTRY {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State,

        [Parameter(Mandatory = $true)]
        [string]$IP
    )

    $State.BlockedIPs = @($State.BlockedIPs | Where-Object { $_.IP -ne $IP })
}

function BLOCK_IP {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$State,

        [Parameter(Mandatory = $true)]
        [string]$IP
    )

    if ($null -ne (GET_BLOCK_ENTRY -State $State -IP $IP)) {
        return
    }

    $ruleName = GET_RULE_NAME -Config $Config -IP $IP
    $expiresAt = (Get-Date).AddHours([int]$Config.BanHours)

    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($null -eq $existingRule) {
        New-NetFirewallRule `
            -Name $ruleName `
            -DisplayName $ruleName `
            -Group $Config.RuleGroup `
            -Direction Inbound `
            -Action Block `
            -RemoteAddress $IP `
            -Profile Any `
            -Description "Auto-blocked by Fail2Ban Windows until $($expiresAt.ToString("s"))" | Out-Null
    }

    $entry = [pscustomobject]@{
        IP        = $IP
        RuleName  = $ruleName
        BlockedAt = (Get-Date).ToString("o")
        ExpiresAt = $expiresAt.ToString("o")
    }

    $State.BlockedIPs = @($State.BlockedIPs) + $entry
    WRITE_LOG -Message ("Blocked IP {0} until {1}" -f $IP, $expiresAt.ToString("yyyy-MM-dd HH:mm:ss"))
}

function UNBLOCK_IP_INTERNAL {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$State,

        [Parameter(Mandatory = $true)]
        [string]$IP,

        [switch]$Silent
    )

    $ruleName = GET_RULE_NAME -Config $Config -IP $IP

    $existingRules = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRules) {
        $existingRules | Remove-NetFirewallRule
    }

    REMOVE_BLOCK_ENTRY -State $State -IP $IP

    if (-not $Silent) {
        WRITE_LOG -Message ("Unblocked IP {0}" -f $IP)
    }
    else {
        WRITE_LOG -Message ("Expired block removed for IP {0}" -f $IP) -Silent
    }
}

function REMOVE_EXPIRED_BLOCKS {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    $now = Get-Date
    foreach ($entry in @($State.BlockedIPs)) {
        if ([datetime]$entry.ExpiresAt -le $now) {
            UNBLOCK_IP_INTERNAL -Config $Config -State $State -IP $entry.IP -Silent
        }
    }
}

function TRY_ACQUIRE_SCAN_LOCK {
    ENSURE_BASE_DIR

    try {
        $script:ScanLockStream = [System.IO.File]::Open($LOCK_PATH, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        return $true
    }
    catch {
        return $false
    }
}

function RELEASE_SCAN_LOCK {
    if ($null -ne $script:ScanLockStream) {
        $script:ScanLockStream.Close()
        $script:ScanLockStream.Dispose()
        $script:ScanLockStream = $null
    }

    if (Test-Path -LiteralPath $LOCK_PATH) {
        Remove-Item -LiteralPath $LOCK_PATH -Force -ErrorAction SilentlyContinue
    }
}

function REGISTER_MONITOR_TASK {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($Config.InstalledScriptPath)`" scan"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes ([int]$Config.TaskIntervalMinutes)) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask `
        -TaskName $Config.TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Fail2Ban-like RDP brute-force protection for Windows." `
        -Force | Out-Null
}

function GET_TASK {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )

    return Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

function ASSERT_INSTALLED {
    if (-not (Test-Path -LiteralPath $CONFIG_PATH)) {
        throw "Fail2Ban Windows is not installed. Run install first."
    }
}

function INSTALL_FAIL2BAN_WINDOWS {
    ASSERT_ADMIN

    ENSURE_BASE_DIR

    $thresholdValue = GET_NUMERIC_SETTING -ProvidedValue $Threshold -Prompt "Allowed RDP failures before ban" -DefaultValue ([int]$DEFAULT_CONFIG.Threshold)
    $banHoursValue = GET_NUMERIC_SETTING -ProvidedValue $BanHours -Prompt "Ban duration in hours" -DefaultValue ([int]$DEFAULT_CONFIG.BanHours)
    $findTimeValue = GET_NUMERIC_SETTING -ProvidedValue $FindTimeMinutes -Prompt "Failure window in minutes" -DefaultValue ([int]$DEFAULT_CONFIG.FindTimeMinutes)
    $intervalValue = GET_NUMERIC_SETTING -ProvidedValue $TaskIntervalMinutes -Prompt "Scan interval in minutes" -DefaultValue ([int]$DEFAULT_CONFIG.TaskIntervalMinutes)
    $minimumFailureIntervalValue = GET_NUMERIC_SETTING -ProvidedValue $MinimumFailureIntervalSeconds -Prompt "Minimum seconds between counted failures from the same IP" -DefaultValue ([int]$DEFAULT_CONFIG.MinimumFailureIntervalSeconds)
    $ignoreIPsValue = GET_LIST_SETTING -Prompt "Ignore IP list, comma separated" -DefaultValues @($DEFAULT_CONFIG.IgnoreIPs) -ProvidedValue $IgnoreIPs

    ENSURE_MONITOR_LOG -LogName $DEFAULT_CONFIG.LogName
    INSTALL_SCRIPT_BINARY

    $config = [pscustomobject][ordered]@{
        Threshold                     = $thresholdValue
        BanHours                      = $banHoursValue
        FindTimeMinutes               = $findTimeValue
        TaskIntervalMinutes           = $intervalValue
        MinimumFailureIntervalSeconds = $minimumFailureIntervalValue
        LogName                       = $DEFAULT_CONFIG.LogName
        EventId                       = $DEFAULT_CONFIG.EventId
        AllowedLogonTypes             = $DEFAULT_CONFIG.AllowedLogonTypes
        RuleGroup                     = $DEFAULT_CONFIG.RuleGroup
        RulePrefix                    = $DEFAULT_CONFIG.RulePrefix
        TaskName                      = $DEFAULT_CONFIG.TaskName
        IgnoreIPs                     = $ignoreIPsValue
        InstalledScriptPath           = $INSTALLED_SCRIPT_PATH
    }

    SAVE_CONFIG -Config $config

    if (Test-Path -LiteralPath $STATE_PATH) {
        $state = LOAD_STATE
    }
    else {
        $state = NEW_DEFAULT_STATE
    }

    SYNC_STATE_WITH_FIREWALL -Config $config -State $state
    SAVE_STATE -State $state
    REGISTER_MONITOR_TASK -Config $config

    $rdpService = Get-Service TermService -ErrorAction SilentlyContinue
    if ($null -eq $rdpService) {
        WRITE_LOG -Message "Installed, but TermService was not found. Remote Desktop protection may not be effective on this system." -Level "WARN"
    }
    else {
        WRITE_LOG -Message ("Detected TermService with status {0}." -f $rdpService.Status)
    }

    WRITE_LOG -Message "Install completed."
    START_FAIL2BAN_WINDOWS
}

function REMOVE_FAIL2BAN_WINDOWS {
    ASSERT_ADMIN

    $config = LOAD_CONFIG

    $task = GET_TASK -TaskName $config.TaskName
    if ($null -ne $task) {
        Disable-ScheduledTask -TaskName $config.TaskName | Out-Null
        Stop-ScheduledTask -TaskName $config.TaskName -ErrorAction SilentlyContinue | Out-Null
        Unregister-ScheduledTask -TaskName $config.TaskName -Confirm:$false
    }

    $rules = Get-NetFirewallRule -Group $config.RuleGroup -ErrorAction SilentlyContinue
    if ($null -ne $rules) {
        $rules | Remove-NetFirewallRule
    }

    if (Test-Path -LiteralPath $BASE_DIR) {
        $resolvedPath = (Resolve-Path -LiteralPath $BASE_DIR).Path
        if ($resolvedPath.Equals($BASE_DIR, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $BASE_DIR -Recurse -Force
        }
    }

    Write-Host "Fail2Ban Windows uninstalled."
}

function START_FAIL2BAN_WINDOWS {
    ASSERT_ADMIN
    ASSERT_INSTALLED

    $config = LOAD_CONFIG
    $state = LOAD_STATE
    SYNC_STATE_WITH_FIREWALL -Config $config -State $state
    SAVE_STATE -State $state
    $task = GET_TASK -TaskName $config.TaskName
    if ($null -eq $task) {
        REGISTER_MONITOR_TASK -Config $config
    }

    Enable-ScheduledTask -TaskName $config.TaskName | Out-Null
    Start-ScheduledTask -TaskName $config.TaskName
    WRITE_LOG -Message "Scheduled monitor started."
}

function STOP_FAIL2BAN_WINDOWS {
    ASSERT_ADMIN
    ASSERT_INSTALLED

    $config = LOAD_CONFIG
    $task = GET_TASK -TaskName $config.TaskName
    if ($null -eq $task) {
        Write-Host "Monitor task does not exist."
        return
    }

    Disable-ScheduledTask -TaskName $config.TaskName | Out-Null
    Stop-ScheduledTask -TaskName $config.TaskName -ErrorAction SilentlyContinue | Out-Null
    WRITE_LOG -Message "Scheduled monitor stopped."
}

function RESTART_FAIL2BAN_WINDOWS {
    STOP_FAIL2BAN_WINDOWS
    START_FAIL2BAN_WINDOWS
}

function SHOW_STATUS {
    if (-not (Test-Path -LiteralPath $CONFIG_PATH)) {
        Write-Host "Fail2Ban Windows is not installed."
        return
    }

    $config = LOAD_CONFIG
    $state = LOAD_STATE
    SYNC_STATE_WITH_FIREWALL -Config $config -State $state
    SAVE_STATE -State $state
    $task = GET_TASK -TaskName $config.TaskName
    $taskInfo = $null

    if ($null -ne $task) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $config.TaskName
    }

    $rdpService = Get-Service TermService -ErrorAction SilentlyContinue

    Write-Host "Config"
    Write-Host "Threshold: $($config.Threshold)"
    Write-Host "BanHours: $($config.BanHours)"
    Write-Host "FindTimeMinutes: $($config.FindTimeMinutes)"
    Write-Host "TaskIntervalMinutes: $($config.TaskIntervalMinutes)"
    Write-Host "MinimumFailureIntervalSeconds: $($config.MinimumFailureIntervalSeconds)"
    Write-Host "LogName: $($config.LogName)"
    Write-Host "EventId: $($config.EventId)"
    Write-Host "AllowedLogonTypes: $(@($config.AllowedLogonTypes) -join ', ')"
    Write-Host "IgnoreIPs: $(@($config.IgnoreIPs) -join ', ')"
    Write-Host ""
    Write-Host "Monitor"

    if ($null -eq $task) {
        Write-Host "Task: missing"
    }
    else {
        Write-Host "Task: $($task.State)"
        Write-Host "LastRunTime: $($taskInfo.LastRunTime)"
        Write-Host "LastTaskResult: $($taskInfo.LastTaskResult)"
        Write-Host "NextRunTime: $($taskInfo.NextRunTime)"
    }

    if ($null -eq $rdpService) {
        Write-Host "TermService: not installed"
    }
    else {
        Write-Host "TermService: $($rdpService.Status)"
    }

    Write-Host ""
    Write-Host "BlockedIPs: $(@($state.BlockedIPs).Count)"
    Write-Host "RecentFailures: $(@($state.RecentFailures).Count)"
}

function SHOW_BLOCKLIST {
    ASSERT_INSTALLED

    $config = LOAD_CONFIG
    $state = LOAD_STATE
    SYNC_STATE_WITH_FIREWALL -Config $config -State $state
    SAVE_STATE -State $state
    $entries = @($state.BlockedIPs | Sort-Object IP)

    if ($entries.Count -eq 0) {
        Write-Host "No blocked IPs."
        return
    }

    $entries | Select-Object IP, BlockedAt, ExpiresAt | Format-Table -AutoSize
}

function UNLOCK_IP {
    ASSERT_ADMIN
    ASSERT_INSTALLED

    $config = LOAD_CONFIG
    $state = LOAD_STATE
    SYNC_STATE_WITH_FIREWALL -Config $config -State $state

    $targetIP = $Value
    if ([string]::IsNullOrWhiteSpace($targetIP)) {
        $targetIP = Read-Host "Enter the IP to unblock"
    }

    if ([string]::IsNullOrWhiteSpace($targetIP)) {
        throw "IP address cannot be empty."
    }

    if ($targetIP -ne "all" -and -not (TEST_IP_ADDRESS -Candidate $targetIP)) {
        throw "Invalid IP address: $targetIP"
    }

    if ($targetIP -eq "all") {
        foreach ($entry in @($state.BlockedIPs)) {
            UNBLOCK_IP_INTERNAL -Config $config -State $state -IP $entry.IP
        }

        SAVE_STATE -State $state
        return
    }

    UNBLOCK_IP_INTERNAL -Config $config -State $state -IP $targetIP
    SAVE_STATE -State $state
}

function SHOW_WHITELIST {
    ASSERT_INSTALLED

    $config = LOAD_CONFIG
    $entries = @($config.IgnoreIPs | Sort-Object -Unique)

    if ($entries.Count -eq 0) {
        Write-Host "Whitelist is empty."
        return
    }

    $entries | ForEach-Object { Write-Host $_ }
}

function ADD_WHITELIST_IP {
    ASSERT_ADMIN
    ASSERT_INSTALLED

    $targetIP = $Value
    if ([string]::IsNullOrWhiteSpace($targetIP) -and $ExtraArgs.Count -gt 0) {
        $targetIP = $ExtraArgs[0]
    }

    if ([string]::IsNullOrWhiteSpace($targetIP)) {
        $targetIP = Read-Host "Enter the IP to whitelist"
    }

    ASSERT_VALID_IP_LIST -IPs @($targetIP)

    $config = LOAD_CONFIG
    $config.IgnoreIPs = @(@($config.IgnoreIPs) + $targetIP | Select-Object -Unique)
    SAVE_CONFIG -Config $config
    WRITE_LOG -Message ("Whitelisted IP {0}" -f $targetIP)
}

function REMOVE_WHITELIST_IP {
    ASSERT_ADMIN
    ASSERT_INSTALLED

    $targetIP = $Value
    if ([string]::IsNullOrWhiteSpace($targetIP) -and $ExtraArgs.Count -gt 0) {
        $targetIP = $ExtraArgs[0]
    }

    if ([string]::IsNullOrWhiteSpace($targetIP)) {
        $targetIP = Read-Host "Enter the IP to remove from whitelist"
    }

    ASSERT_VALID_IP_LIST -IPs @($targetIP)

    $config = LOAD_CONFIG
    $config.IgnoreIPs = @($config.IgnoreIPs | Where-Object { $_ -ne $targetIP })
    SAVE_CONFIG -Config $config
    WRITE_LOG -Message ("Removed whitelisted IP {0}" -f $targetIP)
}

function SHOW_CONFIG {
    ASSERT_INSTALLED
    $config = LOAD_CONFIG
    $config | ConvertTo-Json -Depth 6
}

function SET_CONFIG_VALUE {
    ASSERT_ADMIN
    ASSERT_INSTALLED

    $key = $Value
    $rawValue = $null

    if ($ExtraArgs.Count -gt 0) {
        $rawValue = ($ExtraArgs -join " ")
    }

    if ([string]::IsNullOrWhiteSpace($key)) {
        throw "Config key is required."
    }

    if ([string]::IsNullOrWhiteSpace($rawValue)) {
        $rawValue = Read-Host "Enter value for $key"
    }

    $config = LOAD_CONFIG
    $normalizedKey = $key.ToLowerInvariant()

    switch ($normalizedKey) {
        "threshold" {
            $parsed = 0
            if (-not (TEST_POSITIVE_INT -Candidate $rawValue -ParsedValue ([ref]$parsed))) {
                throw "Threshold must be a positive integer."
            }
            $config.Threshold = $parsed
        }
        "banhours" {
            $parsed = 0
            if (-not (TEST_POSITIVE_INT -Candidate $rawValue -ParsedValue ([ref]$parsed))) {
                throw "BanHours must be a positive integer."
            }
            $config.BanHours = $parsed
        }
        "findtimeminutes" {
            $parsed = 0
            if (-not (TEST_POSITIVE_INT -Candidate $rawValue -ParsedValue ([ref]$parsed))) {
                throw "FindTimeMinutes must be a positive integer."
            }
            $config.FindTimeMinutes = $parsed
        }
        "taskintervalminutes" {
            $parsed = 0
            if (-not (TEST_POSITIVE_INT -Candidate $rawValue -ParsedValue ([ref]$parsed))) {
                throw "TaskIntervalMinutes must be a positive integer."
            }
            $config.TaskIntervalMinutes = $parsed
        }
        "minimumfailureintervalseconds" {
            $parsed = 0
            if (-not (TEST_POSITIVE_INT -Candidate $rawValue -ParsedValue ([ref]$parsed))) {
                throw "MinimumFailureIntervalSeconds must be a positive integer."
            }
            $config.MinimumFailureIntervalSeconds = $parsed
        }
        "ignoreips" {
            $ips = CONVERT_TO_STRING_ARRAY -Value $rawValue -DefaultValues @()
            ASSERT_VALID_IP_LIST -IPs $ips
            $config.IgnoreIPs = @($ips | Select-Object -Unique)
        }
        default {
            throw "Unsupported config key: $key"
        }
    }

    SAVE_CONFIG -Config $config
    UPDATE_SCHEDULED_TASK_IF_NEEDED -Config $config
    WRITE_LOG -Message ("Updated config {0} = {1}" -f $key, $rawValue)
}

function VIEW_RUN_LOG {
    ASSERT_INSTALLED
    Write-Host "Watching $LOG_PATH"
    Get-Content -LiteralPath $LOG_PATH -Wait -Tail 50
}

function SHOW_MORE {
    Write-Host "References"
    Write-Host "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625"
    Write-Host "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
    Write-Host "https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule"
    Write-Host ""
    Write-Host "Supported Windows versions"
    Write-Host "Windows 10, Windows 11, Windows Server 2016/2019/2022/2025"
    Write-Host ""
    Write-Host "Files"
    Write-Host "Config: $CONFIG_PATH"
    Write-Host "State:  $STATE_PATH"
    Write-Host "Log:    $LOG_PATH"
    Write-Host ""
    Write-Host "Useful commands"
    Write-Host "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20"
    Write-Host "Get-ScheduledTask -TaskName Fail2BanWin-Monitor"
    Write-Host ".\fail2ban.ps1 whitelist list"
    Write-Host ".\fail2ban.ps1 config show"
    Write-Host ""
    Write-Host "Advanced install example"
    Write-Host ".\fail2ban.ps1 install -Threshold 8 -BanHours 24 -FindTimeMinutes 30 -MinimumFailureIntervalSeconds 3 -IgnoreIPs '127.0.0.1,::1,10.0.0.5'"
}

function INVOKE_SCAN {
    ASSERT_ADMIN

    if (-not (Test-Path -LiteralPath $CONFIG_PATH)) {
        return
    }

    if (-not (TRY_ACQUIRE_SCAN_LOCK)) {
        return
    }

    try {
        $config = LOAD_CONFIG
        $state = LOAD_STATE
        SYNC_STATE_WITH_FIREWALL -Config $config -State $state

        REMOVE_EXPIRED_BLOCKS -Config $config -State $state
        REMOVE_EXPIRED_FAILURES -Config $config -State $state

        $failures = GET_RECENT_FAILURES -Config $config
        MERGE_RECENT_FAILURES -State $state -NewFailures $failures

        $groups = @($state.RecentFailures | Group-Object -Property IP)

        foreach ($group in $groups) {
            $effectiveCount = GET_EFFECTIVE_FAILURE_COUNT -Config $config -Failures @($group.Group)
            if ($effectiveCount -lt [int]$config.Threshold) {
                continue
            }

            if ($null -ne (GET_BLOCK_ENTRY -State $state -IP $group.Name)) {
                continue
            }

            BLOCK_IP -Config $config -State $state -IP $group.Name
        }

        $state.LastScanAt = (Get-Date).ToString("o")
        SAVE_STATE -State $state
    }
    catch {
        WRITE_LOG -Message $_.Exception.Message -Level "ERROR" -Silent
        throw
    }
    finally {
        RELEASE_SCAN_LOCK
    }
}

switch ($Command.ToLowerInvariant()) {
    "install" {
        INSTALL_FAIL2BAN_WINDOWS
    }
    "uninstall" {
        REMOVE_FAIL2BAN_WINDOWS
    }
    "status" {
        SHOW_STATUS
    }
    "blocklist" {
        SHOW_BLOCKLIST
    }
    "bl" {
        SHOW_BLOCKLIST
    }
    "unlock" {
        UNLOCK_IP
    }
    "ul" {
        UNLOCK_IP
    }
    "whitelist" {
        switch ($Value.ToLowerInvariant()) {
            "list" {
                SHOW_WHITELIST
            }
            "add" {
                if ($ExtraArgs.Count -gt 0) {
                    $script:Value = $ExtraArgs[0]
                }
                ADD_WHITELIST_IP
            }
            "remove" {
                if ($ExtraArgs.Count -gt 0) {
                    $script:Value = $ExtraArgs[0]
                }
                REMOVE_WHITELIST_IP
            }
            default {
                Write-Host "Usage: .\fail2ban.ps1 whitelist {list|add|remove} [ip]"
            }
        }
    }
    "config" {
        switch ($Value.ToLowerInvariant()) {
            "show" {
                SHOW_CONFIG
            }
            "set" {
                if ($ExtraArgs.Count -lt 2) {
                    throw "Usage: .\fail2ban.ps1 config set <key> <value>"
                }
                $script:Value = $ExtraArgs[0]
                $script:ExtraArgs = @($ExtraArgs[1..($ExtraArgs.Count - 1)])
                SET_CONFIG_VALUE
            }
            default {
                Write-Host "Usage: .\fail2ban.ps1 config {show|set} [key] [value]"
            }
        }
    }
    "more" {
        SHOW_MORE
    }
    "runlog" {
        VIEW_RUN_LOG
    }
    "start" {
        START_FAIL2BAN_WINDOWS
    }
    "stop" {
        STOP_FAIL2BAN_WINDOWS
    }
    "restart" {
        RESTART_FAIL2BAN_WINDOWS
    }
    "scan" {
        INVOKE_SCAN
    }
    default {
        SHOW_USAGE
    }
}
