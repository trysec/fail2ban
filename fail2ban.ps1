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
    [string]$IgnoreIPs = ""
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
    LogName                       = "OpenSSH/Operational"
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
    Write-Host ""
    Write-Host "Windows mode monitors OpenSSH failed login events and blocks source IPs with Windows Firewall."
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

function SAVE_CONFIG {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    ENSURE_BASE_DIR
    $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $CONFIG_PATH -Encoding UTF8
}

function LOAD_STATE {
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

    return $state
}

function SAVE_STATE {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    ENSURE_BASE_DIR

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

function ENSURE_OPENSSH_LOG {
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

function TEST_FAILURE_MESSAGE {
    param(
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }

    $normalized = $Message.ToLowerInvariant()

    if ($normalized -match "accepted password|accepted publickey|session opened|starting session|subsystem request") {
        return $false
    }

    $knownPatterns = @(
        "(?i)failed password for(?: invalid user)? .+ from [0-9a-f:\.]+",
        "(?i)failed publickey for(?: invalid user)? .+ from [0-9a-f:\.]+",
        "(?i)invalid user .+ from [0-9a-f:\.]+",
        "(?i)maximum authentication attempts exceeded for(?: invalid user)? .+ from [0-9a-f:\.]+",
        "(?i)pam: authentication failure for .+ from [0-9a-f:\.]+"
    )

    foreach ($pattern in $knownPatterns) {
        if ($normalized -match $pattern) {
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
        [psobject]$Event,

        [Parameter(Mandatory = $true)]
        [hashtable]$EventData
    )

    if (TEST_FAILURE_MESSAGE -Message $Event.Message) {
        return $true
    }

    foreach ($key in @("payload", "message")) {
        if ($EventData.ContainsKey($key) -and (TEST_FAILURE_MESSAGE -Message $EventData[$key])) {
            return $true
        }
    }

    return $false
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

    $message = [string]$Event.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = $Event.ToXml()
    }

    $match = [regex]::Match($message, "(?im)\bfrom\s+(?<ip>[0-9a-f:\.]+)\b")
    if ($match.Success) {
        $candidate = $match.Groups["ip"].Value
        if (TEST_IP_ADDRESS -Candidate $candidate) {
            return $candidate
        }
    }

    $allCandidates = [regex]::Matches($message, "(?im)(?<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}))")
    foreach ($candidateMatch in $allCandidates) {
        $candidate = $candidateMatch.Groups["ip"].Value
        if (TEST_IP_ADDRESS -Candidate $candidate) {
            return $candidate
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
        if (-not (TEST_FAILURE_EVENT -Event $event -EventData $eventData)) {
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

    return @($entries | Sort-Object IP -Unique)
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
        -Description "Fail2Ban-like SSH brute-force protection for Windows OpenSSH." `
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

    $thresholdValue = GET_NUMERIC_SETTING -ProvidedValue $Threshold -Prompt "Allowed SSH failures before ban" -DefaultValue ([int]$DEFAULT_CONFIG.Threshold)
    $banHoursValue = GET_NUMERIC_SETTING -ProvidedValue $BanHours -Prompt "Ban duration in hours" -DefaultValue ([int]$DEFAULT_CONFIG.BanHours)
    $findTimeValue = GET_NUMERIC_SETTING -ProvidedValue $FindTimeMinutes -Prompt "Failure window in minutes" -DefaultValue ([int]$DEFAULT_CONFIG.FindTimeMinutes)
    $intervalValue = GET_NUMERIC_SETTING -ProvidedValue $TaskIntervalMinutes -Prompt "Scan interval in minutes" -DefaultValue ([int]$DEFAULT_CONFIG.TaskIntervalMinutes)
    $minimumFailureIntervalValue = GET_NUMERIC_SETTING -ProvidedValue $MinimumFailureIntervalSeconds -Prompt "Minimum seconds between counted failures from the same IP" -DefaultValue ([int]$DEFAULT_CONFIG.MinimumFailureIntervalSeconds)
    $ignoreIPsValue = GET_LIST_SETTING -Prompt "Ignore IP list, comma separated" -DefaultValues @($DEFAULT_CONFIG.IgnoreIPs) -ProvidedValue $IgnoreIPs

    ENSURE_OPENSSH_LOG -LogName $DEFAULT_CONFIG.LogName
    INSTALL_SCRIPT_BINARY

    $config = [pscustomobject][ordered]@{
        Threshold                     = $thresholdValue
        BanHours                      = $banHoursValue
        FindTimeMinutes               = $findTimeValue
        TaskIntervalMinutes           = $intervalValue
        MinimumFailureIntervalSeconds = $minimumFailureIntervalValue
        LogName                       = $DEFAULT_CONFIG.LogName
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

    $sshdService = Get-Service sshd -ErrorAction SilentlyContinue
    if ($null -eq $sshdService) {
        WRITE_LOG -Message "Installed, but sshd service was not found. Install Windows OpenSSH Server to make blocking effective." -Level "WARN"
    }
    else {
        WRITE_LOG -Message ("Detected sshd service with status {0}." -f $sshdService.Status)
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

    $sshdService = Get-Service sshd -ErrorAction SilentlyContinue

    Write-Host "Config"
    Write-Host "Threshold: $($config.Threshold)"
    Write-Host "BanHours: $($config.BanHours)"
    Write-Host "FindTimeMinutes: $($config.FindTimeMinutes)"
    Write-Host "TaskIntervalMinutes: $($config.TaskIntervalMinutes)"
    Write-Host "MinimumFailureIntervalSeconds: $($config.MinimumFailureIntervalSeconds)"
    Write-Host "LogName: $($config.LogName)"
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

    if ($null -eq $sshdService) {
        Write-Host "sshd: not installed"
    }
    else {
        Write-Host "sshd: $($sshdService.Status)"
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

function VIEW_RUN_LOG {
    ASSERT_INSTALLED
    Write-Host "Watching $LOG_PATH"
    Get-Content -LiteralPath $LOG_PATH -Wait -Tail 50
}

function SHOW_MORE {
    Write-Host "References"
    Write-Host "https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse"
    Write-Host "https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule"
    Write-Host ""
    Write-Host "Files"
    Write-Host "Config: $CONFIG_PATH"
    Write-Host "State:  $STATE_PATH"
    Write-Host "Log:    $LOG_PATH"
    Write-Host ""
    Write-Host "Useful commands"
    Write-Host "Get-WinEvent -LogName OpenSSH/Operational -MaxEvents 20"
    Write-Host "Get-ScheduledTask -TaskName Fail2BanWin-Monitor"
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
