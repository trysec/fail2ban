param(
    [switch]$Uninstall,
    [int]$Threshold = 0,
    [int]$BanHours = 0,
    [int]$FindTimeMinutes = 0,
    [int]$TaskIntervalMinutes = 0,
    [int]$MinimumFailureIntervalSeconds = 0,
    [string]$IgnoreIPs = "",
    [string]$AllowedLogonTypes = "",
    [switch]$DisableAccountLockout
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repoScriptUrl = "https://raw.githubusercontent.com/trysec/fail2ban/master/fail2ban.ps1"
$downloadedScript = Join-Path $env:TEMP "fail2ban.ps1"
$expectedScriptSha256 = "92477cb777b414f3257279374125209d050ebffd1f0c1fd130933fcb215229e2"

Invoke-WebRequest $repoScriptUrl -OutFile $downloadedScript
$actualScriptSha256 = (Get-FileHash -LiteralPath $downloadedScript -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualScriptSha256 -ne $expectedScriptSha256) {
    throw "Downloaded fail2ban.ps1 SHA256 mismatch. Expected $expectedScriptSha256, got $actualScriptSha256."
}

$commandName = if ($Uninstall) { "uninstall" } else { "install" }
$argumentList = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $downloadedScript,
    $commandName
)

if ($Threshold -gt 0) {
    $argumentList += @("-Threshold", $Threshold)
}

if ($BanHours -gt 0) {
    $argumentList += @("-BanHours", $BanHours)
}

if ($FindTimeMinutes -gt 0) {
    $argumentList += @("-FindTimeMinutes", $FindTimeMinutes)
}

if ($TaskIntervalMinutes -gt 0) {
    $argumentList += @("-TaskIntervalMinutes", $TaskIntervalMinutes)
}

if ($MinimumFailureIntervalSeconds -gt 0) {
    $argumentList += @("-MinimumFailureIntervalSeconds", $MinimumFailureIntervalSeconds)
}

if (-not [string]::IsNullOrWhiteSpace($IgnoreIPs)) {
    $argumentList += @("-IgnoreIPs", $IgnoreIPs)
}

if (-not [string]::IsNullOrWhiteSpace($AllowedLogonTypes)) {
    $argumentList += @("-AllowedLogonTypes", $AllowedLogonTypes)
}

if ($DisableAccountLockout) {
    $argumentList += "-DisableAccountLockout"
}

$process = Start-Process -FilePath "powershell.exe" -ArgumentList $argumentList -Wait -PassThru
$global:LASTEXITCODE = $process.ExitCode

$scriptPath = $null
$myCommand = $MyInvocation.MyCommand
if ($null -ne $myCommand) {
    $pathProperty = $myCommand.PSObject.Properties["Path"]
    if ($null -ne $pathProperty) {
        $scriptPath = $pathProperty.Value
    }
}

if (-not [string]::IsNullOrWhiteSpace($scriptPath)) {
    exit $process.ExitCode
}

return $process.ExitCode
