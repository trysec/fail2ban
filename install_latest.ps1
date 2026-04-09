param(
    [switch]$Uninstall,
    [int]$Threshold = 0,
    [int]$BanHours = 0,
    [int]$FindTimeMinutes = 0,
    [int]$TaskIntervalMinutes = 0,
    [int]$MinimumFailureIntervalSeconds = 0,
    [string]$IgnoreIPs = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repoScriptUrl = "https://raw.githubusercontent.com/trysec/fail2ban/master/fail2ban.ps1"
$downloadedScript = Join-Path $env:TEMP "fail2ban.ps1"

Invoke-WebRequest $repoScriptUrl -OutFile $downloadedScript

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

$process = Start-Process -FilePath "powershell.exe" -ArgumentList $argumentList -Wait -PassThru
exit $process.ExitCode
