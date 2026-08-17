<#
.SYNOPSIS
    Root Browser launcher (Windows).

.DESCRIPTION
    1. Starts the root client SOCKS5 proxy in the background.
    2. Waits for the SOCKS port to actually be listening (polls, doesn't sleep-and-hope).
    3. Launches Firefox with the Root Browser profile.
    4. On browser exit, kills the background client process.

.PARAMETER RootBin
    Path to the compiled root.exe. Defaults to looking next to this script
    (..\target\release\root.exe or ..\target\debug\root.exe) or in PATH.

.PARAMETER FirefoxPath
    Path to firefox.exe. Defaults to common install locations or PATH.

.PARAMETER SocksAddr
    Address the SOCKS5 proxy should listen on. Default 127.0.0.1:9050.

.PARAMETER WaitTimeoutSec
    Seconds to wait for the SOCKS port to come up before giving up. Default 30.
#>

param(
    [string]$RootBin = "",
    [string]$FirefoxPath = "",
    [string]$SocksAddr = "127.0.0.1:9050",
    [int]$WaitTimeoutSec = 30
)

$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProfileDir = Join-Path $ScriptDir "profile"

$parts = $SocksAddr -split ":"
$SocksHost = $parts[0]
$SocksPort = [int]$parts[1]

function Log($msg)  { Write-Host "[root-browser] $msg" }
function ErrOut($msg) { Write-Host "[root-browser] ERROR: $msg" -ForegroundColor Red }

$ClientProcess = $null

function Cleanup {
    if ($null -ne $ClientProcess -and -not $ClientProcess.HasExited) {
        Log "Shutting down root client (pid $($ClientProcess.Id))..."
        try {
            Stop-Process -Id $ClientProcess.Id -Force -ErrorAction Stop
        } catch {}
    }
}

# --- Locate the root binary -------------------------------------------------
if (-not $RootBin) {
    $candidates = @(
        (Join-Path $ScriptDir "..\target\release\root.exe"),
        (Join-Path $ScriptDir "..\target\debug\root.exe")
    )
    $cmd = Get-Command "root.exe" -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }

    foreach ($c in $candidates) {
        if (Test-Path $c) { $RootBin = $c; break }
    }
}

if (-not $RootBin -or -not (Test-Path $RootBin)) {
    ErrOut "Could not find root.exe. Build it with 'cargo build --release' in the project root,"
    ErrOut "or pass -RootBin C:\path\to\root.exe."
    exit 1
}

# --- Locate Firefox ----------------------------------------------------------
if (-not $FirefoxPath) {
    $candidates = @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
        "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe"
    )
    $cmd = Get-Command "firefox.exe" -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }

    foreach ($c in $candidates) {
        if (Test-Path $c) { $FirefoxPath = $c; break }
    }
}

if (-not $FirefoxPath -or -not (Test-Path $FirefoxPath)) {
    ErrOut "Could not find firefox.exe. Pass -FirefoxPath C:\path\to\firefox.exe."
    exit 1
}

if (-not (Test-Path $ProfileDir)) {
    ErrOut "Profile directory not found: $ProfileDir"
    exit 1
}

# --- Start the client proxy ---------------------------------------------------
Log "Starting root client (SOCKS5 proxy) on $SocksAddr..."
try {
    $ClientProcess = Start-Process -FilePath $RootBin -ArgumentList @("client", "--socks-addr", $SocksAddr) -PassThru -WindowStyle Hidden
} catch {
    ErrOut "Failed to start root client: $_"
    exit 1
}

if ($ClientProcess.HasExited) {
    ErrOut "root client failed to start (exited immediately)."
    exit 1
}

# --- Wait for the SOCKS port to be listening -----------------------------------
Log "Waiting for SOCKS proxy at $SocksAddr to come up (timeout: ${WaitTimeoutSec}s)..."
$deadline = (Get-Date).AddSeconds($WaitTimeoutSec)
$portOpen = $false

while ((Get-Date) -lt $deadline) {
    if ($ClientProcess.HasExited) {
        ErrOut "root client process exited unexpectedly while waiting for the proxy port."
        exit 1
    }
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($SocksHost, $SocksPort, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne(500)
        if ($success -and $tcp.Connected) {
            $tcp.EndConnect($async)
            $portOpen = $true
            $tcp.Close()
            break
        }
        $tcp.Close()
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

if (-not $portOpen) {
    ErrOut "Timed out waiting for SOCKS proxy to listen on $SocksAddr."
    Cleanup
    exit 1
}
Log "SOCKS proxy is up."

# --- Launch Firefox -------------------------------------------------------------
Log "Launching Firefox with the Root Browser profile..."
Log "Ready. Close the browser window to shut everything down."

try {
    Start-Process -FilePath $FirefoxPath -ArgumentList @("-profile", $ProfileDir, "-no-remote") -Wait
} finally {
    Log "Firefox exited."
    Cleanup
}
