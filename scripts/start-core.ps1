$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Test-Path ".\target\release\cognidns.exe")) {
  cargo build --release
}

Start-Process -FilePath ".\target\release\cognidns.exe" -ArgumentList @("-vv", "agent", "--config", "config/cognidns.toml", "-d") -WorkingDirectory (Get-Location) -WindowStyle Hidden
Write-Output "core started"
