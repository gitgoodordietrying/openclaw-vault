# openclaw-VAULT: Kill Switch (Windows PowerShell)
# Usage: .\scripts\kill.ps1 -Mode soft|hard|nuclear

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("soft", "hard", "nuclear")]
    [string]$Mode
)

$ErrorActionPreference = "Stop"
$VaultDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$VaultDir = Split-Path -Parent $PSScriptRoot

# Detect runtime
$Runtime = if (Get-Command podman -ErrorAction SilentlyContinue) { "podman" } else { "docker" }

switch ($Mode) {
    "soft" {
        Write-Host "[SOFT KILL] Graceful shutdown..." -ForegroundColor Yellow
        Push-Location $VaultDir
        & $Runtime compose stop
        Pop-Location
        Write-Host "[+] Containers stopped. Workspace preserved for forensic review." -ForegroundColor Green
        Write-Host "    Inspect: $Runtime logs openclaw-vault"
        Write-Host "    Inspect: $Runtime logs vault-proxy"
    }

    "hard" {
        Write-Host "[HARD KILL] Force removing all vault resources..." -ForegroundColor Red
        Push-Location $VaultDir
        & $Runtime compose kill 2>$null
        & $Runtime compose down --volumes --remove-orphans 2>$null
        Pop-Location

        # Docker sandbox cleanup
        if ($Runtime -eq "docker") {
            & docker sandbox rm openclaw-vault 2>$null
        }

        & $Runtime rmi openclaw-vault 2>$null
        & $Runtime network prune -f 2>$null
        & $Runtime volume prune -f 2>$null

        Write-Host "[+] All vault containers, volumes, networks, and images removed." -ForegroundColor Green
    }

    "nuclear" {
        Write-Host "[NUCLEAR KILL] Destroying isolation boundary..." -ForegroundColor Magenta

        # Terminate WSL distro
        Write-Host "  Terminating WSL distro 'openclaw-vault'..."
        wsl --terminate openclaw-vault 2>$null
        Write-Host "  To fully unregister: wsl --unregister openclaw-vault"

        # Stop Hyper-V VM
        Write-Host "  Stopping Hyper-V VM 'openclaw-vault'..."
        try {
            Stop-VM -Name "openclaw-vault" -TurnOff -Force -ErrorAction SilentlyContinue
            Write-Host "  To fully remove: Remove-VM -Name 'openclaw-vault' -Force"
        }
        catch {
            Write-Host "  No Hyper-V VM found (expected if Phase 2 not deployed)."
        }

        # Also hard kill containers
        & $PSCommandPath -Mode hard

        Write-Host ""
        Write-Host "[+] NUCLEAR KILL complete. All vault infrastructure destroyed." -ForegroundColor Green
    }
}
