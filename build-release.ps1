# ONRouter Cross-Platform Build Script for Windows PowerShell
# Supports: Windows (x86_64, ARM64), cross-compilation info

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet("build", "clean", "matrix", "help")]
    [string]$Command = "build"
)

$ErrorActionPreference = "Stop"

$VERSION = (Select-String -Path Cargo.toml -Pattern '^version = "([^"]+)"' | Select-Object -First 1).Matches.Groups[1].Value
if (-not $VERSION) { $VERSION = git describe --tags --always --dirty 2>$null }
if (-not $VERSION) { $VERSION = "dev" }
if ($VERSION -notlike "v*") { $VERSION = "v$VERSION" }
$BUILD_DIR = "target\dist"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Check-Rust {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error-Custom "Rust/Cargo not found. Please install from https://rustup.rs/"
        exit 1
    }
}

function Install-Targets {
    Write-Info "Installing cross-compilation targets..."
    
    # Windows targets
    rustup target add x86_64-pc-windows-msvc 2>$null
    rustup target add aarch64-pc-windows-msvc 2>$null
    
    Write-Success "Targets installed"
}

function Build-Target {
    param([string]$Target)
    
    $OutputDir = "$BUILD_DIR\$Target"
    
    Write-Info "Building for $Target..."
    
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    
    # Build binaries
    cargo build --release --target $Target --bin onrouter
    cargo build --release --target $Target --bin orr-gencert
    
    # Copy binaries
    Copy-Item "target\$Target\release\onrouter.exe" "$OutputDir\" -ErrorAction SilentlyContinue
    Copy-Item "target\$Target\release\orr-gencert.exe" "$OutputDir\" -ErrorAction SilentlyContinue
    
    Write-Success "Built for $Target"
}

function Create-Archive {
    param([string]$Target)
    
    $OutputDir = "$BUILD_DIR\$Target"
    $StageDir = "$BUILD_DIR\stage-$Target"
    $ArchiveName = "onrouter-$VERSION-$Target"
    
    Write-Info "Creating archive for $Target..."
    
    New-Item -ItemType Directory -Force -Path "$BUILD_DIR\archives" | Out-Null
    if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
    New-Item -ItemType Directory -Force -Path "$StageDir\conf" | Out-Null
    New-Item -ItemType Directory -Force -Path "$StageDir\docs" | Out-Null
    
    # Binaries
    Copy-Item "$OutputDir\*.exe" "$StageDir\" -ErrorAction SilentlyContinue
    
    # Examples and docs ship with the binary: a download should be runnable, not
    # just an executable with no config. Runtime state (logs/, cache/, .tmp_*) is
    # deliberately not packaged.
    Copy-Item "conf\*.conf" "$StageDir\conf\" -ErrorAction SilentlyContinue
    foreach ($d in @("wasm", "wasm_static", "soak_static", "auth_demo", "include_demo")) {
        if (Test-Path "conf\$d") { Copy-Item -Recurse "conf\$d" "$StageDir\conf\" }
    }
    if (Test-Path "lua") { Copy-Item -Recurse "lua" "$StageDir\" }
    if (Test-Path "public") { Copy-Item -Recurse "public" "$StageDir\" }
    foreach ($doc in @("docs\OPERATIONS.md", "docs\TUTORIAL.md")) {
        if (Test-Path $doc) { Copy-Item $doc "$StageDir\docs\" }
    }
    if (Test-Path "README.md") { Copy-Item "README.md" "$StageDir\" }

    # conf/onrouter.conf ships a TLS listener; generate a throwaway pair at
    # package time so a fresh extract passes -t. No private key lives in git.
    New-Item -ItemType Directory -Force -Path "$StageDir\certs" | Out-Null
    & "$StageDir\orr-gencert.exe" "$StageDir\certs\cert.pem" "$StageDir\certs\key.pem" localhost | Out-Null
    if (-not (Test-Path "$StageDir\certs\cert.pem")) {
        Write-Warn "cert generation failed; packaged conf/onrouter.conf will need certs/ before -t"
    }
    
    Compress-Archive -Path "$StageDir\*" -DestinationPath "$BUILD_DIR\archives\$ArchiveName.zip" -Force
    
    Write-Success "Archive created: $BUILD_DIR\archives\$ArchiveName.zip"
}

function Generate-Checksums {
    Write-Info "Generating SHA256 checksums..."
    
    $ArchivesDir = "$BUILD_DIR\archives"
    Set-Location $ArchivesDir
    
    $Checksums = @()
    Get-ChildItem "*.zip" | ForEach-Object {
        $Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        $Checksums += "$Hash  $($_.Name)"
    }
    
    $Checksums | Out-File -FilePath "SHA256SUMS.txt" -Encoding ASCII
    Set-Location -Path "..\.."
    
    Write-Success "Checksums saved to $ArchivesDir\SHA256SUMS.txt"
}

function Show-Matrix {
    Write-Host ""
    Write-Host "=== ONRouter Build Matrix ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Operating Systems:"
    Write-Host "  ✓ Linux (x86_64, aarch64, armv7, riscv64)"
    Write-Host "  ✓ macOS (x86_64, aarch64/M1/M2)"
    Write-Host "  ✓ Windows (x86_64, aarch64)"
    Write-Host ""
    Write-Host "Architectures:"
    Write-Host "  • x86_64 (Intel/AMD 64-bit)"
    Write-Host "  • aarch64 (ARM 64-bit, Apple Silicon)"
    Write-Host "  • armv7 (ARM 32-bit, Raspberry Pi)"
    Write-Host "  • riscv64 (RISC-V 64-bit)"
    Write-Host ""
    Write-Host "Output Directory: $BUILD_DIR\archives\"
    Write-Host ""
}

function Build-All {
    Check-Rust
    
    Write-Info "Starting cross-platform build v$VERSION..."
    Write-Host ""
    
    Show-Matrix
    
    # Detect architecture
    $Arch = $env:PROCESSOR_ARCHITECTURE
    Write-Info "Detected architecture: $Arch"
    Write-Host ""
    
    # Build for current platform
    if ($Arch -eq "AMD64") {
        Build-Target "x86_64-pc-windows-msvc"
        Create-Archive "x86_64-pc-windows-msvc"
    } elseif ($Arch -eq "ARM64") {
        Build-Target "aarch64-pc-windows-msvc"
        Create-Archive "aarch64-pc-windows-msvc"
    } else {
        Write-Warn "Unknown architecture: $Arch, attempting x86_64 build"
        Build-Target "x86_64-pc-windows-msvc"
        Create-Archive "x86_64-pc-windows-msvc"
    }
    
    Generate-Checksums
    
    Write-Host ""
    Write-Success "Build completed successfully!"
    Write-Info "Archives available in: $BUILD_DIR\archives\"
    Write-Host ""
}

# Main
switch ($Command) {
    "build" { Build-All }
    "clean" {
        Write-Info "Cleaning build artifacts..."
        Remove-Item -Recurse -Force $BUILD_DIR -ErrorAction SilentlyContinue
        cargo clean
        Write-Success "Cleaned"
    }
    "matrix" { Show-Matrix }
    "help" {
        Write-Host "Usage: .\build-release.ps1 [command]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  build    Build for current platform (default)"
        Write-Host "  clean    Clean build artifacts"
        Write-Host "  matrix   Show supported platforms"
        Write-Host "  help     Show this help"
        Write-Host ""
        Write-Host "For full cross-compilation, use GitHub Actions."
    }
}
