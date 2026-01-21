#!/usr/bin/env pwsh
# Build liboqs as a shared library for .NET interop

param(
    [string]$Configuration = "Release",
    [string]$OutputDir = ".\src\native",
    [string]$Platform = "x64"
)

Write-Host "Building liboqs as shared library for .NET ($Platform)..." -ForegroundColor Green

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Navigate to liboqs source
Push-Location "liboqs"

try {
    # Create build directory
    $buildDir = "build-dotnet-shared"
    if (Test-Path $buildDir) {
        Remove-Item -Recurse -Force $buildDir
    }
    New-Item -ItemType Directory -Path $buildDir | Out-Null
    
    Push-Location $buildDir
    
    try {
        Write-Host "Configuring CMake for shared library build..." -ForegroundColor Yellow
        
        # Configure with shared library options
        $cmakeArgs = @(
            ".."
            "-DCMAKE_BUILD_TYPE=$Configuration"
            "-DBUILD_SHARED_LIBS=ON"
            "-DOQS_BUILD_ONLY_LIB=ON"
            "-DOQS_DIST_BUILD=YES"
            "-DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON"
        )
        
        # Add platform-specific configuration for ARM64
        if ($Platform -eq "ARM64") {
            $cmakeArgs += "-A", "ARM64"
        } elseif ($Platform -eq "x64") {
            $cmakeArgs += "-A", "x64"
        }
        
        # Add algorithm selections - enable common algorithms for demo
        $cmakeArgs += @(
            "-DOQS_ENABLE_KEM_ML_KEM=ON"
            "-DOQS_ENABLE_KEM_KYBER=ON"
            "-DOQS_ENABLE_KEM_FRODOKEM=ON"
            "-DOQS_ENABLE_KEM_HQC=ON"
            "-DOQS_ENABLE_KEM_NTRU=ON"
            "-DOQS_ENABLE_KEM_NTRUPRIME=ON"
            "-DOQS_ENABLE_KEM_CLASSIC_MCELIECE=ON"
            "-DOQS_ENABLE_SIG_ML_DSA=ON"
            "-DOQS_ENABLE_SIG_SLH_DSA=ON"
            "-DOQS_ENABLE_SIG_SNOVA=ON"
            "-DOQS_ENABLE_SIG_FALCON=ON"
            "-DOQS_ENABLE_SIG_SPHINCS=ON"
            "-DOQS_ENABLE_SIG_MAYO=ON"
            "-DOQS_ENABLE_SIG_CROSS=ON"
            "-DOQS_ENABLE_SIG_UOV=ON"
        )
        
        & cmake @cmakeArgs
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configuration failed"
        }
        
        Write-Host "Building liboqs..." -ForegroundColor Yellow
        & cmake --build . --config $Configuration
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed"
        }
        
        # Find the built DLL
        $dllPath = Get-ChildItem -Recurse -Filter "oqs.dll" | Select-Object -First 1
        if (-not $dllPath) {
            # Try in src directory for different build layouts
            $dllPath = Get-ChildItem -Path "src" -Recurse -Filter "oqs.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        
        if ($dllPath) {
            # Get the script directory to build absolute paths
            $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
            
            $targetPath = Join-Path $scriptDir $OutputDir
            # Ensure target directory exists
            New-Item -ItemType Directory -Force -Path $targetPath | Out-Null
            
            Copy-Item $dllPath.FullName -Destination $targetPath -Force
            Write-Host "Successfully copied oqs.dll to $targetPath" -ForegroundColor Green
        } else {
            Write-Host "Warning: Could not find oqs.dll in build output" -ForegroundColor Yellow
            Write-Host "Build contents:" -ForegroundColor Yellow
            Get-ChildItem -Recurse | Format-Table Name, FullName -AutoSize
        }
        
    } finally {
        Pop-Location
    }
    
} finally {
    Pop-Location
}

Write-Host "Build complete!" -ForegroundColor Green
