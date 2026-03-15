#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for liboqs and liboqs-python dependencies on Windows.

.DESCRIPTION
    Builds liboqs from source using MSVC and installs liboqs-python.
    Equivalent of build_local_deps.sh for Windows systems.

.PARAMETER InstallPrefix
    Installation directory for liboqs. Default: C:\liboqs

.PARAMETER LiboqsVersion
    Version of liboqs to build. Default: 0.12.0

.PARAMETER LiboqsPythonVersion
    Version of liboqs-python to install. Default: 0.12.0

.PARAMETER SkipEnvSetup
    Skip adding environment variables to user profile.

.EXAMPLE
    .\build_local_deps.ps1
    .\build_local_deps.ps1 -InstallPrefix "D:\liboqs"
    .\build_local_deps.ps1 -SkipEnvSetup
#>

param(
    [string]$InstallPrefix = "C:\liboqs",
    [string]$LiboqsVersion = "0.12.0",
    [string]$LiboqsPythonVersion = "0.12.0",
    [switch]$SkipEnvSetup
)

$ErrorActionPreference = "Stop"

# ──────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────

function Write-Banner {
    param([string]$Message)
    $separator = "=" * 60
    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor DarkYellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Dependency {
    <#
    .SYNOPSIS
        Prompts the user to install a missing dependency.
        Attempts winget first, falls back to manual instructions.
        Returns $true if installation succeeded, $false if user declined or install failed.
    #>
    param(
        [string]$Name,
        [string]$WingetId,
        [string]$ManualUrl,
        [string]$ExtraInfo = ""
    )

    Write-Fail "$Name is required but not found"
    Write-Host ""

    if ($ExtraInfo) {
        Write-Host $ExtraInfo
        Write-Host ""
    }

    $hasWinget = Test-Command "winget"

    if ($hasWinget -and $WingetId) {
        $response = Read-Host "Install $Name now using winget? (y/N)"
        if ($response -match "^[Yy]$") {
            Write-Step "Installing $Name via winget..."
            winget install --id $WingetId --accept-source-agreements --accept-package-agreements 2>&1 | Write-Host

            if ($LASTEXITCODE -eq 0) {
                Write-Success "$Name installed successfully"
                Write-Warn "You may need to restart your terminal for $Name to appear in PATH"
                Write-Host ""

                # Refresh PATH from registry for the current session
                $machinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
                $userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
                $env:PATH = "$machinePath;$userPath"

                return $true
            }
            else {
                Write-Fail "winget installation failed"
                Write-Host ""
            }
        }
    }

    # Manual fallback
    Write-Host "Please install $Name manually:"
    Write-Host "  $ManualUrl" -ForegroundColor White
    if ($hasWinget -and $WingetId) {
        Write-Host "  Or run: winget install --id $WingetId" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "After installing, restart your terminal and re-run this script."
    return $false
}

function Install-VsBuildTools {
    <#
    .SYNOPSIS
        Prompts the user to install Visual Studio Build Tools with C++ workload.
        Returns $true if user should re-run the script, $false if declined.
    #>

    Write-Fail "Visual Studio Build Tools with C++ workload not found"
    Write-Host ""

    $hasWinget = Test-Command "winget"

    if ($hasWinget) {
        Write-Host "Visual Studio Build Tools can be installed via winget, but the"
        Write-Host "C++ workload must be selected during installation."
        Write-Host ""
        $response = Read-Host "Install Visual Studio Build Tools now using winget? (y/N)"
        if ($response -match "^[Yy]$") {
            Write-Step "Installing Visual Studio Build Tools via winget..."
            Write-Warn "The installer UI will open. Select 'Desktop development with C++' workload."
            Write-Host ""
            winget install --id Microsoft.VisualStudio.2022.BuildTools `
                --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" `
                --accept-source-agreements --accept-package-agreements 2>&1 | Write-Host

            if ($LASTEXITCODE -eq 0) {
                Write-Success "Visual Studio Build Tools installed"
                Write-Warn "Restart your terminal and re-run this script."
                return $true
            }
            else {
                Write-Fail "Installation failed or was cancelled"
                Write-Host ""
            }
        }
    }

    Write-Host "Please install Visual Studio Build Tools manually:"
    Write-Host "  https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor White
    Write-Host "  Select 'Desktop development with C++' workload" -ForegroundColor White
    Write-Host ""
    Write-Host "Alternatively, run this script from a 'Developer PowerShell for VS' prompt."
    return $false
}

function Find-VsDevShell {
    <#
    .SYNOPSIS
        Locates and imports the Visual Studio Developer Shell module.
        Returns $true if MSVC environment is available, $false otherwise.
    #>

    # Check if we already have cl.exe (running from Developer Command Prompt)
    if (Test-Command "cl") {
        Write-Success "MSVC compiler (cl.exe) already available"
        return $true
    }

    # Try to find and import VsDevShell
    $vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vsWherePath)) {
        return $false
    }

    $vsInstallPath = & $vsWherePath -latest -property installationPath 2>$null
    if (-not $vsInstallPath) {
        return $false
    }

    $devShellModule = Join-Path $vsInstallPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    if (Test-Path $devShellModule) {
        try {
            Import-Module $devShellModule
            Enter-VsDevShell -VsInstallPath $vsInstallPath -SkipAutomaticLocation -DevCmdArguments "-arch=x64" | Out-Null
            if (Test-Command "cl") {
                Write-Success "Loaded MSVC environment from: $vsInstallPath"
                return $true
            }
        }
        catch {
            Write-Warn "Failed to load VsDevShell: $_"
        }
    }

    # Fallback: try vcvarsall.bat
    $vcvarsall = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (Test-Path $vcvarsall) {
        try {
            # Run vcvarsall and capture the environment
            $output = cmd /c "`"$vcvarsall`" x64 >nul 2>&1 && set" 2>$null
            foreach ($line in $output) {
                if ($line -match "^([^=]+)=(.*)$") {
                    [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                }
            }
            if (Test-Command "cl") {
                Write-Success "Loaded MSVC environment via vcvarsall.bat"
                return $true
            }
        }
        catch {
            Write-Warn "Failed to run vcvarsall.bat: $_"
        }
    }

    return $false
}

# ──────────────────────────────────────────────────────────
# Pre-flight checks
# ──────────────────────────────────────────────────────────

Write-Banner "Building liboqs dependencies for Windows"
Write-Host "liboqs version:        $LiboqsVersion"
Write-Host "liboqs-python version: $LiboqsPythonVersion"
Write-Host "Install prefix:        $InstallPrefix"
Write-Host ""

# Track if any dependency was just installed (may need terminal restart)
$needsRestart = $false

# Check Python
if (-not (Test-Command "python")) {
    if (-not (Install-Dependency -Name "Python" `
            -WingetId "Python.Python.3.12" `
            -ManualUrl "https://www.python.org/downloads/" `
            -ExtraInfo "Make sure to check 'Add Python to PATH' during installation.")) {
        exit 1
    }
    # Verify it's now available
    if (-not (Test-Command "python")) {
        Write-Warn "Python was installed but is not yet in PATH."
        Write-Host "Restart your terminal and re-run this script."
        exit 1
    }
}

$pythonVersion = python --version 2>&1
Write-Success "Python found: $pythonVersion"

# Check pip
try {
    python -m pip --version | Out-Null
    Write-Success "pip is available"
}
catch {
    Write-Step "pip not found, attempting to bootstrap..."
    python -m ensurepip 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Could not bootstrap pip. Run: python -m ensurepip"
        exit 1
    }
    Write-Success "pip bootstrapped successfully"
}

# Check git
if (-not (Test-Command "git")) {
    if (-not (Install-Dependency -Name "Git" `
            -WingetId "Git.Git" `
            -ManualUrl "https://git-scm.com/download/win")) {
        exit 1
    }
    if (-not (Test-Command "git")) {
        Write-Warn "Git was installed but is not yet in PATH."
        Write-Host "Restart your terminal and re-run this script."
        exit 1
    }
}
Write-Success "git is available"

# Check cmake
if (-not (Test-Command "cmake")) {
    if (-not (Install-Dependency -Name "CMake" `
            -WingetId "Kitware.CMake" `
            -ManualUrl "https://cmake.org/download/" `
            -ExtraInfo "Make sure to select 'Add CMake to PATH' during installation.")) {
        exit 1
    }
    if (-not (Test-Command "cmake")) {
        Write-Warn "CMake was installed but is not yet in PATH."
        Write-Host "Restart your terminal and re-run this script."
        exit 1
    }
}
Write-Success "cmake is available"

# Check/load MSVC
Write-Step "Checking for MSVC compiler..."
if (-not (Find-VsDevShell)) {
    if (Install-VsBuildTools) {
        # Installer ran — user needs to restart terminal
        exit 0
    }
    exit 1
}

# ──────────────────────────────────────────────────────────
# Check if already installed with correct versions
# ──────────────────────────────────────────────────────────

Write-Step "Checking existing installations..."

$liboqsOk = $false
$liboqsPythonOk = $false

# Check liboqs
$oqsHeader = Join-Path $InstallPrefix "include\oqs\oqs.h"
$oqsDll = Join-Path $InstallPrefix "bin\oqs.dll"
if ((Test-Path $oqsHeader) -and (Test-Path $oqsDll)) {
    Write-Success "liboqs already installed at $InstallPrefix"
    $liboqsOk = $true
}

# Check liboqs-python
try {
    $result = python -c "import oqs; print(oqs.oqs_python_version())" 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -eq $LiboqsPythonVersion) {
        Write-Success "liboqs-python $LiboqsPythonVersion already installed"
        $liboqsPythonOk = $true
    }
    elseif ($LASTEXITCODE -eq 0) {
        Write-Warn "Found liboqs-python $result, but need $LiboqsPythonVersion"
    }
}
catch {
    # Not installed
}

if ($liboqsOk -and $liboqsPythonOk) {
    Write-Banner "All liboqs dependencies already installed with correct versions"
    exit 0
}

# ──────────────────────────────────────────────────────────
# Step 1: Build liboqs from source
# ──────────────────────────────────────────────────────────

if (-not $liboqsOk) {
    Write-Banner "Step 1/2: Building liboqs $LiboqsVersion"

    # Create temp directory
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "liboqs-build-$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        Write-Step "Cloning liboqs $LiboqsVersion..."
        git clone --depth 1 --branch $LiboqsVersion `
            "https://github.com/open-quantum-safe/liboqs.git" $tempDir 2>&1 | Write-Host

        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to clone liboqs repository"
            exit 1
        }

        $buildDir = Join-Path $tempDir "build"
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

        Write-Step "Configuring with CMake..."
        Push-Location $buildDir
        try {
            cmake .. -G "NMake Makefiles" `
                -DCMAKE_BUILD_TYPE=Release `
                -DBUILD_SHARED_LIBS=ON `
                -DOQS_BUILD_ONLY_LIB=ON `
                -DOQS_DIST_BUILD=ON `
                -DOQS_USE_OPENSSL=OFF `
                -DCMAKE_INSTALL_PREFIX="$InstallPrefix" 2>&1 | Write-Host

            if ($LASTEXITCODE -ne 0) {
                Write-Fail "CMake configuration failed"
                exit 1
            }

            Write-Step "Building liboqs (this may take a few minutes)..."
            nmake 2>&1 | Write-Host

            if ($LASTEXITCODE -ne 0) {
                Write-Fail "Build failed"
                exit 1
            }

            Write-Step "Installing to $InstallPrefix..."
            nmake install 2>&1 | Write-Host

            if ($LASTEXITCODE -ne 0) {
                Write-Fail "Installation failed"
                exit 1
            }
        }
        finally {
            Pop-Location
        }

        # Verify installation
        $oqsHeader = Join-Path $InstallPrefix "include\oqs\oqs.h"
        if (Test-Path $oqsHeader) {
            Write-Success "liboqs $LiboqsVersion installed successfully to $InstallPrefix"
        }
        else {
            Write-Fail "liboqs installation verification failed — header not found at $oqsHeader"
            exit 1
        }

        # Check for DLL in both bin and lib directories
        $oqsDll = Join-Path $InstallPrefix "bin\oqs.dll"
        $oqsDllLib = Join-Path $InstallPrefix "lib\oqs.dll"
        if (Test-Path $oqsDll) {
            Write-Success "Found oqs.dll at $oqsDll"
        }
        elseif (Test-Path $oqsDllLib) {
            Write-Warn "oqs.dll found in lib/ instead of bin/ — this may require PATH adjustment"
            $oqsDll = $oqsDllLib
        }
        else {
            Write-Warn "oqs.dll not found — liboqs-python may not work at runtime"
        }
    }
    finally {
        # Cleanup temp directory
        Write-Step "Cleaning up build directory..."
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    }
}
else {
    Write-Step "Step 1/2: liboqs already installed, skipping build"
}

# ──────────────────────────────────────────────────────────
# Step 2: Install liboqs-python
# ──────────────────────────────────────────────────────────

Write-Banner "Step 2/2: Installing liboqs-python $LiboqsPythonVersion"

# Set environment for liboqs-python build
$env:LIBOQS_INSTALL_PATH = $InstallPrefix
$env:CMAKE_PREFIX_PATH = $InstallPrefix
$env:CFLAGS = "-I$InstallPrefix\include"
$env:LDFLAGS = "-L$InstallPrefix\lib"

Write-Step "Installing liboqs-python from source..."
python -m pip install --no-cache-dir `
    "git+https://github.com/open-quantum-safe/liboqs-python.git@$LiboqsPythonVersion" 2>&1 | Write-Host

if ($LASTEXITCODE -ne 0) {
    Write-Fail "Failed to install liboqs-python"
    Write-Host ""
    Write-Host "Ensure the following environment variables are set correctly:"
    Write-Host "  LIBOQS_INSTALL_PATH = $InstallPrefix"
    Write-Host "  CMAKE_PREFIX_PATH   = $InstallPrefix"
    exit 1
}

# Verify liboqs-python
Write-Step "Verifying liboqs-python installation..."

# Ensure DLL is findable for verification
$binDir = Join-Path $InstallPrefix "bin"
if ($env:PATH -notlike "*$binDir*") {
    $env:PATH = "$binDir;$env:PATH"
}

try {
    $result = python -c "import oqs; print(oqs.oqs_python_version())" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $installedVersion = $result.Trim()
        if ($installedVersion -eq $LiboqsPythonVersion) {
            Write-Success "liboqs-python $installedVersion installed and verified"
        }
        else {
            Write-Warn "Expected version $LiboqsPythonVersion, got $installedVersion"
        }
    }
    else {
        Write-Fail "liboqs-python verification failed: $result"
        Write-Host ""
        Write-Host "The DLL may not be in PATH. Ensure $binDir is in your PATH."
        exit 1
    }
}
catch {
    Write-Fail "liboqs-python verification failed: $_"
    exit 1
}

# ──────────────────────────────────────────────────────────
# Environment variable setup
# ──────────────────────────────────────────────────────────

if (-not $SkipEnvSetup) {
    Write-Banner "Environment Variable Setup"

    $binDir = Join-Path $InstallPrefix "bin"
    $libDir = Join-Path $InstallPrefix "lib"

    # Check current user PATH
    $userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    $needsPathUpdate = $userPath -notlike "*$binDir*"

    if ($needsPathUpdate) {
        Write-Host "The following directory needs to be in your PATH for oqs.dll:"
        Write-Host "  $binDir" -ForegroundColor White
        Write-Host ""

        $response = Read-Host "Add to your user PATH permanently? (y/N)"
        if ($response -match "^[Yy]$") {
            $newPath = "$binDir;$userPath"
            [System.Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
            $env:PATH = "$binDir;$env:PATH"
            Write-Success "Added $binDir to user PATH"
            Write-Host ""
            Write-Warn "IMPORTANT: Restart your terminal for PATH changes to take effect"
            Write-Host "           in new sessions. Current session has been updated."
        }
        else {
            Write-Host "Skipped. You must manually ensure $binDir is in your PATH."
            Write-Host ""
            Write-Host "To add it manually, run:" -ForegroundColor White
            Write-Host '  [System.Environment]::SetEnvironmentVariable("PATH", "' -NoNewline
            Write-Host "$binDir" -ForegroundColor Yellow -NoNewline
            Write-Host ';$env:PATH", "User")'
        }
    }
    else {
        Write-Success "$binDir is already in user PATH"
    }
}

# ──────────────────────────────────────────────────────────
# Final verification
# ──────────────────────────────────────────────────────────

Write-Banner "Final Verification"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$packageRoot = Split-Path -Parent $scriptDir

try {
    $verifyScript = @"
import sys
sys.path.insert(0, r'$packageRoot')
try:
    from openssl_encrypt.versions import check_liboqs_version, check_liboqs_python_version

    liboqs_ok, liboqs_ver, liboqs_msg = check_liboqs_version()
    print(liboqs_msg)

    liboqs_python_ok, liboqs_python_ver, liboqs_python_msg = check_liboqs_python_version()
    print(liboqs_python_msg)

    if liboqs_ok and liboqs_python_ok:
        print('')
        print('All checks passed!')
    else:
        print('')
        print('Some checks failed. If you just updated PATH,')
        print('restart your terminal and try: openssl-encrypt-check-deps')
except Exception as e:
    print(f'Could not run verification: {e}')
    print('This is normal if the package is not yet installed.')
"@

    python -c $verifyScript 2>&1 | Write-Host
}
catch {
    Write-Host "Note: Final verification skipped (package not in path yet)"
}

Write-Host ""
Write-Banner "Done"
Write-Host "Installation location: $InstallPrefix"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. If prompted, restart your terminal for PATH changes"
Write-Host "  2. Install openssl_encrypt:  pip install -e ."
Write-Host "  3. Verify:                   openssl-encrypt --version"
Write-Host ""
