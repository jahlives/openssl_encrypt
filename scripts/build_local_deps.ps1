#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for liboqs and liboqs-python dependencies on Windows.

.DESCRIPTION
    Builds liboqs from source using MSVC and installs liboqs-python.
    Equivalent of build_local_deps.sh for Windows systems.

.PARAMETER InstallPrefix
    Installation directory for liboqs. Default: $HOME\_oqs

.PARAMETER LiboqsVersion
    Version of liboqs to build. Default: 0.12.0

.PARAMETER LiboqsPythonVersion
    Version of liboqs-python to install. Default: 0.12.0

.PARAMETER SkipEnvSetup
    Skip adding environment variables to user profile.

.EXAMPLE
    .\build_local_deps.ps1
    .\build_local_deps.ps1 -InstallPrefix "C:\liboqs"
    .\build_local_deps.ps1 -SkipEnvSetup
#>

param(
    [string]$InstallPrefix = (Join-Path $env:USERPROFILE "_oqs"),
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
            & { $ErrorActionPreference = 'Continue'
                winget install --id $WingetId --accept-source-agreements --accept-package-agreements 2>&1 | Write-Host
            }

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
            & { $ErrorActionPreference = 'Continue'
                winget install --id Microsoft.VisualStudio.2022.BuildTools `
                    --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" `
                    --accept-source-agreements --accept-package-agreements 2>&1 | Write-Host
            }

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

    # Fallback: check via where.exe (Get-Command may miss inherited PATH entries)
    try {
        $whereResult = & where.exe cl 2>$null
        if ($LASTEXITCODE -eq 0 -and $whereResult) {
            Write-Success "MSVC compiler (cl.exe) found via PATH"
            return $true
        }
    } catch { }

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
    & { $ErrorActionPreference = 'Continue'; python -m ensurepip 2>&1 | Write-Host }
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
    Write-Banner "Step 1/3: Building liboqs $LiboqsVersion"

    # Create temp directory
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "liboqs-build-$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        Write-Step "Cloning liboqs $LiboqsVersion..."
        & { $ErrorActionPreference = 'Continue'
            git clone --depth 1 --branch $LiboqsVersion `
                "https://github.com/open-quantum-safe/liboqs.git" $tempDir 2>&1 | Write-Host
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to clone liboqs repository"
            exit 1
        }

        $buildDir = Join-Path $tempDir "build"
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

        Write-Step "Configuring with CMake..."
        Push-Location $buildDir
        try {
            & { $ErrorActionPreference = 'Continue'
                cmake .. -G "NMake Makefiles" `
                    -DCMAKE_BUILD_TYPE=Release `
                    -DBUILD_SHARED_LIBS=ON `
                    -DOQS_BUILD_ONLY_LIB=ON `
                    -DOQS_DIST_BUILD=ON `
                    -DOQS_USE_OPENSSL=OFF `
                    -DCMAKE_INSTALL_PREFIX="$InstallPrefix" 2>&1 | Write-Host
            }

            if ($LASTEXITCODE -ne 0) {
                Write-Fail "CMake configuration failed"
                exit 1
            }

            Write-Step "Building liboqs (this may take a few minutes)..."
            & { $ErrorActionPreference = 'Continue'; nmake 2>&1 | Write-Host }

            if ($LASTEXITCODE -ne 0) {
                Write-Fail "Build failed"
                exit 1
            }

            Write-Step "Installing to $InstallPrefix..."
            & { $ErrorActionPreference = 'Continue'; nmake install 2>&1 | Write-Host }

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
    Write-Step "Step 1/3: liboqs already installed, skipping build"
}

# ──────────────────────────────────────────────────────────
# Step 2: Install liboqs-python
# ──────────────────────────────────────────────────────────

Write-Banner "Step 2/3: Installing liboqs-python $LiboqsPythonVersion"

# Set environment for liboqs-python build
$env:LIBOQS_INSTALL_PATH = $InstallPrefix
$env:CMAKE_PREFIX_PATH = $InstallPrefix
$env:CFLAGS = "-I$InstallPrefix\include"
$env:LDFLAGS = "-L$InstallPrefix\lib"

Write-Step "Installing liboqs-python from source..."
& { $ErrorActionPreference = 'Continue'
    python -m pip install --no-cache-dir `
        "git+https://github.com/open-quantum-safe/liboqs-python.git@$LiboqsPythonVersion" 2>&1 | Write-Host
}

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
# Step 3: Build RandomX for Windows (MSVC patch)
# ──────────────────────────────────────────────────────────

$RandomXVersion = "1.1.10.post3"
$RandomXGitTag = "v1.1.10"

# Check if randomx is already installed and working
$randomxOk = $false
try {
    $rxResult = python -c "import randomx; vm = randomx.RandomX(b'test_seed_hash_00000000000000000'); h = vm.calculate_hash(b'test'); print(len(h))" 2>&1
    if ($LASTEXITCODE -eq 0 -and $rxResult.Trim() -eq "32") {
        $randomxOk = $true
    }
} catch { }

if ($randomxOk) {
    Write-Banner "Step 3/3: RandomX already installed and working"
}
else {
    Write-Banner "Step 3/3: Building RandomX $RandomXVersion for Windows"

    # RandomX from PyPI doesn't build on Windows/MSVC due to:
    # 1. AMD64 not recognized as x86_64 (JIT files skipped)
    # 2. GAS .S assembly not supported by MSVC (need MASM .asm)
    # 3. advapi32.lib not linked
    # This step patches the source and builds with MASM support.

    $randomxTemp = Join-Path ([System.IO.Path]::GetTempPath()) "randomx-build-$(Get-Random)"
    New-Item -ItemType Directory -Path $randomxTemp -Force | Out-Null

    try {
        # Download source
        Write-Step "Downloading RandomX source..."
        & { $ErrorActionPreference = 'Continue'
            python -m pip download "randomx==$RandomXVersion" --no-binary :all: --no-deps --no-build-isolation -d $randomxTemp 2>&1 | Write-Host
        }
        $tarball = Get-ChildItem -Path $randomxTemp -Filter "*.tar.gz" | Select-Object -First 1
        if (-not $tarball) {
            Write-Fail "Failed to download RandomX source"
            exit 1
        }

        # Extract
        Write-Step "Extracting source..."
        python -c "
import tarfile, sys
with tarfile.open(r'$($tarball.FullName)') as t:
    t.extractall(r'$randomxTemp', filter='data')
"
        $sourceDir = Get-ChildItem -Path $randomxTemp -Directory -Filter "RandomX-*" | Select-Object -First 1
        if (-not $sourceDir) {
            Write-Fail "Failed to extract RandomX source"
            exit 1
        }
        $srcRoot = $sourceDir.FullName
        $asmSrcDir = Join-Path $srcRoot "RandomX\src"

        # Download MASM assembly files from upstream (matching version)
        Write-Step "Downloading MASM assembly files (tag $RandomXGitTag)..."
        $asmDir = Join-Path $asmSrcDir "asm"
        New-Item -ItemType Directory -Path $asmDir -Force | Out-Null

        $baseUrl = "https://raw.githubusercontent.com/tevador/RandomX/refs/tags/$RandomXGitTag/src"

        # Download main MASM file
        python -c "
import urllib.request, os
base_url = '$baseUrl'
asm_dir = r'$asmDir'
asm_src_dir = r'$asmSrcDir'

# Main MASM file
urllib.request.urlretrieve(f'{base_url}/jit_compiler_x86_static.asm',
    os.path.join(asm_src_dir, 'jit_compiler_x86_static.asm'))
print('Downloaded jit_compiler_x86_static.asm')

# Include files
inc_files = [
    'configuration.asm',
    'program_prologue_win64.inc',
    'program_xmm_constants.inc',
    'program_loop_load.inc',
    'program_read_dataset.inc',
    'program_read_dataset_sshash_init.inc',
    'program_read_dataset_sshash_fin.inc',
    'program_loop_store.inc',
    'program_epilogue_store.inc',
    'program_epilogue_win64.inc',
    'program_sshash_load.inc',
    'program_sshash_prefetch.inc',
    'program_sshash_constants.inc',
    'randomx_reciprocal.inc',
]
for f in inc_files:
    urllib.request.urlretrieve(f'{base_url}/asm/{f}', os.path.join(asm_dir, f))
    print(f'Downloaded asm/{f}')
"
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to download MASM files"
            exit 1
        }
        Write-Success "MASM assembly files downloaded"

        # Patch setup.py
        Write-Step "Patching setup.py for Windows/MSVC..."
        $setupPy = Join-Path $srcRoot "setup.py"
        $patchedSetup = @'
from setuptools import setup, Extension
from Cython.Build import cythonize

import glob, os, platform, subprocess, sys

machine = platform.machine()
is_windows = sys.platform == 'win32'
is_msvc = is_windows

if is_msvc:
    compile_flags = ['/O2', '/EHsc', '/std:c++14']
else:
    compile_flags = ['-march=native','-std=c++11','-fpic', '-O3']

source_root_dir = os.path.join('RandomX', 'src')
sources = []
sources.extend(glob.glob('**/*.c', root_dir=source_root_dir, recursive=True))
sources.extend(glob.glob('**/*.cpp', root_dir=source_root_dir, recursive=True))
if not is_msvc:
    sources.extend(glob.glob('**/*.S', root_dir=source_root_dir, recursive=True))
sources = [source for source in sources if 'jit_' not in source and 'tests' not in source]

extra_objects = []

if machine in ['i386', 'i686', 'x86_64', 'AMD64']:
    sources.extend(['jit_compiler_x86.cpp'])
    if is_msvc:
        asm_file = os.path.join(source_root_dir, 'jit_compiler_x86_static.asm')
        obj_file = os.path.join(source_root_dir, 'jit_compiler_x86_static.obj')
        if os.path.exists(asm_file):
            print(f"Assembling {asm_file} with ml64...")
            try:
                subprocess.check_call(['ml64', '/c', '/nologo',
                    f'/I{source_root_dir}',
                    f'/Fo{obj_file}', asm_file])
                extra_objects.append(obj_file)
                print(f"Successfully assembled {obj_file}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"WARNING: Failed to assemble {asm_file}: {e}")
    else:
        sources.extend(['jit_compiler_x86_static.S'])
elif machine in ['aarch64_be', 'aarch64', 'armv8b', 'armv8l']:
    sources.extend(['jit_compiler_a64_static.s', 'jit_compiler_a64.cpp'])
    compile_flags.append('-DHAVE_HWCAP')
elif machine.startswith('ppc'):
    compile_flags.append('-mcpu=native')
sources = [os.path.join(source_root_dir,source) for source in sources]

libraries = []
if is_windows:
    libraries.append('advapi32')

if not is_msvc:
    extra_objects.extend([source for source in sources if source.endswith('.S')])

setup(
    name='RandomX',
    version=open('version').read(),
    description='RandomX Proof-of-Work Hasher',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    package_dir={'randomx': 'randomx'},
    packages=['randomx'],
    url='https://github.com/xloem/RandomX-Python',
    keywords=['randomx', 'crypto', 'cryptocurrency', 'blockchain', 'pow'],
    classifiers=[
      'Programming Language :: Python :: 3',
      'Operating System :: OS Independent',
    ],
    include_package_data=True,
    package_data={'': ['*.pyx', '*.pxd', '*.inc', '*.S', '*.h', '*.c', '*.hpp', '*.cpp']},
    ext_modules=cythonize(
        Extension(
            'randomx', [
                os.path.join('randomx','randomx.pyx'),
                *[source for source in sources if source.endswith('.c') or source.endswith('.cpp')]
            ],
            include_dirs=[os.path.join('RandomX','src')],
            extra_objects=extra_objects,
            extra_compile_args=compile_flags,
            libraries=libraries,
            language='c++',
        ),
        compiler_directives=dict(
            language_level='3',
            embedsignature=True
        )
    )
)
'@
        Set-Content -Path $setupPy -Value $patchedSetup -Encoding UTF8
        Write-Success "setup.py patched"

        # Build and install
        Write-Step "Building RandomX (this may take a minute)..."
        Push-Location $srcRoot
        try {
            & { $ErrorActionPreference = 'Continue'
                python -m pip install --no-build-isolation --no-deps . 2>&1 | Write-Host
            }

            if ($LASTEXITCODE -ne 0) {
                Write-Fail "RandomX build failed"
                exit 1
            }
        }
        finally {
            Pop-Location
        }

        # Verify
        Write-Step "Verifying RandomX..."
        $rxVerify = python -c "import randomx; vm = randomx.RandomX(b'test_seed_hash_00000000000000000'); h = vm.calculate_hash(b'test'); print(len(h))" 2>&1
        if ($LASTEXITCODE -eq 0 -and $rxVerify.Trim() -eq "32") {
            Write-Success "RandomX $RandomXVersion built and verified successfully"
        }
        else {
            Write-Fail "RandomX verification failed: $rxVerify"
            exit 1
        }
    }
    finally {
        # Cleanup
        Write-Step "Cleaning up RandomX build directory..."
        Remove-Item -Recurse -Force $randomxTemp -ErrorAction SilentlyContinue
    }
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

    & { $ErrorActionPreference = 'Continue'; python -c $verifyScript 2>&1 | Write-Host }
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
