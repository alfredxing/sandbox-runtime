# Build srt-appcontainer.exe for Windows using MSVC.
#
# Usage (from repo root, in a Developer PowerShell or after running vcvarsall):
#   .\scripts\build-appcontainer-binary.ps1
#   .\scripts\build-appcontainer-binary.ps1 -Arch arm64
#   .\scripts\build-appcontainer-binary.ps1 -Force   # rebuild even if exists
#
# Output: vendor/appcontainer/{x64,arm64}/srt-appcontainer.exe
#
# /MT links the static CRT so the binary has no vcruntime140.dll dependency.
# This mirrors scripts/build-seccomp-binaries.sh which also produces
# self-contained binaries committed to vendor/.

param(
    [ValidateSet("x64", "arm64", "both")]
    [string]$Arch = "x64",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$SourceFile = Join-Path $RootDir "vendor\appcontainer-src\srt-appcontainer.cpp"

if (-not (Test-Path $SourceFile)) {
    Write-Error "Source not found: $SourceFile"
    exit 1
}

function Find-VcVarsAll {
    # Try vswhere first — ships with VS 2017+.
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($vsPath) {
            $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
            if (Test-Path $vcvars) { return $vcvars }
        }
    }
    # Fallback: well-known paths.
    $candidates = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\*\VC\Auxiliary\Build\vcvarsall.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\*\VC\Auxiliary\Build\vcvarsall.bat"
    )
    foreach ($c in $candidates) {
        $found = Get-ChildItem -Path $c -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

function Build-Arch {
    param([string]$TargetArch)

    $OutputDir = Join-Path $RootDir "vendor\appcontainer\$TargetArch"
    $OutputExe = Join-Path $OutputDir "srt-appcontainer.exe"

    if ((Test-Path $OutputExe) -and -not $Force) {
        $size = (Get-Item $OutputExe).Length
        Write-Host "[skip] $TargetArch binary already exists ($size bytes): $OutputExe"
        Write-Host "       (use -Force to rebuild)"
        return
    }

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "Building srt-appcontainer.exe for $TargetArch"
    Write-Host "=========================================="

    # If cl.exe is already on PATH and matches the target arch, use it directly.
    # Otherwise, shell through vcvarsall.bat.
    $clAvailable = Get-Command cl.exe -ErrorAction SilentlyContinue

    $clFlags = @(
        "/nologo",
        "/O2",               # optimize
        "/MT",               # static CRT — no vcruntime140.dll dep
        "/EHsc",             # C++ exceptions
        "/W4",               # warnings
        "/DUNICODE", "/D_UNICODE",
        "/Fe:$OutputExe",
        $SourceFile,
        "/link",
        "userenv.lib", "advapi32.lib", "shell32.lib"
    )

    if ($clAvailable -and $TargetArch -eq "x64") {
        # Direct invocation — caller already set up the environment.
        Write-Host "Using cl.exe from PATH"
        & cl.exe @clFlags
        if ($LASTEXITCODE -ne 0) {
            Write-Error "cl.exe exited with code $LASTEXITCODE"
            exit 1
        }
    } else {
        # Shell through vcvarsall for cross-compilation / env setup.
        $vcvars = Find-VcVarsAll
        if (-not $vcvars) {
            Write-Error "vcvarsall.bat not found. Install Visual Studio Build Tools with the C++ workload."
            exit 1
        }
        Write-Host "Using vcvarsall: $vcvars"

        # vcvarsall arch strings: x64 → x64, arm64 → x64_arm64 (cross)
        $vcArch = if ($TargetArch -eq "arm64") { "x64_arm64" } else { "x64" }

        $clCmd = "cl.exe " + ($clFlags -join " ")
        $cmd = "`"$vcvars`" $vcArch && $clCmd"
        & cmd.exe /c $cmd
        if ($LASTEXITCODE -ne 0) {
            Write-Error "build failed with code $LASTEXITCODE"
            exit 1
        }
    }

    if (-not (Test-Path $OutputExe)) {
        Write-Error "Build succeeded but output not found: $OutputExe"
        exit 1
    }

    # Clean up .obj left in cwd by cl.
    Remove-Item -Path "srt-appcontainer.obj" -ErrorAction SilentlyContinue

    $size = (Get-Item $OutputExe).Length
    Write-Host "[ok] $OutputExe ($size bytes)"
}

$archList = if ($Arch -eq "both") { @("x64", "arm64") } else { @($Arch) }
foreach ($a in $archList) {
    Build-Arch -TargetArch $a
}

Write-Host ""
Write-Host "Build complete. Generated binaries:"
Get-ChildItem -Path (Join-Path $RootDir "vendor\appcontainer") -Recurse -Filter "*.exe" |
    ForEach-Object { Write-Host "  $($_.FullName) ($($_.Length) bytes)" }
