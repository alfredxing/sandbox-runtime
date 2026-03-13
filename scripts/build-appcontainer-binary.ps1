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
$SourceDir = Join-Path $RootDir "vendor\appcontainer-src"

# Binaries to build: (basename, link-libs). All sources are $SourceDir\<basename>.cpp.
$Binaries = @(
    @{ Name = "srt-appcontainer";  Libs = @("userenv.lib", "advapi32.lib", "shell32.lib", "ws2_32.lib", "user32.lib") },
    @{ Name = "srt-pipe-forwarder"; Libs = @("ws2_32.lib") }
)

foreach ($bin in $Binaries) {
    $src = Join-Path $SourceDir "$($bin.Name).cpp"
    if (-not (Test-Path $src)) {
        Write-Error "Source not found: $src"
        exit 1
    }
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

function Build-One {
    param([string]$TargetArch, [string]$BinName, [string[]]$LinkLibs)

    $OutputDir = Join-Path $RootDir "vendor\appcontainer\$TargetArch"
    $OutputExe = Join-Path $OutputDir "$BinName.exe"
    $SourceFile = Join-Path $SourceDir "$BinName.cpp"

    if ((Test-Path $OutputExe) -and -not $Force) {
        $size = (Get-Item $OutputExe).Length
        Write-Host "[skip] $TargetArch $BinName already exists ($size bytes)"
        return
    }

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "Building $BinName.exe for $TargetArch"
    Write-Host "=========================================="

    $clAvailable = Get-Command cl.exe -ErrorAction SilentlyContinue

    $clFlags = @(
        "/nologo", "/O2", "/MT", "/EHsc", "/W4",
        "/DUNICODE", "/D_UNICODE",
        "/Fe:$OutputExe",
        $SourceFile,
        "/link"
    ) + $LinkLibs

    if ($clAvailable -and $TargetArch -eq "x64") {
        Write-Host "Using cl.exe from PATH"
        & cl.exe @clFlags
        if ($LASTEXITCODE -ne 0) {
            Write-Error "cl.exe exited with code $LASTEXITCODE"
            exit 1
        }
    } else {
        $vcvars = Find-VcVarsAll
        if (-not $vcvars) {
            Write-Error "vcvarsall.bat not found. Install Visual Studio Build Tools with the C++ workload."
            exit 1
        }
        Write-Host "Using vcvarsall: $vcvars"
        $vcArch = if ($TargetArch -eq "arm64") { "x64_arm64" } else { "x64" }
        $clCmd = "cl.exe " + ($clFlags -join " ")
        & cmd.exe /c "`"$vcvars`" $vcArch && $clCmd"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "build failed with code $LASTEXITCODE"
            exit 1
        }
    }

    if (-not (Test-Path $OutputExe)) {
        Write-Error "Build succeeded but output not found: $OutputExe"
        exit 1
    }

    Remove-Item -Path "$BinName.obj" -ErrorAction SilentlyContinue

    $size = (Get-Item $OutputExe).Length
    Write-Host "[ok] $OutputExe ($size bytes)"
}

function Build-Arch {
    param([string]$TargetArch)
    foreach ($bin in $Binaries) {
        Build-One -TargetArch $TargetArch -BinName $bin.Name -LinkLibs $bin.Libs
    }
}

$archList = if ($Arch -eq "both") { @("x64", "arm64") } else { @($Arch) }
foreach ($a in $archList) {
    Build-Arch -TargetArch $a
}

Write-Host ""
Write-Host "Build complete. Generated binaries:"
Get-ChildItem -Path (Join-Path $RootDir "vendor\appcontainer") -Recurse -Filter "*.exe" |
    ForEach-Object { Write-Host "  $($_.FullName) ($($_.Length) bytes)" }
