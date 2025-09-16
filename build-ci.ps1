Param(
    [string[]]$TargetFrameworks = @('net8.0')
)

Set-StrictMode -Version Latest
$project = Join-Path $PSScriptRoot 'Il2CppDumper\\Il2CppDumper.csproj'
$configuration = 'Release'
$outBase = Join-Path $PSScriptRoot 'Il2CppDumper\\bin\\Release'

# Clean previous restore artifacts to avoid stale project.assets.json
$projectObj = Join-Path (Split-Path $project) 'obj'
if (Test-Path $projectObj) {
    Write-Host "Removing stale obj folder: $projectObj"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $projectObj
}

$projectBin = Join-Path (Split-Path $project) 'bin'
if (Test-Path $projectBin) {
    Write-Host "Removing stale bin folder: $projectBin"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $projectBin
}

function Run-RestoreForTfm {
    param($tfm)

    Write-Host "Attempting dotnet restore for $tfm"
    $restoreCmd = "dotnet restore `"$project`" --framework $tfm"
    Write-Host "Running: $restoreCmd"
    $restoreOutput = iex $restoreCmd 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "dotnet restore succeeded for $tfm"
        return
    }
    Write-Host "dotnet restore failed for $tfm, falling back to msbuild restore. Output:";
    $restoreOutput | ForEach-Object { Write-Host $_ }
    # Fallback
    Write-Host "Restoring assets for $tfm using dotnet msbuild Restore"
    $restoreCmd = "dotnet msbuild `"$project`" -t:Restore -p:TargetFramework=$tfm"
    Write-Host "Running: $restoreCmd"
    $restoreOutput = iex $restoreCmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Restore command failed. Output:";
        $restoreOutput | ForEach-Object { Write-Host $_ }
        throw "restore failed for $tfm"
    }
}

function Publish-Target {
    param($tfm, $selfContained=$false)

    # Ensure per-TFM assets exist
    Run-RestoreForTfm -tfm $tfm

    $selfArg = if ($selfContained) { ' --self-contained ' } else { ' --no-self-contained ' }

    $out = Join-Path $outBase "$tfm\publish"
    Write-Host "Publishing $tfm -> $out"
    # Framework-dependent publish (no single-file, no trimming) to avoid runtime pack/workload requirements on CI
    $cmd = "dotnet publish `"$project`" -c $configuration -f $tfm -o `"$out`" $selfArg --no-restore"
    Write-Host "Running: $cmd"
    $output = iex $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Publish command failed. Output:";
        $output | ForEach-Object { Write-Host $_ }
        throw "publish failed for $tfm"
    }
    return $out
}

function Safe-Copy {
    param($src, $dst)
    if (Test-Path $src) {
        New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
        Copy-Item $src -Destination $dst -Force
        Write-Host "Copied $src -> $dst"
    } else {
        Write-Host "Skipping missing file $src"
    }
}

$artifacts = @()
$publishFailures = @()
foreach ($tfm in $TargetFrameworks) {
    try {
        $out = Publish-Target -tfm $tfm -selfContained:$false
        $artifacts += $out
    } catch {
        $err = "Publish failed for $($tfm): $($_)"
        Write-Host $err
        $publishFailures += $err
    }
}

# If any mandatory publish failed, exit with non-zero to fail CI
if ($publishFailures.Count -gt 0) {
    Write-Host "One or more publishes failed. Failing the CI."
    $publishFailures | ForEach-Object { Write-Host $_ }
    exit 1
}

# Copy or prepare artifact outputs
$finalDir = Join-Path $outBase 'published'
New-Item -ItemType Directory -Force -Path $finalDir | Out-Null
foreach ($a in $artifacts | Sort-Object -Unique) {
    if (Test-Path $a) {
        Get-ChildItem -Path $a -Filter 'Il2CppDumper*.exe' -File -Recurse | ForEach-Object {
            Safe-Copy $_.FullName (Join-Path $finalDir $_.Name)
        }
    }
}

Write-Host "Published artifacts to $finalDir"
Write-Host "##[set-output name=artifact-path]$finalDir"

exit 0
