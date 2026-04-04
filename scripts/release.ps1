# Publish a GitHub release with a single asset: Manager.exe (Release x64).
# Usage (from repo root):
#   .\scripts\release.ps1 -Tag v4.5.4 -Title "HWID Spoofer v4.5.4" -NotesFile .\notes.md
# Prereq: gh auth, Release x64 build at build\Release\Manager\Manager.exe

param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$Title,
    [Parameter(Mandatory = $true)][string]$NotesFile
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$exe = Join-Path $repoRoot 'build\Release\Manager\Manager.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Manager.exe not found. Build HWIDSpoofer.sln Release x64 first: $exe"
}
if (-not (Test-Path -LiteralPath $NotesFile)) {
    throw "Notes file not found: $NotesFile"
}

$remote = (git -C $repoRoot remote get-url origin 2>$null)
if ($remote -match 'github\.com[:/]([^/]+)/([^/.]+)') {
    $repo = "$($Matches[1])/$($Matches[2])"
} else {
    throw "Could not parse GitHub repo from origin: $remote"
}

Write-Host "Creating $Tag on $repo with single asset Manager.exe"
gh release create $Tag $exe --repo $repo --title $Title --notes-file $NotesFile
