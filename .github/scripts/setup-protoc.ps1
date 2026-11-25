# Use the official protobuf release: arduino/setup-protoc v3 still uses Node 20.
# Pin each archive's published SHA-256 and explicitly supply well-known types.
$ErrorActionPreference = 'Stop'
$version = '36.2'
$platform = "$($env:RUNNER_OS)/$($env:RUNNER_ARCH)"
switch ($platform) {
    'Windows/X64' {
        $suffix = 'win64'
        $sha = 'f0c128dc0d8492eceece83bb459a4c0e316764b929ffbf1aa416357fd644edd3'
    }
    'Linux/X64' {
        $suffix = 'linux-x86_64'
        $sha = '121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278'
    }
    'Linux/ARM64' {
        $suffix = 'linux-aarch_64'
        $sha = '8b8f18bd2b30346efbc698dd5a73dd7c805f3ef8380f6dfc95c768f3f1852f6a'
    }
    'macOS/X64' {
        $suffix = 'osx-x86_64'
        $sha = '228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078'
    }
    'macOS/ARM64' {
        $suffix = 'osx-aarch_64'
        $sha = '9cd98a532c5c5e0c4161314de0225de27e4c8a323917b6ea7b1b714d3ae23466'
    }
    default { throw "Unsupported protoc platform: $platform" }
}

$asset = "protoc-$version-$suffix.zip"
$archive = Join-Path $env:RUNNER_TEMP $asset
$directory = Join-Path $env:RUNNER_TEMP "protoc-$version-$suffix"
Invoke-WebRequest -Uri "https://github.com/protocolbuffers/protobuf/releases/download/v$version/$asset" -OutFile $archive
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ne $sha) {
    throw "Checksum mismatch for $asset"
}
Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
$bin = Join-Path $directory 'bin'
$include = Join-Path $directory 'include'
$protoc = Join-Path $bin $(if ($IsWindows) { 'protoc.exe' } else { 'protoc' })
if (-not $IsWindows) {
    chmod +x $protoc
    if ($LASTEXITCODE -ne 0) { throw 'Failed to make protoc executable' }
}
if (-not (Test-Path -LiteralPath (Join-Path $include 'google/protobuf/descriptor.proto') -PathType Leaf)) {
    throw 'Missing protobuf well-known types'
}
& $protoc --version
if ($LASTEXITCODE -ne 0) { throw 'protoc failed to start' }
$bin | Out-File -FilePath $env:GITHUB_PATH -Append -Encoding utf8
"PROTOC=$protoc" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"PROTOC_INCLUDE=$include" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
