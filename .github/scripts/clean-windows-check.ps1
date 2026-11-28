# Run the release payload on a Windows without the VC++ runtime
# (release-package.yml, inside a Server Core container).
#   powershell -File clean-windows-check.ps1 -Payload <folder>
# The image must not have the runtime (checked first, so the run proves
# something). The command-line binaries run --version; etd-ui, a GUI with no
# such flag, must get past the loader: it is started and must either keep
# running or exit with anything but a loader failure.
param([Parameter(Mandatory)] [string] $Payload)
$ErrorActionPreference = 'Stop'

$system = Join-Path $env:SystemRoot 'System32'
foreach ($dll in 'vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll') {
    if (Test-Path -LiteralPath (Join-Path $system $dll)) { throw "this image has ${dll}: it is not a machine without the VC++ runtime" }
}
Write-Output "no VC++ runtime in this image ($((Get-CimInstance Win32_OperatingSystem).Caption))"

# STATUS_DLL_NOT_FOUND, STATUS_ENTRYPOINT_NOT_FOUND, STATUS_INVALID_IMAGE_FORMAT,
# STATUS_DLL_INIT_FAILED: the loader could not start the image.
# (0xC0000135, 0xC0000139, 0xC000007B, 0xC0000142 as the signed exit codes.)
$loader = @(-1073741515, -1073741511, -1073741701, -1073741502)
function Format-Code([int] $code) { '{0} (0x{1:X8})' -f $code, $code }

$core = Get-ChildItem -LiteralPath (Join-Path $Payload 'cores') -Recurse -Filter easytier-core.exe | Select-Object -First 1
foreach ($exe in (Join-Path $Payload 'etd-host.exe'), (Join-Path $Payload 'etd-ctl.exe'), $core.FullName) {
    # Windows PowerShell turns native stderr into errors under 'Stop'.
    $ErrorActionPreference = 'Continue'
    $out = & $exe --version 2>&1 | Out-String
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw "$exe --version exited $(Format-Code $LASTEXITCODE): $out" }
    Write-Output "$(Split-Path -Leaf $exe) --version: $($out.Trim())"
}

$ui = Start-Process -FilePath (Join-Path $Payload 'etd-ui.exe') -PassThru
if ($ui.WaitForExit(15000)) {
    $code = $ui.ExitCode
    if ($loader -contains $code) { throw "etd-ui.exe could not be loaded: $(Format-Code $code)" }
    Write-Output "etd-ui.exe loaded and exited $(Format-Code $code) (no desktop in a container)"
} else {
    Stop-Process -Id $ui.Id -Force
    Write-Output 'etd-ui.exe loaded and was still running after 15 s'
}
Write-Output 'every shipped binary starts without the VC++ runtime'
