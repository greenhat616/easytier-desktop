param(
    [Parameter(Mandatory)] [string] $Fixture,
    [Parameter(Mandatory)] [string] $Wfp
)
$ErrorActionPreference = 'Stop'
# Only the disposable elevated runner. Use actual LocalSystem, not an administrator.
$tag = [guid]::NewGuid().ToString('N').Substring(0,8)
$folder = Join-Path $env:ProgramData "etd-s1-$tag"
New-Item -ItemType Directory -Path $folder | Out-Null
Copy-Item -LiteralPath $Fixture -Destination "$folder/fixture.exe"
Copy-Item -LiteralPath $Wfp -Destination "$folder/wfp.exe"
$results = "$folder/results"
New-Item -ItemType Directory -Path $results | Out-Null
$user = "etds1_$tag"
$password = [guid]::NewGuid().ToString('N') + 'Aa!5'
$account = "$env:COMPUTERNAME\$user"
$port = Get-Random -Minimum 40000 -Maximum 55000
$control = $port + 1
$token = "fixture-$tag"
$tasks = [System.Collections.Generic.List[string]]::new()
$pids = [System.Collections.Generic.List[int]]::new()
$owned = $false
$created = $false

function Wait-File($path) {
    for ($i = 0; $i -lt 200; $i++) {
        if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 0) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Missing marker: $path"
}
function Launch($suffix, $exe, $arguments, $identity) {
    $name = "etd-s1-$tag-$suffix"
    $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $folder
    if ($identity -eq 'SYSTEM') {
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $name -Action $action -Principal $principal | Out-Null
    } else {
        Register-ScheduledTask -TaskName $name -Action $action -User $account -Password $password -RunLevel Limited | Out-Null
    }
    $tasks.Add($name)
    Start-ScheduledTask -TaskName $name
}
function Start-Listener($suffix, $endpoint) {
    $marker = "$folder/$suffix.pid"
    Launch $suffix "$folder/fixture.exe" ('listen {0} "{1}" {2}' -f $endpoint,$marker,$token) SYSTEM
    Wait-File $marker
    $listenerPid = [int](Get-Content -LiteralPath $marker)
    $pids.Add($listenerPid)
    $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$listenerPid" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    if ($owner -ne 'S-1-5-18') { throw "Listener not LocalSystem: $owner" }
    Write-Host "LISTEN pid=$listenerPid endpoint=$endpoint sid=$owner"
    return $listenerPid
}
function Run-Probe($suffix, $endpoint, $expectation, $identity) {
    $marker = "$results/$suffix.done"
    $log = "$results/$suffix.log"
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}/probe.ps1" {1} {2} {3} "{4}" "{5}"' -f $folder,$endpoint,$token,$expectation,$log,$marker
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ($identity -eq 'SYSTEM') {
        Launch $suffix $powershell $arguments SYSTEM
    } else {
        # CreateProcessWithLogonW, rather than depending on batch-logon rights.
        $credential = [pscredential]::new($account,(ConvertTo-SecureString $password -AsPlainText -Force))
        $probe = Start-Process -FilePath $powershell -ArgumentList $arguments -Credential $credential -WorkingDirectory $folder -WindowStyle Hidden -PassThru
        if (!$probe.WaitForExit(20000)) { $probe.Kill(); throw "Second-user process timed out" }
        if ($probe.ExitCode -ne 0) { throw "Second-user PowerShell exited $($probe.ExitCode)" }
    }
    Wait-File $marker
    $content = Get-Content -LiteralPath $log -Raw
    Write-Host "=== $identity $endpoint $expectation ==="
    Write-Host $content
    $expectedSid = if ($identity -eq 'SYSTEM') { 'S-1-5-18' } else { (Get-LocalUser -Name $user).SID.Value }
    if ($content -notmatch [regex]::Escape("SID=$expectedSid")) { throw "Wrong probe account" }
    if ($content -notmatch [regex]::Escape("PROBE $endpoint expected=$expectation actual=$expectation")) { throw "Missing probe verdict" }
    if ((Get-Content -LiteralPath $marker) -ne '0') { throw "Probe failed: $suffix" }
}
function Invoke-Wfp($verb) {
    & "$folder/wfp.exe" $verb
    if ($LASTEXITCODE -ne 0) { throw "WFP $verb failed" }
}
function Kill-Checked([int]$targetPid) {
    Stop-Process -Id $targetPid -Force
    Wait-Process -Id $targetPid -Timeout 10 -ErrorAction SilentlyContinue
    if (Get-Process -Id $targetPid -ErrorAction SilentlyContinue) { throw "Process still alive: $targetPid" }
    [void]$pids.Remove($targetPid)
}
function Check-Both($phase) {
    foreach ($family in @('v4','v6')) {
        $endpoint = if ($family -eq 'v4') { "127.0.0.1:$port" } else { "[::1]:$port" }
        Run-Probe "$phase-$family-a" $endpoint allowed SYSTEM
        Run-Probe "$phase-$family-b" $endpoint denied second
        Run-Probe "$phase-$family-c" $endpoint allowed SYSTEM
    }
}
try {
    New-LocalUser -Name $user -Password (ConvertTo-SecureString $password -AsPlainText -Force) -Description 'Disposable S1 probe' | Out-Null
    $created = $true
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account
    Start-Service seclogon
    & icacls $folder /inheritance:r /grant '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'fixture ownership ACL failed' }
    & icacls $folder /grant "${account}:(OI)(CI)(RX)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'fixture ACL failed' }
    & icacls $results /grant "${account}:(OI)(CI)(M)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'results ACL failed' }
    @'
param($endpoint,$token,$expectation,$log,$marker)
$ErrorActionPreference = 'Continue'
"SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)" | Set-Content -LiteralPath $log -Encoding UTF8
$output = & "$PSScriptRoot/fixture.exe" probe $endpoint $token $expectation 2>&1
$rc = $LASTEXITCODE
$output | Out-File -LiteralPath $log -Append -Encoding UTF8
$rc | Set-Content -LiteralPath $marker
'@ | Set-Content -LiteralPath "$folder/probe.ps1" -Encoding UTF8
    Invoke-Wfp absent
    $c4 = Start-Listener control4 "127.0.0.1:$control"
    $c6 = Start-Listener control6 "[::1]:$control"
    Run-Probe control4-probe "127.0.0.1:$control" allowed second
    Run-Probe control6-probe "[::1]:$control" allowed second
    @'
param($port)
& "$PSScriptRoot/wfp.exe" install $port "$PSScriptRoot/host.pid" *> "$PSScriptRoot/host.log"
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath "$folder/host.ps1" -Encoding UTF8
    Launch host "$env:SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe" ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}/host.ps1" {1}' -f $folder,$port) SYSTEM
    try { Wait-File "$folder/host.pid" } catch {
        if (Test-Path "$folder/host.log") { Get-Content "$folder/host.log" }
        throw
    }
    $owned = $true
    $hostPid = [int](Get-Content -LiteralPath "$folder/host.pid")
    $pids.Add($hostPid)
    $hostOwner = (Get-CimInstance Win32_Process -Filter "ProcessId=$hostPid" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    if ($hostOwner -ne 'S-1-5-18') { throw "Host not LocalSystem: $hostOwner" }
    Invoke-Wfp present
    $l4 = Start-Listener listener4 "127.0.0.1:$port"
    $l6 = Start-Listener listener6 "[::1]:$port"
    Check-Both before
    Kill-Checked $hostPid
    Write-Host "HOST_KILLED pid=$hostPid; listeners remain"
    Invoke-Wfp present
    Check-Both after
    Kill-Checked $l4
    Kill-Checked $l6
    Invoke-Wfp remove
    $owned = $false
    Invoke-Wfp absent
    Write-Host 'PASS Windows IPv4 + IPv6: identity fence persists after host death; no S1 WFP objects remain'
} finally {
    foreach ($targetPid in @($pids)) { Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue }
    foreach ($name in $tasks) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($owned) { Invoke-Wfp remove; Invoke-Wfp absent }
    if ($created) { Remove-LocalUser -Name $user }
}
