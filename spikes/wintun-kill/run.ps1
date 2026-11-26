#requires -Version 7
#requires -RunAsAdministrator
<#
Spike S2: does a wintun adapter disappear by itself when the easytier-core
process that created it is killed with TerminateProcess?

Creates and kills real network adapters. It is meant for a disposable CI
runner; elsewhere it refuses to run without -AllowLocal.
#>
param(
    # Directory holding easytier-core.exe and the wintun.dll shipped with it.
    [Parameter(Mandatory)][string]$CoreDir,
    [string]$OutDir = (Join-Path $PSScriptRoot 'out'),
    [string]$Name = 'etd-3f9a1c2e',
    [int]$KillRuns = 5,
    [int]$GracefulRuns = 3,
    [switch]$AllowLocal
)
$ErrorActionPreference = 'Stop'
if (-not $env:GITHUB_ACTIONS -and -not $AllowLocal) {
    throw 'This changes the machine network configuration. Run it in CI, or pass -AllowLocal on a disposable machine.'
}
Add-Type -Path (Join-Path $PSScriptRoot 'probe.cs')
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$CoreDir = (Resolve-Path $CoreDir).Path
$core = Join-Path $CoreDir 'easytier-core.exe'

# UUIDv5(NAMESPACE_URL, "https://easytier.rs/wintun/<lower-case name>"), the
# GUID upstream gives the adapter (etd-sysfx naming::wintun_guid).
function Get-WintunGuid([string]$n) {
    $ns = [Convert]::FromHexString('6ba7b8119dad11d180b400c04fd430c8')
    [byte[]]$bytes = $ns + [Text.Encoding]::UTF8.GetBytes("https://easytier.rs/wintun/$($n.ToLowerInvariant())")
    [byte[]]$h = [Security.Cryptography.SHA1]::HashData($bytes)[0..15]
    $h[6] = ($h[6] -band 0x0f) -bor 0x50
    $h[8] = ($h[8] -band 0x3f) -bor 0x80
    [guid]::ParseExact([Convert]::ToHexString($h), 'N')
}
$guid = Get-WintunGuid $Name
$guidText = $guid.ToString('B').ToUpperInvariant()
$predictedId = "SWD\Wintun\$guidText"

# Residue that is not the adapter itself, recorded for O1's other reclaimers.
function Get-Leftovers {
    $net = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    $svc = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    [ordered]@{
        'Control\Network\{guid}'   = Test-Path -LiteralPath "$net\$guidText"
        'Tcpip\Interfaces\{guid}'  = Test-Path -LiteralPath "$svc\Tcpip\Parameters\Interfaces\$guidText"
        'Tcpip6\Interfaces\{guid}' = Test-Path -LiteralPath "$svc\Tcpip6\Parameters\Interfaces\$guidText"
        'NetBT\Tcpip_{guid}'       = Test-Path -LiteralPath "$svc\NetBT\Parameters\Interfaces\Tcpip_$guidText"
        'FirewallRules'            = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*$Name*" -or $_.Group -eq 'EasyTier' } |
                ForEach-Object DisplayName | Sort-Object)
    }
}

# Independent cross-check with the stock tools.
function Save-ToolView([string]$file, [uint32]$ifIndex) {
    & {
        "### $(Get-Date -Format o)"
        '### Get-NetAdapter -IncludeHidden'
        Get-NetAdapter -IncludeHidden | Sort-Object ifIndex |
            Format-Table ifIndex, Name, InterfaceDescription, InterfaceGuid, Status, Hidden -AutoSize
        "### Get-NetRoute (ifIndex $ifIndex)"
        Get-NetRoute | Where-Object ifIndex -EQ $ifIndex |
            Format-Table ifIndex, DestinationPrefix, NextHop -AutoSize
        '### Get-PnpDevice -Class Net (includes non-present)'
        Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
            Format-Table Status, Present, FriendlyName, InstanceId -AutoSize
        '### pnputil /enum-devices /class Net'
        pnputil /enum-devices /class Net
    } | Out-String -Width 300 | Set-Content -LiteralPath $file
}

function Get-ToolCounts([uint32]$ifIndex) {
    $pnp = (pnputil /enum-devices /class Net) -join "`n"
    [ordered]@{
        netAdapter = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid -eq $guidText -or $_.Name -like "$Name*" }).Count
        netRoute   = @(Get-NetRoute | Where-Object ifIndex -EQ $ifIndex).Count
        pnputil    = [regex]::Matches($pnp, [regex]::Escape($predictedId), 'IgnoreCase').Count
        pnpDevice  = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
                Where-Object InstanceId -EQ $predictedId | ForEach-Object { "$($_.Status)/present=$($_.Present)" })
    }
}

function Start-Core([string]$tag, [string]$devName = $Name) {
    $arguments = @(
        '--network-name', "s2-spike-$([guid]::NewGuid().ToString('N'))",
        '--ipv4', '10.144.144.1/24', '--dev-name', $devName, '--no-listener',
        '--manual-routes', '10.200.77.0/24', '--rpc-portal', '127.0.0.1:15888')
    [Probe]::AllowCtrlC()
    # With redirected output and no -NoNewWindow the core gets its own console,
    # which is what send-ctrlc.ps1 attaches to.
    $p = Start-Process -FilePath $core -ArgumentList $arguments -WorkingDirectory $CoreDir -PassThru `
        -RedirectStandardOutput (Join-Path $OutDir "$tag.stdout.log") `
        -RedirectStandardError (Join-Path $OutDir "$tag.stderr.log")
    $null = $p.Handle # keeps ExitCode readable after exit
    $p
}

# Waits for the adapter to carry its address and the on-link route, then lets it settle.
function Wait-Adapter($process, [string]$devName = $Name) {
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if ($process.HasExited) { throw "easytier-core exited early with code $($process.ExitCode)" }
        $found = [Probe]::Interfaces() | Where-Object { $_.Alias -eq $devName -and $_.OperStatus -ne 6 } | Select-Object -First 1
        if ($found -and ([Probe]::Addresses($found.Luid) -contains '10.144.144.1') -and
            ([Probe]::Routes($found.Luid) -contains '10.144.144.0/24')) {
            Start-Sleep -Seconds 5
            return $found
        }
        Start-Sleep -Milliseconds 250
    }
    throw "adapter $devName did not become ready within 60 s"
}

function Format-Row($s) {
    $nodes = @($s.Nodes | Where-Object Id -EQ $predictedId)
    $state = if (-not $nodes) { 'none' } elseif ($nodes[0].Live) { 'live' } elseif ($nodes[0].Phantom) { 'phantom' } else { 'listed-unlocatable' }
    [pscustomobject]@{
        targetMs = $s.TargetMs; atMs = $s.AtMs; tookMs = $s.TookMs
        ifRows = $s.Interfaces.Count; ifPresent = @($s.Interfaces | Where-Object OperStatus -NE 6).Count
        ifOper = (($s.Interfaces | ForEach-Object OperStatus) -join ','); ipIfs = $s.IpInterfaces; routes = $s.Routes.Count; addresses = $s.Addresses.Count
        devnode = $state; wintunNodes = $s.Nodes.Count
    }
}

if (Get-Process easytier-core -ErrorAction SilentlyContinue) { throw 'another easytier-core is already running' }
"core: $core"
& $core --version
Get-ChildItem $CoreDir | Format-Table Name, Length | Out-String
"wintun.dll version: $((Get-Item (Join-Path $CoreDir 'wintun.dll')).VersionInfo.FileVersion)"
"windows: $([Environment]::OSVersion.VersionString)"
"adapter name $Name, predicted GUID $guidText"
$initial = [Probe]::Take($Name, 0, $guid)
"before first run: interfaces=$($initial.Interfaces.Count) wintunNodes=$($initial.Nodes.Count)"

$results = @()
$plan = @(
    for ($i = 1; $i -le $KillRuns; $i++) { "kill-$i" }
    for ($i = 1; $i -le $GracefulRuns; $i++) { "graceful-$i" }
)
foreach ($tag in $plan) {
    "`n===== $tag ====="
    $mode = $tag.Split('-')[0]
    $p = Start-Core $tag
    try {
        $adapter = Wait-Adapter $p
        $before = [Probe]::Take($Name, $adapter.Luid, $adapter.Guid)
        $node = @($before.Nodes | Where-Object Id -EQ $predictedId)
        "pid=$($p.Id) luid=0x$($adapter.Luid.ToString('X16')) ifIndex=$($adapter.Index) guid=$($adapter.Guid) guidMatchesPrediction=$($adapter.Guid -eq $guid)"
        "before: interfaces=[$(($before.Interfaces.Alias) -join '; ')]"
        "before: routes=[$($before.Routes -join ', ')] addresses=[$($before.Addresses -join ', ')]"
        "before: wintun nodes: $(($before.Nodes | ForEach-Object { "$($_.Id) live=$($_.Live) phantom=$($_.Phantom) status=0x$($_.Status.ToString('X8')) problem=$($_.Problem)" }) -join '; ')"
        if (-not $node -or -not $node[0].Live) { throw "no live device node $predictedId; the instance id prediction is wrong" }
        $toolsBefore = Get-ToolCounts $adapter.Index
        "tools before: $($toolsBefore | ConvertTo-Json -Compress)"
        Save-ToolView (Join-Path $OutDir "$tag.tools-before.txt") $adapter.Index
        $leftBefore = Get-Leftovers
        "state before: $($leftBefore | ConvertTo-Json -Compress)"
        if ($p.HasExited) { throw "easytier-core exited before the test with code $($p.ExitCode)" }

        $clock = [Diagnostics.Stopwatch]::StartNew()
        if ($mode -eq 'kill') {
            [Probe]::HardKill($p.Handle)
        }
        else {
            $helper = Start-Process pwsh -ArgumentList '-NoProfile', '-File', "`"$(Join-Path $PSScriptRoot 'send-ctrlc.ps1')`"", '-TargetPid', $p.Id -PassThru -WindowStyle Hidden
            $null = $helper.Handle
        }
        if (-not $p.WaitForExit(30000)) { throw "$tag`: process did not exit within 30 s" }
        $exitMs = $clock.ElapsedMilliseconds
        # t = 0 is the moment the process is observed to have exited.
        $samples = [Probe]::Timeline($Name, $adapter.Luid, $adapter.Guid, 250, 5000)
        $rows = @($samples | ForEach-Object { Format-Row $_ })
        if ($mode -eq 'graceful') { $helper.WaitForExit(); "ctrl-c helper exit code=$($helper.ExitCode)" }
        "exit code=$($p.ExitCode), $exitMs ms after the $(if ($mode -eq 'kill') { 'TerminateProcess call' } else { 'Ctrl+C helper start' })"
        $rows | Format-Table -AutoSize | Out-String
        $toolsAfter = Get-ToolCounts $adapter.Index
        "tools after 5 s: $($toolsAfter | ConvertTo-Json -Compress)"
        Save-ToolView (Join-Path $OutDir "$tag.tools-after.txt") $adapter.Index
        $leftAfter = Get-Leftovers
        "state after:  $($leftAfter | ConvertTo-Json -Compress)"

        $results += [pscustomobject]@{
            run = $tag; mode = $mode; luid = '0x' + $adapter.Luid.ToString('X16'); ifIndex = $adapter.Index
            guid = "$($adapter.Guid)"; exitCode = $p.ExitCode; exitMs = $exitMs; timeline = $rows
            toolsBefore = $toolsBefore; toolsAfter = $toolsAfter
            stateBefore = $leftBefore; stateAfter = $leftAfter
        }
    }
    finally {
        if (-not $p.HasExited) { $p.Kill() }
        "--- $tag stdout (tail)"
        Get-Content (Join-Path $OutDir "$tag.stdout.log") -Tail 15 -ErrorAction SilentlyContinue
    }
}
$results | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutDir 'results.json')

"`n===== summary ====="
# "gone at" is the first sample from which the object stays absent until 5 s.
function Get-GoneAt($rows, [scriptblock]$present) {
    $gone = $null
    foreach ($r in $rows) {
        if (& $present $r) { $gone = $null } elseif ($null -eq $gone) { $gone = $r.atMs }
    }
    if ($null -eq $gone) { 'STILL PRESENT' } else { "$gone ms" }
}
$summary = foreach ($r in $results) {
    [pscustomobject]@{
        run = $r.run; luid = $r.luid; ifIndex = $r.ifIndex; exitMs = $r.exitMs
        interfaceGone = Get-GoneAt $r.timeline { param($x) $x.ifPresent -gt 0 -or $x.ipIfs -gt 0 }
        routesGone    = Get-GoneAt $r.timeline { param($x) $x.routes -gt 0 -or $x.addresses -gt 0 }
        liveNodeGone  = Get-GoneAt $r.timeline { param($x) $x.devnode -eq 'live' }
        devnodeAt5s   = $r.timeline[-1].devnode
        ifRowsAt5s    = "$($r.timeline[-1].ifRows) (oper $($r.timeline[-1].ifOper))"
    }
}
$summary | Format-Table -AutoSize | Out-String -Width 200
$summary | ConvertTo-Json | Set-Content (Join-Path $OutDir 'summary.json')

$killed = @($results | Where-Object mode -EQ 'kill')
$survivors = @($killed | Where-Object { $_.timeline[-1].ifPresent -gt 0 -or $_.timeline[-1].ipIfs -gt 0 -or $_.timeline[-1].routes -gt 0 -or $_.timeline[-1].devnode -eq 'live' })
if ($survivors) { "VERDICT: adapter SURVIVES a hard kill in $($survivors.Count)/$($killed.Count) runs" }
else { "VERDICT: present interface, IP interface, routes and live device node are gone within 5 s after TerminateProcess in $($killed.Count)/$($killed.Count) runs" }

# --- Removing what is left, and whether LUID / instance id identify a generation.
function Get-InstanceId([string]$devName) { "SWD\Wintun\$((Get-WintunGuid $devName).ToString('B').ToUpperInvariant())" }

function Show-Residue([string]$devName) {
    $g = Get-WintunGuid $devName
    $node = [Probe]::Locate((Get-InstanceId $devName))
    $rows = @([Probe]::Interfaces() | Where-Object { $_.Guid -eq $g -or $_.Alias -like "$devName*" })
    $svc = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $net = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    $b = $g.ToString('B')
    "residue $devName`: node live=$($node.Live) phantom=$($node.Phantom); " +
    "ifRows=$($rows.Count) [$(($rows | ForEach-Object { "luid=0x$($_.Luid.ToString('X16')) oper=$($_.OperStatus)" }) -join '; ')]; " +
    "keys Control\Network=$(Test-Path -LiteralPath "$net\$b") Tcpip=$(Test-Path -LiteralPath "$svc\Tcpip\Parameters\Interfaces\$b") " +
    "Tcpip6=$(Test-Path -LiteralPath "$svc\Tcpip6\Parameters\Interfaces\$b") NetBT=$(Test-Path -LiteralPath "$svc\NetBT\Parameters\Interfaces\Tcpip_$b"); " +
    "firewall rules naming it=$(@(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object DisplayName -Like "*$devName*").Count)"
}

function Invoke-Generation([string]$tag, [string]$devName) {
    $p = Start-Core $tag $devName
    try {
        $a = Wait-Adapter $p $devName
        "generation $tag $devName`: luid=0x$($a.Luid.ToString('X16')) ifIndex=$($a.Index) guid=$($a.Guid)"
        [Probe]::HardKill($p.Handle)
        if (-not $p.WaitForExit(30000)) { throw "$tag did not exit" }
        Start-Sleep -Seconds 5
    }
    finally { if (-not $p.HasExited) { $p.Kill() } }
}

"`n===== removal and identity ====="
$nameB = 'etd-00000000'; $nameC = 'etd-ffffffff'
Show-Residue $Name
'-- another name while the phantom of the first is still there'
Invoke-Generation 'identity-b' $nameB
Show-Residue $nameB
$id = Get-InstanceId $Name
"-- remove the first: pnputil /remove-device `"$id`""
pnputil /remove-device $id
if ($LASTEXITCODE -ne 0) { throw "pnputil /remove-device failed with $LASTEXITCODE" }
'pnputil exit code=0'
Show-Residue $Name
$id = Get-InstanceId $nameB
"-- remove the second: DiUninstallDevice($id)"
"needReboot=$([Probe]::Uninstall($id))"
Show-Residue $nameB
'-- a third name after both are removed'
Invoke-Generation 'identity-c' $nameC
'-- the first name again, after its removal'
Invoke-Generation 'identity-a-again' $Name
foreach ($n in $nameC, $Name) {
    "DiUninstallDevice $n needReboot=$([Probe]::Uninstall((Get-InstanceId $n)))"
    Show-Residue $n
}
$left = @([Probe]::WintunNodes())
"wintun nodes left=$($left.Count)"
if ($left.Count) { throw 'device nodes remain after removal' }
$global:LASTEXITCODE = 0
