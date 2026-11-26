# Read-only native inventory. Export stable policy fields, never command
# lines, service credentials, or arbitrary registry hive contents.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$inventory = @{}
foreach ($class in 'interface','route','resolver','firewall','registry','service','process') {
    $inventory[$class] = @{}
}
foreach ($nic in Get-NetAdapter -IncludeHidden) {
    $inventory.interface[$nic.Name] = @($nic.ifIndex, $nic.InterfaceGuid, $nic.PnPDeviceID)
}
Get-NetRoute -PolicyStore ActiveStore | Group-Object InterfaceAlias | ForEach-Object {
    $inventory.route[$_.Name] = @($_.Group | ForEach-Object {
        "$($_.DestinationPrefix) $($_.NextHop) $($_.RouteMetric) $($_.Protocol)"
    } | Sort-Object)
}
foreach ($rule in Get-DnsClientNrptRule) {
    $inventory.resolver[$rule.Name] = @($rule.Namespace, $rule.NameServers, $rule.Comment)
}
foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
    $_.Group -eq 'EasyTier' -or $_.DisplayName -like 'EasyTier *'
}) {
    $app = $rule | Get-NetFirewallApplicationFilter
    $ports = $rule | Get-NetFirewallPortFilter
    $inventory.firewall["policy/$($rule.Name)"] = @(
        $rule.DisplayName, $rule.Group, [string]$rule.Direction, [string]$rule.Action,
        [string]$rule.Enabled, $app.Program, [string]$ports.Protocol, $ports.LocalPort
    )
}
$wfp = Join-Path $env:RUNNER_TEMP ("g2-wfp-{0}.xml" -f [guid]::NewGuid())
try {
    $null = & netsh.exe wfp show filters "file=$wfp" verbose=on
    if ($LASTEXITCODE -ne 0) { throw "WFP inventory failed ($LASTEXITCODE)" }
    [xml]$xml = Get-Content -Raw -LiteralPath $wfp
    foreach ($filter in $xml.SelectNodes('//*[filterKey and displayData]')) {
        $label = [string]$filter.displayData.name
        if ($label.StartsWith('etd-fence:')) {
            $inventory.firewall["wfp/$($filter.filterKey)"] = @($label, $filter.OuterXml)
        }
    }
} finally {
    if (Test-Path -LiteralPath $wfp) { Remove-Item -LiteralPath $wfp }
}
$system = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$network = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
foreach ($tree in @("$system\Tcpip\Parameters\Interfaces","$system\Tcpip6\Parameters\Interfaces",
                     "$system\NetBT\Parameters\Interfaces",$network)) {
    if (!(Test-Path -LiteralPath $tree)) { continue }
    foreach ($key in Get-ChildItem -LiteralPath $tree) {
        foreach ($name in $key.GetValueNames()) {
            if ($name -in @('RegistrationEnabled','DisableDynamicUpdate',
                'MaxNumberOfAddressesToRegister','NetbiosOptions','SearchList','ProfileName','Category')) {
                $id = $key.Name.Replace('HKEY_LOCAL_MACHINE','HKLM') + '\' + $name
                $inventory.registry[$id] = @([string]$key.GetValueKind($name),$key.GetValue($name))
            }
        }
    }
}
foreach ($class in 'Win32_Service','Win32_SystemDriver') {
    foreach ($item in Get-CimInstance -ClassName $class -Property Name,PathName,StartMode,ServiceType) {
        $inventory.service[$item.Name.ToLowerInvariant()] = @($item.PathName, $item.StartMode, $item.ServiceType)
    }
}
$paths = @(ConvertFrom-Json $env:ETD_G2_IMAGES)
foreach ($p in Get-CimInstance Win32_Process -Property ProcessId,ExecutablePath,CreationDate) {
    if (!$p.ExecutablePath) { continue }
    foreach ($path in $paths) {
        if ($p.ExecutablePath -eq $path -or
            $p.ExecutablePath.StartsWith("$path\",[StringComparison]::OrdinalIgnoreCase)) {
            $inventory.process[[string]$p.ProcessId] = @($p.ExecutablePath, $p.CreationDate.ToString('o'))
            break
        }
    }
}
ConvertTo-Json -InputObject $inventory -Depth 12 -Compress
