# Read-only native inventory. Export stable policy fields, never command
# lines, service credentials, or arbitrary registry hive contents.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$inventory = @{}
foreach ($class in 'interface','route','resolver','firewall','registry','service','process') {
    $inventory[$class] = @{}
}
$addresses = @{}
Get-NetIPAddress -PolicyStore ActiveStore | Group-Object InterfaceIndex | ForEach-Object {
    $addresses[[int]$_.Name] = @($_.Group | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" } | Sort-Object)
}
foreach ($nic in Get-NetAdapter -IncludeHidden) {
    $inventory.interface[$nic.Name] = @{
        index=$nic.ifIndex; guid=$nic.InterfaceGuid; device=$nic.PnPDeviceID
        addresses=$addresses[[int]$nic.ifIndex]
    }
}
# IPv6 tunnel and software loopback interfaces may have no NetAdapter row.
foreach ($nic in Get-NetIPInterface) {
    if (!$inventory.interface.ContainsKey($nic.InterfaceAlias)) {
        $inventory.interface[$nic.InterfaceAlias] = @{
            index=$nic.InterfaceIndex; addresses=$addresses[[int]$nic.InterfaceIndex]
        }
    }
}
Get-NetRoute -PolicyStore ActiveStore | Group-Object InterfaceAlias | ForEach-Object {
    $inventory.route[$_.Name] = @($_.Group | ForEach-Object {
        "$($_.DestinationPrefix) $($_.NextHop) $($_.RouteMetric) $($_.Protocol)"
    } | Sort-Object)
}
foreach ($rule in Get-DnsClientNrptRule) {
    $inventory.resolver[$rule.Name] = @($rule.Namespace, $rule.NameServers, $rule.Comment)
}
$rulesPath = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
$ruleStore = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rulesPath)
foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
    $_.Group -eq 'EasyTier' -or $_.DisplayName -like 'EasyTier *'
}) {
    $app = $rule | Get-NetFirewallApplicationFilter
    $ports = $rule | Get-NetFirewallPortFilter
    $inventory.firewall["policy/$($rule.Name)"] = @(
        $rule.DisplayName, $rule.Group, [string]$rule.Direction, [string]$rule.Action,
        [string]$rule.Enabled, $app.Program, [string]$ports.Protocol, $ports.LocalPort,
        $ruleStore.GetValue($rule.Name)
    )
}
$ruleStore.Dispose()
$system = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$network = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
$product = 'HKLM:\SOFTWARE\EasyTier'
if (Test-Path -LiteralPath $product) {
    foreach ($key in Get-ChildItem -Recurse -LiteralPath $product) {
        foreach ($name in $key.GetValueNames()) {
            $id = $key.Name.Replace('HKEY_LOCAL_MACHINE','HKLM') + '\' + $name
            $inventory.registry[$id] = @([string]$key.GetValueKind($name), $key.GetValue($name))
        }
    }
}
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
# Read the installed configuration. CIM's live service view can change when
# Windows spins up a service host independently of a registration change.
$serviceStore = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services')
$rawValue = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
try {
    foreach ($name in $serviceStore.GetSubKeyNames()) {
        $entry = $serviceStore.OpenSubKey($name)
        if ($null -eq $entry) { continue }
        try {
            if ($null -eq $entry.GetValue('Type') -or $null -eq $entry.GetValue('Start')) { continue }
            $values = @{}
            foreach ($field in 'Type','Start','ImagePath','ErrorControl','DependOnService','ObjectName') {
                $values[$field] = $entry.GetValue($field, $null, $rawValue)
            }
            $inventory.service[$name.ToLowerInvariant()] = $values
        } finally { $entry.Dispose() }
    }
} finally { $serviceStore.Dispose() }
ConvertTo-Json -InputObject $inventory -Depth 12 -Compress
