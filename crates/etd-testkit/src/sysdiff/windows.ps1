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
    if ($inventory.interface.ContainsKey($nic.Name)) { throw "Duplicate NetAdapter name: $($nic.Name)" }
    $inventory.interface[$nic.Name] = @{
        index=$nic.ifIndex; guid=$nic.InterfaceGuid; device=$nic.PnPDeviceID
        addresses=$addresses[[int]$nic.ifIndex]
    }
}
# IPv6 tunnel and software loopback interfaces may have no NetAdapter row.
foreach ($nic in Get-NetIPInterface) {
    if ($inventory.interface.ContainsKey($nic.InterfaceAlias)) {
        if ($inventory.interface[$nic.InterfaceAlias].index -ne $nic.InterfaceIndex) {
            throw "Ambiguous interface alias: $($nic.InterfaceAlias)"
        }
    } else {
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
$sha = [Security.Cryptography.SHA256]::Create()
function StableHash($value) {
    $json = ConvertTo-Json -InputObject $value -Depth 10 -Compress
    return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-','')
}
# InstanceID joins the native policy rule to its associated filter objects.
# Bulk reads avoid one PowerShell/CIM round trip per filter per rule.
$specs = [ordered]@{
    Application = @('Program','Package')
    Port = @('Protocol','LocalPort','RemotePort','IcmpType','DynamicTarget')
    Address = @('LocalAddress','RemoteAddress')
    Interface = @('InterfaceAlias')
    InterfaceType = @('InterfaceType')
    Service = @('Service')
    Security = @('Authentication','Encryption','LocalUser','RemoteUser','RemoteMachine','OverrideBlockRules')
}
$filters = @{}
foreach ($kind in $specs.Keys) {
    $byId = @{}
    foreach ($filter in (& "Get-NetFirewall${kind}Filter" -PolicyStore ActiveStore)) {
        $fields = [ordered]@{}
        foreach ($field in $specs[$kind]) { $fields[$field] = $filter.$field }
        $byId.Add($filter.InstanceID, $fields)
    }
    $filters[$kind] = $byId
}
foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore) {
    $policyKey = "policy/$($rule.Name)"
    if ($inventory.firewall.ContainsKey($policyKey)) { throw "Duplicate firewall rule ID: $($rule.Name)" }
    $fields = [ordered]@{}
    foreach ($field in 'Description','Profile','Platform','EdgeTraversalPolicy','LooseSourceMapping',
        'LocalOnlyMapping','Owner','PolicyStoreSource','PolicyStoreSourceType') {
        $fields[$field] = $rule.$field
    }
    foreach ($kind in $specs.Keys) {
        if (!$filters[$kind].ContainsKey($rule.InstanceID)) { throw "Missing $kind filter for $policyKey" }
        $fields[$kind] = $filters[$kind][$rule.InstanceID]
    }
    $fields['persistent'] = $ruleStore.GetValue($rule.Name)
    $inventory.firewall["policy/$($rule.Name)"] = @(
        $rule.DisplayName, $rule.Group, [string]$rule.Direction, [string]$rule.Action,
        [string]$rule.Enabled, $fields.Application.Program, (StableHash $fields)
    )
}
$ruleStore.Dispose()
$system = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$network = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
$product = 'HKLM:\SOFTWARE\EasyTier'
$boot = 'HKLM:\SOFTWARE\EasyTierDesk\Volatile'
if (Test-Path -LiteralPath $boot) {
    $key = Get-Item -LiteralPath $boot
    $inventory.registry['HKLM\SOFTWARE\EasyTierDesk\Volatile'] = @('key')
    foreach ($name in $key.GetValueNames()) {
        $inventory.registry["HKLM\SOFTWARE\EasyTierDesk\Volatile\$name"] = @(
            [string]$key.GetValueKind($name), $key.GetValue($name)
        )
    }
}
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
            $id = $key.Name.Replace('HKEY_LOCAL_MACHINE','HKLM') + '\' + $name
            if ($name -in @('RegistrationEnabled','DisableDynamicUpdate',
                'MaxNumberOfAddressesToRegister','NetbiosOptions','SearchList','ProfileName','Category',
                'NameServer','Domain','EnableDHCP','Dhcpv6State','Dhcpv6Iaid')) {
                $type = [string]$key.GetValueKind($name)
                $value = $key.GetValue($name)
                if ($name -eq 'Dhcpv6Iaid' -and $type -eq 'DWord') {
                    $value = ([long]$value) -band 4294967295L
                }
                $inventory.registry[$id] = @($type,$value)
            } elseif ($tree -eq "$system\Tcpip\Parameters\Interfaces" -or
                      $tree -eq "$system\Tcpip6\Parameters\Interfaces") {
                # Include every other per-interface value in the strict diff.
                # Only a digest leaves this process for these opaque settings.
                $inventory.registry[$id] = @([string]$key.GetValueKind($name), (StableHash $key.GetValue($name)))
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
$sha.Dispose()
ConvertTo-Json -InputObject $inventory -Depth 12 -Compress
