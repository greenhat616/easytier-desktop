# Invoked only via the fixed system PowerShell path; request data is JSON,
# never interpolated into executable script source. All output is UTF-8 JSON.
# No module is autoloaded: autoloading searches the user's Documents module
# directory (a known folder HKCU can redirect) and reads the module analysis
# cache, both writable by the user's non-elevated processes when the host
# runs with the user's elevated token. Every module the script uses is
# imported from $PSHOME by absolute path.
$PSModuleAutoLoadingPreference = 'None'
$ErrorActionPreference = 'Stop'
# Microsoft.PowerShell.Utility: ConvertFrom-Json, ConvertTo-Json, Select-Object, Sort-Object
# CimCmdlets: Get-CimInstance
# NetSecurity: Get-NetFirewallRule, Get-NetFirewallApplicationFilter, Remove-NetFirewallRule
# NetTCPIP: Get-NetIPAddress, Get-NetRoute, Get-NetTCPConnection
foreach ($module in 'Microsoft.PowerShell.Utility','CimCmdlets','NetSecurity','NetTCPIP') {
    Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules',$module,"$module.psd1"))
}
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$q = if ($env:ETD_OS_SERVE -eq '1') { $null } else { ConvertFrom-Json $env:ETD_OS_REQUEST }
$nrpt = 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
$profiles = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
$signatures = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged'
$magic = 'SOFTWARE\EasyTier\MagicDNS'
$tcpip = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
$tcpip6 = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces'
$netbt = 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
function GuidText($s) { return ([guid]$s).ToString('B').ToUpperInvariant() }
function RegistryPath($s) { if (!$s.StartsWith('HKLM\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Not HKLM' }; return $s.Substring(5) }
function RegOpen($s, $write = $false) { return $hklm.OpenSubKey($s, $write) }
function RegNames($s) { $k = RegOpen $s; if ($null -ne $k) { try { $k.GetSubKeyNames() } finally { $k.Dispose() } } }
function ReadValue($k,$n) {
    if ($null -eq $k -or $k.GetValueNames() -notcontains $n) { return @{type='absent'} }
    $v = $k.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    switch ($k.GetValueKind($n).ToString()) {
        'String' { return @{type='string';value=[string]$v} }
        'MultiString' { return @{type='multi_string';value=@($v)} }
        'DWord' { return @{type='u32';value=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$v),0)} }
        'QWord' { return @{type='u64';value=[BitConverter]::ToUInt64([BitConverter]::GetBytes([long]$v),0)} }
        'Binary' { return @{type='bytes';value=@($v)} }
        default { throw 'Unsupported registry value type' }
    }
}
function SameValue($a,$b) { return $a.type -eq $b.type -and (ConvertTo-Json -InputObject $a.value -Compress -Depth 10) -ceq (ConvertTo-Json -InputObject $b.value -Compress -Depth 10) }
function WriteValue($k,$n,$v) {
    switch ($v.type) {
        'absent' { $k.DeleteValue($n,$false) }
        'string' { $k.SetValue($n,[string]$v.value,'String') }
        'multi_string' { $k.SetValue($n,[string[]]$v.value,'MultiString') }
        'u32' { $k.SetValue($n,[BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$v.value),0),'DWord') }
        'u64' { $k.SetValue($n,[BitConverter]::ToInt64([BitConverter]::GetBytes([uint64]$v.value),0),'QWord') }
        'bytes' { $k.SetValue($n,[byte[]]$v.value,'Binary') }
        default { throw 'Unsupported restore type' }
    }
}
function FirewallRows {
    $store = RegOpen 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    try {
        Get-NetFirewallRule -PolicyStore PersistentStore | ForEach-Object {
            $ruleId=$_.Name
            try {
            $raw = if ($store) { $store.GetValue($_.Name) } else { $null }
            if (!$q.name -or $_.DisplayName -eq $q.name) {
                $program = $null
                # Upstream program rules always have an absolute executable
                # path embedded in their display name. Read the *actual*
                # application condition independently, not from that name.
                if ($_.DisplayName -match '^EasyTier (?:[A-Za-z]:\\|\\\\).+ \((Inbound|Outbound)\)$') {
                    $a = @($_ | Get-NetFirewallApplicationFilter)
                    if ($a.Count -ne 1) { throw 'Ambiguous firewall application condition' }
                    $program = $a[0].Program
                }
                @{name=$_.DisplayName;group=$_.Group;id=$_.Name;program=$program;direction=$_.Direction.ToString();description=if ($null -ne $raw) { [string]$raw } else { ($_ | Select-Object DisplayName,Group,Direction,Action,Enabled,Profile,Description | ConvertTo-Json -Compress) }}
            }
            } catch { if ($q.sweep) { @{warning=$_.Exception.Message;object=$ruleId} } else { throw } }
        }
    } finally { if ($store) { $store.Dispose() } }
}
function NrptRows {
    foreach ($id in @(RegNames $nrpt)) { try { $k = RegOpen "$nrpt\$id"; if ($k) { try { @{name=$id;group=[string]$k.GetValue('Comment');id=$id;description=($k.GetValueNames() | Sort-Object | ForEach-Object { "$_=$($k.GetValue($_) -join ',')" }) -join ';'} } finally { $k.Dispose() } } } catch { if ($q.sweep) { @{warning=$_.Exception.Message;object=$id} } else { throw } } }
}
function ProfileRows {
    foreach ($id in @(RegNames $profiles)) { try { $k = RegOpen "$profiles\$id"; if ($k) { try { @{name=[string]$k.GetValue('ProfileName');id=$id;description=($k.GetValueNames() | Sort-Object | ForEach-Object { "$_=$($k.GetValue($_) -join ',')" }) -join ';'} } finally { $k.Dispose() } } } catch { if ($q.sweep) { @{warning=$_.Exception.Message;object=$id} } else { throw } } }
}
function Execute-Request {
    switch ($q.op) {
        'firewall' { return @(FirewallRows) }
        'nrpt' { return @(NrptRows) }
        'profiles' { return @(ProfileRows) }
        'delete_firewall' {
            $r = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -eq $q.id -and $_.DisplayName -eq $q.name -and (!$q.group -or $_.Group -eq $q.group) })
            if ($r.Count -ne 1) { throw 'Credential changed before firewall deletion' }
            if ($q.program) {
                $a = @($r[0] | Get-NetFirewallApplicationFilter)
                if ($a.Count -ne 1 -or ([string]$a[0].Program).Replace('\\?\','') -ine $q.program -or $r[0].Direction.ToString() -ine $q.direction) { throw 'Program firewall credential changed' }
            }
            $r[0] | Remove-NetFirewallRule -ErrorAction Stop
            return 'removed'
        }
        'delete_nrpt' {
            if ((GuidText $q.id) -ine $q.name) { throw 'NRPT credential mismatch' }
            $k = RegOpen "$nrpt\$($q.id)"
            if (!$k) { return 'absent' }
            try { if ($q.group -and $k.GetValue('Comment') -ine $q.group) { throw 'NRPT group mismatch' } } finally { $k.Dispose() }
            $hklm.DeleteSubKey("$nrpt\$($q.id)",$false); return 'removed'
        }
        'delete_profile' {
            if ((GuidText $q.id) -ine $q.id) { throw 'Invalid profile GUID' }
            $k = RegOpen "$profiles\$($q.id)"
            if (!$k) { return 'absent' }
            try { if ($k.GetValue('ProfileName') -ine $q.name) { throw 'Profile credential mismatch' } } finally { $k.Dispose() }
            # Remove only signatures pointing to this verified profile GUID.
            # Do this first so a failure can be retried while the profile
            # record is still present. Never infer signature ownership by name.
            foreach ($signature in @(RegNames $signatures)) {
                $s = RegOpen "$signatures\$signature"
                if (!$s) { continue }
                $matching = $false
                try {
                    $pg = [guid]::Empty
                    if ([guid]::TryParse([string]$s.GetValue('ProfileGuid'),[ref]$pg)) { $matching = $pg -eq [guid]$q.id }
                } finally { $s.Dispose() }
                if ($matching) { $hklm.DeleteSubKeyTree("$signatures\$signature",$false) }
            }
            $k = RegOpen "$profiles\$($q.id)"
            if (!$k) { throw 'Profile disappeared during signature cleanup' }
            try { if ($k.GetValue('ProfileName') -ine $q.name) { throw 'Profile credential changed during signature cleanup' } } finally { $k.Dispose() }
            $hklm.DeleteSubKeyTree("$profiles\$($q.id)",$false); return 'removed'
        }
        'registry' {
            $k = RegOpen (RegistryPath $q.key)
            if (!$k) { return @{type='absent'} }
            try { return ReadValue $k $q.value } finally { $k.Dispose() }
        }
        'restore_registry' {
            $path = RegistryPath $q.key
            $k = RegOpen $path $true
            if (!$k) { return 'absent' }
            try {
                $current = ReadValue $k $q.value
                if (SameValue $current $q.original) { return 'absent' }
                if (!(SameValue $current $q.ours)) { return 'modified' }
                WriteValue $k $q.value $q.original
                return 'restored'
            } finally { $k.Dispose() }
        }
        'magic' { $k = RegOpen $magic; if ($k) { $k.Dispose(); return $true }; return $false }
        'ip_addresses' { return @(Get-NetIPAddress | ForEach-Object { @{index=$_.InterfaceIndex;address=$_.IPAddress;prefix=$_.PrefixLength} }) }
        'routes' { return @(Get-NetRoute | ForEach-Object { @{name=$_.InterfaceAlias;index=$_.InterfaceIndex;description="$($_.DestinationPrefix) via $($_.NextHop) metric $($_.RouteMetric)"} }) }
        'listeners' { return @(Get-NetTCPConnection -State Listen | ForEach-Object { @{address=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess} }) }
        'services' { return @(Get-CimInstance Win32_Service | ForEach-Object { @{name=$_.Name;description="$($_.PathName)|$($_.StartMode)|$($_.State)"} }) }
        'drivers' { return @(Get-CimInstance Win32_SystemDriver | ForEach-Object { @{name=$_.Name;description="$($_.PathName)|$($_.StartMode)|$($_.State)"} }) }
        'processes' { return @(Get-CimInstance Win32_Process | ForEach-Object { @{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;start=$_.CreationDate.ToUniversalTime().Ticks.ToString()} }) }
        'diagnostics' {
            # What the worker runs with, for the session input tests.
            $vars = [Environment]::GetEnvironmentVariables()
            return @{
                environment=@($vars.Keys | Sort-Object | ForEach-Object { @{name=[string]$_;value=[string]$vars[$_]} })
                modules=@(Get-Module | ForEach-Object { @{name=$_.Name;path=$_.Path} })
                autoload=[string]$PSModuleAutoLoadingPreference
                native_images=@([Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -like '*.ni.dll' }).Count
            }
        }
        'registry_rows' {
            foreach ($prefix in @($tcpip,$tcpip6,$netbt)) {
                foreach ($name in @(RegNames $prefix)) {
                    $path = "$prefix\$name"
                    try { $k = RegOpen $path
                    if ($k) { try { foreach ($value in @($k.GetValueNames())) { try { @{key="HKLM\$path";value=$value;description=($k.GetValue($value) -join ',')} } catch { if ($q.sweep) { @{warning=$_.Exception.Message;object="$path\$value"} } else { throw } } } } finally { $k.Dispose() } }
                    } catch { if ($q.sweep) { @{warning=$_.Exception.Message;object=$path} } else { throw } }
                }
            }
        }
        default { throw 'Unknown OS operation' }
    }
}
if ($env:ETD_OS_SERVE -eq '1') {
    # Serve mode: one ASCII JSON request per stdin line, one compressed JSON
    # response per stdout line, until stdin closes. A failed request answers
    # {error} and the worker serves on.
    try {
        while ($null -ne ($line = [Console]::In.ReadLine())) {
            $response = try {
                $script:q = ConvertFrom-Json $line
                $result = Execute-Request
                @{result=@($result | Where-Object { $null -ne $_ })}
            } catch { @{error=[string]$_.Exception.Message} }
            [Console]::Out.WriteLine((ConvertTo-Json -InputObject $response -Depth 20 -Compress))
            [Console]::Out.Flush()
        }
    } finally { $hklm.Dispose() }
    exit 0
}
try {
    $result = Execute-Request
    ConvertTo-Json -InputObject @{result=@($result | Where-Object { $null -ne $_ })} -Depth 20 -Compress
} finally { $hklm.Dispose() }
