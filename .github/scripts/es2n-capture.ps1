# ES2N gate (doc#17): judge one Process Monitor capture. For the processes
# matching -Processes it fails on any COM class, interface, AppID or type
# library lookup, on any image loaded from outside System32, WinSxS or the
# -Allowed directories, and on any -Absent DLL a process loads; for the
# -Product processes also on any access to a user hive (HKCU or any hive
# under HKU) that is not an exact operation and path of
# es2n-hkcu-allowed.tsv. Writes
# <Name>-events.csv, <Name>-loads.txt and <Name>-verdict.txt to -Out.
# Exit 1: the capture fails the gate.
param(
  [Parameter(Mandatory)][string]$Name,
  [Parameter(Mandatory)][string]$Processes,
  [string[]]$Allowed = @(),
  # The product's processes: their HKCU accesses fail the gate. Test
  # processes (which also start PowerShell and other children) are listed.
  [string]$Product = '^etd-host\.exe$',
  # Exact HKCU accesses the product may make (es2n-hkcu-allowed.tsv).
  [string]$HkcuAllowed = (Join-Path $PSScriptRoot 'es2n-hkcu-allowed.tsv'),
  # "<process image>=<dll>": that DLL must not be loaded by that process.
  [string[]]$Absent = @(),
  [string]$Procmon = 'C:\pm\Procmon64.exe',
  [string]$Out = 'C:\pm\out'
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
& $Procmon /AcceptEula /Terminate
Start-Sleep -Seconds 5
Start-Process $Procmon -ArgumentList '/AcceptEula','/Quiet','/OpenLog',"C:\pm\$Name.pml",'/SaveAs',"C:\pm\$Name.csv" -Wait
$rows = Import-Csv "C:\pm\$Name.csv"
$ours = @($rows | Where-Object { $_.'Process Name' -match $Processes })
$ours | Export-Csv "$Out\$Name-events.csv" -NoTypeInformation
Remove-Item "C:\pm\$Name.csv"
$verdict = [System.Collections.Generic.List[string]]::new()
$verdict.Add("[$Name] events: $($rows.Count) captured, $($ours.Count) by $Processes")
$ours | Group-Object 'Process Name' | ForEach-Object { $verdict.Add("  $($_.Name): $($_.Count)") }
if ($ours.Count -eq 0) { $verdict.Add('FAIL: no events by the processes under test') }
$reg = @($ours | Where-Object { $_.Operation -like 'Reg*' })
$com = @($reg | Where-Object { $_.Path -match '(^HKCR|Classes)\\(CLSID|Interface|AppID|TypeLib)(\\|$)' })
# Every user hive is judged alike: HKCU and every hive loaded under HKU
# (account SIDs, the service accounts S-1-5-18/19/20, .DEFAULT, any other
# SID), each matched as HKCU\<rest of the path>; a <SID>_Classes hive is
# the user's Software\Classes. RegSetInfoKey is matched with its
# information class, so only the class on the list passes.
$userHive = '^(HKCU|HKU\\[^\\]+)(?=\\|$)'
$classesHive = '^HKU\\[^\\]+_Classes(?=\\|$)'
$hkcu = @($reg | Where-Object { $_.Path -match $userHive })
function Get-Canonical($row) {
  $path = if ($row.Path -match $classesHive) { $row.Path -replace $classesHive, 'HKCU\Software\Classes' } else { $row.Path -replace $userHive, 'HKCU' }
  $operation = $row.Operation
  if ($operation -eq 'RegSetInfoKey') {
    $class = if ($row.Detail -match 'KeySetInformationClass:\s*(\w+)') { $Matches[1] } else { 'unknown' }
    $operation = "RegSetInfoKey:$class"
  }
  "$operation|$path".ToLowerInvariant()
}
$permitted = @{}
foreach ($line in Get-Content $HkcuAllowed) {
  if ($line -match '^\s*(#|$)') { continue }
  $group, $operations, $path, $reason = $line -split "`t"
  foreach ($operation in $operations -split ',') { $permitted["$operation|$path".ToLowerInvariant()] = $group }
}
$productHkcu = @($hkcu | Where-Object { $_.'Process Name' -match $Product })
$user = @($productHkcu | Where-Object { -not $permitted.ContainsKey((Get-Canonical $_)) })
$listed = @($productHkcu | Where-Object { $permitted.ContainsKey((Get-Canonical $_)) })
$testUser = @($hkcu | Where-Object { $_.'Process Name' -notmatch $Product })
$windows = $env:SystemRoot.TrimEnd('\') + '\'
$trusted = @("$($windows)System32\", "$($windows)WinSxS\") + @($Allowed | ForEach-Object { $_.TrimEnd('\') + '\' })
$loads = @($ours | Where-Object { $_.Operation -eq 'Load Image' })
$loads | ForEach-Object { "$($_.'Process Name') $($_.PID) $($_.Path)" } | Out-File "$Out\$Name-loads.txt"
$foreign = @($loads | Where-Object { $p = $_.Path; -not ($trusted | Where-Object { $p.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }) })
foreach ($check in @(
    @{ what = 'COM class/interface/AppID/type library lookups'; rows = $com; show = { "$($_.'Process Name') $($_.Operation) $($_.Path) $($_.Result)" } },
    @{ what = 'product user-hive accesses off the allowed list'; rows = $user; show = { "$($_.'Process Name') $($_.PID) $($_.Operation) $($_.Path) $($_.Result)" } },
    @{ what = 'image loads outside System32, WinSxS and our directories'; rows = $foreign; show = { "$($_.'Process Name') $($_.Path)" } })) {
  $lines = @($check.rows | ForEach-Object $check.show | Group-Object | ForEach-Object { '{0,5}  {1}' -f $_.Count, $_.Name })
  if ($lines.Count -gt 0) {
    $verdict.Add("FAIL: $($check.what): $($check.rows.Count)")
    $lines | ForEach-Object { $verdict.Add($_) }
  } else {
    $verdict.Add("ok: no $($check.what)")
  }
}
foreach ($pair in $Absent) {
  $process, $dll = $pair -split '=', 2
  $hits = @($loads | Where-Object { $_.'Process Name' -ieq $process -and $_.Path -match "\\$([regex]::Escape($dll))$" })
  if ($hits.Count -gt 0) { $verdict.Add("FAIL: $process loaded $dll ($($hits.Count))") } else { $verdict.Add("ok: $process did not load $dll") }
}
$verdict.Add("note: product user-hive accesses on the allowed list: $($listed.Count)")
$listed | ForEach-Object { "$($permitted[(Get-Canonical $_)]) $($_.Operation) $($_.Path) $($_.Result)" } | Group-Object | Sort-Object Name | ForEach-Object { $verdict.Add(('{0,7}  {1}' -f $_.Count, $_.Name)) }
$verdict.Add("note: user-hive accesses by test processes (not judged): $($testUser.Count)")
$testUser | ForEach-Object { "$($_.'Process Name') $($_.Path) $($_.Result)" } | Group-Object | Sort-Object Count -Descending | ForEach-Object { $verdict.Add(('{0,7}  {1}' -f $_.Count, $_.Name)) }
foreach ($dll in 'combase','oleaut32','ole32','shell32','windows.storage','FirewallAPI') {
  $hits = @($loads | Where-Object { $_.Path -match "\\$([regex]::Escape($dll))\.dll$" } | ForEach-Object { $_.'Process Name' } | Sort-Object -Unique)
  $verdict.Add("note: $dll.dll loaded by: $($hits -join ', ')")
}
$verdict | Out-File "$Out\$Name-verdict.txt"
$verdict | Write-Host
if ($verdict | Where-Object { $_ -like 'FAIL:*' }) { exit 1 }
# Explicitly: a passing verdict must not inherit the caller's last exit code.
exit 0
