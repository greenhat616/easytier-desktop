# ES2N gate (doc#17): judge one Process Monitor capture. For the processes
# matching -Processes it fails on any COM class, interface, AppID or type
# library lookup in any hive, on any HKCU access other than combase's
# feature-flag key, and on any image loaded from outside System32, WinSxS
# or the -Allowed directories, and on any -Absent DLL a process loads.
# Writes <Name>-events.csv, <Name>-loads.txt
# and <Name>-verdict.txt to -Out. Exit 1: the capture fails the gate.
param(
  [Parameter(Mandatory)][string]$Name,
  [Parameter(Mandatory)][string]$Processes,
  [string[]]$Allowed = @(),
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
$com = @($reg | Where-Object { $_.Path -match '\(CLSID|Interface|AppID|TypeLib)(\|$)' })
$feature = '^HKCU\Software\Classes\Local Settings\Software\Microsoft\Ole\FeatureDevelopmentProperties(\|$)'
$user = @($reg | Where-Object { $_.Path -match '^(HKCU|HKU\S-1-5-21-[^\]+)(\|$)' -and $_.Path -notmatch $feature })
$windows = $env:SystemRoot.TrimEnd('\') + '\'
$trusted = @("$($windows)System32\", "$($windows)WinSxS\") + @($Allowed | ForEach-Object { $_.TrimEnd('\') + '\' })
$loads = @($ours | Where-Object { $_.Operation -eq 'Load Image' })
$loads | ForEach-Object { "$($_.'Process Name') $($_.PID) $($_.Path)" } | Out-File "$Out\$Name-loads.txt"
$foreign = @($loads | Where-Object { $p = $_.Path; -not ($trusted | Where-Object { $p.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }) })
foreach ($check in @(
    @{ what = 'COM class/interface/AppID/type library lookups'; rows = $com; show = { "$($_.'Process Name') $($_.Operation) $($_.Path) $($_.Result)" } },
    @{ what = 'HKCU accesses other than the combase feature-flag key'; rows = $user; show = { "$($_.'Process Name') $($_.Operation) $($_.Path) $($_.Result)" } },
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
$featureReads = @($reg | Where-Object { $_.Path -match $feature })
$verdict.Add("note: combase feature-flag key accesses: $($featureReads.Count)")
foreach ($dll in 'combase','oleaut32','ole32','shell32','windows.storage','FirewallAPI') {
  $hits = @($loads | Where-Object { $_.Path -match "\$([regex]::Escape($dll))\.dll$" } | ForEach-Object { $_.'Process Name' } | Sort-Object -Unique)
  $verdict.Add("note: $dll.dll loaded by: $($hits -join ', ')")
}
$verdict | Out-File "$Out\$Name-verdict.txt"
$verdict | Write-Host
if ($verdict | Where-Object { $_ -like 'FAIL:*' }) { exit 1 }
