# Kernel COM investigation (topic#51 msg#2114): register the firewall COM
# classes the kernel activates (NetFwPolicy2, NetFwRule) in the user's own
# HKCU, as any process of that user could, pointing at the marker DLL.
# -Remove undoes it. Disposable Windows CI runners only.
param([switch]$Remove, [string]$Dll = 'C:\etd-kcom\marker.dll')
$ErrorActionPreference = 'Stop'
$classes = 'HKCU:\Software\Classes\CLSID'
$clsids = '{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}', '{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}'
if ($Remove) {
  foreach ($c in $clsids) { Remove-Item "$classes\$c" -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Host 'kcom-plant: removed'
  return
}
foreach ($c in $clsids) {
  if (Test-Path "$classes\$c") { throw "HKCU already has $c" }
  $k = New-Item "$classes\$c\InprocServer32" -Force
  Set-ItemProperty $k.PSPath '(default)' $Dll
  Set-ItemProperty $k.PSPath 'ThreadingModel' 'Both'
}
Write-Host "kcom-plant: $($clsids -join ', ') -> $Dll"
