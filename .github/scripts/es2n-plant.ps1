# ES2N gate (doc#17): user-writable HKCU inputs an elevated process must not
# act on. -Com plants COM class, TreatAs/AutoTreatAs and proxy/stub
# overrides pointing at a DLL that does not exist; -Junk fills combase's
# feature-flag key, the one HKCU\Software\Classes read the native host does.
# -Remove undoes both. Disposable Windows CI runners only.
param([switch]$Com, [switch]$Junk, [switch]$Remove)
$ErrorActionPreference = 'Stop'
$classes = 'HKCU:\Software\Classes'
$feature = "$classes\Local Settings\Software\Microsoft\Ole\FeatureDevelopmentProperties"
$bogus = '{E7D0E5A1-2B4C-4F6D-9E8A-0123456789AB}'
$dir = 'C:\etd-es2n-planted'
# The WMI interfaces the CIM path of PowerShell marshals (IWbemLocator,
# IWbemServices, IEnumWbemClassObject, IWbemClassObject and others).
$iids = '{DC12A687-737F-11CF-884D-00AA004B2E24}','{9556DC99-828C-11CF-A37E-00AA003240C7}','{027947E1-D731-11CE-A357-000000000001}','{DC12A681-737F-11CF-884D-00AA004B2E24}','{44ACA674-E8FC-11D0-A07C-00C04FB68820}','{44ACA675-E8FC-11D0-A07C-00C04FB68820}'
$proxies = @($iids | ForEach-Object { (Get-ItemProperty "HKLM:\SOFTWARE\Classes\Interface\$_\ProxyStubClsid32" -ErrorAction SilentlyContinue).'(default)' } | Where-Object { $_ } | Sort-Object -Unique)
# WbemLocator, WbemContext, NetFwPolicy2, NetFwRule, the proxies, and one
# class nothing registers.
$clsids = @{ locator='{4590F811-1D3A-11D0-891F-00AA004B2E24}'; context='{674B6698-EE92-11D0-AD71-00C04FD8FDFF}'; fwpolicy='{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}'; fwrule='{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}'; bogus=$bogus }
for ($i = 0; $i -lt $proxies.Count; $i++) { $clsids["proxy$i"] = $proxies[$i] }
if ($Remove) {
  foreach ($c in $clsids.Values) { Remove-Item "$classes\CLSID\$c" -Recurse -Force -ErrorAction SilentlyContinue }
  foreach ($i in $iids) { Remove-Item "$classes\Interface\$i" -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-Item $feature -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host 'es2n-plant: removed'
  return
}
if ($Com) {
  foreach ($label in $clsids.Keys) {
    $c = $clsids[$label]
    if (Test-Path "$classes\CLSID\$c") { throw "HKCU already has $c" }
    $k = New-Item "$classes\CLSID\$c\InprocServer32" -Force
    Set-ItemProperty $k.PSPath '(default)' "$dir\$label.dll"
    Set-ItemProperty $k.PSPath 'ThreadingModel' 'Both'
    if ($label -ne 'bogus') {
      Set-ItemProperty (New-Item "$classes\CLSID\$c\TreatAs" -Force).PSPath '(default)' $bogus
      Set-ItemProperty (New-Item "$classes\CLSID\$c\AutoTreatAs" -Force).PSPath '(default)' $bogus
    }
  }
  foreach ($i in $iids) { Set-ItemProperty (New-Item "$classes\Interface\$i\ProxyStubClsid32" -Force).PSPath '(default)' $bogus }
  Write-Host "es2n-plant: $($clsids.Count) classes ($($proxies -join ', ') as proxies), $($iids.Count) interfaces"
}
if ($Junk) {
  $k = New-Item $feature -Force
  foreach ($n in 1..16) { New-ItemProperty $k.PSPath "etd-junk-$n" -Value ($n * 0x01010101) -PropertyType DWord -Force | Out-Null }
  New-ItemProperty $k.PSPath 'etd-junk-text' -Value "$dir\junk.dll" -PropertyType String -Force | Out-Null
  New-ItemProperty $k.PSPath '(default)' -Value 0xFFFFFFFF -PropertyType DWord -Force | Out-Null
  Write-Host 'es2n-plant: combase feature key filled'
}
