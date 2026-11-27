# Kernel COM investigation: list and move the marker's records (one file per
# process that loaded the planted DLL) into -Out as <Name>-hit-<pid>.txt.
param([Parameter(Mandatory)][string]$Name, [string]$Out = 'C:\pm\out')
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$hits = @(Get-ChildItem C:\etd-kcom\hit-*.txt -ErrorAction SilentlyContinue)
Write-Host "--- [$Name] processes that loaded the planted DLL: $($hits.Count) ---"
foreach ($h in $hits) {
  Write-Host "== $($h.Name)"
  Get-Content $h | Write-Host
  Move-Item $h.FullName (Join-Path $Out "$Name-$($h.Name)") -Force
}
$kernel = @($hits | Where-Object { (Get-Content (Join-Path $Out "$Name-$($_.Name)") -Raw) -match 'easytier-core\.exe' })
"[$Name] kernel hits: $($kernel.Count); all hits: $($hits.Count)" | Tee-Object -Append (Join-Path $Out 'kcom-summary.txt')
