# Sends Ctrl+C to the console that process $TargetPid owns. Runs in its own
# pwsh process because it has to leave the current console.
param([Parameter(Mandatory)][int]$TargetPid)
$k = Add-Type -Namespace Spike -Name Console -PassThru -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint pid);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleCtrlHandler(System.IntPtr h, bool add);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool GenerateConsoleCtrlEvent(uint ev, uint group);
'@
[void]$k::FreeConsole()
if (-not $k::AttachConsole($TargetPid)) { exit 2 }
[void]$k::SetConsoleCtrlHandler([IntPtr]::Zero, $true)
if (-not $k::GenerateConsoleCtrlEvent(0, 0)) { exit 3 }
Start-Sleep -Milliseconds 500
exit 0
