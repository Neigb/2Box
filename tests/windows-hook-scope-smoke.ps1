param(
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'

try {
    [Environment]::SetEnvironmentVariable('WORKSPACE_HOOK_SCOPE', 'device', 'Process')
    Add-Type -TypeDefinition @'
public static class HookScopeProbe
{
    public static int Value() { return 42; }
}
'@
    [ordered]@{ ProcessId = $PID; CompilerChildSucceeded = ([HookScopeProbe]::Value() -eq 42) } |
        ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
} catch {
    [ordered]@{ ProcessId = $PID; CompilerChildSucceeded = $false; FatalError = $_.Exception.ToString() } |
        ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
    exit 1
}
