param(
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'

try {
    Add-Type -TypeDefinition @'
public static class HookScopeProbe
{
    public static int Value() { return 42; }
}
'@
    [ordered]@{ ProcessId = $PID; Scope = $env:WORKSPACE_HOOK_SCOPE; CompilerChildSucceeded = ([HookScopeProbe]::Value() -eq 42) } |
        ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
} catch {
    [ordered]@{ ProcessId = $PID; Scope = $env:WORKSPACE_HOOK_SCOPE; CompilerChildSucceeded = $false; FatalError = $_.Exception.ToString() } |
        ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
    exit 1
}
