$Script:H1SSTriageVersion = '9.1.0'
$Script:SchemaVersion = '1.0'
$Script:RuleSetVersion = '2.0'
$Script:ModuleRoot = $PSScriptRoot
$Script:ModuleImportResults = @(
    foreach ($moduleName in @('CimCmdlets','Microsoft.PowerShell.LocalAccounts','NetTCPIP','DnsClient','ScheduledTasks','Defender')) {
        try {
            $module = Import-Module -Name $moduleName -PassThru -ErrorAction Stop | Select-Object -First 1
            $signatureStatus = $null
            $signatureError = ''
            if ($module.Path -and (Test-Path -LiteralPath $module.Path -PathType Leaf)) {
                try { $signatureStatus = [string](Get-AuthenticodeSignature -LiteralPath $module.Path -ErrorAction Stop).Status }
                catch { $signatureStatus = 'Error'; $signatureError = $_.Exception.Message }
            }
            [PSCustomObject]@{ ModuleName=$moduleName; Status='Success'; Version=[string]$module.Version; Path=$module.Path; SignatureStatus=$signatureStatus; SignatureError=$signatureError; ErrorMessage='' }
        }
        catch {
            [PSCustomObject]@{ ModuleName=$moduleName; Status='Unavailable'; Version=$null; Path=$null; SignatureStatus=$null; SignatureError=''; ErrorMessage=$_.Exception.Message }
        }
    }
)

$privateFiles = @(
    'Private\H1SS.Core.ps1',
    'Private\H1SS.Collectors.ps1',
    'Private\H1SS.Enrichment.ps1',
    'Private\H1SS.Rules.ps1',
    'Private\H1SS.Output.ps1'
)

foreach ($relativePath in $privateFiles) {
    $filePath = Join-Path -Path $PSScriptRoot -ChildPath $relativePath
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "Arquivo interno obrigatório não encontrado: $filePath"
    }
    . $filePath
}

$publicFile = Join-Path -Path $PSScriptRoot -ChildPath 'Public\Invoke-H1SSTriage.ps1'
. $publicFile

Export-ModuleMember -Function Invoke-H1SSTriage
