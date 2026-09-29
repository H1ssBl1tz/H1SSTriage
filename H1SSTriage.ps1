#requires -Version 5.1
<#
.SYNOPSIS
    H1SSTriage v9 - Windows Live Response / Triage defensivo.
.DESCRIPTION
    Executa coletores read-only quanto à configuração investigada, registra estado
    explícito por coletor, gera manifesto com metadados de integridade e preserva
    os CSVs legados. A execução cria artefatos no sistema e não é forensically sterile.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [switch]$NoMenu,
    [ValidateSet('Quick','Standard','Deep')][string]$Mode = 'Standard',
    [ValidateRange(1,720)][int]$EventLogHours = 24,
    [ValidateRange(1,720)][int]$RecentFileHours = 24,
    [ValidateRange(1,10000)][int]$MaxRecentFiles = 200,
    [ValidateRange(1,3600)][int]$MaxScanDurationSeconds = 30
)

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'H1SSTriage.psd1'
Import-Module -Name $modulePath -Force -ErrorAction Stop
$Script:CurrentOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
[void][System.IO.Directory]::CreateDirectory($Script:CurrentOutputPath)
$Script:LastReportDir = $null

function Start-H1SSCollection {
    Write-Host "[+] Iniciando H1SSTriage v9.1.0 em modo $Mode..." -ForegroundColor Cyan
    $result = Invoke-H1SSTriage -OutputPath $Script:CurrentOutputPath -Mode $Mode -EventLogHours $EventLogHours -RecentFileHours $RecentFileHours -MaxRecentFiles $MaxRecentFiles -MaxScanDurationSeconds $MaxScanDurationSeconds -ToolScriptPath $PSCommandPath -Verbose:$VerbosePreference
    $Script:LastReportDir = [string]$result
    Write-Host "[+] Relatório: $Script:LastReportDir" -ForegroundColor Green
    Write-Host '[+] Abra primeiro 00_MANIFEST.json e depois 00_SUMARIO.txt.' -ForegroundColor Green
    $Script:LastReportDir
}

function Get-H1SSTriageFolders {
    @(
        Get-ChildItem -LiteralPath $Script:CurrentOutputPath -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^triage_\d{4}-\d{2}-\d{2}_' } |
            Sort-Object LastWriteTime -Descending
    )
}

function Test-H1SSSafeReportDirectory {
    param([Parameter(Mandatory=$true)][System.IO.DirectoryInfo]$Directory)
    try {
        $base = (Get-Item -LiteralPath $Script:CurrentOutputPath -ErrorAction Stop).FullName.TrimEnd('\')
        $current = Get-Item -LiteralPath $Directory.FullName -Force -ErrorAction Stop
        if (-not $current.PSIsContainer) { return $false }
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        if ($current.Name -notmatch '^triage_\d{4}-\d{2}-\d{2}_') { return $false }
        $parent = (Get-Item -LiteralPath $current.Parent.FullName -ErrorAction Stop).FullName.TrimEnd('\')
        return [string]::Equals($base, $parent, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { $false }
}

function Select-H1SSReportDirectory {
    $folders = Get-H1SSTriageFolders
    if ($folders.Count -eq 0) { Write-Host 'Nenhuma pasta de triagem encontrada.' -ForegroundColor Yellow; return $null }
    for ($index=0; $index -lt $folders.Count; $index++) { Write-Host ("[{0}] {1}" -f ($index+1),$folders[$index].Name) }
    $choice = Read-Host 'Número da pasta ou 0 para cancelar'
    $number = 0
    if (-not [int]::TryParse($choice,[ref]$number) -or $number -lt 1 -or $number -gt $folders.Count) { return $null }
    $folders[$number-1]
}

function Remove-H1SSReportDirectory {
    param([Parameter(Mandatory=$true)][System.IO.DirectoryInfo]$Directory)
    if (-not (Test-H1SSSafeReportDirectory -Directory $Directory)) { Write-Host 'Exclusão bloqueada: alvo não comprovado como relatório direto e sem reparse point.' -ForegroundColor Red; return }
    Write-Host "Alvo: $($Directory.FullName)" -ForegroundColor Yellow
    if ((Read-Host 'Digite APAGAR para confirmar') -ne 'APAGAR') { Write-Host 'Cancelado.'; return }
    $fresh = Get-Item -LiteralPath $Directory.FullName -Force -ErrorAction Stop
    if (-not (Test-H1SSSafeReportDirectory -Directory $fresh)) { Write-Host 'Exclusão bloqueada após revalidação final.' -ForegroundColor Red; return }
    Remove-Item -LiteralPath $fresh.FullName -Recurse -Force -ErrorAction Stop
    Write-Host "[+] Pasta removida: $($fresh.FullName)" -ForegroundColor Green
}

function Pause-H1SSMenu { [void](Read-Host 'Pressione ENTER para continuar') }

function Show-H1SSMenu {
    do {
        Clear-Host
        Write-Host 'H1SSTriage v9.1.0 — Windows Live Response / Triage' -ForegroundColor Cyan
        Write-Host "OutputPath: $Script:CurrentOutputPath"
        Write-Host "Mode: $Mode"
        Write-Host ''
        Write-Host '1 - Rodar triagem completa'
        Write-Host '2 - Rodar triagem e abrir a pasta'
        Write-Host '3 - Abrir última pasta'
        Write-Host '4 - Listar pastas de triagem'
        Write-Host '5 - Apagar uma pasta de triagem' -ForegroundColor Yellow
        Write-Host '6 - Apagar todas as pastas de triagem' -ForegroundColor Red
        Write-Host '7 - Alterar OutputPath'
        Write-Host '8 - Mostrar ordem recomendada de análise'
        Write-Host '9 - Abrir pasta base'
        Write-Host '0 - Sair'
        $option = Read-Host 'Escolha uma opção'
        switch ($option) {
            '1' { [void](Start-H1SSCollection); Pause-H1SSMenu }
            '2' { $path=Start-H1SSCollection; if($path){Invoke-Item -LiteralPath $path}; Pause-H1SSMenu }
            '3' { if($Script:LastReportDir -and (Test-Path -LiteralPath $Script:LastReportDir)){Invoke-Item -LiteralPath $Script:LastReportDir}else{$latest=Get-H1SSTriageFolders|Select-Object -First 1;if($latest){Invoke-Item -LiteralPath $latest.FullName}}; Pause-H1SSMenu }
            '4' { Get-H1SSTriageFolders | ForEach-Object { Write-Host $_.FullName }; Pause-H1SSMenu }
            '5' { $selected=Select-H1SSReportDirectory;if($selected){Remove-H1SSReportDirectory $selected};Pause-H1SSMenu }
            '6' {
                $folders=Get-H1SSTriageFolders
                if($folders.Count -and (Read-Host 'Digite APAGAR TUDO para confirmar') -eq 'APAGAR TUDO'){
                    foreach($folder in $folders){if(Test-H1SSSafeReportDirectory $folder){$fresh=Get-Item -LiteralPath $folder.FullName -Force -ErrorAction Stop;if(Test-H1SSSafeReportDirectory $fresh){Remove-Item -LiteralPath $fresh.FullName -Recurse -Force -ErrorAction Stop}}}
                }
                Pause-H1SSMenu
            }
            '7' { $new=Read-Host 'Novo OutputPath';if($new){$full=[IO.Path]::GetFullPath($new);[void][IO.Directory]::CreateDirectory($full);$Script:CurrentOutputPath=$full};Pause-H1SSMenu }
            '8' { Write-Host '1. 00_MANIFEST.json (cobertura/falhas)';Write-Host '2. 00_SUMARIO.txt';Write-Host '3. findings.json / 16_alertas.csv';Write-Host '4. processos, rede, serviços, tarefas e persistência';Pause-H1SSMenu }
            '9' { Invoke-Item -LiteralPath $Script:CurrentOutputPath;Pause-H1SSMenu }
            '0' { }
            default { Write-Host 'Opção inválida.' -ForegroundColor Yellow;Pause-H1SSMenu }
        }
    } while ($option -ne '0')
}

if ($NoMenu) { [void](Start-H1SSCollection) } else { Show-H1SSMenu }
