function Get-H1SSUtcNow {
    [DateTime]::UtcNow
}

function ConvertTo-H1SSIsoUtc {
    param([Parameter(Mandatory = $true)][DateTime]$Value)
    $Value.ToUniversalTime().ToString('o')
}

function ConvertTo-H1SSIsoLocal {
    param([Parameter(Mandatory = $true)][DateTime]$Value)
    $Value.ToLocalTime().ToString('o')
}

function New-H1SSCollectorState {
    param(
        [Parameter(Mandatory = $true)][string]$CollectorName,
        [Parameter(Mandatory = $true)][ValidateSet('Success','Partial','Failed','Unavailable','Unsupported','Skipped')][string]$Status,
        [Parameter(Mandatory = $true)][DateTime]$StartedAtUtc,
        [Parameter(Mandatory = $true)][DateTime]$FinishedAtUtc,
        [int]$RecordCount = 0,
        [string]$ErrorType = '',
        [string]$ErrorMessage = '',
        [bool]$Required = $false,
        [hashtable]$Metadata
    )

    $state = [ordered]@{
        CollectorName = $CollectorName
        Status         = $Status
        StartedAtUtc   = ConvertTo-H1SSIsoUtc -Value $StartedAtUtc
        FinishedAtUtc  = ConvertTo-H1SSIsoUtc -Value $FinishedAtUtc
        DurationMs     = [math]::Max(0, [int][math]::Round(($FinishedAtUtc - $StartedAtUtc).TotalMilliseconds))
        RecordCount    = $RecordCount
        ErrorType      = $ErrorType
        ErrorMessage   = $ErrorMessage
        Required       = $Required
    }

    if ($Metadata) {
        foreach ($key in $Metadata.Keys) {
            $state[$key] = $Metadata[$key]
        }
    }

    [PSCustomObject]$state
}

function New-H1SSCollectorPayload {
    param(
        [object[]]$Records = @(),
        [ValidateSet('Success','Partial','Failed','Unavailable','Unsupported','Skipped')][string]$Status = 'Success',
        [string]$ErrorType = '',
        [string]$ErrorMessage = '',
        [hashtable]$Metadata
    )

    $payload = [PSCustomObject]@{
        Records      = @($Records)
        Status       = $Status
        ErrorType    = $ErrorType
        ErrorMessage = $ErrorMessage
        Metadata     = $Metadata
    }
    $payload.PSObject.TypeNames.Insert(0, 'H1SS.CollectorPayload')
    $payload
}

function Test-H1SSExpectedAbsenceError {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    if ($ErrorRecord.Exception -is [System.Management.Automation.ItemNotFoundException]) { return $true }
    $errorId = [string]$ErrorRecord.FullyQualifiedErrorId
    ($errorId -like 'PathNotFound,*' -or $errorId -like 'PropertyNotFoundStrict,*' -or $errorId -like 'ItemNotFound,*')
}

function Get-H1SSOptionalRegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $LiteralPath -Name $Name -ErrorAction Stop
        [PSCustomObject]@{ Present = $true; Value = $item.$Name; ErrorType = ''; ErrorMessage = '' }
    }
    catch {
        if (Test-H1SSExpectedAbsenceError -ErrorRecord $_) {
            return [PSCustomObject]@{ Present = $false; Value = $null; ErrorType = ''; ErrorMessage = '' }
        }
        [PSCustomObject]@{ Present = $false; Value = $null; ErrorType = $_.Exception.GetType().FullName; ErrorMessage = $_.Exception.Message }
    }
}

function Set-H1SSCollectorPartial {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$ErrorType,
        [Parameter(Mandatory = $true)][string]$ErrorMessage
    )

    if ($State.Status -eq 'Success') { $State.Status = 'Partial' }
    if ([string]::IsNullOrWhiteSpace([string]$State.ErrorType)) { $State.ErrorType = $ErrorType }
    elseif ([string]$State.ErrorType -notlike "*$ErrorType*") { $State.ErrorType = '{0};{1}' -f $State.ErrorType,$ErrorType }
    if ([string]::IsNullOrWhiteSpace([string]$State.ErrorMessage)) { $State.ErrorMessage = $ErrorMessage }
    elseif ([string]$State.ErrorMessage -notlike "*$ErrorMessage*") { $State.ErrorMessage = '{0} | {1}' -f $State.ErrorMessage,$ErrorMessage }
}

function Invoke-H1SSCollector {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [bool]$Required = $false
    )

    $started = Get-H1SSUtcNow
    try {
        $payload = & $ScriptBlock
        if (-not $payload -or $payload.PSObject.TypeNames -notcontains 'H1SS.CollectorPayload') {
            $payload = New-H1SSCollectorPayload -Records @($payload)
        }
        $finished = Get-H1SSUtcNow
        [PSCustomObject]@{
            State = New-H1SSCollectorState -CollectorName $Name -Status $payload.Status -StartedAtUtc $started -FinishedAtUtc $finished -RecordCount @($payload.Records).Count -ErrorType $payload.ErrorType -ErrorMessage $payload.ErrorMessage -Required $Required -Metadata $payload.Metadata
            Data  = @($payload.Records)
        }
    }
    catch {
        $finished = Get-H1SSUtcNow
        $status = if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { 'Unavailable' } elseif ($_.Exception -is [System.PlatformNotSupportedException]) { 'Unsupported' } else { 'Failed' }
        [PSCustomObject]@{
            State = New-H1SSCollectorState -CollectorName $Name -Status $status -StartedAtUtc $started -FinishedAtUtc $finished -RecordCount 0 -ErrorType $_.Exception.GetType().FullName -ErrorMessage $_.Exception.Message -Required $Required
            Data  = @()
        }
    }
}

function Get-H1SSOverallStatus {
    param([Parameter(Mandatory = $true)][object[]]$CollectorStates)

    $required = @($CollectorStates | Where-Object { $_.Required })
    if ($required.Count -eq 0) { return 'Failed' }
    if (@($required | Where-Object { $_.Status -eq 'Success' }).Count -eq $required.Count) { return 'Complete' }
    if (@($required | Where-Object { $_.Status -eq 'Success' }).Count -eq 0) { return 'Failed' }
    'Partial'
}

function Resolve-H1SSOutputBasePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'OutputPath não pode ser vazio.'
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    [void][System.IO.Directory]::CreateDirectory($fullPath)
    $item = Get-Item -LiteralPath $fullPath -ErrorAction Stop
    if (-not $item.PSIsContainer) { throw "OutputPath não é um diretório: $fullPath" }
    $item.FullName
}

function New-H1SSRunDirectory {
    param([Parameter(Mandatory = $true)][string]$BasePath)

    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        $runId = ([guid]::NewGuid().ToString('N').Substring(0, 8)).ToUpperInvariant()
        $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff'
        $name = 'triage_{0}_{1}' -f $stamp, $runId
        $candidate = Join-Path -Path $BasePath -ChildPath $name
        if (-not [System.IO.Directory]::Exists($candidate)) {
            $created = [System.IO.Directory]::CreateDirectory($candidate)
            return [PSCustomObject]@{ RunId = $runId; Path = $created.FullName }
        }
    }
    throw 'Não foi possível criar um diretório de execução exclusivo após cinco tentativas.'
}

function Get-H1SSStringSha256 {
    param([AllowEmptyString()][string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
    }
    finally { $sha.Dispose() }
}

function Get-H1SSFileMetadata {
    param(
        [string]$LiteralPath,
        [switch]$IncludeHash,
        [switch]$ExistenceOnly
    )

    $result = [ordered]@{
        FileExists           = $false
        MetadataStatus       = 'Unavailable'
        SHA256               = $null
        HashStatus           = if ($IncludeHash) { 'Pending' } else { 'NotRequested' }
        SignatureStatus      = 'Unavailable'
        SignerSubject        = $null
        SignerIssuer         = $null
        SignerThumbprint     = $null
        CompanyName          = $null
        ProductName          = $null
        OriginalFileName     = $null
        FileVersion          = $null
        FileCreationTimeUtc  = $null
        FileLastWriteTimeUtc = $null
        FileSize             = $null
        MetadataError        = $null
    }

    if ([string]::IsNullOrWhiteSpace($LiteralPath)) {
        return [PSCustomObject]$result
    }

    try {
        $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        if ($item.PSIsContainer) {
            $result.MetadataStatus = 'Unavailable'
            $result.MetadataError = 'O path aponta para um diretório, não para um arquivo.'
            if ($IncludeHash) { $result.HashStatus = 'Unavailable' }
            return [PSCustomObject]$result
        }
        $result.FileExists = $true
        $result.MetadataStatus = 'Success'
        $result.FileCreationTimeUtc = ConvertTo-H1SSIsoUtc -Value $item.CreationTimeUtc
        $result.FileLastWriteTimeUtc = ConvertTo-H1SSIsoUtc -Value $item.LastWriteTimeUtc
        $result.FileSize = $item.Length
        if ($ExistenceOnly) {
            $result.SignatureStatus = 'NotChecked'
            return [PSCustomObject]$result
        }
        $result.CompanyName = $item.VersionInfo.CompanyName
        $result.ProductName = $item.VersionInfo.ProductName
        $result.OriginalFileName = $item.VersionInfo.OriginalFilename
        $result.FileVersion = $item.VersionInfo.FileVersion

        if (-not (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
            $result.SignatureStatus = 'Unavailable'
            $result.MetadataStatus = 'Partial'
            $result.MetadataError = 'Get-AuthenticodeSignature não está disponível.'
        }
        else {
            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath -ErrorAction Stop
                $signatureStatus = [string]$signature.Status
                $result.SignatureStatus = if ($signatureStatus -in @('Valid','NotSigned','HashMismatch','NotTrusted','UnknownError')) { $signatureStatus } else { 'UnknownError' }
                if ($signatureStatus -notin @('Valid','NotSigned','HashMismatch','NotTrusted','UnknownError')) {
                    $result.MetadataStatus = 'Partial'
                    $result.MetadataError = "Authenticode retornou status não reconhecido: $signatureStatus"
                }
                if ($signature.SignerCertificate) {
                    $result.SignerSubject = $signature.SignerCertificate.Subject
                    $result.SignerIssuer = $signature.SignerCertificate.Issuer
                    $result.SignerThumbprint = $signature.SignerCertificate.Thumbprint
                }
            }
            catch {
                $result.SignatureStatus = 'UnknownError'
                $result.MetadataStatus = 'Partial'
                $result.MetadataError = "Authenticode: $($_.Exception.Message)"
            }
        }

        if ($IncludeHash) {
            try {
                $result.SHA256 = (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256 -ErrorAction Stop).Hash
                $result.HashStatus = 'Success'
            }
            catch {
                $result.HashStatus = if (Test-H1SSExpectedAbsenceError -ErrorRecord $_) { 'FileMissing' } else { 'Failed' }
                $hashError = "SHA256: $($_.Exception.Message)"
                $result.MetadataError = if ($result.MetadataError) { "$($result.MetadataError) | $hashError" } else { $hashError }
                $result.MetadataStatus = 'Partial'
            }
        }
    }
    catch {
        if (Test-H1SSExpectedAbsenceError -ErrorRecord $_) {
            $result.MetadataStatus = 'Missing'
            if ($IncludeHash) { $result.HashStatus = 'FileMissing' }
        }
        else {
            $result.MetadataStatus = 'Partial'
            $result.MetadataError = $_.Exception.Message
            if ($IncludeHash) { $result.HashStatus = 'Failed' }
        }
    }

    [PSCustomObject]$result
}

function New-H1SSFileMetadataCache {
    [PSCustomObject]@{
        Entries     = @{}
        HashResults = @{}
        Hits        = 0
        Misses      = 0
    }
}

function Get-H1SSNormalizedPathKey {
    param([string]$LiteralPath)

    if ([string]::IsNullOrWhiteSpace($LiteralPath)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($LiteralPath).Trim().Trim('"')
    try {
        if ([IO.Path]::IsPathRooted($expanded)) { $expanded = [IO.Path]::GetFullPath($expanded) }
    }
    catch {
        # Preserve an invalid/unresolvable literal as an isolated cache key instead of
        # allowing path canonicalization failure to collapse it into another entry.
        return ('raw:{0}' -f $expanded.ToLowerInvariant())
    }
    $expanded.TrimEnd('\').ToLowerInvariant()
}

function Get-H1SSCachedFileMetadata {
    param(
        [string]$LiteralPath,
        [object]$MetadataCache,
        [switch]$ExistenceOnly
    )

    if (-not $MetadataCache) { return Get-H1SSFileMetadata -LiteralPath $LiteralPath -ExistenceOnly:$ExistenceOnly }
    $key = Get-H1SSNormalizedPathKey -LiteralPath $LiteralPath
    if (-not $key) { return Get-H1SSFileMetadata -LiteralPath $LiteralPath -ExistenceOnly:$ExistenceOnly }
    $requestedLevel = if ($ExistenceOnly) { 0 } else { 1 }
    if ($MetadataCache.Entries.ContainsKey($key) -and [int]$MetadataCache.Entries[$key].DetailLevel -ge $requestedLevel) {
        $MetadataCache.Hits = [int]$MetadataCache.Hits + 1
        return $MetadataCache.Entries[$key].Metadata
    }
    $MetadataCache.Misses = [int]$MetadataCache.Misses + 1
    $metadata = Get-H1SSFileMetadata -LiteralPath $LiteralPath -ExistenceOnly:$ExistenceOnly
    $MetadataCache.Entries[$key] = [PSCustomObject]@{ DetailLevel=$requestedLevel; Metadata=$metadata }
    $metadata
}

function Get-H1SSCachedFileHash {
    param([string]$LiteralPath, [object]$MetadataCache)

    $key = Get-H1SSNormalizedPathKey -LiteralPath $LiteralPath
    if (-not $key) { return [PSCustomObject]@{ SHA256=$null; HashStatus='Unavailable'; ErrorMessage='Path vazio ou inválido.' } }
    if ($MetadataCache -and $MetadataCache.HashResults.ContainsKey($key)) {
        $MetadataCache.Hits = [int]$MetadataCache.Hits + 1
        return $MetadataCache.HashResults[$key]
    }

    $knownMetadata = $null
    if ($MetadataCache -and $MetadataCache.Entries.ContainsKey($key)) { $knownMetadata = $MetadataCache.Entries[$key].Metadata }
    if ($knownMetadata -and $knownMetadata.MetadataStatus -eq 'Missing') {
        $result = [PSCustomObject]@{ SHA256=$null; HashStatus='FileMissing'; ErrorMessage=$null }
    }
    else {
        if ($MetadataCache) { $MetadataCache.Misses = [int]$MetadataCache.Misses + 1 }
        try {
            $result = [PSCustomObject]@{ SHA256=(Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256 -ErrorAction Stop).Hash; HashStatus='Success'; ErrorMessage=$null }
        }
        catch {
            $result = [PSCustomObject]@{ SHA256=$null; HashStatus=$(if (Test-H1SSExpectedAbsenceError -ErrorRecord $_) { 'FileMissing' } else { 'Failed' }); ErrorMessage=$(if (Test-H1SSExpectedAbsenceError -ErrorRecord $_) { $null } else { $_.Exception.Message }) }
        }
    }
    if ($MetadataCache) { $MetadataCache.HashResults[$key] = $result }
    if ($knownMetadata) {
        $knownMetadata.SHA256 = $result.SHA256
        $knownMetadata.HashStatus = $result.HashStatus
        if ($result.ErrorMessage) {
            $hashError = "SHA256: $($result.ErrorMessage)"
            $knownMetadata.MetadataError = if ($knownMetadata.MetadataError) { "$($knownMetadata.MetadataError) | $hashError" } else { $hashError }
            $knownMetadata.MetadataStatus = 'Partial'
        }
    }
    $result
}

function Protect-H1SSCsvValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -and $Value -match '^[=+\-@]') { return "'$Value" }
    $Value
}

function ConvertTo-H1SSCsvSafeObject {
    param([Parameter(ValueFromPipeline = $true)][object]$InputObject)
    process {
        if ($null -eq $InputObject) { return }
        $safe = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $value = ($value | ForEach-Object { [string]$_ }) -join '; '
            }
            $safe[$property.Name] = Protect-H1SSCsvValue -Value $value
        }
        [PSCustomObject]$safe
    }
}

function Get-H1SSAddressClassification {
    param([string]$Address)

    $parsed = $null
    if ([string]::IsNullOrWhiteSpace($Address) -or -not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) {
        return [PSCustomObject]@{ Address = $Address; NormalizedAddress = $Address; AddressFamily = 'Unknown'; Classification = 'Invalid'; IsInternal = $false }
    }

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $parsed.IsIPv4MappedToIPv6) {
        $parsed = $parsed.MapToIPv4()
    }

    $classification = 'Public'
    $isInternal = $false
    if ([System.Net.IPAddress]::IsLoopback($parsed)) { $classification = 'Loopback'; $isInternal = $true }
    elseif ($parsed.Equals([System.Net.IPAddress]::Any) -or $parsed.Equals([System.Net.IPAddress]::IPv6Any)) { $classification = 'Unspecified'; $isInternal = $true }
    elseif ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $parsed.GetAddressBytes()
        if ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)) { $classification = 'Private'; $isInternal = $true }
        elseif ($b[0] -eq 169 -and $b[1] -eq 254) { $classification = 'LinkLocal'; $isInternal = $true }
        elseif ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { $classification = 'CGNAT'; $isInternal = $false }
        elseif ($b[0] -ge 224 -and $b[0] -le 239) { $classification = 'Multicast'; $isInternal = $true }
    }
    else {
        $b = $parsed.GetAddressBytes()
        if ($parsed.IsIPv6LinkLocal) { $classification = 'LinkLocal'; $isInternal = $true }
        elseif ($parsed.IsIPv6Multicast) { $classification = 'Multicast'; $isInternal = $true }
        elseif (($b[0] -band 0xFE) -eq 0xFC) { $classification = 'Private'; $isInternal = $true }
    }

    [PSCustomObject]@{
        Address           = $Address
        NormalizedAddress = $parsed.ToString()
        AddressFamily     = if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
        Classification    = $classification
        IsInternal        = $isInternal
    }
}

function Test-H1SSUserWritablePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $Path -match '(?i)\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)\\|\\ProgramData\\|\\Users\\Public\\|\\Windows\\Temp\\|\\Temp\\|\\\$Recycle\.Bin\\|\\PerfLogs\\'
}

function Get-H1SSIntegrityLevel {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $integritySid = @($identity.Groups | Where-Object { $_.Value -like 'S-1-16-*' } | Select-Object -First 1)
        if (-not $integritySid) { return 'Unknown' }
        $rid = [int]($integritySid[0].Value.Split('-')[-1])
        if ($rid -ge 16384) { 'System' }
        elseif ($rid -ge 12288) { 'High' }
        elseif ($rid -ge 8192) { 'Medium' }
        elseif ($rid -ge 4096) { 'Low' }
        else { 'Untrusted' }
    }
    catch {
        Add-H1SSPreflightError -Component 'IntegrityLevel' -ErrorRecord $_
        'Unknown'
    }
}

function Test-H1SSIsElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Add-H1SSPreflightError -Component 'Elevation' -ErrorRecord $_
        $false
    }
}

function Add-H1SSPreflightError {
    param([string]$Component, [System.Management.Automation.ErrorRecord]$ErrorRecord)
    if (-not $Script:H1SSPreflightErrors) { $Script:H1SSPreflightErrors = New-Object System.Collections.Generic.List[object] }
    $Script:H1SSPreflightErrors.Add([PSCustomObject]@{ Component=$Component; ErrorType=$ErrorRecord.Exception.GetType().FullName; ErrorMessage=$ErrorRecord.Exception.Message }) | Out-Null
}

function Get-H1SSPreflight {
    param([string]$ToolScriptPath, [string]$OutputPath)

    $Script:H1SSPreflightErrors = New-Object System.Collections.Generic.List[object]

    $requiredCommands = @('Get-CimInstance','Get-LocalUser','Get-LocalGroup','Get-LocalGroupMember','Get-NetTCPConnection','Get-NetUDPEndpoint','Get-DnsClientCache','Get-ScheduledTask','Get-ScheduledTaskInfo','Export-ScheduledTask','Get-WinEvent','Get-MpComputerStatus','Get-AuthenticodeSignature','Get-FileHash','Get-Acl')
    $capabilities = foreach ($commandName in $requiredCommands) {
        $command = Get-Command -Name $commandName -ErrorAction SilentlyContinue | Select-Object -First 1
        [PSCustomObject]@{
            Command = $commandName
            Available = [bool]$command
            ModuleName = if ($command) { $command.ModuleName } else { $null }
            ModuleVersion = if ($command -and $command.Module) { [string]$command.Module.Version } else { $null }
            ModulePath = if ($command -and $command.Module) { $command.Module.Path } else { $null }
        }
    }

    $identity = $null
    $collectorUser = $null
    $collectorUserSid = $null
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $collectorUser = [string]$identity.Name
        $collectorUserSid = [string]$identity.User
    }
    catch { Add-H1SSPreflightError -Component 'CollectorIdentity' -ErrorRecord $_ }
    $toolSha256 = $null
    if ($ToolScriptPath) {
        try { $toolSha256 = (Get-FileHash -LiteralPath $ToolScriptPath -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch {
            if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $_)) { Add-H1SSPreflightError -Component 'ToolHash' -ErrorRecord $_ }
        }
    }
    $isElevated = Test-H1SSIsElevated
    $integrityLevel = Get-H1SSIntegrityLevel
    $powerShellEdition = 'Desktop'
    if ($PSVersionTable.ContainsKey('PSEdition') -and $PSVersionTable['PSEdition']) { $powerShellEdition = [string]$PSVersionTable['PSEdition'] }
    [PSCustomObject]@{
        IsWindows            = ($env:OS -eq 'Windows_NT')
        PowerShellSupported  = ($PSVersionTable.PSVersion -ge [version]'5.1')
        PowerShellVersion    = [string]$PSVersionTable.PSVersion
        PowerShellEdition    = $powerShellEdition
        PowerShellBitness    = [IntPtr]::Size * 8
        Is64BitOperatingSystem = [Environment]::Is64BitOperatingSystem
        IsElevated           = $isElevated
        IntegrityLevel       = $integrityLevel
        CollectorUser        = $collectorUser
        CollectorUserSid     = $collectorUserSid
        ToolScriptPath       = $ToolScriptPath
        ToolSha256           = $toolSha256
        OutputPath           = $OutputPath
        Capabilities         = @($capabilities)
        ModuleImports        = @($Script:ModuleImportResults)
        Errors               = $Script:H1SSPreflightErrors.ToArray()
    }
}
