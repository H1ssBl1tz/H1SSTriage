function Get-H1SSSystemCollector {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $machineGuid = $null
    $warnings = New-Object System.Collections.Generic.List[string]
    try {
        $machineGuid = (Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    }
    catch { $warnings.Add("MachineGuid: $($_.Exception.Message)") | Out-Null }

    $fqdn = $cs.Name
    if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
        $fqdn = '{0}.{1}' -f $cs.Name, $env:USERDNSDOMAIN.ToLowerInvariant()
    }

    New-H1SSCollectorPayload -Records @([PSCustomObject]@{
        Hostname          = $cs.Name
        Fqdn              = $fqdn
        DomainOrWorkgroup = $cs.Domain
        PartOfDomain      = $cs.PartOfDomain
        MachineGuid       = $machineGuid
        WindowsEdition    = $os.Caption
        WindowsVersion    = $os.Version
        WindowsBuild      = $os.BuildNumber
        Architecture      = $os.OSArchitecture
        InstallDate       = $os.InstallDate
        LastBootUpTime    = $os.LastBootUpTime
        TotalRamGB        = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    }) -Status $(if ($warnings.Count) { 'Partial' } else { 'Success' }) -ErrorType $(if ($warnings.Count) { 'EnrichmentPartial' } else { '' }) -ErrorMessage ($warnings -join ' | ')
}

function Get-H1SSUsersCollector {
    if (-not (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue)) {
        return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Get-LocalUser não está disponível.'
    }
    $records = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            Name              = $_.Name
            SID               = [string]$_.SID
            Enabled           = $_.Enabled
            LastLogon         = $_.LastLogon
            PasswordRequired  = $_.PasswordRequired
            PasswordLastSet   = $_.PasswordLastSet
            UserMayChangePassword = $_.UserMayChangePassword
            Description       = $_.Description
        }
    })
    New-H1SSCollectorPayload -Records $records
}

function Resolve-H1SSPrincipalSource {
    param(
        [string]$Name,
        [string]$ADsPath,
        [string]$SID,
        [string]$LocalHostName = $env:COMPUTERNAME,
        [string]$LocalSamName = $env:COMPUTERNAME,
        [string]$DomainName = $env:USERDOMAIN
    )

    $authority = $null
    if ($ADsPath -match '(?i)^WinNT://([^/]+)/') { $authority = $Matches[1] }
    elseif ($Name -match '^([^\\]+)\\') { $authority = $Matches[1] }

    if ($SID -like 'S-1-5-32-*' -or $authority -eq 'BUILTIN') { return 'BuiltIn' }
    if ($authority -and $authority -in @('.', 'localhost', $LocalHostName, $LocalSamName)) { return 'Local' }
    if ($authority -and $DomainName -and $authority -eq $DomainName -and $authority -notin @($LocalHostName,$LocalSamName)) { return 'Domain' }
    'Unknown'
}

function Get-H1SSAdministratorsCollector {
    $adminSid = 'S-1-5-32-544'
    if (-not (Get-Command -Name Get-LocalGroup -ErrorAction SilentlyContinue)) {
        return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Microsoft.PowerShell.LocalAccounts não está disponível.'
    }

    $group = Get-LocalGroup -ErrorAction Stop | Where-Object { [string]$_.SID -eq $adminSid } | Select-Object -First 1
    if (-not $group) { throw "Grupo local Administrators ($adminSid) não encontrado." }

    try {
        $records = @(Get-LocalGroupMember -SID $adminSid -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                GroupName       = $group.Name
                Name            = $_.Name
                PrincipalSource = Resolve-H1SSPrincipalSource -Name ([string]$_.Name) -SID ([string]$_.SID) -LocalHostName $env:COMPUTERNAME -LocalSamName $env:COMPUTERNAME -DomainName $env:USERDOMAIN
                ObjectClass     = [string]$_.ObjectClass
                SID             = [string]$_.SID
                ADsPath         = $null
                Resolution      = 'NativeCmdlet'
            }
        })
        return New-H1SSCollectorPayload -Records $records
    }
    catch {
        $nativeError = $_.Exception.Message
    }

    $adsiWarnings = New-Object System.Collections.Generic.List[string]
    try {
        $adsiGroup = [ADSI]("WinNT://./{0},group" -f $group.Name)
        $records = @($adsiGroup.psbase.Invoke('Members') | ForEach-Object {
            $member = $_
            $name = $member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
            $path = $member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
            $class = $member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)
            $sid = $null
            try {
                $rawSid = $member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
                if ($rawSid) { $sid = (New-Object Security.Principal.SecurityIdentifier($rawSid, 0)).Value }
            }
            catch { $adsiWarnings.Add("SID ${path}: $($_.Exception.Message)") | Out-Null }
            $source = Resolve-H1SSPrincipalSource -Name $name -ADsPath $path -SID $sid -LocalHostName $env:COMPUTERNAME -LocalSamName $env:COMPUTERNAME -DomainName $env:USERDOMAIN
            [PSCustomObject]@{
                GroupName       = $group.Name
                Name            = $name
                PrincipalSource = $source
                ObjectClass     = $class
                SID             = $sid
                ADsPath         = $path
                Resolution      = 'ADSI'
            }
        })
        $fallbackErrors = @($nativeError) + @($adsiWarnings)
        New-H1SSCollectorPayload -Records $records -Status Partial -ErrorType 'NativeEnumerationFailed' -ErrorMessage ($fallbackErrors -join ' | ')
    }
    catch {
        throw "Get-LocalGroupMember falhou ($nativeError) e fallback ADSI falhou: $($_.Exception.Message)"
    }
}

function ConvertTo-H1SSProcessDate {
    param($Value, [ref]$ErrorMessage)
    if ($null -eq $Value) { return $null }
    try { return ([DateTime]$Value).ToUniversalTime() }
    catch {
        if ($ErrorMessage) { $ErrorMessage.Value = $_.Exception.Message }
        return $null
    }
}

function Resolve-H1SSOwnerSid {
    param([string]$UserName, [ref]$ErrorMessage)
    if ([string]::IsNullOrWhiteSpace($UserName)) { return $null }
    try { (New-Object Security.Principal.NTAccount($UserName)).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch {
        if ($ErrorMessage) { $ErrorMessage.Value = $_.Exception.Message }
        $null
    }
}

function Get-H1SSProcessesCollector {
    param(
        [ValidateSet('Quick','Standard','Deep')][string]$Mode = 'Standard',
        [object]$MetadataCache
    )

    if (-not $MetadataCache) { $MetadataCache = New-H1SSFileMetadataCache }
    $started = Get-H1SSUtcNow
    $observedAt = $started
    $cimProcesses = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $runtimeMap = @{}
    $partialErrors = New-Object System.Collections.Generic.List[string]

    try {
        Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { $runtimeMap[[int]$_.Id] = $_ }
    }
    catch {
        $partialErrors.Add("Owner/session enrichment: $($_.Exception.Message)") | Out-Null
        try { Get-Process -ErrorAction Stop | ForEach-Object { $runtimeMap[[int]$_.Id] = $_ } }
        catch { $partialErrors.Add("Basic process enrichment: $($_.Exception.Message)") | Out-Null }
    }

    $base = foreach ($process in $cimProcesses) {
        $pidValue = [int]$process.ProcessId
        $runtime = if ($runtimeMap.ContainsKey($pidValue)) { $runtimeMap[$pidValue] } else { $null }
        $creationError = $null
        $creationUtc = ConvertTo-H1SSProcessDate -Value $process.CreationDate -ErrorMessage ([ref]$creationError)
        if ($creationError) { $partialErrors.Add("PID ${pidValue} creation time: $creationError") | Out-Null }
        $owner = if ($runtime -and $runtime.PSObject.Properties.Name -contains 'UserName') { $runtime.UserName } else { $null }
        $ownerError = $null
        $ownerSid = Resolve-H1SSOwnerSid -UserName $owner -ErrorMessage ([ref]$ownerError)
        if ($ownerError) { $partialErrors.Add("PID ${pidValue} owner SID: $ownerError") | Out-Null }
        $ownerResolutionStatus = if (-not $runtime) { 'ExitedOrUnavailable' } elseif ([string]::IsNullOrWhiteSpace([string]$owner)) { 'Unavailable' } elseif ($ownerSid) { 'Resolved' } elseif ($ownerError) { 'Partial' } else { 'Unavailable' }
        $rawPath = [string]$process.ExecutablePath
        $path = [Environment]::ExpandEnvironmentVariables($rawPath)
        $metadata = if ($Mode -eq 'Quick') {
            Get-H1SSCachedFileMetadata -LiteralPath $path -MetadataCache $MetadataCache -ExistenceOnly
        }
        else { Get-H1SSCachedFileMetadata -LiteralPath $path -MetadataCache $MetadataCache }
        if ($metadata.MetadataError) { $partialErrors.Add("PID ${pidValue} file metadata: $($metadata.MetadataError)") | Out-Null }

        $trust = Get-H1SSTrustAssessment -Path $path -SignatureStatus $metadata.SignatureStatus

        [PSCustomObject]@{
            RecordId              = 'process:{0}:{1}' -f $pidValue, $(if ($creationUtc) { $creationUtc.Ticks } else { 'unknown' })
            ObservedAtUtc         = ConvertTo-H1SSIsoUtc -Value $observedAt
            PID                   = $pidValue
            PPID                  = [int]$process.ParentProcessId
            Name                  = $process.Name
            RawExecutablePath     = $rawPath
            ExecutablePath        = $path
            CommandLine           = $process.CommandLine
            CreationDate          = if ($creationUtc) { ConvertTo-H1SSIsoUtc -Value $creationUtc } else { $null }
            SessionId             = if ($runtime) { $runtime.SessionId } else { $null }
            CPUSeconds            = if ($runtime) { $runtime.CPU } else { $null }
            WorkingSet            = if ($runtime) { $runtime.WorkingSet64 } else { $null }
            Owner                 = $owner
            OwnerSid              = $ownerSid
            OwnerResolutionStatus = $ownerResolutionStatus
            OwnerError            = $ownerError
            ParentName            = $null
            ParentPath            = $null
            ParentCreationTime    = $null
            ParentResolutionStatus = 'Unresolved'
            FileExists            = $metadata.FileExists
            MetadataStatus        = $metadata.MetadataStatus
            SHA256                = $metadata.SHA256
            HashStatus            = $metadata.HashStatus
            SignatureStatus       = $metadata.SignatureStatus
            SignerSubject         = $metadata.SignerSubject
            SignerIssuer          = $metadata.SignerIssuer
            SignerThumbprint      = $metadata.SignerThumbprint
            CompanyName           = $metadata.CompanyName
            ProductName           = $metadata.ProductName
            OriginalFileName      = $metadata.OriginalFileName
            FileVersion           = $metadata.FileVersion
            FileCreationTimeUtc   = $metadata.FileCreationTimeUtc
            FileLastWriteTimeUtc  = $metadata.FileLastWriteTimeUtc
            FileSize              = $metadata.FileSize
            MetadataError         = $metadata.MetadataError
            TrustLevel            = $trust.TrustLevel
            TrustReason           = $trust.TrustReason
            PathExpected          = $trust.PathExpected
            PublisherExpected     = $trust.PublisherExpected
            SignatureValid        = $trust.SignatureValid
            OriginalFileNameExpected = $trust.OriginalFileNameExpected
            CompanyExpected       = $trust.CompanyExpected
            HashKnown             = $trust.HashKnown
            TrustSignals          = $trust.TrustSignals
        }
    }

    $base = @(Resolve-H1SSProcessParents -Processes @($base))

    $finished = Get-H1SSUtcNow
    $status = if ($partialErrors.Count) { 'Partial' } else { 'Success' }
    New-H1SSCollectorPayload -Records @($base) -Status $status -ErrorType $(if ($partialErrors.Count) { 'EnrichmentPartial' } else { '' }) -ErrorMessage ($partialErrors -join ' | ') -Metadata @{ CollectionStartedAtUtc=ConvertTo-H1SSIsoUtc $started; CollectionFinishedAtUtc=ConvertTo-H1SSIsoUtc $finished; MetadataCacheHits=$MetadataCache.Hits; MetadataCacheMisses=$MetadataCache.Misses }
}

function ConvertFrom-H1SSServiceImagePath {
    param([string]$RawImagePath)
    $rawValue = [string]$RawImagePath
    $raw = [Environment]::ExpandEnvironmentVariables($rawValue).Trim()
    if ($raw -match '(?i)^\\SystemRoot\\(.+)$' -and $env:SystemRoot) { $raw = Join-Path -Path $env:SystemRoot -ChildPath $Matches[1] }
    elseif ($raw -match '(?i)^System32\\(.+)$' -and $env:SystemRoot) { $raw = Join-Path -Path $env:SystemRoot -ChildPath ("System32\$($Matches[1])") }
    $executable = $null
    $arguments = ''
    $quoted = $false
    if ($raw -match '^"([^"]+)"\s*(.*)$') {
        $quoted = $true; $executable = $Matches[1]; $arguments = $Matches[2]
    }
    elseif ($raw -match '^(.+?\.(?:exe|com|sys))(?=\s|$)\s*(.*)$') {
        $executable = $Matches[1]; $arguments = $Matches[2]
    }
    else { $executable = $raw }
    [PSCustomObject]@{
        RawImagePath       = $RawImagePath
        ExpandedImagePath  = $raw
        ExecutablePath     = $executable
        Arguments          = $arguments
        UnquotedServicePath = [bool]((-not $quoted) -and $executable -and $executable.Contains(' ') -and $executable -match '(?i)\.(?:exe|com|sys)$')
    }
}

function Test-H1SSPathPotentiallyWritable {
    param([string]$LiteralPath, [ref]$ErrorMessage)
    if ([string]::IsNullOrWhiteSpace($LiteralPath)) { return $null }
    try {
        [void](Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop)
        $acl = Get-Acl -LiteralPath $LiteralPath -ErrorAction Stop
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $sids = @($identity.User.Value) + @($identity.Groups | ForEach-Object Value)
        foreach ($entry in $acl.Access) {
            $sid = try { $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
            catch {
                if ($ErrorMessage -and -not $ErrorMessage.Value) { $ErrorMessage.Value = "ACL identity translation: $($_.Exception.Message)" }
                [string]$entry.IdentityReference
            }
            if ($entry.AccessControlType -eq 'Allow' -and $sids -contains $sid -and ($entry.FileSystemRights -band ([Security.AccessControl.FileSystemRights]'Write,Modify,FullControl,CreateFiles,CreateDirectories'))) { return $true }
        }
        $false
    }
    catch {
        if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $_) -and $ErrorMessage) { $ErrorMessage.Value = $_.Exception.Message }
        $null
    }
}

function Get-H1SSServicesCollector {
    param(
        [ValidateSet('Quick','Standard','Deep')][string]$Mode = 'Standard',
        [object]$MetadataCache
    )
    if (-not $MetadataCache) { $MetadataCache = New-H1SSFileMetadataCache }
    $started = Get-H1SSUtcNow
    $records = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        try {
            $parsed = ConvertFrom-H1SSServiceImagePath -RawImagePath ([string]$service.PathName)
            $registryPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}' -f $service.Name
            $serviceDllRead = Get-H1SSOptionalRegistryValue -LiteralPath ($registryPath + '\Parameters') -Name ServiceDll
            $serviceDll = $serviceDllRead.Value
            if ($serviceDllRead.ErrorMessage) { $errors.Add("$($service.Name) ServiceDll: $($serviceDllRead.ErrorMessage)") | Out-Null }
            if ($serviceDll) { $serviceDll = [Environment]::ExpandEnvironmentVariables([string]$serviceDll) }
            $metadata = Get-H1SSCachedFileMetadata -LiteralPath $parsed.ExecutablePath -MetadataCache $MetadataCache
            if ($metadata.MetadataError) { $errors.Add("$($service.Name) executable metadata: $($metadata.MetadataError)") | Out-Null }
            $serviceDllMetadata = if ($serviceDll) { Get-H1SSCachedFileMetadata -LiteralPath $serviceDll -MetadataCache $MetadataCache } else { $null }
            if ($serviceDllMetadata -and $serviceDllMetadata.MetadataError) { $errors.Add("$($service.Name) ServiceDll metadata: $($serviceDllMetadata.MetadataError)") | Out-Null }
            $directory = if ($parsed.ExecutablePath) { [IO.Path]::GetDirectoryName([string]$parsed.ExecutablePath) } else { $null }
            $executableAclError = $null
            $writableExecutable = Test-H1SSPathPotentiallyWritable -LiteralPath $parsed.ExecutablePath -ErrorMessage ([ref]$executableAclError)
            if ($executableAclError) { $errors.Add("$($service.Name) executable ACL: $executableAclError") | Out-Null }
            $directoryAclError = $null
            $writableDirectory = Test-H1SSPathPotentiallyWritable -LiteralPath $directory -ErrorMessage ([ref]$directoryAclError)
            if ($directoryAclError) { $errors.Add("$($service.Name) directory ACL: $directoryAclError") | Out-Null }
            $records.Add([PSCustomObject]@{
                RecordId           = 'service:{0}' -f $service.Name
                ObservedAtUtc      = ConvertTo-H1SSIsoUtc -Value (Get-H1SSUtcNow)
                Name               = $service.Name
                DisplayName        = $service.DisplayName
                State              = $service.State
                StartMode          = $service.StartMode
                StartName          = $service.StartName
                ProcessId          = $service.ProcessId
                PathName           = $service.PathName
                RawImagePath       = $parsed.RawImagePath
                ExpandedImagePath  = $parsed.ExpandedImagePath
                ExecutablePath     = $parsed.ExecutablePath
                Arguments          = $parsed.Arguments
                ServiceDll         = $serviceDll
                ServiceDllMetadata = $serviceDllMetadata
                ServiceType        = $service.ServiceType
                StartType          = $service.StartMode
                FileExists         = $metadata.FileExists
                MetadataStatus     = $metadata.MetadataStatus
                SHA256             = $metadata.SHA256
                HashStatus         = $metadata.HashStatus
                SignatureStatus    = $metadata.SignatureStatus
                SignerSubject      = $metadata.SignerSubject
                SignerIssuer       = $metadata.SignerIssuer
                SignerThumbprint   = $metadata.SignerThumbprint
                CompanyName        = $metadata.CompanyName
                ProductName        = $metadata.ProductName
                OriginalFileName   = $metadata.OriginalFileName
                FileVersion        = $metadata.FileVersion
                FileCreationTimeUtc = $metadata.FileCreationTimeUtc
                FileLastWriteTimeUtc = $metadata.FileLastWriteTimeUtc
                FileSize           = $metadata.FileSize
                MetadataError      = $metadata.MetadataError
                ServiceRegistryPath = $registryPath
                UnquotedServicePath = $parsed.UnquotedServicePath
                WritableExecutable = $writableExecutable
                WritableDirectory  = $writableDirectory
                ExecutableAclStatus = if ($executableAclError) { 'Partial' } elseif ($null -eq $writableExecutable) { 'Unavailable' } else { 'Success' }
                ExecutableAclError = $executableAclError
                DirectoryAclStatus = if ($directoryAclError) { 'Partial' } elseif ($null -eq $writableDirectory) { 'Unavailable' } else { 'Success' }
                DirectoryAclError  = $directoryAclError
            }) | Out-Null
        }
        catch { $errors.Add("$($service.Name): $($_.Exception.Message)") | Out-Null }
    }
    $finished = Get-H1SSUtcNow
    New-H1SSCollectorPayload -Records $records.ToArray() -Status $(if ($errors.Count) { 'Partial' } else { 'Success' }) -ErrorType $(if ($errors.Count) { 'ItemErrors' } else { '' }) -ErrorMessage ($errors -join ' | ') -Metadata @{ CollectionStartedAtUtc=ConvertTo-H1SSIsoUtc $started; CollectionFinishedAtUtc=ConvertTo-H1SSIsoUtc $finished; MetadataCacheHits=$MetadataCache.Hits; MetadataCacheMisses=$MetadataCache.Misses }
}

function Get-H1SSNetworkCollector {
    param([object[]]$Processes)
    if (-not (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Get-NetTCPConnection não está disponível.'
    }
    $errors = New-Object System.Collections.Generic.List[string]
    $started = Get-H1SSUtcNow
    $tcp = @(Get-NetTCPConnection -ErrorAction Stop)
    $udp = @()
    if (Get-Command -Name Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        try { $udp = @(Get-NetUDPEndpoint -ErrorAction Stop) }
        catch { $errors.Add("UDP endpoints: $($_.Exception.Message)") | Out-Null }
    }
    else { $errors.Add('Get-NetUDPEndpoint não está disponível; somente TCP foi coletado.') | Out-Null }
    $finished = Get-H1SSUtcNow
    $processMap = @{}
    foreach ($process in $Processes) { $processMap[[int]$process.PID] = $process }
    $currentProcessMap = @{}
    try {
        foreach ($currentProcess in @(Get-Process -ErrorAction Stop)) {
            $startUtc = $null
            try { $startUtc = $currentProcess.StartTime.ToUniversalTime() }
            catch { $errors.Add("Process $($currentProcess.Id) start time: $($_.Exception.Message)") | Out-Null }
            $currentProcessMap[[int]$currentProcess.Id] = $startUtc
        }
    }
    catch { $errors.Add("Process snapshot: $($_.Exception.Message)") | Out-Null }
    $records = New-Object System.Collections.Generic.List[object]

    foreach ($connection in $tcp) {
        $pidValue = [int]$connection.OwningProcess
        $process = if ($processMap.ContainsKey($pidValue)) { $processMap[$pidValue] } else { $null }
        $resolution = 'ExitedOrUnavailable'
        if ($process -and $currentProcessMap.ContainsKey($pidValue)) {
            $resolution = 'Resolved'
            if ($process.CreationDate -and $currentProcessMap[$pidValue]) {
                try { if ([math]::Abs((([DateTime]$process.CreationDate) - $currentProcessMap[$pidValue]).TotalSeconds) -gt 2) { $resolution = 'PidReuseSuspected' } }
                catch { $resolution = 'Unresolved'; $errors.Add("PID ${pidValue} reuse validation: $($_.Exception.Message)") | Out-Null }
            }
        }
        $remoteClass = Get-H1SSAddressClassification -Address ([string]$connection.RemoteAddress)
        $localClass = Get-H1SSAddressClassification -Address ([string]$connection.LocalAddress)
        $records.Add([PSCustomObject]@{
            RecordId               = ('tcp:{0}:{1}:{2}:{3}:{4}' -f $connection.LocalAddress,$connection.LocalPort,$connection.RemoteAddress,$connection.RemotePort,$pidValue)
            Protocol               = 'TCP'
            CollectionStartedAtUtc = ConvertTo-H1SSIsoUtc -Value $started
            CollectionFinishedAtUtc = ConvertTo-H1SSIsoUtc -Value $finished
            LocalAddress           = [string]$connection.LocalAddress
            LocalPort              = $connection.LocalPort
            LocalClassification    = $localClass.Classification
            RemoteAddress          = [string]$connection.RemoteAddress
            RemotePort             = $connection.RemotePort
            RemoteClassification   = $remoteClass.Classification
            State                  = [string]$connection.State
            OwningProcess          = $pidValue
            ProcessRecordId        = if ($process) { $process.RecordId } else { $null }
            ProcessName            = if ($process) { $process.Name } else { $null }
            ProcessPath            = if ($process) { $process.ExecutablePath } else { $null }
            ProcessSignatureStatus = if ($process) { $process.SignatureStatus } else { $null }
            ProcessTrustLevel      = if ($process) { $process.TrustLevel } else { $null }
            ProcessCreationTime    = if ($process) { $process.CreationDate } else { $null }
            CommandLine            = if ($process) { $process.CommandLine } else { $null }
            ProcessResolutionStatus = $resolution
        }) | Out-Null
    }
    foreach ($endpoint in $udp) {
        $pidValue = [int]$endpoint.OwningProcess
        $process = if ($processMap.ContainsKey($pidValue)) { $processMap[$pidValue] } else { $null }
        $localClass = Get-H1SSAddressClassification -Address ([string]$endpoint.LocalAddress)
        $records.Add([PSCustomObject]@{
            RecordId               = ('udp:{0}:{1}:{2}' -f $endpoint.LocalAddress,$endpoint.LocalPort,$pidValue)
            Protocol               = 'UDP'
            CollectionStartedAtUtc = ConvertTo-H1SSIsoUtc -Value $started
            CollectionFinishedAtUtc = ConvertTo-H1SSIsoUtc -Value $finished
            LocalAddress           = [string]$endpoint.LocalAddress
            LocalPort              = $endpoint.LocalPort
            LocalClassification    = $localClass.Classification
            RemoteAddress          = $null
            RemotePort             = $null
            RemoteClassification   = $null
            State                  = 'Bound'
            OwningProcess          = $pidValue
            ProcessRecordId        = if ($process) { $process.RecordId } else { $null }
            ProcessName            = if ($process) { $process.Name } else { $null }
            ProcessPath            = if ($process) { $process.ExecutablePath } else { $null }
            ProcessSignatureStatus = if ($process) { $process.SignatureStatus } else { $null }
            ProcessTrustLevel      = if ($process) { $process.TrustLevel } else { $null }
            ProcessCreationTime    = if ($process) { $process.CreationDate } else { $null }
            CommandLine            = if ($process) { $process.CommandLine } else { $null }
            ProcessResolutionStatus = if ($process -and $currentProcessMap.ContainsKey($pidValue)) { 'Resolved' } elseif ($process) { 'ExitedOrUnavailable' } else { 'ExitedOrUnavailable' }
        }) | Out-Null
    }
    New-H1SSCollectorPayload -Records $records.ToArray() -Status $(if ($errors.Count) { 'Partial' } else { 'Success' }) -ErrorType $(if ($errors.Count) { 'EnrichmentPartial' } else { '' }) -ErrorMessage ($errors -join ' | ') -Metadata @{ CollectionStartedAtUtc = ConvertTo-H1SSIsoUtc -Value $started; CollectionFinishedAtUtc = ConvertTo-H1SSIsoUtc -Value $finished }
}

function Get-H1SSDnsCollector {
    if (-not (Get-Command -Name Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Get-DnsClientCache não está disponível.'
    }
    $records = @(Get-DnsClientCache -ErrorAction Stop | Select-Object Entry,Name,Type,Status,Section,TimeToLive,Data)
    New-H1SSCollectorPayload -Records $records
}

function Get-H1SSNetworkConfigurationCollector {
    if (-not (Get-Command -Name Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Get-NetIPConfiguration não está disponível.'
    }
    $records = @(Get-NetIPConfiguration -Detailed -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            InterfaceAlias = $_.InterfaceAlias
            InterfaceIndex = $_.InterfaceIndex
            NetProfileName = $_.NetProfile.Name
            IPv4Address = @($_.IPv4Address | ForEach-Object IPAddress)
            IPv6Address = @($_.IPv6Address | ForEach-Object IPAddress)
            IPv4DefaultGateway = @($_.IPv4DefaultGateway | ForEach-Object NextHop)
            IPv6DefaultGateway = @($_.IPv6DefaultGateway | ForEach-Object NextHop)
            DnsServer = @($_.DNSServer.ServerAddresses)
        }
    })
    New-H1SSCollectorPayload -Records $records
}

function Get-H1SSStartupCommandsCollector {
    $records = @(Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{ Name=$_.Name; Command=$_.Command; Location=$_.Location; User=$_.User; UserSID=$_.UserSID }
    })
    New-H1SSCollectorPayload -Records $records
}

function Get-H1SSScheduledTasksCollector {
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Get-ScheduledTask não está disponível.'
    }
    $started = Get-H1SSUtcNow
    $records = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
        $info = $null; $xml = $null; $itemErrors = New-Object System.Collections.Generic.List[string]
        try { $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop } catch { $itemErrors.Add("Info: $($_.Exception.Message)") | Out-Null }
        try { $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop } catch { $itemErrors.Add("XML: $($_.Exception.Message)") | Out-Null }
        if ($itemErrors.Count) { $errors.Add("$($task.TaskPath)$($task.TaskName): $($itemErrors -join '; ')") | Out-Null }
        $actions = @($task.Actions | ForEach-Object { [PSCustomObject]@{ RawExecute = $_.Execute; Execute = $_.Execute; Arguments = $_.Arguments; WorkingDirectory = $_.WorkingDirectory } })
        $triggers = @($task.Triggers | ForEach-Object { [PSCustomObject]@{ Type = $_.CimClass.CimClassName; Enabled = $_.Enabled; StartBoundary = $_.StartBoundary; EndBoundary = $_.EndBoundary; Repetition = [string]$_.Repetition } })
        $records.Add([PSCustomObject]@{
            RecordId             = ('task:{0}{1}' -f $task.TaskPath,$task.TaskName)
            ObservedAtUtc        = ConvertTo-H1SSIsoUtc -Value (Get-H1SSUtcNow)
            TaskName             = $task.TaskName
            TaskPath             = $task.TaskPath
            State                = [string]$task.State
            Enabled              = ($task.State -ne 'Disabled')
            Author               = $task.Author
            Description          = $task.Description
            PrincipalUserId      = $task.Principal.UserId
            PrincipalLogonType   = [string]$task.Principal.LogonType
            PrincipalRunLevel    = [string]$task.Principal.RunLevel
            Actions              = $actions
            Arguments            = @($actions | ForEach-Object Arguments)
            WorkingDirectory     = @($actions | ForEach-Object WorkingDirectory)
            Triggers             = $triggers
            LastRunTime          = if ($info) { $info.LastRunTime } else { $null }
            NextRunTime          = if ($info) { $info.NextRunTime } else { $null }
            LastTaskResult       = if ($info) { $info.LastTaskResult } else { $null }
            NumberOfMissedRuns   = if ($info) { $info.NumberOfMissedRuns } else { $null }
            Hidden               = $task.Settings.Hidden
            XML                  = $xml
            XmlSHA256            = if ($xml) { Get-H1SSStringSha256 -Value $xml } else { $null }
            ItemCollectionStatus = if ($itemErrors.Count) { 'Partial' } else { 'Success' }
            ItemErrors           = $itemErrors.ToArray()
            ActionFileMetadata   = @()
            DetectionEnrichmentStatus = 'Pending'
            DetectionEnrichmentErrors = @()
        }) | Out-Null
    }
    $finished = Get-H1SSUtcNow
    New-H1SSCollectorPayload -Records $records.ToArray() -Status $(if ($errors.Count) { 'Partial' } else { 'Success' }) -ErrorType $(if ($errors.Count) { 'ItemErrors' } else { '' }) -ErrorMessage ($errors -join ' | ') -Metadata @{ CollectionStartedAtUtc=ConvertTo-H1SSIsoUtc $started; CollectionFinishedAtUtc=ConvertTo-H1SSIsoUtc $finished }
}

function Get-H1SSRunKeysCollector {
    $errors = New-Object System.Collections.Generic.List[string]
    $locations = @(
        @{ Hive='HKLM'; Path='Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run' },
        @{ Hive='HKLM'; Path='Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Hive='HKLM32'; Path='Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' },
        @{ Hive='HKLM32'; Path='Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Hive='HKLM'; Path='Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' },
        @{ Hive='HKCU'; Path='Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run' },
        @{ Hive='HKCU'; Path='Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ Hive='HKCU'; Path='Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' }
    )
    try {
        Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^S-1-5-21-' } | ForEach-Object {
            $sid = $_.PSChildName
            $locations += @{ Hive="HKU:$sid"; Path="Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run" }
            $locations += @{ Hive="HKU:$sid"; Path="Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce" }
            $locations += @{ Hive="HKU:$sid"; Path="Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" }
        }
    }
    catch { $errors.Add("HKEY_USERS enumeration: $($_.Exception.Message)") | Out-Null }

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($location in $locations) {
        try {
            $properties = Get-ItemProperty -LiteralPath $location.Path -ErrorAction Stop
            foreach ($property in $properties.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
                $records.Add([PSCustomObject]@{
                    RecordId = ('runkey:{0}:{1}' -f (Get-H1SSStringSha256 -Value $location.Path).Substring(0,12),$property.Name)
                    ObservedAtUtc = ConvertTo-H1SSIsoUtc -Value (Get-H1SSUtcNow)
                    Hive = $location.Hive
                    RegistryPath = $location.Path
                    Name = $property.Name
                    Value = [string]$property.Value
                }) | Out-Null
            }
        }
        catch {
            if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $_)) {
                $errors.Add("$($location.Path): $($_.Exception.Message)") | Out-Null
            }
        }
    }
    New-H1SSCollectorPayload -Records $records.ToArray() -Status $(if ($errors.Count) { 'Partial' } else { 'Success' }) -ErrorType $(if ($errors.Count) { 'RegistryAccessErrors' } else { '' }) -ErrorMessage ($errors -join ' | ')
}

function Get-H1SSStartupCollector {
    $folders = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    $folders.Add([PSCustomObject]@{ Scope='CurrentUser'; UserSid=$null; Path=[Environment]::GetFolderPath('Startup') }) | Out-Null
    $folders.Add([PSCustomObject]@{ Scope='AllUsers'; UserSid=$null; Path=[Environment]::GetFolderPath('CommonStartup') }) | Out-Null
    try {
        foreach ($profile in @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath })) {
            $folders.Add([PSCustomObject]@{ Scope='Profile'; UserSid=$profile.SID; Path=(Join-Path -Path $profile.LocalPath -ChildPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }) | Out-Null
        }
    }
    catch { $errors.Add("Win32_UserProfile: $($_.Exception.Message)") | Out-Null }
    $records = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($folder in $folders) {
        if ([string]::IsNullOrWhiteSpace($folder.Path) -or $seen.ContainsKey($folder.Path)) { continue }
        $seen[$folder.Path] = $true
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $folder.Path -Force -File -ErrorAction Stop)) {
                $target = $null; $arguments = $null; $working = $null
                if ($file.Extension -eq '.lnk') {
                    try {
                        $shell = New-Object -ComObject WScript.Shell
                        $shortcut = $shell.CreateShortcut($file.FullName)
                        $target = $shortcut.TargetPath; $arguments = $shortcut.Arguments; $working = $shortcut.WorkingDirectory
                        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
                    }
                    catch { $errors.Add("LNK $($file.FullName): $($_.Exception.Message)") | Out-Null }
                }
                $records.Add([PSCustomObject]@{
                    RecordId = 'startup:{0}' -f (Get-H1SSStringSha256 -Value $file.FullName).Substring(0,16)
                    ObservedAtUtc = ConvertTo-H1SSIsoUtc -Value (Get-H1SSUtcNow)
                    Scope = $folder.Scope
                    UserSid = $folder.UserSid
                    StartupFolder = $folder.Path
                    FullName = $file.FullName
                    Length = $file.Length
                    CreationTimeUtc = ConvertTo-H1SSIsoUtc -Value $file.CreationTimeUtc
                    LastWriteTimeUtc = ConvertTo-H1SSIsoUtc -Value $file.LastWriteTimeUtc
                    TargetPath = $target
                    Arguments = $arguments
                    WorkingDirectory = $working
                }) | Out-Null
            }
        }
        catch {
            if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $_)) {
                $errors.Add("$($folder.Path): $($_.Exception.Message)") | Out-Null
            }
        }
    }
    New-H1SSCollectorPayload -Records $records.ToArray() -Status $(if ($errors.Count) { 'Partial' } else { 'Success' }) -ErrorType $(if ($errors.Count) { 'ItemErrors' } else { '' }) -ErrorMessage ($errors -join ' | ')
}

function Get-H1SSAdvancedPersistenceCollector {
    $records = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    $observed = ConvertTo-H1SSIsoUtc -Value (Get-H1SSUtcNow)

    foreach ($valueName in @('Shell','Userinit','Taskman')) {
        $read = Get-H1SSOptionalRegistryValue -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name $valueName
        if ($read.Present) {
            $value = $read.Value
            $records.Add([PSCustomObject]@{ RecordId="winlogon:$valueName"; Type='Winlogon'; ObservedAtUtc=$observed; Location='HKLM\...\Winlogon'; Name=$valueName; Value=[string]$value; Details=$null }) | Out-Null
        }
        elseif ($read.ErrorMessage) { $errors.Add("Winlogon ${valueName}: $($read.ErrorMessage)") | Out-Null }
    }

    foreach ($root in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        try {
            foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                foreach ($name in @('Debugger','GlobalFlag')) {
                    if ($props.PSObject.Properties.Name -contains $name) {
                        $records.Add([PSCustomObject]@{ RecordId="ifeo:$($key.PSChildName):$name"; Type='IFEO'; ObservedAtUtc=$observed; Location=$key.Name; Name=$name; Value=[string]$props.$name; Details=$null }) | Out-Null
                    }
                }
            }
        }
        catch {
            if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $_)) {
                $errors.Add("IFEO ${root}: $($_.Exception.Message)") | Out-Null
            }
        }
    }

    try {
        foreach ($key in @(Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction Stop)) {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ($props.MonitorProcess) { $records.Add([PSCustomObject]@{ RecordId="silentexit:$($key.PSChildName)"; Type='SilentProcessExit'; ObservedAtUtc=$observed; Location=$key.Name; Name='MonitorProcess'; Value=[string]$props.MonitorProcess; Details=$null }) | Out-Null }
        }
    }
    catch {
        if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $_)) {
            $errors.Add("SilentProcessExit: $($_.Exception.Message)") | Out-Null
        }
    }

    $profilePaths = @(
        $PROFILE.CurrentUserCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.AllUsersAllHosts,
        (Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath 'PowerShell\Microsoft.PowerShell_profile.ps1'),
        (Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath 'PowerShell\profile.ps1')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    foreach ($profilePath in $profilePaths) {
        try {
            $meta = Get-H1SSFileMetadata -LiteralPath $profilePath -IncludeHash
            if ($meta.MetadataError) { $errors.Add("Profile ${profilePath}: $($meta.MetadataError)") | Out-Null }
            elseif ($meta.FileExists) {
                $records.Add([PSCustomObject]@{ RecordId="profile:$((Get-H1SSStringSha256 -Value $profilePath).Substring(0,12))"; Type='PowerShellProfile'; ObservedAtUtc=$observed; Location=$profilePath; Name='Profile'; Value=$meta.SHA256; Details=$meta }) | Out-Null
            }
        }
        catch { $errors.Add("Profile ${profilePath}: $($_.Exception.Message)") | Out-Null }
    }

    try {
        foreach ($className in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')) {
            foreach ($item in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $className -ErrorAction Stop)) {
                $records.Add([PSCustomObject]@{ RecordId="wmi:${className}:$((Get-H1SSStringSha256 -Value ([string]$item)).Substring(0,12))"; Type='WMISubscription'; ObservedAtUtc=$observed; Location='root\subscription'; Name=$className; Value=$item.Name; Details=$item }) | Out-Null
            }
        }
    }
    catch { $errors.Add("WMI root\subscription: $($_.Exception.Message)") | Out-Null }

    New-H1SSCollectorPayload -Records $records.ToArray() -Status $(if ($errors.Count) { 'Partial' } else { 'Success' }) -ErrorType $(if ($errors.Count) { 'SubcollectorErrors' } else { '' }) -ErrorMessage ($errors -join ' | ')
}

function Get-H1SSRecentFilesCollector {
    param([int]$RecentFileHours = 24, [int]$MaxRecentFiles = 200, [int]$MaxScanDurationSeconds = 30)
    $cutoff = (Get-H1SSUtcNow).AddHours(-1 * $RecentFileHours)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $records = New-Object System.Collections.Generic.List[object]
    $scanErrors = New-Object System.Collections.Generic.List[string]
    $processed = 0; $limitReached = $false
    $paths = @($env:TEMP, "$env:windir\Temp") | Where-Object { $_ } | Select-Object -Unique
    foreach ($path in $paths) {
        $pathErrors = @()
        $files = @()
        try { $files = @(Get-ChildItem -LiteralPath $path -File -Force -Recurse -ErrorAction SilentlyContinue -ErrorVariable pathErrors) }
        catch {
            if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $_)) { $scanErrors.Add("${path}: $($_.Exception.Message)") | Out-Null }
        }
        foreach ($file in $files) {
            $processed++
            if ($watch.Elapsed.TotalSeconds -ge $MaxScanDurationSeconds -or $records.Count -ge $MaxRecentFiles) { $limitReached = $true; break }
            if ($file.LastWriteTimeUtc -lt $cutoff) { continue }
            $records.Add([PSCustomObject]@{ FullName=$file.FullName; Length=$file.Length; CreationTimeUtc=ConvertTo-H1SSIsoUtc $file.CreationTimeUtc; LastWriteTimeUtc=ConvertTo-H1SSIsoUtc $file.LastWriteTimeUtc }) | Out-Null
        }
        foreach ($pathError in $pathErrors) {
            if (-not (Test-H1SSExpectedAbsenceError -ErrorRecord $pathError)) {
                $scanErrors.Add("${path}: $($pathError.Exception.Message)") | Out-Null
            }
        }
        if ($limitReached) { break }
    }
    $watch.Stop()
    $messages = New-Object System.Collections.Generic.List[string]
    if ($limitReached) { $messages.Add('A coleta atingiu limite de tempo ou quantidade.') | Out-Null }
    foreach ($scanError in $scanErrors) { $messages.Add($scanError) | Out-Null }
    $status = if ($limitReached -or $scanErrors.Count) { 'Partial' } else { 'Success' }
    $errorType = if ($limitReached -and $scanErrors.Count) { 'CollectionLimitAndAccessErrors' } elseif ($limitReached) { 'CollectionLimitReached' } elseif ($scanErrors.Count) { 'AccessErrors' } else { '' }
    New-H1SSCollectorPayload -Records @($records | Sort-Object LastWriteTimeUtc -Descending) -Status $status -ErrorType $errorType -ErrorMessage ($messages -join ' | ') -Metadata @{ ItemsProcessed=$processed; ItemsReturned=$records.Count; LimitReached=$limitReached; AccessErrorCount=$scanErrors.Count; MaxScanDurationSeconds=$MaxScanDurationSeconds }
}

function Get-H1SSEventsCollector {
    param([int]$EventLogHours = 24)
    if (-not (Get-Command -Name Get-WinEvent -ErrorAction SilentlyContinue)) { return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Get-WinEvent não está disponível.' }
    $start = (Get-Date).AddHours(-1 * $EventLogHours)
    $queries = @(
        @{ Log='Security'; Id=@(4688,4624,4625,4720,4722,4728,4732,4756,4697) },
        @{ Log='System'; Id=@(7045) },
        @{ Log='Microsoft-Windows-PowerShell/Operational'; Id=@(4103,4104) },
        @{ Log='Microsoft-Windows-TaskScheduler/Operational'; Id=@() },
        @{ Log='Microsoft-Windows-WMI-Activity/Operational'; Id=@() },
        @{ Log='Microsoft-Windows-Windows Defender/Operational'; Id=@() },
        @{ Log='Microsoft-Windows-Sysmon/Operational'; Id=@() }
    )
    $records = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    $sourceStates = New-Object System.Collections.Generic.List[object]
    foreach ($query in $queries) {
        try {
            [void](Get-WinEvent -ListLog $query.Log -ErrorAction Stop)
            $filter = @{ LogName=$query.Log; StartTime=$start }
            if ($query.Id.Count) { $filter.Id = $query.Id }
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 2000 -ErrorAction Stop)
            foreach ($event in $events) {
                $records.Add([PSCustomObject]@{ RecordId="event:$($query.Log):$($event.RecordId)"; LogName=$query.Log; Id=$event.Id; EventRecordId=$event.RecordId; TimeCreated=$event.TimeCreated; LevelDisplayName=$event.LevelDisplayName; ProviderName=$event.ProviderName; Message=$event.Message }) | Out-Null
            }
            $sourceStates.Add([PSCustomObject]@{ LogName=$query.Log; Status='Success'; RecordCount=$events.Count; Error='' }) | Out-Null
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                $sourceStates.Add([PSCustomObject]@{ LogName=$query.Log; Status='Success'; RecordCount=0; Error='' }) | Out-Null
            }
            else {
                $errors.Add("$($query.Log): $($_.Exception.Message)") | Out-Null
                $sourceStates.Add([PSCustomObject]@{ LogName=$query.Log; Status='Unavailable'; RecordCount=0; Error=$_.Exception.Message }) | Out-Null
            }
        }
    }
    $status = if ($errors.Count -eq 0) { 'Success' } elseif ($sourceStates.Count -gt $errors.Count) { 'Partial' } else { 'Unavailable' }
    New-H1SSCollectorPayload -Records $records.ToArray() -Status $status -ErrorType $(if ($errors.Count) { 'LogErrors' } else { '' }) -ErrorMessage ($errors -join ' | ') -Metadata @{ WindowHours=$EventLogHours; Sources=$sourceStates.ToArray() }
}

function Get-H1SSDefenderCollector {
    if (-not (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return New-H1SSCollectorPayload -Status Unavailable -ErrorType 'CommandUnavailable' -ErrorMessage 'Cmdlets Microsoft Defender não disponíveis.' }
    $records = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    try { $records.Add([PSCustomObject]@{ Type='Status'; Data=(Get-MpComputerStatus -ErrorAction Stop) }) | Out-Null } catch { $errors.Add("Status: $($_.Exception.Message)") | Out-Null }
    try { $records.Add([PSCustomObject]@{ Type='Preferences'; Data=(Get-MpPreference -ErrorAction Stop | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,DisableRealtimeMonitoring,PUAProtection) }) | Out-Null } catch { $errors.Add("Preferences: $($_.Exception.Message)") | Out-Null }
    try { foreach ($threat in @(Get-MpThreatDetection -ErrorAction Stop)) { $records.Add([PSCustomObject]@{ Type='Detection'; Data=$threat }) | Out-Null } } catch { $errors.Add("Detections: $($_.Exception.Message)") | Out-Null }
    $status = if ($records.Count -and $errors.Count) { 'Partial' } elseif (-not $records.Count) { 'Failed' } else { 'Success' }
    New-H1SSCollectorPayload -Records $records.ToArray() -Status $status -ErrorType $(if ($errors.Count) { 'SubcollectorErrors' } else { '' }) -ErrorMessage ($errors -join ' | ')
}
