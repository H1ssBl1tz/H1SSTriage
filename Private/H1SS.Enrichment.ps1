function Resolve-H1SSTaskActionPath {
    param([string]$Execute)

    $candidate = [Environment]::ExpandEnvironmentVariables([string]$Execute).Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return [PSCustomObject]@{ ResolvedPath=$null; ResolutionStatus='Unavailable'; ErrorMessage='A action não contém um executável.' }
    }
    if ([IO.Path]::IsPathRooted($candidate)) {
        return [PSCustomObject]@{ ResolvedPath=$candidate; ResolutionStatus='Resolved'; ErrorMessage=$null }
    }
    try {
        $resolved = (Get-Command -Name $candidate -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
        [PSCustomObject]@{ ResolvedPath=$resolved; ResolutionStatus='Resolved'; ErrorMessage=$null }
    }
    catch {
        [PSCustomObject]@{ ResolvedPath=$candidate; ResolutionStatus='Partial'; ErrorMessage=$_.Exception.Message }
    }
}

function Add-H1SSDetectionEnrichment {
    param([Parameter(Mandatory=$true)][hashtable]$Data, [object]$MetadataCache)

    if (-not $MetadataCache) { $MetadataCache = New-H1SSFileMetadataCache }
    $errors = New-Object System.Collections.Generic.List[object]
    foreach ($task in @($Data.ScheduledTasks)) {
        $taskErrors = New-Object System.Collections.Generic.List[string]
        $taskMetadata = New-Object System.Collections.Generic.List[object]
        foreach ($action in @($task.Actions)) {
            $resolution = Resolve-H1SSTaskActionPath -Execute ([string]$action.Execute)
            if ($resolution.ErrorMessage) {
                $message = "$($action.Execute): $($resolution.ErrorMessage)"
                $taskErrors.Add($message) | Out-Null
                $errors.Add([PSCustomObject]@{ CollectorName='ScheduledTasks'; ErrorType='ExecutableResolutionError'; ErrorMessage=$message }) | Out-Null
            }

            $metadata = Get-H1SSCachedFileMetadata -LiteralPath ([string]$resolution.ResolvedPath) -MetadataCache $MetadataCache
            foreach ($name in @('PathExpected','PublisherExpected','OriginalFileNameExpected','CompanyExpected','HashKnown')) {
                if ($metadata.PSObject.Properties.Name -notcontains $name) {
                    $metadata | Add-Member -NotePropertyName $name -NotePropertyValue $null
                }
            }
            if ($metadata.MetadataError) {
                $message = "$($resolution.ResolvedPath): $($metadata.MetadataError)"
                $taskErrors.Add($message) | Out-Null
                $errors.Add([PSCustomObject]@{ CollectorName='ScheduledTasks'; ErrorType='MetadataAcquisitionError'; ErrorMessage=$message }) | Out-Null
            }
            $metadataStatus = if ($metadata.MetadataError -or $resolution.ErrorMessage) { 'Partial' } elseif ($metadata.FileExists) { 'Success' } else { 'Absent' }
            $taskMetadata.Add([PSCustomObject]@{
                Execute          = $action.Execute
                ResolvedPath     = $resolution.ResolvedPath
                ResolutionStatus = $resolution.ResolutionStatus
                MetadataStatus   = $metadataStatus
                Arguments        = $action.Arguments
                WorkingDirectory = $action.WorkingDirectory
                FileExists       = $metadata.FileExists
                SHA256           = $metadata.SHA256
                HashStatus       = $metadata.HashStatus
                SignatureStatus  = $metadata.SignatureStatus
                SignerSubject    = $metadata.SignerSubject
                SignerIssuer     = $metadata.SignerIssuer
                SignerThumbprint = $metadata.SignerThumbprint
                CompanyName      = $metadata.CompanyName
                ProductName      = $metadata.ProductName
                OriginalFileName = $metadata.OriginalFileName
                FileVersion      = $metadata.FileVersion
                Metadata         = $metadata
            }) | Out-Null
        }

        $task.ActionFileMetadata = $taskMetadata.ToArray()
        $status = if ($taskErrors.Count) { 'Partial' } else { 'Success' }
        if ($task.PSObject.Properties.Name -contains 'DetectionEnrichmentStatus') { $task.DetectionEnrichmentStatus = $status }
        else { $task | Add-Member -NotePropertyName DetectionEnrichmentStatus -NotePropertyValue $status }
        if ($task.PSObject.Properties.Name -contains 'DetectionEnrichmentErrors') { $task.DetectionEnrichmentErrors = $taskErrors.ToArray() }
        else { $task | Add-Member -NotePropertyName DetectionEnrichmentErrors -NotePropertyValue $taskErrors.ToArray() }
    }
    $errors.ToArray()
}

function Resolve-H1SSProcessParents {
    param([Parameter(Mandatory=$true)][object[]]$Processes)

    $byPid = @{}
    foreach ($process in @($Processes)) {
        $pidValue = [int]$process.PID
        if (-not $byPid.ContainsKey($pidValue)) { $byPid[$pidValue] = New-Object System.Collections.Generic.List[object] }
        $byPid[$pidValue].Add($process) | Out-Null
    }

    foreach ($child in @($Processes)) {
        foreach ($propertyName in @('ParentName','ParentPath','ParentCreationTime','ParentResolutionStatus','ParentResolutionReason')) {
            if ($child.PSObject.Properties.Name -notcontains $propertyName) { $child | Add-Member -NotePropertyName $propertyName -NotePropertyValue $null }
        }
        $child.ParentName = $null
        $child.ParentPath = $null
        $child.ParentCreationTime = $null
        $child.ParentResolutionStatus = 'Unresolved'
        $child.ParentResolutionReason = 'Temporal evidence is incomplete.'

        $parentPid = [int]$child.PPID
        if ($parentPid -le 0 -or -not $byPid.ContainsKey($parentPid)) {
            $child.ParentResolutionStatus = 'ExitedOrUnavailable'
            $child.ParentResolutionReason = 'No parent candidate exists in the process snapshot.'
            continue
        }

        $childCreation = $null
        if ($child.CreationDate) {
            try { $childCreation = ([DateTime]$child.CreationDate).ToUniversalTime() }
            catch {
                $child.ParentResolutionReason = "Child creation time is invalid: $($_.Exception.Message)"
                continue
            }
        }
        $candidates = @($byPid[$parentPid] | Where-Object { $_.RecordId -ne $child.RecordId })
        if (-not $childCreation -or $candidates.Count -eq 0) {
            $child.ParentResolutionStatus = 'Unresolved'
            $child.ParentResolutionReason = 'Child creation time or distinct parent candidate is unavailable.'
            continue
        }

        $eligible = New-Object System.Collections.Generic.List[object]
        $invalidCandidateTimes = 0
        foreach ($candidate in $candidates) {
            $candidateCreation = $null
            if ($candidate.CreationDate) {
                try { $candidateCreation = ([DateTime]$candidate.CreationDate).ToUniversalTime() }
                catch { $invalidCandidateTimes++ }
            }
            if ($candidateCreation -and $candidateCreation -le $childCreation) {
                $eligible.Add([PSCustomObject]@{ Process=$candidate; Creation=$candidateCreation }) | Out-Null
            }
        }
        if ($eligible.Count -eq 0) {
            $child.ParentResolutionStatus = 'Unresolved'
            $child.ParentResolutionReason = if ($invalidCandidateTimes -gt 0) { "$invalidCandidateTimes parent candidate(s) had an invalid creation time and none was otherwise plausible." } else { 'PID candidates exist, but none is temporally plausible.' }
            continue
        }

        $ordered = @($eligible | Sort-Object Creation -Descending)
        $latest = $ordered[0]
        $sameLatest = @($ordered | Where-Object Creation -eq $latest.Creation)
        if ($sameLatest.Count -ne 1) {
            $child.ParentResolutionStatus = 'Ambiguous'
            $child.ParentResolutionReason = 'Multiple parent candidates share the latest plausible creation time.'
            continue
        }

        $parent = $latest.Process
        $child.ParentName = $parent.Name
        $child.ParentPath = $parent.ExecutablePath
        $child.ParentCreationTime = $parent.CreationDate
        $child.ParentResolutionStatus = 'Resolved'
        $child.ParentResolutionReason = 'Latest unique parent candidate was created before the child.'
    }
    @($Processes)
}

function Add-H1SSSelectiveFileHashes {
    param([object[]]$Findings, [hashtable]$Data, [ValidateSet('Quick','Standard','Deep')][string]$Mode, [object]$MetadataCache)

    if (-not $MetadataCache) { $MetadataCache = New-H1SSFileMetadataCache }
    $entityIds = @{}
    $errors = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $Findings | Where-Object { $_.Bucket -eq 'Alert' }) {
        $entityIds[$finding.EntityId] = $true
        foreach ($recordId in @($finding.SourceRecordIds)) { if ($recordId) { $entityIds[[string]$recordId] = $true } }
    }
    foreach ($process in $Data.Processes) {
        if (($Mode -eq 'Deep' -or $entityIds.ContainsKey($process.RecordId)) -and $process.FileExists -and $process.ExecutablePath) {
            $hash = Get-H1SSCachedFileHash -LiteralPath $process.ExecutablePath -MetadataCache $MetadataCache
            $process.SHA256 = $hash.SHA256
            if ($process.PSObject.Properties.Name -contains 'HashStatus') { $process.HashStatus = $hash.HashStatus } else { $process | Add-Member -NotePropertyName HashStatus -NotePropertyValue $hash.HashStatus }
            if ($hash.HashStatus -ne 'Success') {
                $message = if ($hash.ErrorMessage) { $hash.ErrorMessage } else { 'O arquivo desapareceu antes do hashing.' }
                $errors.Add([PSCustomObject]@{ CollectorName='Processes'; ErrorType='HashAcquisitionError'; ErrorMessage=("$($process.ExecutablePath): $message") }) | Out-Null
            }
        }
    }
    foreach ($service in $Data.Services) {
        if (($Mode -eq 'Deep' -or $entityIds.ContainsKey($service.RecordId)) -and $service.FileExists -and $service.ExecutablePath) {
            $hash = Get-H1SSCachedFileHash -LiteralPath $service.ExecutablePath -MetadataCache $MetadataCache
            $service.SHA256 = $hash.SHA256
            if ($service.PSObject.Properties.Name -contains 'HashStatus') { $service.HashStatus = $hash.HashStatus } else { $service | Add-Member -NotePropertyName HashStatus -NotePropertyValue $hash.HashStatus }
            if ($hash.HashStatus -ne 'Success') {
                $message = if ($hash.ErrorMessage) { $hash.ErrorMessage } else { 'O arquivo desapareceu antes do hashing.' }
                $errors.Add([PSCustomObject]@{ CollectorName='Services'; ErrorType='HashAcquisitionError'; ErrorMessage=("$($service.ExecutablePath): $message") }) | Out-Null
            }
        }
        if (($Mode -eq 'Deep' -or $entityIds.ContainsKey($service.RecordId)) -and $service.ServiceDll -and $service.ServiceDllMetadata -and $service.ServiceDllMetadata.FileExists) {
            $dllHash = Get-H1SSCachedFileHash -LiteralPath $service.ServiceDll -MetadataCache $MetadataCache
            $service.ServiceDllMetadata.SHA256 = $dllHash.SHA256
            $service.ServiceDllMetadata.HashStatus = $dllHash.HashStatus
            if ($dllHash.HashStatus -ne 'Success') {
                $message = if ($dllHash.ErrorMessage) { $dllHash.ErrorMessage } else { 'O ServiceDll desapareceu antes do hashing.' }
                $errors.Add([PSCustomObject]@{ CollectorName='Services'; ErrorType='HashAcquisitionError'; ErrorMessage=("$($service.ServiceDll): $message") }) | Out-Null
            }
        }
    }
    foreach ($task in $Data.ScheduledTasks) {
        if (-not ($Mode -eq 'Deep' -or $entityIds.ContainsKey($task.RecordId))) { continue }
        foreach ($actionMetadata in @($task.ActionFileMetadata)) {
            $candidate = [string]$actionMetadata.ResolvedPath
            $metadata = $actionMetadata.Metadata
            if (-not $candidate -or -not $metadata -or -not $metadata.FileExists -or $metadata.SHA256) { continue }
            $hash = Get-H1SSCachedFileHash -LiteralPath $candidate -MetadataCache $MetadataCache
            $metadata.SHA256 = $hash.SHA256
            $metadata.HashStatus = $hash.HashStatus
            $actionMetadata.SHA256 = $hash.SHA256
            $actionMetadata.HashStatus = $hash.HashStatus
            if ($hash.HashStatus -ne 'Success') {
                $message = if ($hash.ErrorMessage) { $hash.ErrorMessage } else { 'O arquivo da action desapareceu antes do hashing.' }
                $errors.Add([PSCustomObject]@{ CollectorName='ScheduledTasks'; ErrorType='HashAcquisitionError'; ErrorMessage=("${candidate}: $message") }) | Out-Null
            }
        }
    }
    foreach ($entry in @($Data.RunKeys)) {
        if (-not $entry) { continue }
        if (-not $entityIds.ContainsKey($entry.RecordId)) { continue }
        $parsed = ConvertFrom-H1SSServiceImagePath -RawImagePath ([string]$entry.Value)
        $candidate = [string]$parsed.ExecutablePath
        $hash = Get-H1SSCachedFileHash -LiteralPath $candidate -MetadataCache $MetadataCache
        foreach ($property in @(@{Name='ResolvedExecutablePath';Value=$candidate},@{Name='SHA256';Value=$hash.SHA256},@{Name='HashStatus';Value=$hash.HashStatus},@{Name='HashError';Value=$hash.ErrorMessage})) {
            if ($entry.PSObject.Properties.Name -contains $property.Name) { $entry.($property.Name) = $property.Value } else { $entry | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value }
        }
        if ($hash.HashStatus -eq 'Failed') { $errors.Add([PSCustomObject]@{ CollectorName='RunKeys'; ErrorType='HashAcquisitionError'; ErrorMessage=("${candidate}: $($hash.ErrorMessage)") }) | Out-Null }
    }
    foreach ($item in @($Data.Startup)) {
        if (-not $item) { continue }
        if (-not $entityIds.ContainsKey($item.RecordId) -or -not $item.TargetPath) { continue }
        $candidate = [string]$item.TargetPath
        $hash = Get-H1SSCachedFileHash -LiteralPath $candidate -MetadataCache $MetadataCache
        foreach ($property in @(@{Name='SHA256';Value=$hash.SHA256},@{Name='HashStatus';Value=$hash.HashStatus},@{Name='HashError';Value=$hash.ErrorMessage})) {
            if ($item.PSObject.Properties.Name -contains $property.Name) { $item.($property.Name) = $property.Value } else { $item | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value }
        }
        if ($hash.HashStatus -eq 'Failed') { $errors.Add([PSCustomObject]@{ CollectorName='Startup'; ErrorType='HashAcquisitionError'; ErrorMessage=("${candidate}: $($hash.ErrorMessage)") }) | Out-Null }
    }
    $errors.ToArray()
}
