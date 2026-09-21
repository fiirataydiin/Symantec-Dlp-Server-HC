#requires -Version 5.1

<#
.SYNOPSIS
    Collects local Windows server hardware and resource usage information.

.DESCRIPTION
    Read-only health check for the server on which the script is executed.
    Displays hardware inventory, current resource usage and threshold-based
    Normal/Warning/Critical findings in the PowerShell console.

    This is module 3.1 of the planned Symantec DLP health-check tool.

    Prepared by: FIRAT AYDIN

.EXAMPLE
    .\DlpServerHealth.ps1

.EXAMPLE
    .\DlpServerHealth.ps1 -CpuWarningPercent 75 -DiskCriticalFreePercent 8
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 100)]
    [int]$CpuWarningPercent = 70,

    [ValidateRange(1, 100)]
    [int]$CpuCriticalPercent = 85,

    [ValidateRange(1, 100)]
    [int]$MemoryWarningUsedPercent = 80,

    [ValidateRange(1, 100)]
    [int]$MemoryCriticalUsedPercent = 90,

    [ValidateRange(0.1, 100)]
    [double]$DiskWarningFreePercent = 20,

    [ValidateRange(0.1, 100)]
    [double]$DiskCriticalFreePercent = 10,

    [ValidateSet('', 'TwoTier', 'ThreeTier', 'Unknown')]
    [string]$DeploymentTier = '',

    [ValidateRange(1, 60)]
    [int]$CpuSampleCount = 5,

    [ValidateRange(1, 30)]
    [int]$CpuSampleIntervalSeconds = 1,

    [string]$DatabaseHost = 'x.x.x.x',

    [ValidateRange(1, 65535)]
    [int]$DatabasePort = 1521,

    [string]$DatabaseServiceName = 'protect',

    [string]$DatabaseUser = 'protect',

    [ValidateRange(1, 3650)]
    [int]$IncidentLookbackDays = 30,

    [ValidateRange(1, 10)]
    [int]$IncidentTopCount = 10,

    [string]$CustomerName = '',

    [switch]$SkipSyslogConnectivityTest,

    [switch]$SkipDatabaseCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$SystemEventLookbackDays = 7
$MaximumSystemEvents = 100
$HeartbeatStaleSeconds = 180

function Convert-BytesToGB {
    param([double]$Bytes)
    [math]::Round(($Bytes / 1GB), 2)
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text -or $Text -eq '') { return '' }
    $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        'Critical' { '#dc2626' }
        'Warning'  { '#d97706' }
        'Normal'   { '#16a34a' }
        'Error'    { '#dc2626' }
        default    { '#6b7280' }
    }
}

function Get-BarRowsHtml {
    param(
        [object[]]$Items,
        [string]$LabelProperty,
        [string]$ValueProperty,
        [string]$BarColor = '#2563eb',
        [int]$MaxRows = 15
    )

    $rows = @($Items) | Sort-Object -Property $ValueProperty -Descending | Select-Object -First $MaxRows
    if (@($rows).Count -eq 0) {
        return '<p class="muted">No data.</p>'
    }
    $maxValue = ($rows | Measure-Object -Property $ValueProperty -Maximum).Maximum
    if (-not $maxValue -or $maxValue -le 0) { $maxValue = 1 }

    $sb = New-Object System.Text.StringBuilder
    foreach ($row in $rows) {
        $label = ConvertTo-HtmlSafe ([string]$row.$LabelProperty)
        $value = $row.$ValueProperty
        $pct = [math]::Round(($value / $maxValue) * 100, 1)
        [void]$sb.AppendLine("<div class='bar-row'><div class='bar-label' title='$label'>$label</div><div class='bar-track'><div class='bar-fill' style='width:$pct%;background:$BarColor'></div></div><div class='bar-value'>$value</div></div>")
    }
    return $sb.ToString()
}

function Get-GenericTableHtml {
    param(
        [object[]]$Items,
        [System.Collections.Specialized.OrderedDictionary]$Columns,
        [scriptblock]$RowColorSelector
    )

    $rows = @($Items)
    if ($rows.Count -eq 0) { return '<p class="muted">No data.</p>' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="report-table"><thead><tr>')
    foreach ($header in $Columns.Keys) { [void]$sb.Append("<th>$(ConvertTo-HtmlSafe $header)</th>") }
    [void]$sb.AppendLine('</tr></thead><tbody>')

    foreach ($item in $rows) {
        $style = ''
        if ($RowColorSelector) {
            $color = & $RowColorSelector $item
            if ($color) { $style = " style='border-left:4px solid $color'" }
        }
        [void]$sb.Append("<tr$style>")
        foreach ($propName in $Columns.Values) {
            [void]$sb.Append("<td>$(ConvertTo-HtmlSafe ([string]$item.$propName))</td>")
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function Get-FindingsTableHtml {
    param([object[]]$Findings)

    $rows = @($Findings)
    if ($rows.Count -eq 0) { return '<p class="muted">No findings.</p>' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<table class="report-table"><thead><tr><th>Status</th><th>Category</th><th>Metric</th><th>Value</th><th>Note</th></tr></thead><tbody>')
    foreach ($f in $rows) {
        $color = Get-StatusColor -Status $f.Status
        [void]$sb.AppendLine("<tr><td><span class='badge' style='background:$color'>$(ConvertTo-HtmlSafe $f.Status)</span></td><td>$(ConvertTo-HtmlSafe $f.Category)</td><td>$(ConvertTo-HtmlSafe $f.Metric)</td><td>$(ConvertTo-HtmlSafe $f.Value)</td><td>$(ConvertTo-HtmlSafe $f.Note)</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function Get-KpiCardHtml {
    param([string]$Label, [string]$Value, [string]$Color = '#111827')
    "<div class='kpi-card'><div class='kpi-value' style='color:$Color'>$(ConvertTo-HtmlSafe $Value)</div><div class='kpi-label'>$(ConvertTo-HtmlSafe $Label)</div></div>"
}


function New-DlpHtmlReport {
    param(
        [Parameter(Mandatory)] [object]$ReportData,
        [string]$CustomerName = ''
    )

    $reportData = $ReportData

$findings = @($reportData.Findings)
$normalCount = @($findings | Where-Object Status -eq 'Normal').Count
$warningCount = @($findings | Where-Object Status -eq 'Warning').Count
$criticalCount = @($findings | Where-Object Status -eq 'Critical').Count
$unknownCount = @($findings | Where-Object Status -eq 'Unknown').Count

$db = $reportData.Database
$hasDb = [bool]$reportData.DatabaseChecked -and $null -ne $db

$diskRowsHtml = New-Object System.Text.StringBuilder
foreach ($disk in @($reportData.Disks)) {
    $freePct = [double]$disk.FreePercent
    $color = if ($freePct -le 10) { '#dc2626' } elseif ($freePct -le 20) { '#d97706' } else { '#16a34a' }
    [void]$diskRowsHtml.AppendLine("<div class='bar-row'><div class='bar-label'>$(ConvertTo-HtmlSafe $disk.Drive) ($($disk.SizeGB) GB capacity)</div><div class='bar-track'><div class='bar-fill' style='width:$freePct%;background:$color'></div></div><div class='bar-value wide'>$($disk.FreeGB) GB / $freePct% free</div></div>")
}

$cpuVal = $reportData.Hardware.CpuAveragePct
$cpuColor = if ($null -eq $cpuVal) { '#6b7280' } elseif ($cpuVal -ge 85) { '#dc2626' } elseif ($cpuVal -ge 70) { '#d97706' } else { '#16a34a' }
$memVal = $reportData.Hardware.MemoryUsedPct
$memColor = if ($null -eq $memVal) { '#6b7280' } elseif ($memVal -ge 90) { '#dc2626' } elseif ($memVal -ge 80) { '#d97706' } else { '#16a34a' }

$tablespaceHtml = New-Object System.Text.StringBuilder
if ($hasDb) {
    foreach ($ts in @($db.Tablespaces)) {
        $usedPct = [double]$ts.UsedPct
        $color = if ($usedPct -gt 95) { '#dc2626' } elseif ($usedPct -ge 85) { '#d97706' } else { '#2563eb' }
        [void]$tablespaceHtml.AppendLine("<div class='bar-row'><div class='bar-label'>$(ConvertTo-HtmlSafe $ts.Tablespace) ($($ts.UsedMB)/$($ts.TotalMB) MB)</div><div class='bar-track'><div class='bar-fill' style='width:$usedPct%;background:$color'></div></div><div class='bar-value'>$usedPct% used</div></div>")
    }
}

$detectionServerItems = @()
$heartbeatMinutes = 5
if ($reportData.PSObject.Properties['HeartbeatStaleSeconds']) {
    $heartbeatMinutes = [math]::Round([double]$reportData.HeartbeatStaleSeconds / 60)
}
if ($hasDb) {
    $detectionServerItems = @(@($db.DetectionServers) | ForEach-Object {
        $shownVersion = if ([string]$_.Version -match '^\d+\.\d+\.\d+\.\d+$') { [string]$_.Version } else { 'N/A' }
        $shownState = if ($_.PSObject.Properties['Status']) { [string]$_.Status } else { 'Unknown' }
        $shownHeartbeat = if ($_.PSObject.Properties['LastHeartbeat'] -and [string]$_.LastHeartbeat -ne '-') { [string]$_.LastHeartbeat } else { '-' }
        $_ | Add-Member -NotePropertyName VersionDisplay -NotePropertyValue $shownVersion -Force
        $_ | Add-Member -NotePropertyName StatusDisplay -NotePropertyValue $shownState -Force
        $_ | Add-Member -NotePropertyName HeartbeatDisplay -NotePropertyValue $shownHeartbeat -Force -PassThru
    })
}

$systemEventsColumns = [ordered]@{
    'Type'       = 'Type'
    'Server'    = 'ServerName'
    'Host'      = 'HostName'
    'Code'       = 'EventCode'
    'Count'      = 'Count'
    'Last Time' = 'LastTime'
    'Message'     = 'Message'
}

$eventDays = 7
if ($reportData.PSObject.Properties['SystemEventLookbackDays']) { $eventDays = [int]$reportData.SystemEventLookbackDays }
$incidentDays = 30
if ($reportData.PSObject.Properties['IncidentLookbackDays']) { $incidentDays = [int]$reportData.IncidentLookbackDays }

$detectionServerCount = @($detectionServerItems | ForEach-Object { $_.MonitorId } | Sort-Object -Unique).Count

$monitorStates = @{}
foreach ($serverItem in $detectionServerItems) {
    $monitorKey = [string]$serverItem.MonitorId
    if (-not $monitorStates.ContainsKey($monitorKey)) { $monitorStates[$monitorKey] = [string]$serverItem.StatusDisplay }
    elseif ([string]$serverItem.StatusDisplay -ne 'Running') { $monitorStates[$monitorKey] = 'Unknown' }
}
$serverRunningCount = @($monitorStates.Values | Where-Object { $_ -eq 'Running' }).Count
$serverUnknownCount = $monitorStates.Count - $serverRunningCount

$eventCoverageHtml = ''
$eventTableHtml = ''
if ($hasDb) {
    $coverageItems = @()
    if ($db.PSObject.Properties['SystemEventServers']) { $coverageItems = @($db.SystemEventServers) }
    if ($coverageItems.Count -gt 0) {
        $coverageColumns = [ordered]@{
            'Server Queried' = 'ServerName'
            'Errors'              = 'Errors'
            'Warnings'             = 'Warnings'
        }
        $eventCoverageHtml = "<p class='muted' style='margin:0 0 8px 0'>Events were queried for $($coverageItems.Count) servers (the Enforce Server and the active detection servers). Servers without events are shown as 0.</p>" +
            (Get-GenericTableHtml -Items $coverageItems -Columns $coverageColumns -RowColorSelector { param($i) if ([int]$i.Errors -gt 0) { '#dc2626' } elseif ([int]$i.Warnings -gt 0) { '#d97706' } else { '#16a34a' } })
    }
    $eventItems = @(@($db.SystemEvents) | Where-Object { $null -ne $_ })
    if ($eventItems.Count -gt 0) {
        $eventTableHtml = "<div style='margin-top:14px'>" + (Get-GenericTableHtml -Items $eventItems -Columns $systemEventsColumns -RowColorSelector { param($i) Get-StatusColor -Status $i.Type }) + "</div>"
    }
    else {
        $eventTableHtml = "<p class='note-ok'>There were no error or warning events in the last $eventDays days.</p>"
    }
}

$detectionServerColumns = [ordered]@{
    'Status'         = 'StatusDisplay'
    'Server'        = 'ServerName'
    'Host'          = 'HostName'
    'Version'      = 'VersionDisplay'
    'Product'          = 'Product'
    'Channel'         = 'Channel'
    'Last Heartbeat' = 'HeartbeatDisplay'
}

$dlpServiceColumns = [ordered]@{
    'Service Name'     = 'DisplayName'
    'Status'          = 'State'
    'Start Mode' = 'StartMode'
}

$generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$tierSectionHtml = ''
if ($reportData.PSObject.Properties['TierAssessment'] -and $null -ne $reportData.TierAssessment) {
    $ta = $reportData.TierAssessment
    $tierLabel = if ($ta.EffectiveTier -eq 'TwoTier') { 'Two-tier (Enforce Server + Oracle on the same server)' } else { 'Three-tier (Enforce Server and Oracle on separate servers)' }
    $tierSource = if ($ta.DeclaredTier -eq 'TwoTier' -or $ta.DeclaredTier -eq 'ThreeTier') { 'Customer-declared' } else { 'Auto-detected' }
    $levelTr = @{ 'Below minimum' = 'Below minimum'; 'Minimum' = 'Minimum'; 'Small' = 'Small'; 'Medium' = 'Medium'; 'Large' = 'Large' }
    $metricTr = @{ 'CPU (logical)' = 'Logical CPU'; 'RAM (GB)' = 'RAM (GB)'; 'Total disk (GB)' = 'Total Disk (GB)' }

    $tierRows = @(@($ta.Rows) | ForEach-Object {
        [pscustomobject]@{
            Component = $metricTr[[string]$_.Metric]
            Current  = $_.Current
            Min     = $_.Min
            Small   = $_.Small
            Medium  = $_.Medium
            Large   = $_.Large
            LevelName = $levelTr[[string]$_.Level]
            LevelId = $_.LevelId
        }
    })
    $tierColumns = [ordered]@{
        'Component'            = 'Component'
        'Current'             = 'Current'
        'Minimum'            = 'Min'
        'Small'              = 'Small'
        'Medium'             = 'Medium'
        'Large'              = 'Large'
        'Level Met'  = 'LevelName'
    }
    $tierTable = Get-GenericTableHtml -Items $tierRows -Columns $tierColumns -RowColorSelector {
        param($i)
        if ([int]$i.LevelId -le 0) { '#dc2626' } elseif ([int]$i.LevelId -eq 1) { '#d97706' } else { '#16a34a' }
    }

    $tierWarnHtml = ''
    if ($ta.ConsistencyStatus -eq 'Warning') {
        $warnText = if ($ta.DeclaredTier -eq 'TwoTier') { 'Two-tier was selected but Oracle does not appear to run on this server. Please verify the deployment type.' } else { 'Three-tier was selected but Oracle appears to run on this server. Please verify the deployment type.' }
        $tierWarnHtml = "<p class='note-warn'>$(ConvertTo-HtmlSafe $warnText)</p>"
    }
    $twoTierNote = ''
    if ($ta.EffectiveTier -eq 'TwoTier') {
        $twoTierNote = ' Two-tier values are calculated as the sum of the Enforce and Oracle recommendations (Broadcom does not publish a separate two-tier table).'
    }

    $tierSectionHtml = "<section><h2>Deployment Type and Hardware Comparison</h2><div class='info-cards'>" +
        "<div class='info-card'><div class='k'>Deployment Type</div><div class='v'>$(ConvertTo-HtmlSafe $tierLabel)</div></div>" +
        "<div class='info-card'><div class='k'>Determined By</div><div class='v'>$(ConvertTo-HtmlSafe $tierSource)</div></div>" +
        "<div class='info-card'><div class='k'>Level Met</div><div class='v'>$(ConvertTo-HtmlSafe $levelTr[[string]$ta.LevelName])</div></div>" +
        "</div>$tierWarnHtml<div style='margin-top:14px'>$tierTable</div>" +
        "<p class='muted'>Source: Broadcom Symantec DLP 25.1 Hardware Requirements (Enforce Server and Oracle hardware recommendations). The required size depends on the daily incident volume, the number of detection servers and profile sizes.$twoTierNote</p></section>"
}

$licenseSectionHtml = ''
if ($reportData.PSObject.Properties['License'] -and $null -ne $reportData.License) {
    $lic = $reportData.License
    $licKeys = @()
    if ($lic.PSObject.Properties['LicenseKeys']) { $licKeys = @(@($lic.LicenseKeys) | Where-Object { $null -ne $_ }) }
    if ($licKeys.Count -gt 0) {
        $licStatusTr = @{ 'OK' = 'OK'; 'Expiring soon' = 'Expiring soon'; 'Expired' = 'Expired'; 'Not started' = 'Not started'; 'Unknown' = 'Unknown' }
        $licRows = @($licKeys | ForEach-Object {
            $licDays = $null
            if ($null -ne $_.DaysRemaining -and [string]$_.DaysRemaining -match '^-?\d+$') { $licDays = [int]$_.DaysRemaining }
            $licDaysText = '-'
            if ($null -ne $licDays) { $licDaysText = if ($licDays -lt 0) { "expired $([math]::Abs($licDays)) days ago" } else { "$licDays" } }
            $licStatusText = $licStatusTr[[string]$_.Status]
            if ([string]::IsNullOrEmpty($licStatusText)) { $licStatusText = [string]$_.Status }
            [pscustomobject]@{
                Product    = $_.Product
                Count      = $_.Count
                StatusText = $licStatusText
                Expiry     = $_.ExpiryDate
                DaysText   = $licDaysText
                RawStatus  = [string]$_.Status
            }
        })
        $licColumns = [ordered]@{
            'Product'         = 'Product'
            'Count'         = 'Count'
            'Status'        = 'StatusText'
            'Expiry Date' = 'Expiry'
            'Days Remaining'    = 'DaysText'
        }
        $licTable = Get-GenericTableHtml -Items $licRows -Columns $licColumns -RowColorSelector {
            param($i)
            switch ([string]$i.RawStatus) { 'OK' { '#16a34a' } 'Expiring soon' { '#d97706' } 'Expired' { '#dc2626' } default { '#6b7280' } }
        }
        $licOthers = @(); if ($lic.PSObject.Properties['OtherFiles']) { $licOthers = @(@($lic.OtherFiles) | Where-Object { $null -ne $_ }) }
        $licOthersHtml = ''
        if ($licOthers.Count -gt 0) {
            $licOtherNames = (@($licOthers | ForEach-Object { "$($_.Name) (signed: $($_.SignDate))" }) -join ', ')
            $licOthersHtml = "<p class='muted'>$($licOthers.Count) older license file(s) were also found in the license folder: $(ConvertTo-HtmlSafe $licOtherNames). The file with the newest signature date is used.</p>"
        }
        $licenseSectionHtml = "<h3 style='font-size:14px;margin:18px 0 8px 0;color:#374151'>License Status</h3>$licTable" +
            "<p class='muted'>License file: $(ConvertTo-HtmlSafe ([string]$lic.CurrentFile)) (signature date: $(ConvertTo-HtmlSafe ([string]$lic.CurrentSignDate))). The status is calculated from the expiry date and the warning period in the license file (default 60 days).</p>$licOthersHtml"
    }
    else {
        $licSearched = ''
        if ($lic.PSObject.Properties['SearchedDirectories']) { $licSearched = (@($lic.SearchedDirectories) -join '; ') }
        $licenseSectionHtml = "<h3 style='font-size:14px;margin:18px 0 8px 0;color:#374151'>License Status</h3><p class='muted'>The DLP license file (.slf) was not found or could not be read. Locations searched: $(ConvertTo-HtmlSafe $licSearched)</p>"
    }
}

$policySummaryHtml = ''
if ($hasDb) {
    if ($db.PSObject.Properties['PolicySummaryStatus'] -and $db.PolicySummaryStatus -eq 'Successful') {
        $lookbackDays = if ($reportData.PSObject.Properties['IncidentLookbackDays']) { [int]$reportData.IncidentLookbackDays } else { 30 }
        $unusedCount = [int]$db.UnusedPolicyCount
        $policyCards = (Get-KpiCardHtml -Label 'Total Policies' -Value ([string]$db.PolicyTotalCount)) +
            (Get-KpiCardHtml -Label 'Total Policy Groups' -Value ([string]$db.PolicyGroupCount)) +
            (Get-KpiCardHtml -Label "Policies with no incidents in the last $lookbackDays days" -Value ([string]$unusedCount) -Color $(if ($unusedCount -gt 0) { '#d97706' } else { '#16a34a' }))
        $policyNote = if ($unusedCount -gt 0) {
            "<p class='note-warn'>$unusedCount policies produced no incidents in the last $lookbackDays days. Reviewing these policies is recommended (they may be inactive, unnecessary or never triggered).</p>"
        } else {
            "<p class='note-ok'>All policies produced at least one incident in the last $lookbackDays days.</p>"
        }
        $unusedListHtml = ''
        $unusedItems = @()
        if ($db.PSObject.Properties['UnusedPolicies']) { $unusedItems = @($db.UnusedPolicies) }
        if ($unusedCount -gt 0 -and $unusedItems.Count -gt 0) {
            $unusedColumns = [ordered]@{
                'Policy Name'   = 'PolicyName'
                'Policy Group' = 'PolicyGroup'
            }
            $unusedListHtml = "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Policies with no incidents in the last $lookbackDays days</h3>" +
                (Get-GenericTableHtml -Items $unusedItems -Columns $unusedColumns -RowColorSelector { param($i) '#d97706' })
            if ($unusedCount -gt $unusedItems.Count) {
                $unusedListHtml += "<p class='muted'>The first $($unusedItems.Count) policies are listed (total: $unusedCount).</p>"
            }
        }
        $policySummaryHtml = "<section><h2>Policy Summary</h2><div class='kpi-row'>$policyCards</div>$policyNote$unusedListHtml</section>"
    }
    else {
        $policySummaryHtml = "<section><h2>Policy Summary</h2><p class='muted'>The policy summary could not be read.</p></section>"
    }
}

$patternSectionHtml = ''
if ($hasDb) {
    if ($db.PSObject.Properties['PatternSummaryStatus'] -and $db.PatternSummaryStatus -eq 'Successful') {
        $patternCards = (Get-KpiCardHtml -Label 'Patterns (visible in the console)' -Value ([string]$db.PatternActiveCount)) +
            (Get-KpiCardHtml -Label 'User / e-mail / domain entries' -Value ([string]$db.PatternUserEntries)) +
            (Get-KpiCardHtml -Label 'IP entries' -Value ([string]$db.PatternIpEntries)) +
            (Get-KpiCardHtml -Label 'URL domain entries' -Value ([string]$db.PatternUrlEntries))

        $patternColumns = [ordered]@{
            'Pattern Name'                       = 'PatternName'
            'Type'                               = 'PatternType'
            'User / E-mail / Domain'      = 'UserEntries'
            'IP'                                = 'IpEntries'
            'URL Domain'                        = 'UrlEntries'
            'Last Modified'                    = 'Modified'
        }
        $activeItems = @(); if ($db.PSObject.Properties['PatternsActive']) { $activeItems = @($db.PatternsActive) }

        $patternListsHtml = ''
        if ($activeItems.Count -gt 0) {
            $patternListsHtml += "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Active Patterns</h3>" + (Get-GenericTableHtml -Items $activeItems -Columns $patternColumns -RowColorSelector { param($i) '#16a34a' })
            if ([int]$db.PatternActiveCount -gt $activeItems.Count) { $patternListsHtml += "<p class='muted'>The first $($activeItems.Count) patterns are listed (total: $($db.PatternActiveCount)).</p>" }
        }
        $patternNote = "<p class='muted'>No separate history is kept for users removed from within a pattern; only the current content of the pattern is available. Entry counts are calculated from the comma-separated entries of the active patterns.</p>"
        $patternSectionHtml = "<section><h2>Sender/Recipient Pattern Summary</h2><div class='kpi-row'>$patternCards</div>$patternListsHtml$patternNote</section>"
    }
    else {
        $patternSectionHtml = "<section><h2>Sender/Recipient Pattern Summary</h2><p class='muted'>The pattern summary could not be read.</p></section>"
    }
}

$syslogRow = $null
if ($reportData.PSObject.Properties['Syslog'] -and $null -ne $reportData.Syslog) {
    $sl = $reportData.Syslog
    switch ([string]$sl.Status) {
        'Configured' {
            $slConnText = switch ([string]$sl.Connectivity) {
                'Reachable'       { 'Connection: Reachable (a TCP connection was established; message delivery is not verified)' }
                'Unreachable'     { 'Connection: Unreachable (could not connect within 3 seconds)' }
                'UdpUnverifiable' { 'Connection: cannot be verified for UDP' }
                default           { 'Connection: not tested' }
            }
            $syslogRow = [pscustomobject]@{
                Name   = 'Syslog (system events)'
                State  = 'Yes'
                Detail = "$($sl.Protocol)://$($sl.SyslogHost):$($sl.Port); level: $($sl.LevelText); $slConnText"
            }
        }
        'NotConfigured' {
            $syslogRow = [pscustomobject]@{ Name = 'Syslog (system events)'; State = 'No'; Detail = 'The systemevent.syslog setting is not enabled in Manager.properties' }
        }
        default {
            $syslogRow = [pscustomobject]@{ Name = 'Syslog (system events)'; State = 'Unknown'; Detail = 'Manager.properties was not found (the script may not have been run on the Enforce Server)' }
        }
    }
}
$syslogStandaloneHtml = ''
if ($null -ne $syslogRow) {
    $syslogStandaloneHtml = "<section><h2>Syslog</h2><p style='margin:0'><strong>$(ConvertTo-HtmlSafe $syslogRow.State)</strong> - $(ConvertTo-HtmlSafe $syslogRow.Detail)</p></section>"
}

$oraclePatchHtml = ''
$oracleRuCardsHtml = ''
if ($hasDb) {
    $dbHas = { param($name) $db.PSObject.Properties[$name] }
    if (& $dbHas 'OracleBinaryRu') {
        $registryRuText = if ([string]$db.OracleRegistryRu -eq 'N/A') { 'Could not be read' } else { [string]$db.OracleRegistryRu }
        $oracleRuCardsHtml = "<div class='info-card'><div class='k'>RU Level (binary / v`$version)</div><div class='v'>$(ConvertTo-HtmlSafe ([string]$db.OracleBinaryRu))</div></div>" +
            "<div class='info-card'><div class='k'>Last RU in Patch Registry (dba_registry)</div><div class='v'>$(ConvertTo-HtmlSafe $registryRuText)</div></div>"

        $patchRows = @()
        $patchSource = ''
        if ((& $dbHas 'OracleSqlPatches') -and @(@($db.OracleSqlPatches) | Where-Object { $null -ne $_ }).Count -gt 0) {
            $patchSource = 'dba_registry_sqlpatch'
            $patchRows = @(@($db.OracleSqlPatches) | Where-Object { $null -ne $_ } | ForEach-Object {
                [pscustomobject]@{ Time = $_.Time; Action = $_.Action; Status = $_.Status; Detail = "$($_.PatchId) - $($_.Description)" }
            })
        }
        elseif (& $dbHas 'OraclePatchHistory') {
            $patchSource = 'dba_registry_history'
            $patchRows = @(@($db.OraclePatchHistory) | Where-Object { $null -ne $_ } | ForEach-Object {
                [pscustomobject]@{ Time = $_.Time; Action = $_.Action; Status = $_.Version; Detail = $_.Comments }
            })
        }

        $patchTableHtml = ''
        if ($patchRows.Count -gt 0) {
            $patchColumns = [ordered]@{ 'Time' = 'Time'; 'Action' = 'Action'; 'Status / Version' = 'Status'; 'Description' = 'Detail' }
            $patchTableHtml = "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Oracle Patch History</h3>" + (Get-GenericTableHtml -Items $patchRows -Columns $patchColumns)
        }

        $ruWarnHtml = ''
        if ((& $dbHas 'OracleRuStatus') -and $db.OracleRuStatus -eq 'Mismatch') {
            $ruWarnHtml = "<p class='note-warn'>The Oracle binary RU level ($(ConvertTo-HtmlSafe ([string]$db.OracleBinaryRu))) differs from the last RU in the database patch registry ($(ConvertTo-HtmlSafe ([string]$db.OracleRegistryRu))). This may indicate that the patch was applied to the binaries but not completed on the database side (datapatch). Confirm the effective patch level with your DBA before evaluating the version/patch conditions in CVE advisories.</p>"
        }
        $sqlPatchNote = ''
        if ((& $dbHas 'OracleSqlPatchStatus') -and $db.OracleSqlPatchStatus -eq 'Unavailable') {
            $sqlPatchNote = ' The detailed patch list (dba_registry_sqlpatch) could not be read because the connecting user has no privilege on it; the patch record is shown from dba_registry_history instead.'
        }
        $oraclePatchHtml = "$ruWarnHtml$patchTableHtml<p class='muted'>The RU level is taken from Oracle's v`$version output (binary) and from the values in the patch registry table.$sqlPatchNote</p>"
    }
}

$consoleAccessHtml = ''
$integrationHtml = ''
if ($hasDb) {
    if ($db.PSObject.Properties['ConsoleAccessStatus'] -and $db.ConsoleAccessStatus -eq 'Successful') {
        $accessUsers = @(@($db.ConsoleUsers) | Where-Object { $null -ne $_ })
        $accessRoles = @(@($db.ConsoleRoles) | Where-Object { $null -ne $_ })
        $inactiveUsers = @($accessUsers | Where-Object { $null -eq $_.DaysSinceActive -or [int]$_.DaysSinceActive -gt 90 })
        $failedUsers = @($accessUsers | Where-Object { [int]$_.FailedAttempts -gt 0 })
        $disabledUsers = @($accessUsers | Where-Object { $_.PSObject.Properties['Status'] -and [string]$_.Status -eq 'Disabled' })

        $accessCards = (Get-KpiCardHtml -Label 'Console Users' -Value ([string]$accessUsers.Count)) +
            (Get-KpiCardHtml -Label 'Disabled users' -Value ([string]$disabledUsers.Count) -Color $(if ($disabledUsers.Count -gt 0) { '#d97706' } else { '#16a34a' })) +
            (Get-KpiCardHtml -Label 'Roles' -Value ([string]$accessRoles.Count)) +
            (Get-KpiCardHtml -Label 'Users inactive in the last 90 days' -Value ([string]$inactiveUsers.Count) -Color $(if ($inactiveUsers.Count -gt 0) { '#d97706' } else { '#16a34a' })) +
            (Get-KpiCardHtml -Label 'Users with failed login attempts' -Value ([string]$failedUsers.Count) -Color $(if ($failedUsers.Count -gt 0) { '#d97706' } else { '#16a34a' }))

        $userRows = @($accessUsers | ForEach-Object {
            [pscustomobject]@{
                DisplayName    = $(if ($_.IsApiUser) { "$($_.UserName) (API)" } else { $_.UserName })
                StatusText     = $(if ($_.PSObject.Properties['Status']) { [string]$_.Status } else { '-' })
                Email          = $_.Email
                Roles          = $_.Roles
                AuthMethods    = $_.AuthMethods
                LastActive     = $_.LastActive
                FailedAttempts = $_.FailedAttempts
                LastLockout    = $_.LastLockout
                IsInactive     = ($null -eq $_.DaysSinceActive -or [int]$_.DaysSinceActive -gt 90)
            }
        })
        $userColumns = [ordered]@{
            'User'         = 'DisplayName'
            'Status'             = 'StatusText'
            'E-mail'           = 'Email'
            'Roles'            = 'Roles'
            'Authentication'  = 'AuthMethods'
            'Last Active'         = 'LastActive'
            'Failed Attempts'  = 'FailedAttempts'
            'Last Lockout'    = 'LastLockout'
        }
        $userTable = Get-GenericTableHtml -Items $userRows -Columns $userColumns -RowColorSelector { param($i) if ($i.StatusText -eq 'Disabled') { '#dc2626' } elseif ($i.IsInactive) { '#d97706' } else { '#16a34a' } }

        $roleRows = @($accessRoles | ForEach-Object {
            [pscustomobject]@{
                RoleName  = $_.RoleName
                AdManaged = $(if ($_.AdManaged) { 'Yes' } else { 'No' })
                UserCount = $_.UserCount
            }
        })
        $roleColumns = [ordered]@{
            'Role'                     = 'RoleName'
            'AD-Managed'      = 'AdManaged'
            'User Count'        = 'UserCount'
        }
        $roleTable = Get-GenericTableHtml -Items $roleRows -Columns $roleColumns

        $consoleAccessHtml = "<section><h2>Console Users and Roles</h2><div class='kpi-row'>$accessCards</div>" +
            "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Users</h3>$userTable" +
            "<h3 style='font-size:14px;margin:16px 0 8px 0;color:#374151'>Roles</h3>$roleTable" +
            "<p class='muted'>Passwords and password hashes are never read. The internal system account (internal system user) and deleted users are excluded. Status: a user is shown as Disabled if the lockout date (Last Lockout) is set (disabled from the console or locked out) or if no authentication method is enabled; otherwise Enabled (Disabled rows are red). Users whose last active date is older than 90 days or missing are marked orange.</p></section>"
    }
    else {
        $consoleAccessHtml = "<section><h2>Console Users and Roles</h2><p class='muted'>Console user and role information could not be read.</p></section>"
    }

    if ($db.PSObject.Properties['IntegrationStatus'] -and $db.IntegrationStatus -eq 'Successful') {
        $adItems = @(@($db.AdConnections) | Where-Object { $null -ne $_ })
        $ocrItems = @(@($db.OcrConfigs) | Where-Object { $null -ne $_ })
        $adDetail = if ($adItems.Count -gt 0) {
            (@($adItems | ForEach-Object { "$($_.Name): $($_.Host):$($_.Port), SSL: $(if ($_.UseSsl) { 'Yes' } else { 'No' })" }) -join '; ')
        } else { '-' }
        $ocrDetail = if ($ocrItems.Count -gt 0) {
            (@($ocrItems | ForEach-Object { "$($_.Name): $($_.Host):$($_.Port); used by: $($_.Servers)" }) -join '; ')
        } else { '-' }

        $mipState = 'Unknown'; $mipDetail = 'MIP/AIP information could not be read (the related tables may not exist in this DLP version).'
        if ($db.PSObject.Properties['MipStatus']) {
            if ($db.MipStatus -eq 'Configured') { $mipState = 'Yes' }
            elseif ($db.MipStatus -eq 'NotConfigured') { $mipState = 'No' }
            if ($db.MipStatus -ne 'Unknown' -and $db.MipStatus -ne 'Not tested') {
                $mipDetail = "AIP tenant: $($db.MipTenantCount); ICT connection: $($db.MipIctCount); AIP labels: $($db.MipLabelCount)"
            }
        }

        $integrationRows = @(
            [pscustomobject]@{ Name = 'Active Directory (LDAP connection)'; State = $(if ($adItems.Count -gt 0) { 'Yes' } else { 'No' }); Detail = $adDetail },
            [pscustomobject]@{ Name = 'Console login with AD account'; State = $(if ($db.PSObject.Properties['AdLoginDomains'] -and -not [string]::IsNullOrWhiteSpace([string]$db.AdLoginDomains)) { 'Yes' } else { 'No' }); Detail = $(if ($db.PSObject.Properties['AdLoginDomains'] -and -not [string]::IsNullOrWhiteSpace([string]$db.AdLoginDomains)) { "Domains: $($db.AdLoginDomains)" } else { '-' }) },
            [pscustomobject]@{ Name = 'AD-managed roles'; State = $(if ([int]$db.AdManagedRoles -gt 0) { 'Yes' } else { 'No' }); Detail = "Roles: $($db.AdManagedRoles)" },
            [pscustomobject]@{ Name = 'OCR'; State = $(if ($ocrItems.Count -gt 0) { 'Yes' } else { 'No' }); Detail = $ocrDetail },
            [pscustomobject]@{ Name = 'MIP (Microsoft Information Protection / AIP)'; State = $mipState; Detail = $mipDetail }
        )
        if ($null -ne $syslogRow) { $integrationRows += $syslogRow }
        $integrationColumns = [ordered]@{
            'Integration' = 'Name'
            'Status'       = 'State'
            'Detail'       = 'Detail'
        }
        $integrationTable = Get-GenericTableHtml -Items $integrationRows -Columns $integrationColumns -RowColorSelector { param($i) if ($i.State -eq 'Yes') { '#16a34a' } else { '#9ca3af' } }

        $sslWarnHtml = ''
        $noSslItems = @($adItems | Where-Object { -not $_.UseSsl })
        if ($noSslItems.Count -gt 0) {
            $sslWarnHtml = "<p class='note-warn'>The AD connection does not use SSL ($(ConvertTo-HtmlSafe (@($noSslItems | ForEach-Object { $_.Name }) -join ', '))). Unencrypted LDAP traffic can expose credentials; using LDAPS is recommended.</p>"
        }
        $integrationHtml = "<section><h2>Integration Status</h2>$integrationTable$sslWarnHtml" +
            "<p class='muted'>The MIP status is determined from the Azure Information Protection and Information Centric Tagging configuration records in Enforce. The Syslog row shows the system-event setting in Manager.properties on the Enforce Server; 'Log to a Syslog Server' response rules are not checked in this row.</p></section>"
    }
    else {
        $integrationHtml = "<section><h2>Integration Status</h2><p class='muted'>Integration information could not be read.</p></section>"
    }
}

$totalIncidentSectionHtml = ''
if ($hasDb) {
    $incidentLimit = 1000000
    $totalIncidents = $null
    if ($db.IncidentTypeStatus -eq 'Successful') {
        $totalIncidents = [long](@($db.IncidentsByType) | Measure-Object -Property Count -Sum).Sum
    }
    elseif ($db.IncidentTypeStatus -eq 'No incidents') {
        $totalIncidents = 0
    }

    if ($null -eq $totalIncidents) {
        $totalIncidentSectionHtml = "<section><h2>Total Incident Count</h2><p class='muted'>The total incident count could not be read.</p></section>"
    }
    else {
        $tr = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
        $totalText = $totalIncidents.ToString('N0', $tr)
        if ($totalIncidents -gt $incidentLimit) {
            $noteClass = 'note-warn'
            $noteText = "Your incident count ($totalText) is higher than the recommended 1 million incidents. This may affect system performance."
            $totalColor = '#dc2626'
        }
        else {
            $noteClass = 'note-ok'
            $noteText = "Your incident count ($totalText) has not reached the recommended limit of 1 million incidents."
            $totalColor = '#16a34a'
        }
        $pendingText = 'Could not be read'
        if ($db.PSObject.Properties['PendingDeleteStatus'] -and $db.PendingDeleteStatus -eq 'Successful') {
            $pendingText = ([long]$db.PendingDeleteCount).ToString('N0', $tr)
        }
        $pendingCard = Get-KpiCardHtml -Label 'Incidents Pending Deletion (Marked)' -Value $pendingText -Color '#d97706'
        $totalIncidentSectionHtml = "<section><h2>Total Incident Count</h2><div class='kpi-row'>$(Get-KpiCardHtml -Label 'Total Incidents in the Database' -Value $totalText -Color $totalColor)$pendingCard</div><p class='$noteClass'>$(ConvertTo-HtmlSafe $noteText)</p><p class='muted'>The total does not include incidents that are pending deletion (marked for deletion).</p></section>"
    }
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DLP Health Check Report - $(ConvertTo-HtmlSafe $reportData.ComputerName)</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f3f4f6;
    color: #111827;
    margin: 0;
    padding: 24px;
  }
  .page { max-width: 1100px; margin: 0 auto; }
  .report-header {
    background: linear-gradient(135deg,#1e3a8a,#2563eb);
    color: #fff;
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 20px;
  }
  .report-header h1 { margin: 0 0 4px 0; font-size: 22px; }
  .report-header .sub { opacity: .9; font-size: 14px; }
  .editable-note {
    background: #fef9c3; border: 1px dashed #ca8a04; border-radius: 8px;
    padding: 10px 14px; font-size: 13px; margin-bottom: 20px; color: #713f12;
  }
  section { background: #fff; border-radius: 12px; padding: 20px 24px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  section h2 { font-size: 16px; margin: 0 0 14px 0; color: #1e3a8a; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }
  .kpi-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
  .kpi-card { flex: 1; min-width: 130px; background: #f9fafb; border-radius: 10px; padding: 14px; text-align: center; }
  .kpi-value { font-size: 24px; font-weight: 700; }
  .kpi-label { font-size: 12px; color: #6b7280; margin-top: 4px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  table.report-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.report-table th { text-align: left; background: #f3f4f6; padding: 8px 10px; font-size: 12px; color: #374151; }
  table.report-table td { padding: 7px 10px; border-bottom: 1px solid #f1f5f9; }
  table.report-table tr:hover { background: #f8fafc; }
  .badge { color: #fff; padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 13px; }
  .bar-label { flex: 0 0 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #374151; }
  .bar-track { flex: 1; background: #e5e7eb; border-radius: 6px; height: 14px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 6px; }
  .bar-value { flex: 0 0 90px; text-align: right; color: #374151; font-weight: 600; }
  .bar-value.wide { flex-basis: 190px; }
  .note-warn { margin: 12px 0 0 0; padding: 10px 14px; border-radius: 8px; font-size: 13px; background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }
  .note-ok { margin: 12px 0 0 0; padding: 10px 14px; border-radius: 8px; font-size: 13px; background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
  .muted { color: #9ca3af; font-size: 13px; }
  .agent-counts { margin-top: 14px; padding-top: 12px; border-top: 1px solid #e5e7eb; font-size: 14px; line-height: 1.8; color: #111827; font-weight: 600; }
  .info-cards { display: flex; flex-wrap: wrap; gap: 10px; }
  .info-card { background: #f9fafb; border-radius: 8px; padding: 10px 14px; min-width: 160px; }
  .info-card .k { font-size: 11px; color: #6b7280; }
  .info-card .v { font-size: 14px; font-weight: 600; color: #111827; }
  footer { text-align: center; color: #9ca3af; font-size: 12px; margin-top: 20px; }
  @media print {
    body { background: #fff; }
    section { box-shadow: none; border: 1px solid #e5e7eb; }
    .editable-note { display: none; }
  }
</style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <h1>DLP Health Check Report</h1>
    <div class="sub">Customer: $(ConvertTo-HtmlSafe $CustomerName) &nbsp;|&nbsp; Server: $(ConvertTo-HtmlSafe $reportData.ComputerName) &nbsp;|&nbsp; Collected at: $(ConvertTo-HtmlSafe $reportData.CollectedAt)</div>
  </div>

  <section>
    <h2>System Information</h2>
    <div class="info-cards">
      <div class="info-card"><div class="k">Manufacturer / Model</div><div class="v">$(ConvertTo-HtmlSafe $reportData.SystemInfo.Manufacturer) / $(ConvertTo-HtmlSafe $reportData.SystemInfo.Model)</div></div>
      <div class="info-card"><div class="k">Operating System</div><div class="v">$(ConvertTo-HtmlSafe $reportData.SystemInfo.OperatingSystem)</div></div>
      <div class="info-card"><div class="k">OS Version / Architecture</div><div class="v">$(ConvertTo-HtmlSafe $reportData.SystemInfo.OSVersion) / $(ConvertTo-HtmlSafe $reportData.SystemInfo.Architecture)</div></div>
      <div class="info-card"><div class="k">Last Reboot</div><div class="v">$(ConvertTo-HtmlSafe $reportData.SystemInfo.LastBoot)</div></div>
      <div class="info-card"><div class="k">Logical CPU / RAM</div><div class="v">$($reportData.Hardware.LogicalCpu) / $($reportData.Hardware.TotalMemoryGB) GB</div></div>
    </div>
  </section>

  <section>
    <h2>Disk Usage</h2>
    $($diskRowsHtml.ToString())
  </section>

  $tierSectionHtml

  <section>
    <h2>DLP Services</h2>
    $(Get-GenericTableHtml -Items @($reportData.DlpServices) -Columns $dlpServiceColumns -RowColorSelector { param($i) if ($i.StartMode -eq 'Auto' -and $i.State -ne 'Running') { '#dc2626' } elseif ($i.State -eq 'Running') { '#16a34a' } else { $null } })
  </section>

  <section>
    <h2>Overview</h2>
    <div class="kpi-row">
      $(Get-KpiCardHtml -Label 'Normal Findings' -Value $normalCount -Color '#16a34a')
      $(Get-KpiCardHtml -Label 'Warning Findings' -Value $warningCount -Color '#d97706')
      $(Get-KpiCardHtml -Label 'Critical Findings' -Value $criticalCount -Color '#dc2626')
      $(Get-KpiCardHtml -Label 'Unknown Findings' -Value $unknownCount -Color '#6b7280')
      $(Get-KpiCardHtml -Label 'Uptime (days)' -Value $reportData.SystemInfo.UptimeDays)
      $(Get-KpiCardHtml -Label 'Average CPU %' -Value $(if($null -ne $cpuVal){"$cpuVal%"}else{'N/A'}) -Color $cpuColor)
      $(Get-KpiCardHtml -Label 'Memory Usage %' -Value "$memVal%" -Color $memColor)
    </div>
  </section>

  <section>
    <h2>Health Findings</h2>
    $(Get-FindingsTableHtml -Findings $findings)
  </section>

$(
if ($hasDb) {
@"
  <section>
    <h2>Oracle Connection / DLP System Information</h2>
    <div class="info-cards">
      <div class="info-card"><div class="k">DB Login</div><div class="v">$(ConvertTo-HtmlSafe $db.DatabaseLogin)</div></div>
      <div class="info-card"><div class="k">Database / User</div><div class="v">$(ConvertTo-HtmlSafe $db.DatabaseName) / $(ConvertTo-HtmlSafe $db.ConnectedUser)</div></div>
      <div class="info-card"><div class="k">DLP Version</div><div class="v">$(ConvertTo-HtmlSafe $db.DlpVersion)</div></div>
      <div class="info-card"><div class="k">Schema Version</div><div class="v">$(ConvertTo-HtmlSafe $db.DlpSchemaVersion)</div></div>
      <div class="info-card"><div class="k">Installation Date</div><div class="v">$(ConvertTo-HtmlSafe $db.DlpInstalledAt)</div></div>
    </div>
    $licenseSectionHtml
  </section>

  <section>
    <h2>Agent Version Distribution</h2>
    $(Get-BarRowsHtml -Items @($db.AgentVersions) -LabelProperty 'Version' -ValueProperty 'Count' -BarColor '#2563eb')
    <div class="agent-counts">
      <div>Agent Install : $(ConvertTo-HtmlSafe ([string]$db.InstallAgentCount))</div>
      <div>Agent Reporting : $(ConvertTo-HtmlSafe ([string]$db.ReportingAgentCount))</div>
      <div>Agent Disable : $(ConvertTo-HtmlSafe ([string]$db.DisableAgentCount))</div>
      <div>Agent NotReporting : $(ConvertTo-HtmlSafe ([string]$db.NotReportingAgentCount))</div>
      <div>Agent Deleted : $(ConvertTo-HtmlSafe ([string]$db.DeletedAgentCount))</div>
    </div>
  </section>

  <section>
    <h2>Detection Servers and Channels</h2>
    $(Get-GenericTableHtml -Items $detectionServerItems -Columns $detectionServerColumns -RowColorSelector { param($i) if ($i.StatusDisplay -eq 'Running') { '#16a34a' } else { '#d97706' } })
    <p style="margin:12px 0 4px 0;font-size:14px"><strong>Total Detection Servers: $detectionServerCount</strong> <span class="muted">(A server can run more than one channel, so the table has one row per channel.)</span></p>
    <p style="margin:6px 0"><span class="badge" style="background:#16a34a">Running: $serverRunningCount</span> <span class="badge" style="background:#d97706">Unknown: $serverUnknownCount</span> <span class="muted">Servers that stop sending heartbeats are counted as Unknown, as in the Enforce console; a Stopped state cannot be detected separately from heartbeats.</span></p>
    <p class="muted">The status is calculated from the last heartbeat the server reported to Enforce: Running if a heartbeat arrived within the last $heartbeatMinutes minutes, Unknown if heartbeats stopped or no record exists (the Enforce console also shows Unknown in this case). A lost heartbeat does not distinguish between a stopped server and an unreachable one.</p>
  </section>

  <section>
    <h2>Detection Server Error and Warning Events (Last $eventDays Days)</h2>
    $eventCoverageHtml
    $eventTableHtml
    <p class="muted">The same event code is grouped into one row per server; "Count" shows the number of occurrences in this period and "Last Time" the most recent occurrence.</p>
  </section>

  <section>
    <h2>Oracle Database Information</h2>
    <div class="info-cards">
      <div class="info-card"><div class="k">Oracle Version</div><div class="v">$(ConvertTo-HtmlSafe $db.OracleVersion)</div></div>
      <div class="info-card"><div class="k">Server Name</div><div class="v">$(ConvertTo-HtmlSafe $db.OracleHostName)</div></div>
      <div class="info-card"><div class="k">Instance</div><div class="v">$(ConvertTo-HtmlSafe $db.OracleInstanceName)</div></div>
      <div class="info-card"><div class="k">Instance Start Time</div><div class="v">$(ConvertTo-HtmlSafe $db.OracleInstanceStartTime)</div></div>
      $oracleRuCardsHtml
    </div>
    $oraclePatchHtml
  </section>

  <section>
    <h2>Oracle Tablespace Usage</h2>
    $($tablespaceHtml.ToString())
  </section>

  $totalIncidentSectionHtml

  <div class="grid-2">
    <section>
      <h2>Incident Type Distribution</h2>
      $(Get-BarRowsHtml -Items @($db.IncidentsByType) -LabelProperty 'Type' -ValueProperty 'Count' -BarColor '#7c3aed')
    </section>
    <section>
      <h2>Incidents by Detection Server</h2>
      $(Get-BarRowsHtml -Items @($db.IncidentsByServer) -LabelProperty 'ServerName' -ValueProperty 'Count' -BarColor '#0891b2')
    </section>
  </div>

  $policySummaryHtml

  <section>
    <h2>Most Violated Policies (Last $incidentDays Days)</h2>
    $(Get-BarRowsHtml -Items @($db.TopPolicies) -LabelProperty 'PolicyName' -ValueProperty 'Count' -BarColor '#db2777' -MaxRows 10)
  </section>

  <div class="grid-2">
    <section>
      <h2>Network - Top Incident-Generating Senders (Last $incidentDays Days)</h2>
      $(Get-BarRowsHtml -Items @($db.TopNetworkSenders) -LabelProperty 'Sender' -ValueProperty 'Count' -BarColor '#ea580c' -MaxRows 10)
    </section>
    <section>
      <h2>Endpoint - Top Incident-Generating Users (Last $incidentDays Days)</h2>
      $(Get-BarRowsHtml -Items @($db.TopEndpointUsers) -LabelProperty 'UserName' -ValueProperty 'Count' -BarColor '#16a34a' -MaxRows 10)
    </section>
  </div>

  $patternSectionHtml

  $consoleAccessHtml

  $integrationHtml
"@
}
else {
  "<section><h2>Oracle / Database</h2><p class='muted'>The database check was skipped in this run (-SkipDatabaseCheck).$(if ($licenseSectionHtml) { '</p>' + $licenseSectionHtml } else { '</p>' })</section>$syslogStandaloneHtml"
}
)

  <footer>Report generated on $generatedAt by the DLP Health Check script. This report contains data collected in read-only mode; no change was made to the system.<br><strong>FIRAT AYDIN</strong></footer>
</div>
</body>
</html>
"@

    return $html
}

function Get-Status {
    param(
        [double]$Value,
        [double]$WarningThreshold,
        [double]$CriticalThreshold,
        [ValidateSet('HigherIsWorse', 'LowerIsWorse')]
        [string]$Direction = 'HigherIsWorse'
    )

    if ($Direction -eq 'HigherIsWorse') {
        if ($Value -ge $CriticalThreshold) { return 'Critical' }
        if ($Value -ge $WarningThreshold)  { return 'Warning' }
    }
    else {
        if ($Value -le $CriticalThreshold) { return 'Critical' }
        if ($Value -le $WarningThreshold)  { return 'Warning' }
    }

    return 'Normal'
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Category,
        [string]$Metric,
        [string]$Value,
        [ValidateSet('Normal', 'Warning', 'Critical', 'Unknown')]
        [string]$Status,
        [string]$Note
    )

    $List.Add([pscustomobject]@{
        Category = $Category
        Metric   = $Metric
        Value    = $Value
        Status   = $Status
        Note     = $Note
    })
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ("=== {0} ===" -f $Title) -ForegroundColor Cyan
}

function Write-StatusTable {
    param([object[]]$Rows)

    foreach ($row in $Rows) {
        $color = switch ($row.Status) {
            'Critical' { 'Red' }
            'Warning'  { 'Yellow' }
            'Normal'   { 'Green' }
            default    { 'DarkYellow' }
        }

        $line = '[{0,-8}] {1,-18} {2,-28} {3,-16} {4}' -f `
            $row.Status.ToUpperInvariant(), $row.Category, $row.Metric, $row.Value, $row.Note
        Write-Host $line -ForegroundColor $color
    }
}

function Get-DlpServices {
    $allServices = Get-CimInstance -ClassName Win32_Service
    @($allServices |
        Where-Object {
            $_.Name -match 'Vontu|SymantecDLP|DataLossPrevention' -or
            $_.DisplayName -match 'Vontu|Symantec.*Data Loss Prevention|DLP' -or
            $_.PathName -match 'Vontu|DataLossPrevention'
        } |
        Sort-Object DisplayName |
        Select-Object Name, DisplayName, State, StartMode, PathName)
}

function Get-DlpSystemEventMessage {
    param(
        [int]$EventCode,
        [string]$SummaryKey
    )

    switch ($EventCode) {
        2202 { return 'License expired' }
        2300 { return 'Disk space low' }
        2317 { return 'Failed to send incident email notification' }
        2905 { return 'Exact data profile creation failed' }
        3008 { return 'Replication failed' }
        default {
            if ([string]::IsNullOrWhiteSpace($SummaryKey)) {
                return 'No message was returned.'
            }
            return $SummaryKey
        }
    }
}

function Get-DlpLicenseInfo {
    param([string[]]$LicenseDirectories)

    $info = [ordered]@{
        Status              = 'NotFound'
        SearchedDirectories = @()
        CurrentFile         = ''
        CurrentDirectory    = ''
        CurrentSignDate     = ''
        LicenseKeys         = @()
        OtherFiles          = @()
        Error               = $null
    }

    $searched = [System.Collections.Generic.List[string]]::new()
    $directories = [System.Collections.Generic.List[string]]::new()

    if ($LicenseDirectories) {
        foreach ($directory in $LicenseDirectories) {
            [void]$searched.Add($directory)
            if (Test-Path -LiteralPath $directory) { [void]$directories.Add($directory) }
        }
    }
    else {
        $driveLetters = [System.Collections.Generic.List[string]]::new()
        try {
            foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) { [void]$driveLetters.Add([string]$disk.DeviceID) }
        }
        catch { }
        foreach ($fallbackDrive in @('C:', 'D:')) {
            if ($driveLetters -notcontains $fallbackDrive) { [void]$driveLetters.Add($fallbackDrive) }
        }
        foreach ($drive in $driveLetters) {
            $baseDirectory = "$drive\ProgramData\Symantec\DataLossPrevention\EnforceServer"
            [void]$searched.Add("$baseDirectory\<version>\license")
            if (Test-Path -LiteralPath $baseDirectory) {
                foreach ($versionDirectory in @(Get-ChildItem -LiteralPath $baseDirectory -Directory -ErrorAction SilentlyContinue)) {
                    $licenseDirectory = Join-Path $versionDirectory.FullName 'license'
                    if (Test-Path -LiteralPath $licenseDirectory) { [void]$directories.Add($licenseDirectory) }
                }
            }
        }
    }
    $info.SearchedDirectories = @($searched)

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $today = (Get-Date).Date
    $parsedFiles = [System.Collections.Generic.List[object]]::new()

    foreach ($directory in $directories) {
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -Filter '*.slf' -File -ErrorAction SilentlyContinue)) {
            try {
                $xml = New-Object System.Xml.XmlDocument
                $xml.XmlResolver = $null
                $xml.Load($file.FullName)

                $signNode = $xml.SelectSingleNode("//*[local-name()='license']/*[local-name()='sign_date']")
                $signDate = $null
                if ($null -ne $signNode) {
                    $parsedSign = [datetime]::MinValue
                    if ([datetime]::TryParseExact($signNode.InnerText.Trim(), 'yyyy-MM-dd', $invariant, [System.Globalization.DateTimeStyles]::None, [ref]$parsedSign)) { $signDate = $parsedSign }
                }

                $keys = [System.Collections.Generic.List[object]]::new()
                foreach ($keyNode in @($xml.SelectNodes("//*[local-name()='key']"))) {
                    $nameNode = $keyNode.SelectSingleNode("*[local-name()='name']")
                    $countNode = $keyNode.SelectSingleNode("*[local-name()='count']")
                    $startNode = $keyNode.SelectSingleNode("*[local-name()='start_date']")
                    $endNode = $keyNode.SelectSingleNode("*[local-name()='end_date']")
                    $warnNode = $keyNode.SelectSingleNode("*[local-name()='warn_policy']")
                    if ($null -eq $nameNode -or $null -eq $endNode) { continue }

                    $rawName = $nameNode.InnerText.Trim()
                    $productName = switch -Regex ($rawName) {
                        '^DLP Mail Prevent$' { 'Network Prevent for Email'; break }
                        '^DLP Web Prevent$'  { 'Network Prevent for Web'; break }
                        '^DLP (.+)$'         { $Matches[1]; break }
                        default              { $rawName }
                    }

                    $endDate = [datetime]::MinValue
                    $endOk = [datetime]::TryParseExact($endNode.InnerText.Trim(), 'yyyy-MM-dd', $invariant, [System.Globalization.DateTimeStyles]::None, [ref]$endDate)
                    $startDate = [datetime]::MinValue
                    $startOk = $false
                    if ($null -ne $startNode) { $startOk = [datetime]::TryParseExact($startNode.InnerText.Trim(), 'yyyy-MM-dd', $invariant, [System.Globalization.DateTimeStyles]::None, [ref]$startDate) }

                    $warnDays = 60
                    if ($null -ne $warnNode) {
                        $warnParts = $warnNode.InnerText.Trim() -split ','
                        if ($warnParts.Count -ge 2 -and $warnParts[1].Trim() -match '^\d+$') { $warnDays = [int]$warnParts[1].Trim() }
                    }

                    $daysRemaining = $null
                    $status = 'Unknown'
                    if ($endOk) {
                        $daysRemaining = [int]($endDate - $today).TotalDays
                        if ($startOk -and $startDate -gt $today) { $status = 'Not started' }
                        elseif ($daysRemaining -lt 0) { $status = 'Expired' }
                        elseif ($daysRemaining -le $warnDays) { $status = 'Expiring soon' }
                        else { $status = 'OK' }
                    }

                    $countValue = ''
                    if ($null -ne $countNode) { $countValue = $countNode.InnerText.Trim() }

                    [void]$keys.Add([pscustomobject]@{
                        Product       = $productName
                        RawName       = $rawName
                        Count         = $countValue
                        StartDate     = $(if ($startOk) { $startDate.ToString('yyyy-MM-dd') } else { '-' })
                        ExpiryDate    = $(if ($endOk) { $endDate.ToString('yyyy-MM-dd') } else { '-' })
                        DaysRemaining = $daysRemaining
                        Status        = $status
                    })
                }

                [void]$parsedFiles.Add([pscustomobject]@{
                    Name          = $file.Name
                    Directory     = $directory
                    SignDate      = $signDate
                    LastWriteTime = $file.LastWriteTime
                    Keys          = @($keys)
                })
            }
            catch {
                $info.Error = "License file could not be parsed ($($file.Name)): $($_.Exception.Message)"
            }
        }
    }

    if ($parsedFiles.Count -eq 0) {
        return [pscustomobject]$info
    }

    $orderedFiles = @($parsedFiles | Sort-Object -Property @{ Expression = { if ($null -ne $_.SignDate) { $_.SignDate } else { [datetime]::MinValue } }; Descending = $true }, @{ Expression = { $_.LastWriteTime }; Descending = $true })
    $current = $orderedFiles[0]

    $productOrder = @('Network Monitor', 'Network Discover', 'Network Protect', 'Network Prevent for Email', 'Network Prevent for Web', 'Endpoint Prevent', 'Endpoint Discover', 'Data Insight', 'Sensitive Image Recognition')
    $sortedKeys = @($current.Keys | Sort-Object -Property @{ Expression = { $index = [array]::IndexOf($productOrder, $_.Product); if ($index -lt 0) { 99 } else { $index } } }, Product)

    $info.LicenseKeys = $sortedKeys
    $info.CurrentFile = $current.Name
    $info.CurrentDirectory = $current.Directory
    $info.CurrentSignDate = $(if ($null -ne $current.SignDate) { $current.SignDate.ToString('yyyy-MM-dd') } else { '-' })
    $info.OtherFiles = @($orderedFiles | Select-Object -Skip 1 | ForEach-Object {
        [pscustomobject]@{
            Name     = $_.Name
            SignDate = $(if ($null -ne $_.SignDate) { $_.SignDate.ToString('yyyy-MM-dd') } else { '-' })
            Modified = $_.LastWriteTime.ToString('yyyy-MM-dd')
        }
    })

    $info.Status = if ($sortedKeys.Count -eq 0) { 'NoKeys' }
        elseif (@($sortedKeys | Where-Object { $_.Status -eq 'Expired' }).Count -gt 0) { 'Expired' }
        elseif (@($sortedKeys | Where-Object { $_.Status -eq 'Expiring soon' }).Count -gt 0) { 'Expiring soon' }
        else { 'OK' }

    [pscustomobject]$info
}

function Get-DlpSyslogInfo {
    param(
        [string[]]$ManagerPropertiesPaths,
        [switch]$SkipConnectivityTest
    )

    $info = [ordered]@{
        Status       = 'FileNotFound'
        File         = ''
        Protocol     = ''
        SyslogHost   = ''
        Port         = ''
        Level        = ''
        LevelText    = ''
        Format       = ''
        Connectivity = 'NotTested'
        OtherFiles   = @()
        Error        = $null
    }

    $candidates = [System.Collections.Generic.List[object]]::new()
    if ($ManagerPropertiesPaths) {
        foreach ($path in $ManagerPropertiesPaths) {
            if (Test-Path -LiteralPath $path) { [void]$candidates.Add((Get-Item -LiteralPath $path)) }
        }
    }
    else {
        $driveLetters = [System.Collections.Generic.List[string]]::new()
        try {
            foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) { [void]$driveLetters.Add([string]$disk.DeviceID) }
        }
        catch { }
        foreach ($fallbackDrive in @('C:', 'D:')) {
            if ($driveLetters -notcontains $fallbackDrive) { [void]$driveLetters.Add($fallbackDrive) }
        }
        foreach ($drive in $driveLetters) {
            foreach ($baseDirectory in @("$drive\Program Files\Symantec\DataLossPrevention\EnforceServer", "$drive\ProgramData\Symantec\DataLossPrevention\EnforceServer", "$drive\SymantecDLP")) {
                if (Test-Path -LiteralPath $baseDirectory) {
                    foreach ($file in @(Get-ChildItem -LiteralPath $baseDirectory -Filter 'Manager.properties' -File -Recurse -Depth 5 -ErrorAction SilentlyContinue)) {
                        [void]$candidates.Add($file)
                    }
                }
            }
        }
    }

    if ($candidates.Count -eq 0) { return [pscustomobject]$info }

    $ordered = @($candidates | Sort-Object -Property LastWriteTime -Descending)
    $current = $ordered[0]
    $info.File = $current.FullName
    $info.OtherFiles = @($ordered | Select-Object -Skip 1 | ForEach-Object { $_.FullName })

    $values = @{}
    try {
        foreach ($line in @(Get-Content -LiteralPath $current.FullName -ErrorAction Stop)) {
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith('#') -or $trimmed.StartsWith('!') -or $trimmed -eq '') { continue }
            $separator = $trimmed.IndexOf('=')
            if ($separator -lt 1) { continue }
            $key = $trimmed.Substring(0, $separator).Trim()
            if ($key -like 'systemevent.syslog.*') { $values[$key] = $trimmed.Substring($separator + 1).Trim() }
        }
    }
    catch {
        $info.Error = "Manager.properties could not be read: $($_.Exception.Message)"
        return [pscustomobject]$info
    }

    $syslogHost = if ($values.ContainsKey('systemevent.syslog.host')) { [string]$values['systemevent.syslog.host'] } else { '' }
    if ([string]::IsNullOrWhiteSpace($syslogHost)) {
        $info.Status = 'NotConfigured'
        return [pscustomobject]$info
    }

    $protocol = if ($values.ContainsKey('systemevent.syslog.protocol') -and $values['systemevent.syslog.protocol']) { ([string]$values['systemevent.syslog.protocol']).ToLowerInvariant() } else { 'udp' }
    $port = if ($values.ContainsKey('systemevent.syslog.port') -and $values['systemevent.syslog.port'] -match '^\d+$') { [int]$values['systemevent.syslog.port'] } else { 514 }
    $level = if ($values.ContainsKey('systemevent.syslog.level') -and $values['systemevent.syslog.level'] -match '^\d+$') { [int]$values['systemevent.syslog.level'] } else { 3 }
    $levelText = switch ($level) {
        3 { 'SEVERE' }
        4 { 'SEVERE + WARNING' }
        5 { 'INFO + WARNING + SEVERE' }
        default { "Level $level" }
    }

    $info.Status = 'Configured'
    $info.Protocol = $protocol
    $info.SyslogHost = $syslogHost
    $info.Port = [string]$port
    $info.Level = [string]$level
    $info.LevelText = $levelText
    $info.Format = $(if ($values.ContainsKey('systemevent.syslog.format')) { [string]$values['systemevent.syslog.format'] } else { '' })

    if ($SkipConnectivityTest) {
        $info.Connectivity = 'NotTested'
    }
    elseif ($protocol -eq 'udp') {
        $info.Connectivity = 'UdpUnverifiable'
    }
    else {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $asyncResult = $client.BeginConnect($syslogHost, $port, $null, $null)
            $connected = $asyncResult.AsyncWaitHandle.WaitOne(3000, $false)
            if ($connected -and $client.Connected) {
                $client.EndConnect($asyncResult)
                $info.Connectivity = 'Reachable'
            }
            else {
                $info.Connectivity = 'Unreachable'
            }
        }
        catch {
            $info.Connectivity = 'Unreachable'
        }
        finally {
            $client.Close()
        }
    }

    [pscustomobject]$info
}

function Test-DlpDatabaseHostIsLocal {
    param(
        [string]$DatabaseHost,
        [string]$OracleHostName
    )

    $localNames = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @('localhost', '127.0.0.1', '::1', $env:COMPUTERNAME)) { [void]$localNames.Add($name) }
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($unicast in $nic.GetIPProperties().UnicastAddresses) {
                [void]$localNames.Add($unicast.Address.IPAddressToString)
            }
        }
    }
    catch { }

    if (-not [string]::IsNullOrWhiteSpace($DatabaseHost)) {
        $hostValue = $DatabaseHost.Trim()
        foreach ($name in $localNames) {
            if ($name -ieq $hostValue) { return $true }
        }
        if ($hostValue.Split('.')[0] -ieq $env:COMPUTERNAME) { return $true }
    }
    if (-not [string]::IsNullOrWhiteSpace($OracleHostName) -and $OracleHostName -ne 'N/A') {
        if ($OracleHostName.Trim().Split('.')[0] -ieq $env:COMPUTERNAME) { return $true }
    }
    return $false
}

function Get-DlpTierAssessment {
    param(
        [string]$DeclaredTier,
        [int]$LogicalCpu,
        [double]$RamGB,
        [double]$DiskTotalGB,
        [bool]$DatabaseChecked,
        [string]$DatabaseHost,
        [string]$OracleHostName
    )

    $localOracleService = $false
    try {
        $localOracleService = @(Get-CimInstance -ClassName Win32_Service |
            Where-Object { $_.Name -like 'OracleService*' }).Count -gt 0
    }
    catch { }

    $databaseIsLocal = $false
    if ($DatabaseChecked) {
        $databaseIsLocal = Test-DlpDatabaseHostIsLocal -DatabaseHost $DatabaseHost -OracleHostName $OracleHostName
    }
    $observedTwoTier = $localOracleService -or $databaseIsLocal
    $observedText = if ($observedTwoTier) {
        'Oracle appears to run on this server (local Oracle service or database host resolves to this server).'
    } else {
        'Oracle does not appear to run on this server.'
    }

    $effectiveTier = $DeclaredTier
    $consistencyStatus = 'Normal'
    switch ($DeclaredTier) {
        'TwoTier' {
            if ($observedTwoTier) {
                $consistencyNote = "Declared two-tier matches the observation. $observedText"
            }
            else {
                $consistencyStatus = 'Warning'
                $consistencyNote = "Two-tier was declared but the observation differs. $observedText Verify the deployment type."
            }
        }
        'ThreeTier' {
            if ($observedTwoTier) {
                $consistencyStatus = 'Warning'
                $consistencyNote = "Three-tier was declared but the observation differs. $observedText Verify the deployment type."
            }
            else {
                $consistencyNote = "Declared three-tier matches the observation. $observedText"
            }
        }
        default {
            $effectiveTier = if ($observedTwoTier) { 'TwoTier' } else { 'ThreeTier' }
            $consistencyStatus = 'Unknown'
            $consistencyNote = "Deployment type was not provided; it was detected automatically as $effectiveTier. $observedText"
        }
    }

    $enforce = [ordered]@{
        Min    = @(4, 8, 500)
        Small  = @(8, 32, 500)
        Medium = @(12, 64, 500)
        Large  = @(16, 128, 1024)
    }
    $oracle = [ordered]@{
        Small  = @(2, 8, 500)
        Medium = @(4, 32, 500)
        Large  = @(6, 32, 2048)
    }

    if ($effectiveTier -eq 'TwoTier') {
        $tierProfile = [ordered]@{
            Min    = @(($enforce.Min[0] + $oracle.Small[0]), ($enforce.Min[1] + $oracle.Small[1]), ($enforce.Min[2] + $oracle.Small[2]))
            Small  = @(($enforce.Small[0] + $oracle.Small[0]), ($enforce.Small[1] + $oracle.Small[1]), ($enforce.Small[2] + $oracle.Small[2]))
            Medium = @(($enforce.Medium[0] + $oracle.Medium[0]), ($enforce.Medium[1] + $oracle.Medium[1]), ($enforce.Medium[2] + $oracle.Medium[2]))
            Large  = @(($enforce.Large[0] + $oracle.Large[0]), ($enforce.Large[1] + $oracle.Large[1]), ($enforce.Large[2] + $oracle.Large[2]))
        }
    }
    else {
        $tierProfile = $enforce
    }

    $levelNames = @('Below minimum', 'Minimum', 'Small', 'Medium', 'Large')
    $metrics = @(
        [pscustomobject]@{ Name = 'CPU (logical)';     Index = 0; Current = $LogicalCpu;  Factor = 1.0 },
        [pscustomobject]@{ Name = 'RAM (GB)';          Index = 1; Current = $RamGB;       Factor = 0.95 },
        [pscustomobject]@{ Name = 'Total disk (GB)';   Index = 2; Current = $DiskTotalGB; Factor = 0.9 }
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $overallLevel = 4
    foreach ($metric in $metrics) {
        $requirements = @($tierProfile.Min[$metric.Index], $tierProfile.Small[$metric.Index], $tierProfile.Medium[$metric.Index], $tierProfile.Large[$metric.Index])
        $level = 0
        for ($i = 0; $i -lt 4; $i++) {
            if ($metric.Current -ge ($requirements[$i] * $metric.Factor)) { $level = $i + 1 }
        }
        if ($level -lt $overallLevel) { $overallLevel = $level }
        [void]$rows.Add([pscustomobject]@{
            Metric  = $metric.Name
            Current = [math]::Round($metric.Current, 1)
            Min     = $requirements[0]
            Small   = $requirements[1]
            Medium  = $requirements[2]
            Large   = $requirements[3]
            Level   = $levelNames[$level]
            LevelId = $level
        })
    }

    $scope = if ($effectiveTier -eq 'TwoTier') { 'two-tier (Enforce + Oracle on the same server)' } else { 'three-tier Enforce Server' }
    $weakest = @($rows | Where-Object { $_.LevelId -eq $overallLevel } | ForEach-Object { $_.Metric }) -join ', '
    $hardwareStatus = 'Normal'
    if ($overallLevel -eq 0) { $hardwareStatus = 'Critical' }
    elseif ($overallLevel -eq 1) { $hardwareStatus = 'Warning' }

    $hardwareNote = switch ($overallLevel) {
        0 { "Below the Broadcom 25.1 minimum for a $scope. Limiting metric: $weakest." }
        1 { "Meets only the minimum for a $scope; below the 'Small' recommendation. Limiting metric: $weakest." }
        default { "Meets the Broadcom 25.1 '$($levelNames[$overallLevel])' recommendation for a $scope. The required size depends on daily incident volume, detection server count and profile sizes." }
    }
    if ($effectiveTier -eq 'TwoTier') {
        $hardwareNote += ' Two-tier values are calculated as Enforce + Oracle recommendations (Broadcom does not publish a separate two-tier table).'
    }

    [pscustomobject]@{
        DeclaredTier      = $DeclaredTier
        EffectiveTier     = $effectiveTier
        ConsistencyStatus = $consistencyStatus
        ConsistencyNote   = $consistencyNote
        HardwareStatus    = $hardwareStatus
        HardwareNote      = $hardwareNote
        LevelName         = $levelNames[$overallLevel]
        Rows              = @($rows)
    }
}

function Invoke-DlpDatabaseCheck {
    param(
        [string]$HostName,
        [int]$Port,
        [string]$ServiceName,
        [string]$UserName
    )

    $result = [ordered]@{
        SqlPlusVersion   = 'N/A'
        TcpAccess        = 'Not tested'
        DatabaseLogin    = 'Not tested'
        DatabaseName     = 'N/A'
        ConnectedUser    = 'N/A'
        DlpInfoStatus    = 'Not tested'
        DlpVersion       = 'N/A'
        DlpSchemaVersion = 'N/A'
        DlpInstalledAt   = 'N/A'
        InstallAgentCount = 'N/A'
        ReportingAgentCount = 'N/A'
        DisableAgentCount = 'N/A'
        NotReportingAgentCount = 'N/A'
        DeletedAgentCount = 'N/A'
        AgentVersionStatus = 'Not tested'
        AgentVersions      = @()
        AgentVersionError  = $null
        DetectionServers = @()
        SystemEventStatus = 'Not tested'
        SystemEvents      = @()
        SystemEventServers = @()
        SystemEventError  = $null
        OracleInfoStatus = 'Not tested'
        OracleVersion    = 'N/A'
        OracleVersionFull = 'N/A'
        OracleBinaryRu   = 'N/A'
        OracleRegistryRu = 'N/A'
        OracleRuStatus   = 'Unknown'
        OraclePatchHistory = @()
        OracleSqlPatchStatus = 'Not tested'
        OracleSqlPatches = @()
        OracleDatabaseVersion = 'N/A'
        OracleHostName   = 'N/A'
        OracleInstanceName = 'N/A'
        OracleInstanceStartTime = 'N/A'
        TablespaceStatus = 'Not tested'
        Tablespaces      = @()
        TablespaceError  = $null
        IncidentTypeStatus   = 'Not tested'
        IncidentsByType      = @()
        IncidentTypeError    = $null
        IncidentServerStatus = 'Not tested'
        IncidentsByServer    = @()
        IncidentServerError  = $null
        TopPolicyStatus  = 'Not tested'
        TopPolicies      = @()
        TopPolicyError   = $null
        NetworkSenderStatus = 'Not tested'
        TopNetworkSenders   = @()
        NetworkSenderError  = $null
        EndpointUserStatus = 'Not tested'
        TopEndpointUsers   = @()
        EndpointUserError  = $null
        PolicySummaryStatus = 'Not tested'
        PolicyTotalCount    = 'N/A'
        PolicyGroupCount    = 'N/A'
        UnusedPolicyCount   = 'N/A'
        PolicySummaryError  = $null
        UnusedPolicies      = @()
        PatternSummaryStatus = 'Not tested'
        PatternActiveCount   = 'N/A'
        PatternUserEntries   = 'N/A'
        PatternIpEntries     = 'N/A'
        PatternUrlEntries    = 'N/A'
        PatternsActive       = @()
        ConsoleAccessStatus  = 'Not tested'
        ConsoleUsers         = @()
        ConsoleRoles         = @()
        IntegrationStatus    = 'Not tested'
        AdConnections        = @()
        AdLdapDataSources    = 'N/A'
        AdLdapLoginSources   = 'N/A'
        AdManagedRoles       = 'N/A'
        AdLoginDomains       = ''
        OcrConfigs           = @()
        MipStatus            = 'Not tested'
        MipTenantCount       = 'N/A'
        MipIctCount          = 'N/A'
        MipLabelCount        = 'N/A'
        PendingDeleteStatus = 'Not tested'
        PendingDeleteCount  = 'N/A'
        PendingDeleteError  = $null
        ErrorMessage     = $null
    }

    $sqlPlus = Get-Command 'sqlplus.exe' -ErrorAction SilentlyContinue
    if (-not $sqlPlus) {
        $result.ErrorMessage = 'sqlplus.exe was not found in PATH.'
        return [pscustomobject]$result
    }

    try {
        $versionOutput = & $sqlPlus.Source -v 2>&1
        $result.SqlPlusVersion = (($versionOutput | Where-Object { $_ -match '^Version ' }) -join ' ').Trim()
    }
    catch {
        $result.ErrorMessage = "SQL*Plus version could not be read: $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $connectionDescriptor = (
        '(DESCRIPTION=' +
            '(ADDRESS=' +
                "(HOST=$HostName)" +
                '(PROTOCOL=TCP)' +
                "(PORT=$Port)" +
            ')' +
            '(CONNECT_DATA=' +
                "(SERVICE_NAME=$ServiceName)" +
            ')' +
        ')'
    )

    $sqlTempDirectory = Join-Path $env:ProgramData 'DlpHealthTemp'
    $sqlFile = Join-Path $sqlTempDirectory 'dlp_oracle_test.sql'
    $sqlMarkerFile = Join-Path $sqlTempDirectory 'dlp_oracle_connection.marker'
    $dlpInfoFile = Join-Path $sqlTempDirectory 'dlp_system_information.txt'
    $agentVersionFile = Join-Path $sqlTempDirectory 'dlp_agent_versions.txt'
    $detectionServerFile = Join-Path $sqlTempDirectory 'dlp_detection_servers.txt'
    $systemEventFile = Join-Path $sqlTempDirectory 'dlp_system_events.txt'
    $eventCoverageFile = Join-Path $sqlTempDirectory 'dlp_system_event_coverage.txt'
    $oracleInfoFile = Join-Path $sqlTempDirectory 'dlp_oracle_information.txt'
    $oracleHistoryFile = Join-Path $sqlTempDirectory 'dlp_oracle_patch_history.txt'
    $oracleSqlPatchFile = Join-Path $sqlTempDirectory 'dlp_oracle_sqlpatch.txt'
    $tablespaceFile = Join-Path $sqlTempDirectory 'dlp_tablespace_usage.txt'
    $incidentTypeFile = Join-Path $sqlTempDirectory 'dlp_incident_by_type.txt'
    $incidentServerFile = Join-Path $sqlTempDirectory 'dlp_incident_by_server.txt'
    $topPolicyFile = Join-Path $sqlTempDirectory 'dlp_incident_top_policies.txt'
    $networkSenderFile = Join-Path $sqlTempDirectory 'dlp_incident_top_network_senders.txt'
    $endpointUserFile = Join-Path $sqlTempDirectory 'dlp_incident_top_endpoint_users.txt'
    $pendingDeleteFile = Join-Path $sqlTempDirectory 'dlp_incident_pending_delete.txt'
    $policySummaryFile = Join-Path $sqlTempDirectory 'dlp_policy_summary.txt'
    $unusedPolicyFile = Join-Path $sqlTempDirectory 'dlp_policy_unused.txt'
    $patternSummaryFile = Join-Path $sqlTempDirectory 'dlp_pattern_summary.txt'
    $patternListFile = Join-Path $sqlTempDirectory 'dlp_pattern_list.txt'
    $consoleAccessFile = Join-Path $sqlTempDirectory 'dlp_console_access.txt'
    $integrationFile = Join-Path $sqlTempDirectory 'dlp_integrations.txt'
    $mipFile = Join-Path $sqlTempDirectory 'dlp_mip.txt'

    $sqlContent = @"
SET HEADING OFF
SET FEEDBACK OFF
SET VERIFY OFF
SET ECHO OFF
SET TERMOUT OFF
SET PAGESIZE 0
SET LINESIZE 32767
SET TRIMSPOOL ON
SET TAB OFF

WHENEVER SQLERROR EXIT SQL.SQLCODE
WHENEVER OSERROR EXIT 10

SPOOL $sqlMarkerFile
SELECT 'CONNECTION_OK|' || USER FROM DUAL;
SPOOL OFF

WHENEVER SQLERROR CONTINUE

SPOOL $dlpInfoFile
SELECT
    ev.version || '|' ||
    TO_CHAR(ev.dateinstalled, 'YYYY-MM-DD HH24:MI:SS') || '|' ||
    NVL((SELECT MAX(dlpversion) KEEP (DENSE_RANK LAST ORDER BY dateinstalled)
         FROM dbschemaversion WHERE iscurrentversion = 'Y'), 'N/A') || '|' ||
    (SELECT COUNT(*) FROM agent WHERE NVL(isdeleted, 0) = 0) || '|' ||
    (SELECT COUNT(*) FROM agent WHERE NVL(isdeleted, 0) = 0 AND status = 1) || '|' ||
    (SELECT COUNT(*) FROM agent WHERE NVL(isdeleted, 0) = 0 AND status = 2) || '|' ||
    (SELECT COUNT(*) FROM agent WHERE NVL(isdeleted, 0) = 0 AND status = 3) || '|' ||
    (SELECT COUNT(*) FROM agent WHERE isdeleted = 1)
FROM enforceversion ev
WHERE ev.iscurrentversion = 'Y';
SPOOL OFF

SPOOL $agentVersionFile
SELECT
    COUNT(*) || '|' ||
    REPLACE(NVL(TRIM(version), 'Unknown'), '|', '/')
FROM agent
WHERE NVL(isdeleted, 0) = 0
GROUP BY NVL(TRIM(version), 'Unknown')
ORDER BY COUNT(*) DESC, NVL(TRIM(version), 'Unknown');
SPOOL OFF

SPOOL $detectionServerFile
SELECT
    im.informationmonitorid || '|' ||
    REPLACE(im.monitorname, '|', '/') || '|' ||
    REPLACE(im.host, '|', '/') || '|' ||
    NVL((SELECT MAX(s.stringvalue) KEEP (DENSE_RANK LAST ORDER BY s.statisticid)
         FROM statuses s
         WHERE s.observedentityid = im.informationmonitorid
           AND s.observedentitytype = 2
           AND s.type = 16), 'N/A') || '|' ||
    channels.product_name || '|' ||
    channels.channel_type || '|' ||
    NVL((SELECT TO_CHAR(MAX(h.lastheartbeat), 'YYYY-MM-DD HH24:MI:SS')
         FROM heartbeat h
         WHERE h.informationmonitorid = im.informationmonitorid), '-') || '|' ||
    NVL((SELECT TO_CHAR(ROUND((CAST(SYSTIMESTAMP AS DATE) - CAST(MAX(h.lastheartbeat) AS DATE)) * 86400))
         FROM heartbeat h
         WHERE h.informationmonitorid = im.informationmonitorid), '-')
FROM informationmonitor im
JOIN (
    SELECT informationmonitorid, 'Endpoint Prevent/Discover' product_name, 'Endpoint' channel_type
    FROM endpointchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network Prevent for Web/Mobile', 'ICAP'
    FROM icapchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network Prevent for Email', 'Inline SMTP'
    FROM inlinesmtpchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network Discover', 'File System'
    FROM filesystemchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network Monitor', 'Packet Capture'
    FROM packetcapturechannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'REST Detection', 'REST Induction'
    FROM restinductionchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network Monitor', 'SMTP Copy'
    FROM smtpcopychannel WHERE state = 1
) channels ON channels.informationmonitorid = im.informationmonitorid
WHERE NVL(im.isdeleted, 0) = 0
ORDER BY im.informationmonitorid, channels.channel_type;
SPOOL OFF

SPOOL $systemEventFile
SELECT event_row
FROM (
    SELECT
        ev.eventcode || '|' ||
        ev.severity || '|' ||
        ev.informationmonitorid || '|' ||
        REPLACE(
            CASE WHEN ev.informationmonitorid = -1 THEN 'Enforce Server'
                 ELSE NVL(im.monitorname, 'Unknown') END,
            '|', '/'
        ) || '|' ||
        REPLACE(
            CASE WHEN ev.informationmonitorid = -1 THEN 'ENFORCE_LOCAL'
                 ELSE NVL(im.host, 'Unknown') END,
            '|', '/'
        ) || '|' ||
        ev.event_count || '|' ||
        TO_CHAR(ev.eventdate, 'YYYY-MM-DD HH24:MI:SS') || '|' ||
        REPLACE(REPLACE(REPLACE(NVL(ev.summary, ''), '|', '/'), CHR(10), ' '), CHR(13), ' ')
        AS event_row
    FROM (
        SELECT
            se.eventcode, se.severity, se.informationmonitorid, se.eventdate, se.summary,
            ROW_NUMBER() OVER (PARTITION BY se.eventcode, se.severity, se.informationmonitorid ORDER BY se.eventdate DESC) AS rn,
            COUNT(*) OVER (PARTITION BY se.eventcode, se.severity, se.informationmonitorid) AS event_count
        FROM systemevent se
        WHERE se.severity IN (3, 4)
          AND se.eventdate >= SYSTIMESTAMP - NUMTODSINTERVAL($SystemEventLookbackDays, 'DAY')
    ) ev
    LEFT JOIN informationmonitor im
        ON im.informationmonitorid = ev.informationmonitorid
    WHERE ev.rn = 1
    ORDER BY ev.eventdate DESC
)
WHERE ROWNUM <= $MaximumSystemEvents;
SPOOL OFF

SPOOL $eventCoverageFile
SELECT
    s.monitor_id || '|' ||
    REPLACE(s.server_name, '|', '/') || '|' ||
    NVL(SUM(CASE WHEN se.severity = 3 THEN 1 ELSE 0 END), 0) || '|' ||
    NVL(SUM(CASE WHEN se.severity = 4 THEN 1 ELSE 0 END), 0)
FROM (
    SELECT -1 AS monitor_id, 'Enforce Server' AS server_name FROM dual
    UNION ALL
    SELECT informationmonitorid, monitorname FROM informationmonitor WHERE NVL(isdeleted, 0) = 0
) s
LEFT JOIN systemevent se
    ON se.informationmonitorid = s.monitor_id
   AND se.severity IN (3, 4)
   AND se.eventdate >= SYSTIMESTAMP - NUMTODSINTERVAL($SystemEventLookbackDays, 'DAY')
GROUP BY s.monitor_id, s.server_name
ORDER BY s.monitor_id;
SPOOL OFF

SPOOL $oracleInfoFile
SELECT 'VERSION|' || REPLACE(REPLACE(REPLACE(banner_full, '|', '/'), CHR(10), ' '), CHR(13), ' ')
FROM v`$version
WHERE banner_full LIKE 'Oracle Database%'
  AND ROWNUM = 1;

SELECT
    'INSTANCE|' || d.name || '|' || i.host_name || '|' || i.version || '|' ||
    i.instance_name || '|' || TO_CHAR(i.startup_time, 'YYYY-MM-DD HH24:MI:SS')
FROM v`$database d
CROSS JOIN v`$instance i;

SELECT 'FULLVERSION|' || version_full FROM v`$instance;
SPOOL OFF

SPOOL $oracleHistoryFile
SELECT 'H|' || NVL(TO_CHAR(action_time, 'YYYY-MM-DD HH24:MI'), '-') || '|' || action || '|' || NVL(version, '-') || '|' ||
       REPLACE(REPLACE(REPLACE(NVL(comments, '-'), '|', '/'), CHR(10), ' '), CHR(13), ' ')
FROM (
    SELECT action_time, action, version, comments
    FROM dba_registry_history
    ORDER BY action_time DESC NULLS LAST
)
WHERE ROWNUM <= 10;
SPOOL OFF

SPOOL $oracleSqlPatchFile
SELECT 'P|' || patch_id || '|' || action || '|' || status || '|' ||
       NVL(TO_CHAR(action_time, 'YYYY-MM-DD HH24:MI'), '-') || '|' ||
       REPLACE(REPLACE(REPLACE(NVL(SUBSTR(description, 1, 150), '-'), '|', '/'), CHR(10), ' '), CHR(13), ' ')
FROM (
    SELECT patch_id, action, status, action_time, description
    FROM dba_registry_sqlpatch
    ORDER BY action_time DESC
)
WHERE ROWNUM <= 15;
SPOOL OFF

SPOOL $tablespaceFile
SELECT
    df.tablespace_name || '|' ||
    tu.totalusedspace || '|' ||
    (df.totalspace - tu.totalusedspace) || '|' ||
    df.totalspace || '|' ||
    ROUND(100 * ((df.totalspace - tu.totalusedspace) / df.totalspace)) || '|' ||
    ROUND(100 * (tu.totalusedspace / df.totalspace))
FROM
    (
        SELECT tablespace_name, ROUND(SUM(bytes) / 1048576) totalspace
        FROM dba_data_files
        GROUP BY tablespace_name
    ) df,
    (
        SELECT ROUND(SUM(bytes) / (1024 * 1024)) totalusedspace, tablespace_name
        FROM dba_segments
        GROUP BY tablespace_name
    ) tu
WHERE df.tablespace_name = tu.tablespace_name
ORDER BY ROUND(100 * (tu.totalusedspace / df.totalspace)) DESC;
SPOOL OFF

SPOOL $incidentTypeFile
WITH channel_raw AS (
    SELECT informationmonitorid, 'Endpoint' incident_type, 1 priority FROM endpointchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Discover', 2 FROM filesystemchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'REST', 3 FROM restinductionchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM icapchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM inlinesmtpchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM packetcapturechannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM smtpcopychannel WHERE state = 1
),
channels AS (
    SELECT informationmonitorid, incident_type FROM (
        SELECT informationmonitorid, incident_type,
               ROW_NUMBER() OVER (PARTITION BY informationmonitorid ORDER BY priority) rn
        FROM channel_raw
    ) WHERE rn = 1
)
SELECT NVL(c.incident_type, 'Unknown') || '|' || COUNT(*)
FROM incident i
JOIN message m ON m.messageid = i.messageid
LEFT JOIN channels c ON c.informationmonitorid = m.monitorid
WHERE i.isdeleted = 0
GROUP BY NVL(c.incident_type, 'Unknown')
ORDER BY COUNT(*) DESC;
SPOOL OFF

SPOOL $incidentServerFile
SELECT
    REPLACE(NVL(im.monitorname, 'Unknown'), '|', '/') ||
    CASE WHEN NVL(im.isdeleted, 0) = 1 THEN ' (deleted/inactive server record)' ELSE '' END ||
    '|' || COUNT(*)
FROM incident i
JOIN message m ON m.messageid = i.messageid
JOIN informationmonitor im ON im.informationmonitorid = m.monitorid
WHERE i.isdeleted = 0
GROUP BY REPLACE(NVL(im.monitorname, 'Unknown'), '|', '/'), NVL(im.isdeleted, 0)
ORDER BY COUNT(*) DESC;
SPOOL OFF

SPOOL $topPolicyFile
SELECT REPLACE(p.name, '|', '/') || '|' || COUNT(*)
FROM incident i
JOIN policy p ON p.policyid = i.policyid
WHERE i.isdeleted = 0
  AND i.creationdate >= SYSTIMESTAMP - NUMTODSINTERVAL($IncidentLookbackDays, 'DAY')
GROUP BY REPLACE(p.name, '|', '/')
ORDER BY COUNT(*) DESC
FETCH FIRST $IncidentTopCount ROWS ONLY;
SPOOL OFF

SPOOL $networkSenderFile
WITH channel_raw AS (
    SELECT informationmonitorid, 'Endpoint' incident_type, 1 priority FROM endpointchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Discover', 2 FROM filesystemchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'REST', 3 FROM restinductionchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM icapchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM inlinesmtpchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM packetcapturechannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM smtpcopychannel WHERE state = 1
),
channels AS (
    SELECT informationmonitorid, incident_type FROM (
        SELECT informationmonitorid, incident_type,
               ROW_NUMBER() OVER (PARTITION BY informationmonitorid ORDER BY priority) rn
        FROM channel_raw
    ) WHERE rn = 1
)
SELECT REPLACE(mo.networksenderidentifier, '|', '/') || '|' || COUNT(*)
FROM incident i
JOIN message m ON m.messageid = i.messageid
JOIN messageoriginator mo ON mo.messageoriginatorid = m.messageoriginatorid
LEFT JOIN channels c ON c.informationmonitorid = m.monitorid
WHERE i.isdeleted = 0
  AND NVL(c.incident_type, 'Unknown') = 'Network'
  AND mo.networksenderidentifier IS NOT NULL
  AND i.creationdate >= SYSTIMESTAMP - NUMTODSINTERVAL($IncidentLookbackDays, 'DAY')
GROUP BY REPLACE(mo.networksenderidentifier, '|', '/')
ORDER BY COUNT(*) DESC
FETCH FIRST $IncidentTopCount ROWS ONLY;
SPOOL OFF

SPOOL $endpointUserFile
WITH channel_raw AS (
    SELECT informationmonitorid, 'Endpoint' incident_type, 1 priority FROM endpointchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Discover', 2 FROM filesystemchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'REST', 3 FROM restinductionchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM icapchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM inlinesmtpchannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM packetcapturechannel WHERE state = 1
    UNION ALL
    SELECT informationmonitorid, 'Network', 4 FROM smtpcopychannel WHERE state = 1
),
channels AS (
    SELECT informationmonitorid, incident_type FROM (
        SELECT informationmonitorid, incident_type,
               ROW_NUMBER() OVER (PARTITION BY informationmonitorid ORDER BY priority) rn
        FROM channel_raw
    ) WHERE rn = 1
)
SELECT REPLACE(NVL(m.endpointapploggedinuser, mo.domainusername), '|', '/') || '|' || COUNT(*)
FROM incident i
JOIN message m ON m.messageid = i.messageid
LEFT JOIN messageoriginator mo ON mo.messageoriginatorid = m.messageoriginatorid
LEFT JOIN channels c ON c.informationmonitorid = m.monitorid
WHERE i.isdeleted = 0
  AND NVL(c.incident_type, 'Unknown') = 'Endpoint'
  AND NVL(m.endpointapploggedinuser, mo.domainusername) IS NOT NULL
  AND i.creationdate >= SYSTIMESTAMP - NUMTODSINTERVAL($IncidentLookbackDays, 'DAY')
GROUP BY REPLACE(NVL(m.endpointapploggedinuser, mo.domainusername), '|', '/')
ORDER BY COUNT(*) DESC
FETCH FIRST $IncidentTopCount ROWS ONLY;
SPOOL OFF

SPOOL $pendingDeleteFile
SELECT COUNT(*) FROM incident WHERE isdeleted = 1;
SPOOL OFF

SPOOL $policySummaryFile
SELECT
    (SELECT COUNT(*) FROM policy WHERE NVL(isdeleted, 0) = 0) || '|' ||
    (SELECT COUNT(*) FROM policygroup WHERE NVL(isdeleted, 0) = 0) || '|' ||
    (SELECT COUNT(*) FROM policy p
      WHERE NVL(p.isdeleted, 0) = 0
        AND NOT EXISTS (
            SELECT 1 FROM incident i
            WHERE i.policyid = p.policyid
              AND i.isdeleted = 0
              AND i.creationdate >= SYSTIMESTAMP - NUMTODSINTERVAL($IncidentLookbackDays, 'DAY')))
FROM dual;
SPOOL OFF

SPOOL $unusedPolicyFile
SELECT
    REPLACE(p.name, '|', '/') || '|' || REPLACE(NVL(g.name, '-'), '|', '/')
FROM policy p
LEFT JOIN policygroup g ON g.policygroupid = p.policygroupid
WHERE NVL(p.isdeleted, 0) = 0
  AND NOT EXISTS (
      SELECT 1 FROM incident i
      WHERE i.policyid = p.policyid
        AND i.isdeleted = 0
        AND i.creationdate >= SYSTIMESTAMP - NUMTODSINTERVAL($IncidentLookbackDays, 'DAY'))
ORDER BY p.name
FETCH FIRST 50 ROWS ONLY;
SPOOL OFF

SPOOL $patternSummaryFile
SELECT
    (SELECT COUNT(*) FROM senderrecipientpattern WHERE NVL(isdeleted, 0) = 0 AND name IS NOT NULL) || '|' ||
    (SELECT NVL(SUM(NVL(REGEXP_COUNT(userpatterns, '[^,[:space:]]+'), 0)), 0) FROM senderrecipientpattern WHERE NVL(isdeleted, 0) = 0 AND name IS NOT NULL) || '|' ||
    (SELECT NVL(SUM(NVL(REGEXP_COUNT(ipaddresses, '[^,[:space:]]+'), 0)), 0) FROM senderrecipientpattern WHERE NVL(isdeleted, 0) = 0 AND name IS NOT NULL) || '|' ||
    (SELECT NVL(SUM(NVL(REGEXP_COUNT(urldomains, '[^,[:space:]]+'), 0)), 0) FROM senderrecipientpattern WHERE NVL(isdeleted, 0) = 0 AND name IS NOT NULL)
FROM dual;
SPOOL OFF

SPOOL $patternListFile
SELECT status_flag || '|' || REPLACE(pattern_name, '|', '/') || '|' || user_entries || '|' || ip_entries || '|' || url_entries || '|' || modified_text || '|' || rule_type
FROM (
    SELECT
        CASE WHEN NVL(isdeleted, 0) = 0 THEN 'A' ELSE 'D' END AS status_flag,
        name AS pattern_name,
        NVL(REGEXP_COUNT(userpatterns, '[^,[:space:]]+'), 0) AS user_entries,
        NVL(REGEXP_COUNT(ipaddresses, '[^,[:space:]]+'), 0) AS ip_entries,
        NVL(REGEXP_COUNT(urldomains, '[^,[:space:]]+'), 0) AS url_entries,
        NVL(TO_CHAR(modifieddate, 'YYYY-MM-DD HH24:MI'), '-') AS modified_text,
        NVL(ruletype, -1) AS rule_type,
        ROW_NUMBER() OVER (PARTITION BY CASE WHEN NVL(isdeleted, 0) = 0 THEN 'A' ELSE 'D' END ORDER BY name) AS rn
    FROM senderrecipientpattern
    WHERE name IS NOT NULL
      AND NVL(isdeleted, 0) = 0
)
WHERE rn <= 50
ORDER BY status_flag, pattern_name;
SPOOL OFF

SPOOL $consoleAccessFile
SELECT line
FROM (
    SELECT 1 AS ord, u.name AS sort_name,
        'U|' || u.userid || '|' ||
        REPLACE(u.name, '|', '/') || '|' ||
        REPLACE(NVL(u.emailaddress, '-'), '|', '/') || '|' ||
        NVL(u.isapiuser, 0) || '|' ||
        NVL(u.ispasswordauthenabled, 0) || '|' ||
        NVL(u.iscertificateauthenabled, 0) || '|' ||
        NVL(u.issamlauthenabled, 0) || '|' ||
        NVL(u.consecutivefailedattempts, 0) || '|' ||
        NVL(TO_CHAR(u.lastactivedate, 'YYYY-MM-DD HH24:MI'), '-') || '|' ||
        NVL(TO_CHAR(u.datelockedout, 'YYYY-MM-DD HH24:MI'), '-') || '|' ||
        CASE WHEN u.adobjectguid IS NULL THEN 0 ELSE 1 END || '|' ||
        NVL((SELECT LISTAGG(REPLACE(r.name, '|', '/'), ', ') WITHIN GROUP (ORDER BY r.name)
             FROM userrolemapping m
             JOIN role r ON r.roleid = m.roleid
             WHERE m.userid = u.userid AND NVL(r.isdeleted, 0) = 0), '-') AS line
    FROM protectuser u
    WHERE NVL(u.isdeleted, 0) = 0
      AND LOWER(u.name) <> 'internal system user'
    UNION ALL
    SELECT 2, r.name,
        'R|' || r.roleid || '|' ||
        REPLACE(r.name, '|', '/') || '|' ||
        NVL(r.isactivedirectorymanaged, 0) || '|' ||
        (SELECT COUNT(*) FROM userrolemapping m
           JOIN protectuser u2 ON u2.userid = m.userid
          WHERE m.roleid = r.roleid AND NVL(u2.isdeleted, 0) = 0)
    FROM role r
    WHERE NVL(r.isdeleted, 0) = 0
)
ORDER BY ord, sort_name;
SPOOL OFF

SPOOL $integrationFile
SELECT line
FROM (
    SELECT 1 AS ord,
        'C|' ||
        (SELECT COUNT(*) FROM directoryconnection) || '|' ||
        (SELECT COUNT(*) FROM ldapdatausersource) || '|' ||
        (SELECT COUNT(*) FROM ldaploginusersource) || '|' ||
        (SELECT COUNT(*) FROM role WHERE NVL(isdeleted, 0) = 0 AND NVL(isactivedirectorymanaged, 0) = 1) || '|' ||
        (SELECT COUNT(*) FROM ocrconfiguration) AS line
    FROM dual
    UNION ALL
    SELECT 2,
        'D|' || REPLACE(NVL(name, '-'), '|', '/') || '|' ||
        REPLACE(NVL(host, '-'), '|', '/') || '|' ||
        NVL(port, 0) || '|' ||
        NVL(usessl, 0) || '|' ||
        NVL(anonymousbind, 0)
    FROM directoryconnection
    UNION ALL
    SELECT 3,
        'O|' || REPLACE(NVL(c.name, '-'), '|', '/') || '|' ||
        REPLACE(NVL(c.hostname, '-'), '|', '/') || '|' ||
        NVL(c.port, 0) || '|' ||
        NVL((SELECT LISTAGG(REPLACE(im.monitorname, '|', '/'), ', ') WITHIN GROUP (ORDER BY im.monitorname)
             FROM informationmonitor im
             WHERE im.ocrconfigurationid = c.ocrconfigurationid AND NVL(im.isdeleted, 0) = 0), '-')
    FROM ocrconfiguration c
    UNION ALL
    SELECT 4,
        'K|' || REPLACE(NVL((SELECT TO_CHAR(SUBSTR(a.value, 1, 500))
                             FROM attribute a
                             JOIN setting s ON s.settingid = a.settingid
                             WHERE s.name = 'kerberosAuth' AND a.name = 'ADDomainList' AND ROWNUM = 1), '-'), '|', '/')
    FROM dual
)
ORDER BY ord;
SPOOL OFF

SPOOL $mipFile
SELECT
    (SELECT COUNT(*) FROM aiptenant) || '|' ||
    (SELECT COUNT(*) FROM ictconnection) || '|' ||
    (SELECT COUNT(*) FROM aiplabel)
FROM dual;
SPOOL OFF

EXIT SUCCESS
"@

    try {
        if (-not (Test-Path -LiteralPath $sqlTempDirectory)) {
            [void](New-Item -Path $sqlTempDirectory -ItemType Directory -Force)
        }

        Set-Content `
            -Path $sqlFile `
            -Value $sqlContent `
            -Encoding ASCII `
            -Force

        if (-not (Test-Path -LiteralPath $sqlFile)) {
            throw "SQL test file could not be created: $sqlFile"
        }

        Write-Host ''
        Write-Host '=== ORACLE CONNECTION TEST ===' -ForegroundColor Cyan
        Write-Host "Database Host    : $HostName"
        Write-Host "Database Port    : $Port"
        Write-Host "Database Service : $ServiceName"
        Write-Host "Database User    : $UserName"
        Write-Host ''
        Write-Host 'PowerShell will ask for the Oracle password.' -ForegroundColor Yellow
        Write-Host 'The password is masked while you type it.' -ForegroundColor Yellow
        Write-Host "SQL file: $sqlFile" -ForegroundColor DarkGray
        Write-Host ''

        Remove-Item -Path $sqlMarkerFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $dlpInfoFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $agentVersionFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $detectionServerFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $systemEventFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $eventCoverageFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oracleInfoFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oracleHistoryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oracleSqlPatchFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $tablespaceFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $incidentTypeFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $incidentServerFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $topPolicyFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $networkSenderFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $endpointUserFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $pendingDeleteFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $policySummaryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $unusedPolicyFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $patternSummaryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $patternListFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $consoleAccessFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $integrationFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $mipFile -Force -ErrorAction SilentlyContinue

        $securePassword = Read-Host -Prompt "Oracle password for $UserName" -AsSecureString
        $passwordPointer = [IntPtr]::Zero
        $plainPassword = $null
        $sqlLogon = $null

        try {
            $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)

            # Use the same logon format that is confirmed to work from CMD on
            # the Enforce server: user/password@(DESCRIPTION=...). PowerShell's
            # call operator passes the entire logon value as one argument.
            $sqlLogon = [string]::Concat(
                $UserName, '/', $plainPassword, '@', $connectionDescriptor
            )
            $sqlScriptArgument = [string]::Concat('@', $sqlFile)

            $sqlOutput = @(& $sqlPlus.Source -L $sqlLogon $sqlScriptArgument 2>&1)
            $sqlExitCode = $LASTEXITCODE

            # SQL*Plus output is displayed with Write-Host so it cannot become
            # an extra return object and break the DatabaseLogin property.
            foreach ($sqlOutputLine in $sqlOutput) {
                $safeOutputLine = $sqlOutputLine.ToString().Replace($plainPassword, '********')
                Write-Host $safeOutputLine
            }

            $sqlLogon = $null
        }
        finally {
            $sqlLogon = $null
            $plainPassword = $null
            $securePassword = $null
            if ($passwordPointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
            }
        }

        Write-Host ''

        $expectedConnectionMarker = "CONNECTION_OK|$($UserName.ToUpperInvariant())"
        $connectionMarkerFound = $false
        if (Test-Path -LiteralPath $sqlMarkerFile) {
            $markerContent = Get-Content -LiteralPath $sqlMarkerFile -Raw -ErrorAction SilentlyContinue
            $connectionMarkerFound = $markerContent -match [regex]::Escape($expectedConnectionMarker)
        }

        if ($sqlExitCode -eq 0 -and $connectionMarkerFound) {
            Write-Host 'Oracle connection: SUCCESSFUL' -ForegroundColor Green
            $result.TcpAccess = 'Successful'
            $result.DatabaseLogin = 'Successful'
            $result.DatabaseName = $ServiceName
            $result.ConnectedUser = $UserName.ToUpperInvariant()

            if (Test-Path -LiteralPath $dlpInfoFile) {
                $dlpInfoLine = Get-Content -LiteralPath $dlpInfoFile -ErrorAction SilentlyContinue |
                    Where-Object { ($_ -split '\|').Count -eq 8 -and $_ -notmatch 'ORA-\d+' } |
                    Select-Object -First 1
                if ($dlpInfoLine) {
                    $dlpInfoParts = $dlpInfoLine.Trim() -split '\|'
                    $result.DlpVersion = $dlpInfoParts[0].Trim()
                    $result.DlpInstalledAt = $dlpInfoParts[1].Trim()
                    $result.DlpSchemaVersion = $dlpInfoParts[2].Trim()
                    $result.InstallAgentCount = $dlpInfoParts[3].Trim()
                    # AGENT.STATUS: 1=Disable, 2=Reporting, 3=Not Reporting (confirmed against Enforce console agent list; not the 1/2/3 order the raw column position suggests)
                    $result.DisableAgentCount = $dlpInfoParts[4].Trim()
                    $result.ReportingAgentCount = $dlpInfoParts[5].Trim()
                    $result.NotReportingAgentCount = $dlpInfoParts[6].Trim()
                    $result.DeletedAgentCount = $dlpInfoParts[7].Trim()
                    $result.DlpInfoStatus = 'Successful'
                }
                else {
                    $result.DlpInfoStatus = 'Failed'
                }
            }

            $agentVersions = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $agentVersionFile) {
                foreach ($agentVersionLine in (Get-Content -LiteralPath $agentVersionFile -ErrorAction SilentlyContinue)) {
                    $agentVersionParts = $agentVersionLine.Trim() -split '\|'
                    if ($agentVersionParts.Count -eq 2 -and
                        $agentVersionParts[0].Trim() -match '^\d+$') {
                        [void]$agentVersions.Add([pscustomobject]@{
                            Count   = [int]$agentVersionParts[0].Trim()
                            Version = $agentVersionParts[1].Trim()
                        })
                    }
                }
            }
            $result.AgentVersions = @($agentVersions)
            if ($agentVersions.Count -gt 0) {
                $result.AgentVersionStatus = 'Successful'
            }
            elseif (Test-Path -LiteralPath $agentVersionFile) {
                $agentVersionOracleError = Get-Content -LiteralPath $agentVersionFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'ORA-\d+' } |
                    Select-Object -First 1
                if ($agentVersionOracleError) {
                    $result.AgentVersionStatus = 'Failed'
                    $result.AgentVersionError = $agentVersionOracleError.Trim()
                }
                else {
                    $result.AgentVersionStatus = 'No agents'
                }
            }

            $detectionServers = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $detectionServerFile) {
                foreach ($serverLine in (Get-Content -LiteralPath $detectionServerFile -ErrorAction SilentlyContinue)) {
                    $serverParts = $serverLine.Trim() -split '\|'
                    if ($serverParts.Count -eq 8 -and $serverParts[0].Trim() -match '^\d+$') {
                        $heartbeatAgeText = $serverParts[7].Trim()
                        $heartbeatAge = $null
                        if ($heartbeatAgeText -match '^-?\d+$') { $heartbeatAge = [long]$heartbeatAgeText }
                        $serverState = 'Unknown'
                        if ($null -ne $heartbeatAge) {
                            $serverState = if ($heartbeatAge -le $HeartbeatStaleSeconds) { 'Running' } else { 'Unknown' }
                        }
                        [void]$detectionServers.Add([pscustomobject]@{
                            MonitorId  = [int]$serverParts[0].Trim()
                            ServerName = $serverParts[1].Trim()
                            HostName   = $serverParts[2].Trim()
                            Version    = $serverParts[3].Trim()
                            Product    = $serverParts[4].Trim()
                            Channel    = $serverParts[5].Trim()
                            Status     = $serverState
                            LastHeartbeat = $serverParts[6].Trim()
                            HeartbeatAgeSeconds = $heartbeatAge
                        })
                    }
                }
            }
            $result.DetectionServers = @($detectionServers)

            $systemEvents = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $systemEventFile) {
                foreach ($eventLine in (Get-Content -LiteralPath $systemEventFile -ErrorAction SilentlyContinue)) {
                    $eventParts = $eventLine.Trim() -split '\|'
                    if ($eventParts.Count -eq 8 -and
                        $eventParts[0].Trim() -match '^\d+$' -and
                        $eventParts[1].Trim() -match '^[34]$' -and
                        $eventParts[2].Trim() -match '^-?\d+$' -and
                        $eventParts[5].Trim() -match '^\d+$') {
                        $eventCode = [int]$eventParts[0].Trim()
                        $severity = [int]$eventParts[1].Trim()
                        $eventHost = $eventParts[4].Trim()
                        if ($eventHost -eq 'ENFORCE_LOCAL') {
                            $eventHost = $env:COMPUTERNAME
                        }

                        [void]$systemEvents.Add([pscustomobject]@{
                            EventCode  = $eventCode
                            Severity   = $severity
                            Type       = if ($severity -eq 3) { 'Error' } else { 'Warning' }
                            MonitorId  = [int]$eventParts[2].Trim()
                            ServerName = $eventParts[3].Trim()
                            HostName   = $eventHost
                            Count      = [int]$eventParts[5].Trim()
                            LastTime   = $eventParts[6].Trim()
                            Message    = Get-DlpSystemEventMessage -EventCode $eventCode `
                                -SummaryKey $eventParts[7].Trim()
                            MessageKey = $eventParts[7].Trim()
                        })
                    }
                }
            }
            $result.SystemEvents = @($systemEvents)

            $eventServers = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $eventCoverageFile) {
                foreach ($coverageLine in (Get-Content -LiteralPath $eventCoverageFile -ErrorAction SilentlyContinue)) {
                    $coverageParts = $coverageLine.Trim() -split '\|'
                    if ($coverageParts.Count -eq 4 -and $coverageParts[0].Trim() -match '^-?\d+$' -and
                        $coverageParts[2].Trim() -match '^\d+$' -and $coverageParts[3].Trim() -match '^\d+$') {
                        [void]$eventServers.Add([pscustomobject]@{
                            MonitorId  = [int]$coverageParts[0].Trim()
                            ServerName = $coverageParts[1].Trim()
                            Errors     = [int]$coverageParts[2].Trim()
                            Warnings   = [int]$coverageParts[3].Trim()
                        })
                    }
                }
            }
            $result.SystemEventServers = @($eventServers)
            if ($systemEvents.Count -gt 0) {
                $result.SystemEventStatus = 'Successful'
            }
            elseif (Test-Path -LiteralPath $systemEventFile) {
                $systemEventOracleError = Get-Content -LiteralPath $systemEventFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'ORA-\d+' } |
                    Select-Object -First 1
                if ($systemEventOracleError) {
                    $result.SystemEventStatus = 'Failed'
                    $result.SystemEventError = $systemEventOracleError.Trim()
                }
                else {
                    $result.SystemEventStatus = 'No events'
                }
            }

            if (Test-Path -LiteralPath $oracleInfoFile) {
                foreach ($oracleLine in (Get-Content -LiteralPath $oracleInfoFile -ErrorAction SilentlyContinue)) {
                    $oracleParts = $oracleLine.Trim() -split '\|'
                    if ($oracleParts.Count -eq 2 -and $oracleParts[0].Trim() -eq 'VERSION') {
                        $result.OracleVersion = $oracleParts[1].Trim()
                    }
                    elseif ($oracleParts.Count -eq 6 -and $oracleParts[0].Trim() -eq 'INSTANCE') {
                        $result.DatabaseName = $oracleParts[1].Trim()
                        $result.OracleHostName = $oracleParts[2].Trim()
                        $result.OracleDatabaseVersion = $oracleParts[3].Trim()
                        $result.OracleInstanceName = $oracleParts[4].Trim()
                        $result.OracleInstanceStartTime = $oracleParts[5].Trim()
                    }
                    elseif ($oracleParts.Count -eq 2 -and $oracleParts[0].Trim() -eq 'FULLVERSION') {
                        $result.OracleVersionFull = $oracleParts[1].Trim()
                    }
                }
                if ($result.OracleVersion -ne 'N/A' -and $result.OracleHostName -ne 'N/A') {
                    $result.OracleInfoStatus = 'Successful'
                }
                else {
                    $result.OracleInfoStatus = 'Failed'
                }
            }

            $oraclePatchHistory = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $oracleHistoryFile) {
                foreach ($historyLine in (Get-Content -LiteralPath $oracleHistoryFile -ErrorAction SilentlyContinue)) {
                    if ($historyLine -match 'ORA-\d+') { continue }
                    $historyParts = $historyLine.Trim() -split '\|'
                    if ($historyParts.Count -eq 5 -and $historyParts[0] -eq 'H') {
                        [void]$oraclePatchHistory.Add([pscustomobject]@{
                            Time     = $historyParts[1].Trim()
                            Action   = $historyParts[2].Trim()
                            Version  = $historyParts[3].Trim()
                            Comments = $historyParts[4].Trim()
                        })
                    }
                }
            }
            $result.OraclePatchHistory = @($oraclePatchHistory)

            $oracleSqlPatches = [System.Collections.Generic.List[object]]::new()
            $sqlPatchUnavailable = $false
            if (Test-Path -LiteralPath $oracleSqlPatchFile) {
                foreach ($sqlPatchLine in (Get-Content -LiteralPath $oracleSqlPatchFile -ErrorAction SilentlyContinue)) {
                    if ($sqlPatchLine -match 'ORA-00942|ORA-01031') { $sqlPatchUnavailable = $true; continue }
                    $sqlPatchParts = $sqlPatchLine.Trim() -split '\|'
                    if ($sqlPatchParts.Count -eq 6 -and $sqlPatchParts[0] -eq 'P') {
                        [void]$oracleSqlPatches.Add([pscustomobject]@{
                            PatchId     = $sqlPatchParts[1].Trim()
                            Action      = $sqlPatchParts[2].Trim()
                            Status      = $sqlPatchParts[3].Trim()
                            Time        = $sqlPatchParts[4].Trim()
                            Description = $sqlPatchParts[5].Trim()
                        })
                    }
                }
            }
            $result.OracleSqlPatches = @($oracleSqlPatches)
            $result.OracleSqlPatchStatus = $(if ($oracleSqlPatches.Count -gt 0) { 'Successful' } elseif ($sqlPatchUnavailable) { 'Unavailable' } else { 'No rows' })

            $binaryRu = $null
            if ($result.OracleVersionFull -match '^\d+\.\d+\.\d+\.\d+\.\d+$') { $binaryRu = $result.OracleVersionFull }
            elseif ($result.OracleVersion -match 'Version\s+(\d+\.\d+\.\d+\.\d+\.\d+)') { $binaryRu = $Matches[1] }

            $registryRu = $null
            foreach ($appliedPatch in $oracleSqlPatches) {
                if ($appliedPatch.Action -eq 'APPLY' -and $appliedPatch.Status -eq 'SUCCESS' -and $appliedPatch.Description -match '(?i)Database\s+(?:Release\s+Update|Bundle\s+Patch)[^0-9]*(\d+\.\d+\.\d+\.\d+)') {
                    $registryRu = $Matches[1]
                    break
                }
            }
            if ($null -eq $registryRu) {
                foreach ($historyEntry in $oraclePatchHistory) {
                    if ($historyEntry.Comments -match 'to (\d+\.\d+\.\d+\.\d+\.\d+)') { $registryRu = $Matches[1]; break }
                    if ($historyEntry.Comments -match 'RDBMS_(\d+\.\d+\.\d+\.\d+\.\d+)') { $registryRu = $Matches[1]; break }
                }
            }
            if ($null -ne $binaryRu) { $result.OracleBinaryRu = $binaryRu }
            if ($null -ne $registryRu) { $result.OracleRegistryRu = $registryRu }
            if ($null -ne $binaryRu -and $null -ne $registryRu) {
                $binaryKey = ($binaryRu -split '\.')[0..1] -join '.'
                $registryKey = ($registryRu -split '\.')[0..1] -join '.'
                $result.OracleRuStatus = $(if ($binaryKey -eq $registryKey) { 'Match' } else { 'Mismatch' })
            }

            $tablespaceRows = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $tablespaceFile) {
                foreach ($tablespaceLine in (Get-Content -LiteralPath $tablespaceFile -ErrorAction SilentlyContinue)) {
                    $tablespaceParts = $tablespaceLine.Trim() -split '\|'
                    if ($tablespaceParts.Count -eq 6 -and
                        $tablespaceParts[1].Trim() -match '^\d+$' -and
                        $tablespaceParts[2].Trim() -match '^\d+$' -and
                        $tablespaceParts[3].Trim() -match '^\d+$' -and
                        $tablespaceParts[4].Trim() -match '^\d+$' -and
                        $tablespaceParts[5].Trim() -match '^\d+$') {
                        [void]$tablespaceRows.Add([pscustomobject]@{
                            Tablespace = $tablespaceParts[0].Trim()
                            UsedMB     = [long]$tablespaceParts[1].Trim()
                            FreeMB     = [long]$tablespaceParts[2].Trim()
                            TotalMB    = [long]$tablespaceParts[3].Trim()
                            FreePct    = [int]$tablespaceParts[4].Trim()
                            UsedPct    = [int]$tablespaceParts[5].Trim()
                        })
                    }
                }
            }

            $result.Tablespaces = @($tablespaceRows)
            if ($tablespaceRows.Count -gt 0) {
                $result.TablespaceStatus = 'Successful'
            }
            else {
                $result.TablespaceStatus = 'Failed'
                $tablespaceOracleError = $null
                if (Test-Path -LiteralPath $tablespaceFile) {
                    $tablespaceOracleError = Get-Content -LiteralPath $tablespaceFile -ErrorAction SilentlyContinue |
                        Where-Object { $_ -match 'ORA-\d+' } |
                        Select-Object -First 1
                }
                if ($tablespaceOracleError) {
                    $result.TablespaceError = "Tablespace query failed: $($tablespaceOracleError.Trim())"
                }
                else {
                    $result.TablespaceError = 'Tablespace data could not be read. The PROTECT user may not have access to DBA_DATA_FILES or DBA_SEGMENTS.'
                }
            }

            $incidentsByType = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $incidentTypeFile) {
                foreach ($incidentTypeLine in (Get-Content -LiteralPath $incidentTypeFile -ErrorAction SilentlyContinue)) {
                    $incidentTypeParts = $incidentTypeLine.Trim() -split '\|'
                    if ($incidentTypeParts.Count -eq 2 -and $incidentTypeParts[1].Trim() -match '^\d+$') {
                        [void]$incidentsByType.Add([pscustomobject]@{
                            Type  = $incidentTypeParts[0].Trim()
                            Count = [long]$incidentTypeParts[1].Trim()
                        })
                    }
                }
            }
            $result.IncidentsByType = @($incidentsByType)
            if ($incidentsByType.Count -gt 0) {
                $result.IncidentTypeStatus = 'Successful'
            }
            elseif (Test-Path -LiteralPath $incidentTypeFile) {
                $incidentTypeOracleError = Get-Content -LiteralPath $incidentTypeFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'ORA-\d+' } | Select-Object -First 1
                if ($incidentTypeOracleError) {
                    $result.IncidentTypeStatus = 'Failed'
                    $result.IncidentTypeError = $incidentTypeOracleError.Trim()
                }
                else {
                    $result.IncidentTypeStatus = 'No incidents'
                }
            }

            $incidentsByServer = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $incidentServerFile) {
                foreach ($incidentServerLine in (Get-Content -LiteralPath $incidentServerFile -ErrorAction SilentlyContinue)) {
                    $incidentServerParts = $incidentServerLine.Trim() -split '\|'
                    if ($incidentServerParts.Count -eq 2 -and $incidentServerParts[1].Trim() -match '^\d+$') {
                        [void]$incidentsByServer.Add([pscustomobject]@{
                            ServerName = $incidentServerParts[0].Trim()
                            Count      = [long]$incidentServerParts[1].Trim()
                        })
                    }
                }
            }
            $result.IncidentsByServer = @($incidentsByServer)
            if ($incidentsByServer.Count -gt 0) {
                $result.IncidentServerStatus = 'Successful'
            }
            elseif (Test-Path -LiteralPath $incidentServerFile) {
                $incidentServerOracleError = Get-Content -LiteralPath $incidentServerFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'ORA-\d+' } | Select-Object -First 1
                if ($incidentServerOracleError) {
                    $result.IncidentServerStatus = 'Failed'
                    $result.IncidentServerError = $incidentServerOracleError.Trim()
                }
                else {
                    $result.IncidentServerStatus = 'No incidents'
                }
            }

            $topPolicies = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $topPolicyFile) {
                foreach ($topPolicyLine in (Get-Content -LiteralPath $topPolicyFile -ErrorAction SilentlyContinue)) {
                    $topPolicyParts = $topPolicyLine.Trim() -split '\|'
                    if ($topPolicyParts.Count -eq 2 -and $topPolicyParts[1].Trim() -match '^\d+$') {
                        [void]$topPolicies.Add([pscustomobject]@{
                            PolicyName = $topPolicyParts[0].Trim()
                            Count      = [long]$topPolicyParts[1].Trim()
                        })
                    }
                }
            }
            $result.TopPolicies = @($topPolicies)
            if ($topPolicies.Count -gt 0) {
                $result.TopPolicyStatus = 'Successful'
            }
            elseif (Test-Path -LiteralPath $topPolicyFile) {
                $topPolicyOracleError = Get-Content -LiteralPath $topPolicyFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'ORA-\d+' } | Select-Object -First 1
                if ($topPolicyOracleError) {
                    $result.TopPolicyStatus = 'Failed'
                    $result.TopPolicyError = $topPolicyOracleError.Trim()
                }
                else {
                    $result.TopPolicyStatus = 'No incidents'
                }
            }

            $topNetworkSenders = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $networkSenderFile) {
                foreach ($networkSenderLine in (Get-Content -LiteralPath $networkSenderFile -ErrorAction SilentlyContinue)) {
                    $networkSenderParts = $networkSenderLine.Trim() -split '\|'
                    if ($networkSenderParts.Count -eq 2 -and $networkSenderParts[1].Trim() -match '^\d+$') {
                        [void]$topNetworkSenders.Add([pscustomobject]@{
                            Sender = $networkSenderParts[0].Trim()
                            Count  = [long]$networkSenderParts[1].Trim()
                        })
                    }
                }
            }
            $result.TopNetworkSenders = @($topNetworkSenders)
            if ($topNetworkSenders.Count -gt 0) {
                $result.NetworkSenderStatus = 'Successful'
            }
            elseif (Test-Path -LiteralPath $networkSenderFile) {
                $networkSenderOracleError = Get-Content -LiteralPath $networkSenderFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'ORA-\d+' } | Select-Object -First 1
                if ($networkSenderOracleError) {
                    $result.NetworkSenderStatus = 'Failed'
                    $result.NetworkSenderError = $networkSenderOracleError.Trim()
                }
                else {
                    $result.NetworkSenderStatus = 'No incidents'
                }
            }

            $topEndpointUsers = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $endpointUserFile) {
                foreach ($endpointUserLine in (Get-Content -LiteralPath $endpointUserFile -ErrorAction SilentlyContinue)) {
                    $endpointUserParts = $endpointUserLine.Trim() -split '\|'
                    if ($endpointUserParts.Count -eq 2 -and $endpointUserParts[1].Trim() -match '^\d+$') {
                        [void]$topEndpointUsers.Add([pscustomobject]@{
                            UserName = $endpointUserParts[0].Trim()
                            Count    = [long]$endpointUserParts[1].Trim()
                        })
                    }
                }
            }
            $result.TopEndpointUsers = @($topEndpointUsers)
            if ($topEndpointUsers.Count -gt 0) {
                $result.EndpointUserStatus = 'Successful'
            }
            elseif (Test-Path -LiteralPath $endpointUserFile) {
                $endpointUserOracleError = Get-Content -LiteralPath $endpointUserFile -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'ORA-\d+' } | Select-Object -First 1
                if ($endpointUserOracleError) {
                    $result.EndpointUserStatus = 'Failed'
                    $result.EndpointUserError = $endpointUserOracleError.Trim()
                }
                else {
                    $result.EndpointUserStatus = 'No incidents'
                }
            }

            if (Test-Path -LiteralPath $policySummaryFile) {
                $policySummaryLines = @(Get-Content -LiteralPath $policySummaryFile -ErrorAction SilentlyContinue)
                $policySummaryLine = $policySummaryLines | Where-Object { $_.Trim() -match '^\d+\|\d+\|\d+$' } | Select-Object -First 1
                if ($null -ne $policySummaryLine) {
                    $policySummaryParts = $policySummaryLine.Trim() -split '\|'
                    $result.PolicyTotalCount = $policySummaryParts[0]
                    $result.PolicyGroupCount = $policySummaryParts[1]
                    $result.UnusedPolicyCount = $policySummaryParts[2]
                    $result.PolicySummaryStatus = 'Successful'
                }
                else {
                    $policySummaryOracleError = $policySummaryLines | Where-Object { $_ -match 'ORA-\d+' } | Select-Object -First 1
                    $result.PolicySummaryStatus = 'Failed'
                    if ($policySummaryOracleError) { $result.PolicySummaryError = $policySummaryOracleError.Trim() }
                }
            }

            $unusedPolicies = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $unusedPolicyFile) {
                foreach ($unusedPolicyLine in (Get-Content -LiteralPath $unusedPolicyFile -ErrorAction SilentlyContinue)) {
                    if ($unusedPolicyLine -match 'ORA-\d+') { continue }
                    $unusedPolicyParts = $unusedPolicyLine.Trim() -split '\|'
                    if ($unusedPolicyParts.Count -eq 2 -and -not [string]::IsNullOrWhiteSpace($unusedPolicyParts[0])) {
                        [void]$unusedPolicies.Add([pscustomobject]@{
                            PolicyName  = $unusedPolicyParts[0].Trim()
                            PolicyGroup = $unusedPolicyParts[1].Trim()
                        })
                    }
                }
            }
            $result.UnusedPolicies = @($unusedPolicies)

            if (Test-Path -LiteralPath $patternSummaryFile) {
                $patternSummaryLine = @(Get-Content -LiteralPath $patternSummaryFile -ErrorAction SilentlyContinue) |
                    Where-Object { $_.Trim() -match '^\d+\|\d+\|\d+\|\d+$' } | Select-Object -First 1
                if ($null -ne $patternSummaryLine) {
                    $patternSummaryParts = $patternSummaryLine.Trim() -split '\|'
                    $result.PatternActiveCount = $patternSummaryParts[0]
                    $result.PatternUserEntries = $patternSummaryParts[1]
                    $result.PatternIpEntries = $patternSummaryParts[2]
                    $result.PatternUrlEntries = $patternSummaryParts[3]
                    $result.PatternSummaryStatus = 'Successful'
                }
                else {
                    $result.PatternSummaryStatus = 'Failed'
                }
            }

            $patternsActive = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $patternListFile) {
                foreach ($patternLine in (Get-Content -LiteralPath $patternListFile -ErrorAction SilentlyContinue)) {
                    if ($patternLine -match 'ORA-\d+') { continue }
                    $patternParts = $patternLine.Trim() -split '\|'
                    if ($patternParts.Count -eq 7 -and $patternParts[0] -match '^[AD]$' -and
                        $patternParts[2] -match '^\d+$' -and $patternParts[3] -match '^\d+$' -and $patternParts[4] -match '^\d+$' -and
                        $patternParts[6].Trim() -match '^-?\d+$') {
                        $patternTypeId = [int]$patternParts[6].Trim()
                        $patternTypeLabel = switch ($patternTypeId) {
                            2 { 'Recipient' }
                            4 { 'Sender' }
                            default { "Tip $patternTypeId" }
                        }
                        $patternItem = [pscustomobject]@{
                            PatternName = $patternParts[1].Trim()
                            PatternType = $patternTypeLabel
                            UserEntries = [int]$patternParts[2]
                            IpEntries   = [int]$patternParts[3]
                            UrlEntries  = [int]$patternParts[4]
                            Modified    = $patternParts[5].Trim()
                        }
                        if ($patternParts[0] -eq 'A') { [void]$patternsActive.Add($patternItem) }
                    }
                }
            }
            $result.PatternsActive = @($patternsActive)

            $consoleUsers = [System.Collections.Generic.List[object]]::new()
            $consoleRoles = [System.Collections.Generic.List[object]]::new()
            if (Test-Path -LiteralPath $consoleAccessFile) {
                $consoleAccessLines = @(Get-Content -LiteralPath $consoleAccessFile -ErrorAction SilentlyContinue)
                foreach ($accessLine in $consoleAccessLines) {
                    if ($accessLine -match 'ORA-\d+') { continue }
                    $accessParts = $accessLine.Trim() -split '\|'
                    if ($accessParts[0] -eq 'U' -and $accessParts.Count -eq 13 -and $accessParts[1] -match '^\d+$') {
                        $authMethods = @()
                        if ($accessParts[5] -eq '1') { $authMethods += 'Parola' }
                        if ($accessParts[6] -eq '1') { $authMethods += 'Sertifika' }
                        if ($accessParts[7] -eq '1') { $authMethods += 'SAML' }
                        if ($accessParts[11] -eq '1') { $authMethods += 'AD' }
                        $daysSinceActive = $null
                        $lastActiveText = $accessParts[9].Trim()
                        $parsedActive = [datetime]::MinValue
                        if ([datetime]::TryParseExact($lastActiveText, 'yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedActive)) {
                            $daysSinceActive = [int]((Get-Date) - $parsedActive).TotalDays
                        }
                        $signInEnabled = ($accessParts[5] -eq '1' -or $accessParts[6] -eq '1' -or $accessParts[7] -eq '1') -and ($accessParts[10].Trim() -eq '-')
                        [void]$consoleUsers.Add([pscustomobject]@{
                            UserId         = [int]$accessParts[1]
                            UserName       = $accessParts[2].Trim()
                            Email          = $accessParts[3].Trim()
                            IsApiUser      = ($accessParts[4] -eq '1')
                            Status         = $(if ($signInEnabled) { 'Enabled' } else { 'Disabled' })
                            AuthMethods    = $(if ($authMethods.Count -gt 0) { $authMethods -join ', ' } else { '-' })
                            FailedAttempts = [int]$accessParts[8]
                            LastActive     = $lastActiveText
                            DaysSinceActive = $daysSinceActive
                            LastLockout    = $accessParts[10].Trim()
                            Roles          = $accessParts[12].Trim()
                        })
                    }
                    elseif ($accessParts[0] -eq 'R' -and $accessParts.Count -eq 5 -and $accessParts[1] -match '^\d+$' -and $accessParts[4] -match '^\d+$') {
                        [void]$consoleRoles.Add([pscustomobject]@{
                            RoleName  = $accessParts[2].Trim()
                            AdManaged = ($accessParts[3] -eq '1')
                            UserCount = [int]$accessParts[4]
                        })
                    }
                }
                $result.ConsoleUsers = @($consoleUsers)
                $result.ConsoleRoles = @($consoleRoles)
                if ($consoleUsers.Count -gt 0 -or $consoleRoles.Count -gt 0) { $result.ConsoleAccessStatus = 'Successful' }
                else { $result.ConsoleAccessStatus = 'Failed' }
            }

            if (Test-Path -LiteralPath $integrationFile) {
                $adConnections = [System.Collections.Generic.List[object]]::new()
                $ocrConfigs = [System.Collections.Generic.List[object]]::new()
                $integrationCountsFound = $false
                foreach ($integrationLine in (Get-Content -LiteralPath $integrationFile -ErrorAction SilentlyContinue)) {
                    if ($integrationLine -match 'ORA-\d+') { continue }
                    $integrationParts = $integrationLine.Trim() -split '\|'
                    if ($integrationParts[0] -eq 'C' -and $integrationParts.Count -eq 6) {
                        $result.AdLdapDataSources = $integrationParts[2]
                        $result.AdLdapLoginSources = $integrationParts[3]
                        $result.AdManagedRoles = $integrationParts[4]
                        $integrationCountsFound = $true
                    }
                    elseif ($integrationParts[0] -eq 'D' -and $integrationParts.Count -eq 6) {
                        [void]$adConnections.Add([pscustomobject]@{
                            Name      = $integrationParts[1].Trim()
                            Host      = $integrationParts[2].Trim()
                            Port      = $integrationParts[3].Trim()
                            UseSsl    = ($integrationParts[4] -eq '1')
                            Anonymous = ($integrationParts[5] -eq '1')
                        })
                    }
                    elseif ($integrationParts[0] -eq 'K' -and $integrationParts.Count -eq 2) {
                        $loginDomains = @($integrationParts[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and $_ -ne '-' -and $_ -ne '/' })
                        $result.AdLoginDomains = ($loginDomains -join ', ')
                    }
                    elseif ($integrationParts[0] -eq 'O' -and $integrationParts.Count -eq 5) {
                        [void]$ocrConfigs.Add([pscustomobject]@{
                            Name    = $integrationParts[1].Trim()
                            Host    = $integrationParts[2].Trim()
                            Port    = $integrationParts[3].Trim()
                            Servers = $integrationParts[4].Trim()
                        })
                    }
                }
                $result.AdConnections = @($adConnections)
                $result.OcrConfigs = @($ocrConfigs)
                $result.IntegrationStatus = $(if ($integrationCountsFound) { 'Successful' } else { 'Failed' })
            }

            if (Test-Path -LiteralPath $mipFile) {
                $mipLine = @(Get-Content -LiteralPath $mipFile -ErrorAction SilentlyContinue) |
                    Where-Object { $_.Trim() -match '^\d+\|\d+\|\d+$' } | Select-Object -First 1
                if ($null -ne $mipLine) {
                    $mipParts = $mipLine.Trim() -split '\|'
                    $result.MipTenantCount = $mipParts[0]
                    $result.MipIctCount = $mipParts[1]
                    $result.MipLabelCount = $mipParts[2]
                    $result.MipStatus = $(if (([int]$mipParts[0] + [int]$mipParts[1]) -gt 0) { 'Configured' } else { 'NotConfigured' })
                }
                else {
                    $result.MipStatus = 'Unknown'
                }
            }

            if (Test-Path -LiteralPath $pendingDeleteFile) {
                $pendingDeleteLines = @(Get-Content -LiteralPath $pendingDeleteFile -ErrorAction SilentlyContinue)
                $pendingDeleteValue = $pendingDeleteLines | Where-Object { $_.Trim() -match '^\d+$' } | Select-Object -First 1
                if ($null -ne $pendingDeleteValue) {
                    $result.PendingDeleteCount = $pendingDeleteValue.Trim()
                    $result.PendingDeleteStatus = 'Successful'
                }
                else {
                    $pendingDeleteOracleError = $pendingDeleteLines | Where-Object { $_ -match 'ORA-\d+' } | Select-Object -First 1
                    $result.PendingDeleteStatus = 'Failed'
                    if ($pendingDeleteOracleError) { $result.PendingDeleteError = $pendingDeleteOracleError.Trim() }
                }
            }
        }
        else {
            Write-Host "Oracle connection: FAILED (Exit code: $sqlExitCode, validation marker: $connectionMarkerFound)" -ForegroundColor Red
            $result.TcpAccess = 'Failed'
            $result.DatabaseLogin = 'Failed'
            $result.ErrorMessage = 'SQL*Plus did not return the expected CONNECTION_OK validation marker.'
        }
    }
    catch {
        $result.DatabaseLogin = 'Failed'
        $result.ErrorMessage = $_.Exception.Message
        Write-Host "Oracle connection error: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Remove-Item -Path $sqlFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $sqlMarkerFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $dlpInfoFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $agentVersionFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $detectionServerFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $systemEventFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $eventCoverageFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oracleInfoFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oracleHistoryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $oracleSqlPatchFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $tablespaceFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $incidentTypeFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $incidentServerFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $topPolicyFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $networkSenderFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $endpointUserFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $pendingDeleteFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $policySummaryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $unusedPolicyFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $patternSummaryFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $patternListFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $consoleAccessFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $integrationFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $mipFile -Force -ErrorAction SilentlyContinue
    }

    [pscustomobject]$result
}

if ($CpuWarningPercent -ge $CpuCriticalPercent) {
    throw 'CpuWarningPercent must be lower than CpuCriticalPercent.'
}
if ($MemoryWarningUsedPercent -ge $MemoryCriticalUsedPercent) {
    throw 'MemoryWarningUsedPercent must be lower than MemoryCriticalUsedPercent.'
}
if ($DiskWarningFreePercent -le $DiskCriticalFreePercent) {
    throw 'DiskWarningFreePercent must be higher than DiskCriticalFreePercent.'
}

Clear-Host

Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ' DLP Health Check' -ForegroundColor White
Write-Host ' FIRAT AYDIN' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ''
Write-Host 'A DLP installation can be one of two types: Two-tier (the Enforce Server and the Oracle database on the SAME server) or Three-tier (the Enforce Server and the Oracle database on SEPARATE servers).' -ForegroundColor Gray
Write-Host 'The health check evaluates the hardware recommendations according to the deployment type you select.' -ForegroundColor Gray
Write-Host ''

if ([string]::IsNullOrWhiteSpace($CustomerName)) {
    $enteredCustomerName = Read-Host -Prompt 'Customer name (for the report title, may be left empty)'
    if (-not [string]::IsNullOrWhiteSpace($enteredCustomerName)) {
        $CustomerName = $enteredCustomerName.Trim()
    }
    Write-Host ''
}

if ([string]::IsNullOrWhiteSpace($DeploymentTier)) {
    Write-Host 'Which deployment type is your system?' -ForegroundColor White
    Write-Host '  [2] Two-tier   (Enforce Server + Oracle on the same server)'
    Write-Host '  [3] Three-tier (Enforce Server and Oracle on separate servers)'
    Write-Host '  [B] I do not know (detected automatically)'
    while ([string]::IsNullOrWhiteSpace($DeploymentTier)) {
        $tierAnswer = (Read-Host -Prompt 'Your choice (2 / 3 / B)').Trim().ToLowerInvariant()
        switch -Regex ($tierAnswer) {
            '^(2|two|two-tier|twotier)$'         { $DeploymentTier = 'TwoTier' }
            '^(3|three|three-tier|threetier)$'   { $DeploymentTier = 'ThreeTier' }
            '^(b|unknown|dont know|do not know)$'           { $DeploymentTier = 'Unknown' }
            default { Write-Host 'Invalid choice. Please enter 2, 3 or B.' -ForegroundColor Yellow }
        }
    }
    Write-Host ''
}

$findings = [System.Collections.Generic.List[object]]::new()
$collectionErrors = [System.Collections.Generic.List[string]]::new()
$startedAt = Get-Date

try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $processors = @(Get-CimInstance -ClassName Win32_Processor)
}
catch {
    throw "Core system information could not be collected: $($_.Exception.Message)"
}

$totalPhysicalCores = [int](($processors | Measure-Object -Property NumberOfCores -Sum).Sum)
$totalLogicalCpu = [int](($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
$totalMemoryGB = Convert-BytesToGB -Bytes ([double]$computerSystem.TotalPhysicalMemory)
$freeMemoryGB = [math]::Round(([double]$operatingSystem.FreePhysicalMemory * 1KB / 1GB), 2)
$usedMemoryGB = [math]::Round(($totalMemoryGB - $freeMemoryGB), 2)
$memoryUsedPercent = if ($totalMemoryGB -gt 0) {
    [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 1)
} else { 0 }
$lastBoot = $operatingSystem.LastBootUpTime
$uptime = (Get-Date) - $lastBoot
$uptimeDays = [math]::Floor($uptime.TotalDays)
$uptimeStatus = if ($uptimeDays -gt 45) { 'Warning' } else { 'Normal' }
$uptimeNote = if ($uptimeDays -gt 45) {
    'The server has been running for more than 45 days. A planned machine restart is recommended after checking change and maintenance procedures.'
} else {
    'The server uptime is within the configured 45-day threshold.'
}
Add-Finding -List $findings -Category 'System' -Metric 'Uptime' `
    -Value ("{0} days" -f $uptimeDays) -Status $uptimeStatus -Note $uptimeNote

$memoryStatus = Get-Status -Value $memoryUsedPercent `
    -WarningThreshold $MemoryWarningUsedPercent `
    -CriticalThreshold $MemoryCriticalUsedPercent
$memoryNote = switch ($memoryStatus) {
    'Critical' { 'Memory pressure is critical. Check DLP/Java processes, paging and sustained usage.' }
    'Warning'  { 'Memory usage is high. Monitor whether this level is sustained.' }
    default    { 'Memory usage is within the configured threshold.' }
}
Add-Finding -List $findings -Category 'Memory' -Metric 'Used memory' `
    -Value ("{0}% ({1}/{2} GB)" -f $memoryUsedPercent, $usedMemoryGB, $totalMemoryGB) `
    -Status $memoryStatus -Note $memoryNote

$cpuAverage = $null
try {
    $cpuSamples = for ($index = 0; $index -lt $CpuSampleCount; $index++) {
        $sample = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor `
            -Filter "Name='_Total'"
        if ($null -ne $sample.PercentProcessorTime) {
            [double]$sample.PercentProcessorTime
        }
        if ($index -lt ($CpuSampleCount - 1)) {
            Start-Sleep -Seconds $CpuSampleIntervalSeconds
        }
    }

    if (@($cpuSamples).Count -gt 0) {
        $cpuAverage = [math]::Round((($cpuSamples | Measure-Object -Average).Average), 1)
        $cpuStatus = Get-Status -Value $cpuAverage `
            -WarningThreshold $CpuWarningPercent `
            -CriticalThreshold $CpuCriticalPercent
        $cpuNote = switch ($cpuStatus) {
            'Critical' { 'CPU usage is critical during sampling. Confirm with longer-term monitoring and identify high-CPU processes.' }
            'Warning'  { 'CPU usage is high during sampling. Confirm whether the load is sustained.' }
            default    { 'CPU usage is within the configured threshold during sampling.' }
        }
        Add-Finding -List $findings -Category 'CPU' -Metric 'Average usage' `
            -Value ("{0}%" -f $cpuAverage) `
            -Status $cpuStatus -Note $cpuNote
    }
    else {
        throw 'No CPU samples were returned.'
    }
}
catch {
    $collectionErrors.Add("CPU performance data could not be collected: $($_.Exception.Message)")
    Add-Finding -List $findings -Category 'CPU' -Metric 'Average usage' -Value 'N/A' `
        -Status 'Unknown' -Note 'CPU performance counters could not be queried.'
}

$logicalDisks = @()
try {
    $logicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' |
        Sort-Object -Property DeviceID)

    foreach ($disk in $logicalDisks) {
        $sizeGB = Convert-BytesToGB -Bytes ([double]$disk.Size)
        $freeGB = Convert-BytesToGB -Bytes ([double]$disk.FreeSpace)
        $freePercent = if ([double]$disk.Size -gt 0) {
            [math]::Round(([double]$disk.FreeSpace / [double]$disk.Size) * 100, 1)
        } else { 0 }

        $diskStatus = Get-Status -Value $freePercent `
            -WarningThreshold $DiskWarningFreePercent `
            -CriticalThreshold $DiskCriticalFreePercent `
            -Direction 'LowerIsWorse'
        $diskNote = switch ($diskStatus) {
            'Critical' { 'Free disk space is critical. Capacity cleanup or expansion should be prioritized.' }
            'Warning'  { 'Free disk space is low. Review growth rate and capacity planning.' }
            default    { 'Free disk space is within the configured threshold.' }
        }

        Add-Finding -List $findings -Category 'Disk' -Metric ("Drive {0}" -f $disk.DeviceID) `
            -Value ("{0}% free ({1}/{2} GB)" -f $freePercent, $freeGB, $sizeGB) `
            -Status $diskStatus -Note $diskNote
    }
}
catch {
    $collectionErrors.Add("Disk information could not be collected: $($_.Exception.Message)")
    Add-Finding -List $findings -Category 'Disk' -Metric 'Fixed drives' -Value 'N/A' `
        -Status 'Unknown' -Note 'Fixed disk information could not be queried.'
}

$dlpServices = @()
$databaseCheck = $null

try {
    $dlpServices = @(Get-DlpServices)
    if ($dlpServices.Count -eq 0) {
        Add-Finding -List $findings -Category 'DLP' -Metric 'DLP services' -Value '0 detected' `
            -Status 'Unknown' -Note 'No DLP-related Windows service was detected. Review the service matching rules.'
    }
    else {
        $stoppedAutomaticServices = @($dlpServices |
            Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
        if ($stoppedAutomaticServices.Count -gt 0) {
            Add-Finding -List $findings -Category 'DLP' -Metric 'DLP services' `
                -Value ("{0}/{1} automatic services not running" -f $stoppedAutomaticServices.Count, $dlpServices.Count) `
                -Status 'Critical' -Note 'One or more automatic DLP services are not running.'
        }
        else {
            Add-Finding -List $findings -Category 'DLP' -Metric 'DLP services' `
                -Value ("{0} detected" -f $dlpServices.Count) -Status 'Normal' `
                -Note 'All detected automatic DLP services are running.'
        }
    }
}
catch {
    $collectionErrors.Add("DLP service information could not be collected: $($_.Exception.Message)")
    Add-Finding -List $findings -Category 'DLP' -Metric 'DLP services' -Value 'N/A' `
        -Status 'Unknown' -Note 'DLP-related Windows services could not be queried.'
}

if (-not $SkipDatabaseCheck) {
    Write-Host '=== ORACLE CONNECTION INFORMATION ===' -ForegroundColor Cyan
    Write-Host 'For fields left empty, the default value in brackets is used.' -ForegroundColor DarkGray
    Write-Host ''

    $enteredDatabaseHost = Read-Host -Prompt "Oracle IP or Host [$DatabaseHost]"
    if (-not [string]::IsNullOrWhiteSpace($enteredDatabaseHost)) {
        $DatabaseHost = $enteredDatabaseHost.Trim()
    }

    $enteredDatabaseUser = Read-Host -Prompt "Oracle User [$DatabaseUser]"
    if (-not [string]::IsNullOrWhiteSpace($enteredDatabaseUser)) {
        $DatabaseUser = $enteredDatabaseUser.Trim()
    }

    $enteredDatabaseService = Read-Host -Prompt "Oracle DB / Service Name [$DatabaseServiceName]"
    if (-not [string]::IsNullOrWhiteSpace($enteredDatabaseService)) {
        $DatabaseServiceName = $enteredDatabaseService.Trim()
    }

    Write-Host ''
    $databaseCheck = Invoke-DlpDatabaseCheck -HostName $DatabaseHost -Port $DatabasePort `
        -ServiceName $DatabaseServiceName -UserName $DatabaseUser
    if ($databaseCheck.DatabaseLogin -eq 'Successful') {
        Add-Finding -List $findings -Category 'Database' -Metric 'Oracle login' `
            -Value 'Successful' -Status 'Normal' -Note 'The Enforce server can authenticate to the Oracle database.'
    }
    else {
        Add-Finding -List $findings -Category 'Database' -Metric 'Oracle login' `
            -Value $databaseCheck.DatabaseLogin -Status 'Critical' `
            -Note $(if ($databaseCheck.ErrorMessage) { $databaseCheck.ErrorMessage } else { 'Oracle database login failed.' })
    }
}

$diskTotalGB = 0.0
if (@($logicalDisks).Count -gt 0) {
    $diskTotalGB = [double](Convert-BytesToGB -Bytes ([double](@($logicalDisks) | Measure-Object -Property Size -Sum).Sum))
}
$oracleHostForTier = if ($null -ne $databaseCheck) { $databaseCheck.OracleHostName } else { '' }
$tierAssessment = Get-DlpTierAssessment -DeclaredTier $DeploymentTier `
    -LogicalCpu $totalLogicalCpu -RamGB $totalMemoryGB -DiskTotalGB $diskTotalGB `
    -DatabaseChecked (-not $SkipDatabaseCheck) -DatabaseHost $DatabaseHost -OracleHostName $oracleHostForTier

Add-Finding -List $findings -Category 'Architecture' -Metric 'Deployment tier' `
    -Value ("{0} ({1})" -f $tierAssessment.EffectiveTier, $(if ($DeploymentTier -eq 'Unknown' -or [string]::IsNullOrWhiteSpace($DeploymentTier)) { 'auto-detected' } else { 'declared' })) `
    -Status $tierAssessment.ConsistencyStatus -Note $tierAssessment.ConsistencyNote
Add-Finding -List $findings -Category 'Hardware' -Metric 'Broadcom sizing check' `
    -Value ("{0} logical CPU / {1} GB RAM / {2} GB disk -> {3}" -f $totalLogicalCpu, $totalMemoryGB, $diskTotalGB, $tierAssessment.LevelName) `
    -Status $tierAssessment.HardwareStatus -Note $tierAssessment.HardwareNote

if ($null -ne $databaseCheck -and $databaseCheck.DatabaseLogin -eq 'Successful' -and $databaseCheck.OracleInfoStatus -eq 'Successful') {
    switch ($databaseCheck.OracleRuStatus) {
        'Match' {
            Add-Finding -List $findings -Category 'Database' -Metric 'Oracle patch level' `
                -Value ("RU {0}" -f $databaseCheck.OracleBinaryRu) -Status 'Normal' `
                -Note "Oracle binary Release Update ($($databaseCheck.OracleBinaryRu)) matches the database patch registry ($($databaseCheck.OracleRegistryRu))."
        }
        'Mismatch' {
            Add-Finding -List $findings -Category 'Database' -Metric 'Oracle patch level' `
                -Value ("Binary {0} / Registry {1}" -f $databaseCheck.OracleBinaryRu, $databaseCheck.OracleRegistryRu) -Status 'Warning' `
                -Note 'The Oracle binary Release Update level differs from the last Release Update recorded in the database patch registry (datapatch may not have been run). Confirm the effective patch level with the DBA before evaluating CVE advisories.'
        }
        default {
            Add-Finding -List $findings -Category 'Database' -Metric 'Oracle patch level' `
                -Value ("Binary {0}" -f $databaseCheck.OracleBinaryRu) -Status 'Unknown' `
                -Note 'The database patch registry could not be read or parsed, so the binary and registry levels could not be compared.'
        }
    }
}

$syslogInfo = Get-DlpSyslogInfo -SkipConnectivityTest:$SkipSyslogConnectivityTest
if ($syslogInfo.Status -eq 'Configured') {
    $syslogTarget = "{0}://{1}:{2}" -f $syslogInfo.Protocol, $syslogInfo.SyslogHost, $syslogInfo.Port
    switch ($syslogInfo.Connectivity) {
        'Unreachable' {
            Add-Finding -List $findings -Category 'Integration' -Metric 'Syslog (system events)' -Value $syslogTarget -Status 'Warning' `
                -Note "Syslog is configured (level: $($syslogInfo.LevelText)) but the TCP connection to the syslog server could not be established within 3 seconds."
        }
        'Reachable' {
            Add-Finding -List $findings -Category 'Integration' -Metric 'Syslog (system events)' -Value $syslogTarget -Status 'Normal' `
                -Note "Syslog is configured (level: $($syslogInfo.LevelText)) and the syslog server accepted a TCP connection. Message delivery itself is not verified."
        }
        default {
            Add-Finding -List $findings -Category 'Integration' -Metric 'Syslog (system events)' -Value $syslogTarget -Status 'Normal' `
                -Note "Syslog is configured (level: $($syslogInfo.LevelText)). Connectivity could not be verified for this protocol/setting."
        }
    }
}

$licenseInfo = Get-DlpLicenseInfo
$licenseKeys = @($licenseInfo.LicenseKeys)
$earliestExpiry = if ($licenseKeys.Count -gt 0) { (@($licenseKeys | ForEach-Object { $_.ExpiryDate } | Where-Object { $_ -ne '-' } | Sort-Object)[0]) } else { '-' }
switch ($licenseInfo.Status) {
    'OK' {
        Add-Finding -List $findings -Category 'License' -Metric 'DLP license' -Value ("OK ({0} products)" -f $licenseKeys.Count) `
            -Status 'Normal' -Note "All license keys in $($licenseInfo.CurrentFile) are valid. Earliest expiry: $earliestExpiry."
    }
    'Expiring soon' {
        Add-Finding -List $findings -Category 'License' -Metric 'DLP license' -Value 'Expiring soon' `
            -Status 'Warning' -Note "One or more license keys are within the warning period. Earliest expiry: $earliestExpiry."
    }
    'Expired' {
        Add-Finding -List $findings -Category 'License' -Metric 'DLP license' -Value 'Expired' `
            -Status 'Critical' -Note "One or more license keys have expired. Earliest expiry: $earliestExpiry."
    }
    default {
        $licenseNote = if ($licenseInfo.Error) { [string]$licenseInfo.Error } else { 'No DLP license (.slf) file was found in the searched ProgramData locations.' }
        Add-Finding -List $findings -Category 'License' -Metric 'DLP license' -Value 'Not found' -Status 'Unknown' -Note $licenseNote
    }
}

Write-Host 'DLP SERVER HARDWARE AND RESOURCE HEALTH CHECK' -ForegroundColor White
Write-Host ('Server       : {0}' -f $env:COMPUTERNAME)
Write-Host ('Collected at : {0:yyyy-MM-dd HH:mm:ss}' -f $startedAt)

Write-Section -Title 'SYSTEM INFORMATION'
[pscustomobject]@{
    ComputerName     = $computerSystem.Name
    Manufacturer     = $computerSystem.Manufacturer
    Model            = $computerSystem.Model
    OperatingSystem  = $operatingSystem.Caption
    OSVersion        = $operatingSystem.Version
    Architecture     = $operatingSystem.OSArchitecture
    LastBoot         = $lastBoot.ToString('dd.MM.yyyy HH:mm:ss')
} | Format-List

Write-Host '*** SERVER UPTIME ***' -ForegroundColor White
Write-Host ("      {0} DAYS      " -f $uptimeDays) -ForegroundColor $(
    if ($uptimeDays -gt 45) { 'Red' } else { 'Green' }
)
if ($uptimeDays -gt 45) {
    Write-Host 'Machine restart is recommended.' -ForegroundColor Red
}

Write-Section -Title 'PROCESSOR AND MEMORY'
[pscustomobject]@{
    ProcessorModel    = (($processors | Select-Object -ExpandProperty Name -Unique) -join '; ')
    VirtualCPUs       = $totalLogicalCpu
    VirtualSockets    = $processors.Count
    CoresPerSocket    = if ($processors.Count -gt 0) {
        [int]($totalPhysicalCores / $processors.Count)
    } else { 'N/A' }
    CpuUsagePct       = if ($null -ne $cpuAverage) { $cpuAverage } else { 'N/A' }
    TotalMemoryGB     = $totalMemoryGB
    UsedMemoryGB      = $usedMemoryGB
} | Format-List

Write-Section -Title 'DEPLOYMENT TIER AND BROADCOM HARDWARE RECOMMENDATION'
Write-Host ("Deployment tier : {0}" -f $tierAssessment.EffectiveTier) -ForegroundColor Cyan
Write-Host ("Result          : {0}" -f $tierAssessment.LevelName) -ForegroundColor Cyan
$tierAssessment.Rows |
    Select-Object Metric, Current, Min, Small, Medium, Large, Level |
    Format-Table -AutoSize |
    Out-Host
Write-Host $tierAssessment.HardwareNote -ForegroundColor DarkGray
Write-Host 'Source: Broadcom Symantec DLP 25.1 - Hardware Requirements (Enforce Server / Oracle recommendations).' -ForegroundColor DarkGray

Write-Section -Title 'FIXED DISKS'
if ($logicalDisks.Count -gt 0) {
    $logicalDisks | ForEach-Object {
        $diskSizeGB = Convert-BytesToGB -Bytes ([double]$_.Size)
        $diskFreeGB = Convert-BytesToGB -Bytes ([double]$_.FreeSpace)
        [pscustomobject]@{
            Drive       = $_.DeviceID
            VolumeName  = $_.VolumeName
            FileSystem  = $_.FileSystem
            SizeGB      = $diskSizeGB
            UsedGB      = [math]::Round(($diskSizeGB - $diskFreeGB), 2)
            FreeGB      = $diskFreeGB
            FreePercent = if ([double]$_.Size -gt 0) {
                [math]::Round(([double]$_.FreeSpace / [double]$_.Size) * 100, 1)
            } else { 0 }
        }
    } | Format-Table -AutoSize
}
else {
    Write-Host 'No fixed disk information was returned.' -ForegroundColor DarkYellow
}

Write-Section -Title 'DLP COMPONENTS AND SERVICES'
if ($dlpServices.Count -gt 0) {
    $dlpServices |
        Select-Object Name, DisplayName, State, StartMode |
        Format-Table -AutoSize
}
else {
    Write-Host 'No DLP-related Windows services were detected.' -ForegroundColor DarkYellow
}

Write-Section -Title 'ORACLE DATABASE CONNECTION'
if ($SkipDatabaseCheck) {
    Write-Host 'Database check was skipped by parameter.' -ForegroundColor DarkYellow
}
elseif ($databaseCheck) {
    [pscustomobject]@{
        DatabaseHost       = $DatabaseHost
        DatabasePort       = $DatabasePort
        DatabaseService    = $DatabaseServiceName
        SqlPlusVersion     = $databaseCheck.SqlPlusVersion
        TcpAccess          = $databaseCheck.TcpAccess
        DatabaseLogin      = $databaseCheck.DatabaseLogin
        DatabaseName       = $databaseCheck.DatabaseName
        ConnectedUser      = $databaseCheck.ConnectedUser
    } | Format-List

    if ($databaseCheck.ErrorMessage) {
        Write-Host ("Database note: {0}" -f $databaseCheck.ErrorMessage) -ForegroundColor Red
    }

    Write-Section -Title 'DLP SYSTEM INFORMATION'
    if ($databaseCheck.DlpInfoStatus -eq 'Successful') {
        [pscustomobject]@{
            DlpVersion        = $databaseCheck.DlpVersion
            DlpSchemaVersion  = $databaseCheck.DlpSchemaVersion
            DlpInstalledAt    = $databaseCheck.DlpInstalledAt
            InstallAgentCount = $databaseCheck.InstallAgentCount
            ReportingAgentCount = $databaseCheck.ReportingAgentCount
            DisableAgentCount = $databaseCheck.DisableAgentCount
            NotReportingAgentCount = $databaseCheck.NotReportingAgentCount
            DeletedAgentCount = $databaseCheck.DeletedAgentCount
        } | Format-List
    }
    else {
        Write-Host 'DLP system information could not be read from the Oracle schema.' -ForegroundColor Red
    }


    Write-Section -Title 'AGENT VERSION INFORMATION'
    if ($databaseCheck.AgentVersionStatus -eq 'Successful') {
        $databaseCheck.AgentVersions |
            Select-Object Count, Version |
            Format-Table -AutoSize |
            Out-Host

        $versionedAgentCount = [int](($databaseCheck.AgentVersions |
            Measure-Object -Property Count -Sum).Sum)
        Write-Host ("DistinctAgentVersionCount : {0}" -f @($databaseCheck.AgentVersions).Count) -ForegroundColor Cyan
        Write-Host ("InstalledAgentCount       : {0}" -f $versionedAgentCount) -ForegroundColor Cyan

        if ($databaseCheck.InstallAgentCount -match '^\d+$' -and
            $versionedAgentCount -ne [int]$databaseCheck.InstallAgentCount) {
            Write-Host ("Warning: Agent version total ({0}) does not match InstallAgentCount ({1})." -f `
                $versionedAgentCount, $databaseCheck.InstallAgentCount) -ForegroundColor Yellow
        }
    }
    elseif ($databaseCheck.AgentVersionStatus -eq 'No agents') {
        Write-Host 'No installed (non-deleted) agent record was found.' -ForegroundColor DarkYellow
    }
    else {
        Write-Host ("Agent version information could not be read: {0}" -f `
            $databaseCheck.AgentVersionError) -ForegroundColor Red
    }

    Write-Section -Title 'DLP DETECTION SERVERS AND CHANNELS'
    if (@($databaseCheck.DetectionServers).Count -gt 0) {
        $databaseCheck.DetectionServers |
            Select-Object ServerName, HostName, Version, Product, Channel, Status, LastHeartbeat |
            Format-Table -AutoSize |
            Out-Host

        $detectionServerCount = @(
            $databaseCheck.DetectionServers |
                ForEach-Object { $_.MonitorId } |
                Sort-Object -Unique
        ).Count

        Write-Host ("DetectionServerCount : {0}" -f $detectionServerCount) -ForegroundColor Cyan
        $consoleServerStates = @{}
        foreach ($consoleServer in @($databaseCheck.DetectionServers)) {
            $consoleKey = [string]$consoleServer.MonitorId
            if (-not $consoleServerStates.ContainsKey($consoleKey)) { $consoleServerStates[$consoleKey] = [string]$consoleServer.Status }
            elseif ([string]$consoleServer.Status -ne 'Running') { $consoleServerStates[$consoleKey] = 'Unknown' }
        }
        $consoleRunning = @($consoleServerStates.Values | Where-Object { $_ -eq 'Running' }).Count
        Write-Host ("Running : {0} | Unknown : {1}" -f $consoleRunning, ($consoleServerStates.Count - $consoleRunning)) -ForegroundColor Cyan
        Write-Host 'Note: Detection Server version is read from the Enforce STATUSES table (last reported value); N/A means no version has been reported.' -ForegroundColor DarkYellow
        Write-Host ("Note: Status is derived from the last heartbeat time in Enforce (Running = heartbeat within {0} minutes; Unknown = heartbeat lost or no record, same as the Enforce console)." -f [math]::Round($HeartbeatStaleSeconds / 60)) -ForegroundColor DarkYellow
    }
    else {
        Write-Host 'No active Detection Server/channel record was found.' -ForegroundColor DarkYellow
    }

    Write-Section -Title 'DETECTION SERVER ERROR AND WARNING EVENTS'
    if (@($databaseCheck.SystemEventServers).Count -gt 0) {
        Write-Host ("Servers queried ({0}) - errors / warnings in the last {1} day(s):" -f @($databaseCheck.SystemEventServers).Count, $SystemEventLookbackDays) -ForegroundColor DarkGray
        $databaseCheck.SystemEventServers | Select-Object ServerName, Errors, Warnings | Format-Table -AutoSize | Out-Host
    }
    if ($databaseCheck.SystemEventStatus -eq 'Successful') {
        Write-Host ("Period: Last {0} day(s) | Same event codes are grouped per server" -f `
            $SystemEventLookbackDays) -ForegroundColor DarkGray
        Write-Host ('{0,-8} {1,-29} {2,-16} {3,-7} {4,-6} {5,-19} {6}' -f `
            'Type', 'ServerName', 'HostName', 'Code', 'Count', 'LastTime', 'Message') -ForegroundColor Cyan
        Write-Host ('-' * 120) -ForegroundColor DarkGray

        foreach ($systemEvent in $databaseCheck.SystemEvents) {
            $eventText = '{0,-8} {1,-29} {2,-16} {3,-7} {4,-6} {5,-19} {6}' -f `
                $systemEvent.Type, $systemEvent.ServerName, $systemEvent.HostName, `
                $systemEvent.EventCode, $systemEvent.Count, $systemEvent.LastTime, $systemEvent.Message
            $eventColor = if ($systemEvent.Type -eq 'Error') { 'Red' } else { 'Yellow' }
            Write-Host $eventText -ForegroundColor $eventColor
        }

        $errorEventCount = [int](@($databaseCheck.SystemEvents | Where-Object Type -eq 'Error') | Measure-Object -Property Count -Sum).Sum
        $warningEventCount = [int](@($databaseCheck.SystemEvents | Where-Object Type -eq 'Warning') | Measure-Object -Property Count -Sum).Sum
        Write-Host ''
        Write-Host ("ErrorEventCount   : {0}" -f $errorEventCount) -ForegroundColor Red
        Write-Host ("WarningEventCount : {0}" -f $warningEventCount) -ForegroundColor Yellow
        Write-Host 'Unmapped event codes are displayed with their Oracle resource key.' -ForegroundColor DarkGray
    }
    elseif ($databaseCheck.SystemEventStatus -eq 'No events') {
        Write-Host ("No Error or Warning event was found in the last {0} day(s)." -f `
            $SystemEventLookbackDays) -ForegroundColor Green
    }
    else {
        Write-Host ("System events could not be read: {0}" -f $databaseCheck.SystemEventError) -ForegroundColor Red
    }

    Write-Section -Title 'ORACLE DATABASE INFORMATION'
    if ($databaseCheck.OracleInfoStatus -eq 'Successful') {
        [pscustomobject]@{
            OracleVersion     = $databaseCheck.OracleVersion
            DatabaseName      = $databaseCheck.DatabaseName
            HostName          = $databaseCheck.OracleHostName
            DatabaseVersion   = $databaseCheck.OracleDatabaseVersion
            InstanceName      = $databaseCheck.OracleInstanceName
            InstanceStartTime = $databaseCheck.OracleInstanceStartTime
            BinaryRuLevel     = $databaseCheck.OracleBinaryRu
            RegistryRuLevel   = $databaseCheck.OracleRegistryRu
            RuStatus          = $databaseCheck.OracleRuStatus
        } | Format-List

        if (@($databaseCheck.OraclePatchHistory).Count -gt 0 -or @($databaseCheck.OracleSqlPatches).Count -gt 0) {
            Write-Host 'Oracle patch history:' -ForegroundColor White
            if (@($databaseCheck.OracleSqlPatches).Count -gt 0) {
                $databaseCheck.OracleSqlPatches | Select-Object Time, Action, Status, PatchId, Description | Format-Table -AutoSize | Out-Host
            }
            else {
                $databaseCheck.OraclePatchHistory | Select-Object Time, Action, Version, Comments | Format-Table -AutoSize | Out-Host
            }
        }
        if ($databaseCheck.OracleRuStatus -eq 'Mismatch') {
            Write-Host ("Warning: the Oracle binary RU ({0}) differs from the last RU in the patch registry ({1}). Confirm the effective patch level with the DBA (datapatch may not have been run)." -f $databaseCheck.OracleBinaryRu, $databaseCheck.OracleRegistryRu) -ForegroundColor Yellow
        }
        if ($databaseCheck.OracleSqlPatchStatus -eq 'Unavailable') {
            Write-Host 'Note: DBA_REGISTRY_SQLPATCH is not readable by this user; the patch history above comes from DBA_REGISTRY_HISTORY.' -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host 'Oracle database/instance details could not be read. Access to V$VERSION, V$DATABASE or V$INSTANCE may be restricted.' -ForegroundColor Red
    }

    Write-Section -Title 'ORACLE TABLESPACE USAGE'
    if ($databaseCheck.TablespaceStatus -eq 'Successful') {
        Write-Host ('{0,-24} {1,12} {2,12} {3,12} {4,9} {5,9}' -f `
            'Tablespace', 'Used MB', 'Free MB', 'Total MB', '% Free', '% Used') -ForegroundColor Cyan
        Write-Host ('-' * 83) -ForegroundColor DarkGray

        foreach ($tablespace in $databaseCheck.Tablespaces) {
            $rowText = '{0,-24} {1,12} {2,12} {3,12} {4,9} {5,9}' -f `
                $tablespace.Tablespace, $tablespace.UsedMB, $tablespace.FreeMB, `
                $tablespace.TotalMB, $tablespace.FreePct, $tablespace.UsedPct

            if ($tablespace.UsedPct -gt 95) {
                Write-Host $rowText -ForegroundColor Red
            }
            else {
                Write-Host $rowText -ForegroundColor White
            }
        }
    }
    else {
        Write-Host $databaseCheck.TablespaceError -ForegroundColor Red
    }

    Write-Section -Title 'TOTAL INCIDENT COUNT'
    if ($databaseCheck.IncidentTypeStatus -eq 'Successful' -or $databaseCheck.IncidentTypeStatus -eq 'No incidents') {
        $consoleTotalIncidents = 0
        if ($databaseCheck.IncidentTypeStatus -eq 'Successful') {
            $consoleTotalIncidents = [long](@($databaseCheck.IncidentsByType) | Measure-Object -Property Count -Sum).Sum
        }
        $consoleTotalText = $consoleTotalIncidents.ToString('N0', [System.Globalization.CultureInfo]::GetCultureInfo('en-US'))
        Write-Host ("TotalIncidentCount : {0}" -f $consoleTotalText) -ForegroundColor Cyan
        if ($databaseCheck.PendingDeleteStatus -eq 'Successful') {
            Write-Host ("PendingDeleteCount : {0} (pending deletion, not included in the total)" -f ([long]$databaseCheck.PendingDeleteCount).ToString('N0', [System.Globalization.CultureInfo]::GetCultureInfo('en-US'))) -ForegroundColor Yellow
        }
        else {
            Write-Host 'PendingDeleteCount : could not be read' -ForegroundColor DarkYellow
        }
        if ($consoleTotalIncidents -gt 1000000) {
            Write-Host ("Your incident count ({0}) is higher than the recommended 1 million incidents. This may affect system performance." -f $consoleTotalText) -ForegroundColor Red
        }
        else {
            Write-Host ("Your incident count ({0}) has not reached the recommended limit of 1 million incidents." -f $consoleTotalText) -ForegroundColor Green
        }
    }
    else {
        Write-Host 'The total incident count could not be read.' -ForegroundColor Red
    }

    Write-Section -Title 'INCIDENT TYPE DISTRIBUTION'
    if ($databaseCheck.IncidentTypeStatus -eq 'Successful') {
        $databaseCheck.IncidentsByType | Select-Object Type, Count | Format-Table -AutoSize | Out-Host
        $totalIncidentCount = [long](($databaseCheck.IncidentsByType | Measure-Object -Property Count -Sum).Sum)
        Write-Host ("TotalIncidentCount : {0}" -f $totalIncidentCount) -ForegroundColor Cyan
    }
    elseif ($databaseCheck.IncidentTypeStatus -eq 'No incidents') {
        Write-Host 'No recorded (non-deleted) incidents were found.' -ForegroundColor DarkYellow
    }
    else {
        Write-Host ("The incident type distribution could not be read: {0}" -f $databaseCheck.IncidentTypeError) -ForegroundColor Red
    }

    Write-Section -Title 'INCIDENTS BY DETECTION SERVER'
    if ($databaseCheck.IncidentServerStatus -eq 'Successful') {
        $databaseCheck.IncidentsByServer | Select-Object ServerName, Count | Format-Table -AutoSize | Out-Host
    }
    elseif ($databaseCheck.IncidentServerStatus -eq 'No incidents') {
        Write-Host 'No incidents were found per server.' -ForegroundColor DarkYellow
    }
    else {
        Write-Host ("The per-server incident distribution could not be read: {0}" -f $databaseCheck.IncidentServerError) -ForegroundColor Red
    }

    Write-Section -Title 'POLICY SUMMARY'
    if ($databaseCheck.PolicySummaryStatus -eq 'Successful') {
        Write-Host ("TotalPolicyCount        : {0}" -f $databaseCheck.PolicyTotalCount) -ForegroundColor Cyan
        Write-Host ("TotalPolicyGroupCount   : {0}" -f $databaseCheck.PolicyGroupCount) -ForegroundColor Cyan
        Write-Host ("Policies without incident in last {0} days : {1}" -f $IncidentLookbackDays, $databaseCheck.UnusedPolicyCount) -ForegroundColor $(if ([int]$databaseCheck.UnusedPolicyCount -gt 0) { 'Yellow' } else { 'Green' })
        if (@($databaseCheck.UnusedPolicies).Count -gt 0) {
            $databaseCheck.UnusedPolicies | Select-Object PolicyName, PolicyGroup | Format-Table -AutoSize | Out-Host
            if ([int]$databaseCheck.UnusedPolicyCount -gt @($databaseCheck.UnusedPolicies).Count) {
                Write-Host ("Showing the first {0} policies (total {1})." -f @($databaseCheck.UnusedPolicies).Count, $databaseCheck.UnusedPolicyCount) -ForegroundColor DarkGray
            }
        }
    }
    else {
        Write-Host 'Policy summary could not be read.' -ForegroundColor Red
    }

    Write-Section -Title ("TOP VIOLATED POLICIES (Last {0} days, Top {1})" -f $IncidentLookbackDays, $IncidentTopCount)
    if ($databaseCheck.TopPolicyStatus -eq 'Successful') {
        $databaseCheck.TopPolicies | Select-Object PolicyName, Count | Format-Table -AutoSize | Out-Host
    }
    elseif ($databaseCheck.TopPolicyStatus -eq 'No incidents') {
        Write-Host ("No policy violations were found in the last {0} days." -f $IncidentLookbackDays) -ForegroundColor DarkYellow
    }
    else {
        Write-Host ("The most violated policies could not be read: {0}" -f $databaseCheck.TopPolicyError) -ForegroundColor Red
    }

    Write-Section -Title ("NETWORK - TOP INCIDENT-GENERATING SENDERS (Last {0} days, Top {1})" -f $IncidentLookbackDays, $IncidentTopCount)
    if ($databaseCheck.NetworkSenderStatus -eq 'Successful') {
        $databaseCheck.TopNetworkSenders | Select-Object Sender, Count | Format-Table -AutoSize | Out-Host
    }
    elseif ($databaseCheck.NetworkSenderStatus -eq 'No incidents') {
        Write-Host ("No network incidents were found in the last {0} days." -f $IncidentLookbackDays) -ForegroundColor DarkYellow
    }
    else {
        Write-Host ("The network sender distribution could not be read: {0}" -f $databaseCheck.NetworkSenderError) -ForegroundColor Red
    }

    Write-Section -Title ("ENDPOINT - TOP INCIDENT-GENERATING USERS (Last {0} days, Top {1})" -f $IncidentLookbackDays, $IncidentTopCount)
    if ($databaseCheck.EndpointUserStatus -eq 'Successful') {
        $databaseCheck.TopEndpointUsers | Select-Object UserName, Count | Format-Table -AutoSize | Out-Host
    }
    elseif ($databaseCheck.EndpointUserStatus -eq 'No incidents') {
        Write-Host ("No endpoint incidents were found in the last {0} days." -f $IncidentLookbackDays) -ForegroundColor DarkYellow
    }
    else {
        Write-Host ("The endpoint user distribution could not be read: {0}" -f $databaseCheck.EndpointUserError) -ForegroundColor Red
    }

    Write-Section -Title 'SENDER/RECIPIENT PATTERN SUMMARY'
    if ($databaseCheck.PatternSummaryStatus -eq 'Successful') {
        Write-Host ("Active patterns (visible in console) : {0}" -f $databaseCheck.PatternActiveCount) -ForegroundColor Cyan
        Write-Host ("User/e-mail/domain entries           : {0}" -f $databaseCheck.PatternUserEntries)
        Write-Host ("IP entries                           : {0}" -f $databaseCheck.PatternIpEntries)
        Write-Host ("URL domain entries                   : {0}" -f $databaseCheck.PatternUrlEntries)
        if (@($databaseCheck.PatternsActive).Count -gt 0) {
            Write-Host ''
            Write-Host 'Active patterns:' -ForegroundColor White
            $databaseCheck.PatternsActive | Select-Object PatternName, PatternType, UserEntries, IpEntries, UrlEntries, Modified | Format-Table -AutoSize | Out-Host
        }
        Write-Host 'Note: Users removed from inside a pattern are not kept in history; only the current content is stored.' -ForegroundColor DarkGray
    }
    else {
        Write-Host 'Pattern summary could not be read.' -ForegroundColor Red
    }

    Write-Section -Title 'ENFORCE CONSOLE USERS AND ROLES'
    if ($databaseCheck.ConsoleAccessStatus -eq 'Successful') {
        Write-Host ("Users: {0} | Roles: {1}" -f @($databaseCheck.ConsoleUsers).Count, @($databaseCheck.ConsoleRoles).Count) -ForegroundColor Cyan
        $databaseCheck.ConsoleUsers |
            Select-Object UserName, Status, Email, Roles, AuthMethods, LastActive, FailedAttempts, LastLockout |
            Format-Table -AutoSize | Out-Host
        $databaseCheck.ConsoleRoles | Select-Object RoleName, AdManaged, UserCount | Format-Table -AutoSize | Out-Host
        Write-Host 'Note: passwords are never read; the internal system user is excluded.' -ForegroundColor DarkGray
    }
    else {
        Write-Host 'Console users and roles could not be read.' -ForegroundColor Red
    }

    Write-Section -Title 'INTEGRATIONS (AD / OCR / MIP)'
    if ($databaseCheck.IntegrationStatus -eq 'Successful') {
        if (@($databaseCheck.AdConnections).Count -gt 0) {
            foreach ($adConnection in @($databaseCheck.AdConnections)) {
                Write-Host ("AD connection : {0} - {1}:{2} (SSL: {3})" -f $adConnection.Name, $adConnection.Host, $adConnection.Port, $(if ($adConnection.UseSsl) { 'Yes' } else { 'No' })) -ForegroundColor Green
                if (-not $adConnection.UseSsl) {
                    Write-Host '  Warning: the AD connection does not use SSL (LDAPS is recommended).' -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host 'AD connection : None' -ForegroundColor DarkYellow
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$databaseCheck.AdLoginDomains)) {
            Write-Host ("Console login with AD credentials : Yes (domains: {0})" -f $databaseCheck.AdLoginDomains) -ForegroundColor Green
        }
        else {
            Write-Host 'Console login with AD credentials : No' -ForegroundColor DarkYellow
        }
        Write-Host ("AD-managed roles : {0}" -f $databaseCheck.AdManagedRoles)
        if (@($databaseCheck.OcrConfigs).Count -gt 0) {
            foreach ($ocrConfig in @($databaseCheck.OcrConfigs)) {
                Write-Host ("OCR           : {0} - {1}:{2}; used by: {3}" -f $ocrConfig.Name, $ocrConfig.Host, $ocrConfig.Port, $ocrConfig.Servers) -ForegroundColor Green
            }
        }
        else {
            Write-Host 'OCR           : None' -ForegroundColor DarkYellow
        }
        switch ($databaseCheck.MipStatus) {
            'Configured'    { Write-Host ("MIP / AIP     : Configured (AIP tenants: {0}, ICT connections: {1}, labels: {2})" -f $databaseCheck.MipTenantCount, $databaseCheck.MipIctCount, $databaseCheck.MipLabelCount) -ForegroundColor Green }
            'NotConfigured' { Write-Host ("MIP / AIP     : Not configured (AIP tenants: {0}, ICT connections: {1}, labels: {2})" -f $databaseCheck.MipTenantCount, $databaseCheck.MipIctCount, $databaseCheck.MipLabelCount) -ForegroundColor DarkYellow }
            default         { Write-Host 'MIP / AIP     : Unknown (tables not readable on this DLP version)' -ForegroundColor DarkYellow }
        }
    }
    else {
        Write-Host 'Integration information could not be read.' -ForegroundColor Red
    }

}

Write-Section -Title 'DLP LICENSE'
if ($licenseKeys.Count -gt 0) {
    $licenseKeys |
        Select-Object Product, Count, Status, @{ Name = 'Expiration'; Expression = { $_.ExpiryDate } }, @{ Name = 'DaysRemaining'; Expression = { $_.DaysRemaining } } |
        Format-Table -AutoSize |
        Out-Host
    Write-Host ("License file : {0} (signed {1})" -f $licenseInfo.CurrentFile, $licenseInfo.CurrentSignDate) -ForegroundColor DarkGray
    Write-Host ("Location     : {0}" -f $licenseInfo.CurrentDirectory) -ForegroundColor DarkGray
    if (@($licenseInfo.OtherFiles).Count -gt 0) {
        Write-Host ("Note: {0} older license file(s) also exist; the newest signed file is used:" -f @($licenseInfo.OtherFiles).Count) -ForegroundColor DarkYellow
        @($licenseInfo.OtherFiles) | Select-Object Name, SignDate, Modified | Format-Table -AutoSize | Out-Host
    }
}
else {
    Write-Host 'No DLP license (.slf) file could be read.' -ForegroundColor DarkYellow
    foreach ($searchedPath in @($licenseInfo.SearchedDirectories)) { Write-Host ("  searched: {0}" -f $searchedPath) -ForegroundColor DarkGray }
    if ($licenseInfo.Error) { Write-Host $licenseInfo.Error -ForegroundColor Red }
}

Write-Section -Title 'SYSLOG (SYSTEM EVENTS)'
switch ($syslogInfo.Status) {
    'Configured' {
        Write-Host ("Configured : {0}://{1}:{2}" -f $syslogInfo.Protocol, $syslogInfo.SyslogHost, $syslogInfo.Port) -ForegroundColor Green
        Write-Host ("Level      : {0} ({1})" -f $syslogInfo.Level, $syslogInfo.LevelText)
        if ($syslogInfo.Format) { Write-Host ("Format     : {0}" -f $syslogInfo.Format) }
        switch ($syslogInfo.Connectivity) {
            'Reachable'       { Write-Host 'Connection : TCP connection to the syslog server succeeded (message delivery is not verified).' -ForegroundColor Green }
            'Unreachable'     { Write-Host 'Connection : could not connect to the syslog server within 3 seconds.' -ForegroundColor Yellow }
            'UdpUnverifiable' { Write-Host 'Connection : cannot be verified for UDP.' -ForegroundColor DarkGray }
            default           { Write-Host 'Connection : not tested.' -ForegroundColor DarkGray }
        }
        Write-Host ("Source     : {0}" -f $syslogInfo.File) -ForegroundColor DarkGray
    }
    'NotConfigured' {
        Write-Host 'Syslog for system events is not enabled in Manager.properties.' -ForegroundColor DarkYellow
        Write-Host ("Source     : {0}" -f $syslogInfo.File) -ForegroundColor DarkGray
    }
    default {
        Write-Host 'Manager.properties was not found (run this script on the Enforce Server).' -ForegroundColor DarkYellow
    }
}
Write-Host "Note: 'Log to a Syslog Server' response rules are separate and are not checked here." -ForegroundColor DarkGray

Write-Section -Title 'HEALTH FINDINGS AND NOTES'
Write-StatusTable -Rows $findings

Write-Section -Title 'SUMMARY'
[pscustomobject]@{
    Normal   = @($findings | Where-Object Status -eq 'Normal').Count
    Warning  = @($findings | Where-Object Status -eq 'Warning').Count
    Critical = @($findings | Where-Object Status -eq 'Critical').Count
    Unknown  = @($findings | Where-Object Status -eq 'Unknown').Count
} | Format-List

if ($collectionErrors.Count -gt 0) {
    Write-Section -Title 'COLLECTION ERRORS'
    foreach ($message in $collectionErrors) {
        Write-Host ("- {0}" -f $message) -ForegroundColor DarkYellow
    }
}

Write-Host ''
Write-Host 'Read-only check completed. No system configuration was changed.' -ForegroundColor Cyan

try {
    $reportData = [pscustomobject]@{
        ComputerName    = $env:COMPUTERNAME
        CollectedAt     = $startedAt.ToString('o')
        SystemInfo      = [pscustomobject]@{
            Manufacturer    = $computerSystem.Manufacturer
            Model           = $computerSystem.Model
            OperatingSystem = $operatingSystem.Caption
            OSVersion       = $operatingSystem.Version
            Architecture    = $operatingSystem.OSArchitecture
            LastBoot        = $lastBoot.ToString('o')
            UptimeDays      = $uptimeDays
        }
        Hardware        = [pscustomobject]@{
            LogicalCpu    = $totalLogicalCpu
            PhysicalCores = $totalPhysicalCores
            TotalMemoryGB = $totalMemoryGB
            UsedMemoryGB  = $usedMemoryGB
            MemoryUsedPct = $memoryUsedPercent
            CpuAveragePct = $cpuAverage
        }
        Disks           = @($logicalDisks | ForEach-Object {
            [pscustomobject]@{
                Drive       = $_.DeviceID
                SizeGB      = Convert-BytesToGB -Bytes ([double]$_.Size)
                FreeGB      = Convert-BytesToGB -Bytes ([double]$_.FreeSpace)
                FreePercent = if ([double]$_.Size -gt 0) {
                    [math]::Round(([double]$_.FreeSpace / [double]$_.Size) * 100, 1)
                } else { 0 }
            }
        })
        DlpServices      = @($dlpServices | Select-Object Name, DisplayName, State, StartMode)
        Findings         = @($findings)
        CollectionErrors = @($collectionErrors)
        DatabaseChecked  = -not $SkipDatabaseCheck
        TierAssessment   = $tierAssessment
        License          = $licenseInfo
        Syslog           = $syslogInfo
        IncidentLookbackDays = $IncidentLookbackDays
        HeartbeatStaleSeconds = $HeartbeatStaleSeconds
        SystemEventLookbackDays = $SystemEventLookbackDays
        Database         = $databaseCheck
    }

    $reportForHtml = $reportData | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $htmlContent = New-DlpHtmlReport -ReportData $reportForHtml -CustomerName $CustomerName

    $reportFileName = "{0}_DLP_HC_{1:yyyyMMdd_HHmmss}.html" -f $env:COMPUTERNAME, $startedAt
    $reportPath = Join-Path -Path ([Environment]::GetFolderPath('Desktop')) -ChildPath $reportFileName
    Set-Content -Path $reportPath -Value $htmlContent -Encoding UTF8 -Force

    Write-Host ''
    Write-Host "HTML report created: $reportPath" -ForegroundColor Green
}
catch {
    Write-Host ''
    Write-Host "The HTML report could not be created: $($_.Exception.Message)" -ForegroundColor Red
}
