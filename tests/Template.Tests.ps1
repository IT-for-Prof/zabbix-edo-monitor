# itforprof.com by Konstantin Tyutyunnik
# Contract tests: Zabbix template <-> probe <-> agent config <-> README.
# Run under Windows PowerShell 5.1 with Pester 6.2.0 and powershell-yaml 0.4.12:
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    Import-Module powershell-yaml -RequiredVersion 0.4.12 -ErrorAction Stop
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:ProbePath = Join-Path $root 'agent\edo.ps1'
    $script:ConfPath = Join-Path $root 'agent\edo-monitor.conf'
    $script:ReadmePath = Join-Path $root 'README.md'
    $script:TemplatePath = Join-Path $root 'template\edo-monitor-by-zabbix-agent-active.yaml'
    . $script:ProbePath

    $script:Export = ConvertFrom-Yaml ([IO.File]::ReadAllText($script:TemplatePath))
    $script:T = $script:Export.zabbix_export.templates[0]
    $script:TemplateName = $script:T.template
    $script:Rule = $script:T.discovery_rules[0]
    $script:MacroStep = @($script:Rule.preprocessing | Where-Object { $_.type -eq 'REGEX' })
    $script:JsStep = @($script:Rule.preprocessing | Where-Object { $_.type -eq 'JAVASCRIPT' })
    $script:Js = $script:JsStep[0].parameters[0]
    $script:Macros = @{}
    foreach ($m in $script:T.macros) { $script:Macros[$m.macro] = $m }
    $script:TargetMacros = @($script:T.macros | Where-Object { $_.macro -like '{$EDO.TARGETS.*}' } | ForEach-Object { $_.macro })
    $script:ProtoArgs = '[{#MODE},{#HOST},{#PORT},{#PATH}]'
    # Stock triggers of "Windows by Zabbix agent active" 7.0, copied verbatim from the official template.
    $script:WindowsDependencies = @(
        @{ name = 'Windows: Active checks are not available'; expression = 'min(/Windows by Zabbix agent active/zabbix[host,active_agent,available],{$AGENT.TIMEOUT})=2' }
        @{ name = 'Windows: Zabbix agent is not available'; expression = 'nodata(/Windows by Zabbix agent active/agent.ping,{$AGENT.NODATA_TIMEOUT})=1' }
    )

    function Get-MacroValue([string]$Name) {
        $m = $script:Macros[$Name]
        if ($null -eq $m -or -not $m.ContainsKey('value')) { return '' }
        [string]$m.value
    }

    function Get-TargetEntries {
        foreach ($name in $script:TargetMacros) {
            foreach ($entry in ((Get-MacroValue $name) -split ';')) {
                if ($entry.Trim()) { [pscustomobject]@{ Macro = $name; Text = $entry.Trim(); Fields = @($entry.Trim() -split '\|' | ForEach-Object { $_.Trim() }) } }
            }
        }
    }

    function ConvertTo-Seconds([string]$Duration) {
        if ($Duration -notmatch '^(\d+)([smhdw]?)$') { throw "not a Zabbix duration: $Duration" }
        $n = [int]$Matches[1]
        switch ($Matches[2]) { 'm' { $n * 60 } 'h' { $n * 3600 } 'd' { $n * 86400 } 'w' { $n * 604800 } default { $n } }
    }

    # Runs the discovery pipeline: the regex step's output with macros substituted, as Zabbix does textually,
    # becomes the value of the JavaScript step, which runs under JScript.NET.
    # Not Duktape: this checks the logic; the Zabbix "Test" button confirms the engine.
    function Invoke-DiscoveryJs([hashtable]$Override = @{}) {
        $feed = $script:MacroStep[0].parameters[1]
        foreach ($name in $script:TargetMacros) {
            $value = Get-MacroValue $name
            if ($Override.ContainsKey($name)) { $value = $Override[$name] }
            $feed = $feed.Replace($name, $value)
        }
        $code = $script:Js
        $literal = "'" + $feed + "'"
        $json = @'
var JSON = { stringify: function (rows) {
    function q(s) { return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
    var out = [];
    for (var i = 0; i < rows.length; i++) { var p = []; for (var k in rows[i]) p.push(q(k) + ':' + q(rows[i][k])); out.push('{' + p.join(',') + '}'); }
    return '[' + out.join(',') + ']';
} };
'@
        Add-Type -AssemblyName Microsoft.JScript
        $engine = [Microsoft.JScript.Vsa.VsaEngine]::CreateEngine()
        $result = [Microsoft.JScript.Eval]::JScriptEvaluate($json + "`n(function (value) {`n" + $code + "`n})($literal);", $engine)
        @(ConvertFrom-Json $result)
    }

    function Get-AllTriggers {
        foreach ($i in $script:T.items) { if ($i.ContainsKey('triggers')) { $i.triggers } }
        $script:Export.zabbix_export.triggers
        $script:Rule.trigger_prototypes
    }

    function Get-Trigger([string]$Name) {
        $found = @(Get-AllTriggers | Where-Object { $_.name -eq $Name })
        if ($found.Count -ne 1) { throw "trigger '$Name' found $($found.Count) times" }
        $found[0]
    }

    # Asserts that $Trigger depends on exactly the named triggers, each quoted with its real expression,
    # so that the import resolves the dependency to the trigger this template actually creates.
    function Assert-DependsOn($Trigger, [string[]]$Names) {
        @($Trigger.dependencies | ForEach-Object { $_.name } | Sort-Object) | Should -Be @($Names | Sort-Object) -Because $Trigger.name
        foreach ($d in $Trigger.dependencies) {
            $stock = @($script:WindowsDependencies | Where-Object { $_.name -eq $d.name })
            $expected = if ($stock) { $stock[0].expression } else { (Get-Trigger $d.name).expression }
            $d.expression | Should -Be $expected -Because "$($Trigger.name) -> $($d.name)"
            # The import matches a dependency by name, expression and recovery expression together.
            if (-not $stock) {
                $master = Get-Trigger $d.name
                $expectedRecovery = if ($master.ContainsKey('recovery_expression')) { $master.recovery_expression } else { $null }
                $actualRecovery = if ($d.ContainsKey('recovery_expression')) { $d.recovery_expression } else { $null }
                $actualRecovery | Should -Be $expectedRecovery -Because "$($Trigger.name) -> $($d.name) recovery"
            }
        }
    }

    $script:DeclaredKeys = @($script:T.items | ForEach-Object { $_.key }) + @($script:Rule.item_prototypes | ForEach-Object { $_.key })
}

Describe 'Template shape' {
    It 'is a Zabbix 7.0 export with one template' {
        $script:Export.zabbix_export.version | Should -Be '7.0'
        @($script:Export.zabbix_export.templates).Count | Should -Be 1
        $script:TemplateName | Should -Be 'EDO Monitor by Zabbix agent active'
    }

    It 'carries the team template tags class, target and vendor' {
        $tags = @{}
        foreach ($tag in $script:T.tags) { $tags[$tag.tag] = $tag.value }
        $tags['class'] | Should -Be 'service'
        $tags['target'] | Should -Be 'edo'
        $tags['vendor'] | Should -Not -BeNullOrEmpty
    }

    It 'every item and item prototype has a component tag; prototypes are tagged by endpoint, mode and service' {
        foreach ($i in @($script:T.items) + @($script:Rule.item_prototypes)) {
            @($i.tags | Where-Object { $_.tag -eq 'component' }).Count | Should -Be 1 -Because $i.key
        }
        foreach ($p in $script:Rule.item_prototypes) {
            $map = @{}; foreach ($tag in $p.tags) { $map[$tag.tag] = $tag.value }
            $map['endpoint'] | Should -Be '{#HOST}' -Because $p.key
            $map['mode'] | Should -Be '{#MODE}' -Because $p.key
            $map['service'] | Should -Be '{#NAME}' -Because $p.key
        }
    }

    It 'does not reuse item keys of Windows by Zabbix agent active' {
        foreach ($key in 'agent.version', 'agent.variant', 'agent.hostname', 'agent.ping', 'system.localtime', 'zabbix[host,active_agent,available]') {
            $script:DeclaredKeys | Should -Not -Contain $key
        }
    }

    It 'has unique 32-hex UUIDs' {
        $uuids = @([regex]::Matches([IO.File]::ReadAllText($script:TemplatePath), '(?m)^\s*-?\s*uuid: (\S+)') | ForEach-Object { $_.Groups[1].Value })
        $uuids.Count | Should -BeGreaterThan 5
        $uuids | ForEach-Object { $_ | Should -Match '^[0-9a-f]{32}$' }
        @($uuids | Sort-Object -Unique).Count | Should -Be $uuids.Count
    }
}

Describe 'Target macros' {
    It 'every entry has five fields and passes the probe argument check' {
        $entries = @(Get-TargetEntries)
        $entries.Count | Should -BeGreaterThan 20
        foreach ($e in $entries) {
            $e.Fields.Count | Should -Be 5 -Because $e.Text
            $e.Fields[0] | Should -Not -BeNullOrEmpty -Because $e.Text
            Test-EdoArgs -Mode $e.Fields[1] -TargetHost $e.Fields[2] -Port $e.Fields[3] -Path $e.Fields[4] | Should -BeNullOrEmpty -Because $e.Text
        }
    }

    It 'has no duplicate mode|host|port|path' {
        $ids = @(Get-TargetEntries | ForEach-Object { ($_.Fields[1..4] -join '|').ToLower() })
        @($ids | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name) | Should -BeNullOrEmpty
    }

    It 'keeps every value within 2048 characters and free of the backtick separator, regex output escapes and line breaks' {
        foreach ($name in $script:TargetMacros) {
            $value = Get-MacroValue $name
            $value.Length | Should -BeLessOrEqual 2048 -Because $name
            $value | Should -Not -Match "['\\``\r\n]" -Because $name
        }
    }

    It 'covers every probe mode' {
        $modes = @(Get-TargetEntries | ForEach-Object { $_.Fields[1] } | Sort-Object -Unique)
        $modes | Should -Be @('gost', 'http', 'stall')
    }
}

Describe 'Discovery JavaScript' {
    It 'a regex step feeds exactly the declared target macros; the JavaScript holds no macro at all' {
        # ZBX-25568 (fixed in 7.0.9 / 7.2.3): the compiled script is cached with macros substituted and dropped only
        # when the preprocessing changes. Macros in a regex step are resolved on every run.
        $script:Rule.preprocessing.Count | Should -Be 2
        $script:Rule.preprocessing[0].type | Should -Be 'REGEX'
        $script:Rule.preprocessing[1].type | Should -Be 'JAVASCRIPT'
        $script:Js | Should -Not -Match '\{\$'
        $output = $script:MacroStep[0].parameters[1]
        $used = @([regex]::Matches($output, '\{\$EDO\.TARGETS\.[A-Z.]+\}') | ForEach-Object Value)
        @($used | Sort-Object) | Should -Be @($script:TargetMacros | Sort-Object)
        # Nothing but macros and separators, so the JavaScript splits it back unambiguously.
        ($output -replace '\{\$EDO\.TARGETS\.[A-Z.]+\}', '') | Should -Match '^`*$'
    }

    It 'uses the same field patterns as Test-EdoArgs in edo.ps1' {
        $probe = [IO.File]::ReadAllText($script:ProbePath)
        $hostPs = [regex]::Match($probe, "\`$TargetHost -cnotmatch '([^']+)'").Groups[1].Value
        $pathPs = [regex]::Match($probe, "\`$Path -cnotmatch '([^']+)'").Groups[1].Value
        $hostJs = [regex]::Match($script:Js, 'hostPattern = /(.+)/;').Groups[1].Value
        $pathJs = [regex]::Match($script:Js, 'pathPattern = /(.+)/;').Groups[1].Value
        $hostPs | Should -Not -BeNullOrEmpty
        # .NET needs \z where JavaScript "$" already means end of input.
        $hostJs | Should -Be $hostPs.Replace('\z', '$')
        $pathJs.Replace('\/', '/') | Should -Be $pathPs.Replace('\z', '$')
        $pathJs | Should -Not -Match '~' -Because 'agent2 refuses ~ in key parameters'
        $pathJs | Should -Not -Match '%' -Because 'cmd.exe expands %VAR% in UserParameter arguments'
        $script:Js | Should -Match ([regex]::Escape('modePattern = /^(http|stall|gost)$/'))
        $probe | Should -Match ([regex]::Escape("@('http', 'stall', 'gost')"))
    }

    It 'turns the default macros into one row per entry' {
        $rows = Invoke-DiscoveryJs
        $entries = @(Get-TargetEntries)
        $rows.Count | Should -Be $entries.Count
        $fromJs = @($rows | ForEach-Object { @($_.'{#NAME}', $_.'{#MODE}', $_.'{#HOST}', $_.'{#PORT}', $_.'{#PATH}') -join '|' } | Sort-Object)
        $fromMacros = @($entries | ForEach-Object { $_.Fields -join '|' } | Sort-Object)
        $fromJs | Should -Be $fromMacros
    }

    It 'skips empty groups, trims spaces and drops duplicates' {
        $override = @{}
        foreach ($name in $script:TargetMacros) { $override[$name] = '' }
        $override['{$EDO.TARGETS.EXTRA}'] = ' A | http | Example.com | 443 | / ;; B|http|example.com|443|/ ; '
        $rows = Invoke-DiscoveryJs $override
        $rows.Count | Should -Be 1
        $rows[0].'{#NAME}' | Should -Be 'A'
        $rows[0].'{#HOST}' | Should -Be 'example.com'
    }

    It 'throws instead of returning an empty list when every group is empty or only separators' -ForEach @(
        @{ name = 'all empty'; extra = '' }
        @{ name = 'separators and spaces'; extra = ' ; ;  ' }
    ) {
        $override = @{}
        foreach ($n in $script:TargetMacros) { $override[$n] = '' }
        $override['{$EDO.TARGETS.EXTRA}'] = $extra
        { Invoke-DiscoveryJs $override } | Should -Throw
    }

    It 'turns a bad entry into a safe invalid target that the probe answers with 91' {
        $override = @{}
        foreach ($name in $script:TargetMacros) { $override[$name] = '' }
        $override['{$EDO.TARGETS.EXTRA}'] = 'Плохая|http|bad_host|443|/;Без пути|http|example.com|443|x;Короткая|http|example.com;Тильда|http|example.com|443|/a~b;Процент|http|example.com|443|/%COMPUTERNAME%;' + ('Длинная' * 60) + '|http|bad host|443|/'
        $rows = Invoke-DiscoveryJs $override
        $rows.Count | Should -Be 6
        foreach ($row in $rows) { $row.'{#NAME}'.Length | Should -BeLessThan 120 -Because 'item names are limited to 255 characters' }
        foreach ($r in $rows) {
            $r.'{#MODE}' | Should -Be 'invalid'
            $r.'{#NAME}' | Should -Match '^Неверная запись: '
            foreach ($param in @($r.'{#MODE}', $r.'{#HOST}', $r.'{#PORT}', $r.'{#PATH}')) {
                $param | Should -Not -Match '[\\''"`*?\[\]{}~$!&;()<>|#@]' -Because 'agent2 must accept every key parameter'
            }
            (Invoke-EdoProbe -Mode $r.'{#MODE}' -TargetHost $r.'{#HOST}' -Port $r.'{#PORT}' -Path $r.'{#PATH}').class | Should -Be 91
        }
        @($rows | ForEach-Object { $_.'{#HOST}' } | Sort-Object -Unique).Count | Should -Be 6
    }
}

Describe 'Items and prototypes' {
    It 'item prototypes are keyed by exactly the four LLD macros' {
        foreach ($p in $script:Rule.item_prototypes) {
            $p.key | Should -Match ('^edo\.[a-z_]+' + [regex]::Escape($script:ProtoArgs) + '$')
        }
    }

    It 'dependent prototypes read existing JSON contract fields from the probe item' {
        $contract = @((New-EdoResult).Keys)
        $master = @($script:Rule.item_prototypes | Where-Object { $_.type -eq 'ZABBIX_ACTIVE' })
        $master.Count | Should -Be 1
        $master[0].key | Should -Be ('edo.probe' + $script:ProtoArgs)
        foreach ($p in @($script:Rule.item_prototypes | Where-Object { $_.type -eq 'DEPENDENT' })) {
            $p.master_item.key | Should -Be $master[0].key
            $p.preprocessing[0].type | Should -Be 'JSONPATH'
            $field = $p.preprocessing[0].parameters[0] -replace '^\$\.', ''
            $contract | Should -Contain $field
            $p.key | Should -Be ("edo.$field" + $script:ProtoArgs)
        }
    }

    It 'fields that may be -1 are FLOAT, not UNSIGNED' {
        foreach ($p in @($script:Rule.item_prototypes | Where-Object { $_.type -eq 'DEPENDENT' -and $_.key -notlike 'edo.class*' })) {
            $p.value_type | Should -Be 'FLOAT' -Because $p.key
        }
    }

    It 'the probe item runs with the interval and timeout macros' {
        $master = @($script:Rule.item_prototypes | Where-Object { $_.type -eq 'ZABBIX_ACTIVE' })[0]
        $master.delay | Should -Be '{$EDO.INTERVAL:"{#MODE}"}'
        $master.timeout | Should -Be '{$EDO.TIMEOUT}'
        $master.value_type | Should -Be 'TEXT'
    }

    It 'discovery hangs off the hourly pacing master and disables lost targets at once' {
        # The master only paces discovery; its value is irrelevant to whether macro edits arrive (see ZBX-25568 test).
        $script:Rule.type | Should -Be 'DEPENDENT'
        $script:Rule.master_item.key | Should -Be 'system.localtime[utc]'
        $script:DeclaredKeys | Should -Contain 'system.localtime[utc]'
        $script:Rule.enabled_lifetime_type | Should -Be 'DISABLE_IMMEDIATELY'
        $script:Rule.lifetime | Should -Be '7d'
    }

    It 'an unreadable probe answer becomes class 91 at once instead of waiting for nodata' {
        $class = @($script:Rule.item_prototypes | Where-Object { $_.key -like 'edo.class*' })[0]
        $class.preprocessing[0].error_handler | Should -Be 'CUSTOM_VALUE'
        $class.preprocessing[0].error_handler_params | Should -Be '91'
    }

    It 'the value map names every probe class exactly as edo.ps1 does' {
        $map = @($script:T.valuemaps | Where-Object { $_.name -eq 'EDO probe class' })[0]
        $fromTemplate = @($map.mappings | ForEach-Object { '{0}={1}' -f $_.value, $_.newvalue } | Sort-Object)
        $fromProbe = @($script:EdoClassNames.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value } | Sort-Object)
        $fromTemplate | Should -Be $fromProbe
        @($script:Rule.item_prototypes | Where-Object { $_.key -like 'edo.class*' })[0].valuemap.name | Should -Be 'EDO probe class'
    }

    It '{$EDO.SCRIPT.MD5} is the MD5 of agent/edo.ps1 as deployed (CRLF)' {
        $text = [IO.File]::ReadAllText($script:ProbePath) -replace "`r`n", "`n" -replace "`n", "`r`n"
        $bytes = [byte[]](0xEF, 0xBB, 0xBF) + (New-Object Text.UTF8Encoding($false)).GetBytes($text)
        $md5 = [BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($bytes)).Replace('-', '').ToLower()
        Get-MacroValue '{$EDO.SCRIPT.MD5}' | Should -Be $md5
    }
}

Describe 'Macros' {
    It 'every referenced macro is declared, every declared one is used and described' {
        $text = [IO.File]::ReadAllText($script:TemplatePath)
        $macrosAt = $text.IndexOf('      macros:')
        $valuemapsAt = $text.IndexOf('      valuemaps:')
        $declaredSection = $text.Substring($macrosAt, $valuemapsAt - $macrosAt)
        # Everything but the declarations: host-level triggers live after the template, at export level.
        $body = $text.Substring(0, $macrosAt) + $text.Substring($valuemapsAt)
        foreach ($d in $script:WindowsDependencies) { $body = $body.Replace($d.expression, '') }
        $used = @([regex]::Matches($body, '\{\$[A-Z0-9_.]+(?::"[^"]*")?\}') | ForEach-Object { $_.Value -replace ':"[^"]*"', '' } | Sort-Object -Unique)
        $declared = @($script:T.macros | ForEach-Object { $_.macro -replace ':"[^"]*"', '' } | Sort-Object -Unique)
        $used | Should -Be $declared
        foreach ($m in $script:T.macros) { $m.description | Should -Not -BeNullOrEmpty -Because $m.macro }
        $declaredSection | Should -Not -BeNullOrEmpty
    }

    It 'nodata window is longer than the interval for every mode' {
        foreach ($ctx in @('', ':"stall"')) {
            $interval = Get-MacroValue "{`$EDO.INTERVAL$ctx}"
            $nodata = Get-MacroValue "{`$EDO.NODATA$ctx}"
            if (-not $interval) { $interval = Get-MacroValue '{$EDO.INTERVAL}' }
            if (-not $nodata) { $nodata = Get-MacroValue '{$EDO.NODATA}' }
            (ConvertTo-Seconds $nodata) | Should -BeGreaterThan (2 * (ConvertTo-Seconds $interval)) -Because "context '$ctx'"
        }
    }

    It 'every slow threshold for a stall target is reachable inside the probe phase budget' {
        $stallHosts = @(Get-TargetEntries | Where-Object { $_.Fields[1] -eq 'stall' } | ForEach-Object { $_.Fields[2] })
        foreach ($h in $stallHosts) {
            $v = Get-MacroValue "{`$EDO.SLOW.MS:""$h""}"
            if (-not $v) { $v = Get-MacroValue '{$EDO.SLOW.MS}' }
            [int]$v | Should -BeLessThan $script:EdoBudget.Http -Because "stall to $h longer than the phase budget is already class 50"
        }
    }

    It 'nodata window outlasts the stock agent nodata so the agent trigger fires first' {
        (ConvertTo-Seconds (Get-MacroValue '{$EDO.NODATA}')) | Should -BeGreaterThan (30 * 60)
    }

    It 'the host silence window fires before any target nodata and after the stock active-checks trigger' {
        $hostWindow = ConvertTo-Seconds (Get-MacroValue '{$EDO.NODATA.HOST}')
        $interval = ConvertTo-Seconds (Get-MacroValue '{$EDO.INTERVAL}')
        # Every target is at most one interval older than the freshest one, so the host window must
        # close at least one interval before the per-target window opens.
        ((ConvertTo-Seconds (Get-MacroValue '{$EDO.NODATA}')) - $hostWindow) | Should -BeGreaterThan $interval
        $hostWindow | Should -BeGreaterThan (2 * $interval)
        # "Windows: Active checks are not available" rises about 7.5 min after the agent stops.
        $hostWindow | Should -BeGreaterThan (10 * 60)
    }

    It 'mass thresholds are a percentage and a small absolute floor' {
        [int](Get-MacroValue '{$EDO.MASS.PCT}') | Should -BeGreaterThan 0
        [int](Get-MacroValue '{$EDO.MASS.PCT}') | Should -BeLessOrEqual 100
        [int](Get-MacroValue '{$EDO.MASS.MIN}') | Should -BeGreaterOrEqual 2
    }

    It 'mass failure needs two bad rounds, not one' {
        (ConvertTo-Seconds (Get-MacroValue '{$EDO.MASS.PERIOD}')) | Should -BeGreaterThan (ConvertTo-Seconds (Get-MacroValue '{$EDO.INTERVAL}'))
    }

    It 'the instability threshold needs two separate failures, not one blip or one outage' {
        [int](Get-MacroValue '{$EDO.UNSTABLE.CHANGES}') | Should -BeGreaterOrEqual 4
        foreach ($ctx in @('', ':"stall"')) {
            $window = Get-MacroValue "{`$EDO.UNSTABLE.PERIOD$ctx}"
            $interval = Get-MacroValue "{`$EDO.INTERVAL$ctx}"
            # Four changes need at least five values inside the window.
            (ConvertTo-Seconds $window) | Should -BeGreaterOrEqual (4 * (ConvertTo-Seconds $interval)) -Because "context '$ctx'"
        }
    }

    It 'item timeout leaves room over the probe deadline' {
        (ConvertTo-Seconds (Get-MacroValue '{$EDO.TIMEOUT}')) | Should -BeGreaterOrEqual 30
    }
}

Describe 'Triggers' {
    It 'every trigger has a scope tag; trigger prototypes link to the latest data of their endpoint' {
        foreach ($t in @(Get-AllTriggers)) { @($t.tags | Where-Object { $_.tag -eq 'scope' }).Count | Should -Be 1 -Because $t.name }
        foreach ($t in $script:Rule.trigger_prototypes) {
            $t.url_name | Should -Not -BeNullOrEmpty -Because $t.name
            $t.url | Should -Match '^zabbix\.php\?action=latest\.view&hostids%5B%5D=\{HOST\.ID\}&' -Because $t.name
            $t.url | Should -Match 'tags%5B0%5D%5Btag%5D=endpoint&tags%5B0%5D%5Boperator%5D=1&tags%5B0%5D%5Bvalue%5D=\{#HOST\}' -Because $t.name
        }
    }

    It 'every trigger has event name, operational data, manual close and "Что делать"' {
        foreach ($t in @(Get-AllTriggers)) {
            $t.event_name | Should -Not -BeNullOrEmpty -Because $t.name
            $t.opdata | Should -Not -BeNullOrEmpty -Because $t.name
            $t.manual_close | Should -Be 'YES' -Because $t.name
            $t.description | Should -Match 'Что делать' -Because $t.name
            if ($t.priority -eq 'WARNING') { $t.description | Should -Match '^Только для дашборда' -Because $t.name }
        }
    }

    It 'expressions use only this template and its own keys' {
        foreach ($t in @(Get-AllTriggers)) {
            foreach ($m in [regex]::Matches($t.expression, '\(/([^/]+)/(.+?)(?:,[^,\]]*)?\)')) {
                $m.Groups[1].Value | Should -Be $script:TemplateName -Because $t.name
            }
            $keys = @([regex]::Matches($t.expression, "/$([regex]::Escape($script:TemplateName))/([a-z0-9_.]+(?:\[[^\]]*\])?)") | ForEach-Object { $_.Groups[1].Value })
            $keys.Count | Should -BeGreaterThan 0
            foreach ($k in $keys) { $script:DeclaredKeys | Should -Contain $k -Because $t.name }
        }
    }

    It 'recovery expressions also use only this template and its own keys' {
        foreach ($t in @(Get-AllTriggers | Where-Object { $_.ContainsKey('recovery_expression') })) {
            $t.recovery_mode | Should -Be 'RECOVERY_EXPRESSION' -Because $t.name
            $keys = @([regex]::Matches($t.recovery_expression, "/$([regex]::Escape($script:TemplateName))/([a-z0-9_.]+(?:\[[^\]]*\])?)") | ForEach-Object { $_.Groups[1].Value })
            $keys.Count | Should -BeGreaterThan 0
            foreach ($k in $keys) { $script:DeclaredKeys | Should -Contain $k -Because $t.name }
        }
    }

    It 'numeric literals are only class boundaries, boolean results and percent' {
        foreach ($t in @(Get-AllTriggers)) {
            $texts = @($t.expression)
            if ($t.ContainsKey('recovery_expression')) { $texts += $t.recovery_expression }
            foreach ($text in $texts) {
                $expr = [regex]::Replace($text, '\{\$[^}]+\}', 'M')
                foreach ($m in [regex]::Matches($expr, '(?:[<>]=?|=|<>)\s*(-?\d+(?:\.\d+)?)')) {
                    @('0', '1', '90') | Should -Contain $m.Groups[1].Value -Because "$($t.name): $text"
                }
                foreach ($m in [regex]::Matches($expr, '(\d+)\*')) { $m.Groups[1].Value | Should -Be '100' -Because "$($t.name): $text" }
            }
        }
    }

    It 'no macro inside a function count: Zabbix 7.0 rejects #{$MACRO} on import' {
        foreach ($t in @(Get-AllTriggers)) { $t.expression | Should -Not -Match '#\{\$' -Because $t.name }
    }

    It 'the failure period macro is a Zabbix count long enough for the host summary to win the race' {
        Get-MacroValue '{$EDO.FAIL.PERIOD}' | Should -Match '^#\d+$'
        # The host summary needs up to one interval plus a minute to see a mass failure; with #2 a target's second
        # failure arrives just as late, and per-target High would race the host trigger.
        [int](Get-MacroValue '{$EDO.FAIL.PERIOD}').TrimStart('#') | Should -BeGreaterOrEqual 3
    }

    It 'per target: two Average (no data, check impossible), one High, three dashboard Warnings' {
        $p = @($script:Rule.trigger_prototypes)
        @($p | Where-Object priority -eq 'AVERAGE' | ForEach-Object name | Sort-Object) | Should -Be @('EDO {#NAME}: нет данных пробы', 'EDO {#NAME}: проверка невозможна')
        @($p | Where-Object priority -eq 'HIGH').Count | Should -Be 1
        @($p | Where-Object priority -eq 'WARNING').Count | Should -Be 3
        @($p).Count | Should -Be 6
    }

    It 'dependency chain: agent -> probe on host -> mass failure -> target triggers' {
        # Zabbix follows dependencies transitively (checked on 7.0.30), so each trigger names only its nearest masters.
        $hostProbe = 'EDO: проба не работает на хосте'
        $mass = 'EDO: массовый отказ с хоста'
        $noData = 'EDO {#NAME}: нет данных пробы'
        $impossible = 'EDO {#NAME}: проверка невозможна'
        $stock = @($script:WindowsDependencies | ForEach-Object { $_.name })
        Assert-DependsOn (Get-Trigger $hostProbe) $stock
        Assert-DependsOn (Get-Trigger 'EDO: версия скрипта пробы не совпадает') $stock
        Assert-DependsOn (Get-Trigger $mass) @($hostProbe)
        Assert-DependsOn (Get-Trigger $noData) @($hostProbe)
        Assert-DependsOn (Get-Trigger $impossible) @($hostProbe)
        Assert-DependsOn (Get-Trigger 'EDO {#NAME}: недоступен несколько проверок подряд') @($mass, $noData, $impossible)
        foreach ($t in @($script:Rule.trigger_prototypes | Where-Object priority -eq 'WARNING')) { Assert-DependsOn $t @($noData, $impossible) }
    }

    It 'the High trigger fires only on network or service classes and closes only on a successful check' {
        $high = @($script:Rule.trigger_prototypes | Where-Object priority -eq 'HIGH')[0]
        $high.expression | Should -Match 'min\(/[^)]*edo\.class[^)]*,\{\$EDO\.FAIL\.PERIOD\}\)>0'
        $high.expression | Should -Match 'max\(/[^)]*edo\.class[^)]*,\{\$EDO\.FAIL\.PERIOD\}\)<90'
        # Without it a 90-91 value or a lone success inside the window closed the problem while the service was still down.
        $high.recovery_expression | Should -Match '^last\(/[^)]*edo\.class\[[^)]*\]\)=0$'
    }

    It 'dashboard Warnings do not flap on a single failed check' {
        $slow = Get-Trigger 'EDO {#NAME}: медленный ответ'
        $slow.recovery_expression | Should -Match 'last\(/[^)]*edo\.total_ms\[[^)]*\]\)<=\{\$EDO\.SLOW\.MS:"\{#HOST\}"\}'
        $slow.recovery_expression | Should -Match 'last\(/[^)]*edo\.class\[[^)]*\]\)=0'
        # cert_days is -1 whenever the check failed before TLS: -1 must neither raise nor close the problem.
        $cert = Get-Trigger 'EDO {#NAME}: сертификат сервера истекает'
        $cert.expression | Should -Match 'edo\.cert_days\[[^)]*\]\)>=0'
        $cert.recovery_expression | Should -Match '^last\(/[^)]*edo\.cert_days\[[^)]*\]\)>=\{\$EDO\.CERT\.DAYS:"\{#HOST\}"\}$'
    }

    It 'instability and outage are mutually exclusive: instability needs a success inside the outage window' {
        $unstable = Get-Trigger 'EDO {#NAME}: нестабилен'
        $unstable.expression | Should -Match 'changecount\(/[^)]*edo\.class\[[^)]*\],\{\$EDO\.UNSTABLE\.PERIOD:"\{#MODE\}"\}\)>=\{\$EDO\.UNSTABLE\.CHANGES\}'
        $unstable.expression | Should -Match 'min\(/[^)]*edo\.class\[[^)]*\],\{\$EDO\.FAIL\.PERIOD\}\)=0'
    }

    It 'host summaries aggregate the class of this host only, with one wildcard per key parameter' {
        $paramCount = ($script:ProtoArgs.Trim('[', ']') -split ',').Count
        $calc = @($script:T.items | Where-Object { $_.type -eq 'CALCULATED' })
        @($calc | ForEach-Object key | Sort-Object) | Should -Be @('edo.targets.broken', 'edo.targets.failing', 'edo.targets.reporting', 'edo.targets.total')
        foreach ($i in $calc) {
            $refs = @([regex]::Matches($i.params, '_foreach\((/[^/]*/)edo\.class\[([^\]]*)\]'))
            $refs.Count | Should -BeGreaterThan 0 -Because $i.key
            foreach ($r in $refs) {
                # "/*/" would count every host on the server; "//" is the host the template is linked to.
                $r.Groups[1].Value | Should -Be '//' -Because $i.key
                # edo.class[*] matches nothing: one "*" stands for exactly one parameter (checked on 7.0.30).
                $r.Groups[2].Value | Should -Be ((@('*') * $paramCount) -join ',') -Because $i.key
            }
        }
    }

    It 'the host probe trigger closes only after a full check interval of data' {
        # Target nodata triggers run on a timer: closing on the first answering target would raise nodata for every
        # target that has not answered yet.
        $t = Get-Trigger 'EDO: проба не работает на хосте'
        $t.recovery_mode | Should -Be 'RECOVERY_EXPRESSION'
        $t.recovery_expression | Should -Match 'min\(/[^)]*edo\.targets\.reporting,\{\$EDO\.INTERVAL\}\)>0'
    }

    It 'the target count does not depend on item state' {
        # last_foreach skips unsupported items: with edo-monitor.conf gone the count would fall to 0 and switch off
        # "проба не работает на хосте" exactly when it is needed.
        $total = @($script:T.items | Where-Object { $_.key -eq 'edo.targets.total' })[0]
        $total.params | Should -Be 'sum(exists_foreach(//edo.class[*,*,*,*]))'
    }

    It 'host triggers refuse to fire on a host with fewer targets than the floor or none at all' {
        (Get-Trigger 'EDO: массовый отказ с хоста').expression | Should -Match '^min\(/[^)]*edo\.targets\.failing,\{\$EDO\.MASS\.PERIOD\}\)>=\{\$EDO\.MASS\.MIN\} and 100\*min\(/[^)]*edo\.targets\.failing,\{\$EDO\.MASS\.PERIOD\}\)>='
        (Get-Trigger 'EDO: проба не работает на хосте').expression | Should -Match '^last\(/[^)]*edo\.targets\.total\)>0 and '
    }
}

Describe 'Agent config and README agree with the template' {
    It 'UserParameter key matches the probe prototype and passes four arguments' {
        $line = @(Get-Content $script:ConfPath | Where-Object { $_ -match '^UserParameter=' })
        $line.Count | Should -Be 1
        $line[0] | Should -Match '^UserParameter=edo\.probe\[\*\],'
        foreach ($n in 1..4) { $line[0] | Should -Match ([regex]::Escape("""`$$n""")) }
        $line[0] | Should -Not -Match '\$5'
    }

    It 'script path is the same in the config, the md5sum item and README' {
        $line = @(Get-Content $script:ConfPath | Where-Object { $_ -match '^UserParameter=' })[0]
        $path = [regex]::Match($line, '-File "([^"]+)"').Groups[1].Value
        $path | Should -Be 'C:\Program Files\Zabbix Agent 2\scripts\edo.ps1'
        $script:DeclaredKeys | Should -Contain ('vfs.file.md5sum["' + $path + '"]')
        [IO.File]::ReadAllText($script:ReadmePath) | Should -Match ([regex]::Escape($path))
    }

    It 'README describes every class code and every macro' {
        $readme = [IO.File]::ReadAllText($script:ReadmePath)
        foreach ($c in $script:EdoClassNames.GetEnumerator()) { $readme | Should -Match "\b$($c.Key)\b.*$($c.Value)" -Because "class $($c.Key)" }
        foreach ($m in $script:T.macros) { $readme | Should -Match ([regex]::Escape($m.macro)) -Because $m.macro }
    }
}
