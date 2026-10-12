# itforprof.com by Konstantin Tyutyunnik
# Tests for agent/edo.ps1. Run under Windows PowerShell 5.1 with Pester 6.2.0:
#   powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -CI"

BeforeAll {
    $script:ProbePath = (Resolve-Path (Join-Path $PSScriptRoot '..\agent\edo.ps1')).Path
    Import-Module (Join-Path $PSScriptRoot 'Helpers\FakeServers.psm1') -Force
    . $script:ProbePath
    $script:Cert = New-FakeCertificate
    $script:ContractKeys = @(
        'class', 'class_name', 'ip',
        'dns_ms', 'tcp_ms', 'tls_ms', 'http_ms', 'total_ms',
        'tls_proto', 'cert_days', 'cert_issuer', 'http_code', 'bytes_sent', 'error'
    )
    $script:DeadlineMs = 25000

    function Invoke-Probe {
        param([string]$Mode, [int]$Port, [string]$Path = '/', [bool]$UseTls = $true, [string]$CsptestPath)
        $p = @{ Mode = $Mode; TargetHost = '127.0.0.1'; Port = "$Port"; Path = $Path; UseTls = $UseTls }
        if ($CsptestPath) { $p.CsptestPath = $CsptestPath }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-EdoProbe @p
        $sw.Stop()
        $r['__wall_ms'] = $sw.ElapsedMilliseconds
        $r
    }
}

Describe 'Source invariants' {
    It 'parses under Windows PowerShell 5.1 without errors' {
        $PSVersionTable.PSVersion.Major | Should -Be 5
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:ProbePath, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
    }

    It 'starts with a UTF-8 BOM' {
        $bytes = [IO.File]::ReadAllBytes($script:ProbePath)
        ($bytes[0], $bytes[1], $bytes[2]) -join ',' | Should -Be '239,187,191'
    }

    It 'enables strict mode 2.0' {
        [IO.File]::ReadAllText($script:ProbePath) | Should -Match '(?m)^\s*Set-StrictMode -Version 2\.0'
    }
}

Describe 'Process contract (as agent2 runs it)' {
    It 'prints one ASCII JSON object, exit 0, empty stderr for <name>' -ForEach @(
        @{ name = 'unknown mode';        argv = @('ftp', 'example.com', '443', '/');   class = 91 }
        @{ name = 'host with ;';         argv = @('http', 'bad;name', '443', '/');     class = 91 }
        @{ name = 'path without /';      argv = @('http', 'example.com', '443', 'x');  class = 91 }
        @{ name = 'port 0';              argv = @('http', 'example.com', '0', '/');    class = 91 }
        @{ name = 'port 70000';          argv = @('http', 'example.com', '70000', '/'); class = 91 }
        @{ name = 'empty argument';      argv = @('http', 'example.com', '443', '');   class = 91 }
        @{ name = 'upper-case mode';     argv = @('HTTP', 'example.com', '443', '/');  class = 91 }
        @{ name = 'path with ~';         argv = @('http', 'example.com', '443', '/a~b'); class = 91 }
        @{ name = 'path with %';         argv = @('http', 'example.com', '443', '/a%20b'); class = 91 }
        @{ name = 'non-ASCII host';      argv = @('http', 'пример.рф', '443', '/');   class = 91 }
        @{ name = 'unresolvable host';   argv = @('http', 'no-such-host.invalid', '443', '/'); class = 10 }
    ) {
        $r = Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList $argv
        $r.ExitCode | Should -Be 0
        $r.StdErr | Should -BeNullOrEmpty
        $r.StdOut | Should -Match '^\{.*\}$'
        $r.StdOut | Should -Not -Match '[^\x20-\x7E]'
        $json = $r.StdOut | ConvertFrom-Json
        $json.class | Should -Be $class
        @($json.PSObject.Properties.Name | Sort-Object) -join ',' | Should -Be (@($script:ContractKeys | Sort-Object) -join ',')
    }

    It 'closed local port gives 22 TCP_REFUSED' {
        $port = Get-ClosedPort
        $r = Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('http', '127.0.0.1', "$port", '/')
        $json = $r.StdOut | ConvertFrom-Json
        $json.class | Should -Be 22
        $json.class_name | Should -Be 'TCP_REFUSED'
        $json.ip | Should -Be '127.0.0.1'
        $r.StdErr | Should -BeNullOrEmpty
    }

    It 'unroutable TEST-NET address gives 20 TCP_TIMEOUT within the deadline' {
        $r = Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('http', '192.0.2.1', '443', '/')
        $json = $r.StdOut | ConvertFrom-Json
        $json.class | Should -Be 20
        $r.Ms | Should -BeLessThan $script:DeadlineMs
    }

    It 'records the phase time of a failed phase' {
        $port = Get-ClosedPort
        $json = (Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('http', '127.0.0.1', "$port", '/')).StdOut | ConvertFrom-Json
        $json.tcp_ms | Should -BeGreaterOrEqual 1000 -Because 'Windows retries SYN after RST for about 2 s'
        $json = (Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('http', 'no-such-host.invalid', '443', '/')).StdOut | ConvertFrom-Json
        $json.dns_ms | Should -BeGreaterOrEqual 0
    }

    It 'validation error runs nothing: no network timings' {
        $r = Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('http', 'bad;name', '443', '/')
        $json = $r.StdOut | ConvertFrom-Json
        $json.dns_ms | Should -Be -1
        $json.tcp_ms | Should -Be -1
        $json.ip | Should -Be ''
    }
}

Describe 'Argument check and JSON output' {
    It 'rejects a trailing newline or CRLF that .NET "$" would let through' -ForEach @(
        @{ name = 'path + LF'; mode = 'http'; target = 'example.com'; port = '443'; path = "/a`n" }
        @{ name = 'host + CRLF'; mode = 'http'; target = "example.com`r`n"; port = '443'; path = '/' }
        @{ name = 'port + LF'; mode = 'http'; target = 'example.com'; port = "443`n"; path = '/' }
    ) {
        Test-EdoArgs -Mode $mode -TargetHost $target -Port $port -Path $path | Should -Not -BeNullOrEmpty
    }

    It 'TLS is on for every port except 80, and an unspecified mode keeps that rule' {
        Get-EdoUseTls -Port 443 | Should -BeTrue
        Get-EdoUseTls -Port 8443 | Should -BeTrue
        Get-EdoUseTls -Port 80 | Should -BeFalse
        $s = Start-FakeServer -Certificate $script:Cert -Behavior {
            param($client, $cert)
            $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
            $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::None, $false)
            Start-Sleep -Milliseconds 300
        }
        try { $r = Invoke-EdoProbe -Mode http -TargetHost '127.0.0.1' -Port "$($s.Port)" -Path '/' } finally { Stop-FakeServer $s }
        $r.tls_proto | Should -Match '^Tls' -Because 'without -UseTls a non-80 port must go through TLS'
    }

    It 'the last-resort JSON literal matches the contract and says 91' {
        $source = [IO.File]::ReadAllText($script:ProbePath)
        $literal = [regex]::Match($source, "catch \{ \`$json = '(\{[^']+\})' \}").Groups[1].Value
        $literal | Should -Not -BeNullOrEmpty
        $json = $literal | ConvertFrom-Json
        $json.class | Should -Be 91
        @($json.PSObject.Properties.Name | Sort-Object) -join ',' | Should -Be (@($script:ContractKeys | Sort-Object) -join ',')
    }

    It 'phase budgets add up to less than the 25 s deadline for every mode' {
        $b = $script:EdoBudget
        ($b.Dns + $b.Tcp + $b.Tls + $b.Http) | Should -BeLessOrEqual 25000
        ($b.Dns + $b.Tcp + $b.Csptest + 2 * $b.CsptestOutput) | Should -BeLessOrEqual 25000
    }

    It 'escapes quotes, backslashes, control and non-ASCII characters and cuts error to 300' {
        $r = New-EdoResult
        $message = 'Кириллица "в кавычках" C:\path' + "`r`n" + ('x' * 400)
        Set-EdoClass $r 91 $message
        $json = ConvertTo-EdoJson $r
        $json | Should -Not -Match '[^\x20-\x7E]'
        $json | Should -Match '\\u041a'
        $back = $json | ConvertFrom-Json
        $back.error | Should -Be $message.Substring(0, 300)
        $back.class_name | Should -Be 'PROBE_ERROR'
    }
}

Describe 'TCP error classification' {
    It 'maps <code> to <class>' -ForEach @(
        @{ code = 'TimedOut';           class = 20 }
        @{ code = 'ConnectionRefused';  class = 22 }
        @{ code = 'AccessDenied';       class = 23 }
        @{ code = 'NetworkUnreachable'; class = 23 }
        @{ code = 'HostUnreachable';    class = 23 }
    ) {
        Get-EdoTcpClass -SocketError ([System.Net.Sockets.SocketError]$code) | Should -Be $class
    }
}

Describe 'TLS phase' {
    It 'RST after ClientHello gives 31 TLS_RESET' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $buf = New-Object byte[] 4096; [void]$client.GetStream().Read($buf, 0, 4096)
            $client.Client.LingerState = New-Object System.Net.Sockets.LingerOption($true, 0)
            $client.Client.Close()
        }
        try { $r = Invoke-Probe -Mode http -Port $s.Port } finally { Stop-FakeServer $s }
        $r.class | Should -Be 31
        $r.tcp_ms | Should -BeGreaterOrEqual 0
        $r.tls_ms | Should -BeGreaterOrEqual 0 -Because 'the failed phase keeps its time'
    }

    It 'FIN after ClientHello gives 32 TLS_FAIL' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $buf = New-Object byte[] 4096; [void]$client.GetStream().Read($buf, 0, 4096)
            $client.Client.Shutdown('Both')
        }
        try { $r = Invoke-Probe -Mode http -Port $s.Port } finally { Stop-FakeServer $s }
        $r.class | Should -Be 32
    }

    It 'silence after ClientHello gives 30 TLS_TIMEOUT within the deadline' {
        $s = Start-FakeServer -Behavior { param($client, $cert) Start-Sleep -Seconds 20 }
        try { $r = Invoke-Probe -Mode http -Port $s.Port } finally { Stop-FakeServer $s }
        $r.class | Should -Be 30
        $r['__wall_ms'] | Should -BeLessThan $script:DeadlineMs
    }

    It 'stall negotiates TLS 1.2 so session tickets are not taken for an early answer; http keeps the OS choice' {
        $behavior = {
            param($client, $cert)
            $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
            $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::None, $false)
            Start-Sleep -Milliseconds 300
        }
        $s = Start-FakeServer -Certificate $script:Cert -Behavior $behavior
        try { $stall = Invoke-Probe -Mode stall -Port $s.Port -Path '/check/post' } finally { Stop-FakeServer $s }
        $s = Start-FakeServer -Certificate $script:Cert -Behavior $behavior
        try { $http = Invoke-Probe -Mode http -Port $s.Port } finally { Stop-FakeServer $s }
        $stall.tls_proto | Should -Be 'Tls12'
        $http.tls_proto | Should -Match '^Tls1[23]$'
        $stall.class | Should -Be 33
    }

    It 'self-signed certificate gives 33 CERT_UNTRUSTED with certificate details' {
        $s = Start-FakeServer -Certificate $script:Cert -Behavior {
            param($client, $cert)
            $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
            $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::None, $false)
            $buf = New-Object byte[] 4096; [void]$ssl.Read($buf, 0, 4096)
            $b = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`n`r`nok")
            $ssl.Write($b, 0, $b.Length); $ssl.Flush(); Start-Sleep -Milliseconds 300
        }
        try { $r = Invoke-Probe -Mode http -Port $s.Port } finally { Stop-FakeServer $s }
        $r.class | Should -Be 33
        $r.class_name | Should -Be 'CERT_UNTRUSTED'
        $r.tls_ms | Should -BeGreaterOrEqual 0
        $r.cert_days | Should -BeGreaterThan 0
        $r.cert_issuer | Should -Be 'localhost'
        $r.tls_proto | Should -Match '^Tls'
    }
}

Describe 'HTTP phase (plain stream)' {
    It 'status <code> gives class <class>' -ForEach @(
        @{ code = 200; class = 0 }
        @{ code = 404; class = 0 }
        @{ code = 302; class = 0 }
        @{ code = 503; class = 40 }
    ) {
        $s = Start-FakeServer -Behavior ([scriptblock]::Create(@"
            param(`$client, `$cert)
            `$ns = `$client.GetStream()
            `$buf = New-Object byte[] 4096; [void]`$ns.Read(`$buf, 0, 4096)
            `$b = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $code Status``r``nContent-Length: 0``r``n``r``n")
            `$ns.Write(`$b, 0, `$b.Length); `$ns.Flush(); Start-Sleep -Milliseconds 300
"@))
        try { $r = Invoke-Probe -Mode http -Port $s.Port -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be $class
        $r.http_code | Should -Be $code
        $r.tls_ms | Should -Be -1
        $r.http_ms | Should -BeGreaterOrEqual 0
    }

    It 'a status line dripped one byte a second still ends at the phase budget with 42' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $ns = $client.GetStream(); $buf = New-Object byte[] 4096; [void]$ns.Read($buf, 0, 4096)
            foreach ($i in 1..30) { $ns.WriteByte(72); $ns.Flush(); Start-Sleep -Seconds 1 }
        }
        try { $r = Invoke-Probe -Mode http -Port $s.Port -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be 42
        $r['__wall_ms'] | Should -BeLessThan 12000
    }

    It 'silence after the request gives 42 HTTP_TIMEOUT within the deadline' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $buf = New-Object byte[] 4096; [void]$client.GetStream().Read($buf, 0, 4096)
            Start-Sleep -Seconds 20
        }
        try { $r = Invoke-Probe -Mode http -Port $s.Port -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be 42
        $r['__wall_ms'] | Should -BeLessThan $script:DeadlineMs
    }
}

Describe 'Stall phase (plain stream)' {
    It 'reset after ~16 KB gives 50 STALL with partial bytes_sent' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $ns = $client.GetStream(); $buf = New-Object byte[] 4096; $total = 0
            while ($total -lt 16384) { $n = $ns.Read($buf, 0, 4096); if ($n -le 0) { break }; $total += $n }
            $client.Client.LingerState = New-Object System.Net.Sockets.LingerOption($true, 0)
            $client.Client.Close()
        }
        try { $r = Invoke-Probe -Mode stall -Port $s.Port -Path '/check/post' -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be 50
        $r.bytes_sent | Should -BeGreaterThan 0
        $r.bytes_sent | Should -BeLessThan 262144
    }

    It 'a server that reads once and then stops gives 50 at the phase budget, not after the item timeout' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $client.ReceiveBufferSize = 4096
            $buf = New-Object byte[] 4096; [void]$client.GetStream().Read($buf, 0, 4096)
            Start-Sleep -Seconds 25
        }
        try { $r = Invoke-Probe -Mode stall -Port $s.Port -Path '/check/post' -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be 50
        $r.bytes_sent | Should -BeGreaterThan 0
        $r.bytes_sent | Should -BeLessThan 262144
        $r['__wall_ms'] | Should -BeLessThan 12000
    }

    It 'a throttled upload (4 KB a second) gives 50 at the phase budget' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $client.ReceiveBufferSize = 4096
            $ns = $client.GetStream(); $buf = New-Object byte[] 4096
            foreach ($i in 1..30) { [void]$ns.Read($buf, 0, 4096); Start-Sleep -Seconds 1 }
        }
        try { $r = Invoke-Probe -Mode stall -Port $s.Port -Path '/check/post' -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be 50
        $r.bytes_sent | Should -BeLessThan 262144
        $r['__wall_ms'] | Should -BeLessThan 12000
    }

    It 'early 302 before the body is read gives 0' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $ns = $client.GetStream(); $buf = New-Object byte[] 4096; [void]$ns.Read($buf, 0, 4096)
            $b = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 302 Found`r`nLocation: /install`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
            $ns.Write($b, 0, $b.Length); $ns.Flush()
            $client.Client.Shutdown('Send'); Start-Sleep -Milliseconds 2000
        }
        try { $r = Invoke-Probe -Mode stall -Port $s.Port -Path '/check/post' -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be 0
        $r.http_code | Should -Be 302
    }

    It 'server reading the whole body and answering 302 gives 0 with bytes_sent 262144' {
        $s = Start-FakeServer -Behavior {
            param($client, $cert)
            $ns = $client.GetStream(); $buf = New-Object byte[] 65536; $seen = New-Object System.IO.MemoryStream
            $headEnd = -1
            while ($true) {
                $n = $ns.Read($buf, 0, $buf.Length); if ($n -le 0) { break }
                $seen.Write($buf, 0, $n)
                if ($headEnd -lt 0) {
                    $i = [Text.Encoding]::ASCII.GetString($seen.ToArray()).IndexOf("`r`n`r`n")
                    if ($i -ge 0) { $headEnd = $i + 4 }
                }
                if ($headEnd -ge 0 -and ($seen.Length - $headEnd) -ge 262144) { break }
            }
            $b = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 302 Found`r`nLocation: /install`r`nContent-Length: 0`r`n`r`n")
            $ns.Write($b, 0, $b.Length); $ns.Flush(); Start-Sleep -Milliseconds 300
        }
        try { $r = Invoke-Probe -Mode stall -Port $s.Port -Path '/check/post' -UseTls $false } finally { Stop-FakeServer $s }
        $r.class | Should -Be 0
        $r.http_code | Should -Be 302
        $r.bytes_sent | Should -Be 262144
    }
}

Describe 'GOST phase (csptest)' {
    BeforeAll {
        $script:Accept = { param($client, $cert) Start-Sleep -Milliseconds 500 }
        # Output shapes seen from real csptest (CSP 5.0.12000 and 5.0.13000) with -hello -exchange 3.
        $script:FakeAccepted = Join-Path $TestDrive 'csptest-accepted.cmd'
        Set-Content -Path $script:FakeAccepted -Encoding ASCII -Value "@echo off`r`necho Total: SYS: 0,016 sec USR: 0,016 sec UTC: 0,083 sec`r`necho [ErrorCode: 0x00000000]`r`nexit /b 0"
        $script:FakeSspi = Join-Path $TestDrive 'csptest-sspi.cmd'
        Set-Content -Path $script:FakeSspi -Encoding ASCII -Value "@echo off`r`necho **** Error 0x80090326 returned by InitializeSecurityContext (2)`r`necho [ErrorCode: 0x80090326]`r`nexit /b 1"
        $script:FakeArgs = Join-Path $TestDrive 'csptest-args.cmd'
        Set-Content -Path $script:FakeArgs -Encoding ASCII -Value "@echo off`r`necho invalid option -- 'silent'`r`necho [ErrorCode: 0x000000a0]`r`nexit /b 160"
        $script:FakeHang = Join-Path $TestDrive 'csptest-hang.cmd'
        Set-Content -Path $script:FakeHang -Encoding ASCII -Value "@echo off`r`nping -n 30 127.0.0.1 >nul"
    }

    It 'missing csptest gives 90 GOST_NO_CSP' {
        $s = Start-FakeServer -Behavior $script:Accept
        try { $r = Invoke-Probe -Mode gost -Port $s.Port -CsptestPath (Join-Path $TestDrive 'absent\csptest.exe') } finally { Stop-FakeServer $s }
        $r.class | Should -Be 90
        $r.class_name | Should -Be 'GOST_NO_CSP'
    }

    It 'accepted GOST ClientHello (ErrorCode 0) gives 0' {
        $s = Start-FakeServer -Behavior $script:Accept
        try { $r = Invoke-Probe -Mode gost -Port $s.Port -CsptestPath $script:FakeAccepted } finally { Stop-FakeServer $s }
        $r.class | Should -Be 0
        $r.tls_ms | Should -BeGreaterOrEqual 0
        $r.error | Should -BeNullOrEmpty
    }

    It 'rejected GOST ClientHello (SSPI ErrorCode) gives 32 TLS_FAIL' {
        $s = Start-FakeServer -Behavior $script:Accept
        try { $r = Invoke-Probe -Mode gost -Port $s.Port -CsptestPath $script:FakeSspi } finally { Stop-FakeServer $s }
        $r.class | Should -Be 32
        $r.error | Should -Match '0x80090326'
    }

    It 'csptest rejecting its arguments gives 32 with the code, not OK' {
        $s = Start-FakeServer -Behavior $script:Accept
        try { $r = Invoke-Probe -Mode gost -Port $s.Port -CsptestPath $script:FakeArgs } finally { Stop-FakeServer $s }
        $r.class | Should -Be 32
        $r.error | Should -Match '0x000000a0'
    }

    It 'hanging csptest gives 30 TLS_TIMEOUT within the deadline' {
        $s = Start-FakeServer -Behavior $script:Accept
        try { $r = Invoke-Probe -Mode gost -Port $s.Port -CsptestPath $script:FakeHang } finally { Stop-FakeServer $s }
        $r.class | Should -Be 30
        $r['__wall_ms'] | Should -BeLessThan $script:DeadlineMs
    }
}

Describe 'Interactive mode' {
    BeforeAll {
        # Canned probe result: class, total ms, cert days; nothing touches the network.
        function New-Result([int]$Class = 0, [int]$Ms = 100, [int]$CertDays = 100) {
            $r = New-EdoResult
            $message = ''; if ($Class) { $message = 'canned failure' }
            Set-EdoClass $r $Class $message
            $r.total_ms = $Ms; $r.cert_days = $CertDays; $r.ip = '192.0.2.10'
            $r
        }
        function New-Target([string]$Mode = 'http', [int]$Port = 443) {
            @(ConvertFrom-EdoTargetList "Цель|$Mode|example.com|$Port|/")[0]
        }
        $script:NoProxy = @{ WinHttp = ''; UserProxy = ''; UserPac = '' }
        function Invoke-Interactive([object[]]$ArgList, [scriptblock]$Probe, $ProxyInfo = $script:NoProxy) {
            $lines = New-Object Collections.Generic.List[string]
            $code = Invoke-EdoInteractive -ArgList $ArgList -Probe $Probe -ProxyInfo $ProxyInfo -Sink { param($text) $lines.Add($text) }.GetNewClosure()
            [pscustomobject]@{ Code = $code; Text = ($lines -join "`n") }
        }
    }

    Context 'switch parsing' {
        It 'console-shaped arguments: arrays, integers and -Name: tokens' {
            $o = ConvertFrom-EdoSwitches @('-Group', @('fns', 'taxcom'), '-Repeat', 3, '-Out:', 'x')
            $o.Error | Should -BeNullOrEmpty
            $o.Group -join ',' | Should -Be 'FNS,Taxcom'
            $o.Repeat | Should -Be 3
            $o.Out | Should -Be 'x'
        }

        It '-File-shaped arguments: comma string and -Out:value' {
            $o = ConvertFrom-EdoSwitches @('-group', 'FNSGOST,kontur', '-Out:C:\t\r', '-ViaProxy')
            $o.Error | Should -BeNullOrEmpty
            $o.Group -join ',' | Should -Be 'FNSGost,Kontur'
            $o.Out | Should -Be 'C:\t\r'
            $o.ViaProxy | Should -BeTrue
        }

        It 'defaults are fully populated' {
            $o = ConvertFrom-EdoSwitches @()
            $o.Error | Should -BeNullOrEmpty
            $o.Repeat | Should -Be 1
            @($o.Group).Count | Should -Be 0
            $o.Out | Should -Be ''
            $o.ViaProxy | Should -BeFalse
        }

        It 'rejects <case>' -ForEach @(
            @{ case = 'unknown switch'; argv = @('-Bogus') }
            @{ case = 'Repeat 0'; argv = @('-Repeat', '0') }
            @{ case = 'Repeat x'; argv = @('-Repeat', 'x') }
            @{ case = 'unknown group'; argv = @('-Group', 'Nope') }
            @{ case = 'missing value'; argv = @('-Target') }
            @{ case = 'stray value'; argv = @('-ViaProxy', 'yes') }
        ) {
            (ConvertFrom-EdoSwitches $argv).Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'target selection' {
        It '-Group fns,taxcom selects 5 targets' {
            @(Get-EdoSelectedTargets (ConvertFrom-EdoSwitches @('-Group', 'fns,taxcom'))).Count | Should -Be 5
        }

        It '<sw> <spec> gives <mode> <port> <path>' -ForEach @(
            @{ spec = 'lkul.nalog.ru'; sw = '-Target'; mode = 'http'; port = '443'; path = '/' }
            @{ spec = 'host.example:8080/x/y'; sw = '-Target'; mode = 'http'; port = '8080'; path = '/x/y' }
            @{ spec = 'lkulgost.nalog.ru'; sw = '-Gost'; mode = 'gost'; port = '443'; path = '/' }
        ) {
            $t = @(Get-EdoSelectedTargets (ConvertFrom-EdoSwitches @($sw, $spec)))
            $t.Count | Should -Be 1
            $t[0].Mode | Should -Be $mode
            $t[0].Port | Should -Be $port
            $t[0].Path | Should -Be $path
            $t[0].Name | Should -Be $t[0].Host
            $t[0].Error | Should -BeNullOrEmpty
        }

        It '-Targets with a bad entry is rejected and names it' {
            (ConvertFrom-EdoSwitches @('-Targets', 'Ok|http|example.com|443|/;Bad|ftp|example.com|21|/')).Error | Should -Match 'Bad'
        }

        It 'a bad -Target is rejected' {
            (ConvertFrom-EdoSwitches @('-Target', 'bad;host')).Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'labels and verdicts' {
        It '<case> -> <label>' -ForEach @(
            @{ case = 'fast OK'; class = 0; ms = 100; days = 100; mode = 'http'; port = 443; label = 'OK' }
            @{ case = 'slow OK'; class = 0; ms = 3001; days = 100; mode = 'http'; port = 443; label = 'SLOW' }
            @{ case = 'stall 7 s'; class = 0; ms = 7000; days = 100; mode = 'stall'; port = 443; label = 'OK' }
            @{ case = 'stall 9 s'; class = 0; ms = 9000; days = 100; mode = 'stall'; port = 443; label = 'SLOW' }
            @{ case = 'cert 5 days'; class = 0; ms = 100; days = 5; mode = 'http'; port = 443; label = 'CERT' }
            @{ case = 'plain http, no cert'; class = 0; ms = 100; days = -1; mode = 'http'; port = 80; label = 'OK' }
            @{ case = 'slow and cert'; class = 0; ms = 3500; days = 5; mode = 'http'; port = 443; label = 'CERT' }
            @{ case = 'TCP timeout'; class = 20; ms = 5000; days = -1; mode = 'http'; port = 443; label = 'FAIL' }
            @{ case = 'probe error'; class = 91; ms = 1; days = -1; mode = 'http'; port = 443; label = 'ERR' }
            @{ case = 'no CSP'; class = 90; ms = 1; days = -1; mode = 'gost'; port = 443; label = 'N/A' }
        ) {
            Get-EdoLabel (New-Result $class $ms $days) (New-Target $mode $port) | Should -Be $label
        }

        It 'mass verdict for <case>' -ForEach @(
            @{ case = '3 of 5 FAIL'; classes = @(20, 20, 20, 0, 0); mass = $true }
            @{ case = '2 of 3 FAIL'; classes = @(20, 20, 0); mass = $false }
            @{ case = '1 of 4 FAIL'; classes = @(20, 0, 0, 0); mass = $false }
            @{ case = '13 FAIL of 27 with 2 N/A'; classes = (@(20) * 13 + @(0) * 12 + @(90, 90)); mass = $true }
            @{ case = '13 FAIL of 27 without N/A'; classes = (@(20) * 13 + @(0) * 14); mass = $false }
            @{ case = 'all ERR'; classes = @(91, 91, 91); mass = $false }
        ) {
            Test-EdoMassFailure @($classes | ForEach-Object { New-Result $_ }) | Should -Be $mass
        }

        It 'an AccessDenied connect says the local firewall blocked it' {
            $r = New-Result 23 5 -1
            $r.error = 'SocketException AccessDenied: access denied 192.0.2.10:443'
            Format-EdoLine 'FAIL' (New-Target) $r | Should -Match 'запрещено брандмауэром Windows \[23 TCP_FAIL\]'
        }

        It 'every failure class has a short text and advice' {
            foreach ($c in @($script:EdoClassNames.Keys)) {
                if ($c -eq 0) { continue }
                @($script:EdoAdvice[$c]).Count | Should -Be 2 -Because "class $c"
            }
        }
    }

    Context 'run' {
        It 'prints header, lines, advice and returns 1 on a failure' {
            $probe = { param($t) if ($t.Host -eq 'bad.example') { New-Result 22 2000 -1 } else { New-Result 0 120 200 } }
            $r = Invoke-Interactive @('-Targets', 'Хорошая|http|good.example|443|/;Плохая|http|bad.example|443|/') $probe
            $r.Code | Should -Be 1
            $r.Text | Should -Match $env:COMPUTERNAME
            $r.Text | Should -Match 'Хорошая'
            $r.Text | Should -Match 'OK'
            $r.Text | Should -Match 'FAIL'
            $r.Text | Should -Match '22 TCP_REFUSED'
            $r.Text | Should -Match 'Что делать'
            $r.Text | Should -Match 'bad\.example'
            $r.Text | Should -Not -Match 'Массов'
        }

        It 'returns 0 when everything is OK, SLOW or N/A' {
            $probe = { param($t) switch ($t.Host) { 'a.example' { New-Result 0 100 } 'b.example' { New-Result 0 5000 } default { New-Result 90 1 -1 } } }
            $r = Invoke-Interactive @('-Targets', 'A|http|a.example|443|/;B|http|b.example|443|/;C|gost|c.example|443|/') $probe
            $r.Code | Should -Be 0
            $r.Text | Should -Match 'SLOW'
            $r.Text | Should -Match 'N/A'
            $r.Text | Should -Match '\[SLOW\] медленный ответ: b\.example'
            $r.Text | Should -Match '\[90 GOST_NO_CSP\]'
        }

        It 'default run says targets are template defaults; -Targets run does not' {
            $probe = { param($t) New-Result 0 }
            (Invoke-Interactive @('-Group', 'Taxcom') $probe).Text | Should -Match '-Targets'
            (Invoke-Interactive @('-Targets', 'A|http|a.example|443|/') $probe).Text | Should -Not -Match 'значения шаблона'
        }

        It 'mass failure across services: proxy set -> points to -ViaProxy' {
            $proxy = @{ WinHttp = ''; UserProxy = 'proxy.local:3128'; UserPac = '' }
            $r = Invoke-Interactive @('-Group', 'CRPT,Taxcom') { param($t) New-Result 20 5000 -1 } $proxy
            $r.Text | Should -Match 'Массовый отказ: большинство целей недоступно напрямую'
            $r.Text | Should -Match '-ViaProxy'
        }

        It 'mass failure across services without a proxy blames this computer' {
            $r = Invoke-Interactive @('-Group', 'CRPT,Taxcom') { param($t) New-Result 20 5000 -1 }
            $r.Text | Should -Match 'Массовый отказ: недоступна большая часть целей'
            $r.Text | Should -Not -Match 'большинство целей недоступно напрямую'
        }

        It 'FNS with its GOST cabinets is one service, so is Kontur with its large POST' {
            $r = Invoke-Interactive @('-Group', 'FNS,FNSGost') { param($t) New-Result 20 5000 -1 }
            $r.Text | Should -Match 'Все отказы — у одного сервиса \(ФНС\)'
            $r = Invoke-Interactive @('-Group', 'Kontur,Stall') { param($t) New-Result 20 5000 -1 }
            $r.Text | Should -Match 'Все отказы — у одного сервиса \(Контур\)'
        }

        It 'an explicitly empty -Targets is an error: <case>' -ForEach @(@{ case = 'empty string'; v = '' }, @{ case = 'only separators'; v = ' ; ' }) {
            (Invoke-Interactive @('-Targets', $v) { throw 'must not probe' }).Code | Should -Be 2
        }

        It 'many failures of one service point to that service, not to the computer' {
            $r = Invoke-Interactive @('-Group', 'CRPT') { param($t) New-Result 20 5000 -1 }
            $r.Text | Should -Match 'Все отказы — у одного сервиса \(Честный знак\)'
            $r.Text | Should -Not -Match 'Массовый отказ'
        }

        It '<sw> prints usage and returns 0 without probing' -ForEach @(@{ sw = '-Help' }, @{ sw = '-h' }, @{ sw = '-?' }) {
            $r = Invoke-Interactive @($sw) { throw 'must not probe' }
            $r.Code | Should -Be 0
            $r.Text | Should -Match '-ViaProxy'
        }

        It 'an empty -Targets is an error, not a run of all template targets' {
            $r = Invoke-Interactive @('-Targets', ' ; ') { throw 'must not probe' }
            $r.Code | Should -Be 2
        }

        It 'a relative -Out follows the PowerShell location' {
            Push-Location $TestDrive
            try { [void](Invoke-Interactive @('-Targets', 'A|http|a.example|443|/', '-Out', 'rel') { param($t) New-Result 0 }) }
            finally { Pop-Location }
            Test-Path -LiteralPath (Join-Path $TestDrive 'rel.txt') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $TestDrive 'rel.json') | Should -BeTrue
        }

        It 'a stopped pipeline (Ctrl+C) still prints the summary and writes -Out' {
            $out = Join-Path $TestDrive 'stop'
            $lines = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList))
            $ps = [powershell]::Create()
            [void]$ps.AddScript({
                param($probePath, $out, $lines)
                . $probePath
                $probe = { param($t) if ($t.Host -eq 'b.example') { Start-Sleep 30 }; $r = New-EdoResult; $r.total_ms = 5; $r }
                Invoke-EdoInteractive -ArgList @('-Targets', 'A|http|a.example|443|/;B|http|b.example|443|/', '-Out', $out) -Probe $probe -ProxyInfo @{ WinHttp = ''; UserProxy = ''; UserPac = '' } -Sink { param($x) [void]$lines.Add($x) }.GetNewClosure()
            }).AddArgument($script:ProbePath).AddArgument($out).AddArgument($lines)
            $handle = $ps.BeginInvoke()
            $deadline = [DateTime]::Now.AddSeconds(20)
            while (-not ($lines -match 'a\.example') -and [DateTime]::Now -lt $deadline) { Start-Sleep -Milliseconds 100 }
            $ps.Stop()
            $ps.Dispose()
            ($lines -join "`n") | Should -Match 'Прогон прерван\.'
            ($lines -join "`n") | Should -Match 'Итог \(проверок: 1'
            Test-Path -LiteralPath "$out.json" | Should -BeTrue
        }

        It 'returns 2 with usage on a bad switch' {
            $r = Invoke-Interactive @('-Bogus') { throw 'must not probe' }
            $r.Code | Should -Be 2
            $r.Text | Should -Match '-Group'
        }

        It 'an exception mid-run still prints the summary and writes -Out, marked interrupted' {
            $out = Join-Path $TestDrive 'int'
            $probe = { param($t) if ($t.Host -eq 'b.example') { throw 'boom' }; New-Result 0 }
            $r = Invoke-Interactive @('-Targets', 'A|http|a.example|443|/;B|http|b.example|443|/;C|http|c.example|443|/', '-Out', $out) $probe
            $r.Code | Should -Be 1
            $r.Text | Should -Match 'прерван'
            $r.Text | Should -Match 'boom'
            Test-Path -LiteralPath "$out.txt" | Should -BeTrue
            (ConvertFrom-Json (Get-Content -LiteralPath "$out.json" -Raw)).Count | Should -Be 1
        }

        It '-Repeat 3 counts passes, flags an unstable target, runs stall once, returns 1' {
            $script:n = 0; $script:stall = 0
            $probe = { param($t) if ($t.Mode -eq 'stall') { $script:stall++; return (New-Result 0) }; $script:n++; if ($script:n % 2) { New-Result 0 } else { New-Result 20 5000 -1 } }
            $r = Invoke-Interactive @('-Repeat', '3', '-Targets', 'A|http|a.example|443|/;S|stall|s.example|443|/') $probe
            $script:stall | Should -Be 1
            $r.Code | Should -Be 1
            $r.Text | Should -Match 'нестабил'
            $r.Text | Should -Match '2/1'
        }

        It '-Out writes plain text and JSON with numeric classes' {
            $out = Join-Path $TestDrive 'out'
            [void](Invoke-Interactive @('-Repeat', '2', '-Targets', 'A|http|a.example|443|/;B|http|b.example|443|/', '-Out', "$out.txt") { param($t) New-Result 0 })
            $json = ConvertFrom-Json (Get-Content -LiteralPath "$out.json" -Raw)
            $json.Count | Should -Be 4
            $json[0].class | Should -BeOfType [int]
            $json[0].name | Should -Be 'A'
            $json[0].pass | Should -Be 1
            $txt = Get-Content -LiteralPath "$out.txt" -Raw
            $txt | Should -Match 'Итог'
            $txt | Should -Not -Match "\x1b"
        }
    }

    Context 'proxy' {
        It 'WinHTTP settings blob: <case>' -ForEach @(
            @{ case = 'direct'; hex = '2800000001000000010000000000000000000000'; proxy = '' }
            @{ case = 'proxy'; hex = '2800000002000000030000001000000070726f78792e6c6f63616c3a3331323800000000'; proxy = 'proxy.local:3128' }
            @{ case = 'empty'; hex = ''; proxy = '' }
        ) {
            $bytes = [byte[]]@(for ($i = 0; $i -lt $hex.Length; $i += 2) { [Convert]::ToByte($hex.Substring($i, 2), 16) })
            ConvertFrom-EdoWinHttpSettings $bytes | Should -BeExactly $proxy
        }

        It 'proxy string <text> -> <uri>' -ForEach @(
            @{ text = 'proxy.local:3128'; uri = 'http://proxy.local:3128/' }
            @{ text = 'http=p1:3128;https=p2:3129'; uri = 'http://p2:3129/' }
            @{ text = 'http=p1:3128'; uri = 'http://p1:3128/' }
            @{ text = 'http://p3:8080'; uri = 'http://p3:8080/' }
        ) {
            "$(ConvertTo-EdoProxyUri $text)" | Should -Be $uri
        }

        It '-ViaProxy without any proxy says so and probes direct only' {
            $r = Invoke-Interactive @('-ViaProxy', '-Targets', 'A|http|a.example|443|/') { param($t) New-Result 0 }
            $r.Code | Should -Be 0
            $r.Text | Should -Match 'прокси не настроен'
        }

        It 'fetch through a proxy: <case>' -ForEach @(
            @{ case = 'proxy answers 200'; status = '200 OK'; expect = 'через прокси Windows 127\.0\.0\.1:\d+: HTTP 200' }
            @{ case = 'proxy wants credentials'; status = '407 Proxy Authentication Required'; expect = 'HTTP 407: прокси требует аутентификацию' }
            @{ case = 'proxy fails'; status = '502 Bad Gateway'; expect = 'HTTP 502: ошибка на прокси или сервисе' }
        ) {
            $s = Start-FakeServer -Behavior ([scriptblock]::Create(@"
                param(`$client, `$cert)
                `$ns = `$client.GetStream()
                `$buf = New-Object byte[] 4096; `$n = `$ns.Read(`$buf, 0, 4096)
                if (-not [Text.Encoding]::ASCII.GetString(`$buf, 0, `$n).StartsWith('GET http://example.com/')) { return }
                `$b = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $status``r``nContent-Length: 0``r``nConnection: close``r``n``r``n")
                `$ns.Write(`$b, 0, `$b.Length); `$ns.Flush(); Start-Sleep -Milliseconds 300
"@))
            try {
                $stub = [pscustomobject]@{ P = [Uri]"http://127.0.0.1:$($s.Port)/" }
                $stub | Add-Member ScriptMethod IsBypassed { param($u) $false }
                $stub | Add-Member ScriptMethod GetProxy { param($u) $this.P }
                $text = Invoke-EdoProxyFetch (New-Target 'http' 80) '' $stub
            } finally { Stop-FakeServer $s }
            $text | Should -Match $expect
        }

        It 'fetch for an address the proxy bypasses and no WinHTTP proxy says so' {
            $stub = [pscustomobject]@{}
            $stub | Add-Member ScriptMethod IsBypassed { param($u) $true }
            Invoke-EdoProxyFetch (New-Target) '' $stub | Should -Match 'прокси не применяется'
        }

        It 'a failing proxy resolution stays on its target line' {
            $stub = [pscustomobject]@{}
            $stub | Add-Member ScriptMethod IsBypassed { param($u) throw 'PAC script error' }
            Invoke-EdoProxyFetch (New-Target) '' $stub | Should -Match 'прокси не определён.*PAC script error'
        }

        It 'reads this host''s proxy settings without throwing' {
            $p = Get-EdoProxyInfo
            $p.ContainsKey('WinHttp') | Should -BeTrue
            $p.ContainsKey('UserProxy') | Should -BeTrue
            $p.ContainsKey('UserPac') | Should -BeTrue
        }
    }

    Context 'as a process' {
        It 'empty strings from agent2 stay in Zabbix mode' {
            $r = Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('', '', '', '')
            $r.ExitCode | Should -Be 0
            $r.StdErr | Should -BeNullOrEmpty
            ($r.StdOut | ConvertFrom-Json).class | Should -Be 91
        }

        It 'switches select manual mode only when not SYSTEM; no arguments always do' {
            Test-EdoManualCall @() $true | Should -BeTrue
            Test-EdoManualCall @('-Group', 'FNS') $false | Should -BeTrue
            Test-EdoManualCall @('-Group', 'FNS') $true | Should -BeFalse
            Test-EdoManualCall @('-1', 'example.com', '443', '/') $false | Should -BeFalse
            Test-EdoManualCall @('http', 'example.com', '443', '/') $false | Should -BeFalse
        }

        It 'bad switch exits 2' {
            (Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('-Bogus')).ExitCode | Should -Be 2
        }

        It 'refused loopback port: Cyrillic readable in the OEM code page, exit 1' {
            $port = Get-ClosedPort
            $r = Invoke-ProbeProcess -ScriptPath $script:ProbePath -ArgumentList @('-Targets', "Закрытый|http|127.0.0.1|$port|/") -Oem
            $r.ExitCode | Should -Be 1
            $r.StdOut | Should -Match 'Закрытый'
            $r.StdOut | Should -Match '22 TCP_REFUSED'
            $r.StdOut | Should -Match 'Что делать'
        }

        It 'the real probe through the interactive loop reaches a fake HTTP server' {
            $s = Start-FakeServer -Behavior {
                param($client, $cert)
                $ns = $client.GetStream()
                $buf = New-Object byte[] 4096; [void]$ns.Read($buf, 0, 4096)
                $b = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 0`r`n`r`n")
                $ns.Write($b, 0, $b.Length); $ns.Flush(); Start-Sleep -Milliseconds 300
            }
            try {
                $probe = { param($t) Invoke-EdoProbe -Mode $t.Mode -TargetHost $t.Host -Port $t.Port -Path $t.Path -UseTls $false }
                $r = Invoke-Interactive @('-Targets', "Фейк|http|127.0.0.1|$($s.Port)|/") $probe
            } finally { Stop-FakeServer $s }
            $r.Code | Should -Be 0
            $r.Text | Should -Match 'OK\s+Фейк'
        }
    }
}
