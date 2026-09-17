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
