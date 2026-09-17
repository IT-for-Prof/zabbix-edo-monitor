<#
.SYNOPSIS
    EDO Monitor probe: DNS -> TCP -> TLS -> HTTP to one target, one JSON object on stdout.

.DESCRIPTION
    Run by Zabbix agent2 through UserParameter edo.probe[mode,host,port,path].
    Always prints exactly one ASCII JSON object and exits with code 0; every failure,
    including bad arguments, becomes a class code. Nothing is ever written to stderr:
    agent2 glues stderr into the item value and would break every dependent item.

    Classes: 0 OK, 10 DNS_FAIL, 20 TCP_TIMEOUT, 22 TCP_REFUSED, 23 TCP_FAIL,
    30 TLS_TIMEOUT, 31 TLS_RESET, 32 TLS_FAIL, 33 CERT_UNTRUSTED, 40 HTTP_BAD,
    42 HTTP_TIMEOUT, 50 STALL, 90 GOST_NO_CSP, 91 PROBE_ERROR.

.NOTES
    itforprof.com by Konstantin Tyutyunnik

    Arguments are positional ($args, not a param block): an argument starting with "-"
    must not turn into a parameter binding error on stderr.
#>

Set-StrictMode -Version 2.0

$script:EdoClassNames = @{
    0 = 'OK'; 10 = 'DNS_FAIL'; 20 = 'TCP_TIMEOUT'; 22 = 'TCP_REFUSED'; 23 = 'TCP_FAIL'
    30 = 'TLS_TIMEOUT'; 31 = 'TLS_RESET'; 32 = 'TLS_FAIL'; 33 = 'CERT_UNTRUSTED'
    40 = 'HTTP_BAD'; 42 = 'HTTP_TIMEOUT'; 50 = 'STALL'; 90 = 'GOST_NO_CSP'; 91 = 'PROBE_ERROR'
}

# Static phase budgets, ms, each covering its whole phase. Sums stay under the 25 s deadline (item timeout 30 s,
# powershell.exe start on a loaded terminal server up to ~3 s): http and stall 2+5+7+9 = 23 s (stall's upload and answer share
# the Http budget), gost 2+5+13 + 2 x 1 s output wait = 22 s. Normal phases take < 0.2 s.
$script:EdoBudget = @{ Dns = 2000; Tcp = 5000; Tls = 7000; Http = 9000; Csptest = 13000; CsptestOutput = 1000 }
$script:EdoStallBytes = 262144
$script:EdoStallChunk = 4096

function New-EdoResult {
    [ordered]@{
        class = 0; class_name = 'OK'; ip = ''
        dns_ms = -1; tcp_ms = -1; tls_ms = -1; http_ms = -1; total_ms = -1
        tls_proto = ''; cert_days = -1; cert_issuer = ''; http_code = -1; bytes_sent = -1; error = ''
    }
}

function Set-EdoClass {
    param($Result, [int]$Class, [string]$Message = '')
    $Result.class = $Class
    $Result.class_name = $script:EdoClassNames[$Class]
    if ($Message.Length -gt 300) { $Message = $Message.Substring(0, 300) }
    $Result.error = $Message
}

function Get-EdoInnermostException {
    param($Exception)
    $x = $Exception
    while ($true) {
        if ($x -is [AggregateException] -and $x.InnerExceptions.Count -gt 0) { $x = $x.InnerExceptions[0]; continue }
        if ($null -ne $x.InnerException) { $x = $x.InnerException; continue }
        return $x
    }
}

function Format-EdoError {
    param($Exception)
    $x = Get-EdoInnermostException $Exception
    $text = "$($x.GetType().Name): $($x.Message)"
    if ($x -is [System.Net.Sockets.SocketException]) { $text = "$($x.GetType().Name) $($x.SocketErrorCode): $($x.Message)" }
    ($text -replace '\s+', ' ').Trim()
}

function Get-EdoSocketError {
    param($Exception)
    $x = Get-EdoInnermostException $Exception
    if ($x -is [System.Net.Sockets.SocketException]) { return $x.SocketErrorCode }
    $null
}

function Get-EdoTcpClass {
    param([System.Net.Sockets.SocketError]$SocketError)
    switch ($SocketError) {
        'TimedOut'          { return 20 }
        'ConnectionRefused' { return 22 }
        default             { return 23 }
    }
}

# Case-sensitive and anchored with \z: in .NET "$" also matches before a trailing newline, and -notcontains
# ignores case, while the discovery JavaScript accepts neither. "~" is refused by agent2 in key parameters;
# "%" passes agent2 but cmd.exe expands %VAR% before powershell.exe starts (verified with agent2 -t).
function Test-EdoArgs {
    param([string]$Mode, [string]$TargetHost, [string]$Port, [string]$Path)
    if (@('http', 'stall', 'gost') -cnotcontains $Mode) { return "mode must be http, stall or gost" }
    if ($TargetHost -cnotmatch '^(?=.{1,253}\z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z') {
        return 'host must be a DNS name or IPv4 address'
    }
    if ($Port -cnotmatch '^[0-9]{1,5}\z' -or [int]$Port -lt 1 -or [int]$Port -gt 65535) { return 'port must be 1..65535' }
    if ($Path -cnotmatch '^/[A-Za-z0-9._/-]*\z') { return 'path must start with / and use only A-Z a-z 0-9 . _ / -' }
    $null
}

# Port 80 is plain HTTP; every other port gets TLS.
function Get-EdoUseTls {
    param([int]$Port)
    $Port -ne 80
}

function Find-EdoCsptest {
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        $candidate = Join-Path $root 'Crypto Pro\CSP\csptest.exe'
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    Join-Path "$env:ProgramFiles" 'Crypto Pro\CSP\csptest.exe'
}

# The HTTP/stall budget covers the whole phase, not each call: a server dripping bytes or a throttled
# upload must not stretch the phase to budget x calls. Throws TimeoutException once the budget is spent.
function Set-EdoPhaseTimeout {
    param($NetworkStream, $Stopwatch, [int]$BudgetMs)
    $left = $BudgetMs - [int]$Stopwatch.ElapsedMilliseconds
    if ($left -le 0) { throw (New-Object TimeoutException("phase budget of $BudgetMs ms spent")) }
    $NetworkStream.ReadTimeout = $left
    $NetworkStream.WriteTimeout = $left
}

function Test-EdoTimeout {
    param($Exception)
    ((Get-EdoInnermostException $Exception) -is [TimeoutException]) -or ((Get-EdoSocketError $Exception) -eq [Net.Sockets.SocketError]::TimedOut)
}

# Reads until the status line is complete, EOF or 4 KB. Returns the text read.
function Read-EdoStatusLine {
    param($Stream, $NetworkStream, $Stopwatch, [int]$BudgetMs)
    $buf = New-Object byte[] 4096
    $total = 0
    while ($total -lt $buf.Length) {
        Set-EdoPhaseTimeout $NetworkStream $Stopwatch $BudgetMs
        $n = $Stream.Read($buf, $total, $buf.Length - $total)
        if ($n -le 0) { break }
        $total += $n
        if ([Text.Encoding]::ASCII.GetString($buf, 0, $total).Contains("`r`n")) { break }
    }
    [Text.Encoding]::ASCII.GetString($buf, 0, $total)
}

# Classifies a response head by HTTP rules: status >= 500 is 40, any other status is 0.
function Set-EdoHttpStatus {
    param($Result, [string]$Head)
    if ($Head -match '^HTTP/\d\.\d (\d{3})') {
        $Result.http_code = [int]$Matches[1]
        if ($Result.http_code -ge 500) { Set-EdoClass $Result 40 "HTTP $($Result.http_code)" }
        return $true
    }
    $false
}

function Invoke-EdoGost {
    param($Result, [string]$TargetHost, [int]$Port, [string]$CsptestPath)
    if (-not (Test-Path -LiteralPath $CsptestPath)) {
        Set-EdoClass $Result 90 "csptest not found: $CsptestPath"
        return
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $CsptestPath
    # -hello: the server must accept a GOST-only ClientHello (-exchange 3). A full handshake is impossible
    # without the user's key: GOST cabinets demand a client certificate. -silent is absent in CSP 5.0.12000.
    $psi.Arguments = "-tlsc -server $TargetHost -port $Port -hello -exchange 3 -nosave"
    $psi.WorkingDirectory = [IO.Path]::GetTempPath()
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($script:EdoBudget.Csptest)) {
        # Kills csptest itself only; a grandchild keeping the pipe open is abandoned, not awaited.
        try { $p.Kill() } catch { }
        $Result.tls_ms = $sw.ElapsedMilliseconds
        Set-EdoClass $Result 30 "csptest did not finish in $($script:EdoBudget.Csptest) ms"
        return
    }
    $Result.tls_ms = $sw.ElapsedMilliseconds
    $text = ''
    if ($outTask.Wait($script:EdoBudget.CsptestOutput)) { $text += $outTask.Result }
    if ($errTask.Wait($script:EdoBudget.CsptestOutput)) { $text += "`n" + $errTask.Result }
    $codes = [regex]::Matches($text, 'ErrorCode:\s*(0x[0-9A-Fa-f]{8})')
    if ($codes.Count -gt 0) {
        $code = $codes[$codes.Count - 1].Groups[1].Value
        if ([Convert]::ToUInt32($code.Substring(2), 16) -eq 0) { return }
        Set-EdoClass $Result 32 "csptest ErrorCode $code"
        return
    }
    $tail = ($text -replace '\s+', ' ').Trim()
    if ($tail.Length -gt 200) { $tail = $tail.Substring($tail.Length - 200) }
    Set-EdoClass $Result 32 "csptest printed no ErrorCode (exit $($p.ExitCode)): $tail"
}

function Invoke-EdoProbe {
    param(
        [string]$Mode, [string]$TargetHost, [string]$Port, [string]$Path,
        $UseTls = $null,
        [string]$CsptestPath = ''
    )
    $ErrorActionPreference = 'Stop'
    $r = New-EdoResult
    $total = [Diagnostics.Stopwatch]::StartNew()
    $tc = $null
    try {
        $bad = Test-EdoArgs -Mode $Mode -TargetHost $TargetHost -Port $Port -Path $Path
        if ($bad) { Set-EdoClass $r 91 $bad; return $r }
        $portNumber = [int]$Port
        if ($null -eq $UseTls) { $UseTls = Get-EdoUseTls -Port $portNumber }

        # DNS: IPv4 only (AAAA answers gave false failures in zabbix-dpi-checker).
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $dns = [Net.Dns]::GetHostAddressesAsync($TargetHost)
        # Phase times are recorded on failure too: 5 s against 2 ms tells a timeout from a refusal at a glance.
        try { $resolved = $dns.Wait($script:EdoBudget.Dns) }
        catch { $r.dns_ms = $sw.ElapsedMilliseconds; Set-EdoClass $r 10 (Format-EdoError $_.Exception); return $r }
        $r.dns_ms = $sw.ElapsedMilliseconds
        if (-not $resolved) { Set-EdoClass $r 10 "DNS did not answer in $($script:EdoBudget.Dns) ms"; return $r }
        $v4 = @($dns.Result | Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork })
        if ($v4.Count -eq 0) { Set-EdoClass $r 10 'no IPv4 address'; return $r }
        $r.ip = $v4[0].ToString()

        # TCP
        $sw.Restart()
        $tc = New-Object System.Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetwork)
        if ($Mode -eq 'stall') { $tc.SendBufferSize = $script:EdoStallChunk }
        try { $connected = $tc.ConnectAsync($v4[0], $portNumber).Wait($script:EdoBudget.Tcp) }
        catch {
            $r.tcp_ms = $sw.ElapsedMilliseconds
            $code = Get-EdoSocketError $_.Exception
            $class = 23; if ($null -ne $code) { $class = Get-EdoTcpClass -SocketError $code }
            Set-EdoClass $r $class (Format-EdoError $_.Exception)
            return $r
        }
        $r.tcp_ms = $sw.ElapsedMilliseconds
        if (-not $connected) { Set-EdoClass $r 20 "TCP connect did not finish in $($script:EdoBudget.Tcp) ms"; return $r }

        if ($Mode -eq 'gost') {
            $tc.Close(); $tc = $null
            if (-not $CsptestPath) { $CsptestPath = Find-EdoCsptest }
            Invoke-EdoGost -Result $r -TargetHost $TargetHost -Port $portNumber -CsptestPath $CsptestPath
            return $r
        }

        $ns = $tc.GetStream()
        $stream = $ns

        # TLS: the OS picks the protocol, except stall: TLS 1.3 servers send session tickets after the handshake,
        # which would look like an early answer to the pending-data check below. Chain errors are recorded, not fatal.
        if ($UseTls) {
            $ns.ReadTimeout = $script:EdoBudget.Tls
            $ns.WriteTimeout = $script:EdoBudget.Tls
            $state = @{ policy = [Net.Security.SslPolicyErrors]::None }
            $callback = [Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $state.policy = $e; $true }.GetNewClosure()
            $ssl = New-Object System.Net.Security.SslStream($ns, $false, $callback)
            $sw.Restart()
            $protocols = [Security.Authentication.SslProtocols]::None
            if ($Mode -eq 'stall') { $protocols = [Security.Authentication.SslProtocols]::Tls12 }
            # The TLS budget is per read, not per handshake. AuthenticateAsClientAsync would run the
            # PowerShell certificate callback on a pool thread without a runspace (fails the handshake); a peer
            # dripping handshake bytes can outlast the item timeout -> nodata instead of 30. A compiled C# callback would lift this limit.
            try { $ssl.AuthenticateAsClient($TargetHost, $null, $protocols, $false) }
            catch {
                $r.tls_ms = $sw.ElapsedMilliseconds
                $code = Get-EdoSocketError $_.Exception
                $class = 32
                if ($code -eq [Net.Sockets.SocketError]::TimedOut) { $class = 30 }
                elseif ($code -eq [Net.Sockets.SocketError]::ConnectionReset -or $code -eq [Net.Sockets.SocketError]::ConnectionAborted) { $class = 31 }
                Set-EdoClass $r $class (Format-EdoError $_.Exception)
                return $r
            }
            $r.tls_ms = $sw.ElapsedMilliseconds
            $r.tls_proto = "$($ssl.SslProtocol)"
            if ($null -ne $ssl.RemoteCertificate) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                $r.cert_days = [int][Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
                $r.cert_issuer = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
            }
            if ($state.policy -ne [Net.Security.SslPolicyErrors]::None) {
                Set-EdoClass $r 33 "certificate: $($state.policy)"
                return $r
            }
            $stream = $ssl
        }

        $budget = $script:EdoBudget.Http
        $sw.Restart()
        if ($Mode -eq 'http') {
            $head = "GET $Path HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: edo-monitor`r`nAccept: */*`r`nConnection: close`r`n`r`n"
            $bytes = [Text.Encoding]::ASCII.GetBytes($head)
            try {
                Set-EdoPhaseTimeout $ns $sw $budget
                $stream.Write($bytes, 0, $bytes.Length)
                $answer = Read-EdoStatusLine $stream $ns $sw $budget
            } catch {
                $r.http_ms = $sw.ElapsedMilliseconds
                $class = 40; if (Test-EdoTimeout $_.Exception) { $class = 42 }
                Set-EdoClass $r $class (Format-EdoError $_.Exception)
                return $r
            }
            $r.http_ms = $sw.ElapsedMilliseconds
            if (-not (Set-EdoHttpStatus $r $answer)) { Set-EdoClass $r 40 'no HTTP status line' }
            return $r
        }

        # Stall: a large POST in small chunks; a break after part of the body is class 50.
        $head = "POST $Path HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: edo-monitor`r`nContent-Type: application/x-www-form-urlencoded`r`nContent-Length: $($script:EdoStallBytes)`r`nConnection: close`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($head)
        $chunk = New-Object byte[] $script:EdoStallChunk
        for ($i = 0; $i -lt $chunk.Length; $i++) { $chunk[$i] = 120 }
        $r.bytes_sent = 0
        try {
            Set-EdoPhaseTimeout $ns $sw $budget
            $stream.Write($bytes, 0, $bytes.Length)
            while ($r.bytes_sent -lt $script:EdoStallBytes) {
                # Pending data mid-upload is an early answer (stall runs TLS 1.2: no post-handshake tickets).
                if ($ns.DataAvailable) { break }
                Set-EdoPhaseTimeout $ns $sw $budget
                $stream.Write($chunk, 0, $chunk.Length)
                $r.bytes_sent += $chunk.Length
            }
        } catch {
            # A broken or stuck upload is the stall itself; reading after it would only spend more of the deadline.
            $r.http_ms = $sw.ElapsedMilliseconds
            Set-EdoClass $r 50 ("after $($r.bytes_sent) bytes: " + (Format-EdoError $_.Exception))
            return $r
        }
        try { $answer = Read-EdoStatusLine $stream $ns $sw $budget }
        catch {
            $r.http_ms = $sw.ElapsedMilliseconds
            Set-EdoClass $r 50 ("after $($r.bytes_sent) bytes: " + (Format-EdoError $_.Exception))
            return $r
        }
        $r.http_ms = $sw.ElapsedMilliseconds
        if (Set-EdoHttpStatus $r $answer) { return $r }
        Set-EdoClass $r 50 "after $($r.bytes_sent) bytes: no HTTP status line"
        return $r
    } catch {
        Set-EdoClass $r 91 (Format-EdoError $_.Exception)
        return $r
    } finally {
        if ($null -ne $tc) { $tc.Close() }
        $r.total_ms = $total.ElapsedMilliseconds
    }
}

# ASCII-only JSON: non-ASCII is escaped as \uXXXX, so the console code page cannot corrupt it.
function ConvertTo-EdoJson {
    param($Result)
    $parts = foreach ($key in $Result.Keys) {
        $value = $Result[$key]
        if ($value -is [string]) {
            $sb = New-Object System.Text.StringBuilder
            foreach ($ch in $value.ToCharArray()) {
                $code = [int]$ch
                if ($ch -eq '"') { [void]$sb.Append('\"') }
                elseif ($ch -eq '\') { [void]$sb.Append('\\') }
                elseif ($code -lt 32 -or $code -gt 126) { [void]$sb.AppendFormat('\u{0:x4}', $code) }
                else { [void]$sb.Append($ch) }
            }
            '"{0}":"{1}"' -f $key, $sb.ToString()
        } else {
            '"{0}":{1}' -f $key, ([long]$value).ToString([Globalization.CultureInfo]::InvariantCulture)
        }
    }
    '{' + ($parts -join ',') + '}'
}

if ($MyInvocation.InvocationName -ne '.') {
    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    try {
        $result = Invoke-EdoProbe -Mode "$($args[0])" -TargetHost "$($args[1])" -Port "$($args[2])" -Path "$($args[3])"
    } catch {
        $result = New-EdoResult
        Set-EdoClass $result 91 "$($_.Exception.Message)"
    }
    try { $json = ConvertTo-EdoJson $result }
    catch { $json = '{"class":91,"class_name":"PROBE_ERROR","ip":"","dns_ms":-1,"tcp_ms":-1,"tls_ms":-1,"http_ms":-1,"total_ms":-1,"tls_proto":"","cert_days":-1,"cert_issuer":"","http_code":-1,"bytes_sent":-1,"error":"JSON serialization failed"}' }
    [Console]::Out.Write($json)
    exit 0
}
