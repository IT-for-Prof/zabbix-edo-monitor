<#
.SYNOPSIS
    EDO Monitor probe: DNS -> TCP -> TLS -> HTTP to one target, one JSON object on stdout.

.DESCRIPTION
    Run by Zabbix agent2 through UserParameter edo.probe[mode,host,port,path].
    With positional arguments (the Zabbix call) it always prints exactly one ASCII JSON object and exits with code 0; every failure,
    including bad arguments, becomes a class code. Nothing is ever written to stderr:
    agent2 glues stderr into the item value and would break every dependent item.

    Classes: 0 OK, 10 DNS_FAIL, 20 TCP_TIMEOUT, 22 TCP_REFUSED, 23 TCP_FAIL,
    30 TLS_TIMEOUT, 31 TLS_RESET, 32 TLS_FAIL, 33 CERT_UNTRUSTED, 40 HTTP_BAD,
    42 HTTP_TIMEOUT, 50 STALL, 90 GOST_NO_CSP, 91 PROBE_ERROR.

    Manual diagnostics: run without arguments, or with switches (-Group, -Target, -Gost,
    -Targets, -ViaProxy, -Repeat, -Out, -Help), to get a readable table for every target of
    the template instead of JSON. Exit code 0 no failures, 1 failures, 2 bad switches.

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

# ---------------------------------------------------------------- Manual diagnostics
# Run by hand: no arguments, or switches. agent2 always passes four positional arguments and discovery never
# yields a mode starting with "-", so the Zabbix path below stays untouched.

# Snapshot of the template's default {$EDO.TARGETS.*}, pinned to it by tests/Template.Tests.ps1. Overrides of
# these macros on a host or group in Zabbix are not visible here: pass the effective value with -Targets.
$script:EdoTargets = [ordered]@{
    Kontur    = 'Контур Auth|http|auth.kontur.ru|443|/_status/ping;Контур API|http|api.kontur.ru|443|/robots.txt;Контур Identity|http|identity.kontur.ru|443|/;Контур Update|http|update.kontur.ru|443|/_status/ping;УЦ Контур|http|pki.skbkontur.ru|80|/ping;УЦ Контур ЛК|http|ca.kontur.ru|443|/robots.txt;Диадок|http|diadoc.kontur.ru|443|/_status/ping;Диадок API|http|diadoc-api.kontur.ru|443|/_status/ping;Диадок EDI|http|edi.kontur.ru|443|/_status/ping;Диадок EDI API|http|edi-api.kontur.ru|443|/_status/ping;Экстерн|http|extern.kontur.ru|443|/;Экстерн CDN|http|cdn.kontur.host|443|/environments/Prod/bundles/connection-check/files/;Контур МЧД|http|m4d.kontur.ru|443|/'
    Stall     = 'Контур большой POST|stall|help.kontur.ru|443|/check/post'
    Gosuslugi = 'Госуслуги|http|www.gosuslugi.ru|443|/;ЕСИА|http|esia.gosuslugi.ru|443|/'
    FNS       = 'ФНС|http|www.nalog.gov.ru|443|/;ЛК ЮЛ|http|lkul.nalog.ru|443|/;ЛК ИП|http|lkip2.nalog.ru|443|/'
    FNSGost   = 'ЛК ЮЛ ГОСТ|gost|lkulgost.nalog.ru|443|/;ЛК ИП ГОСТ|gost|lkipgost.nalog.ru|443|/'
    Taxcom    = 'Такском|http|online.taxcom.ru|443|/;Такском ЛК|http|lk-new.taxcom.ru|443|/'
    CRPT      = 'Честный знак ЛК|http|markirovka.crpt.ru|443|/;Честный знак ИС МП|http|ismp.crpt.ru|443|/;Честный знак СУЗ|http|suzgrid.crpt.ru|443|/;Честный знак сайт|http|crpt.ru|443|/'
}
$script:EdoGroupTitles = @{
    Kontur = 'Контур'; Stall = 'Контур: большая отправка'; Gosuslugi = 'Госуслуги'; FNS = 'ФНС'
    FNSGost = 'ФНС: кабинеты с ГОСТ TLS'; Taxcom = 'Такском'; CRPT = 'Честный знак'
}
# Template macro defaults: {$EDO.SLOW.MS}, {$EDO.SLOW.MS:"help.kontur.ru"} (the stall target), {$EDO.CERT.DAYS},
# {$EDO.MASS.PCT}, {$EDO.MASS.MIN}.
$script:EdoThresholds = @{ SlowMs = 3000; SlowStallMs = 8000; CertDays = 14; MassPct = 50; MassMin = 3 }

# Per class: what broke, in a few words, and what to do about it.
$script:EdoAdvice = @{
    10 = @('DNS: имя не разрешается', 'Хост не получил IPv4-адрес имени. Проверить DNS-серверы в настройках сети (Resolve-DnsName <имя>), доступ к DNS через брандмауэр, фильтрацию DNS у провайдера.')
    20 = @('TCP: нет ответа', 'Пакеты до адреса не доходят или ответ не возвращается. Проверить исходящее правило брандмауэра Windows и периметра для этого IP и порта, маршрут; блокировку у провайдера (ТСПУ) — сравнить с другим хостом или провайдером.')
    22 = @('TCP: соединение отклонено', 'На подключение пришёл отказ (RST): порт закрыт на сервере или соединение сбрасывает межсетевой экран по пути. Если так со всех хостов — сервис недоступен; если только с этого — смотреть правила и прокси.')
    23 = @('TCP: ошибка сети', 'Подключение не началось. AccessDenied — запрет брандмауэра Windows на этом компьютере: нужно разрешающее исходящее правило для указанных IP и порта (или сам адрес сменился и старое правило его не покрывает). Иначе — нет маршрута или сеть недоступна (текст ошибки в строке).')
    30 = @('TLS: сервер молчит', 'TCP-соединение есть, а TLS-рукопожатие не завершилось за отведённое время: признак DPI/ТСПУ или прокси, удерживающего соединение. Сравнить с другим провайдером. Для ГОСТ-целей — csptest не ответил вовремя.')
    31 = @('TLS: соединение сброшено', 'Соединение оборвали во время TLS-рукопожатия — типичная фильтрация по имени сервера (SNI): ТСПУ, DLP, межсетевой экран с инспекцией TLS.')
    32 = @('TLS: рукопожатие не прошло', 'Сервер или посредник отверг TLS. Для ГОСТ-целей — сервер не принял ГОСТ-ClientHello или сбой КриптоПро CSP (код ошибки в строке); для остальных — несовместимые протоколы или шифры на пути.')
    33 = @('TLS: сертификат не доверенный', 'Сертификат сервера не прошёл проверку Windows. Издатель не сервис, а антивирус, прокси или DLP — включена подмена TLS, нужно исключение для адреса. Издатель Russian Trusted CA — установить корневые сертификаты НУЦ Минцифры.')
    40 = @('HTTP: ошибка сервера', 'Ответ с кодом 5xx или не по протоколу HTTP. Если так со всех хостов — сбой самого сервиса, проверить его статус; если только с этого — посредник на пути (прокси, фильтр).')
    42 = @('HTTP: нет ответа', 'Запрос отправлен, ответ не пришёл вовремя: перегрузка сервиса или фильтр, задерживающий ответы.')
    50 = @('большая отправка оборвалась', 'Отправка 256 КБ оборвалась или застряла: признак ТСПУ/DPI, режущего объёмные TLS-сессии, или проблем с MTU. У пользователей будет зависать отправка документов и отчётности.')
    90 = @('нет КриптоПро CSP', 'csptest.exe не найден, ГОСТ-проверка невозможна. Установить КриптоПро CSP, если с хоста работают в ГОСТ-кабинетах ФНС; иначе группу FNSGost здесь не проверять.')
    91 = @('проверка не выполнена', 'Проба не смогла выполнить проверку: неверная запись цели или ошибка PowerShell (текст в строке). Исправить запись; при повторении сообщить автору с текстом ошибки.')
}

$script:EdoWarnings = @{
    SLOW = @('медленный ответ', ('Сервис работает, но ответ дольше {0} с (большая отправка — {1} с): перегрузка канала, прокси или сервиса. Разовое замедление не страшно; если повторяется — прогнать с -Repeat 5 и сравнить с другим хостом.' -f ($script:EdoThresholds.SlowMs / 1000), ($script:EdoThresholds.SlowStallMs / 1000)))
    CERT = @('сертификат сервера скоро истекает', 'Сервис обычно меняет сертификат сам. Если сертификат успеет истечь — браузер и программы ЭДО перестанут подключаться: это проблема на стороне сервиса, не хоста.')
}

$script:EdoUsage = @'
EDO Monitor — ручная диагностика доступа к ЭДО и госсервисам с этого компьютера.
  edo.ps1                                      все цели шаблона Zabbix
  edo.ps1 -Group FNS,FNSGost                   группы: Kontur, Stall, Gosuslugi, FNS, FNSGost, Taxcom, CRPT
  edo.ps1 -Target lkul.nalog.ru[:443][/путь]   одна цель по HTTPS (порт 80 — HTTP)
  edo.ps1 -Gost lkulgost.nalog.ru[:443]        одна ГОСТ-цель (нужен КриптоПро CSP)
  edo.ps1 -Targets 'Имя|http|хост|443|/;...'   список в формате макроса {$EDO.TARGETS.*}
  -ViaProxy    http-цели ещё раз через прокси Windows (или WinHTTP)
  -Repeat N    N проходов подряд (1..100): ловит нестабильность
  -Out путь    сохранить отчёт в путь.txt и путь.json
Код выхода: 0 — отказов нет, 1 — есть FAIL или ERR, 2 — неверные параметры.
'@

# A target checked by the probe's own argument rules; Error says which entry ($Context) is invalid.
function New-EdoTarget {
    param([string]$Group, [string]$Name, [string]$Mode, [string]$TargetHost, [string]$Port, [string]$Path, [string]$Context)
    $t = [pscustomobject]@{ Group = $Group; Name = $Name; Mode = $Mode; Host = $TargetHost; Port = $Port; Path = $Path; Error = $null }
    $bad = Test-EdoArgs -Mode $Mode -TargetHost $TargetHost -Port $Port -Path $Path
    if ($bad) { $t.Error = "${Context}: $bad" }
    $t
}

# "Name|mode|host|port|path;..." -> targets.
function ConvertFrom-EdoTargetList {
    param([string]$Text, [string]$Group = '')
    foreach ($entry in @($Text -split ';')) {
        $entry = $entry.Trim()
        if (-not $entry) { continue }
        $f = @($entry -split '\|' | ForEach-Object { $_.Trim() })
        if ($f.Count -ne 5) {
            $t = New-EdoTarget $Group $f[0] '' '' '' '' ''
            $t.Error = "запись «$entry»: нужно Имя|mode|host|port|path"
            $t
            continue
        }
        New-EdoTarget $Group $f[0] $f[1] $f[2] $f[3] $f[4] "запись «$entry»"
    }
}

function Get-EdoDefaultTargets {
    param([string[]]$Groups = @())
    foreach ($g in @($script:EdoTargets.Keys)) {
        if ($Groups.Count -gt 0 -and $Groups -notcontains $g) { continue }
        ConvertFrom-EdoTargetList $script:EdoTargets[$g] $g
    }
}

# -Target host[:port][/path] (http) or -Gost host[:port].
function ConvertFrom-EdoTargetSpec {
    param([string]$Spec, [string]$Mode)
    $pattern = '^([^:/]+)(?::([0-9]{1,5}))?(/.*)?\z'
    if ($Mode -eq 'gost') { $pattern = '^([^:/]+)(?::([0-9]{1,5}))?\z' }
    if ($Spec -notmatch $pattern) {
        $t = New-EdoTarget '' $Spec $Mode '' '' '' ''
        $t.Error = "цель «$Spec»: нужно хост[:порт]$(if ($Mode -eq 'http') { '[/путь]' })"
        return $t
    }
    $port = '443'; if ($Matches[2]) { $port = $Matches[2] }
    $path = '/'; if ($Matches[3]) { $path = $Matches[3] }
    New-EdoTarget '' $Matches[1] $Mode $Matches[1] $port $path "цель «$Spec»"
}

function Get-EdoSelectedTargets {
    param($Options)
    $list = @()
    if ($Options.Target) { $list += ConvertFrom-EdoTargetSpec $Options.Target 'http' }
    if ($Options.Gost) { $list += ConvertFrom-EdoTargetSpec $Options.Gost 'gost' }
    if ($Options.Targets) { $list += @(ConvertFrom-EdoTargetList $Options.Targets) }
    if ($list.Count -gt 0) { return $list }
    Get-EdoDefaultTargets $Options.Group
}

# Hand-parsed: a param block would turn the Zabbix call's positional arguments into binding errors. From a console,
# "-Group a,b" arrives as an array, "-Repeat 3" as an integer and "-Out:x" as "-Out:" plus "x"; through -File all
# are strings and "-Out:x" stays one token.
function ConvertFrom-EdoSwitches {
    param([object[]]$ArgList = @())
    $o = @{ Error = $null; Help = $false; Group = @(); Target = ''; Gost = ''; Targets = ''; ViaProxy = $false; Repeat = 1; Out = '' }
    $names = @('Group', 'Target', 'Gost', 'Targets', 'Repeat', 'Out', 'ViaProxy', 'Help')
    $i = 0
    while ($i -lt $ArgList.Count) {
        $token = "$($ArgList[$i])"; $i++
        if ($token -notmatch '^-([A-Za-z?]+)(:(.*))?\z') { $o.Error = "лишнее значение «$token»"; return $o }
        $name = @($names | Where-Object { $_ -eq $Matches[1] })
        $inline = $Matches[3]
        if ($Matches[1] -eq '?' -or $Matches[1] -eq 'h') { $name = @('Help') }
        if ($name.Count -eq 0) { $o.Error = "неизвестный параметр «$token»"; return $o }
        $name = $name[0]
        if ($name -eq 'ViaProxy' -or $name -eq 'Help') {
            if ($inline) { $o.Error = "у -$name не бывает значения"; return $o }
            $o[$name] = $true
            continue
        }
        if ($inline) { $value = $inline }
        else {
            if ($i -ge $ArgList.Count -or "$($ArgList[$i])".StartsWith('-')) { $o.Error = "у -$name нет значения"; return $o }
            $value = @($ArgList[$i] | ForEach-Object { "$_" }) -join ','
            $i++
        }
        switch ($name) {
            'Group' {
                foreach ($g in @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                    $known = @($script:EdoTargets.Keys | Where-Object { $_ -eq $g })
                    if ($known.Count -eq 0) { $o.Error = "неизвестная группа «$g»; есть: $(@($script:EdoTargets.Keys) -join ', ')"; return $o }
                    $o.Group += $known[0]
                }
            }
            'Repeat' {
                if ($value -notmatch '^[0-9]{1,3}\z' -or [int]$value -lt 1 -or [int]$value -gt 100) { $o.Error = "-Repeat: нужно число от 1 до 100, а не «$value»"; return $o }
                $o.Repeat = [int]$value
            }
            default { $o[$name] = $value }
        }
    }
    if ($o.Group.Count -gt 0 -and ($o.Target -or $o.Gost -or $o.Targets)) { $o.Error = '-Group выбирает из целей шаблона и не сочетается с -Target, -Gost, -Targets'; return $o }
    # An empty explicit list must not silently turn into "all template targets".
    if (($o.Target -or $o.Gost -or $o.Targets) -and @(Get-EdoSelectedTargets $o | Where-Object { -not $_.Group }).Count -eq 0) { $o.Error = 'в -Target, -Gost, -Targets нет ни одной цели'; return $o }
    $bad = @(Get-EdoSelectedTargets $o | Where-Object { $_.Error } | ForEach-Object { $_.Error })
    if ($bad.Count -gt 0) { $o.Error = $bad -join '; ' }
    $o
}

# Same precedence as the template: failures first, then "cannot check", then the warnings.
function Get-EdoLabel {
    param($Result, $Target)
    $c = [int]$Result.class
    if ($c -ge 10 -and $c -lt 90) { return 'FAIL' }
    if ($c -eq 91) { return 'ERR' }
    if ($c -eq 90) { return 'N/A' }
    if ($Result.cert_days -ge 0 -and $Result.cert_days -lt $script:EdoThresholds.CertDays) { return 'CERT' }
    $slow = $script:EdoThresholds.SlowMs
    if ($Target.Mode -eq 'stall') { $slow = $script:EdoThresholds.SlowStallMs }
    if ($Result.total_ms -gt $slow) { return 'SLOW' }
    'OK'
}

# The template's "mass failure from the host": failing (10..89) >= MIN and >= PCT % of the targets that could be checked.
function Test-EdoMassFailure {
    param([object[]]$Results)
    $failing = @($Results | Where-Object { $_.class -ge 10 -and $_.class -lt 90 }).Count
    $broken = @($Results | Where-Object { $_.class -ge 90 }).Count
    $failing -ge $script:EdoThresholds.MassMin -and 100 * $failing -ge $script:EdoThresholds.MassPct * ($Results.Count - $broken)
}

# Which service a result belongs to: its template group, or for own targets the domain (last two labels).
function Get-EdoService {
    param($Record)
    if ($Record.group) { return $script:EdoGroupTitles[$Record.group] }
    if ($Record.host -match '^[0-9.]+\z') { return $Record.host }
    (@($Record.host -split '\.') | Select-Object -Last 2) -join '.'
}

# Binary WinHttpSettings value (what "netsh winhttp show proxy" prints, without its localized text):
# DWORD version, DWORD counter, DWORD flags (2 = proxy set), DWORD length, proxy string, then the bypass list.
function ConvertFrom-EdoWinHttpSettings {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 16) { return '' }
    $flags = [BitConverter]::ToInt32($Bytes, 8)
    $length = [BitConverter]::ToInt32($Bytes, 12)
    if (($flags -band 2) -eq 0 -or $length -le 0 -or 16 + $length -gt $Bytes.Length) { return '' }
    [Text.Encoding]::ASCII.GetString($Bytes, 16, $length)
}

# "host:port", "http://host:port" or per scheme "http=a:1;https=b:2" (HTTPS preferred: every EDO target is HTTPS).
function ConvertTo-EdoProxyUri {
    param([string]$Text)
    $pick = $Text.Trim()
    if ($pick.Contains('=')) {
        $parts = @{}
        foreach ($p in @($pick -split ';')) { if ($p -match '^\s*([A-Za-z]+)=(\S+)\s*\z') { $parts[$Matches[1].ToLower()] = $Matches[2] } }
        $pick = ''
        foreach ($k in 'https', 'http') { if ($parts.ContainsKey($k)) { $pick = $parts[$k]; break } }
    }
    $pick = $pick -split '[;\s]' | Where-Object { $_ } | Select-Object -First 1
    if (-not $pick) { return $null }
    if ($pick -notmatch '^[A-Za-z]+://') { $pick = "http://$pick" }
    New-Object Uri($pick)
}

function Get-EdoProxyInfo {
    $info = @{ WinHttp = ''; UserProxy = ''; UserPac = ''; UserAutoDetect = $false }
    # "Automatically detect settings" (WPAD): flag 0x08 in byte 8 of DefaultConnectionSettings. Often on by default,
    # so it is shown but does not count as "a proxy is configured".
    try {
        $c = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name DefaultConnectionSettings -ErrorAction Stop
        $b = [byte[]]$c.DefaultConnectionSettings
        if ($b.Length -gt 8) { $info.UserAutoDetect = (($b[8] -band 8) -ne 0) }
    } catch { }
    try {
        $w = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name WinHttpSettings -ErrorAction Stop
        $info.WinHttp = ConvertFrom-EdoWinHttpSettings $w.WinHttpSettings
    } catch { }
    try {
        $u = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $has = @($u.PSObject.Properties | ForEach-Object { $_.Name })
        if ($has -contains 'ProxyEnable' -and $u.ProxyEnable -eq 1 -and $has -contains 'ProxyServer') { $info.UserProxy = [string]$u.ProxyServer }
        if ($has -contains 'AutoConfigURL') { $info.UserPac = [string]$u.AutoConfigURL }
    } catch { }
    $info
}

# One GET through the proxy the user's Windows settings pick for this address (static, PAC or WPAD, as .NET resolves
# them), else through WinHTTP. Returns one line of text.
function Invoke-EdoProxyFetch {
    param($Target, [string]$WinHttp, $SystemProxy = [Net.WebRequest]::GetSystemWebProxy())
    $scheme = 'http'; if (Get-EdoUseTls -Port $Target.Port) { $scheme = 'https' }
    $uri = New-Object Uri("${scheme}://$($Target.Host):$($Target.Port)$($Target.Path)")
    $proxyUri = $null; $source = ''
    # PAC or WPAD resolution can fail too: that is one target's answer, not the end of the run.
    try {
        if (-not $SystemProxy.IsBypassed($uri)) { $proxyUri = $SystemProxy.GetProxy($uri); $source = 'прокси Windows' }
        elseif ($WinHttp) { $proxyUri = ConvertTo-EdoProxyUri $WinHttp; $source = 'прокси WinHTTP' }
    } catch { return "через прокси: прокси не определён: $(Format-EdoError $_.Exception)" }
    if ($null -eq $proxyUri) { return 'через прокси: для этого адреса прокси не применяется' }
    # Windows PowerShell 5.1 leaves TLS 1.2 out of HttpWebRequest unless .NET strong crypto is enabled in the registry;
    # the direct probe (SslStream) is not affected. SystemDefault (0) already lets the OS choose.
    $protocols = [Net.ServicePointManager]::SecurityProtocol
    if ([int]$protocols -ne 0 -and -not ($protocols -band [Net.SecurityProtocolType]::Tls12)) { [Net.ServicePointManager]::SecurityProtocol = $protocols -bor [Net.SecurityProtocolType]::Tls12 }
    $via = "через $source $($proxyUri.Authority)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $response = $null
    try {
        $request = [Net.WebRequest]::Create($uri)
        $proxy = New-Object Net.WebProxy($proxyUri)
        $proxy.UseDefaultCredentials = $true
        $request.Proxy = $proxy
        $request.KeepAlive = $false
        $request.AllowAutoRedirect = $false
        $request.Timeout = $script:EdoBudget.Http
        $request.ReadWriteTimeout = $script:EdoBudget.Http
        $request.UserAgent = 'edo-monitor'
        try { $response = $request.GetResponse() }
        catch {
            $x = $_.Exception
            while ($null -ne $x -and -not ($x -is [Net.WebException])) { $x = $x.InnerException }
            if ($null -eq $x -or $null -eq $x.Response) { throw }
            $response = $x.Response
        }
        $code = [int]$response.StatusCode
        $text = "HTTP $code"
        if ($code -eq 407) { $text = 'HTTP 407: прокси требует аутентификацию, которую Windows не передала' }
        elseif ($code -ge 500) { $text = "HTTP ${code}: ошибка на прокси или сервисе" }
        "${via}: $text, $($sw.ElapsedMilliseconds) мс"
    } catch {
        "${via}: $(Format-EdoError $_.Exception), $($sw.ElapsedMilliseconds) мс"
    } finally {
        if ($null -ne $response) { $response.Close() }
    }
}

# Outbound Block by default is the usual reason for class 20 on hardened terminal servers.
function Get-EdoFirewallNote {
    try {
        $blocked = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' -and "$($_.DefaultOutboundAction)" -eq 'Block' } | ForEach-Object { $_.Name })
    } catch { return 'Брандмауэр Windows: настройки не прочитаны' }
    if ($blocked.Count) { return "Брандмауэр Windows: исходящие по умолчанию ЗАПРЕЩЕНЫ (профили $($blocked -join ', ')) — до каждой цели нужно разрешающее правило" }
    'Брандмауэр Windows: исходящие по умолчанию разрешены'
}

function Format-EdoLine {
    param([string]$Label, $Target, $Result)
    $name = $Target.Name; if ($name.Length -gt 22) { $name = $name.Substring(0, 21) + '…' }
    $line = '  {0,-4} {1,-22} {2,-32} {3,-15} {4,6} мс' -f $Label, $name, "$($Target.Host):$($Target.Port)", $Result.ip, $Result.total_ms
    $c = [int]$Result.class
    if ($c -eq 0) {
        if ($Target.Mode -eq 'gost') { $line += '  сервер принял ГОСТ TLS (csptest)' }
        if ($Result.http_code -ge 0) { $line += "  HTTP $($Result.http_code)" }
        if ($Result.tls_proto) { $line += "  $($Result.tls_proto)" }
        if ($Result.cert_days -ge 0) { $line += "  серт. $($Result.cert_days) дн." }
        if ($Label -eq 'CERT') { $line += " ($($Result.cert_issuer))" }
        if ($Label -eq 'SLOW') { $line += '  медленно' }
        return $line
    }
    $short = $script:EdoAdvice[$c][0]
    if ($c -eq 23 -and $Result.error -match 'AccessDenied') { $short = 'TCP: запрещено брандмауэром Windows' }
    $line += "  $short [$c $($Result.class_name)]"
    if ($Result.error) { $line += ": $($Result.error)" }
    if ($c -eq 33 -and $Result.cert_issuer) { $line += "; издатель: $($Result.cert_issuer)" }
    $line
}

# Returns the exit code. -Probe, -ProxyInfo and -Sink exist for tests; by hand only -ArgList is passed.
function Invoke-EdoInteractive {
    param(
        [object[]]$ArgList = @(),
        [scriptblock]$Probe = { param($t) Invoke-EdoProbe -Mode $t.Mode -TargetHost $t.Host -Port $t.Port -Path $t.Path },
        $ProxyInfo = $null,
        [scriptblock]$Sink = { param($text, $color) if ($color) { Write-Host $text -ForegroundColor $color } else { Write-Host $text } }
    )
    $report = New-Object Collections.Generic.List[string]
    function Out-Line([string]$Text = '', [string]$Color = '') { $report.Add($Text); & $Sink $Text $Color }
    # Labels in summary order.
    $colors = [ordered]@{ OK = 'Green'; SLOW = 'Yellow'; CERT = 'Yellow'; FAIL = 'Red'; ERR = 'Red'; 'N/A' = 'DarkGray' }
    $failed = { $_.label -eq 'FAIL' -or $_.label -eq 'ERR' }

    $o = ConvertFrom-EdoSwitches $ArgList
    if ($o.Error) { Out-Line "Ошибка: $($o.Error)" 'Red'; Out-Line $script:EdoUsage; return 2 }
    if ($o.Help) { Out-Line $script:EdoUsage; return 0 }
    $targets = @(Get-EdoSelectedTargets $o)
    if ($null -eq $ProxyInfo) { $ProxyInfo = Get-EdoProxyInfo }
    $anyProxy = [bool]($ProxyInfo.WinHttp -or $ProxyInfo.UserProxy -or $ProxyInfo.UserPac)

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = 'без прав администратора'
    if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $admin = 'администратор' }
    # Session 0 is services and remoting (WinRM, a scheduled task without a user); a user's RDP session has its own id.
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $session = "$sessionId"
    if ($env:SESSIONNAME) { $session = "$env:SESSIONNAME (id $sessionId)" }
    if ($sessionId -eq 0) { $session = '0 (служба или удалённый запуск: прокси и сертификаты пользователя не видны)' }
    Out-Line ("EDO Monitor: диагностика с {0} | {1} ({2}) | сессия {3} | {4:yyyy-MM-dd HH:mm}" -f $env:COMPUTERNAME, $id.Name, $admin, $session, (Get-Date)) 'Cyan'
    $csp = Find-EdoCsptest
    if (Test-Path -LiteralPath $csp) { Out-Line "КриптоПро CSP: $((Get-Item -LiteralPath $csp).VersionInfo.ProductVersion)" }
    else { Out-Line 'КриптоПро CSP: не найден — ГОСТ-цели будут N/A' }
    $userProxy = 'нет'
    if ($ProxyInfo.UserProxy) { $userProxy = $ProxyInfo.UserProxy }
    if ($ProxyInfo.UserPac) { $userProxy += "; автонастройка $($ProxyInfo.UserPac)" }
    if ($ProxyInfo.ContainsKey('UserAutoDetect') -and $ProxyInfo.UserAutoDetect) { $userProxy += '; автоопределение (WPAD) включено' }
    $winHttp = 'нет'; if ($ProxyInfo.WinHttp) { $winHttp = $ProxyInfo.WinHttp }
    Out-Line "Прокси пользователя: $userProxy | Прокси WinHTTP: $winHttp"
    Out-Line (Get-EdoFirewallNote)
    if ($anyProxy -and -not $o.ViaProxy) { Out-Line 'Проверки идут напрямую, мимо прокси. Путь через прокси покажет -ViaProxy.' 'Yellow' }
    if ($o.ViaProxy -and -not $anyProxy) { Out-Line 'Явно прокси не настроен: -ViaProxy спросит Windows (автоопределение WPAD, прокси для всего компьютера); где прокси нет, строка скажет «не применяется».' 'Yellow' }
    # One object for the run: with PAC or WPAD a new one would fetch the script again for every target. Created whenever
    # -ViaProxy is given: WPAD and per-machine proxies are not visible in the settings read above.
    $systemProxy = $null; if ($o.ViaProxy) { $systemProxy = [Net.WebRequest]::GetSystemWebProxy() }
    if (-not ($o.Target -or $o.Gost -or $o.Targets)) { Out-Line 'Цели: значения шаблона Zabbix по умолчанию; переопределения макросов на хосте или группе здесь не видны — передайте их через -Targets.' 'DarkGray' }

    $records = New-Object Collections.ArrayList
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $failure = ''
    $finished = $false
    try {
        for ($pass = 1; $pass -le $o.Repeat; $pass++) {
            if ($o.Repeat -gt 1) { Out-Line; Out-Line "Проход $pass из $($o.Repeat)" 'Cyan' }
            $group = $null
            foreach ($t in $targets) {
                # The 256 KB POST goes to someone else's server; the template sends it once an hour.
                if ($t.Mode -eq 'stall' -and $pass -gt 1) { continue }
                if ($t.Group -and $t.Group -ne $group) { $group = $t.Group; Out-Line; Out-Line $script:EdoGroupTitles[$group] }
                $r = & $Probe $t
                $label = Get-EdoLabel $r $t
                Out-Line (Format-EdoLine $label $t $r) $colors[$label]
                $viaProxy = ''
                if ($systemProxy -and $t.Mode -eq 'http') { $viaProxy = Invoke-EdoProxyFetch $t $ProxyInfo.WinHttp $systemProxy; Out-Line "         $viaProxy" }
                $rec = [ordered]@{ pass = $pass; group = $t.Group; name = $t.Name; mode = $t.Mode; host = $t.Host; port = $t.Port; path = $t.Path; label = $label }
                foreach ($k in @($r.Keys)) { $rec[$k] = $r[$k] }
                $rec['via_proxy'] = $viaProxy
                [void]$records.Add($rec)
            }
            if ($o.Repeat -gt 1) {
                $bad = @($records | Where-Object { $_.pass -eq $pass } | Where-Object $failed)
                Out-Line "Проход ${pass}: отказов $($bad.Count)$(if ($bad.Count) { ' — ' + (@($bad | ForEach-Object { $_.host }) -join ', ') })"
            }
        }
        $finished = $true
    } catch {
        $failure = Format-EdoError $_.Exception
    } finally {
        # Also on Ctrl+C: whatever finished is summarised and saved.
        Out-Line
        if (-not $finished) {
            $why = '.'; if ($failure) { $why = " ошибкой: $failure." }
            Out-Line "Прогон прерван$why Итог — только по завершённым проверкам." 'Yellow'
        }
        $counts = @(foreach ($l in @($colors.Keys)) { $n = @($records | Where-Object { $_.label -eq $l }).Count; if ($n) { "$n $l" } })
        $summary = "Итог (проверок: $($records.Count), $([int]$elapsed.Elapsed.TotalSeconds) с)"
        if ($counts.Count) { $summary += ': ' + ($counts -join ', ') }
        $summaryColor = 'Green'
        if (@($records | Where-Object $failed).Count) { $summaryColor = 'Red' }
        elseif (@($records | Where-Object { $_.label -ne 'OK' }).Count) { $summaryColor = 'Yellow' }
        Out-Line $summary $summaryColor

        $mass = @($records | Group-Object { $_.pass } | Where-Object { Test-EdoMassFailure @($_.Group) })
        # Many failures of one service (a -Group CRPT run, say) are that service's outage, not the computer's.
        $failingServices = @($records | Where-Object { $_.class -ge 10 -and $_.class -lt 90 } | ForEach-Object { Get-EdoService $_ } | Select-Object -Unique)
        if ($mass.Count -and $failingServices.Count -lt 2) {
            Out-Line "Все отказы — у одного сервиса ($($failingServices -join '')): похоже на сбой или блокировку именно его. Сравните с другой группой целей или с другого компьютера." 'Red'
        } elseif ($mass.Count) {
            if ($anyProxy) { Out-Line 'Массовый отказ: большинство целей недоступно напрямую, а на компьютере настроен прокси. Вероятно, прямой выход в интернет закрыт и пользователи ходят через прокси — проверьте этот путь с -ViaProxy.' 'Red' }
            else { Out-Line 'Массовый отказ: недоступна большая часть целей сразу — проблема у этого компьютера или его сети (брандмауэр, DNS, прокси, провайдер), а не у сервисов.' 'Red' }
        }

        if ($o.Repeat -gt 1) {
            Out-Line 'По целям, удачно/отказ за все проходы:'
            foreach ($target in @($records | Group-Object { "$($_.name)|$($_.host)" })) {
                $of = @($target.Group)
                $okCount = @($of | Where-Object { $_.class -eq 0 }).Count
                $badCount = @($of | Where-Object $failed).Count
                $note = ''; $color = ''
                if ($okCount -and $badCount) { $note = '  нестабильно: то работает, то нет'; $color = 'Yellow' }
                elseif ($badCount) { $color = 'Red' }
                Out-Line ('  {0,-22} {1}/{2}{3}' -f $of[0].name, $okCount, $badCount, $note) $color
            }
        }

        $classes = @($records | Where-Object { $_.class -ne 0 } | ForEach-Object { [int]$_.class } | Sort-Object -Unique)
        $warned = @($records | Where-Object { $_.label -eq 'SLOW' -or $_.label -eq 'CERT' })
        if ($classes.Count -or $warned.Count) {
            Out-Line
            Out-Line 'Что делать:'
            foreach ($l in 'SLOW', 'CERT') {
                $of = @($warned | Where-Object { $_.label -eq $l } | ForEach-Object { $_.host } | Select-Object -Unique)
                if ($of.Count -eq 0) { continue }
                Out-Line "  [$l] $($script:EdoWarnings[$l][0]): $($of -join ', ')"
                Out-Line "      $($script:EdoWarnings[$l][1])"
            }
            foreach ($c in $classes) {
                # With the address: firewall rules are written for IP and port, not for names.
                $hosts = @($records | Where-Object { $_.class -eq $c } | ForEach-Object { if ($_.ip) { "$($_.host) ($($_.ip):$($_.port))" } else { $_.host } } | Select-Object -Unique) -join ', '
                Out-Line "  [$c $($script:EdoClassNames[$c])] $($script:EdoAdvice[$c][0]): $hosts"
                Out-Line "      $($script:EdoAdvice[$c][1])"
            }
        }

        if ($o.Out) {
            # Relative to the PowerShell location; [IO.File] alone would resolve against the process directory.
            $base = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(($o.Out -replace '\.(txt|json)\z', ''))
            try {
                $utf8 = New-Object Text.UTF8Encoding($true)
                Out-Line
                Out-Line "Отчёт: $base.txt, $base.json"
                [IO.File]::WriteAllLines("$base.txt", $report.ToArray(), $utf8)
                [IO.File]::WriteAllText("$base.json", (ConvertTo-Json -InputObject @($records) -Depth 5), $utf8)
            } catch { Out-Line "Не удалось сохранить отчёт: $(Format-EdoError $_.Exception)" 'Red' }
        }
    }
    if ($failure -or @($records | Where-Object $failed).Count) { return 1 }
    0
}

if ($MyInvocation.InvocationName -ne '.') {
    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    if ($args.Count -eq 0 -or "$($args[0])".StartsWith('-')) { exit (Invoke-EdoInteractive -ArgList $args) }
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
