# itforprof.com by Konstantin Tyutyunnik
# Loopback fake servers and a process runner for the EDO probe tests.
# Certificates live only in memory: nothing is written to any certificate store.

Set-StrictMode -Version 2.0

function New-FakeCertificate {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        'CN=localhost', $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $tmp = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(30))
    New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $tmp.Export('Pfx', 'x'), 'x', 'Exportable')
}

# Runs $Behavior once for the first accepted connection, in its own runspace.
# $Behavior receives: $client (TcpClient), $cert (X509Certificate2).
function Start-FakeServer {
    param(
        [Parameter(Mandatory)] [scriptblock] $Behavior,
        $Certificate
    )
    $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        param($listener, $behaviorText, $cert)
        try {
            $client = $listener.AcceptTcpClient()
            try { & ([scriptblock]::Create($behaviorText)) $client $cert } catch { }
            finally { $client.Close() }
        } finally { $listener.Stop() }
    }).AddArgument($listener).AddArgument($Behavior.ToString()).AddArgument($Certificate)
    $handle = $ps.BeginInvoke()
    [pscustomobject]@{ Port = $listener.LocalEndpoint.Port; PowerShell = $ps; Handle = $handle; Listener = $listener }
}

function Stop-FakeServer {
    param([Parameter(Mandatory)] $Server)
    try { $Server.Listener.Stop() } catch { }
    try { $Server.PowerShell.Stop() } catch { }
    $Server.PowerShell.Dispose()
}

# A port that nothing listens on: bind, remember, release.
function Get-ClosedPort {
    $l = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
    $port
}

# Runs the probe the way agent2 does and returns exit code, stdout, stderr, duration.
function Invoke-ProbeProcess {
    param(
        [Parameter(Mandatory)] [string] $ScriptPath,
        [string[]] $ArgumentList = @()
    )
    $quoted = @($ArgumentList | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" $quoted"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.CreateNoWindow = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    $sw.Stop()
    [pscustomobject]@{
        ExitCode = $p.ExitCode
        StdOut   = $out.Trim()
        StdErr   = $errTask.Result.Trim()
        Ms       = $sw.ElapsedMilliseconds
    }
}

Export-ModuleMember -Function New-FakeCertificate, Start-FakeServer, Stop-FakeServer, Get-ClosedPort, Invoke-ProbeProcess
