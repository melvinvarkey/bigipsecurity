# BigIP Security Cheatsheet

This document describes common misconfigurations of F5 Networks BigIP systems.

## Summary
The BIG-IP family of products offers the application intelligence network managers need to ensure applications are fast, secure and available.
All BIG-IP products share a common underlying architecture, F5's Traffic Management Operating System (TMOS), which provides unified intelligence, flexibility and programmability.
Together, BIG-IP's powerful platforms, advanced modules, and centralized management system make up the most comprehensive set of application delivery tools in the industry.

BIG-IP devices work on a modular system, which enables to add new functions as necessary to quickly adapt to changing application and business needs.
The following modules are currently available for the BIG-IP systems:
* Application Acceleration Manager (AAM)
* Advanced Firewall Manager (AFM)
* Access Policy Manager (APM)
* Application Security Manger (ASM)
* Global Traffic Manager (GTM)
* Link Controller (LC)
* Local Traffic Manager (LTM)
* Protocol Security Module (PSM)

## Common Misconfigurations

### BIG-IP persistence cookie information leakage

#### Description

An attacker can receive sensitive information about internal network via BIG-IP LTM persistence cookie.  

To implement persistence sessions BIG-IP system inserts a cookie into the HTTP response,
which well-behaved clients include in subsequent HTTP requests for the host name until the cookie expires.
The cookie, by default, is named `BIGipServer<pool_name>`. The cookie is set to expire based on the time-out configured in the persistence profile.
The cookie value contains the encoded IP address and port of the destination server in one of the following [format](https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html):
* IPv4 pool members: `BIGipServer<pool name> = <The encoded server IP>.<The encoded server port>.0000`
* IPv6 pool members: `BIGipServer<pool name> = vi<The full hexadecimal IPv6 address>.<The port number calculated in the same way as for IPv4 pool members>`
* IPv4 pool members in non-default route domains: `BIGipServer<pool name> = rd<The route domain ID>o00000000000000000000ffff<The hexadecimal representation of the IP address of the pool member>o<The port number of the pool member>`
* IPv6 pool members in non-default route domains: `BIGipServer<pool name> = rd<The route domain ID>o<The full hexadecimal IPv6 address>o<The port number of the pool member>`

Examples:
* `BIGipServer~DMZ_V101~web_443=1677787402.36895.0000`
* `BIGipServer~CORP_DC1=vi20010112000000000000000000000030.20480`
* `BIGipServer~EE_ORACLE=rd5o00000000000000000000ffffc0000201o80`
* `BIGipServer~ES~test.example.com=rd3o20010112000000000000000000000030o80`

After decoding of the BIG-IP persistence cookie value an attacker can receive an internal IP address, port number, and routed domain for backend servers.
In some cases an attacker can also retreive sensitive informaion via `<pool_name>` suffix of the cookie name.
For example, if an administrator give meaningful name to server pool (e.g. Sharepoint, 10.1.1.0, AD_prod) an attacker will get some additional information about network.
Besides, an attacker detects that BIG-IP system is used in network infrustructure.

#### Testing

1. Run intercepting proxy or traffic intercepting browser plug-in, trap all responses where a cookie is set by the web application.
2. If possible, log in to web application and inspect cookies.
3. Find a cookie with a name beginning with BIGipServer string or with a value that has one of the formats above (e.g., `1677787402.36895.0000` for IPv4 pool members scheme).
4. Try to decode this value using available tools (see below).
5. Inspect suffix of BIGipServer cookie name and verify that it does not contain any sensitive information about network infrustructure.

The following example shows a GET request to BIG-IP with LTM module and a response containing BIGipServer cookie.
 ```
GET /app HTTP/1.1
Host: x.x.x.x
 ```
 ```
HTTP/1.1 200 OK
Set-Cookie: BIGipServerOldOWASSL=110536896.20480.0000; path=/
 ```
Here we can see that backend's pool has the meaningful name OldOWASSL and includes backend server 192.168.150.6:80

#### Tools
* [Metasploit Framework module] (http://www.rapid7.com/db/modules/auxiliary/gather/f5_bigip_cookie_disclosure)
* [Burp Suite extension] (http://professionallyevil.com/subdomains/extensions/Burp-F5Cookie-Extension.py.zip)
* [BeEF module] (https://github.com/beefproject/beef/tree/master/modules/network/ADC/f5_bigip_cookie_disclosure)

#### Remediation

##### Configuring secure cookie persistence using the Configuration utility

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > Persistence`.
3. Create a new secure persistence profile with persistence type equals to `Cookie`.
4. Check the custom box for `Cookie Name` and enter a cookie name that does not conflict with any existing cookie names.
5. Check the custom box for `Cookie Encryption Use Policy` and choose a `required` option. Enter a passphrase in `Encryption Passphrase` field.
6. Click `Finished`.
7. Assign created persistence profile to the virtual server.

##### Configuring secure cookie persistence using TMSH

 ```
create ltm persistense cookie <profile_name>
modify ltm persistense cookie <profile_name> cookie-name <secure_cookie_name>
modify ltm persistense cookie <profile_name> cookie-encryption required
modify ltm persistense cookie <profile_name> cookie-encryption-passphrase <secure_passphrase>
modify ltm virtual <virtual_server> persist replace-all-with { <profile_name> }
save /sys config
 ```

### BIG-IP HTTP Server header information leakage

#### Description

An attacker can receive information that a web application is protected by BIG-IP system via HTTP `Server` header.  
BIG-IP system uses different HTTP Profiles for managing HTTP traffic.
In particular, BIG-IP system uses HTTP Profile that specifies the string used as the `Server` name in traffic generated by LTM.
The default value is equal to `BigIP` or `BIG-IP` and depends on BIG-IP system version.
An attacker can detect that BIG-IP is used in network infrustructure and then know role, type, and version of the BIG-IP system.

#### Testing

1. Run intercepting proxy or traffic intercepting browser plug-in, trap all responses from a web application.
2. If possible, log in to web application and inspect HTTP responses.
3. If Server header contains `BIG-IP` or `BigIP` value then BIG-IP is used.

The following example shows a GET request to BIG-IP and a response containing Server header inserted by BIG-IP LTM.
 ```
 GET / HTTP/1.1
 Host: x.x.x.x
 ```
 ```
 HTTP/1.0 302 Found
 Server: BigIP
 Connection: Close
 Content-Length: 0
 Location: /my.policy
 Set-Cookie: LastMRH_Session=05da1fc5;path=/;secure
 Set-Cookie: MRHSession=03e47713f1a8ef1aaa71cd9d05da1fc5;path=/;secure
 Set-Cookie: MRHSHint=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/
 ```
#### Tools
* [Metasploit Framework module] (http://www.rapid7.com/db/modules/auxiliary/scanner/http/f5_bigip_virtual_server)

#### Remediation

It is recommended to remove `Server` header from HTTP responses.

##### Removing Server header using the Configuration Utility

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > Services > HTTP`.
3. Create new secure HTTP profile.
4. Enter empty string in `Server Agent Name` field.
5. Click `Finished`.
6. Assign created HTTP profile to the virtual server.

##### Removing Server header using TMSH
 ```
create ltm profile http <profile_name>
modify ltm profile http <profile_name> server-agent-name none
save /sys config
 ```

### Administrative access to BIG-IP system via Internet

#### Description
An attacker can access to BIG-IP management interface via Internet.
This is can lead to different attacks on BIG-IP administrative tools, unauthorized access or mass enumeration of BIG-IP systems via search engines. 
The BIG-IP system uses the following [two network connection entry points] (https://support.f5.com/kb/en-us/solutions/public/7000/300/sol7312.html):
* TMM switch interfaces
* Management interface (MGMT)

Either the TMM switch interfaces or the MGMT interface can provide administrative access to the BIG-IP system.
The TMM switch interfaces are the interfaces that the BIG-IP system uses to send and receive load-balanced traffic.
The MGMT interface is the interface to perform system management functions via browser-based or command line configuration tools.
The MGMT interface is intended for administrative traffic and cannot be used for load-balanced traffic.
It is recommended to connect MGMT interface to a secure, management-only network, such as one that uses an [RFC 1918] (https://tools.ietf.org/html/rfc1918) private IP address space.
Otherwise an attacker can identify BIG-IP systems in your network and then [attack them](https://www.blackhat.com/html/webcast/07182013-hacking-appliances-ironic-exploits-in-security-products.html) via management plane.

#### Testing

1. Try to use the following queries for [https://www.google.com/ Google] (googledorks):
  * inurl:"tmui/login.jsp"
  * intitle:"BIG-IP" inurl:"tmui"
2. Try to use the following queries for [https://www.shodanhq.com/ Shodan]
  * F5-Login-Page
  * WWW-Authenticate: Basic realm=BIG-IP
  * BigIP
  * BIG-IP
3. Run [Metasploit Framework module] (http://www.rapid7.com/db/modules/auxiliary/scanner/http/f5_mgmt_scanner)

#### Tools
* [Metasploit Framework module] (http://www.rapid7.com/db/modules/auxiliary/scanner/http/f5_mgmt_scanner)

#### Remediation

Connect MGMT interface to special management network only. Management network should operates under private ([RFC 1918] (https://tools.ietf.org/html/rfc1918)) IP-address space that is completely separate from the production network.
 The most secure configuration is to set "Allow None" on all Self IPs and only administer a BIG-IP using the Management Port.
Setting "Allow None" on each Self IP will block all access to BIG-IP's administrative IP addresses except for the Management Port. Access to individual ports can be selectively enabled, but this is not recommended in a highly secure environment.

To deny all connections on the self IP addresses using the Configuration utility
1. Log in to the Configuration utility.
2. Go to `Network > Self IPs`.
3. For all self IPs set `Port Lockdown` option to `Allow None`.
4. Click `Update`.

If you need to administer BIG-IP using Self IPs you should also use private [RFC 1918] (https://tools.ietf.org/html/rfc1918) IP-address space.
The most unsecure configuation is to use routable addresses on your Self-IPs. In this case it is highly recommended to lock down access to the networks that need it. To lock-down SSH and the GUI for a Self IP from a specific network.
For examle, to permit access from network 192.268.2.0/24 it is necessary to perform the following commands in TMSH:
 ```
modify /sys sshd allow replace-all-with { 192.168.2.* }
modify /sys httpd allow replace-all-with { 192.168.2.* }
save /sys config
 ```

### Protection against HTTP host header attacks

#### Description

Host header in HTTP requests is not always validated by BIG-IP systems by default.
This validation depends on enabled modules, features and their configuration: for example, BIG-IP system in APM portal access mode performs a base sanitization of HTTP host header against XSS attacks.
In most cases BIG-IP systems handle HTTP request with arbitrary `Host` header.
This weakness can lead to vulnerabilities which can be used in [different attacks based on HTTP Host header] (http://www.acunetix.com/blog/articles/automated-detection-of-host-header-attacks). For example, [DNS Rebinding] (http://www.ptsecurity.com/download/DNS-rebinding.pdf), [XSS](https://www.mehmetince.net/concrete5-reflected-xss-vulnerability-via-http-header-host-parameter), [password reset poisoning] (http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.htm), etc.  

#### Tesing

1. Run intercepting proxy, trap all responses from a web application.
2. If possible, log in to web application. 
3. Change `Host` header in HTTP requests. If responses for requests with normal and modified Host header are the same then BIG-IP does not validate `Host` header.
 
#### Remediation

BIG-IP systems can be protected against HTTP host header attacks using Centralized Policy Matching (CPM) feature of LTM module.
Let's consider an example of configuration BIG-IP system with LTM and APM modules that illustrates the main idea of this protection.
The following settings ensures that user will be redirected to `/vdesk/hangup.php3` script deleting a user's session if HTTP Host header contains a value different from permitted and correct hostnames.

##### Configuring host validation in CPM using the Configuration utility

1. Log in to the Configuration utility.
2. Navigate `Local Traffic > Policies`.
3. Click `Create`. Input `_host_header_validation` in the `Name` field. Add `http` to Requires box.
4. Click `Add` in Rules section.
5. Add the following Condition:
  * Operand: `http-host`
  * Event: `request`
  * Selector: `host`
  * Negotiate: `not`
  * Condition: `equals`
  * Values: `<dns_name_1>`, `<dns_name_2>`, `<dns_name_3>`, etc
6. Click `Add`.
7. Add the following Rule:
  * Target: `http-uri`
  * Event: `request`
  * Action: `replace`
  * Parameters
    * Name: `path`
    * Value: `/vdesk/hangup.php3`
8. Go to `Local Traffic > Virtual Servers`. Choose a virtual server that should be protected by CPM and click `Resources`.  9. Click `Manage` in `Policies` section and add `_http_host_validation` to `Enabled` box.
10. Click `Finished`.

##### Configuring host validation in CPM using TMSH
1. Prepare the following CPM config for host validation

 ```
ltm policy _http_host_validation {
    requires { http }
    rules {
        host_validation {
            actions {
                0 {
                    http-uri
                    replace
                    path /vdesk/hangup.php3
                }
            }
            conditions {
                0 {
                    http-host
                    host
                    not
                    values { <dns_name_1> <dns_name_2> <dns_name_3> }
                }
            }
            ordinal 1
        }
    }
    strategy first-match
}
 ```
 
2. Log in to TMSH.
3. Run the following command:

 ```
load sys config from terminal merge
 ```
 
4. Copy the config and press `CTL-D` to submit.
5. Run the following command:
 
 ```
modify ltm virtual <virtual_server> policies add { _http_host_validation }
 ```

### Protection against mass enumeration via search engines

#### Description
Web-based components of BIG-IP systems, such as APM, use different HTML pages with default values that can be used for mass enumeration.

#### Testing
Try to use the following search queries with BIG-IP keyword in [Google] (https://www.google.com/):
* intitle:"BIG-IP logout page"
* "Thank you for using BIG-IP."

#### Remediation
BIG-IP systems can be protected against web enumeration using Customization mechanism.

1. Log in to the Configuration utility.
2. Go to `Access Policy > Customization > General`.
3. Change all `BIG-IP` substrings to some neutral strings.
3. Go to `Access Policy > Customization > Advanced`.
4. Change strings with `BIG-IP` values.

For example, navigate to the `Customization Settings > Access profiles > /Common/<profile_name> > Logout > logout.inc`.
Change `<title>BIG-IP logout page</title>` to `<title>Logout page</title>`.

### Protection against APM session exhaustion DoS attack

#### Description

An unauthenticated attacker can establish multiple connections with BigIP Access Policy Manager and exhaust all available sessions defined in customer's license.
In the first step of BigIP APM protocol the client sends a HTTP request to virtual server with access profile (/).
The BigIP system creates a new session, marks it as progress (pending), decreases the number of the available sessions by one, and then redirects client to access policy URI (/my.policy).
Since BigIP allocates a new session after the first unauthenticated request and deletes the session only if an access policy timeout will be expired the attacker can exhaust all available sessions repeatedly sending initial HTTP request.
New versions of BigIP system has secure configuration by default and they are not vulnerable to this attack.

#### Testing

1. Log in to the Configuration utility.
2. Go to `Access Policy > Access Profiles > <profile_name>`.
3. Review `Max In Progress Sessions Per Client IP` setting.
4. If `Max In Progress Sessions Per Client IP` value is equal to 0 then the BigIP system is vulnerable to this attack.

#### Tools
* [Metasploit Framework module](http://www.rapid7.com/db/modules/auxiliary/dos/http/f5_bigip_apm_max_sessions)

#### Remediation

The default recommendation is to set value of `Max In Progress Sessions Per Client IP` in all access profiles to 128.

##### Protection settings using the Configuration utility

1. Log in to the Configuration utility.
2. Navigate `Access Policy > Access Profiles > <profile_name>`.
3. Set `Max In Progress Sessions Per Client IP` value to 128.
4. Click `Update` and then click `Apply Access Policy`.

##### Protection settings in the TMSH
 ```
modify apm profile access <profile_name> max-in-progress-sessions 128
modify /apm profile access <profile_name> generation-action increment
save /sys config
 ```
 
### Protection against Brute-force Passwords Attack
 
#### Description
By default, BigIP APM with any type of AAA is vulnerable to brute-force password attack.

#### Remediation
The `Minimum Authentication Failure Delay` and `Maximum Authentication Failure Delay` options or CAPTCHA can be enabled to slow down or mitigate brute-force passwords attacks against BIG-IP APM

To enable `Minimum Authentication Failure Delay` and `Maximum Authentication Failure Delay` options using the Configuration utility

1. Log in to the Configuration utility.
2. Go to `Access Policy > Access Profiles`. Click a profile name.
3. Enable `Minimum Authentication Failure Delay` and `Maximum Authentication Failure Delay` options and change their values if necessary.
4. Click `Update` and then click `Apply Access Policy`.

To enable CAPTCHA using the Configuration utility

1. Log in to the Configuration utility.
2. Go to `Access Policy > CAPTCHA Configurations` and create a new one.
3. Go to `Access Policy > Access Profiles`. Click `Edit` link for the profile name.
4. Click `Logon Page`. Set the created CAPTCHA configuration.
5. Click `Apply Access Policy`.

## Getting an "A" grade on Qualys's SSL Labs

It is necessary to configure the following settings in BigIP's client SSL profile
* Enable TLS_FALLBACK-SCSV extension
* Enable HSTS
* Prioritize PFS ciphers

### Enabling Strict Transport Security
There are several ways for implementing HSTS on BigIP: HTTP profile and iRules.

#### Enabling HSTS using SSL Profile

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > Services > HTTP`.
3. Choose existent or create a new HTTP profile.
4. Select `Mode` and `Include Subdomains` in the `HTTP Strict Transport Security` section.
5. Click `Update`.

#### Enabling HSTS using iRules

1. Log in to the Configuration utility.
2. Go to `Local Traffic > iRules`.
3. Create a new iRule:

 ```
### iRule for HSTS HTTPS Virtuals ###

when HTTP_RESPONSE {
  HTTP::header insert Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
 ```
4. Assign the iRule to the HTTPS virtual server.

### Configuring ciphersuites

There are many different cipher strings that prioritize PFS ciphers and can provide forward secrecy. On of them is the following:

```
ECDHE+AES-GCM:ECDHE+AES:DEFAULT:!DHE:!RC4:!MD5:!EXPORT:!LOW:!SSLv2
```

#### Configuring ciphers using SSL profile

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > SSL > Client`.
3. Choose the existent or create a new cleint SSL profile.
4. Choose `Advanced` configuration mode. Input your cipher string in the `Cipher` option.
5. Click `Update`.

## References
* [F5 Networks Official Site] (https://f5.com/products/big-ip)
* [BIG-IP Modules Datasheet](https://www.f5.com/pdf/products/big-ip-modules-ds.pdf)
* [David Holmes. 10 Settings to Lock Down your BIG-IP] (https://devcentral.f5.com/articles/10-settings-to-lock-down-your-big-ip)
* [SOL13092: Overview of securing access to the BIG-IP system](https://support.f5.com/kb/en-us/solutions/public/13000/000/sol13092.html)
* [SOL13309: Restricting access to the Configuration utility by source IP address](https://support.f5.com/kb/en-us/solutions/public/13000/300/sol13309.html)
* [F5 TLS & SSL Practices](http://www.slideshare.net/bamchenry/f5-tls-ssl-practices)
* [OWASP Secure Configuration Guide: BigIP] (https://www.owasp.org/index.php/SCG_D_BIGIP)
