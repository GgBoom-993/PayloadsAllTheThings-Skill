# Insecure Direct Object References

> Insecure Direct Object References (IDOR) is a security vulnerability that occurs when an application allows users to directly access or modify objects (such as files, database records, or URLs) based on user-supplied input, without sufficient access controls. This means that if a user changes a parameter value (like an ID) in a URL or API request, they might be able to access or manipulate data that they aren’t authorized to see or modify.

## Tools

* [PortSwigger/BApp Store > Authz](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e)
* [PortSwigger/BApp Store > AuthMatrix](https://portswigger.net/bappstore/30d8ee9f40c041b0bfec67441aad158e)
* [PortSwigger/BApp Store > Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)

## Methodology

IDOR stands for Insecure Direct Object Reference. It's a type of security vulnerability that arises when an application provides direct access to objects based on user-supplied input. As a result, attackers can bypass authorization and access resources in the system directly, potentially leading to unauthorized information disclosure, modification, or deletion.

**Example of IDOR**:

Imagine a web application that allows users to view their profile by clicking a link `https://example.com/profile?user_id=123`:

```php
<?php
    $user_id = $_GET['user_id'];
    $user_info = get_user_info($user_id);
    ...
```

Here, `user_id=123` is a direct reference to a specific user's profile. If the application doesn't properly check that the logged-in user has the right to view the profile associated with `user_id=123`, an attacker could simply change the `user_id` parameter to view other users' profiles:

```ps1
https://example.com/profile?user_id=124
```

### Numeric Value Parameter

Increment and decrement these values to access sensitive information.

* Decimal value: `287789`, `287790`, `287791`, ...
* Hexadecimal: `0x4642d`, `0x4642e`, `0x4642f`, ...
* Unix epoch timestamp: `1695574808`, `1695575098`, ...

**Examples**:

* [HackerOne - IDOR to view User Order Information - meals](https://hackerone.com/reports/287789)
* [HackerOne - Delete messages via IDOR - naaash](https://hackerone.com/reports/697412)

### Common Identifiers Parameter

Some identifiers can be guessed like names and emails, they might grant you access to customer data.

* Name: `john`, `doe`, `john.doe`, ...
* Email: `john.doe@mail.com`
* Base64 encoded value: `am9obi5kb2VAbWFpbC5jb20=`

**Examples**:

* [HackerOne - Insecure Direct Object Reference (IDOR) - Delete Campaigns - datph4m](https://hackerone.com/reports/1969141)

### Weak Pseudo Random Number Generator

* UUID/GUID v1 can be predicted if you know the time they were created: `95f6e264-bb00-11ec-8833-00155d01ef00`
* MongoDB Object Ids are generated in a predictable manner: `5ae9b90a2c144b9def01ec37`
    * a 4-byte value representing the seconds since the Unix epoch
    * a 3-byte machine identifier
    * a 2-byte process id
    * a 3-byte counter, starting with a random value

**Examples**:

* [HackerOne - IDOR allowing to read another user's token on the Social Media Ads service - a_d_a_m](https://hackerone.com/reports/1464168)
* [IDOR through MongoDB Object IDs Prediction](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)

### Hashed Parameter

Sometimes we see websites using hashed values to generate a random user id or token, like `sha1(username)`, `md5(email)`, ...

* MD5: `098f6bcd4621d373cade4e832627b4f6`
* SHA1: `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`
* SHA2: `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

**Examples**:

* [IDOR with Predictable HMAC Generation - DiceCTF 2022 - CryptoCat](https://youtu.be/Og5_5tEg6M0)

### Wildcard Parameter

Send a wildcard (`*`, `%`, `.`, `_`) instead of an ID, some backend might respond with the data of all the users.

* `GET /api/users/* HTTP/1.1`
* `GET /api/users/% HTTP/1.1`
* `GET /api/users/_ HTTP/1.1`
* `GET /api/users/. HTTP/1.1`

### IDOR Tips

* Change the HTTP request: `POST → PUT`
* Change the content type: `XML → JSON`
* Transform numerical values to arrays: `{"id":19} → {"id":[19]}`
* Use Parameter Pollution: `user_id=hacker_id&user_id=victim_id`
