---
title: "CTF: Best Web Challenges 2022"
thumbnail: /images/default_thumbnail.png
date: 2022-12-17 23:00:00
tags:
    - CTF
    - AdC
description: 2022年で特におもしろかったweb問の紹介
---

この記事はCTF Advent Calendar 2022 17日目の記事です。

::: webcard https://adventar.org/calendars/7550
:::

16日目はLaikaさんの「[Wani HackaseのSlackにあるスラッシュコマンドの紹介](https://www.albina.cc/posts/Wani%20Hackase%E3%81%AESlack%E3%81%AB%E3%81%82%E3%82%8B%E3%82%B9%E3%83%A9%E3%83%83%E3%82%B7%E3%83%A5%E3%82%B3%E3%83%9E%E3%83%B3%E3%83%89%E3%81%AE%E7%B4%B9%E4%BB%8B)」です。CTFtimeからｼｭｯと情報を取ってきて選ぶ形式はおもしろくていいですね。

さて、本日は今年見たweb問で特に好きな問題を紹介します[^top-1]。

[^top-1]: 「おもしろかったxxx問の紹介」系の記事を誰かが書くと、他の人が同じジャンルで似た記事を書きにくくなるのでは？と若干危惧しています。いろいろな人のその人視点の「おもしろかった問題」を知りたいので、ツイートでもいいのでどんどん書いてほしいです！

## 【シンプル部門】 simplewaf - corCTF 2022

- 難易度目安: ★☆☆

今年出会った問題の中で一番好きなweb問です。非常にシンプルでありつつ、CTFらしい楽しさが詰まっている感動的な問題でした。

本質的なソースコードは以下のJavaScript（Node.js）のファイルだけです:
```javascript
const express = require("express");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 3456;

app.use((req, res, next) => {
    if([req.body, req.headers, req.query].some(
        (item) => {
            return item && JSON.stringify(item).includes("flag")
        }
    )) {
        return res.send("bad hacker!");
    }
    next();
});

app.get("/", (req, res) => {
    try {
        res.setHeader("Content-Type", "text/html");
        res.send(fs.readFileSync(req.query.file || "index.html").toString());
    }
    catch(err) {
        console.log(err);
        res.status(500).send("Internal server error");
    }
});

app.listen(PORT, () => console.log(`web/simplewaf listening on port ${PORT}`));
```

フラグファイルがサーバ上の`flag.txt`にあるので、これをLFIするのがゴールです。ただし、`req.body`、`req.headers`、`req.query`のいずれかに、（JSONとして）`flag`の文字列が含まれていた場合はそのリクエストがリジェクトされます。

一見フラグファイルを盗むのは不可能なんですが、Node.jsの`fs.readFileSync`の実装を掘っていくと、"いい感じ"のオブジェクトが`URL`オブジェクトとして認識されるということがわかり、それを利用するとバイパスが可能です。

`fs.readFileSync`の動作デモ:
```javascript
> const fs = require("fs")
undefined

// 通常の、ファイルパスを文字列として指定する例
> fs.readFileSync("flag.txt").toString()
'corctf{test_flag}'

// オブジェクトを指定してflag.txtを読む例
> fs.readFileSync({href: "x", origin: "x", protocol: "file:", hostname: "", pathname: "flag.txt"}).toString()
'corctf{test_flag}'

// オブジェクト経由だとファイルパス部分にパーセントエンコードが使える
> fs.readFileSync({href: "x", origin: "x", protocol: "file:", hostname: "", pathname: "%66lag.txt"}).toString()
'corctf{test_flag}'
```

「こんなことができたの！？という驚き」や「ソースコードの調査をしながらオブジェクトをパズル的に構成する楽しさ」がこのシンプルな問題の中に濃縮されていて、この問題を解くのは非常に良い体験でした。

詳しい解法は作問者writeupがあるのでそちらを参照してください:

- 作問者writeup: https://brycec.me/posts/corctf_2022_challenges#simplewaf
- 公式リポジトリ: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/web/simplewaf

## 【教育部門】 Cliche - ångstromCTF 2022

- 難易度目安: ★☆☆

こちらは高校生向けのCTFであるångstromCTF[^cliche-1]で出題された問題です。

[^cliche-1]: 高校生向けとはありますが特に制限はないので誰でも参加できます。問題の質が良く教育的な問題も多いので個人的におすすめの初心者向けCTFです。

問題ファイルはこちらにあります:

- https://github.com/blairsec/challenges/tree/master/angstromctf/2022/web/cliche

botがフラグのクッキーをもっているので、うまくXSSを発動させる問題です。本質的な箇所は以下の`<script>`部分です。

```html
<script>
    const qs = new URLSearchParams(location.search);
    if (qs.get("content")?.length > 0) {
        document.body.innerHTML = marked.parse(DOMPurify.sanitize(qs.get("content")));
    }
</script>
```

クエリパラメータ`content`に対して、`DOMPurify.sanitize`でサニタイズしたあとに`marked.parse`でMarkdownのパースを行い、そのパース結果を画面上に表示する処理になっています。

通常、`DOMPurify`のようなサニタイザは文字列を加工する過程の最後で行うことが鉄則ですが、この問題ではそうはなっていません。つまり、「XSSに対して安全な文字列だが、Markdownパーサを通すことによってXSSが発火するようになる文字列」の入力を特定する必要があります。

この手の問題は、主に3つ（あるいはその組み合わせ）のアプローチがあるかなと思います:

- ①コード解析
    - パーサのロジックを理解する
    - 利用できそうな処理や怪しい処理を見つける
    - Prototype Pollution系はだいたいこれ
- ②手作業で試行錯誤
    - 手作業で試行錯誤しながらパーサが壊れそうな入力をぶつける
    - 攻撃者の"勘"が物を言う
- ③fuzzerで殴る
    - fuzzerを実装してぶん回す
    - 出題例: Marked - Hayyim CTF 2022

markedは一般的に使われているライブラリなので、まずはMarkdownの表記周りで色々悪さできないか試すと良さそうです（つまり②）。

例えば、「`」で囲むとインラインコード扱いになるMakrdownの仕様を利用して以下のHTMLでXSSが可能です:
```html
`<p id="`<img src=x onerror=console.log(1)>">
```

これに`marked.parse`を通すと
```html
<p><code>&lt;p id=&quot;</code><img src=x onerror=console.log(1)>&quot;&gt;</p></p>
```
となり、`id`属性の文字列だったXSSペイロードが外側に放り出されて`<img>`タグとして露出します。

```javascript
marked.parse(DOMPurify.sanitize('<p id="x\n\n<img src=x onerror=console.log(1)>"></p>'))
'<p id="x\n\n<p><img src=x onerror=console.log(1)>&quot;&gt;</p></p>\n'
```

他にも以下のような解法がありました:
```javascript
marked.parse(DOMPurify.sanitize('`<p id="`<img src=x onerror=console.log(1)>">'))
marked.parse(DOMPurify.sanitize('[<p id="<img src=x onerror=console.log(1)>](x"></p>)'))
marked.parse(DOMPurify.sanitize('[x](y "<style>")<!--</style><div id="x--><img src=1 onerror=console.log(1)>"></div>'))

marked.parse(DOMPurify.sanitize('<p id="x\n\n<img src=x onerror=console.log(1)>"></p>'))

marked.parse(DOMPurify.sanitize('<div id="1\n\n![](contenteditable/autofocus/onfocus=console.log(1)//)">'))
```

パーサ周りは色々おもしろい話があり、そのおもしろさの一端を味わえる教育的な問題として気に入っています。解法も色々あり、アイデアソンみたいな楽しさもある良問でした。

## 【the攻撃部門】 spoink - UIUCTF 2022

- 難易度目安: ★★☆

この問題については以前に解法や感想をwriteupで書きました。攻撃のステップ数が多く複雑ですが、各要素はそれほど難しくはないのでよかったらぜひ読んでください:

- https://blog.arkark.dev/2022/08/01/uiuctf/

ひとつの小さい脆弱性からRCEという致命的な脆弱性までもっていくリアルワールド[^spoink-1]的な攻撃を楽しめる問題という点で気に入っています。

[^spoink-1]: 「リアルワールド」の解釈は状況によって異なりますが、少なくともここではスクリプトキディやOSINT的な要素は指してません。

## 【天才解法部門】 modernblog - corCTF 2022

- 難易度目安: ★★★

最後に紹介する問題はcorCTFで出題されたmodernblogで、React製[^modernblog-1]のクライアントサイド問です。めちゃくちゃ難しいのですが解法が天才的で気に入っています。ちなみに私はコンテスト中に解けませんでした。

[^modernblog-1]: 最近はReactやVue.jsのようなフロントエンドのフレームワークに絡んだ問題が少しずつ増えてきている印象です。時代の流れを感じます。

- 公式リポジトリ: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/web/modernblog
- 公式writeup: https://brycec.me/posts/corctf_2022_challenges#modernblog

解説をしようと思ったのですが、問題概要も含めて公式writeupがかなりわかりやすくて[^modernblog-2]蛇足にしかなりえなかったので、そちらを参照してください。

読んでいくとおそらく何度も頭の中が「？」になりますが、すべてを理解した瞬間にすべてが結びつき「最高」になれます。この感動を一人でも味わってほしいです。

[^modernblog-2]: 作問者のStrellicさんは作問のクオリティが高いだけでなくwriteupでの解説も丁寧なので、問題を解かずに読むだけでも楽しいと思います。理想的なので自分もこうなれるように精進したいです。

## その他の良問

紹介しきれなかったですが次の問題もおもしろい問題で印象的でした。問題名と関連リンクだけ貼っておきます:

- Live Art - picoCTF 2022
    - https://github.com/zwade/live-art
- denoblog - DiceCTF 2022
    - https://brycec.me/posts/dicectf_2022_writeups#denoblog
    - https://github.com/dicegang/dicectf-2022-challenges/tree/master/web/denoblog
- Yet Another Calculator App - PlaidCTF 2022
    - https://github.com/zwade/yaca
- Request Bin (Extra Hard) - WeCTF 2022
    - https://github.com/wectf/2022#request-bin-extra-hard
    - https://gist.github.com/arkark/51e6dee1c548616ed35ac64fbe006fc1

他にも楽しい問題や新しい発見をくれた問題などたくさんありました。
各CTFの運営・作問者のみなさまありがとうございました！来年もよろしくお願いします。

## 明日のアドベントカレンダー

明日のAdCはkash1064さんの記事です！内容は...まだ不明？
