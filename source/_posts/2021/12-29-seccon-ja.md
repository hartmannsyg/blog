---
title: SECCON CTF 2021 作問感想
thumbnail: /images/default_thumbnail.png
date: 2021-12-29 23:00:00
tags:
    - diary
description: SECCON CTF 2021の作問感想です。
---

**English writeup is >[here](https://blog.arkark.dev/2021/12/22/seccon/)<.**

他の人が参加記を書いてていいなと思ったので、自分も書きます。
**!!! 作問の感想や背景を書いているだけなのでちゃんとしたwriteupを読みたい人は[こちら](https://blog.arkark.dev/2021/12/22/seccon/)を参照ください。 !!!**

---

今年は作問メンバーの一員としてSECCONに関わることになりました。./Vespiaryからは私と[Xornet](https://twitter.com/Xornet_Euphoria)が作問に加わりました。

作問の打診を受けたときに、作問したことがない自分がSECCONという大舞台（？）で作問してもいいのかという不安があったのですが、初心者だからという理由で遠慮してたら一生作問やらないだろうなと思ったので、参加表明をしました。最初はみんな初心者ですし。とは言っても、参加表明したからには自信もった問題を準備する責任は当然あるわけで、がんばって作問しました。問題を見てくださった方々、解いてくださった方々ありがとうございます。観測したwriteup・感想は全部読んでます。

今回はwebカテゴリで4問つくりました。

- [web] x-note: 3 team solved / 428 pts
- [web] Cookie Spinner: 7 team solved / 322 pts
- [web] Sequence as a Service 1: 20 team solved / 205 pts
- [web] Sequence as a Service 2: 19 team solved / 210 pts

順番は問題をつくった順番です。

## x-note

アカウントが作成できてノートが投稿できるサービスが与えられます。botが投稿したノートの中身（フラグ）を盗む、よくある形式のXS-Search問題です。他の3問はパズルなのですが、この問題だけ純粋[^x-note-1]なweb問です。

[^x-note-1]: 純粋ってなんだろうね。

この手の問題は、フラグのprefixを判定するためのオラクルを構成するのが目標であることが多いです。x-noteは実装の脆弱な部分や不自然な部分を利用して複雑なオラクルを組み立てられるかを問いてました。writeupを見たらわかるように想定解は4ステップくらいあり、結構ヘビーな問題です。

想定解のメインの部分は次の2つです:

- ①EJSの描画時のエラー文を利用しようという発想ができるか、また、エラーが2種類あることに気付けるか
- ②無限リダイレクトできることに気付けるか、また、無限リダイレクトと有限リダイレクトの分岐を検知する機構をつくれるか

①について、エラー文を利用するという部分をミニマムにした問題がTSG CTF 2021のWelcome to TSG CTF!だと思います。実はTSG CTFのときに私はこの問題を解けていない（他のチームメンバーが解いてくれた）ので、結構非自明な発想なんだなと思ってました[^x-note-2]。

[^x-note-2]: x-noteをつくったのはTSG CTFの前なので、作問の参考にしたわけではないです。

②については、リダイレクト周りのXS-Leakの知見（例: https://portswigger.net/daily-swig/playing-fetch-new-xs-leak-exploits-browser-redirects-to-break-user-privacy ）があると有利かもしれません。

最終的に3 solvesで、1位は解けていて2,3位が解けていないという結果になり、いい感じにボス問になってくれたようで良かったです。ただ、`meta`タグを使った非想定解が見つかってしまいショックです。`meta`タグによって自明問題になるというわけでなく後半のステップをスキップできる程度なので、深刻なレベルで難易度崩壊になったわけではないですが多少簡単になってしまいました。普段CTFに参加する側のときは「`meta`タグ最高！いちばんすきな作問者泣かせタグです！」という感じで使ってたのですが急に敵に寝返ってきました。いざ作問しようとすると見落としてしまうものなんですね...次回[^x-note-3]から気をつけたいです。

[^x-note-3]: 次回...あるのか？

## Cookie Spinner

DOM Clobberingで循環参照を生むような問題にしたいなと思って作問しました。ただし、露骨に「DOM Clobberingしてください」という問題にするとおもしろくないので、自然な感じ[^cookie-1]の問題に落とし込むのに苦労しました。うまく問題として溶け込んでいたでしょうか？

[^cookie-1]: 自然ってなんだろうね。

DOM Clobberingに気づいたら、DOMの挙動を実験したり、MDNで各HTMLElementのプロパティを調べたりしてパズルを解くのが想定でした。DOM Clobberingの問題は他の攻撃と組み合わせるのが想定な問題が多いのですが、DOM Clobbering単独の問題としてはこれより複雑な問題はないと思っています。あったら是非教えてください。

```javascript
// index.html
// ... snip ...
    if (document.querySelector("meta") != null) {
      console.error("I hate <meta> tags :(");
    } else {
// ... snip ...
```

ところでここの場合分けは`meta`タグ対策です。kusanoさんがレビュー時に見つけてくださいました。感謝です。（...ここで対策したのにx-noteでやられてしまうとは...）

非想定として`parentNode`や`parentElement`を使った解法が出てきましたが、想定内のうちの非想定という認識です。

また、この問題だけURLがドメインではなく生IPだったことに気づいたでしょうか。
理由はこれです（CTF終了後の./Vespiary内の会話です）。
![](/images/2021/20211229-seccon-ja-01.png)

## Sequence as a Service 1 / Sequence as a Service 2

実はSECCONの1ヶ月くらい前の時点ではweb問はx-noteとCookie Spinnerの2問しかなかったです。流石にまずいなと思って急遽つくった問題がこのSaaS 1とSaaS 2です。[LJSON](https://github.com/MaiaVictor/LJSON)というおもしろい問題を見つけるのに1日間、SaaS 1をつくるのに3日間、SaaS 2をつくるのに一晩かかりました。急ピッチでつくったにしては割とおもしろい問題になったのではないかと我ながら思っています。

問題のメイン処理は、SaaS 1が
```javascript
console.log(LJSON.parseWithLib(lib, sequence)(n));
```
で、SaaS 2が
```javascript
console.log([
  LJSON.parseWithLib(lib, sequence0)({}, n0),
  LJSON.parseWithLib(lib, sequence1)({}, n1),
]);
```
です。シンプルにできて満足してます。

非想定解法はたくさん出てしまったのですが、どれもおもしろい解法で、問題の多様性という観点では結果的に良かったです。ただ、SaaS 1でもSaaS 2でも通用してしまう解法が発見されてしまったのは反省です。

出題の背景を話します。web問全体のバランスとしてPrototype Pollution問を1問くらいは出したかったです。Prototype Pollutionはオブジェクトの汚染後の値が 文字列 or 配列 or オブジェクト であることが多く、関数で汚染できたらおもしろいだろうなあと思ってました。パースが絡んでいて[^saas-1]且つ関数が扱えるライブラリがないかなと探していたらLJSONを見つけました。関数で汚染できてしまうと実質なんでもできてしまいますが、LJSONは使える関数にいい感じに制限があって最高でした。

[^saas-1]: パースという発想は[この記事](https://blog.p6.is/AST-Injection/)から来ています。

SaaS 1はPrototype Pollutionと見せかけておいて`__proto__`に直接関数を代入してprototypeそのものを書き換えてしまうという荒業が想定でした。JavaScriptって言語、なんておもしろいんだ。SaaS 2はPrototype PollutionでRCEできる汚染先を、LJSONの実装を読んで発見するのが想定でした。SaaS 2の方が順当なweb問という意味でやや簡単という認識です。

SaaS 1 / SaaS 2 の問題には

> Note: It is possible to solve SaaS 2 even if you don't solve SaaS 1.

という注意文句がありました。これは、SaaS 2がSaaS 1の上位互換というわけではないというメッセージでした。SaaS 2だけを解いているチームやSaaS 2から解けているチームがあったので、あってよかったと思っています[^saas-2]。

[^saas-2]: この文言はkusanoさんに指摘されて追加しました。ありがとうございます。
