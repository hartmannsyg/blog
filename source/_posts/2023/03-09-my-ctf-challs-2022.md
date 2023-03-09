---
title: CTF作問感想 - 2022
thumbnail: /images/default_thumbnail.png
date: 2023-03-09 23:00:00
tags:
    - diary
description: 2022年のCTF作問の感想
---

2022年につくった各問題の作問感想や背景の話です[^top-1]。writeupではありません。
非常に遅くなってしまったし、そもそも需要はあるのだろうか...:thinking:

2022年は全部で14問つくりました（web:11, misc:3）[^top-2]:

- SECCON CTF 2022 Quals:
    - [web] skipinx
    - [web] easylfi
    - [web] bffcalc
    - [web] piyosay
    - [web] denobox
    - [web] spanote
    - [misc] latexipy
    - [misc] txtchecker
    - [misc] noiseccon
- SECCON CTF 2022 Finals:
    - [web] babybox
    - [web] easylfi2
    - [web] MaaS
    - [web] light-note
    - [web] dark-note

なお、以下では**問題のネタバレを多分に含むので注意してください**。問題のソースコードやwriteupはこちらにまとめてます:
::: webcard https://github.com/arkark/my-ctf-challenges
:::

また、作問する上で参考にした問題や影響元になっている問題も謝辞の意味合いを込めて載せました。どれも好きな問題なので興味があればそちらもぜひ。

[^top-1]: 自分が出題されて楽しいと思える問題を提供したい気持ちがあるので、基本的にはどの問題にも愛着があり話したい裏話もあります。が、writeupに載せても興味ない人にとっては雑音でしかなく、また、自己満足な側面も大きいので別記事としてここにまとめようというスタンスです。

[^top-2]: SECCON CTFしかなくてちょっとさみしい。意外と自分は問題をつくるのがすきなことに気づいたので最近は作問意欲が結構あります。web問で良ければぜひCTF運営に誘ってください。作問ストックが毎回空になってるのでつくれる保証はないですが...。

## [web] skipinx

「simplewaf - corCTF 2022」の問題に出会い、自分も同じような問題をつくりたいと思ってました。そこで以下を満たす問題をwarmupに配置することを目指しました:

- とにかく短いソースコード
- 初心者でも解くことが可能だが、上級者にとっても自明でない[^skipinx-1]
- 解法が非常にシンプル

今のところ自明と言っている人は観測しておらず、また、序盤はwarmupなのにあまり解かれず徐々にsolvesが増えていき最終的に100solves程度になったので目的は達成できてそうで良かったです。

ところで、この問題の設定は「nginxの処理をskipさせたらフラグを入手できる」というものでした。問題名はskip+nginxを略してskipinx、読み方はnginxの音に引っ張られるため「スキッピンエックス」です。正解した人はいましたか？

[^skipinx-1]: これはTSG CTFにおけるbeginner問の考えに感化されている部分が大きいです（[参考](https://hakatashi.hatenadiary.com/entry/2020/12/01/000825) >「Beginner問題の整備」）。ところでTSG CTFというCTFが大好きで開催を待ち望んでいます:pray:

### 関連問題

- simplewaf - corCTF 2022
    - 作問者writeup: https://brycec.me/posts/corctf_2022_challenges#simplewaf
    - 公式リポジトリ: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/web/simplewaf

## [web] easylfi

curlの[URL globbing](https://everything.curl.dev/cmdline/globbing)でパズルがつくれるなと思ってつくった問題がこれです。

LFI自体は簡単（なので問題名がeasylfi）ですが、WAFを突破するための一癖あるパズルが待ち構えているという形式の問題でした。「あること」に気づく必要があり、「あっ！」と気づいてもらえることを期待しています。

実質パズルゲームなので邪魔にならず問題に集中できるレベルの「誘導」を設けて、レベルデザインに気をつけて設計しました。

この問題については特に多くのポジティブな感想をいただきました。ありがとうございます。

## [web] bffcalc

HTTP Request SmugglingやHTTP Response SplittingのようなHTTPを改竄する系の攻撃を行う問題をつくりたかったという背景がありました。ただ、一般的なソフトウェアやライブラリはこの手の攻撃に対する対策をすでに実施済みで[^bffcalc-1]、自然な問題設定として出題するのが難しかったです。

[^bffcalc-1]: 逆に対策されてなかったらそれは0 dayなので報告するべきで、結局出題はできないです[^bffcalc-2]。

[^bffcalc-2]: CTFで0 day出すのは本当にやめてほしいです。

HTTP Response Splittingについては「Sticky Notes - Circle City Con 2021」で過去に出会ったことがあり、よくできていた問題だったので参考にしました。

最終的に、XSSを攻撃の起点として、HTTP Request Splittingで本来アクセス不可能なHttpOnlyなクッキーを奪取するという問題になりました。この形式の問題は出会ったことがないので珍しいと思ってます。

### 関連問題

- Sticky Notes - Circle City Con 2021[^bffcalc-3]

[^bffcalc-3]: CTF開催後に公式リポジトリが公開されていたのですが、あるときに消されてアクセスできなくなっていました。大人の事情があったのかもしれないけど非常に残念:sob:

## [web] piyosay

狂ったパズルを1問置きたくて、つくった問題がこれです。

Baba Is You、Induction、The Witnessなどのパズルゲームが好きな人にはぜひやってもらいたい問題です。

残念なことに非想定解が2つあり、観測範囲では想定解で解かれなかったので泣いています。`DOMPurify.removed`にどうして気づかなかったんだ...非常に悔やんでます。cross-siteのiframeを使った解法も非想定です:innocent:

ちなみに、`RegExp.input`の機能は「no-cookies - DiceCTF 2022」の[非想定解法writeup](https://blog.bawolff.net/2022/02/write-up-for-dicectf-2022-nocookies.html)で知りました。どうしてこんな機能があるんだ...と思いつつCTF的にはおもしろいおもちゃなので、使わない手はありません。ただし、知識ゲーにはしたくないとおもっていて、ソースコード中の
```javascript
// Delete a secret in RegExp
"".match(/^$/);
```
は知らない人向けのヒントも兼ねてました。`RegExp.input`を知らなかった人は「この処理はなんだ？」と思って調べてもらうというのを期待しています。今後はCTFでの典型になるかもしれないです。

あと、piyosayの問題名はcowsayから来ています。見た目もこだわりました:

![](/images/2022/20221118-seccon-piyosay-01.png)

piyoの絵文字を決める†アルゴリズム†:
```javascript
get("piyo").innerHTML = "🐥/🐣/🐤".split("/")[(Math.random()*3)|0];
```

リロードすると3つの中からどれかが選ばれます。

### 関連問題

- no-cookies - DiceCTF 2022
    - 公式リポジトリ: https://github.com/dicegang/dicectf-2022-challenges/tree/master/web/no-cookies
    - `RegExp.input`解法のwriteup: https://blog.bawolff.net/2022/02/write-up-for-dicectf-2022-nocookies.html

## [web] denobox

Rust + Deno + SWC の今どきな人が好きそうな欲張り3点セットです。でも本質的に関係あるのはDenoだけでした。もしRustで期待していた人がいたらすみません。

問題名通りDeno sandbox問です。Deno特有の機能をつかってなにかできないかな〜とドキュメントを眺めながら考えてたらできました。また、既存のDeno問はあまり把握してないのですが、「denoblog - DiceCTF 2022」がとてもおもしろくておすすめです。

あと、作問にあたっていい感じのバリデーションを設けたかったのですが、「Treebox - Google CTF 2022」にあったASTをtraverseして制限する方法が非想定を出しにくくちょうどよかったのでまねしました。でも、結局非想定が出てしまったのでおしまいです。この問題は1 solvesで、その1が非想定でした:innocent: ＨＥＬＰ！

想定解はかなり独自性があって自信作です。

### 関連問題

- denoblog - DiceCTF 2022
    - 公式リポジトリ: https://github.com/dicegang/dicectf-2022-challenges/tree/master/web/denoblog
    - 公式writeup: https://brycec.me/posts/dicectf_2022_writeups#denoblog
- Treebox - Google CTF 2022
    - 公式リポジトリ: https://github.com/google/google-ctf/tree/master/2022/quals/sandbox-treebox

## [web] spanote

1問くらいsolves想定が0~1の問題がほしいなと思ってつくった問題です。

Google Chromeのあまり知られていないキャッシュの挙動を知っている（あるいは実験で気づく）必要があり、また、XSSとしてその挙動を悪用する方法はおそらく新規性のあるものなのでかなりむずかしい想定です。自分も最初はキャッシュ機構についてそんなに詳しくはなかったため、問題作成にあたって、各資料を漁ったりchromeのソースコードを読んだりと色々苦労しました。

最終的に（おそらく）新しいXSS手法に落ち着いたので、これをうまくシンプルなノートアプリケーションに問題として落とし込むようにがんばりました。思いついた手法をどこかしらで発表するのもありだったかもしれないです。

最悪誰にも解かれないんじゃないかと予想してましたが、終盤ギリギリで1チームに解かれてしまい、しかも想定解通りだったので感動しています。

ちなみに理解するにあたって、日本語記事では以下が詳しいです。ただし、現在のchromeはデフォルトでbfcacheに対応しているという違いがあるという点は注意してください:

- [Chrome の Back button を押した際に「意図しない Cache」が利用されて、期待と違うページが表示される問題について調査した](https://south37.hatenablog.com/entry/2021/01/11/Chrome_%E3%81%AE_Back_button_%E3%82%92%E6%8A%BC%E3%81%97%E3%81%9F%E9%9A%9B%E3%81%AB%E3%80%8C%E6%84%8F%E5%9B%B3%E3%81%97%E3%81%AA%E3%81%84_Cache%E3%80%8D%E3%81%8C%E5%88%A9%E7%94%A8%E3%81%95%E3%82%8C)

このような、ブラウザの実装依存だったり時代とともに変わる挙動だったりが関係する問題は難しい傾向があるという認識です。でも、webといえばブラウザなので、こういう問題が特にwebらしい問題だと思っています。

## [misc] latexipy

みんな大好きpyjail問です。

magic commentを使ってエンコーディングの解釈の差異を利用したbypassを行います。想定はUTF-7を使っていて、人によってはなつかしさを感じたのではないでしょうか？

解法は単純で多くの人に解かれるだろうと予想していましたが、最終的に8 solvesと少なくて予想外でした。現代ではこの手のエンコーディングに関する問題が発生しにくくなってきている傾向があるので意外と盲点だったのかもしれません。いや、[latexify](https://github.com/google/latexify_py)への誤誘導が意地悪すぎました。すみません。反省はしてません。

作問の形式や非想定潰しに関しては「Treebox - Google CTF 2022」と「not a pyjail - DownUnderCTF 2022」が大いに参考になりました。

```python
spec = util.spec_from_file_location("tmp", file.name)
spec.loader.exec_module(util.module_from_spec(spec))
```
で奇妙なロードの仕方をしているのは、not a pyjailの解を避けるためでした。

### 関連問題

- Treebox - Google CTF 2022
    - 公式リポジトリ: https://github.com/google/google-ctf/tree/master/2022/quals/sandbox-treebox
- not a pyjail - DownUnderCTF 2022
    - 公式リポジトリ: https://github.com/DownUnderCTF/Challenges_2022_Public/tree/main/misc/not-a-pyjail


## [misc] txtchecker

みんな大好きReDoS問です。

fileコマンドのmagic fileへのinjectionによる問題をつくりたいなと思ってつくった問題です。
blind SQLiならぬblind magic file injectionです。

問題ファイルが
```bash
#!/bin/bash

read -p "Input a file path: " filepath
file $filepath 2>/dev/null | grep -q "ASCII text" 2>/dev/null

# TODO: print the result the above command.
#   $? == 0 -> It's a text file.
#   $? != 0 -> It's not a text file.
exit 0
```
で、本質的な行が3行という究極的にシンプルな問題になったと思っていて、勝手に満足しています。

何も出力が得られず、得られるものは実行時間くらいなので、time-basedなオラクル作成 → ReDoS？というメタ読みが経験豊富なCTFプレイヤにとってはすぐだったかもしれないです。ただし、この手の問題はsolver作成に骨が折れるというのが定説で、実際に作問者の私も確実に動くsolverを実装するのに手間取りました。

ところで想定解の最初のステップの、fileコマンドの引数で`/dev/tty`や`/proc/self/fd/0`を使うことで任意の内容を書き込めるようにするというのは「what is include? - KosenXmasCTF」がアイデア元になっています。misc問で特に好きな問題の一つです。

### 関連問題

- what is include? - KosenXmasCTF
    - 公式リポジトリ: https://github.com/KosenXmasCTF/what_is_include

## [misc] noiseccon

多くのCTFプレイヤにとってはおそらく馴染みのないパーリンノイズに関する問題です。

パーリンノイズというのは、CGやクリエイティブコーディング界隈では比較的有名な古典的ノイズ生成手法です。ノイズに関しては奥が深く私はエキスパートというわけではないですが、日本語資料だと以下の本がわかりやすくておすすめです:

- [Unity Graphics Programming](https://github.com/IndieVisualLab/UnityGraphicsProgrammingSeries) vol.2 第5章
- [リアルタイムグラフィックスの数学―GLSLではじめるシェーダプログラミング | 技術評論社](https://gihyo.jp/book/2022/978-4-297-13034-3)

CTFのmisc問では、（コンピュータサイエンス内ではあるが）全く他分野の技術/理論が絡む問題が稀によく出されます。そのような問題が多いと微妙なCTFになってしまいますが、1,2問CTFに混ざっているのは異種格闘CTFみたいで好きなので、今回出題してみました。

想定では、パーリンノイズの実装（または理論）からアルゴリズムの性質を考察し、そこからcrypto的な思考でオラクルを構成してフラグの各ビットを特定するというものでした。brute forceで解いたチームが複数あったようなので悲しいです。ただ、完全に想定通りな解法で解かれているのは見かけてはいませんが、本質的（間接的）には想定解で用いた性質を利用してオラクルしているものがあったので、うれしかったです。

## [web] babybox

JavaScript sandbox問です。

野生のおもしろJavaScript sandboxが遊べるライブラリがないかな〜と漁っていたらたまたま見つけて、色々いじったらprototype pollution to RCEができ、そのやり方がJavaScript特有のパズル要素があっておもしろかったのでそのまま問題として出題しちゃいました。

sandbox系は色々な解法が出がちで、この問題では非想定を歓迎していました。実際、prototype pollutionを使わずに解いている人もいておもしろかったです。

なお、この問題はライブラリの脆弱性を使ったものなので本来は出題せずに報告するべきものでしたが、issueやPRを見るとどうやらすでに報告済みで修正されていました。ただし、なぜかnpmへは修正済みの内容がpublishされておらず数年間放置されており、また、報告されている脆弱性はprototype pollution止まりだったため、問題として出してもよいだろうと判断しました。

sandbox問としてはおもしろいと思うのですが、issueに気づくか気づかないかで解くスピードに差が出てしまうので、その点だけが気に入っておらず[^babybox-1]、悔やんでます。

[^babybox-1]: ライブラリやフレームワークの脆弱性をissueやPR等で探して、そこを取っ掛かりにして解く問題は世の中にたくさんありますが、自分はその手の問題があまり好きではないです。個人的には、CTFの問題では既知脆弱性探しはさせずに、自力で脆弱性を見つけてゴール（フラグ）までの道筋を見つけて攻撃する、その過程の楽しさに主眼を置きたい気持ちがあります。

## [web] easylfi2

easylfiではテンプレートエンジンがあったからWAFのbypassができたのに、まさかのそのテンプレートエンジンが消えた上でなおWAFが健在しています。不可能では？？？を第一印象に抱いてもらえたら大成功です。

ぱっと見easylfiの上位互換の問題に見えるが実はそうではないという問題でした。

予選の段階ではeasylfi2の問題案はまったく思いついておらず名前は完全に後付けです。後述のdark-noteの問題を作成中にバグではまってたのですが、その原因がstdoutの詰まりでした。せっかくなので問題にできないか考えたところ、予選で出題したeasylfiの続編としてちょうどよい構成を思いついたので出題に至りました。

## [web] MaaS

この問題は攻撃フェイズが2段階あり、1段階目はform submitの挙動を突いてbypassする、2段階目はパズルでCSP bypassをするという構成になっています。

1段階目で関係するのはnewline normalizationというものです。これはブラウザに実装されているform submit時に`\n`が`\r\n`に変換される挙動（仕様？）を指します。これによって送信前と送信後で文字数が変化するので攻撃に利用できるという想定でした。ガチャガチャ実験すると偶然見つけてしまう可能性が高かったため、minifierによって`\n`を潰しやすくして、ついでにMinifier as a Serviceというそれっぽいwebサービスにしました。

newline normalizationを利用したCTFの問題は今まで見たことがないので初出だと思っています。web開発者ならこの挙動に苦しんだ人もいるかもしれません。どの程度知名度があるものなのか知らなかったので難易度想定が難しく、簡単すぎたらどうしようと不安になっておまけで後半に雑にパズルを設置しました。感想を聞く限りこのパズルが曲者だったようです。すみません（？）

writeupでパズルの解説もしたかったですが、実際解説しようとすると狂いそうになったので適当にごまかしました。

## [web] light-note

0 solvesその1です。どうして...

ブラウザの新しい機能に関係する問題を1問混ぜたいというモチベーションで作問を始めました。案としてはSanitizer API、Import Maps、Trusted Typesあたりが浮上しました。

最終的にはSanitizer APIとImport Mapsを用いた以下の`write`関数をDOM Clobberingだけで壊すという至極シンプルな問題に落ち着きました:
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

新しい機能はブラウザによって対応状況が異なるので、FirefoxとSafari向けのfallbackを用意したという体の問題になっています。それっぽくコメントを付けてますが、実際にSafariで2つ目のfallback先に遷移するのかは試してません。

DOM Clobberingパズル設計については「Simple Blog - zer0pts CTF 2021」「modernblog - corCTF 2022」あたりから色々学んでから取り掛かりました。

また、単純にDOM Clobberingするだけだとおもしろみがないので、「nested forms回避」というひと捻りを加えてみました。参加者の感想を聞く限り、この回避方法を思いつくことに苦戦していた人が多いようで[^light-note-1]、作問者としてはしてやったりになってます。

[^light-note-1]: 作問者とは違い、解く人はこれが想定解という確信がないので余計にむずかしいという要因があります。

ところでSanitizer APIについては、DOMPurifyと同様の用途でセキュリティ対策として使えるかどうかという観点でも探っていました。[仕様書](https://wicg.github.io/sanitizer-api/#security-considerations)にもあるようにSanitizer APIには対策を想定していない攻撃シナリオが複数存在します[^light-note-2]。mXSS対策に親和性があるのは魅力的ですが、効果的にセキュリティ対策として利用するには適切な設定を行う必要があり、ある程度の知識・経験を要求することから、安易にDOMPurifyの代替として勧めるのはよくなさそうだなと感じました。一方で、使用目的が明確なときは適切な設定と利用方法を行うことで強力な武器（というか盾）になりうり、また、外部ライブラリに頼らないブラウザネイティブのAPIとしての存在意義があり、今後の動向が気になるところです。

[^light-note-2]: これは機能の存在理由や責任の所在等に依るものなので、Sanitizer APIが悪いということを意味しません。

### 関連問題

- Simple Blog - zer0pts CTF 2021
    - 公式リポジトリ: https://github.com/zer0pts/zer0pts-CTF-2021/tree/master/web/simple_blog
    - 公式writeup: https://st98.github.io/diary/posts/2021-03-07-zer0pts-ctf-2021.html#web-192-simple-blog-23-solves
- modernblog - corCTF 2022
    - 公式リポジトリ: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/web/modernblog
    - 公式writeup: https://brycec.me/posts/corctf_2022_challenges#modernblog

## [web] dark-note

0 solvesその2です。どうして...

決勝のために作成したボス問です。作問余力が足りなくて予選のボス問ほど難しい問題にはならなかったですが、ヘビーな問題ではあったと思います。

最初は一風変わったXS-Leakの問題をつくろうと検討していたのですが、クライアント上でのリークではなくサーバ上でのリークにするとおもしろいのではないか？と思い、最終的にテンプレートエンジンでのキャッシュの有無によるレンダリング速度の差異でオラクルをする問題になりました。

webをある程度やっているCTFプレイヤであれば、解法のコンセプトを理解することは比較的簡単で問題自体も簡単そうに見えると思います。一方で、実際にオラクルを構成するには色々と工夫するポイントが多くありひらめきやセンスを要求するという点で難しいという想定です。exploitの実装においても、botに対してCSRFを仕掛けてキャッシュを汚染するフェイズと直接サーバにリクエストを送ってキャッシュの有無からリークするフェイズがあり、割と複雑です。

また、light-note/dark-noteで問題名が似ていますが、実は実装も似せているため、差分を取ることによってある程度時短できるようにしていました。というのも、ソースコードを理解する時間よりも問題の本質部分に取り掛かる時間を多くとってほしかったためです。

ちなみに、テンプレートエンジンのキャッシュを利用した問題は「Panda Memo - CakeCTF 2022」があります。`"mustache" ctf`などで検索するとこの問題がヒットしてしまうので、キャッシュを利用することがすぐにバレないように`mustache`ではなく`Hogan.js`を使ってました。

### 関連問題

- Panda Memo - CakeCTF 2022
    - 公式リポジトリ: https://github.com/theoremoon/cakectf2022-public/tree/master/web/panda_memo
    - 公式writeup: https://ptr-yudai.hatenablog.com/entry/2022/09/04/230612

## まとめ

こうしてみると、自分の作問は過去に解いたCTFの問題から多くの影響を受けているなと感じました。普段はたのしくて創造的な問題を遊ばせてもらっている立場なので、逆に提供する側になってCTF界隈に還元できていたらうれしいです。

また、参加者のwriteupはうれしすぎて何度も読んでいます。大感謝です。
