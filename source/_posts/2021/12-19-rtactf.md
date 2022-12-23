---
title: RTACTF (SECCON Speedrun Challenge) crypto writeup
thumbnail: /images/2021/20211219-rsactf-leaky-rsa.png
date: 2021-12-19 23:00:00
tags:
    - CTF
description: RTACTF（SECCON Speedrun Challenge）のcryptoパートのwriteupです
---

今年のSECCONではRTACTFという早解きCTFが開催されました。

- コンテストページ: ~~https://speedrun.seccon.jp/~~

RTACTF実況動画:
::: webcard https://www.youtube.com/watch?v=VXaROnAmAiY
:::

kurenaifさん視点動画:
::: webcard https://www.youtube.com/watch?v=tDkNKz0qMW4
:::

問題リポジトリ:
::: webcard https://github.com/ptr-yudai/RTACTF-2021
:::

ジャンルはpwnとcryptoの2つで、pwnはできないのでcryptoだけ外野で走ってました:runner:

結果です（順位は執筆時点）:
| Challenge | Rank | Time |
|:-:|:-:|:-:|
| Sexy RSA | 11th | 229.03 sec |
| Proth RSA | 6th | 741.37 sec |
| Leaky RSA | :2nd_place_medal: | 1582.89 sec |
| Neighbor RSA | 9th | 1957.66 sec |

思ったより良い結果になってうれしいです。
cryptoは普段あまりやってないのですがRSA問はたまに解いたりしてたので問題セットに恵まれました。

## Sexy RSA

> crypto
> 目標：300 sec
> Sexy RSA is an RSA scheme with a sexy private key.
> 秘密鍵がセクシーなRSA暗号をSexy RSAと呼びます。
> author: ptr-yudai

### 問題ファイル

- `chall.py`
- `output.txt`

```python
# chall.py

from Crypto.Util.number import getPrime, isPrime
import os

def getSexyPrime(n=512):
    # Sexy prime: https://en.wikipedia.org/wiki/Sexy_prime
    while True:
        p = getPrime(n)
        if isPrime(p+6):
            return p, p+6

if __name__ == '__main__':
    # Plaintext (FLAG)
    m = int.from_bytes(os.getenv("FLAG", "FAKE{sample_flag}").encode(), 'big')

    # Generate key
    p, q = getSexyPrime()
    n = p * q
    e = 65537

    # Encryption
    c = pow(m, e, n)

    # Information disclosure
    print(f"n = 0x{n:x}")
    print(f"e = 0x{e:x}")
    print(f"c = 0x{c:x}")
```

### 解法

RSAですが、2つの素数の差が小さいのでフェルマー法です。アルゴリズム名がすぐに思い出せなくて時間ロスしました。

```python
# exploit.sage

from Crypto.Util.number import long_to_bytes
from math import isqrt

n = 0xe72988e811f04091c3291ac28f1e8332193187f3dc5af01579c36badb06671aa9a9543aa07eba8cdab36d787f1ff98a06db995c43cd5c63581ce050e0b9ba856634dabfaf8c7f271fbd026edd6ea1257b16013a526e0581a688cc6a335e7ee4c1b0633f0532d3d0824824195b6b249c70cf0e458609efc01a6575f084e6de53b
e = 0x10001
c = 0x6fadd5d7095bd6f45de69bb4e76080e0ea5f8c5a159de10663133e585b71ae580b99b3e0a8e047a9c51c8091a6b33b01c9ab95668794c3acfb084e939a04cb151757c3b2522da99e03f83e205c7c701066d69b120ca17fcf59061c078d9099e5f4bf6dd6dab206418527035f2c1096861c2896327977ac88c2728faa7504d879

# ./Vespiary wikiから盗んできた
def fermat_method(N, attempt=None):
    a = isqrt(N) + 1
    while attempt != 0:
        b2 = a * a - N
        if isqrt(b2)**2 == b2:
            return (a - isqrt(b2), a + isqrt(b2))
        a += 1
        if attempt is not None:
            attempt -= 1
    return None

p, q = fermat_method(n)

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

```sh
$ sage exploit.sage
b'-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= RTACON{n3v3r_us3_sp3c14l_p41r_0f_pr1m3s_4_RSA} =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'
```

### フラグ

```
RTACON{n3v3r_us3_sp3c14l_p41r_0f_pr1m3s_4_RSA}
```

## Proth RSA

> crypto
> 目標：900 sec
> Proth RSA is an RSA scheme invented by Francois Proth in the 19th century.
> フランソワ・プロスが19世紀に発明したRSA暗号をProth RSAと呼びます。
> author: ptr-yudai

### 問題ファイル

- `chall.py`
- `output.txt`

```python
# chall.py

from Crypto.Util.number import getRandomInteger, getPrime, isPrime
import os

def getProthPrime(n=512):
    # Proth prime: https://en.wikipedia.org/wiki/Proth_prime
    while True:
        k = getRandomInteger(n)
        p = (2*k + 1) * (1<<n) + 1
        if isPrime(p):
            return p, k

if __name__ == '__main__':
    # Plaintext (FLAG)
    m = int.from_bytes(os.getenv("FLAG", "FAKE{sample_flag}").encode(), 'big')

    # Generate key
    p, k1 = getProthPrime()
    q, k2 = getProthPrime()
    n = p * q
    e = 65537
    s = (k1 * k2) % n

    # Encryption
    c = pow(m, e, n)

    # Information disclosure
    print(f"n = 0x{n:x}")
    print(f"e = 0x{e:x}")
    print(f"s = 0x{s:x}")
    print(f"c = 0x{c:x}")
```

### 解法

素数の生成方法が特殊です。

- $p = (2k_1 + 1) \cdot 2^{512} + 1$
- $q = (2k_2 + 1) \cdot 2^{512} + 1$

で生成して、さらに $s \coloneqq k_1 k_2$ の値が既知です。
式の対称性から $t \coloneqq k_1 + k_2$ とおくと変数が一つ減って見通しが良さそうです。
また、以降の等号はすべて $\bmod$ $n$ で計算しています。

このとき
$$
\begin{aligned}
\phi(n)
&= (p - 1) \cdot (q - 1)\\
&= (2k_1 + 1) \cdot 2^{512} \cdot (2k_2 + 1) \cdot 2^{512}\\
&= (4s + 2t + 1)\cdot 2^{1024}
\end{aligned}
$$

から$t$の値が得られれば良いことがわかります[^proth1]。

[^proth1]: $t$の値がわかれば$k_1 k_2$が既知なので$k_1$と$k_2$も求まりますが、今回は不要です。

続いて
$$
\begin{aligned}
n
&= pq\\
&= ((2k_1 + 1) \cdot 2^{512} + 1) \cdot ((2k_1 + 1) \cdot 2^{512} + 1)\\
&= 4s \cdot 2^{1024} + t \cdot (2^{1024} + 2^{513}) + 2^{1024} + 2^{513} + 1
\end{aligned}
$$

より
$$
t = \frac{n - 4s \cdot 2^{1024} - 2^{1024} - 2^{513} - 1}{2^{1024} + 2^{513}}
$$

で$t$が求まりました[^proth2]。

[^proth2]: 方程式が出た段階でsageに投げればよかったんですが、慣れてないことをするのはRTAでは悪手なので素直に手計算しました。

```python
# exploit.sage

from Crypto.Util.number import long_to_bytes

n = 0xa19028b5c0e77e19fc167374358aa346776e6c20c27499505be59c83ea02014e97af631ba0ccbab881313818fd323c15c82dad8793220ba6679ec4b38787e04d0c1fff0880e04423ea288e443660c63a1607532e47dbaad421723d0546c208447f701cd7e9ee1bb43774d132abbb2e91bf50b67be40ed854dbe6c3071ca3ae3307ac03abd76f74e506594106a22795d4b7938611301248a9957e1a637538a9169cf38daf5d60ffc05ae32ea7e638e16d790ffeebfff655a645c99a513616d3ce00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
e = 0x10001
s = 0x28640a2d7039df867f059cdd0d62a8d19ddb9b08309d265416f96720fa808053a5ebd8c6e8332eae204c4e063f4c8f05720b6b61e4c882e999e7b12ce1e1f812c11cfed72a5c33cfb8f3d34f650e4c19579cf34745f2588aa2fd08a8746257cb789f23ca232346fcf72468a2b160934911902de3f90620aba5874a2d79a33699
c = 0x4595c3c923bd191ba07456611f80e656a197ff528a031e2952adedda532b1fa2caef719c929132a3cdf06d0e55e6a00f7eb1f189a614b26759916ec42f83579a75ab5948186769a1a936b019466f918f29e32852675c464b7f0797c6fdc55efcd54fbe2083761b1df3dde0b9a9a35b96e3b216c54770b444b1f02525f0268c44483c6e84a781fe9111e6912130d69f462c519873043d44e4a3f1f938491feeb591b5831d0abe7399bc87244576decaf2925f287d3c2bb4061d560c919d820e364744f2322c7efd37d42563842bcf9b1d6b46218694dcd49758d311c6896e38cf2b55c7114d78cfdfaeba74720ecf30d9133034799b9735e26ec913cc9f26bb0a

x = (n - 4 * s * (1<<1024) - (1 << 1024) - (1<<513) - 1) % n
t = x * pow(((1<<1025) + (1 << 513)) % n, -1, n)

phi = (4*s + 2*t + 1) * (1<<1024) % n
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

```sh
$ sage exploit.sage
b'-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= RTACON{d1d_U_us3_th3_p0w3r_0f_Groebner_basis?} =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'
```

### フラグ

```
RTACON{d1d_U_us3_th3_p0w3r_0f_Groebner_basis?}
```

## Leaky RSA

> crypto
> 目標：1800 sec
> Leaky RSA is an RSA scheme whose private key is partially leaked but is still considered secure.
> 秘密鍵が多少漏洩しても安全と考えられているRSA暗号をLeaky RSAと呼びます。
> author: ptr-yudai

### 問題ファイル

- `chall.py`
- `output.txt`

```python
# chall.py

from Crypto.Util.number import getPrime, isPrime, inverse
import os

if __name__ == '__main__':
    # Plaintext (FLAG)
    m = int.from_bytes(os.getenv("FLAG", "FAKE{sample_flag}").encode(), 'big')

    # Generate key
    p = getPrime(600)
    q = getPrime(500)
    n = p*p*q*q
    e = 65537
    s = ((p**3 - 20211219*q) * inverse(p*p+q*q,n)) % n # tekitou (ha?)

    # Encryption
    c = pow(m, e, n)

    # Information disclosure
    print(f"n = 0x{n:x}")
    print(f"e = 0x{e:x}")
    print(f"c = 0x{c:x}")
    print(f"s = 0x{s:x}")
```

### 解法

普通のRSAと違うところは

- $n$ が $n = p^2 q^2$ であること
- $s \coloneqq \frac{p^3 - 20211219q}{p^2 + q^2} \pmod n$ という謎の値が既知であること

の2つです。

multi-prime RSAっぽい形をしているので、この$n$に対しても$\phi(n)$を求めて復号ができそうです。RTAなので確認はしていません。$\phi$関数の計算方法をど忘れしてしまったので、定義から調べるハメになり時間ロスしました:cry:

$$
\phi(n) = p(p-1) \cdot q(q-1)
$$

以下、$a\coloneqq 20211219$ とします。この数値は今日の日にちなので値自体に意味はなく、また、（$p$や$q$と比較して）非常に小さい値であることから、適当な方程式からいい感じに$p$や$q$の†情報量†が残り Coppersmith's Attack に持ち込めるかもと思いました。

$s$に対する方程式を式変形すると

$$
sp^2 + sq^2 = p^3 - aq \pmod n
$$

です。ここで色々悩んだのですが、そういえばsageの`small_roots`は`beta`を適当な値にしたら$n$の約数、つまり$p$や$q$の$\bmod$に対しても計算できるということを思い出し、指数が大きくて邪魔な$p$で$\bmod$を取ってみます:

$$
sq^2 = - aq \pmod p
$$

行けそうな雰囲気を醸し出しているのでコードを書きます。

```python
# exploit.sage

from Crypto.Util.number import long_to_bytes
from math import isqrt

n = 0x2ac1fcbbf63ffeade11cd2c57c37db18d96d52e433bd9034d4eac2c269ea49a81e5ac41fb631523bb5983adc6fc939c073c13d8a3a42a06accf5a9c304fc444508a8b5833b5431e9af7007bb216c510c62a97eb1fe380bf155b3e497c7d70c2bb921f97eec61e9e9ac7b5d71e47876d20cbfb1a0732e29ec6872041eb67e0ccd39d7b6429bda1581537dda95e79d3aad4df072beada1c72a4ffd86db91918ec9db44ab9c4bebf387ccc1ce7b2540b0d595a4c11823cdbcd8850bd3b666b4a08bd69de515afecc75b283ae47fbf3af6f034f3b0f7848dec935ba8b97e36d2d0a9208df63610cf8825fb729aacaa4c119d0b4c5e230e080d7633f145d22eb06b917fe632c01a373b1c4c8a741bea1d5dd98003e9
e = 0x10001
c = 0xe50a858f715238a9ab44dfd691f6e5ced84e74115e003e31a98b324cf9e8bc9cfe08065f2538cff519e035566b4080742139062e672a0ad3196275cb121ea837de2808f99958bcfe58d1c8996f291412220d01fe65fbf18611b348407b2e2db45b2adcc341926c6d76a9d08fc77db0fedef78cec9e4b881812e60c015c1005dfd0b9408cb3c6f9f98332f165acc3ae98ef97f2a1d98524fe240d3351676ed84ddb73283a6d3efc40bbd466fe3532e579eb9adf07ebbc49af71fb22934a75a69a538eca0fd4e2a5b617abb361a64c553985950dd5201ac7c631580c8bb27d795a196d584ae7c7478bdc1b5ff531ff88e984bceb1e26cf9793f99a11287555d5d2d2a13e1171f77bf8491d8dfa297e9cd6d4b7d
s = 0x14c0af71a961be72e2d4e5ee06337cde2034db1d920f4476e3a3371c8a35e7ba8efabf5c8e8ff86e7297156c4fde5bdc7aabe1516a46c554236104022eb4544f1d7fcb80279595dfe0527bcc373909ce7cc0965ece5ff76b7ee9a5cc31a1b567ed3ddd2364bb596e3c41e4fffb5974f71e788da5c21598e9c6dc32bca162026ba3c410bb1c5c9d5bed4c3b97e3cacbd7b6693f29c74b0756381b658efaa757d448f62a48fbdb06604525222aa51797a1a1e43af4b0c221deef47f84bb5bfa1480cd31242c3d7fba21bdf487709853879dcea284e44cb5ee1a02c558a29740a44e39c7ee3a97ab4805d21cb90b596bd86c51f4e0f783701da73c66f5a4c67d989bb2dba2b8a55a697eb187cc181fc8ce54de370

a = 20211219

pq = isqrt(n)
assert pq * pq == n

PR.<var_q> = PolynomialRing(Zmod(n))
f = var_q*var_q*s + a*var_q
f = f.monic()
xs = f.small_roots(X=2**500, beta=0.3)
print(xs)

q = int(xs[1])
assert pq%q == 0
p = pq // q
phi = p*(p-1) * q*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

```sh
$ sage exploit.sage
[0, 1922170375642253101720795198135909686494155409464023438804428444232467343105956174957087101662812915933127607975743244342906562612795777257605243515321]
b'---===---===---===---=== RTACON{C0pp3rsm1th_h3r3_4nd_th3r3_4nd_3v3rywh3r3} ===---===---===---===---'
```

勝った。

### フラグ

```
RTACON{C0pp3rsm1th_h3r3_4nd_th3r3_4nd_3v3rywh3r3}
```

## Neighbor RSA

> crypto
> 目標：1800 sec
> Neighbor RSA is an RSA scheme with the private key made with your neighbor.
> お隣さんと秘密鍵を作ったRSA暗号をNeighbor RSAと呼びます。
> author: ptr-yudai

### 問題ファイル

- `chall.py`
- `output.txt`

```python
# chall.py

import os

# Plaintext (FLAG)
plaintext = os.getenv("FLAG", "FAKE{sample_flag}").encode()
plai  = plaintext[:len(plaintext)//2]
ntext = plaintext[len(plaintext)//2:]
m1 = int.from_bytes(plai  + os.urandom(128), 'big')
m2 = int.from_bytes(ntext + os.urandom(128), 'big')

# Generate key
e = 65537
p = random_prime(1<<2048)
q = random_prime(1<<512)
r = random_prime(1<<512)
n1 = p * q
n2 = next_prime(p) * r
assert m1 < n1 and m2 < n2

# Encryption
c1 = pow(m1, e, n1)
c2 = pow(m2, e, n2)

# Information disclosure
print(f"e = {hex(e)}")
print(f"n1 = {hex(n1)}")
print(f"n2 = {hex(n2)}")
print(f"c1 = {hex(c1)}")
print(f"c2 = {hex(c2)}")
```

### 解法

普通のRSAの暗号化が2回行われています。あやしいのは次の2つです:

- $n_1$と$n_2$の素数の片方が`p`と`next_prime(p)`で近い値を使っている。
    - 以下、$p_1, p_2$とおきます。
- $p_1, p_2$が$q, r$に比較して非常に大きい。

$k \coloneqq p_2 - p_1$ とおきます。$k$は小さい値であることが予想できるのでfor文を回すことにより既知の値とみなすことが可能です。

ここで
$$
n_2 = p_1r + kr
$$

に対して$n_1$の約数である$p_1$で$\bmod$をとると
$$
n_2 = kr \pmod{p_1}
$$

になります。あとはLeaky RSAと同じ要領で Coppersmith's Attack で殴れば$r$が求まりそうです。$r$がわかれば他の素数も求まります。

```python
# exploit.sage

from Crypto.Util.number import long_to_bytes

e = 0x10001
n1 = 0xa8ed020c3dd125d503bf124052d643ba1405f2c349244122140e79e7d2244304a1590762c61ac83900c2aced76007b2e3f320464fd51fcfad167ebdc87e69329230869e0a3e153b44ed3b04bfe94174bc8b5ee1a3fa8036b6b9e834666aa07229a431b477e589d94f9a4cfed25b195215b0c694b86e874413b8a00cb064809c8e3677632cde9b43b87a0b812c2024b0c821b5c10764fd4de2d18af55d897d94aeded80b71e36fd73014f75641a8c5b38b36faa020e7cf1327a707bb7d42503bcc28768ef184d66b9ba16efd019b68268885a2da302cd326e78b1d473bcf7cd62442ccd25dc85d23aeb5408922b6b00f13584bea394f1bca4cc431f3c29c5d98ec1683453cc0c526abe4aec08781c7a53f50f2047b4995b9bea6a7a9f6b5425b29be6e867764efaa050799f716af78273041372cfe4f3c88a62329f6f1feff99
n2 = 0x16ea1bde86ea11cdec196a9173258efca235da66f8e3d5437e39e1b2e2574dd3f93d65104ca0225d6119519ae9ea9c035e0f85f02212c0992d0705723fa8b97ed6cff860c4d8fb65f0214a0047feca64e662dcbf025fff47590305e90e5d070d39871880828f5e960ab2ef330129ed5752c3b4debe827376a632b06487740fff4b622a88de23649e3e6993cd332b0284b84eb8765d58527209cc202c89d479421131a2f64ae517ee1e62e6c0f329c306569e427113ec6a8b9d96d73e95580d3a33f6add681f9a9156f0681eb1804183dfa8cebbe921d2fb1d43b256f727d46c5859cc5229f7e555ad25397e5cd14620ebbaefa0a0a520bada3ef8b115481734242af6befbd9b069d4a03281094c0f4aca4e6fdcbe2558b104fc2b383e1c70f0e5a07d1a623f9fc2309ca1d09b69aa1869e280fbc50de2adbada7ea545743b12b
c1 = 0x690e49037fee7649033ffaaa71e4730d2d7143fab97beb22e2afdf6eca449cad3f95b60295f592e7e84833e08b3468d61a34c1d1123f4c683c79d68bbe27dd0af203fc50ef7ebe98b1bc1221918470f058a8fb7645eacb569931835bd7f80494dbb67fbaa592ec19d9b4930c787a2ce1267f8088229b5031e710d6cd5720756923ccb64444939a0f09a51c87488650d4d02551fd4ed7a2fd248825ec34c5df8b6077a6d0d75c5832f9140420c92d3d00cf51e3b0665f5a6d031cb369ddebbb5ce77f2176cd12bb0add5aeda6ae88c4ceade0c1fd0ff3960d3ee36a0c6455ae3027f33e660663d0e2298654e19e8c8a06b4de991fac3b4c1673825b3d9f8f5c675f920a7d137f85ba723bf741321904e0c3c601f5c18d02e1e5b7b118e62e91a7926a9b1eda3cc53e2a6cbc95553e1990ec3f6cceddf283410d6e6849a26f89b
c2 = 0x5c4c7dce82753a68dcdbcdce9af52c9b7af2f561c08b8e23b27c6145d4c3df29d498303bee1bd29829a2e0ae9faaf243b387c39d69daccba07dace7bb420115ffaa69f89a3ea4e1ef0e08eb19043e012a090b79e51d6ae8446ca76e88abe5adbdbe25a731d7ee9aa333a84447edafbc360b505ff293c751571c6bf29dee99fdc443b756f182eb588b4a03de3d35dc4f23736d7239cfbd0ca13fa7b234bc4064a2053ab0045f4833250c8c9de91798502b09d4312ee52f3dc5229dfcb73b42f7c3440932839e6e790bb0db1788fbd7c60365121bbe3858ecedd3d48261d081c380e7ddf6ca570c13cc89c0af2011b4978b22d5456d1122dabd7b2068ab30e301a674809732daede77a27ae13e1bc4779e15d51210f6c10be159907ec1a59bfaf8db6cf290a348f734fd88e3c2b7df6bda84665b810cfe55bc3645d8d118c9172

PR.<var_r> = PolynomialRing(Zmod(n1))
for k in range(1, 2000):
    f = n2 - k*var_r
    f = f.monic()
    xs = f.small_roots(X=2**512, beta=0.3)

    for x in xs:
        r = int(x)
        if n2 % r != 0:
            continue
        p2 = n2 // r
        p1 = p2 - k
        if n1 % p1 != 0:
            continue
        q = n1 // p1

        phi1 = (p1-1) * (q-1)
        d1 = pow(e, -1, phi1)
        m1 = pow(c1, d1, n1)
        phi2 = (p2-1) * (r-1)
        d2 = pow(e, -1, phi2)
        m2 = pow(c2, d2, n2)

        print(f"{k = }")

        print(long_to_bytes(m1))
        print(long_to_bytes(m2))

        exit(0)
```

```sh
$ sage exploit.sage
k = 720
b"RTACON{1nt3nd3d_s0lut10n_\xa3m\x1c\xf1/w\x8b\xdcH\x15\xe5\xaf#\xc3\xc8G\x10\r\xf8\x00\x00M1\x06^\xfeB\xa1X\xf0\x88I\xd9&\x07\xb2t\xb2%\xfe\xcc\xae\x8aa\x7fxukDEa\xab\x15{\x8e\x9d\x87m\x81\x95\xeb\xe9\xc7l_{U\xae\xbb\x1d}\xa40*\xbe\xad'\xa6k\xdeJ\x0e\xceI\xfd\xb3T\xa9\x7f\\\x08\xc0\x14\x00\xd2\x06\xf2\x1d%\x98Y\xea\xbe\x86\xee\xc1H\xea\xf6\x10\x95CU$\x04\xb9\x08\xb8\xcax\x89x)\xef\xa3\xfbQ\xe4"
b"1s_Approximate_GCD_:pray:}z\xa5I\xec8\xcdF\xc2\xf0\xa4r\xbc\x03\x95\xfb\xf5^GP\x80\xc3X\xe5\xbf\x9a\xbcb\xbc\x89Z?\xcc\xc7\x94\x08\x18\xc91-P\xbf\xda\xb9\n)\x82\xa6\xd2\x8a$\xff\xbc_`\xa4\xaa\xe7\xa4\x10\x1a?\xfd\xd9\x92>_\xd44\x86\x80\x16\x9ebcW\xf7j\x18\xdax4\x83\xf4\x0bNGa\x91\x13.\x8a\xac\x1bA\xfd\xb4\xef\x8a\x88Z0\x91\x83:?\xeecA\x1b\x7f\xda\xbd\xc6\x81\xd7\x04\xfd\xa7\xb7\xc6\xeb\x04\xd0\x83\x7f\xf4'\xf8"
0
```

### フラグ

```
RTACON{1nt3nd3d_s0lut10n_1s_Approximate_GCD_:pray:}
```

Leaky RSAの延長線上でこれは想定解法だ〜と思っていたのですが、想定解はApproximate GCDと呼ばれるものでLLLか連分数展開で解くようでした。LLLは未履修なのでいずれ理解できるようになりたいです[^neighbor]。

[^neighbor]: Coppersmith's Attackの内部でも使われているらしいので、その理解も含めて理解したいです。

## 感想

webがないので走る予定はなかったのですが、Twitter見てたらCTF界隈が賑わっていたので参加してみました。コードを読むフェイズがほとんどなくRTAとして取り組みやすいシンプルな問題で良かったです。内容もおもしろい問題でした。
pwnは実力不足で挑戦しませんでしたが動画実況で上位プレイヤーが爆速で解く光景を見るだけでも楽しかったです。
