---
title: 動作テスト
date: 2020-11-04 22:40:36
tags:
    - misc
thumbnail: /images/2020/20201104-ark_white.png
---

## テスト

### テスト

####  テスト

以下、テストです。

1. これはテストです。
1. *これはテストです。*
1. **これはテストです。**
    - :cat::wolf::camel::snake::bird::turtle::octopus::whale::dolphin::dragon:

xxx | yyy | zzz
--: | :-: | :--
111 | 222 | 333
qw  | er  | ty
a   | b   | c

> Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. This framework includes a suite of full-featured, high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows, macOS, and Linux. Capabilities include disassembly, assembly, decompilation, graphing, and scripting, along with hundreds of other features. Ghidra supports a wide variety of processor instruction sets and executable formats and can be run in both user-interactive and automated modes. Users may also develop their own Ghidra plug-in components and/or scripts using Java or Python.
> https://github.com/NationalSecurityAgency/ghidra

$x^y = 1$

$$
c = \pm\sqrt{a^2 + b^2}
$$

```rust
// https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn main() {
    // File hosts must exist in current path before this produces output
    if let Ok(lines) = read_lines("./hosts") {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            if let Ok(ip) = line {
                println!("{}", ip);
            }
        }
    }
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
```

![](/images/2020/20201104-ark_white.png)
