<div align="center"><img src="assets/misc/unycoin.png" style="width: 300px"></div>
<br>
<h1 align="center">Unycoin</h1>

<div align="center">
<br>

![license](https://img.shields.io/github/license/leoraclet/unycoin)
![language](https://img.shields.io/github/languages/top/leoraclet/unycoin)
![lastcommit](https://img.shields.io/github/last-commit/leoraclet/unycoin)
<br>
![Language](https://img.shields.io/badge/Language-Python-1d50de)
![Libraries](https://img.shields.io/badge/Framework-None-fa8925)
![Size](https://img.shields.io/badge/Size-1.6Mo-f12222)
![Open Source](https://badges.frapsoft.com/os/v2/open-source.svg?v=103)

</div>

## Table of Contents
- [Table of Contents](#table-of-contents)
- [📖 About](#-about)
- [✨ Features](#-features)
- [📦 Structure](#-structure)
- [🔌 Modules](#-modules)
  - [Cryptography](#cryptography)
- [📚 Libraries](#-libraries)
- [🚀 Install \& Run](#-install--run)
- [❤️ Thanks](#️-thanks)
- [📜 License](#-license)


## 📖 About

> [!WARNING]
>
> ⚠️ This project was started even before I entered high school because I wanted to understand how
> **Bitcoin** worked. I almost didn't touched this project since then.
>
This project is a pure Python implementation of a cryptocurrency inspired by the original concept
introduced in Satoshi Nakamoto's whitepaper: [Bitcoin: A Peer-to-Peer Electronic Cash
System](https://bitcoin.org/bitcoin.pdf).

> [!IMPORTANT]
>
> ### Security
>
> All cryptographic protocols and functions in this project are implemented according to their
> official specifications. The **ECDSA** algorithm is secured against side-channel attacks by using
> the Montgomery Ladder technique for point multiplication on elliptic curves.
>
> ### Efficiency
>
> Since this project is written entirely in Python, the cryptographic protocols are way less
> efficient compared to implementations in lower-level languages like C++. However, for general
> tasks such as networking, Python provides sufficient performance.


## ✨ Features

- **Project**

    - 🔄 **Reproducible**: Built with **uv**, this configuration can be effortlessly reproduced on
    other machines, ensuring a consistent setup.

    - 📖 **Documented**: Most of the parts of my source files are commented and documented with
    links and explanations if necessary

- **Program**


## 📦 Structure

**Directories**

  - [**`assets`**](./ansible/) - Resources
  - [**`src`**](./server/) - Source files and modules
  - [**`tests`**](./assets/) - Test files and modules


## 🔌 Modules

### Cryptography

This module implements all cryptographic protocols and primitives that are necessary to ensure
cryptocurrency's security and integrity. All protocols were implemented from scratch in pure python
based on their official description.

Here is the implemented ones :

- **Base 58**
- **Ecdsa**
- **AES**
- **Bloom filter**
- **Murmur hash**
- **Merkle tree**
- **Sparse merkle tree**
- **Ripemd160**
- **Sha256**


## 📚 Libraries

> [!NOTE]
>
> None, everything was re-implemented from Scratch for learning purposes

## 🚀 Install & Run

First, ensure you have the [**`uv`**](https://docs.astral.sh/uv/) python package manager installed.

If so, then clone the repo

```bash
git clone https://github.com/leoraclet/unycoin
cd unycoin
```

Create a virtual environment for Python if you want to add package in the future

```bash
uv venv
```

## ❤️ Thanks

Resources that guided me :

- [The **REPO**](https://github.com/jimmysong/programmingbitcoin)
- [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)
- [Bitcoin Wiki](https://en.bitcoin.it/wiki/Main_Page)
- [This Incredible Blog Post](http://karpathy.github.io/2021/06/21/blockchain/)

*and many more hours of research ton internet to finally understand how Bitcoin works (the only **TRUE**
cyrptocurrency btw)


## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

