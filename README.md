# Unycoin

![License](https://img.shields.io/github/license/leoraclet/unycoin)

This project aims to be a pure python implementation of a cryptocurrency similar to Bitcoin as it
was first introduced by Satoshi Nakamoto's whitepaper :
[Bitcoin: A Peer-to-Peer Electronic Cash System](https://bitcoin.org/bitcoin.pdf).

![](shared/misc/bitcoin-ethereum.jpeg)

## Summary

* **[Disclaimer](#disclaimer)**
  * **[Security](#security)**
  * **[Efficiency](#efficiency)**
* **[Description](#description)**
  * **[What about this project ?](#what-about-this-project)**
  * **[How it works](#how-it-works)**
  * **[Why python ?](#why-python-)**
* **[Structure](#structure)**
  * **[Cryptography](#cryptography)**
  * **[Database](#database)**
  * **[Ledger](#ledger)**
  * **[Network](#network)**
  * **[Virtual Machine](#virtual-machine)**
  * **[Wallet](#wallet)**
* **[Contribute](#contribute)**
* **[Releases](#releases)**
* **[License](#license)**
* **[Credits](#credits)**

## Disclaimer

- This implementation is made for educational purposes only.
Do **NOT** use this program in a real world scenario as it is considered
insecure in regard of today's security standards.
- **DON'T RULE YOUR OWN CRYPTO** : 
The main reason I implemented this cryptographic primitives from scratch
is to understand how they are made and how they work. If you want secure
cryptographic protocols, you should use already existing libraries that
have been reviewed for years by many experts and the community.

### Security

All cryptographic protocols and functions implemented in this
project follows all rules specified in their description.
**ECDSA** is protected against side-channel attack by using
the Montgomery Ladder as the algorithm for point multiplications
over Elliptic Curves.

### Efficiency

As this software is written in pure python, every cryptographic protocol
implemented here is rather inefficient compared to the same one in another language like C++.
However, when it comes to more usual tasks like networks, python is good enough.

## Description

### What about this project
### How it works
### Why python ?

I choosed python as the programming language for this project for the two following reasons :

- **Simplicity** ~ Python is a programming language that is easy to use and more importantly, easy to read and to understand.

- **Originality** ~ Most of today's cyptocurrencies are built in C/C++ for better performances and enhanced security.

## Structure

### Cryptography

This module implements all cryptographic protocols and primitives that are necessary
to ensure cryptocurrency's security and integrity. All protocols were implemented from
scratch in pure python based on their official description. 
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

### Database
This module aims to store the blockchain and all according data into a structured database using Sqlite3.
### Ledger
### Network
### Wallet

## License

This project is released under the 
[**MIT**](https://mit-license.org/)
license.

## Releases

To run the program without editing the source code or building
it yourself, go see the 
[**Releases**](https://github.com/leoraclet/cpp_skeleton/releases).

## Credits

* [**Léo Raclet**](https://github.com/leoraclet) : Creator of the project.
