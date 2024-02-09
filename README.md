🔒 **SHA-2 implementation in C**

 [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_c-sha2&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_c-sha2)
 [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_c-sha2&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_c-sha2)
 [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_c-sha2&metric=bugs)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_c-sha2)
 [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_c-sha2&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_c-sha2)
 [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_c-sha2&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_c-sha2)
 [![NPM Downloads](https://img.shields.io/npm/dw/@exact-realty/sha2?style=flat-square)](https://npmjs.com/package/%40exact-realty/sha2)


---
### 🚀 Features

- C implementation
- JavaScript compiled from C
- No dependencies
- No `async` required
- Supports SHA-256 (and SHA-512, but that's currently not part of the NPM package)
- Can export the digest state
- Can easily work with streams

### 💻 Installation

The C library can be compiled from source using `cmake`.

To install the JavaScript package, you can use `npm` or `yarn`:

```sh
npm install @exact-realty/sha2
```

or

```sh
yarn add @exact-realty/sha2
```

### 📚 Usage

#### Decrypting Data

```javascript
import sha2 from '@exact-realty/sha2';

// Create a SHA-256 instance
const hasher = sha2();

// Update the hash with data
hasher.update(Buffer.from('Hello, world!'));

// Finalize the hash and get the result
const hashResult = hasher.finish();
// ArrayBuffer {
//  [Uint8Contents]: <31 5f 5b db 76 d0 78 c4 3b 8a c0 06 4e 4a 01 64 61 2b 1f
//    ce 77 c8 69 34 5b fc 94 c7 58 94 ed d3>,
//  byteLength: 32
// }

// Export the current state
const exportedState = hasher.exportState();
// ArrayBuffer {
//  [Uint8Contents]: <6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a 51 0e 52
//    7f 9b 05 68 8c 1f 83 d9 ab 5b e0 cd 19 00 00 00 00 00 00 00 00 00 00 00 00
//    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
//    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
//    00 00 00 00 00 00 ... 4 more bytes>,
//  byteLength: 104
// }

// Import a previously exported state
hasher.importState(exportedState);

// Scrub the hash state
hasher.scrub();

```

### 🤝 Contributing

We welcome any contributions and feedback! Please feel free to submit pull
requests, bug reports or feature requests to our GitHub repository.

### 📜 License

This project is released under the Apache 2.0 license. Check out the `LICENSE`
file for more information.
