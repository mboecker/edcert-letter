[![Build Status](https://travis-ci.org/zombiemuffin/edcert.svg?branch=master)](https://travis-ci.org/zombiemuffin/edcert)

Hi and welcome on the git page of my crate "edcert".

Edcert is a simple library for certification and authentication of data.

# How Edcert it works

1. You create a master keypair. This will be used to sign the highest certificate.
2. You create a root certificate. Sign this with the master key.
3. You can now create other certificates and use certificates to sign each other.
4. Transmit your certificates in a json-encoded format over the network.
5. Sign and verify data with the certificates using the ".sign" and ".verify" methods.

The design uses the "super-secure, super-fast" elliptic curve [Ed25519],
which you can learn more about here

For cryptography it uses the [sodiumoxide] library, which is based on [NaCl],
the well known cryptography libraray by Dan Bernstein et al.

# How Letter<T> works

You can use Letter with a Ed25519 Keypair directly:

```rust
// You generate a ed25519 keypair
let (public_key, private_key) = ed25519::generate_keypair();

// Sign the letter with the private key
let test_str = "hello world";
let mut letter = Letter::with_private_key(test_str, &private_key);

// Now you can transport the letter and validate it using the public key.
assert_eq!(true, letter.is_valid(&public_key).is_ok());
letter.content = "world hello";
assert_eq!(false, letter.is_valid(&public_key).is_ok());
```

Or you can use Edcert Certificates:

```rust
// (let meta = ..., let expires = ...)
let (public_key, private_key) = ed25519::generate_keypair();
let mut cert = Certificate::generate_random(meta, expires);
cert.sign_with_master(&private_key);

let test_str = "hello world";
let mut letter = Letter::with_certificate(test_str, &cert);

assert_eq!(true, letter.is_valid(&public_key).is_ok());
letter.content = "world hello";
assert_eq!(false, letter.is_valid(&public_key).is_ok());
```

# License

MIT

That means you can use this code in open source projects and/or commercial
projects without any problems. Please read the license file "LICENSE" for
details

[Ed25519]: https://ed25519.cr.yp.to/
[sodiumoxide]: http://dnaq.github.io/sodiumoxide/sodiumoxide/index.html
[NaCl]: https://nacl.cr.yp.to/
