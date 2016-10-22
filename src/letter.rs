// The MIT License (MIT)
//
// Copyright (c) 2016 Marvin Böcker
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::ops::Deref;

use edcert::certificate::Certificate;
use edcert::fingerprint::Fingerprint;
use edcert::signature::Signature;
use edcert::validator::Validatable;
use edcert::validator::Validator;
use edcert::validator::ValidationError;
use edcert::revoker::RevokeError;
use edcert::revoker::Revoker;
use edcert::revoker::Revokable;

/// Use this type to sign content.
#[derive(PartialEq, Debug)]
pub struct Letter<T: Fingerprint> {
    content: T,
    signature: Signature,
}

impl<T: Fingerprint> Letter<T> {
    /// This method creates a Letter from its parts: A piece of content (which must be
    /// convertable to a &[u8] (must implement AsRef<[u8]>)) and a Signature.
    pub fn new(content: T, signature: Signature) -> Letter<T> {
        Letter {
            content: content,
            signature: signature,
        }
    }

    /// This method creates a Letter by signing itself with the given private key
    pub fn with_private_key(content: T, private_key: &[u8]) -> Letter<T> {
        use edcert::ed25519;
        let signature = Signature::new(ed25519::sign(&content.fingerprint(), private_key));
        Letter::new(content, signature)
    }

    /// This method creates a Letter by signing itself with the given certificate. The certificate
    /// must have a private key.
    pub fn with_certificate(content: T, cert: &Certificate) -> Result<Letter<T>, ()> {
        // This next call can fail, if the given certificate has no private key.
        let res = cert.sign(&content.fingerprint());

        match res {
            Some(hash) => {
                let signature = Signature::with_parent(Box::new(cert.clone()), hash);
                Ok(Letter::new(content, signature))
            },
            None => {
                Err(())
            }
        }
    }

    /// This method returns a reference to the contained object.
    pub fn get(&self) -> &T {
        &self.content
    }
}

impl<T: Fingerprint> Validatable for Letter<T> {
    fn self_validate<V: Validator>(&self, cv: &V) -> Result<(), ValidationError> {
        let sig = &self.signature;
        let bytes = self.content.fingerprint();

        if sig.is_signed_by_master() {
            if cv.is_signature_valid(&bytes, sig.hash()) {
                Ok(())
            } else {
                Err(ValidationError::SignatureInvalid)
            }
        } else {
            let parent = sig.parent().unwrap();

            if cv.is_valid(parent).is_ok() {
                if parent.verify(&bytes, sig.hash()) {
                    Ok(())
                } else {
                    Err(ValidationError::SignatureInvalid)
                }
            } else {
                Err(ValidationError::ParentInvalid)
            }
        }
    }
}

impl<T: Fingerprint> Fingerprint for Letter<T> {
    fn fingerprint(&self) -> Vec<u8> {
        self.content.fingerprint()
    }
}

impl<T: Fingerprint> Deref for Letter<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T: Fingerprint> Revokable for Letter<T> {
    fn self_check_revoked<R: Revoker>(&self, _: &R) -> Result<(), RevokeError> {
        Ok(())
    }
}

#[test]
fn test_simple() {
    use edcert::ed25519;
    use edcert::root_validator::RootValidator;
    use edcert::revoker::NoRevoker;

    let (mpk, msk) = ed25519::generate_keypair();

    let test_str = "hello world";

    let mut letter = Letter::with_private_key(test_str, &msk);

    let cv = RootValidator::new(&mpk, NoRevoker);

    assert_eq!(true, cv.is_valid(&letter).is_ok());

    letter.content = "world hello";

    assert_eq!(false, cv.is_valid(&letter).is_ok());
}

#[test]
fn test_certificate() {
    use edcert::ed25519;
    use edcert::meta::Meta;
    use edcert::root_validator::RootValidator;
    use edcert::revoker::NoRevoker;

    use chrono::Timelike;
    use chrono::UTC;
    use chrono::Duration;

    let (mpk, msk) = ed25519::generate_keypair();

    let meta = Meta::new_empty();
    let expires = UTC::now()
                      .checked_add(Duration::days(90))
                      .expect("Failed to add a day to expiration date.")
                      .with_nanosecond(0)
                      .unwrap();

    let mut cert = Certificate::generate_random(meta, expires);

    cert.sign_with_master(&msk);

    let test_str = "hello world";

    let cv = RootValidator::new(&mpk, NoRevoker);

    let mut letter = Letter::with_certificate(test_str, &cert).expect("This fails only if the Certificate has no private key.");

    assert_eq!(true, cv.is_valid(&letter).is_ok());

    letter.content = "world hello";

    assert_eq!(false, cv.is_valid(&letter).is_ok());
}

#[test]
fn test_deref() {
    use edcert::ed25519;

    let (_, msk) = ed25519::generate_keypair();
    let test_str = "hello world";
    let letter = Letter::with_private_key(test_str, &msk);

    let deref_str: &str = *letter;
    assert_eq!(deref_str, test_str);
}
