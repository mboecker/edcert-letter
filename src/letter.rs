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

use edcert::certificate::Certificate;
use edcert::signature::Signature;
use edcert::certificate_validator::Validatable;

/// Use this type to sign content.
pub struct Letter<T: AsRef<[u8]>> {
    content: T,
    signature: Signature
}

impl<T: AsRef<[u8]>> Letter<T> {

    /// This method creates a Letter from its parts: A piece of content (which must be
    /// convertable to a &[u8] (must implement AsRef<[u8]>)) and a Signature.
    pub fn new(content: T, signature: Signature) -> Letter<T> {
        Letter {
            content: content,
            signature: signature
        }
    }

    /// This method creates a Letter by signing itself with the given private key
    pub fn with_private_key(content: T, private_key: &[u8]) -> Letter<T> {
        use edcert::ed25519;
        let signature = Signature::new(ed25519::sign(content.as_ref(), &private_key));
        Letter::new(content, signature)
    }

    /// This method creates a Letter by signing itself with the given certificate. The certificate
    /// must have a private key.
    pub fn with_certificate(content: T, cert: &Certificate) -> Letter<T> {
        let hash = cert.sign(content.as_ref()).expect("Failed to sign content. Maybe private key missing?");
        let signature = Signature::with_parent(Box::new(cert.clone()), hash);
        Letter::new(content, signature)
    }

    pub fn get(&self) -> &T {
        &self.content
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.content
    }
}

impl<T: AsRef<[u8]>> Validatable for Letter<T> {
    fn is_valid(&self, mpk: &[u8]) -> Result<(), &'static str> {
        let sig = &self.signature;
        let bytes = self.content.as_ref();

        if sig.is_signed_by_master() {
            use edcert::ed25519;

            let res = ed25519::verify(&bytes, sig.hash(), mpk);

            match res {
                true => Ok(()),
                false => Err("Master signature invalid")
            }
        } else {
            let parent = sig.parent().unwrap();

            if parent.is_valid(mpk).is_ok() {
                if parent.verify(bytes, sig.hash()) {
                    Ok(())
                }
                else
                {
                    Err("Invalid signature")
                }
            }
            else
            {
                Err("My parent isn't valid.")
            }
        }
    }

    fn is_revokable(&self) -> bool {
        false
    }

    fn get_id(&self) -> String {
        panic!();
    }
}

#[test]
fn test_simple() {
    use edcert::ed25519;

    let (mpk, msk) = ed25519::generate_keypair();

    let test_str = "hello world";

    let mut letter = Letter::with_private_key(test_str, &msk);

    assert_eq!(true, letter.is_valid(&mpk).is_ok());

    letter.content = "world hello";

    assert_eq!(false, letter.is_valid(&mpk).is_ok());
}

#[test]
fn test_certificate() {
    use edcert::ed25519;
    use edcert::meta::Meta;

    use chrono::Timelike;
    use chrono::UTC;
    use time::Duration;

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

    let mut letter = Letter::with_certificate(test_str, &cert);

    assert_eq!(true, letter.is_valid(&mpk).is_ok());

    letter.content = "world hello";

    assert_eq!(false, letter.is_valid(&mpk).is_ok());
}
