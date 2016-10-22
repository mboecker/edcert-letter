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

//! This crate contains the type Letter<T>. It is supposed to be a container for signed data.
//! You can create signed data either from a ed25519 key or using a `Certificate`.
//! 
//! For example, when you generate a ephermeral keypair, you sign your public key by creating a
//! Letter<PublicKeyType> and send that over the network. The other end can then validate the
//! Letter and knows that you own that certificate, and if the other end trusts that certificate
//! (for example, by signing your certificate with the master keypair), it knows, that the
//! sent public key is really yours.

#![deny(missing_docs)]

extern crate edcert;
extern crate chrono;

/// This module contains the Letter<T> type.
pub mod letter;
pub use letter::Letter;
