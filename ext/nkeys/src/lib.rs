//! Ruby bindings for the Rust `nkeys` crate, via magnus.
//!
//! NKeys is the NATS key format: an Ed25519 keypair whose public half is
//! base32-encoded behind a prefix byte naming its role (`A...` account,
//! `U...` user, `N...` server), with a CRC-16 check, plus a separate x25519
//! "xkey" (`X...`) used for encryption rather than signing.
//!
//! WHY BIND THE RUST CRATE rather than use the pure-Ruby `nkeys` gem: that gem
//! stopped at 0.1.0 and is incomplete in two ways that matter to anything doing
//! NATS auth callout.
//!
//!   1. Its `public_key` hardcodes the USER prefix byte, so an account keypair
//!      reports a `U...` key rather than the `A...` a server config names in
//!      `auth_callout.issuer`. A verdict signed by a key the server cannot name
//!      is refused.
//!
//!   2. It has no concept of xkeys at all -- no prefix, no key type, no
//!      seal/open -- so the encrypted form of auth callout cannot be spoken.
//!
//! The API is string-centric (seeds and public keys in, base32 strings out)
//! because that is how NATS moves keys around: in config files, in credentials
//! files and in JWT claims.

use magnus::{function, method, prelude::*, Error, Ruby};

use nkeys::{KeyPair, KeyPairType, XKey as NKeysXKey};

// --- helpers ---------------------------------------------------------------

fn rt_err<E: std::fmt::Display>(e: E) -> Error {
    // Safe: every caller runs inside a Ruby method invocation (GVL held).
    let ruby = Ruby::get().expect("rt_err called outside the Ruby VM");
    Error::new(ruby.exception_runtime_error(), e.to_string())
}

fn arg_err<S: Into<String>>(message: S) -> Error {
    let ruby = Ruby::get().expect("arg_err called outside the Ruby VM");
    Error::new(ruby.exception_arg_error(), message.into())
}

/// Map a role name to its prefix byte. Accepts the same spellings NATS uses in
/// its own tooling, so a caller can pass what `nsc` would print.
fn key_pair_type(role: &str) -> Result<KeyPairType, Error> {
    match role {
        "account" => Ok(KeyPairType::Account),
        "user" => Ok(KeyPairType::User),
        "server" => Ok(KeyPairType::Server),
        "operator" => Ok(KeyPairType::Operator),
        "cluster" => Ok(KeyPairType::Cluster),
        other => Err(arg_err(format!(
            "unknown key role {other:?}: expected account, user, server, operator or cluster"
        ))),
    }
}

// --- KeyPair ---------------------------------------------------------------

/// An Ed25519 NATS keypair, of any role.
#[magnus::wrap(class = "NKeys::KeyPair", free_immediately, size)]
struct RKeyPair(KeyPair);

impl RKeyPair {
    /// A fresh keypair. `role` picks the prefix byte, and so what the public key
    /// looks like: "account" -> `A...`, "user" -> `U...`, "server" -> `N...`.
    fn generate(role: String) -> Result<Self, Error> {
        Ok(RKeyPair(KeyPair::new(key_pair_type(&role)?)))
    }

    /// Restore from an `S...` seed. A seed encodes its own role, so the public
    /// key comes back with the right prefix without being told which it is.
    fn from_seed(seed: String) -> Result<Self, Error> {
        KeyPair::from_seed(&seed).map(RKeyPair).map_err(rt_err)
    }

    /// A VERIFY-ONLY keypair from a public key. `sign` and `seed` on one of
    /// these raise, because there is no private half to use.
    fn from_public_key(public_key: String) -> Result<Self, Error> {
        KeyPair::from_public_key(&public_key)
            .map(RKeyPair)
            .map_err(rt_err)
    }

    /// The public half, prefixed by role.
    fn public_key(&self) -> String {
        self.0.public_key()
    }

    /// The seed -- the whole private key, and the thing that belongs in a
    /// secret rather than a config file. Raises for a verify-only keypair.
    fn seed(&self) -> Result<String, Error> {
        self.0.seed().map_err(rt_err)
    }

    /// Raw Ed25519 signature bytes over `input`.
    ///
    /// Deliberately NOT base64: callers need different encodings of the same
    /// signature (a JWT wants base64url without padding, a CONNECT nonce wants
    /// standard base64), so the encoding is theirs to choose.
    fn sign(&self, input: String) -> Result<Vec<u8>, Error> {
        self.0.sign(input.as_bytes()).map_err(rt_err)
    }

    /// Whether `sig` is a valid signature over `input`. A bad signature is
    /// `false` rather than an exception -- it is an expected answer, not a fault.
    fn verify(&self, input: String, sig: Vec<u8>) -> bool {
        self.0.verify(input.as_bytes(), &sig).is_ok()
    }
}

// --- XKey ------------------------------------------------------------------

/// An x25519 NATS xkey: the curve keypair used to ENCRYPT rather than sign.
#[magnus::wrap(class = "NKeys::XKey", free_immediately, size)]
struct RXKey(NKeysXKey);

impl RXKey {
    fn generate() -> Self {
        RXKey(NKeysXKey::new())
    }

    fn from_seed(seed: String) -> Result<Self, Error> {
        NKeysXKey::from_seed(&seed).map(RXKey).map_err(rt_err)
    }

    /// A seal-only xkey from a public key, for encrypting to someone else.
    fn from_public_key(public_key: String) -> Result<Self, Error> {
        NKeysXKey::from_public_key(&public_key)
            .map(RXKey)
            .map_err(rt_err)
    }

    /// The public half -- an `X...` key.
    fn public_key(&self) -> String {
        self.0.public_key()
    }

    fn seed(&self) -> Result<String, Error> {
        self.0.seed().map_err(rt_err)
    }

    /// Encrypt `input` to `recipient` (an `X...` public key).
    ///
    /// The crate wants an `XKey` for the counterparty; the Ruby side passes the
    /// public key as a STRING, because that is the form NATS moves keys in --
    /// out of a config file, or off the `xkey` field of an auth callout
    /// request. Parsing it here keeps that conversion out of every caller.
    fn seal(&self, input: Vec<u8>, recipient: String) -> Result<Vec<u8>, Error> {
        let recipient = NKeysXKey::from_public_key(&recipient).map_err(rt_err)?;

        self.0.seal(&input, &recipient).map_err(rt_err)
    }

    /// Decrypt `input` from `sender` (an `X...` public key).
    fn open(&self, input: Vec<u8>, sender: String) -> Result<Vec<u8>, Error> {
        let sender = NKeysXKey::from_public_key(&sender).map_err(rt_err)?;

        self.0.open(&input, &sender).map_err(rt_err)
    }
}

// --- init ------------------------------------------------------------------

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let namespace = ruby.define_module("NKeys")?;

    let keypair = namespace.define_class("KeyPair", ruby.class_object())?;
    keypair.define_singleton_method("generate", function!(RKeyPair::generate, 1))?;
    keypair.define_singleton_method("from_seed", function!(RKeyPair::from_seed, 1))?;
    keypair.define_singleton_method("from_public_key", function!(RKeyPair::from_public_key, 1))?;
    keypair.define_method("public_key", method!(RKeyPair::public_key, 0))?;
    keypair.define_method("seed", method!(RKeyPair::seed, 0))?;
    keypair.define_method("sign", method!(RKeyPair::sign, 1))?;
    keypair.define_method("verify", method!(RKeyPair::verify, 2))?;

    let xkey = namespace.define_class("XKey", ruby.class_object())?;
    xkey.define_singleton_method("generate", function!(RXKey::generate, 0))?;
    xkey.define_singleton_method("from_seed", function!(RXKey::from_seed, 1))?;
    xkey.define_singleton_method("from_public_key", function!(RXKey::from_public_key, 1))?;
    xkey.define_method("public_key", method!(RXKey::public_key, 0))?;
    xkey.define_method("seed", method!(RXKey::seed, 0))?;
    xkey.define_method("seal", method!(RXKey::seal, 2))?;
    xkey.define_method("open", method!(RXKey::open, 2))?;

    Ok(())
}
