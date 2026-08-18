# nkeys-rb

Ruby bindings for the Rust [`nkeys`](https://crates.io/crates/nkeys) crate.

NKeys is the NATS key format: an Ed25519 keypair whose public half is
base32-encoded behind a prefix byte naming its role (`A...` account, `U...`
user, `N...` server), with a CRC-16 check — plus a separate x25519 "xkey"
(`X...`) used for encryption rather than signing.

## Why this exists

There is already an `nkeys` gem on rubygems.org. It stopped at 0.1.0 and is
incomplete in two ways that matter to anything implementing NATS
[auth callout](https://docs.nats.io/learn/security/auth-callout):

1. Its `public_key` hardcodes the **user** prefix byte, so an account keypair
   reports a `U...` key rather than the `A...` a server config names in
   `auth_callout.issuer`. A verdict signed by a key the server cannot name is
   refused.
2. It has no concept of **xkeys** at all — no prefix, no key type, no
   seal/open — so the encrypted form of auth callout cannot be spoken.

Hence the name: `nkeys-rb`, because `nkeys` is taken.

This gem is only the key primitives. Building the NATS JWTs an auth callout
answers with is ordinary Ruby work (JSON, base64url, `SHA512-256`, base32) and
deliberately lives in the caller.

## Usage

```ruby
require "nkeys"

account = NKeys::KeyPair.generate("account")
account.public_key            # => "A..."  — goes in the server config
account.seed                  # => "SA..." — goes in a secret

signature = account.sign("payload")
account.verify("payload", signature)   # => true

# Verify-only, from a public key alone.
NKeys::KeyPair.from_public_key(account.public_key).verify("payload", signature)

# xkeys encrypt rather than sign.
service = NKeys::XKey.generate
server  = NKeys::XKey.generate

sealed = server.seal("credentials", service.public_key)
service.open(sealed, server.public_key)   # => "credentials"
```

Roles accepted by `KeyPair.generate`: `account`, `user`, `server`, `operator`,
`cluster`.

## Development

The repository ships a `flake.nix` with Ruby, the Rust toolchain and the
libclang that `rb_sys`' bindgen needs:

```bash
direnv allow          # or: nix develop
bundle install
bundle exec rake compile
bundle exec rake test
```

## Releasing

Consumers must never need Rust. That is the whole point of the release process:
`bundle install` should find a gem for its platform with the `.so` already
inside, rather than a source gem that shells out to `cargo`.

1. Bump `NKeys::VERSION` in `lib/nkeys/version.rb`, commit, tag and push:

   ```bash
   git tag v0.1.0 && git push origin main --tags
   ```

2. Run the **Release** workflow (`.github/workflows/release.yml`) with that tag.
   It cross-compiles one gem per platform via `oxidize-rb/actions/cross-gem`,
   builds the source gem, and pushes them all to RubyGems.org.

Publishing uses RubyGems **trusted publishing** (OIDC) rather than an API key,
so there is no long-lived credential in repository secrets. Configure the
trusted publisher once, on the gem's RubyGems.org settings page, before the
first release — pointing it at this repository and the `release.yml` workflow.

The `ruby` platform in the matrix is the **source** gem. It is the fallback for
any platform not cross-compiled, and the only build that needs cargo on the
installing machine, so it is published alongside the others rather than instead
of them.

`.github/workflows/cross-compile.yml` builds the same matrix on every push to
`main` without publishing, so a break in the cross toolchain surfaces before a
release rather than during one.
