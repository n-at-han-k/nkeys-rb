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
bin/test
```

## Versioning

The gem version is `<nkeys crate version>.<our release>`:

```
nkeys-rb 0.4.5.0
         └─┬─┘ └ our release against that crate
           └ the Rust nkeys crate this wraps
```

So `nkeys-rb 0.4.5.2` is the third build of this gem against `nkeys 0.4.5`. The
crate is pinned exactly in `ext/nkeys/Cargo.toml` (`version = "=0.4.5"`) so the
claim cannot quietly become false — `bin/increment-version` moves both together.

Depend on it pessimistically to the fourth segment (`~> 0.4.5.0`) and you track
our fixes without silently moving to a new crate.

## Releasing

Consumers must never need Rust. That is the whole point: `bundle install` should
find a gem for its platform with the `.so` already inside, rather than a source
gem that shells out to `cargo`.

A release is TWO kinds of gem for the same version — the source gem (the
fallback for any platform not precompiled) and one precompiled gem per platform.
CI builds the second kind; `bin/release-gem` builds the first and pushes both.

```bash
bin/increment-version           # bump our segment: 0.4.5.0 -> 0.4.5.1
# ...or, to track a new crate release (also repins ext/nkeys/Cargo.toml):
# bin/increment-version 0.4.6   # -> 0.4.6.0
git commit -am "Bump to $(ruby -Ilib -rnkeys/version -e 'print NKeys::VERSION')"
git push origin main            # cross-compile.yml builds the platform gems
# ...wait for that run to go green...
bin/release-gem                 # downloads them, builds the source gem, pushes all
```

`bin/release-gem` refuses to run if the local version is not ahead of what is
already on RubyGems, and if the latest green CI run built a different version it
says so rather than publishing a mismatched set. It tolerates gems that are
already published, so a release that dies partway through can simply be re-run.

It needs the [GitHub CLI](https://cli.github.com) to fetch the CI artifacts.

## Testing

Specs are co-located with the code they cover, in `__END__` blocks, and run with
[scampi](https://github.com/general-intelligence-systems/scampi):

```bash
bin/test
```

`bundle exec lefthook install` wires that plus a trufflehog secret scan into a
pre-commit hook.
