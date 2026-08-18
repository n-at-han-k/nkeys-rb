# frozen_string_literal: true

require_relative "lib/nkeys/version"

Gem::Specification.new do |spec|
  spec.name = "nkeys-rb"
  spec.version = NKeys::VERSION
  spec.authors = ["Nathan Kidd"]
  spec.email = ["nathankidd@hey.com"]
  spec.license = "Apache-2.0"

  spec.summary = "Ruby bindings for the Rust nkeys crate."
  spec.description = "NATS NKeys for Ruby, as a native extension over the Rust `nkeys` crate: " \
    "Ed25519 keypairs across every key role, and the x25519 XKey sealing used by " \
    "NATS auth callout. Named nkeys-rb because the plain `nkeys` gem name is taken " \
    "by an unrelated pure-Ruby implementation."
  spec.homepage = "https://git.kremlin.email/n-at-han-k/nkeys-rb"

  spec.required_ruby_version = ">= 3.3"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{rs,rb,toml}",
    "Cargo.toml",
    "Cargo.lock",
    "LICENSE",
    "README.md"
  ]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/nkeys/extconf.rb"]

  spec.add_dependency "rb_sys", "~> 0.9"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
end
