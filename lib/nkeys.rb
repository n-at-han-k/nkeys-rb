# frozen_string_literal: true

# NATS NKeys for Ruby, over the Rust `nkeys` crate.
#
# The classes (NKeys::KeyPair, NKeys::XKey) are defined by the native
# extension's #[magnus::init]; this file only locates and requires the compiled
# object. See ext/nkeys/src/lib.rs for what each method does and why this is a
# binding rather than a pure-Ruby implementation.
#
#   account = NKeys::KeyPair.generate("account")
#   account.public_key                  # => "A..."
#   account.seed                        # => "SA..."
#   account.sign("payload")             # => raw Ed25519 signature bytes
#
#   xkey  = NKeys::XKey.generate
#   xkey.public_key                     # => "X..."
#   sealed = xkey.seal("secret", recipient_public_key)
#   xkey.open(sealed, sender_public_key)

require_relative "nkeys/version"

module NKeys
end

# Precompiled ("fat") gems ship one .so per Ruby minor version under a versioned
# subdir (lib/nkeys/3.3/nkeys_rb.so). A locally source-compiled build lands flat,
# in lib/nkeys/. Try the versioned path first, then fall back to the flat one.
begin
  RUBY_VERSION =~ /(\d+\.\d+)/
  require_relative "nkeys/#{Regexp.last_match(1)}/nkeys_rb"
rescue LoadError
  require_relative "nkeys/nkeys_rb"
end

__END__
  describe "NKeys::KeyPair" do
    it "prefixes the public key by role" do
      # The whole reason this binding exists: the pure-Ruby nkeys gem reports a
      # U... key for every role, so an account key could not be named in a
      # server's auth_callout.issuer.
      NKeys::KeyPair.generate("account").public_key.should.start_with "A"
      NKeys::KeyPair.generate("user").public_key.should.start_with "U"
      NKeys::KeyPair.generate("server").public_key.should.start_with "N"
    end

    it "rejects an unknown role" do
      lambda { NKeys::KeyPair.generate("wombat") }.should.raise(ArgumentError)
    end

    it "round-trips through its seed" do
      original = NKeys::KeyPair.generate("account")
      restored = NKeys::KeyPair.from_seed(original.seed)

      # A seed carries its own role, so the restored key keeps the A... prefix
      # without being told which role it was.
      restored.public_key.should == original.public_key
    end

    it "signs and verifies" do
      key = NKeys::KeyPair.generate("account")
      signature = key.sign("payload")

      key.verify("payload", signature).should == true
      key.verify("tampered", signature).should == false
    end

    it "verifies with a public-key-only keypair" do
      key = NKeys::KeyPair.generate("account")
      signature = key.sign("payload")

      NKeys::KeyPair.from_public_key(key.public_key).verify("payload", signature).should == true
    end

    it "cannot sign with a public-key-only keypair" do
      key = NKeys::KeyPair.from_public_key(NKeys::KeyPair.generate("account").public_key)

      lambda { key.sign("payload") }.should.raise(RuntimeError)
    end
  end

  describe "NKeys::XKey" do
    it "prefixes the public key with X" do
      NKeys::XKey.generate.public_key.should.start_with "X"
    end

    it "round-trips a sealed message between two xkeys" do
      # The shape auth callout uses: the server seals a request to the service's
      # xkey, and the service seals its response back to the server's.
      server  = NKeys::XKey.generate
      service = NKeys::XKey.generate

      sealed = server.seal("credentials", service.public_key)
      service.open(sealed, server.public_key).should == "credentials"
    end

    it "refuses to open a message sealed for someone else" do
      server    = NKeys::XKey.generate
      service   = NKeys::XKey.generate
      stranger  = NKeys::XKey.generate

      sealed = server.seal("credentials", service.public_key)

      lambda { stranger.open(sealed, server.public_key) }.should.raise(RuntimeError)
    end

    it "round-trips through its seed" do
      original = NKeys::XKey.generate
      restored = NKeys::XKey.from_seed(original.seed)

      restored.public_key.should == original.public_key
    end
  end
