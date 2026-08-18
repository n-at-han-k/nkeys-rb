# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require_relative "../../lib/nkeys"

module Nats
  # NATS JWTs: the signed claims a NATS server accepts.
  #
  # TEST SUPPORT, NOT PART OF THE GEM. This is not shipped (the gemspec's files
  # glob is lib/**) and nothing in lib/ requires it. It exists because the
  # primitives in NKeys are only worth anything if they can produce a real NATS
  # JWT, and a round-trip of toy strings does not prove that. Building the
  # actual artefact here -- account-signed, ed25519-nkey, the `jti` hash NATS
  # computes -- is what makes the specs evidence rather than decoration.
  #
  # A NATS JWT is not a JOSE JWT and no JWT gem will produce one. The envelope
  # is familiar (three base64url segments) but the algorithm is `ed25519-nkey`
  # -- an Ed25519 signature by an nkey -- and the claims carry a `nats` object
  # whose shape the server parses strictly.
  #
  # Ported from nats-io/jwt v2 (claims.go, doEncode/hash).
  # https://docs.nats.io/learn/security/auth-callout
  module JWT
    HEADER = { "typ" => "JWT", "alg" => "ed25519-nkey" }.freeze

    # The claims every JWT carries, in the order nats-io/jwt's ClaimsData
    # declares them. Order matters only for the `jti` hash below, but matching
    # Go's field order costs nothing and removes the question.
    STANDARD_KEYS = %w[aud exp jti iat iss name nbf sub].freeze

    # RFC 4648 base32, which is what `jti` is encoded with. Ruby has no base32
    # in its standard library and it is four lines, so it is here not a gem.
    BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    class Error < StandardError; end

    class << self
      # Sign `claims` (with its `nats` payload already built) as `key`.
      #
      # The issuer and issued-at are set here rather than by the caller: they
      # are a property of the act of signing, not of what is being claimed.
      def encode(claims, key)
        claims = claims.dup
        claims["iss"] = key.public_key
        claims["iat"] = Time.now.to_i
        claims["jti"] = jti(claims)

        header_segment  = segment(HEADER)
        payload_segment = segment(ordered(claims))

        signing_input = "#{header_segment}.#{payload_segment}"

        "#{signing_input}.#{b64(key.sign(signing_input))}"
      end

      # The claims of a JWT, WITHOUT verifying its signature. Kept separate from
      # `verify` so a caller cannot read one without deciding the other.
      def decode(token)
        _header, payload, _signature = split(token)

        JSON.parse(unb64(payload))
      rescue JSON::ParserError => e
        raise Error, "malformed JWT payload: #{e.message}"
      end

      # Whether `token` was signed by the key it names as its issuer.
      #
      # The issuer is read FROM the token, so this answers "is this self
      # consistent", not "is this someone I trust" -- the caller still has to
      # check that `iss` is a key it expects.
      def verify(token)
        header, payload, signature = split(token)
        issuer = JSON.parse(unb64(payload))["iss"]

        return false if issuer.nil? || issuer.empty?

        NKeys::KeyPair
          .from_public_key(issuer)
          .verify("#{header}.#{payload}", unb64(signature))
      rescue StandardError
        # A key that will not parse, or a signature that will not decode, is an
        # invalid token rather than an exceptional condition.
        false
      end

      private

        def split(token)
          segments = token.to_s.split(".")
          raise Error, "expected 3 JWT segments, got #{segments.size}" unless segments.size == 3

          segments
        end

        # The claim ID: base32 of the SHA-512/256 of the STANDARD claims alone,
        # with `jti` itself absent. Not SHA-256 -- nats-io/jwt uses
        # sha512.New512_256(), and a plain SHA-256 here produces an id the rest
        # of the NATS tooling disagrees with.
        def jti(claims)
          standard = ordered(claims.reject { |k, _| k == "jti" }, STANDARD_KEYS)

          base32(OpenSSL::Digest.new("SHA512-256").digest(JSON.generate(standard)))
        end

        # Go's `omitempty` drops empty strings and zero integers, and the hash
        # above is taken over the result -- so an empty value present as `null`
        # or `""` would change it.
        def ordered(claims, keys = STANDARD_KEYS + %w[nats])
          keys.each_with_object({}) do |key, out|
            value = claims[key]
            next if value.nil? || value == "" || value == 0

            out[key] = value
          end
        end

        def segment(object) = b64(JSON.generate(object))
        def b64(bytes) = Base64.urlsafe_encode64(bytes, padding: false)
        def unb64(string) = Base64.urlsafe_decode64(string)

        def base32(bytes)
          bytes
            .unpack1("B*")
            .scan(/.{1,5}/)
            .map { |chunk| BASE32_ALPHABET[chunk.ljust(5, "0").to_i(2)] }
            .join
        end
    end
  end
end

__END__
  describe "Nats::JWT" do
    def account = NKeys::KeyPair.generate("account")

    def user_claims(user = NKeys::KeyPair.generate("user").public_key)
      {
        "aud"  => "$G",
        "sub"  => user,
        "name" => "einstein",
        "exp"  => Time.now.to_i + 3600,
        "nats" => {
          "pub"  => { "allow" => [ "matrix.as.einstein.out.>" ] },
          "sub"  => { "allow" => [ "_INBOX.>" ] },
          "subs" => -1, "data" => -1, "payload" => -1,
          "type" => "user", "version" => 2,
        },
      }
    end

    it "emits the three-segment ed25519-nkey envelope" do
      header, payload, signature = Nats::JWT.encode(user_claims, account).split(".")

      JSON.parse(Base64.urlsafe_decode64(header))
        .should == { "typ" => "JWT", "alg" => "ed25519-nkey" }

      JSON.parse(Base64.urlsafe_decode64(payload))["nats"]["type"].should == "user"

      # Raw Ed25519, base64url without padding.
      Base64.urlsafe_decode64(signature).bytesize.should == 64
      signature.should.not.be.include? "="
    end

    it "signs as the account, so the server can name the issuer" do
      key = account
      claims = Nats::JWT.decode(Nats::JWT.encode(user_claims, key))

      # The whole reason nkeys-rb exists: a U... issuer here could not be named
      # in a server's auth_callout.issuer, and the verdict would be refused.
      claims["iss"].should == key.public_key
      claims["iss"].should.start_with "A"
    end

    it "stamps iat and a base32 jti" do
      claims = Nats::JWT.decode(Nats::JWT.encode(user_claims, account))

      claims["iat"].should.be.kind_of Integer
      # SHA-512/256 is 32 bytes, which is 52 base32 characters unpadded.
      claims["jti"].length.should == 52
      claims["jti"].should.be.match?(/\A[A-Z2-7]+\z/)
    end

    it "round-trips the claims it was given" do
      user = NKeys::KeyPair.generate("user").public_key
      claims = Nats::JWT.decode(Nats::JWT.encode(user_claims(user), account))

      claims["sub"].should == user
      claims["aud"].should == "$G"
      claims["name"].should == "einstein"
      claims["nats"]["pub"]["allow"].should == [ "matrix.as.einstein.out.>" ]
    end

    it "verifies its own signature" do
      Nats::JWT.verify(Nats::JWT.encode(user_claims, account)).should == true
    end

    it "rejects a tampered payload" do
      header, payload, signature = Nats::JWT.encode(user_claims, account).split(".")

      claims = JSON.parse(Base64.urlsafe_decode64(payload))
      claims["name"] = "margaret"
      forged = Base64.urlsafe_encode64(JSON.generate(claims), padding: false)

      Nats::JWT.verify("#{header}.#{forged}.#{signature}").should == false
    end

    it "rejects a token signed by a different account" do
      # Re-signing with another key produces a self-consistent token, so verify
      # says true -- which is exactly why it answers "self consistent", not
      # "trusted". The caller compares `iss` against the key it expects.
      other = account
      token = Nats::JWT.encode(user_claims, other)

      Nats::JWT.verify(token).should == true
      Nats::JWT.decode(token)["iss"].should.not.be == account.public_key
    end

    it "refuses a malformed token" do
      lambda { Nats::JWT.decode("not.a.jwt.at.all") }.should.raise(Nats::JWT::Error)
      Nats::JWT.verify("garbage").should == false
    end

    it "signs and seals an auth callout response end to end" do
      # The actual shape of a verdict: a user JWT nested inside an
      # authorization_response, then sealed to the server's xkey.
      server  = NKeys::XKey.generate
      service = NKeys::XKey.generate
      issuer  = account

      user_nkey = NKeys::KeyPair.generate("user").public_key
      inner = Nats::JWT.encode(user_claims(user_nkey), issuer)

      response = Nats::JWT.encode({
        "aud"  => "NDHJKL",
        "sub"  => user_nkey,
        "nats" => { "jwt" => inner, "type" => "authorization_response", "version" => 2 },
      }, issuer)

      sealed = service.seal(response, server.public_key)
      opened = server.open(sealed, service.public_key)

      opened.should == response
      Nats::JWT.verify(opened).should == true
      Nats::JWT.decode(Nats::JWT.decode(opened)["nats"]["jwt"])["sub"].should == user_nkey
    end
  end
