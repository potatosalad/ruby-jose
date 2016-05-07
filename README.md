# JOSE

[![Travis](https://img.shields.io/travis/potatosalad/ruby-jose.svg?maxAge=2592000)](https://travis-ci.org/potatosalad/ruby-jose) [![Gem](https://img.shields.io/gem/v/jose.svg?maxAge=2592000)](https://rubygems.org/gems/jose) [![Docs](https://img.shields.io/badge/yard-docs-blue.svg?maxAge=2592000)](http://www.rubydoc.info/gems/jose) [![Inline docs](http://inch-ci.org/github/potatosalad/ruby-jose.svg?branch=master&style=shields)](http://inch-ci.org/github/potatosalad/ruby-jose)

JSON Object Signing and Encryption (JOSE) for Ruby.

Heavily based on [erlang-jose](https://github.com/potatosalad/erlang-jose).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'jose'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install jose

## Usage

Better documentation is in progress, but here are a few resources to get started. First, a simple example of key generation and message signing:

```ruby
# Let's use our secret key "symmetric key" for use with
# the HMAC using SHA-256 (HS256) algorithm.
jwk = JOSE::JWK.from_oct('symmetric key')

# Here is the JSON format of our JWK.
jwk.to_binary
# => "{\"k\":\"c3ltbWV0cmljIGtleQ\",\"kty\":\"oct\"}"

# Now let's sign our message using HS256.
signed = jwk.sign('test', { 'alg' => 'HS256' }).compact
# => "eyJhbGciOiJIUzI1NiJ9.dGVzdA.VlZz7pJCnos0k-WUL9O9RoT9N--2kHSakNIdOg-MIro"

# We use the same key for verification.
verified, message, = jwk.verify(signed)
# => [true, "test"]
```

More details and examples:
- [Getting Started](http://www.rubydoc.info/gems/jose/file/docs/GettingStarted.md)
- [Key Generation](http://www.rubydoc.info/gems/jose/file/docs/KeyGeneration.md)
- [Encryption Algorithms](http://www.rubydoc.info/gems/jose/file/docs/EncryptionAlgorithms.md)
- [Signature Algorithms](http://www.rubydoc.info/gems/jose/file/docs/SignatureAlgorithms.md)

Finally, the [erlang-jose documentation](https://hexdocs.pm/jose/) can provide more ideas of the functionality available in this gem.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/potatosalad/ruby-jose. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MPL-2.0 License](http://opensource.org/licenses/MPL-2.0).
