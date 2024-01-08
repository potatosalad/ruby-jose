source 'https://rubygems.org'

platforms :ruby do
  group :development do
    gem 'pry'
    gem 'pry-doc'
    # gem 'redcarpet'
    gem 'yard'
  end
end

group :test do
  gem "bundler"
  gem "rake"
  gem "minitest"
  gem "json"
  gem "rbnacl"
  gem "ed25519"
  gem "x25519"
  gem 'minitest-focus', require: false
  gem 'minitest-perf', require: false
  gem 'rantly', github: 'rantly-rb/rantly', ref: '9ea88a43d6437db76a0b5341a3c41c2687e18cd8', require: false
  gem 'simplecov', require: false
  if ENV['CI']
    gem 'codecov', require: false
  end
end

# Specify your gem's dependencies in jose.gemspec
gemspec
