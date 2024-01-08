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
  gem 'rantly', github: 'abargnesi/rantly', ref: '8ba1d908659c1cf2a08487b2a4e758a6197a0802', require: false
  gem 'simplecov', require: false
  if ENV['CI']
    gem 'coveralls', require: false
  end
end

# Specify your gem's dependencies in jose.gemspec
gemspec
