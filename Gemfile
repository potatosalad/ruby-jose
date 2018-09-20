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
  gem 'minitest-focus', require: false
  gem 'minitest-perf', require: false
  gem 'rantly', github: 'abargnesi/rantly', ref: '2875f63bfc695d270ecb574c56d1a7d8f6af0153', require: false
  gem 'simplecov', require: false
  if ENV['CI']
    gem 'coveralls', require: false
  end
end

# Specify your gem's dependencies in jose.gemspec
gemspec
