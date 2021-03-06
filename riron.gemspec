# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'riron/version'

Gem::Specification.new do |spec|
  spec.name          = "riron"
  spec.version       = Riron::VERSION
  spec.authors       = ["Jan Algermissen"]
  spec.email         = ["algermissen@acm.org"]
  spec.summary       = %q{This is a Ruby implementation of iron}
  spec.description   = %q{riron is a cryptographic utility for sealing a JSON object using symmetric key encryption with message integrity verification.}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
end
