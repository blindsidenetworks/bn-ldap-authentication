lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.name          = "bn-ldap-authentication"
  gem.version       = "0.1.2"
  gem.authors       = ["shawn-higgins1"]
  gem.email         = ["23224097+shawn-higgins1@users.noreply.github.com"]

  gem.summary       = "An ruby gem for authenticating users with ldap"
  gem.description   = "A ruby gem for using ldap to authenticate greenlight users"

  gem.files = 'git ls-files'.split("\n")

  gem.require_paths = ["lib"]

  gem.add_runtime_dependency 'net-ldap'
end
