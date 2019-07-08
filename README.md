# bn-ldap-authentication

This gem allows you to authenticate users using ldap

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'bn-ldap-authentication'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install bn-ldap-authentication

## Usage

To use the gem pass a hash containing the users user_id and password to the send_ldap_request method allow with the
ldap server configuration parameters. The send_ldap_request method will then return the user's information
