# frozen_string_literal: true

module LdapAuthenticator
    LDAP_ATTRIBUTE_MAPPING = {
        'name' => [:cn],
        'first_name' => [:givenName],
        'last_name' => [:sn],
        'email' => [:mail, :email, :userPrincipalName],
        'nickname' => [:uid, :userid, :sAMAccountName],
        'image' => [:jpegPhoto]
    }

    def send_ldap_request(user_params, provider_info)
        ldap = Net::LDAP.new(
            host: provider_info[:host],
            port: provider_info[:port],
            auth: {
                method: :simple,
                username: provider_info[:bind_dn],
                password: provider_info[:password]
            },
            encryption: provider_info[:encryption]
        )

        ldap.bind_as(
            base: provider_info[:base],
            filter: "(#{provider_info[:uid]}=#{user_params[:username]})",
            password: user_params[:password]
        )
    end
end
