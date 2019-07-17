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

    def parse_auth(result, role_field)
        auth = {}
        auth['info'] = {}
        auth['uid'] = result.dn
        auth['provider'] = :ldap

        LDAP_ATTRIBUTE_MAPPING.each do |key, value|
            value.each do |v|
                if result[v].first
                    auth['info'][key] = result[v].first
                    break
                end
            end
        end

        auth['info']['roles'] = result[role_field].first

        auth
    end
end
