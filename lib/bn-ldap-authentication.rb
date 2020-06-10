# frozen_string_literal: true

module LdapAuthenticator
  LDAP_ATTRIBUTE_MAPPING = {
    'uid' => [:dn],
    'name' => [:cn, :displayName],
    'first_name' => [:givenName],
    'last_name' => [:sn],
    'email' => [:mail, :email, :userPrincipalName],
    'nickname' => [:uid, :userid, :sAMAccountName],
    'image' => [:jpegPhoto]
  }

  def send_ldap_request(user_params, provider_info)
    case provider_info[:auth_method]
    when 'anonymous'
      auth = {
          method: :anonymous
      }
    when 'user'
      auth = {
        method: :simple,
        username: provider_info[:uid] + '=' + user_params[:username] + ',' + provider_info[:base],
        password: user_params[:password]
      }
    else
      auth = {
        method: :simple,
        username: provider_info[:bind_dn],
        password: provider_info[:password]
      }
    end
    ldap = Net::LDAP.new(
      host: provider_info[:host],
      port: provider_info[:port],
      auth: auth,
      encryption: provider_info[:encryption]
    )

    ldap_filter = Net::LDAP::Filter.eq(provider_info[:uid], user_params[:username])
    if provider_info[:filter].present?
      ldap_filter = ldap_filter & Net::LDAP::Filter.construct(provider_info[:filter])
    end

    ldap.bind_as(
      base: provider_info[:base],
      filter: ldap_filter,
      password: user_params[:password]
    )
  end

  def parse_auth(result, role_field, mapping)
    use_attribute_mapping(mapping)

    auth = {}
    auth['info'] = {}
    auth['provider'] = :ldap

    LDAP_ATTRIBUTE_MAPPING.each do |key, value|
      value.each do |v|
        next unless result[v].first

        if key == "uid"
          auth[key] = result[v].first
          break
        else 
          auth['info'][key] = result[v].first
          break
        end
      end
    end

    auth['info']['roles'] = result[role_field].first

    auth
  end

  private

  def use_attribute_mapping(mapping)
    return if mapping.blank?

    # Split the different mappings into an array
    mapping = mapping.split(";")

    # Loop through all pairs (name=test) and split them apart
    mapping.each do |pair|
      key_val = pair.split("=")

      # Skip this attribute if value isn't set up correctly
      next if key_val[1].blank?
      
      # Make the attribute the preferred option by prepending it to the attribute mapping array if it exists 
      LDAP_ATTRIBUTE_MAPPING[key_val[0]].prepend(key_val[1].to_sym) if LDAP_ATTRIBUTE_MAPPING[key_val[0]].present?
    end
  end
end
