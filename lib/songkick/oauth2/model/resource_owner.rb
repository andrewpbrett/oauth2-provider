module Songkick
  module OAuth2
    module Model

      module ResourceOwner
        def self.included(klass)
          klass.has_many :oauth2_authorizations,
                         :class_name => Songkick::OAuth2::Model::Authorization.name,
                         :as => :oauth2_resource_owner,
                         :dependent => :destroy
        end

        def grant_access!(client, options = {})
          Authorization.for(self, client, options)
        end

        def oauth2_authorization_for(client)
          oauth2_authorizations.where(:client_id => client.id.to_s).first
        end
      end

    end
  end
end
