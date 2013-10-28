module Songkick
  module OAuth2
    module Model

      class Client
        include Mongoid::Document
        field :oauth2_client_owner_type
        field :oauth2_client_owner_id, :type => Integer
        field :name   
        field :client_id
        field :client_secret_hash
        field :redirect_uri

        belongs_to :oauth2_client_owner, :polymorphic => true
        alias :owner  :oauth2_client_owner
        alias :owner= :oauth2_client_owner=

        many :authorizations, :class_name => Songkick::OAuth2::Model::Authorization.name, :dependent => :destroy
        # def authorizations
        #   Songkick::OAuth2::Model::Authorization.where(:client_id => self.id.to_s)
        # end

        validates_uniqueness_of :client_id, :name
        validates_presence_of   :name, :redirect_uri
        validate :check_format_of_redirect_uri

        # attr_accessible :name, :redirect_uri, :authorizations

        before_create :generate_credentials

        def self.create_client_id
          Songkick::OAuth2.generate_id do |client_id|
            Helpers.count(self, :client_id => client_id).zero?
          end
        end

        attr_reader :client_secret

        def client_secret=(secret)
          @client_secret = secret
          hash = BCrypt::Password.create(secret)
          hash.force_encoding('UTF-8') if hash.respond_to?(:force_encoding)
          self.client_secret_hash = hash
        end

        def valid_client_secret?(secret)
          BCrypt::Password.new(client_secret_hash) == secret
        end

      private

        def check_format_of_redirect_uri
          uri = URI.parse(redirect_uri)
          errors.add(:redirect_uri, 'must be an absolute URI') unless uri.absolute?
        rescue
          errors.add(:redirect_uri, 'must be a URI')
        end

        def generate_credentials
          self.client_id = self.class.create_client_id
          self.client_secret = Songkick::OAuth2.random_string
        end
      end

    end
  end
end

