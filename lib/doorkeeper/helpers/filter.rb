module Doorkeeper
  module Helpers
    module Filter
      module ClassMethods
        def doorkeeper_for(*args)
          doorkeeper_for = DoorkeeperForBuilder.create_doorkeeper_for(*args)

          before_filter doorkeeper_for.filter_options do
            if doorkeeper_token.nil? or doorkeeper_token.empty?
              # This header settings needed in both steps
              headers['Access-Control-Allow-Origin'] = '*'
              headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
              headers['Access-Control-Max-Age'] = '1000'
              headers['Access-Control-Allow-Headers'] = '*, accept, authorization'
              
              render :nothing => true
            elsif !doorkeeper_for.validate_token(doorkeeper_token)
              @error = OAuth::InvalidTokenResponse.from_access_token(doorkeeper_token)
              headers.merge!(@error.headers.reject {|k, v| ['Content-Type'].include? k })
              
              render_options = doorkeeper_unauthorized_render_options

              if render_options.nil? || render_options.empty?
                head :unauthorized
              else
                render_options[:status] = :unauthorized
                render_options[:layout] = false if render_options[:layout].nil?
                render render_options
              end
            else
              # default render
            end
          end
        end
      end

      def self.included(base)
        base.extend ClassMethods
        base.send :private, :doorkeeper_token, :doorkeeper_unauthorized_render_options
      end

      def doorkeeper_token
        return @token if instance_variable_defined?(:@token)
        methods = Doorkeeper.configuration.access_token_methods
        @token = OAuth::Token.authenticate request, *methods
      end

      def doorkeeper_unauthorized_render_options
        nil
      end
    end
  end
end
