require 'net/ssh/errors'
require 'net/ssh/prompt'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the "password" SSH authentication method.
        class Password < Abstract
          include Prompt

          # Attempt to authenticate the given user for the given service. If
          # the password parameter is nil, this will ask for password
          def authenticate(next_service, username, password=nil)
            retries = 0
            max_retries =  get_max_retries
            return false if !password && max_retries == 0

            begin
              password_to_send = password || ask_password(username)

              send_message(userauth_request(username, next_service, "password", false, password_to_send))
              message = session.next_message
              retries += 1

              if message.type == USERAUTH_FAILURE
                debug { "password failed" }

                raise Net::SSH::Authentication::DisallowedMethod unless
                  message[:authentications].split(/,/).include? 'password'
                password = nil
              end
            end until (message.type != USERAUTH_FAILURE || retries >= max_retries)

            case message.type
              when USERAUTH_SUCCESS
                debug { "password succeeded" }
                return true
              when USERAUTH_FAILURE
                return false
              when USERAUTH_PASSWD_CHANGEREQ
                debug { "password change request received, failing" }
                return false
              else
                raise Net::SSH::Exception, "unexpected reply to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
            end
          end

          def self.supports_server?
            true
          end

          def server_authenticate(username,next_service,auth_method,packet,auth_logic)
            packet.read_bool
            password = packet.read_string

            auth_logic.allow_password?(username,password,
              {:next_service => next_service,:auth_method => auth_method, :packet => packet, :method => self})
          end

          private

          NUMBER_OF_PASSWORD_PROMPTS = 3

          def ask_password(username)
            echo = false
            prompt("#{username}@#{session.transport.host}'s password:", echo)
          end

          def get_max_retries
            (session.options||{})[:number_of_password_prompts] || NUMBER_OF_PASSWORD_PROMPTS
          end
        end

      end
    end
  end
end
