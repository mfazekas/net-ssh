require 'net/ssh/errors'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex/diffie_hellman_group1_sha1'

module Net::SSH::Transport::Kex

  # A key-exchange service implementing the
  # "diffie-hellman-group-exchange-sha1" key-exchange algorithm.
  class DiffieHellmanGroupExchangeSHA1 < DiffieHellmanGroup1SHA1
    MINIMUM_BITS      = 1024
    MAXIMUM_BITS      = 8192

    KEXDH_GEX_GROUP   = 31
    KEXDH_GEX_INIT    = 32
    KEXDH_GEX_REPLY   = 33
    KEXDH_GEX_REQUEST = 34

    private

      # Compute the number of bits needed for the given number of bytes.
      def compute_need_bits

        # for Compatibility: OpenSSH requires (need_bits * 2 + 1) length of parameter
        need_bits = data[:need_bytes] * 8 * 2 + 1

        if need_bits < MINIMUM_BITS
          need_bits = MINIMUM_BITS
        elsif need_bits > MAXIMUM_BITS
          need_bits = MAXIMUM_BITS
        end

        data[:need_bits ] = need_bits
        data[:need_bytes] = need_bits / 8
      end

      def read_and_handle_get_request
        buffer = connection.next_message
        if buffer.type == KEXDH_GEX_REQUEST
          min_bits = buffer.read_long
          need_bits = buffer.read_long
          max_bits = buffer.read_long
          @data[:min_bits] = min_bits
          @data[:max_bits] = max_bits
          min_bits = [min_bits,MINIMUM_BITS].max
          max_bits = [max_bits,MAXIMUM_BITS].min
          need_bits = [min_bits,need_bits].max
          need_bits = [max_bits,need_bits].min
          @data[:need_bits] = need_bits

          #priv_key = OpenSSL::PKey::RSA.new(need_bits)
          dh = OpenSSL::PKey::DH.new(need_bits)
          buffer = Net::SSH::Buffer.from(:byte,KEXDH_GEX_GROUP, :bignum, dh.p ,:bignum, dh.g)
          connection.send_message(buffer)
          return dh
        else
          raise Net::SSH::Exception, "expected KEXDH_GEX_REQUEST, got #{buffer.type}"
        end
      end


      # Returns the DH key parameters for the given session.
      def get_parameters
        compute_need_bits

        # request the DH key parameters for the given number of bits.
        buffer = Net::SSH::Buffer.from(:byte, KEXDH_GEX_REQUEST, :long, MINIMUM_BITS,
          :long, data[:need_bits], :long, MAXIMUM_BITS)
        connection.send_message(buffer)

        buffer = connection.next_message
        unless buffer.type == KEXDH_GEX_GROUP
          raise Net::SSH::Exception, "expected KEXDH_GEX_GROUP, got #{buffer.type}"
        end

        p = buffer.read_bignum
        g = buffer.read_bignum

        [p, g]
      end

      # Returns the INIT/REPLY constants used by this algorithm.
      def get_message_types
        [KEXDH_GEX_INIT, KEXDH_GEX_REPLY]
      end

      # Build the signature buffer to use when verifying a signature from
      # the server.
      def build_signature_buffer(result)
        response = Net::SSH::Buffer.new

        if data[:server_side]
          response.write_string data[:client_version_string],
                              data[:server_version_string],
                              data[:server_algorithm_packet],
                              data[:client_algorithm_packet],
                              result[:key_blob]
          response.write_long data[:min_bits],
                              data[:need_bits],
                              data[:max_bits]
          response.write_bignum dh.p, dh.g, result[:client_pubkey],
                              result[:server_dh_pubkey],
                              result[:shared_secret]
        else
          response.write_string data[:client_version_string],
                              data[:server_version_string],
                              data[:client_algorithm_packet],
                              data[:server_algorithm_packet],
                              result[:key_blob]
          response.write_long MINIMUM_BITS,
                            data[:need_bits],
                            MAXIMUM_BITS
          response.write_bignum dh.p, dh.g, dh.pub_key,
                              result[:server_dh_pubkey],
                              result[:shared_secret]
        end
        response
      end
  end

end
