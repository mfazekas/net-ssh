require 'rbnacl/aead/chacha20poly1305_ietf'
require 'net/ssh/authentication/ed25519_loader'

module Net; module SSH; module Transport; module Cipher
  class CachaPoly
    def initialize(name, options)
      byebug
      @name = name
      @cacha = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(options[:key])
    end

    def iv_len
      0
    end

    def auth_len
      32
    end

    def name
      @name
    end

    def block_size
      8
    end

    def update(data)
      nonce = "\0"*12
      auth = nil
      @cacha.encrypt(nonce, data, auth)
    end

    def final
      ""
    end

    def reset
      # TODO
    end

    def iv=(data)
      # TODO
    end

    def self.key_len
      64
    end

    def self.auth_len
      16
    end

    def self.block_size
      8
    end
  end
end ; end ; end ; end
