module Net ; module SSH ; module Server
  module ChannelExtensions

    def send_eof_and_close
      eof!
      _flush
      close
    end

    def send_reply(result)
      msg_type = result ? Net::SSH::Connection::Constants::CHANNEL_SUCCESS : Net::SSH::Connection::Constants::CHANNEL_FAILURE
      msg = Net::SSH::Buffer.from(:byte, msg_type, :long, remote_id)
      connection.send_message(msg)
    end

  end
end ; end ; end