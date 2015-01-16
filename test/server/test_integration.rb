require 'common'
require 'net/ssh'
require 'net/ssh/server'
require 'net/ssh/server/keys'
require 'net/ssh/server/channel_extensions'
require 'net/ssh/transport/server_session'
require 'net/ssh/transport/session'
require 'open3'

module Server

  class TestIntegration < Test::Unit::TestCase

    def stdoptions(logprefix)
      logger = Logger.new(STDERR)
      logger.level = Logger::DEBUG
      logger.formatter = proc { |severity, datetime, progname, msg| "[#{logprefix}] #{datetime}: #{msg}\n" }
      #{logger: logger, :verbose => :debug}
      {}
    end

    def test_with_real_ssh_client
      exit_status = 42

      opts = stdoptions("SRV")

      server = TCPServer.new 0
      port,host = server.addr[1],server.addr[2]

      Thread.abort_on_exception = true

      Thread.start do |th|
        client = server.accept
        server_session = Net::SSH::Transport::ServerSession.new(client,
           {server_keys:{'ssh-rsa'=>OpenSSL::PKey::RSA.new(1024)}}.merge(opts))
        server_session.run_loop do |connection|
          connection.on_open_channel('session') do |session, channel, packet|
            channel.extend(Net::SSH::Server::ChannelExtensions)
            channel.on_request 'env' do |channel,data|
              puts ""
            end
            channel.on_request 'exec' do |channel,data,opt|
              command = data.read_string
              if opt[:want_reply]
                channel.send_reply(true)
                opt[:want_reply] = false
              end
              channel.send_data "reply #{command}\n"
              channel.send_eof_and_close
              channel.send_channel_request('exit-status',:long,42)
            end
          end
        end
      end

      sshopts = {LogLevel:'ERROR', UserKnownHostsFile:'/dev/null', StrictHostKeyChecking:'no',
        ServerAliveInterval:1000}
      sshopts_str = sshopts.map { |k,v| "-o #{k.to_s}=#{v}" }.join(' ')
      #sshopts_str += ' -vvvv'
      command = "ssh #{sshopts_str} #{host} -p #{port} 'sleep 3 ; echo hello'"
      #command = "ssh #{sshopts_str} localhost 'sleep 3 ; echo hello'"
      output, status = Open3.capture2(command)

      assert_equal "reply sleep 3 ; echo hello\n", output
      assert_equal 42, status.exitstatus
    end

    def test_with_net_ssh_client
      server = TCPServer.new 0
      port,host = server.addr[1],server.addr[2]

      Thread.abort_on_exception = true
      Thread.start do |th|
        opts = stdoptions("CLI")
        transport = Net::SSH::Transport::Session.new(host, {:port => port}.merge(opts))
        auth = Net::SSH::Authentication::Session.new(transport, opts)
        auth.authenticate('foo',nil)
        connection = Net::SSH::Connection::Session.new(transport, opts)
        connection.open_channel('client-session') do |ch|
          ch.send_channel_request('command-from-client', :string, "data-from-client")
        end
        connection.loop
        connection.close
      end

      got_command = false

      client = server.accept
      opts = stdoptions("SRV")

      server_session = Net::SSH::Transport::ServerSession.new(client,
         {server_keys:{'ssh-rsa'=>OpenSSL::PKey::RSA.new(1024)}}.merge(opts))
      server_session.run_loop do |connection|
        connection.on_open_channel('client-session') do |session, channel, packet|
          channel.on_request 'command-from-client' do |channel,data|
            got_command = true
            datastr = data.read_string
            assert_equal datastr, 'data-from-client'
            channel.close
            begin
              session.close
              connection.close
              server_session.stop
            rescue IOError
            end
          end
        end
      end
      assert_equal true,got_command
    end
  end
end
