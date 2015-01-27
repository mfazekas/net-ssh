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

    class AuthLogic
      def allow_password?(username,password,options)
        password == username+'pwd'
      end

      def allow_none?(username,options)
        username == 'foo'
      end
    end

    def _stdoptions(logprefix)
      logger = Logger.new(STDERR)
      logger.level = Logger::DEBUG
      logger.formatter = proc { |severity, datetime, progname, msg| "[#{logprefix}] #{datetime}: #{msg}\n" }
      #{logger: logger, :verbose => :debug}
      {}
    end

    def _net_ssh_client(host,options={})
      opts = _stdoptions("CLI")
      transport = Net::SSH::Transport::Session.new(host,options.merge(opts))
      auth = Net::SSH::Authentication::Session.new(transport, options.merge(opts))
      auth.authenticate("ssh-connection",options[:user] || 'foo',options[:password])
      connection = Net::SSH::Connection::Session.new(transport, opts)
      connection.open_channel('client-session') do |ch|
        ch.send_channel_request('command-from-client', :string, "data-from-client")
      end
      connection.loop
      connection.close
    end

    def _ssh_async_reply_server(options,&block)
      Thread.abort_on_exception = true
      server = TCPServer.new 0
      port,host = server.addr[1],server.addr[2]
      Thread.start do |th|
        client = server.accept
        server_session = Net::SSH::Transport::ServerSession.new(client,
           {server_keys:{'ssh-rsa'=>OpenSSL::PKey::RSA.new(1024)},
            kex:['diffie-hellman-group-exchange-sha256'],
            hmac:['hmac-md5'],
            auth_logic:AuthLogic.new
           }.merge(options))
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
              reply = yield(command)
              channel.send_data reply[:string]
              channel.send_eof_and_close
              channel.send_channel_request('exit-status',:long,reply[:exit_code])
            end
          end
        end
      end
      [port,host]
    end

    def test_with_real_ssh_client
      exit_status = 42

      port,host = _ssh_async_reply_server(_stdoptions("SRV")) do |command|
        {exit_code:exit_status,string:"reply #{command}\n"}
      end

      sshopts = {LogLevel:'ERROR', UserKnownHostsFile:'/dev/null', StrictHostKeyChecking:'no',
        #MACs:'macs',
        ServerAliveInterval:1000}
      sshopts_str = sshopts.map { |k,v| "-o #{k.to_s}=#{v}" }.join(' ')
      #sshopts_str += ' -vvvv'
      command = "ssh #{sshopts_str} foo@#{host} -p #{port} 'sleep 3 ; echo hello'"
      #command = "ssh #{sshopts_str} localhost 'sleep 3 ; echo hello'"
      output, status = Open3.capture2(command)

      assert_equal "reply sleep 3 ; echo hello\n", output
      assert_equal exit_status, status.exitstatus
    end

    def test_with_net_ssh_client
      server = TCPServer.new 0
      port,host = server.addr[1],server.addr[2]

      Thread.abort_on_exception = true
      Thread.start do |th|
        _net_ssh_client(host,{:port => port})
      end

      got_command = false

      client = server.accept
      opts = _stdoptions("SRV")

      server_session = Net::SSH::Transport::ServerSession.new(client,
         {server_keys:{'ssh-rsa'=>OpenSSL::PKey::RSA.new(1024)}, auth_logic:AuthLogic.new}.merge(opts))
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

    def test_with_net_ssh_client_and_pwd
      server = TCPServer.new 0
      port,host = server.addr[1],server.addr[2]

      Thread.abort_on_exception = true
      Thread.start do |th|
        _net_ssh_client(host,{:user => 'foo', :password => 'foopwd',:auth_methods => ['password'],:number_of_password_prompts => 0, 
          :port => port,:append_supported_algorithms => false})
      end

      got_command = false

      client = server.accept
      opts = _stdoptions("SRV")

      server_session = Net::SSH::Transport::ServerSession.new(client,
         {server_keys:{'ssh-rsa'=>OpenSSL::PKey::RSA.new(1024)},auth_logic:AuthLogic.new}.merge(opts))
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
