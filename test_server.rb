$:.push('./lib')
require 'net/ssh'
require 'net/ssh/server'
require 'net/ssh/server/keys'
require 'net/ssh/transport/server_session'
require 'socket'
require 'ostruct'
require 'byebug'

PORT = 2000
Thread.abort_on_exception=true


logger = Logger.new(STDERR)
logger.level = Logger::DEBUG

puts "Setting up server keys..."
server_keys = Net::SSH::Server::Keys.new(logger: logger, server_keys_directory: '.')
server_keys.load_or_generate

def send_reply(channel,result)
  msg_type = result ? Net::SSH::Connection::Constants::CHANNEL_SUCCESS : Net::SSH::Connection::Constants::CHANNEL_FAILURE
  msg = Net::SSH::Buffer.from(:byte, msg_type, :long, channel.remote_id)
  channel.connection.send_message(msg)
end

puts "Listening on port #{PORT}..."
Thread.start do
  server = TCPServer.new PORT
  header = []
  loop do
    Thread.start(server.accept) do |client|
      options = {}
      options[:logger] = logger
      options[:server_side] = true
      options[:server_keys] = server_keys.keys
      options[:host_key] = server_keys.types
      options[:kex] = ['diffie-hellman-group-exchange-sha256']
      options[:hmac] = ['hmac-md5']
      session = Net::SSH::Transport::ServerSession.new(client,options)
      session.run_loop do |connection|
        connection.on_open_channel('session') do |session, channel, packet|
          channel.on_request 'shell' do |channel,data|
            command = data.read_string
            puts "received command:#{command}"
            channel.send_data "reply to :#{command}"
          end
          channel.on_request 'exec' do |channel,data,opt|
            #channel.process
            command = data.read_string
            if opt[:want_reply]
              send_reply(channel,true)
              opt[:want_reply] = false
            end
            sleep 2
            puts "received command:#{command}"
            channel.send_data "command :#{command} reply: 42\n"
            channel.eof!
            channel._flush
            channel.send_channel_request('exit-status',:long,42)
            #channel.send_channel_request('eow@openssh.com')
            channel.close
            channel.on_eof { puts "on eof" ; channel.close }
            #channel.close
            #channel.send_channel_request('command-from-client', :string, "data-from-client")
           end
        end
      end
    end
  end
end

sleep(1)
#Net::SSH.start('localhost', 'boga', port: PORT, password: "boga", verbose: :debug) do |ssh|
#  output = ssh.exec("hostname") 
#end
sleep(160)
puts "END"

