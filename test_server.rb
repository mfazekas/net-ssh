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

server_keys = Net::SSH::Server::Keys.new(logger: logger, server_keys_directory: '.')
server_keys.load_or_generate

key_sizes = [1024]
server_dhs = Hash[key_sizes.map {|i| [i,OpenSSL::PKey::DH.new(i)]}]

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
      options[:server_dh] = server_dhs
      session = Net::SSH::Transport::ServerSession.new(client,options)
      session.run_loop do |connection|
        connection.on_open_channel('session') do |session, channel, packet|
          channel.on_request 'shell' do |channel,data|
            command = data.read_string
            puts "received command:#{command}"
            channel.send_data "reply to :#{command}"
          end
          channel.on_request 'exec' do |channel,data|
            command = data.read_string
            puts "received command:#{command}"
            channel.send_data "reply to :#{command}"
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

