$:.push('./lib')
require 'net/ssh'
require 'net/ssh/server'
require 'net/ssh/server/keys'
require 'net/ssh/transport/server_session'
require 'net/ssh/server/channel_extensions'
require 'socket'
require 'ostruct'
require 'byebug'

PORT = 2000
Thread.abort_on_exception=true

logger = Logger.new(STDERR)
logger.level = Logger::DEBUG
logger.level = Logger::WARN

puts "Setting up server keys..."
server_keys = Net::SSH::Server::Keys.new(logger: logger, server_keys_directory: '.')
server_keys.load_or_generate

puts "Listening on port #{PORT}..."

class AuthLogic
  def allow_password?(username,password,options)
    password == username+'pwd'
  end

  def allow_none?(username,options)
    username == 'foo'
  end
end


class FwdConnection
  module FwdChannelExtensions
    def fwd_channel
      @fwd_channel
    end
    def fwd_channel=(value)
      @fwd_channel=value
    end
  end

  def initialize(host,options)
    @host = host
    @options = options
    logger = Logger.new(STDERR)
    logger.level = Logger::DEBUG
    logger.level = Logger::WARN
    logger.formatter = proc { |severity, datetime, progname, msg| "[FWD] #{datetime}: #{msg}\n" }
    options[:logger] = logger
  end
  def connect
    @transport = Net::SSH::Transport::Session.new(@host, @options)
    @transport.socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    @auth = Net::SSH::Authentication::Session.new(@transport, @options)
  end

  def _init_connection
    @fwd_conn = Net::SSH::Connection::Session.new(@transport, @options)
  end

  def allow_password?(username,password,options)
    if @auth.authenticate(options[:next_service], username, password) 
      _init_connection
    end
  end

  def allow_none?(username,options)
    false
  end

  def _supported_requests
    ['shell','exec','pty-req','env']
  end

  def _fwd_channel(channel)
    result = channel.fwd_channel
    while result.nil? do
      timeout = nil
      @fwd_conn.process(timeout)
      result = channel.fwd_channel
    end
    return result
  end

  def _handle_channel(channel)
    _supported_requests.each do |request_type|
      channel.on_request request_type do |channel,data,options|
        _fwd_channel(channel).on_data do |fwd_channel,data|
          #puts "#{request_type}: data from server => client"
          channel.send_data(data)
        end
        channel.on_data do |channel,data|
          #puts "#{request_type}: data from client => server"
          _fwd_channel(channel).send_data(data)
        end
        if options[:want_reply]
          _fwd_channel(channel).send_channel_request(request_type,:raw,data.read) do |fwd_ch, success|
            channel.send_reply(success)
            options[:want_reply] = false
          end
        else
          _fwd_channel(channel).send_channel_request(request_type,:raw,data.read)
        end
      end
    end
  end

  def process
    @fwd_conn.process(nil) if @fwd_conn
  end

  def handle(connection)
    connection.on_open_channel('session') do |session, channel, packet|
      channel.extend(Net::SSH::Server::ChannelExtensions)
      channel.extend(FwdChannelExtensions)
      _handle_channel(channel)
      @fwd_conn.open_channel('session') do |fwd_channel|
        puts "opened channel on fwd! setting:#{fwd_channel}"
        channel.fwd_channel=fwd_channel
      end
    end
  end
end

Thread.start do
  server = TCPServer.new PORT
  header = []
  auth_logic = AuthLogic.new
  loop do
    Thread.start(server.accept) do |client|
      client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      options = {}
      options[:logger] = logger
      options[:server_side] = true
      options[:server_keys] = server_keys.keys
      options[:host_key] = server_keys.types
      options[:kex] = ['diffie-hellman-group-exchange-sha256']
      options[:hmac] = ['hmac-md5']
      options[:auth_logic] = auth_logic
      options[:listeners] = {}

      fwd_options = {}
      fwd_options[:listeners] = options[:listeners]
      fwd_host = 'localhost'

      fwd_connection = FwdConnection.new(fwd_host,fwd_options)
      options[:auth_logic] = fwd_connection
      run_loop_hook = -> { fwd_connection.process }
      fwd_connection.connect
      session = Net::SSH::Transport::ServerSession.new(client,options.merge(run_loop_hook:run_loop_hook))
      handler_added = false
      session.run_loop do |connection|
        if !handler_added
          fwd_connection.handle(connection)
          handler_added = true
        end
        fwd_connection.process
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

