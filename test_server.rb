$:.push('./lib')
require 'net/ssh'
require 'socket'
require 'ostruct'
require 'byebug'

PORT = 2000
Thread.abort_on_exception=true

module Net ; module SSH ; module Transport

# Negotiates the SSH protocol version and trades information about server
# and client. This is never used directly--it is always called by the
# transport layer as part of the initialization process of the transport
# layer.
#
# Note that this class also encapsulates the negotiated version, and acts as
# the authoritative reference for any queries regarding the version in effect.
class ClientVersion
  include Loggable

  # The SSH version string as reported by Net::SSH
  PROTO_VERSION = "SSH-2.0-Ruby/Net::SSH_#{Net::SSH::Version::CURRENT} #{RUBY_PLATFORM}"

  # Any header text sent by the server prior to sending the version.
  attr_reader :header

  # The version string reported by the server.
  attr_reader :version

  # Instantiates a new ServerVersion and immediately (and synchronously)
  # negotiates the SSH protocol in effect, using the given socket.
  def initialize(socket, logger)
    @header = ""
    @version = nil
    @logger = logger
    negotiate!(socket)
  end

  private

    # Negotiates the SSH protocol to use, via the given socket. If the server
    # reports an incompatible SSH version (e.g., SSH1), this will raise an
    # exception.
    def negotiate!(socket)
      info { "negotiating protocol version" }

      debug { "local is `#{PROTO_VERSION}'" }
      socket.write "#{PROTO_VERSION}\r\n"
      socket.flush

      loop do
        @version = ""
        loop do
          begin
            b = socket.readpartial(1)
            raise Net::SSH::Disconnect, "connection closed by remote host" if b.nil?
          rescue EOFError
            raise Net::SSH::Disconnect, "connection closed by remote host"
          end
          @version << b
          break if b == "\n"
        end
        break if @version.match(/^SSH-/)
        @header << @version
      end

      @version.chomp!
      debug { "remote is `#{@version}'" }

      unless @version.match(/^SSH-(1\.99|2\.0)-/)
        raise Net::SSH::Exception, "incompatible SSH version `#{@version}'"
      end
    end
end
  

class ServerSession
  include Constants, Loggable
  include Net::SSH::Authentication::Constants
  include Net::SSH::Connection::Constants

  # The standard port for the SSH protocol.
  DEFAULT_PORT = 22

  # The host to connect to, as given to the constructor.
  attr_reader :host

  # The port number to connect to, as given in the options to the constructor.
  # If no port number was given, this will default to DEFAULT_PORT.
  attr_reader :port

  # The underlying socket object being used to communicate with the remote
  # host.
  attr_reader :socket

  # The ServerVersion instance that encapsulates the negotiated protocol
  # version.
  attr_reader :server_version

  # The Algorithms instance used to perform key exchanges.
  attr_reader :algorithms

  # The host-key verifier object used to verify host keys, to ensure that
  # the connection is not being spoofed.
  attr_reader :host_key_verifier

  # The hash of options that were given to the object at initialization.
  attr_reader :options

  # Instantiates a new transport layer abstraction. This will block until
  # the initial key exchange completes, leaving you with a ready-to-use
  # transport session.
  def initialize(socket, options={})
    self.logger = options[:logger]

    @host = Socket.gethostname
    @port = options[:port] || DEFAULT_PORT
    @bind_address = options[:bind_address] || nil
    @options = options

    @socket = socket
    @socket.extend(PacketStream)
    @socket.logger = @logger

    debug { "connection established" }

    @queue = []

    @host_key_verifier = select_host_key_verifier(options[:paranoid])
    @server_version = timeout(options[:timeout] || 0) { ClientVersion.new(socket, logger) }

    @algorithms = Algorithms.new(self, options)
    @algorithms.send(:send_kexinit)
    debug { "send_kexinit done" }
    wait { algorithms.initialized? }
    debug { "server algorithms.initialized?" }
  end

  # Returns the host (and possibly IP address) in a format compatible with
  # SSH known-host files.
  def host_as_string
    @host_as_string ||= begin
      string = "#{host}"
      string = "[#{string}]:#{port}" if port != DEFAULT_PORT

      peer_ip = socket.peer_ip

      if peer_ip != Net::SSH::Transport::PacketStream::PROXY_COMMAND_HOST_IP &&
         peer_ip != host
        string2 = peer_ip
        string2 = "[#{string2}]:#{port}" if port != DEFAULT_PORT
        string << "," << string2
      end

      string
    end
  end

  # Returns true if the underlying socket has been closed.
  def closed?
    socket.closed?
  end

  def run_loop
    loop do
      if @connection
        @connection.process
      else
        packet = poll_message(:block)
        case packet.type
        when SERVICE_REQUEST
          packet_str = packet.read_string
          case packet_str
          when "ssh-userauth"
            send_message(Buffer.from(:byte, SERVICE_ACCEPT))
          end
        when USERAUTH_REQUEST
          username = packet.read_string
          next_service = packet.read_string
          auth_method = packet.read_string
          send_message(Buffer.from(:byte,USERAUTH_SUCCESS))
          @connection = Connection::Session.new(self, options)
          @connection.on_open_channel('session') do |session, channel, packet|
            channel.on_request 'exec' do |channel,data|
              command = data.read_string
              puts "received command:#{command}"
              channel.send_data "reply to :#{command}"
            end
          end
          @connection.process
        end
      end
    end
  end

  # Cleans up (see PacketStream#cleanup) and closes the underlying socket.
  def close
    socket.cleanup
    socket.close
  end

  # Performs a "hard" shutdown of the connection. In general, this should
  # never be done, but it might be necessary (in a rescue clause, for instance,
  # when the connection needs to close but you don't know the status of the
  # underlying protocol's state).
  def shutdown!
    error { "forcing connection closed" }
    socket.close
  end

  # Returns a new service_request packet for the given service name, ready
  # for sending to the server.
  def service_request(service)
    Net::SSH::Buffer.from(:byte, SERVICE_REQUEST, :string, service)
  end

  # Requests a rekey operation, and blocks until the operation completes.
  # If a rekey is already pending, this returns immediately, having no
  # effect.
  def rekey!
    if !algorithms.pending?
      algorithms.rekey!
      wait { algorithms.initialized? }
    end
  end

  # Returns immediately if a rekey is already in process. Otherwise, if a
  # rekey is needed (as indicated by the socket, see PacketStream#if_needs_rekey?)
  # one is performed, causing this method to block until it completes.
  def rekey_as_needed
    return if algorithms.pending?
    socket.if_needs_rekey? { rekey! }
  end

  # Returns a hash of information about the peer (remote) side of the socket,
  # including :ip, :port, :host, and :canonized (see #host_as_string).
  def peer
    @peer ||= { :ip => socket.peer_ip, :port => @port.to_i, :host => @host, :canonized => host_as_string }
  end

  # Blocks until a new packet is available to be read, and returns that
  # packet. See #poll_message.
  def next_message
    poll_message(:block)
  end

  # Tries to read the next packet from the socket. If mode is :nonblock (the
  # default), this will not block and will return nil if there are no packets
  # waiting to be read. Otherwise, this will block until a packet is
  # available. Note that some packet types (DISCONNECT, IGNORE, UNIMPLEMENTED,
  # DEBUG, and KEXINIT) are handled silently by this method, and will never
  # be returned.
  #
  # If a key-exchange is in process and a disallowed packet type is
  # received, it will be enqueued and otherwise ignored. When a key-exchange
  # is not in process, and consume_queue is true, packets will be first
  # read from the queue before the socket is queried.
  def poll_message(mode=:nonblock, consume_queue=true)
    loop do
      if consume_queue && @queue.any? && algorithms.allow?(@queue.first)
        return @queue.shift
      end

      packet = socket.next_packet(mode)
      return nil if packet.nil?

      case packet.type
      when DISCONNECT
        raise Net::SSH::Disconnect, "disconnected: #{packet[:description]} (#{packet[:reason_code]})"

      when IGNORE
        debug { "IGNORE packet recieved: #{packet[:data].inspect}" }

      when UNIMPLEMENTED
        lwarn { "UNIMPLEMENTED: #{packet[:number]}" }

      when DEBUG
        send(packet[:always_display] ? :fatal : :debug) { packet[:message] }

      when KEXINIT
        algorithms.accept_kexinit(packet)

      else
        return packet if algorithms.allow?(packet)
        push(packet)
      end
    end
  end

  # Waits (blocks) until the given block returns true. If no block is given,
  # this just waits long enough to see if there are any pending packets. Any
  # packets read are enqueued (see #push).
  def wait
    loop do
      break if block_given? && yield
      message = poll_message(:nonblock, false)
      push(message) if message
      break if !block_given?
    end
  end

  # Adds the given packet to the packet queue. If the queue is non-empty,
  # #poll_message will return packets from the queue in the order they
  # were received.
  def push(packet)
    @queue.push(packet)
  end

  # Sends the given message via the packet stream, blocking until the
  # entire message has been sent.
  def send_message(message)
    socket.send_packet(message)
  end

  # Enqueues the given message, such that it will be sent at the earliest
  # opportunity. This does not block, but returns immediately.
  def enqueue_message(message)
    socket.enqueue_packet(message)
  end

  # Configure's the packet stream's client state with the given set of
  # options. This is typically used to define the cipher, compression, and
  # hmac algorithms to use when sending packets to the server.
  def configure_client(options={})
    socket.client.set(options)
  end

  # Configure's the packet stream's server state with the given set of
  # options. This is typically used to define the cipher, compression, and
  # hmac algorithms to use when reading packets from the server.
  def configure_server(options={})
    socket.server.set(options)
  end

  # Sets a new hint for the packet stream, which the packet stream may use
  # to change its behavior. (See PacketStream#hints).
  def hint(which, value=true)
    socket.hints[which] = value
  end

  public

    # this method is primarily for use in tests
    attr_reader :queue #:nodoc:

  private

    # Instantiates a new host-key verification class, based on the value of
    # the parameter. When true or nil, the default Lenient verifier is
    # returned. If it is false, the Null verifier is returned, and if it is
    # :very, the Strict verifier is returned. If it is :secure, the even more
    # strict Secure verifier is returned. If the argument happens to respond
    # to :verify, it is returned directly. Otherwise, an exception
    # is raised.
    def select_host_key_verifier(paranoid)
      case paranoid
      when true, nil then
        Net::SSH::Verifiers::Lenient.new
      when false then
        Net::SSH::Verifiers::Null.new
      when :very then
        Net::SSH::Verifiers::Strict.new
      when :secure then
        Net::SSH::Verifiers::Secure.new
      else
        if paranoid.respond_to?(:verify)
          paranoid
        else
          raise ArgumentError, "argument to :paranoid is not valid: #{paranoid.inspect}"
        end
      end
    end
end

end ; end ; end

Thread.start do
  server = TCPServer.new PORT
  header = []
  loop do
    Thread.start(server.accept) do |client|
      options = {}
      if !options.key?(:logger)
        options[:logger] = Logger.new(STDERR)
        options[:logger].level = Logger::DEBUG
      end
      options[:server_side] = true
      session = Net::SSH::Transport::ServerSession.new(client,options)
      session.run_loop
    end
  end
end

sleep(1)
Net::SSH.start('localhost', 'boga', port: PORT, password: "boga", verbose: :debug) do |ssh|
  output = ssh.exec("hostname") 
end
sleep(20)
puts "END"

