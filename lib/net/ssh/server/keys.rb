module Net ; module SSH ; module Server
class Keys
  include Loggable

  def initialize(options = {})
    if !options.key?(:logger)
      options[:logger] = Logger.new(STDERR)
      options[:logger].level = Logger::FATAL
    end
    self.logger = options[:logger]
    @base_path = options[:server_keys_directory] || '.'
    @keys = {}
  end

  def load_or_generate
    load || (generate && write)
  end

  def load
    if File.readable?(_path(_type))
      @keys[_type] = OpenSSL::PKey::RSA.new File.read(_path(_type))
    else
      return false
    end
  end

  def write
    File::write(_path(_type),@keys[_type])
    true
  end

  def generate
    info { " => generating keys" }
    @keys[_type] = OpenSSL::PKey::RSA.new(1024)
    info { " => keys generated" }
    true
  end

  def keys
    @keys
  end

  def types
    [_type]
  end

  private

  def _path(type)
    File.join(@base_path,"serverkey-#{_type}.pem")
  end

  def _type
    'ssh-rsa'
  end
end

end ; end ; end
