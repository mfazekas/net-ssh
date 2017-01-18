$:.push('./lib')
#gem 'net-ssh', '= 3.0.2'
require 'net/ssh'
require 'byebug'
puts Net::SSH::Version::CURRENT

# sh ssh boga@localhost -vvvvv -c chacha20-poly1305@openssh.com

@host = 'localhost'
@user = ENV['USER']
ssh = Net::SSH.start(@host, @user, encryption: ['chacha20-poly1305@openssh.com'], kex: ['diffie-hellman-group-exchange-sha256'], verbose: :debug)
ssh.exec!('ls -la') do |ch,success|
  puts "OK:#{success}"
end
ssh.close

# ssh boga@localhost -vvvvv -c chacha20-poly1305@openssh.com -o KexAlgorithms=curve25519-sha256@libssh.org
# ssh boga@localhost -vvvvv -c chacha20-poly1305@openssh.com -o KexAlgorithms=diffie-hellman-group-exchange-sha256
