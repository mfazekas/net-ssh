ENABLE_KERBEROS = true
$:.push('./lib')
$:.push(ENV['NET_SSH_KERBEROS'] || '../net-ssh-kerberos/lib/')
require 'net/ssh/kerberos'
Net::SSH.start('precise32.fazmic.com', 'fazmic', {:port => 2000, :auth_methods => ["gssapi-with-mic"],verbose: :debug}) do |ssh|
  puts ssh.exec!('hostname')
end
