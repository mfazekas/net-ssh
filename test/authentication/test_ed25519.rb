require 'common'
require 'net/ssh/authentication/ed25519'
require 'base64'

module Authentication

  class TestED25519 < Test::Unit::TestCase
    def test_file_read
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key_no_pwd.split(' ')[1]))
      type = pub.read_string
      pub_data = pub.read_string
      priv = private_key_no_pwd

      pub_key = ED25519::PubKey.new(pub_data)
      priv_key = ED25519::PrivKey.new(priv,nil)

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true,pub_key.ssh_do_verify(signed,shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
    end

    def private_key_no_pwd
      @anonymous_key = <<-EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQAAAKjlHzLo5R8y
6AAAAAtzc2gtZWQyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQ
AAAEBPrD+n4901Y+NYJ2sry+EWRdltGFhMISvp91TywJ//mTB2NBh4GJPPUN1kXPMu8b63
3Xcv55WoKC3OkBjFAbzJAAAAIHZhZ3JhbnRAdmFncmFudC11YnVudHUtdHJ1c3R5LTY0AQ
IDBAU=
-----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def public_key_no_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB2NBh4GJPPUN1kXPMu8b633Xcv55WoKC3OkBjFAbzJ vagrant@vagrant-ubuntu-trusty-64'
    end
  end

end