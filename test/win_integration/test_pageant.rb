require_relative '../common'
require 'net/ssh/authentication/agent'

module Authentication

  class TestPageapnt < NetSSHTest
    def with_pagent
      pageant_path = 'C:\ProgramData\chocolatey\lib\putty.portable\tools\pageant.exe'
      raise "No pageant found at:#{pageant_path}" unless File.executable?(pageant_path)
      pageant_pid = Process.spawn(pageant_path)
      puts "pageant started from: #{pageant_path} pid: #{pageant_pid}!!!"
      system('tasklist')
      sleep 30
      system('tasklist')
      yield
    ensure
      Process.kill(9, pageant_pid)
    end

    def test_agent_should_be_able_to_negotiate_with_pagent
      with_pagent do
        begin
          agent.negotiate!
        rescue
          puts "=> Test failing connect now!.... :#{$!}"
          sleep 1800
          raise
        end
      end
    end

    def test_agent_should_raise_without_pagent
      assert_raises Net::SSH::Authentication::AgentNotAvailable do
        agent.negotiate!
      end
    end

    private

      def agent(auto=:connect)
        @agent ||= begin
          agent = Net::SSH::Authentication::Agent.new
          agent.connect! if auto == :connect
          agent
        end
      end

  end

end
