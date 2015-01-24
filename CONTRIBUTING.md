
## TODO this is work in progress

## Testing net-ssh

Net-ssh is used by capistrano, chef, puppet and vagrant which means indirectly hundreds of thousands of people are potentially affected by changes in net-ssh.
This document aims to describe testing ```net-ssh``` with those products.

### Capistrano

If you invoke capistrano with ```bundle exec cap``` then you'll be able to override the ```net-ssh``` gem in your ```Gemfile```.

To run capistrano with your local modifications  use the following syntax in your ```Gemfile```:
```ruby
gem 'net-ssh', :path => '/path/to/your/net-ssh
```

To run capistrano with a branch on github:
```ruby
gem 'net-ssh', :github => 'mfazekas/net-ssh', :branch => 'my-nice-branch'
```

For more information see [bundler](http://bundler.io)
