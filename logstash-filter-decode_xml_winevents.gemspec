Gem::Specification.new do |s|
  s.name = 'logstash-filter-decode_xml_winevents'
  s.version         = '1.0.0'
  s.licenses = ['Apache-2.0']
  s.summary = "This filter decodes an XML Windows Event and outputs ECS"
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Shawn Hooton"]
  s.email = 'shawn.hooton@gmail.com'
  s.homepage = "https://github.com/codingogre/logstash-filter-decode_xml_winevents"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_development_dependency 'logstash-devutils'
  s.add_runtime_dependency 'nokogiri', '~> 1.12', '>= 1.12.5'
  s.add_runtime_dependency 'awrence', '~> 1.2', '>= 1.2.1'
  s.add_runtime_dependency 'nori', '~> 2.6', '>= 2.6.0'
end
