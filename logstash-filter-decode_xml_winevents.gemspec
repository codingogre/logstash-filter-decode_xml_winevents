Gem::Specification.new do |s|
  s.name = 'logstash-filter-decode_xml_winevents'
  s.version         = '0.1.0'
  s.licenses = ['Apache License (2.0)']
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
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
  s.add_runtime_dependency "nokogiri"
  s.add_runtime_dependency "awrence"
  s.add_runtime_dependency "nori"
end
