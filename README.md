![Logstash Image](https://www.nicepng.com/png/detail/36-363052_easily-import-logstash-errors-into-airbrake-elastic-logstash.png)

# Decode XML Windows Events (Logstash Plugin)

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Documentation

This plugin will decode Windows Events that are formatted as XML.  The output of the filter will conform to the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html).

The plugin only takes one parameter:  field.  This points to the field in the Logstash event that contains the Windows Event

e.g.
```sh
input {
###
}

filter {
  decode_xml_winevents {
    field => "xmlstring"
  }
}

output {
  stdout { }
}
````


**IMPORTANT**: Since the output will conform to ECS the message field in the Logstash event is copied to event.original and the original Windows Event message is located in winlog.message.
- Download plugin
```sh
wget https://github.com/codingogre/logstash-filter-decode_xml_winevents/blob/main/logstash-filter-decode_xml_winevents-1.0.0.gem
```
- Install plugin
```sh
# Logstash 2.3 and higher
cd to where logstash is installed
bin/logstash-plugin install --no-verify /path/to/logstash-filter-decode_xml_winevents-1.0.0.gem
```
- Restart Logstash
```sh
systemctl restart logstash.service # or whatever system initialization your OS uses
```
- Test filter in Logstash pipeline
```sh
export LOGSTASH_HOME=#whereever you installed Logstash
export FILTER_HOME=#whereever the git repo is

cp $FILTER_HOME/samples/windows_event.xml /tmp && $LOGSTASH_HOME/bin/logstash -f $FILTER_HOME/samples/logstash-sample.conf
```

- Test filter with field configuration in Logstash pipeline
```sh
export LOGSTASH_HOME=#whereever you installed Logstash
export FILTER_HOME=#whereever the git repo is

cp $FILTER_HOME/samples/windows_event_field.xml /tmp && $LOGSTASH_HOME/bin/logstash -f $FILTER_HOME/samples/logstash-sample-field.conf
```
