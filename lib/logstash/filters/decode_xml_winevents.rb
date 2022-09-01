# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'json'
require 'nokogiri'
require 'nori'
require 'awrence'


class LogStash::Filters::DecodeXmlWinEvents < LogStash::Filters::Base
  config_name "decode_xml_winevents"

  # Set the field to decode
  config :field, :validate => :string, :default => "message",  :required => false

  AUDITFAILURE = 0x10000000000000
  AUDITSUCCESS = 0x20000000000000

  public
  def register
  end # def register

  public
  def filter(event)
    # Grab the field from the Logstash event
    @logger.debug? && @logger.debug("field in configuration is defined as: #{@field}")
    xml = event.get("[#{@field}]")
    @logger.debug? && @logger.debug("value found in field is: #{xml}")


    # Parse the Windows Event (removing namespaces)
    start = Time.now
    doc = Nokogiri::XML(xml).remove_namespaces!
    finish = Time.now
    @logger.info? && @logger.info("Time took to parse Windows event: #{finish - start}")

    # Grab a reference to the root element
    root = doc.xpath('/Event').first
    root.name = 'winlog'

    # Process the <Event><System> section.  The following things are done:
    # 1.) Make any XML element with an attribute e.g. <Execution ProcessID="4" ThreadID="6676" />
    # Into multiple XML Elements like <ExecutionProcessID>4</ExecutionProcessID>
    #                                 <ExecutionThreadID>4</ExecutionThreadID>
    # 2.) Move all <winlog><System> Elements under <winlog>
    start = Time.now
    system_data = doc.xpath('/winlog/System')
    system_data.children.each do |node|
      if node.keys.length > 0
        node.keys.each do |key|
          root.add_child("<#{node.name}#{key}>#{node.attributes[key]}</#{node.name}#{key}>")
        end
        node.remove
        next
      end
      root.add_child(node)
    end
    system_data.remove
    finish = Time.now
    @logger.info? && @logger.info("Time took to process <Event><System>: #{finish - start}")

    # Process the <Event><EventData> section by taking the elements with attributes and rewriting them as elements
    # e.g. <Data Name="SubjectUserSid">S-1-5-18</Data> to <SubjectUserSid>S-1-5-18</SubjectUserSid>
    start = Time.now
    event_data = doc.xpath('/winlog/EventData/*[@Name]')
    event_data.each do |node|
      node.swap("<#{node.attributes['Name']}>#{node.content}</#{node.attributes['Name']}>")
    end
    finish = Time.now
    @logger.info? && @logger.info("Time took to process <Event><EventData>: #{finish - start}")

    start = Time.now
    # Change all of the Element names to snake_case and convert to Ruby hash
    doc_hash = Nori.new(:convert_tags_to => lambda { |tag| tag.snakecase.to_sym }, :advanced_typecasting => false).parse(doc.to_s)
    finish = Time.now
    @logger.info? && @logger.info("Time took to go from XML -> Ruby hash: #{finish - start}")

    # Make an exception for the EventData by renaming the snake_case to CamelCase
    # hash.deep_transform_keys(&:underscore)
    start = Time.now
    if doc_hash[:winlog][:event_data]
      doc_hash[:winlog][:event_data] = doc_hash[:winlog][:event_data].to_camel_keys
    else
      @logger.warn? && @logger.warn("\nNo event data found for: #{xml}\n")
    end
    finish = Time.now
    @logger.info? && @logger.info("Time took to go from snake_case to CamelCase: #{finish - start}")

    start = Time.now
    # Generate required ECS fields
    doc_hash[:event] = {:original => xml, :code => doc_hash[:winlog][:event_id], :provider => doc_hash[:winlog][:provider_name], :kind => "event"}
    if doc_hash[:winlog][:keywords].hex & AUDITFAILURE > 0
      doc_hash[:event][:outcome] = "failure"
    elsif doc_hash[:winlog][:keywords].hex & AUDITSUCCESS > 0
      doc_hash[:event][:outcome] = "success"
    end
    doc_hash[:event][:dataset] = "windows.security"

    if doc_hash[:winlog][:rendering_info]
      doc_hash[:winlog][:message] = doc_hash[:winlog][:rendering_info][:message]
      level = doc_hash[:winlog][:rendering_info][:level].downcase
    else
      level = 'information'
    end
    doc_hash[:log] = {:level => level}
    doc_hash[:@timestamp] = LogStash::Timestamp.parse_iso8601(doc_hash[:winlog][:time_created_system_time])
    doc_hash[:host] = { :name => doc_hash[:winlog][:computer]}
    doc_hash[:host][:os] = {:family => 'windows', :platform => 'windows', :type => 'windows' }

    # Generate Winlogbeat fields
    doc_hash[:winlog][:process] = {:pid => doc_hash[:winlog][:execution_process_id], :thread => {:id => doc_hash[:winlog][:execution_thread_id]}}
    doc_hash[:agent] = {:type => "winlogbeat"}

    # Delete fields that are no longer needed
    doc_hash[:winlog].delete(:execution_process_id)
    doc_hash[:winlog].delete(:execution_thread_id)
    doc_hash[:winlog].delete(:rendering_info)
    doc_hash[:winlog].delete(:time_created_system_time)
    doc_hash[:winlog].delete(:level)
    doc_hash[:winlog].delete(:security)
    event.remove("[#{@field}]")

    # Clean up our own inconsistent Winlogbeat field names
    doc_hash[:winlog][:record_id] = doc_hash[:winlog].delete(:event_record_id)
    doc_hash[:winlog][:computer_name] = doc_hash[:winlog].delete(:computer)
    finish = Time.now
    @logger.info? && @logger.info("Time took to xform to ECS fields: #{finish - start}")

    # Populate event with data from the Ruby hash
    start = Time.now
    doc_hash.keys.each do |key|
      event.set("[#{key}]", doc_hash[:"#{key}"])
    end
    finish = Time.now
    @logger.info? && @logger.info("Time took to populate Logstash Event: #{finish - start}")

    filter_matched(event)
  end # def filter
end # class LogStash::Filters::DecodeXmlWinEvents
