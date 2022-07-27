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
    @logger.debug? && @logger.info("field in configuration is defined as: #{@field}")
    xml = event.get("[#{@field}]")
    @logger.debug? && @logger.info("value found in field is: #{xml}")

    # Parse the Windows Event (removing namespaces)
    doc = Nokogiri::XML(xml).remove_namespaces!

    # Rename the <Event> root tag to winlog
    root = doc.xpath('/Event').first
    root.name = 'winlog'

    # Process the <Event><System> section.  The following things are done:
    # 1.) Make any XML element with an attribute e.g. <Execution ProcessID="4" ThreadID="6676" />
    # Into multiple XML Elements like <ExecutionProcessID>4</ExecutionProcessID>
    #                                 <ExecutionThreadID>4</ExecutionThreadID>
    # 2.) Move all <winlog><System> Elements under <winlog>
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

    # Process the <Event><EventData> section by taking the elements with attributes and rewriting them as elements
    # e.g. <Data Name="SubjectUserSid">S-1-5-18</Data> to <SubjectUserSid>S-1-5-18</SubjectUserSid>
    event_data = doc.xpath('/winlog/EventData/Data[@Name]')
    event_data.each do |node|
      node.swap("<#{node.attributes['Name']}>#{node.text}</#{node.attributes['Name']}>")
    end

    # Change all of the Element names to snake_case
    doc_hash = Nori.new(:convert_tags_to => lambda { |tag| tag.snakecase.to_sym }, :advanced_typecasting => false).parse(doc.to_s)
    # Make an exception for the EventData by renaming the snake_case to CamelCase
    doc_hash[:winlog][:event_data] = doc_hash[:winlog][:event_data].to_camel_keys

    # Generate required fields
    doc_hash[:event] = {:original => xml, :code => doc_hash[:winlog][:event_id], :provider => doc_hash[:winlog][:provider_name], :kind => "event"}
    if doc_hash[:winlog][:keywords].hex & AUDITFAILURE > 0
      doc_hash[:event][:outcome] = "failure"
    elsif doc_hash[:winlog][:keywords].hex & AUDITSUCCESS > 0
      doc_hash[:event][:outcome] = "success"
    end
    doc_hash[:event][:dataset] = "windows.security"
    doc_hash[:log] = {:level => doc_hash[:winlog][:rendering_info][:level].downcase}
    doc_hash[:@timestamp] = LogStash::Timestamp.parse_iso8601(doc_hash[:winlog][:time_created_system_time])
    doc_hash[:winlog][:process] = {:pid => doc_hash[:winlog][:execution_process_id], :thread => {:id => doc_hash[:winlog][:execution_thread_id]}}
    doc_hash[:winlog].merge({:message => doc_hash[:winlog][:rendering_info][:message]})
    doc_hash[:winlog][:channel] = doc_hash[:winlog][:rendering_info][:channel]
    doc_hash[:agent] = {:type => "winlogbeat"}

    # Delete fields that are no longer needed
    doc_hash[:winlog].delete(:execution_process_id)
    doc_hash[:winlog].delete(:execution_thread_id)
    doc_hash[:winlog].delete(:rendering_info)
    doc_hash[:winlog].delete(:time_created_system_time)
    doc_hash[:winlog].delete(:level)
    doc_hash[:winlog].delete(:security)
    event.remove("message")

    # Clean up our own inconsistent field names
    doc_hash[:winlog][:record_id] = doc_hash[:winlog].delete(:event_record_id)
    doc_hash[:winlog][:computer_name] = doc_hash[:winlog].delete(:computer)

    # Populate event with data from the Ruby hash
    doc_hash.keys.each do |key|
      event.set("[#{key}]", doc_hash[:"#{key}"])
    end

    filter_matched(event)
  end # def filter
end # class LogStash::Filters::DecodeXmlWinEvents
