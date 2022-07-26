# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'json'
require 'nokogiri'
require 'nori'
require 'awrence'


class LogStash::Filters::DecodeXmlWinEvents < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   decode_xml_winevents {
  #     field => "My field..."
  #   }
  # }
  #
  config_name "decode_xml_winevents"

  # Set the field to decode
  config :field, :validate => :string, :default => "message",  :required => false

  AUDITFAILURE = 0x10000000000000
  AUDITSUCCESS = 0x20000000000000

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    # Grab the field from the Logstash event
    @logger.info? && @logger.info("field is defined as: #{@field}")
    xml = event.get("[#{@field}]")
    @logger.info? && @logger.info("field value is: #{xml}")

    #    xml = <<XML
    #<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2022-07-14T11:02:25.754432400Z'/><EventRecordID>1237241223</EventRecordID><Correlation/><Execution ProcessID='900' ThreadID='6408'/><Channel>Security</Channel><Computer>amw-int-dc02.int.pg.com</Computer><Security/></System><EventData><SubjectUserSid Name='SubjectUserSid'>S-1-0-0</SubjectUserSid><SubjectUserName Name='SubjectUserName'>-</SubjectUserName><SubjectDomainName Name='SubjectDomainName'>-</SubjectDomainName><SubjectLogonId Name='SubjectLogonId'>0x0</SubjectLogonId><TargetUserSid Name='TargetUserSid'>S-1-0-0</TargetUserSid><TargetUserName Name='TargetUserName'>_questaadm</TargetUserName><TargetDomainName Name='TargetDomainName'>INT</TargetDomainName><Status Name='Status'>0xc000006e</Status><FailureReason Name='FailureReason'>%%2313</FailureReason><SubStatus Name='SubStatus'>0xc000006e</SubStatus><LogonType Name='LogonType'>3</LogonType><LogonProcessName Name='LogonProcessName'>NtLmSsp </LogonProcessName><AuthenticationPackageName Name='AuthenticationPackageName'>NTLM</AuthenticationPackageName><WorkstationName Name='WorkstationName'>AMW-INTACTRLS01</WorkstationName><TransmittedServices Name='TransmittedServices'>-</TransmittedServices><LmPackageName Name='LmPackageName'>-</LmPackageName><KeyLength Name='KeyLength'>0</KeyLength><ProcessId Name='ProcessId'>0x0</ProcessId><ProcessName Name='ProcessName'>-</ProcessName><IpAddress Name='IpAddress'>137.181.32.164</IpAddress><IpPort Name='IpPort'>51394</IpPort></EventData><RenderingInfo Culture='en-US'><Message>An account failed to log on.    Subject:  	Security ID:		S-1-0-0  	Account Name:		-  	Account Domain:		-  	Logon ID:		0x0    Logon Type:			3    Account For Which Logon Failed:  	Security ID:		S-1-0-0  	Account Name:		_questaadm  	Account Domain:		INT    Failure Information:  	Failure Reason:		Unknown user name or bad password.  	Status:			0xC000006E  	Sub Status:		0xC000006E    Process Information:  	Caller Process ID:	0x0  	Caller Process Name:	-    Network Information:  	Workstation Name:	AMW-INTACTRLS01  	Source Network Address:	137.181.32.164  	Source Port:		51394    Detailed Authentication Information:  	Logon Process:		NtLmSsp   	Authentication Package:	NTLM  	Transited Services:	-  	Package Name (NTLM only):	-  	Key Length:		0    This event is generated when a logon request fails. It is generated on the computer where access was attempted.    The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.    The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).    The Process Information fields indicate which account and process on the system requested the logon.    The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.    The authentication information fields provide detailed information about this specific logon request.  	- Transited services indicate which intermediate services have participated in this logon request.  	- Package name indicates which sub-protocol was used among the NTLM protocols.  	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.</Message><Level>Information</Level><Task>Logon</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Failure</Keyword></Keywords></RenderingInfo></Event>
    #XML

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
      if (node.keys.length > 0)
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
    if (doc_hash[:winlog][:keywords].hex & AUDITFAILURE > 0)
      doc_hash[:event][:outcome] = "failure"
    elsif (doc_hash[:winlog][:keywords].hex & AUDITSUCCESS > 0)
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
