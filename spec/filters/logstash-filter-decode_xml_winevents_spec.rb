# encoding: utf-8
require 'spec_helper'
require "logstash/filters/decode_xml_winevents"

describe LogStash::Filters::DecodeXmlWinEvents do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        decode_xml_winevents {
          field => "message"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("message")).to eq('some text')
    end
  end
end
