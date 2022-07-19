# encoding: utf-8
require 'spec_helper'
require "logstash/filters/decode_xml_winevents"

describe LogStash::Filters::DecodeXmlWinEvents do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        decode_xml_winevents {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("message")).to eq('Hello World')
    end
  end
end
