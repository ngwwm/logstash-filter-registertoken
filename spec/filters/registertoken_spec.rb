# encoding: utf-8
require 'spec_helper'
require "logstash/filters/registertoken"

describe LogStash::Filters::RegisterToken do
  describe "Generate Token for Registration" do
    let(:config) do <<-CONFIG
      filter {
        registertoken {
          payload => { sid: "PERP0I1", userhost: "CORP\HAHO-ERP-125", osuser: "HHT093", dbuser: "HHT093", module: "null" }
          secret => "my$ecretK3y"
          alg => "HS256"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("token")).to eq('ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKemFXUWlPaUpRUlZKUU1Fa3hJaXdpZFhObGNtaHZjM1FpT2lKRFQxSlFTRUZJVHkxRlVsQXRNVEkxSWl3aWIzTjFjMlZ5SWpvaVNFaFVNRGt6SWl3aVpHSjFjMlZ5SWpvaVNFaFVNRGt6SWl3aWJXOWtkV3hsSWpvaWJuVnNiQ0o5LlR2Qm5jUWttVjRYSGdqanpVOXVrelE4ZjhlTEg0OUFnMWE1RkdDVlRXalU=')
    end
  end
end
