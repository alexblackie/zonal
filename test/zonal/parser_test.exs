defmodule Zonal.ParserTest do
  use ExUnit.Case, async: true

  alias Zonal.Parser

  @fixture_a_request <<170, 170, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108,
                       101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>

  @fixture_a_www_request <<241, 64, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120,
                           97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>

  @fixture_a_request_with_extra_data <<144, 21, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 5, 109, 111, 105,
                                       115, 116, 4, 122, 111, 110, 101, 0, 0, 1, 0, 1, 0, 0, 41,
                                       16, 0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 224, 86, 93, 252,
                                       195, 43, 54, 223>>

  test "parse/1 with a valid A record request" do
    packet = Parser.parse(@fixture_a_request)

    assert packet.query_count == 1
    assert packet.domain_name == "example"
    assert packet.tld_name == "com"
    assert Enum.empty?(packet.resources)
    assert packet.query_or_resource == 0
  end

  test "parse/1 with subdomains" do
    packet = Parser.parse(@fixture_a_www_request)

    assert packet.query_count == 1
    assert packet.subdomains == ["www"]
    assert packet.domain_name == "example"
    assert packet.tld_name == "com"
  end

  test "parse/1 with a valid A record request with extra data" do
    Parser.parse(@fixture_a_request_with_extra_data)
  end
end
