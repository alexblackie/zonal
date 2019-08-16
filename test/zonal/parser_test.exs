defmodule Zonal.ParserTest do
  use ExUnit.Case, async: true

  alias Zonal.{Parser, Resource}

  @fixture_a_request <<170, 170, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108,
                       101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>

  @fixture_a_www_request <<241, 64, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120,
                           97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>

  @fixture_a_request_with_extra_data <<144, 21, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 5, 109, 111, 105,
                                       115, 116, 4, 122, 111, 110, 101, 0, 0, 1, 0, 1, 0, 0, 41,
                                       16, 0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 224, 86, 93, 252,
                                       195, 43, 54, 223>>

  @fixture_a_response_multiple <<47, 101, 129, 128, 0, 1, 0, 4, 0, 0, 0, 1, 11, 97, 108, 101, 120,
                                 98, 108, 97, 99, 107, 105, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1,
                                 192, 12, 0, 1, 0, 1, 0, 0, 0, 19, 0, 4, 99, 86, 58, 13, 192, 12,
                                 0, 1, 0, 1, 0, 0, 0, 19, 0, 4, 99, 86, 58, 32, 192, 12, 0, 1, 0,
                                 1, 0, 0, 0, 19, 0, 4, 99, 86, 58, 65, 192, 12, 0, 1, 0, 1, 0, 0,
                                 0, 19, 0, 4, 99, 86, 58, 92, 0, 0, 41, 5, 172, 0, 0, 0, 0, 0, 0>>

  @fixture_mx_heavy_compression <<157, 167, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 11, 97, 108, 101,
                                  120, 98, 108, 97, 99, 107, 105, 101, 3, 99, 111, 109, 0, 0, 15,
                                  0, 1, 192, 12, 0, 15, 0, 1, 0, 0, 1, 23, 0, 24, 0, 10, 4, 97,
                                  108, 116, 52, 5, 97, 115, 112, 109, 120, 1, 108, 6, 103, 111,
                                  111, 103, 108, 101, 192, 24, 192, 12, 0, 15, 0, 1, 0, 0, 1, 23,
                                  0, 4, 0, 1, 192, 52, 192, 12, 0, 15, 0, 1, 0, 0, 1, 23, 0, 9, 0,
                                  5, 4, 97, 108, 116, 49, 192, 52, 192, 12, 0, 15, 0, 1, 0, 0, 1,
                                  23, 0, 9, 0, 5, 4, 97, 108, 116, 50, 192, 52, 192, 12, 0, 15, 0,
                                  1, 0, 0, 1, 23, 0, 9, 0, 10, 4, 97, 108, 116, 51, 192, 52, 0, 0,
                                  41, 5, 172, 0, 0, 0, 0, 0, 0>>

  @fixture_soa_response <<8, 88, 129, 128, 0, 1, 0, 1, 0, 0, 0, 1, 11, 97, 108, 101, 120, 98, 108,
                          97, 99, 107, 105, 101, 3, 99, 111, 109, 0, 0, 6, 0, 1, 192, 12, 0, 6, 0,
                          1, 0, 0, 3, 132, 0, 72, 6, 110, 115, 45, 54, 52, 48, 9, 97, 119, 115,
                          100, 110, 115, 45, 49, 54, 3, 110, 101, 116, 0, 17, 97, 119, 115, 100,
                          110, 115, 45, 104, 111, 115, 116, 109, 97, 115, 116, 101, 114, 6, 97,
                          109, 97, 122, 111, 110, 3, 99, 111, 109, 0, 0, 0, 0, 1, 0, 0, 28, 32, 0,
                          0, 3, 132, 0, 18, 117, 0, 0, 1, 81, 128, 0, 0, 41, 5, 172, 0, 0, 0, 0,
                          0, 0>>

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
    packet = Parser.parse(@fixture_a_request_with_extra_data)

    assert [%Resource{} = resource] = packet.resources
    # (edns(0))
    assert resource.type == 41
  end

  test "parse/1 with a valid A response with multiple records" do
    packet = Parser.parse(@fixture_a_response_multiple)

    assert length(packet.resources) == 1
    assert length(packet.answers) == 4

    assert Enum.all?(packet.answers, fn a -> a.name == "alexblackie.com" end)
  end

  test "parse/1 with a valid but heavily compressed MX record" do
    packet = Parser.parse(@fixture_mx_heavy_compression)

    assert length(packet.answers) == 5

    mx_values = Enum.map(packet.answers, fn a -> a.data end)
    assert Enum.member?(mx_values, "10 alt4.aspmx.l.google.com")
    assert Enum.member?(mx_values, "1 aspmx.l.google.com")
    assert Enum.member?(mx_values, "5 alt1.aspmx.l.google.com")
    assert Enum.member?(mx_values, "5 alt2.aspmx.l.google.com")
    assert Enum.member?(mx_values, "10 alt3.aspmx.l.google.com")
  end

  test "parse/1 with a valid SOA response" do
    packet = Parser.parse(@fixture_soa_response)

    assert length(packet.answers) == 1
    rr = List.first(packet.answers)
    assert rr.name == "alexblackie.com"

    assert %{mname: "ns-640.awsdns-16.net", rname: "awsdns-hostmaster.amazon.com", minimum: 86400} =
             rr.data
  end
end
