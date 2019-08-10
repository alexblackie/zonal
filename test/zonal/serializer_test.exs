defmodule Zonal.SerializerTest do
  use ExUnit.Case, async: true

  alias Zonal.{Packet, Resource, Serializer}

  @standard_query_packet %Packet{
    id: 1234,
    query_or_resource: 0,
    opcode: 0,
    authoritative_answer: 0,
    truncated: 0,
    recursion_desired: 1,
    recursion_available: 0,
    response_code: 0,
    query_count: 1,
    answer_count: 0,
    nameserver_count: 0,
    additional_count: 0,
    query_type: 1,
    query_class: 1,
    domain_name: "example",
    tld_name: "com"
  }
  @standard_query_packet_binary <<4, 210, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112,
                                  108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>

  @standard_answer_packet %Packet{
    id: 123,
    query_or_resource: 1,
    opcode: 0,
    authoritative_answer: 1,
    truncated: 0,
    recursion_desired: 1,
    recursion_available: 1,
    response_code: 0,
    query_count: 1,
    answer_count: 1,
    nameserver_count: 0,
    additional_count: 0,
    query_type: 1,
    query_class: 1,
    domain_name: "example",
    tld_name: "com",
    answers: [
      %Resource{name: "example.com", class: 0, type: 0, ttl: 300, data: <<127, 0, 0, 1>>}
    ]
  }

  @standard_answer_packet_binary <<0, 123, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97, 109,
                                   112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
                                   0, 0, 1, 44, 0, 4, 127, 0, 0, 1>>

  @standard_answer_packet_subdomains %Packet{
    id: 123,
    query_or_resource: 1,
    opcode: 0,
    authoritative_answer: 1,
    truncated: 0,
    recursion_desired: 1,
    recursion_available: 1,
    response_code: 0,
    query_count: 1,
    answer_count: 1,
    nameserver_count: 0,
    additional_count: 0,
    query_type: 1,
    query_class: 1,
    subdomains: ["www2", "a"],
    domain_name: "example",
    tld_name: "com",
    answers: [
      %Resource{name: "a.www2.example.com", class: 0, type: 0, ttl: 300, data: <<127, 0, 0, 1>>}
    ]
  }

  @standard_answer_packet_subdomains_binary <<0, 123, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, 1, 97, 4,
                                              119, 119, 119, 50, 7, 101, 120, 97, 109, 112, 108,
                                              101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
                                              0, 0, 1, 44, 0, 4, 127, 0, 0, 1>>

  test "serialize/1 basic query" do
    assert @standard_query_packet_binary = Serializer.serialize(@standard_query_packet)
  end

  test "serialize/1 basic answer" do
    assert @standard_answer_packet_binary = Serializer.serialize(@standard_answer_packet)
  end

  test "serialize/1 basic answer with subdomains" do
    assert @standard_answer_packet_subdomains_binary =
             Serializer.serialize(@standard_answer_packet_subdomains)
  end
end
