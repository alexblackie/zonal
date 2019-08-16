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
      %Resource{name: "example.com", class: 1, type: 1, ttl: 300, data: "127.0.0.1"}
    ]
  }

  @standard_answer_packet_binary <<0, 123, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97, 109,
                                   112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1,
                                   0, 1, 0, 0, 1, 44, 0, 4, 127, 0, 0, 1>>

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
      %Resource{name: "a.www2.example.com", class: 1, type: 1, ttl: 300, data: "127.0.0.1"}
    ]
  }

  @standard_answer_packet_subdomains_binary <<0, 123, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, 1, 97, 4,
                                              119, 119, 119, 50, 7, 101, 120, 97, 109, 112, 108,
                                              101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1,
                                              0, 1, 0, 0, 1, 44, 0, 4, 127, 0, 0, 1>>

  @standard_answer_packet_txt %Packet{
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
    query_type: 16,
    query_class: 1,
    subdomains: [],
    domain_name: "example",
    tld_name: "com",
    answers: [
      %Resource{name: "example.com", class: 1, type: 16, ttl: 300, data: "test"}
    ]
  }
  @standard_answer_packet_txt_binary <<0, 123, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97,
                                       109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 16, 0, 1, 192,
                                       12, 0, 16, 0, 1, 0, 0, 1, 44, 0, 5, 4, 116, 101, 115, 116>>

  @standard_answer_packet_mx %Packet{
    id: 123,
    query_or_resource: 1,
    opcode: 0,
    authoritative_answer: 1,
    truncated: 0,
    recursion_desired: 1,
    recursion_available: 1,
    response_code: 0,
    query_count: 1,
    answer_count: 2,
    nameserver_count: 0,
    additional_count: 0,
    query_type: 15,
    query_class: 1,
    subdomains: [],
    domain_name: "example",
    tld_name: "com",
    answers: [
      %Resource{name: "example.com", class: 1, type: 15, ttl: 300, data: "10 mx-a.example.com"},
      %Resource{name: "example.com", class: 1, type: 15, ttl: 300, data: "20 mx-b.example.com"}
    ]
  }

  @standard_answer_packet_mx_binary <<0, 123, 133, 128, 0, 1, 0, 2, 0, 0, 0, 0, 7, 101, 120, 97,
                                      109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 15, 0, 1, 192,
                                      12, 0, 15, 0, 1, 0, 0, 1, 44, 0, 20, 0, 10, 4, 109, 120, 45,
                                      97, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0,
                                      192, 12, 0, 15, 0, 1, 0, 0, 1, 44, 0, 20, 0, 20, 4, 109,
                                      120, 45, 98, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99,
                                      111, 109, 0>>

  @standard_answer_packet_soa %Packet{
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
    query_type: 6,
    query_class: 1,
    subdomains: [],
    domain_name: "example",
    tld_name: "com",
    answers: [
      %Resource{
        name: "example.com",
        class: 1,
        type: 6,
        ttl: 300,
        data: %{
          expire: 1_209_600,
          minimum: 86400,
          mname: "ns-640.awsdns-16.net",
          refresh: 7200,
          retry: 900,
          rname: "awsdns-hostmaster.amazon.com",
          serial: 1
        }
      }
    ]
  }

  @standard_answer_packet_soa_binary <<0, 123, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97,
                                       109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 6, 0, 1, 192,
                                       12, 0, 6, 0, 1, 0, 0, 1, 44, 0, 72, 6, 110, 115, 45, 54,
                                       52, 48, 9, 97, 119, 115, 100, 110, 115, 45, 49, 54, 3, 110,
                                       101, 116, 0, 17, 97, 119, 115, 100, 110, 115, 45, 104, 111,
                                       115, 116, 109, 97, 115, 116, 101, 114, 6, 97, 109, 97, 122,
                                       111, 110, 3, 99, 111, 109, 0, 0, 0, 0, 1, 0, 0, 28, 32, 0,
                                       0, 3, 132, 0, 18, 117, 0, 0, 1, 81, 128>>

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

  test "serialize/1 basic answer TXT record" do
    assert @standard_answer_packet_txt_binary = Serializer.serialize(@standard_answer_packet_txt)
  end

  test "serialize/1 basic answer MX record" do
    assert @standard_answer_packet_mx_binary = Serializer.serialize(@standard_answer_packet_mx)
  end

  test "serialize/1 basic answer SOA record" do
    assert @standard_answer_packet_soa_binary = Serializer.serialize(@standard_answer_packet_soa)
  end
end
