defmodule Zonal.PacketTest do
  use ExUnit.Case

  alias Zonal.Packet

  test "query?/1" do
    query_packet = %Packet{query_or_resource: 0}
    assert Packet.query?(query_packet)

    resource_packet = %Packet{query_or_resource: 1}
    refute Packet.query?(resource_packet)
  end

  test "query_type/1" do
    a_packet = %Packet{query_type: 1}
    assert Packet.query_type(a_packet) == :a

    mx_packet = %Packet{query_type: 15}
    assert Packet.query_type(mx_packet) == :mx
  end

  test "query_class/1" do
    inet_packet = %Packet{query_class: 1}
    assert Packet.query_class(inet_packet) == :in
  end

  test "query_domain/1" do
    packet = %Packet{domain_name: "example", tld_name: "com", subdomains: ["www", "deep"]}
    assert Packet.query_domain(packet) == "deep.www.example.com"
  end
end
