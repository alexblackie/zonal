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
    assert Packet.query_type(a_packet) == "A"

    mx_packet = %Packet{query_type: 15}
    assert Packet.query_type(mx_packet) == "MX"
  end

  test "query_class/1" do
    inet_packet = %Packet{query_class: 1}
    assert Packet.query_class(inet_packet) == "IN"
  end
end
