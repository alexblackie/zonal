defmodule Zonal.Resolver do
  @moduledoc """
  This module provide recursive resolution capabilities, querying external
  nameservers to provide a response.
  """

  alias Zonal.{Parser, Serializer}

  @doc "Pass the given query packet to an external resolver."
  @spec resolve(Zonal.Packet.t()) :: Zonal.Packet.t()
  def resolve(packet) do
    serialized_packet = Serializer.serialize(packet)

    {:ok, sock} = :socket.open(:inet, :dgram)
    :ok = :socket.connect(sock, %{family: :inet, port: 53, addr: {1, 1, 1, 1}})
    :ok = :socket.send(sock, serialized_packet)

    {:ok, bresp} = :socket.recv(sock)

    Parser.parse(bresp)
  end
end
