defmodule Zonal.Listener do
  use GenServer
  require Logger

  alias Zonal.{Packet, Parser, Serializer, Zones}

  @port Application.get_env(:zonal, :port)

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(_opts) do
    {:ok, _sock} = :gen_udp.open(@port, [:binary, :inet])
    {:ok, []}
  end

  @impl true
  def handle_info({:udp, sock, addr, port, blob}, state) do
    packet = Parser.parse(blob)

    log_query(addr, packet)

    resp =
      case Zones.get_resource(packet) do
        [] ->
          # recurse if we don't know it
          Zonal.Resolver.resolve(packet)

        records ->
          packet
          |> Map.put(:answer_count, 1)
          |> Map.put(:answers, records)
      end

    resp =
      resp
      |> Map.put(:query_or_resource, 1)
      |> Map.put(:authoritative_answer, 1)
      |> Serializer.serialize()

    :gen_udp.send(sock, addr, port, resp)

    {:noreply, state}
  end

  defp log_query({addr_one, addr_two, addr_three, addr_four}, %Packet{} = packet) do
    logline = [
      "#{addr_one}.#{addr_two}.#{addr_three}.#{addr_four}",
      Packet.query_domain(packet),
      Packet.query_type(packet),
      Packet.query_class(packet)
    ]

    Logger.debug("QUERY: " <> Enum.join(logline, " - "))
  end
end
