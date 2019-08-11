defmodule Zonal.Listener do
  use GenServer

  alias Zonal.{Parser, Serializer, Zones}

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

    resp =
      case Zones.get_resource(packet) do
        [] ->
          # nxdomain
          Map.put(packet, :response_code, 3)

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
end
