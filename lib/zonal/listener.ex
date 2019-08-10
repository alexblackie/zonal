defmodule Zonal.Listener do
  use GenServer

  alias Zonal.{Parser, Resource, Serializer}

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
    resp =
      Parser.parse(blob)
      |> Map.put(:query_or_resource, 1)
      |> Map.put(:authoritative_answer, 1)
      |> Map.put(:answer_count, 1)
      |> Map.put(:answers, [
        # stub
        %Resource{type: 1, class: 1, name: "www.example.com", ttl: 300, data: <<127, 0, 0, 1>>}
      ])
      |> Serializer.serialize()

    :gen_udp.send(sock, addr, port, resp)

    {:noreply, state}
  end
end
