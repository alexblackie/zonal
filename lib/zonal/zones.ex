defmodule Zonal.Zones do
  @moduledoc """
  Provides access to all known authoritative zones.
  """

  alias Zonal.{Packet, Resource}

  @zones %{
    "com" => %{
      "example" => [
        %Resource{
          name: "www.example.com",
          ttl: 300,
          class: 1,
          type: 1,
          data: <<192, 168, 2, 40>>
        },
        %Resource{name: "test.example.com", ttl: 300, class: 1, type: 16, data: "hello"},
        %Resource{name: "example.com", ttl: 300, class: 1, type: 1, data: <<192, 168, 2, 40>>}
      ]
    }
  }

  @doc """
  Get a resource from a zone.

  Example:

  iex> get_resource(%Packet{domain_name: "example", tld_name: "com", ...})
  [%Resource{name: "example.com", ...}, ...]
  """
  @spec get_resource(Packet.t()) :: list()
  def get_resource(%Packet{domain_name: apex, tld_name: tld, query_type: type} = packet) do
    domain = Packet.query_domain(packet)

    @zones
    |> Map.get(tld, %{})
    |> Map.get(apex, [])
    |> Enum.filter(fn r ->
      r.name == domain && r.type == type
    end)
  end
end
