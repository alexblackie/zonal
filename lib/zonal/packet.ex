defmodule Zonal.Packet do
  @moduledoc """
  A struct to hold the contents of a DNS packet in a nicer format.

  Here's what we're working with (from the RFC):

  ```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ```

  This follows this struct pretty well, with the addition of some list fields to
  hold the resource records. The resource records themselves use a different
  struct for their data: `Zonal.Resource`.

  Reference: https://tools.ietf.org/html/rfc1035
  """

  @types %{
    1 => :a,
    2 => :ns,
    3 => :md,
    4 => :mf,
    5 => :cname,
    6 => :soa,
    7 => :mb,
    8 => :mg,
    9 => :mr,
    10 => :null,
    11 => :wks,
    12 => :ptr,
    13 => :hinfo,
    14 => :minfo,
    15 => :mx,
    16 => :txt,
    28 => :aaaa
  }

  @classes %{
    1 => :in,
    2 => :csnet,
    3 => :chaos,
    4 => :hs
  }

  @type t() :: %__MODULE__{}

  defstruct [
    :id,
    :query_or_resource,
    :opcode,
    :authoritative_answer,
    :truncated,
    :recursion_desired,
    :recursion_available,
    :response_code,
    :query_count,
    :answer_count,
    :nameserver_count,
    :additional_count,
    :query_type,
    :query_class,
    :domain_name,
    :tld_name,
    subdomains: [],
    resources: [],
    answers: [],
    authorities: []
  ]

  def query?(packet), do: packet.query_or_resource == 0
  def query_type(packet), do: Map.get(@types, packet.query_type)
  def query_class(packet), do: Map.get(@classes, packet.query_class)

  @doc "Get the full query domain, with dots."
  @spec query_domain(t()) :: String.t()
  def query_domain(packet) do
    packet.subdomains
    |> Enum.reverse()
    |> Enum.concat([packet.domain_name, packet.tld_name])
    |> Enum.join(".")
  end
end
