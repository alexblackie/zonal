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
    1 => "A",
    2 => "NS",
    3 => "MD",
    4 => "MF",
    5 => "CNAME",
    6 => "SOA",
    7 => "MB",
    8 => "MG",
    9 => "MR",
    10 => "NULL",
    11 => "WKS",
    12 => "PTR",
    13 => "HINFO",
    14 => "MINFO",
    15 => "MX",
    16 => "TXT"
  }

  @classes %{
    1 => "IN",
    2 => "CSNET",
    3 => "CHAOS",
    4 => "Hesiod"
  }

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
    answers: []
  ]

  def query?(packet), do: packet.query_or_resource == 0
  def query_type(packet), do: Map.get(@types, packet.query_type)
  def query_class(packet), do: Map.get(@classes, packet.query_class)
end
