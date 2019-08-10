defmodule Zonal.Serializer do
  @moduledoc """
  Perhaps most easily described as "the opposite of Zonal.Parser", this takes a
  Packet struct and serializes it back to a binary blob, suitable for transmission.
  """

  alias Zonal.{Packet, Resource}

  @doc "Take the given packet struct and excrete a DNS-compliant binary blob."
  def serialize(%Packet{} = packet) do
    # Pre-"render" the control octets for cleaner serialization later.
    meta =
      <<packet.query_or_resource::1, packet.opcode::4, packet.authoritative_answer::1,
        packet.truncated::1, packet.recursion_desired::1, packet.recursion_available::1, 0, 0, 0,
        packet.response_code::4>>

    # Start with the packet header information.
    result =
      <<packet.id::16, meta::16-bitstring, packet.query_count::16, packet.answer_count::16,
        packet.nameserver_count::16, packet.additional_count::16>>

    # Serialize each subdomain first
    result =
      packet.subdomains
      |> Enum.reverse()
      |> Enum.reduce(result, fn sd, packet ->
        sd_length = byte_size(sd)
        packet <> <<sd_length::8, sd::size(sd_length)-binary>>
      end)

    domain_length = byte_size(packet.domain_name)
    tld_length = byte_size(packet.tld_name)

    # Serialize the root domain and the query type.
    result =
      result <>
        <<domain_length::8, packet.domain_name::size(domain_length)-binary, tld_length::8,
          packet.tld_name::size(tld_length)-binary, 0, packet.query_type::16,
          packet.query_class::16>>

    Enum.reduce(packet.answers, result, fn %Resource{} = resource, packet ->
      data_length = byte_size(resource.data)

      packet <>
        <<0, resource.type::16, resource.class::16, resource.ttl::32, data_length::16,
          resource.data::size(data_length)-binary>>
    end)
  end
end
