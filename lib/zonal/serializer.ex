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
        packet.truncated::1, packet.recursion_desired::1, packet.recursion_available::1, 0::1,
        0::1, 0::1, packet.response_code::4>>

    # Start with the packet header information.
    result =
      <<packet.id::16, meta::16-bitstring, packet.query_count::16, packet.answer_count::16,
        packet.nameserver_count::16, packet.additional_count::16>>

    # Serialize each subdomain first
    result =
      packet.subdomains
      |> Enum.reverse()
      |> Enum.reduce(result, fn sd, packet ->
        packet <> serialize_character_string(sd)
      end)

    domain_length = byte_size(packet.domain_name)
    tld_length = byte_size(packet.tld_name)

    # Serialize the root domain and the query type.
    result =
      result <>
        <<domain_length::8, packet.domain_name::size(domain_length)-binary, tld_length::8,
          packet.tld_name::size(tld_length)-binary, 0, packet.query_type::16,
          packet.query_class::16>>

    result =
      Enum.reduce(packet.answers, result, fn %Resource{} = resource, packet ->
        packet <> serialize_resource(resource, packet)
      end)

    result =
      Enum.reduce(packet.authorities, result, fn %Resource{} = resource, packet ->
        packet <> serialize_resource(resource, packet)
      end)

    Enum.reduce(packet.resources, result, fn %Resource{} = resource, packet ->
      packet <> serialize_resource(resource, packet)
    end)
  end

  @doc """
  Turn the given binary into a RFC-1035 <character-string>, which prefixes the
  byte length as an 8-bit field directly preceeding the binary data itself.
  """
  @spec serialize_character_string(binary()) :: binary()
  def serialize_character_string(data) do
    d_length = byte_size(data)
    <<d_length::8, data::size(d_length)-binary>>
  end

  defp serialize_resource(%Resource{} = resource, packet) do
    name =
      resource.name
      |> serialize_name()
      |> compress_name(packet)

    data = serialize_rdata(resource.type, resource.data)

    name_length = byte_size(name)
    data_length = byte_size(data)

    <<name::size(name_length)-binary, resource.type::16, resource.class::16, resource.ttl::32,
      data_length::16, data::size(data_length)-binary>>
  end

  defp serialize_rdata(1, data) do
    data
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
    |> :binary.list_to_bin()
  end

  defp serialize_rdata(
         6,
         %{
           rname: rname,
           mname: mname,
           serial: serial,
           refresh: refresh,
           retry: retry,
           expire: expire,
           minimum: minimum
         } = data
       ) do
    mname = serialize_name(mname)
    rname = serialize_name(rname)

    mname_length = byte_size(mname)
    rname_length = byte_size(rname)

    <<mname::size(mname_length)-binary, rname::size(rname_length)-binary, serial::32, refresh::32,
      retry::32, expire::32, minimum::32>>
  end

  defp serialize_rdata(15, data) do
    [prio, exchange] = String.split(data, " ")
    prio = String.to_integer(prio)
    exchange = serialize_name(exchange)
    exchange_length = byte_size(exchange)

    <<prio::16, exchange::size(exchange_length)-binary>>
  end

  defp serialize_rdata(16, data) do
    # TXT records must be serialized as character strings.
    serialize_character_string(data)
  end

  defp serialize_rdata(_type, data) do
    data
  end

  defp serialize_name(nil) do
    # If the name is nil, assume <<0>> which is the root domain.
    <<0>>
  end

  defp serialize_name(name) do
    name
    |> String.split(".")
    |> Enum.reduce(<<>>, fn x, acc ->
      acc <> serialize_character_string(x)
    end)
    |> Kernel.<>(<<0>>)
  end

  # If the query domain matches the domain we're serializing, reference that
  # using a compression pointer instead of re-serializing it again.
  defp compress_name(name, packet) do
    name_size = byte_size(name)

    with <<_header::12-binary, ^name::size(name_size)-binary, _rest::binary>> <- packet do
      # we're relying on the header always being 12 bytes. This might be naive.
      <<1::1, 1::1, 12::14>>
    else
      _ -> name
    end
  end
end
