defmodule Zonal.Parser do
  @moduledoc """
  Provides parsing abilities for DNS binary packets.
  """
  require Logger

  alias Zonal.{Packet, Resource}

  @doc "Parses a query packet."
  def parse(
        <<id::16, meta::16-bitstring, question_count::16, answer_count::16, ns_count::16,
          ar_count::16, domain_and_data::binary>> = packet
      ) do
    <<qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, _z::3, rcode::4>> = meta

    parts = extract_domains(domain_and_data, [])

    domain_bytes = serialized_name_byte_size(parts)

    <<_domains::size(domain_bytes)-binary, 0, qtype::16, qclass::16, additional::binary>> =
      domain_and_data

    resources =
      additional
      |> parse_resources(packet, [])
      |> Enum.map(fn r -> Map.put(r, :name, decompress_name(r.name, packet)) end)
      |> Enum.reverse()

    # TODO: there has to be some function on `Enum` that does the take/drop in one step?? This is
    # disgusting.
    answer_records = Enum.take(resources, answer_count)
    resources = Enum.drop(resources, answer_count)

    authority_records = Enum.take(resources, ns_count)
    resources = Enum.drop(resources, ns_count)

    other_records = Enum.take(resources, ar_count)

    tld_name = Enum.at(parts, 0)
    domain_name = Enum.at(parts, 1)
    subdomains = Enum.drop(parts, 2)

    %Packet{
      id: id,
      query_or_resource: qr,
      opcode: opcode,
      authoritative_answer: aa,
      truncated: tc,
      recursion_desired: rd,
      recursion_available: ra,
      response_code: rcode,
      query_count: question_count,
      answer_count: answer_count,
      nameserver_count: ns_count,
      additional_count: ar_count,
      query_type: qtype,
      query_class: qclass,
      domain_name: domain_name,
      tld_name: tld_name,
      subdomains: subdomains,
      resources: other_records,
      answers: answer_records,
      authorities: authority_records
    }
  end

  # Parse RR data into a %Resource struct.
  #
  # EDNS packet: (<<0>> is the root domain)
  def parse_resources(
        <<0, rtype::16, rclass::16, ttl::32, rdlength::16, rdata::size(rdlength)-binary>>,
        _packet,
        bag
      ) do
    [
      %Resource{
        type: rtype,
        class: rclass,
        ttl: ttl,
        data: rdata
      }
      | bag
    ]
  end

  def parse_resources(
        <<pointer::16-bitstring, rtype::16, rclass::16, ttl::32, rdlength::16,
          rdata::size(rdlength)-binary, more::binary>>,
        packet,
        bag
      ) do
    parse_resources(
      more,
      packet,
      [
        %Resource{
          name: <<pointer::16-bitstring>>,
          type: rtype,
          class: rclass,
          ttl: ttl,
          data: parse_rdata(rtype, rdata, packet)
        }
        | bag
      ]
    )
  end

  def parse_resources(<<>>, _packet, bag) do
    bag
  end

  # because we don't know the length of the first field (name), we can't match out.
  def parse_resources(<<domain_and_data::binary>>, packet, bag) do
    parts =
      extract_domains(domain_and_data, [])
      |> Enum.map(fn d -> decompress_name(d, packet) end)

    domain_bytes = serialized_name_byte_size(parts)

    domain_name = Enum.reverse(parts) |> Enum.join(".")

    <<_::size(domain_bytes)-binary, 0, rtype::16, rclass::16, ttl::32, rdlength::16,
      rdata::size(rdlength)-binary, more::binary>> = domain_and_data

    parse_resources(
      more,
      packet,
      [
        %Resource{
          name: domain_name,
          type: rtype,
          class: rclass,
          ttl: ttl,
          data: parse_rdata(rtype, rdata, packet)
        }
        | bag
      ]
    )
  end

  def parse_resources(other, _packet, bag) do
    Logger.error("Tried to parse unhandled resource! #{inspect(other, limit: :infinity)}")

    bag
  end

  # Use the compression pointer bits to find the domain in <packet>
  def decompress_name(<<1::1, 1::1, pointer::14>>, packet) do
    remaining_packet_size = byte_size(packet) - pointer
    domains_and_data = :binary.part(packet, {pointer, remaining_packet_size})

    extract_domains(domains_and_data, [])
    |> Enum.map(fn d -> decompress_name(d, packet) end)
    |> Enum.reverse()
    |> Enum.join(".")
  end

  def decompress_name(name, _packet) do
    name
  end

  # fall through
  defp extract_domains(<<0, _additional::binary>>, parts) do
    parts
  end

  # Extract the last domain from a packet
  defp extract_domains(
         <<part_length::8, domain_part::size(part_length)-binary, 0, _remainder::binary>>,
         parts
       ) do
    [domain_part | parts]
  end

  # Extract the domain part, add to the list, and recurse.
  defp extract_domains(
         <<part_length::8, domain_part::size(part_length)-binary, remainder::binary>>,
         parts
       ) do
    extract_domains(remainder, [domain_part | parts])
  end

  # Keep a compressed name pointer intact, push the decompression responsibility up the chain.
  #
  # A pointer can only *end* a name, not be in the middle or start, therefore we stop recursing
  # after finding a pointer, as it must be the end of the name.
  defp extract_domains(<<1::1, 1::1, pointer::14-bitstring, _remainder::binary>>, parts) do
    [<<1::1, 1::1, pointer::14-bitstring>> | parts]
  end

  # Anything else we don't recognize, just ignore.
  defp extract_domains(_, parts) do
    parts
  end

  defp parse_rdata(1, ip, _packet) do
    ip
    |> :binary.bin_to_list()
    |> Enum.join(".")
  end

  defp parse_rdata(6, soa_data, _packet) do
    mname =
      extract_domains(soa_data, [])
      |> Enum.reverse()

    mname_length = serialized_name_byte_size(mname)

    <<_mname::size(mname_length)-binary, 0, rname_and_beyond::binary>> = soa_data

    rname =
      extract_domains(rname_and_beyond, [])
      |> Enum.reverse()

    rname_length = serialized_name_byte_size(rname)

    total_name_bytes = mname_length + rname_length + 1

    <<_mname_and_rname::size(total_name_bytes)-binary, 0, serial::32, refresh::32, retry::32,
      expire::32, minimum::32>> = soa_data

    %{
      mname: Enum.join(mname, "."),
      rname: Enum.join(rname, "."),
      serial: serial,
      refresh: refresh,
      retry: retry,
      expire: expire,
      minimum: minimum
    }
  end

  defp parse_rdata(15, <<priority::16, exchange::binary>>, packet) do
    address =
      extract_domains(exchange, [])
      |> Enum.map(fn d -> decompress_name(d, packet) end)
      |> Enum.reverse()
      |> Enum.join(".")

    "#{priority} #{address}"
  end

  defp parse_rdata(16, <<_length::8, txt::binary>>, _packet) do
    txt
  end

  defp parse_rdata(_type, data, _packet) do
    data
  end

  # Get the number of bytes this list of names would be when serialized
  # in a packet as a <domain-name> (with bytes-per-field prefixed).
  defp serialized_name_byte_size(parts) do
    parts
    |> Enum.reduce(0, fn p, acc -> acc + byte_size(p) end)
    |> Kernel.+(length(parts))
  end
end
