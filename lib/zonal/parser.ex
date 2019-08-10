defmodule Zonal.Parser do
  @moduledoc """
  Provides parsing abilities for DNS binary packets.
  """
  require Logger

  alias Zonal.Packet

  @doc "Parses a query packet."
  def parse(
        <<id::16, meta::16-bitstring, question_count::16, answer_count::16, ns_count::16,
          ar_count::16, domain_and_data::binary>>
      ) do
    <<qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, _z::3, rcode::4>> = meta

    parts = extract_domains(domain_and_data, [])

    domain_bytes =
      parts
      |> Enum.reduce(0, fn p, acc -> acc + byte_size(p) end)
      |> Kernel.+(length(parts))

    <<_domains::size(domain_bytes)-binary, 0, qtype::16, qclass::16, _additional::binary>> =
      domain_and_data

    # <<0>> == root domain
    # TODO: parse and support EDNS OPT
    # <<0, rtype::16, rclass::16, _ttl::32, rdlength::16, _rdata::size(rdlength)-binary>> = additional

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
      subdomains: subdomains
    }
  end

  # Fall through if there are no domain parts left.
  defp extract_domains(<<0>>, parts) do
    parts
  end

  # Fall through if there are no domain parts left, only extra data.
  defp extract_domains(<<0, _remainder::binary>>, parts) do
    parts
  end

  # Extract the last domain from a packet with extra data
  defp extract_domains(
         <<part_length::8, domain_part::size(part_length)-binary, 0, _remainder::binary>>,
         parts
       ) do
    [domain_part | parts]
  end

  # Extract the last domain part.
  defp extract_domains(<<part_length::8, domain_part::size(part_length)-binary, 0>>, parts) do
    [domain_part | parts]
  end

  # Extract the domain part, add to the list, and recurse.
  defp extract_domains(
         <<part_length::8, domain_part::size(part_length)-binary, remainder::binary>>,
         parts
       ) do
    extract_domains(remainder, [domain_part | parts])
  end
end
