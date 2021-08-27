#include "zeek/packet_analysis/protocol/teredo/Teredo.h"

#include "zeek/TunnelEncapsulation.h"
#include "zeek/Conn.h"
#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"
#include "zeek/RunState.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"
#include "zeek/RE.h"

#include "zeek/packet_analysis/protocol/teredo/events.bif.h"

namespace zeek::packet_analysis::teredo {

namespace detail {

bool TeredoEncapsulation::DoParse(const u_char* data, size_t& len,
                                  bool found_origin, bool found_auth)
	{
	if ( len < 2 )
		{
		Weird("truncated_Teredo");
		return false;
		}

	uint16_t tag = ntohs((*((const uint16_t*)data)));

	if ( tag == 0 )
		{
		// Origin Indication
		if ( found_origin )
			// can't have multiple origin indications
			return false;

		if ( len < 8 )
			{
			Weird("truncated_Teredo_origin_indication");
			return false;
			}

		origin_indication = data;
		len -= 8;
		data += 8;
		return DoParse(data, len, true, found_auth);
		}

	else if ( tag == 1 )
		{
		// Authentication
		if ( found_origin || found_auth )
			// can't have multiple authentication headers and can't come after
			// an origin indication
			return false;

		if ( len < 4 )
			{
			Weird("truncated_Teredo_authentication");
			return false;
			}

		uint8_t id_len = data[2];
		uint8_t au_len = data[3];
		uint16_t tot_len = 4 + id_len + au_len + 8 + 1;

		if ( len < tot_len )
			{
			Weird("truncated_Teredo_authentication");
			return false;
			}

		auth = data;
		len -= tot_len;
		data += tot_len;
		return DoParse(data, len, found_origin, true);
		}

	else if ( ((tag & 0xf000)>>12) == 6 )
		{
		// IPv6
		if ( len < 40 )
			{
			Weird("truncated_IPv6_in_Teredo");
			return false;
			}

		// There's at least a possible IPv6 header, we'll decide what to do
		// later if the payload length field doesn't match the actual length
		// of the packet.
		inner_ip = data;
		return true;
		}

	return false;
	}

RecordValPtr TeredoEncapsulation::BuildVal(const std::shared_ptr<IP_Hdr>& inner) const
	{
	static auto teredo_hdr_type = id::find_type<RecordType>("teredo_hdr");
	static auto teredo_auth_type = id::find_type<RecordType>("teredo_auth");
	static auto teredo_origin_type = id::find_type<RecordType>("teredo_origin");

	auto teredo_hdr = make_intrusive<RecordVal>(teredo_hdr_type);

	if ( auth )
		{
		auto teredo_auth = make_intrusive<RecordVal>(teredo_auth_type);
		uint8_t id_len = *((uint8_t*)(auth + 2));
		uint8_t au_len = *((uint8_t*)(auth + 3));
		uint64_t nonce = ntohll(*((uint64_t*)(auth + 4 + id_len + au_len)));
		uint8_t conf = *((uint8_t*)(auth + 4 + id_len + au_len + 8));
		teredo_auth->Assign(0, new String(auth + 4, id_len, true));
		teredo_auth->Assign(1, new String(auth + 4 + id_len, au_len, true));
		teredo_auth->Assign(2, nonce);
		teredo_auth->Assign(3, conf);
		teredo_hdr->Assign(0, std::move(teredo_auth));
		}

	if ( origin_indication )
		{
		auto teredo_origin = make_intrusive<RecordVal>(teredo_origin_type);
		uint16_t port = ntohs(*((uint16_t*)(origin_indication + 2))) ^ 0xFFFF;
		uint32_t addr = ntohl(*((uint32_t*)(origin_indication + 4))) ^ 0xFFFFFFFF;
		teredo_origin->Assign(0, val_mgr->Port(port, TRANSPORT_UDP));
		teredo_origin->Assign(1, make_intrusive<AddrVal>(htonl(addr)));
		teredo_hdr->Assign(1, std::move(teredo_origin));
		}

	teredo_hdr->Assign(2, inner->ToPktHdrVal());
	return teredo_hdr;
	}

} // namespace detail

TeredoAnalyzer::TeredoAnalyzer() : zeek::packet_analysis::Analyzer("TEREDO")
	{
	// The pattern matching below is based on this old DPD signature
	// signature dpd_teredo {
	// 	ip-proto = udp
	// 	payload /^(\x00\x00)|(\x00\x01)|([\x60-\x6f].{7}((\x20\x01\x00\x00)).{28})|([\x60-\x6f].{23}((\x20\x01\x00\x00))).{12}/
	// 	enable "teredo"
	// 	}

	pattern_re = std::make_unique<zeek::detail::Specific_RE_Matcher>(zeek::detail::MATCH_EXACTLY);
	pattern_re->AddPat("^(\\x00\\x00)|(\\x00\\x01)|([\\x60-\\x6f].{7}((\\x20\\x01\\x00\\x00)).{28})|([\\x60-\\x6f].{23}((\\x20\\x01\\x00\\x00))).{12}");
	pattern_re->Compile();
	}

bool TeredoAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! BifConst::Tunnel::enable_teredo )
		return false;

	// Teredo always comes from a UDP connection, which means that session should always
	// be valid and always be a connection. Store this off for the span of the
	// processing so that it can be used for other things. Return a weird if we didn't
	// have a session stored.
	if ( ! packet->session )
		{
		reporter->Weird("teredo_missing_connection");
		return false;
		}

	conn = static_cast<Connection*>(packet->session);
	zeek::detail::ConnKey conn_key = conn->Key();

	OrigRespMap::iterator or_it = orig_resp_map.find(conn->Key());
	if ( or_it == orig_resp_map.end() )
		or_it = orig_resp_map.insert(or_it, {conn_key, {}});

	if ( packet->is_orig )
		or_it->second.valid_orig = false;
	else
		or_it->second.valid_resp = false;

	detail::TeredoEncapsulation te(this);
	if ( ! te.Parse(data, len) )
		{
		// TODO
		//ProtocolViolation("Bad Teredo encapsulation", (const char*) data, len);
		return false;
		}

	if ( packet->encap &&
	     packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	// TODO: i'm not sure about this. on the one hand, we do some error checking with the result
	// but on the other hand we duplicate this work here. maybe this header could just be stored
	// and reused in the IP analyzer somehow?
	std::shared_ptr<IP_Hdr> inner = nullptr;
	int rslt = packet_analysis::IP::ParsePacket(len, te.InnerIP(), IPPROTO_IPV6, inner);
	if ( rslt > 0 )
		{
		if ( inner->NextProto() == IPPROTO_NONE && inner->PayloadLen() == 0 )
			// Teredo bubbles having data after IPv6 header isn't strictly a
			// violation, but a little weird.
			Weird("Teredo_bubble_with_payload", true);
		else
			{
			// TODO
			//ProtocolViolation("Teredo payload length", (const char*) data, len);
			return false;
			}
		}

	if ( rslt == 0 || rslt > 0 )
		{
		if ( packet->is_orig )
			or_it->second.valid_orig = false;
		else
			or_it->second.valid_resp = false;

		Confirm(or_it->second.valid_orig, or_it->second.valid_resp);
		}
	else
		{
		// TODO
		//ProtocolViolation("Truncated Teredo or invalid inner IP version", (const char*) data, len);
		return false;
		}

	ValPtr teredo_hdr;

	if ( teredo_packet )
		{
		teredo_hdr = te.BuildVal(inner);
		packet->session->EnqueueEvent(teredo_packet, nullptr,
		                              packet->session->GetVal(), teredo_hdr);
		}

	if ( te.Authentication() && teredo_authentication )
		{
		if ( ! teredo_hdr )
			teredo_hdr = te.BuildVal(inner);

		packet->session->EnqueueEvent(teredo_authentication, nullptr,
		                              packet->session->GetVal(), teredo_hdr);
		}

	if ( te.OriginIndication() && teredo_origin_indication )
		{
		if ( ! teredo_hdr )
			teredo_hdr = te.BuildVal(inner);

		packet->session->EnqueueEvent(teredo_origin_indication, nullptr,
		                              packet->session->GetVal(), teredo_hdr);
		}

	if ( inner->NextProto() == IPPROTO_NONE && teredo_bubble )
		{
		if ( ! teredo_hdr )
			teredo_hdr = te.BuildVal(inner);

		packet->session->EnqueueEvent(teredo_bubble, nullptr,
		                              packet->session->GetVal(), teredo_hdr);
		}

	Packet inner_packet;
	int encap_index = 0;
	packet_analysis::IPTunnel::build_inner_packet(
		&inner_packet, packet, IPPROTO_IPV6, &encap_index,
		nullptr, len, te.InnerIP(), DLT_RAW, BifEnum::Tunnel::TEREDO,
		GetAnalyzerTag());

	return ForwardPacket(len, te.InnerIP(), &inner_packet);
	}

bool TeredoAnalyzer::DetectProtocol(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! BifConst::Tunnel::enable_teredo )
		return false;

	if ( ! pattern_re->Match(data, len) )
		return false;

	return true;
	}

} // namespace zeek::packet_analysis::teredo
