#pragma once

// This needs to remain the first include in this file, or some defines aren't
// set correctly when netinet/tcp.h is included and the CentOS 7 build breaks.
// clang-format off
#include "zeek/net_util.h"

#include <netinet/tcp.h>
#include <sys/types.h>
#include <string>
// clang-format on

// For some reason, these two constants are not defined in every 'netinet/tcp.h' file
// on every system. Therefore, adding them here as they are part of the TCP standard.
#define	TH_ECE	0x40
#define	TH_CWR	0x80

namespace zeek::analyzer::tcp
	{

class TCP_Flags
	{
public:
	TCP_Flags(const struct tcphdr* tp) { flags = tp->th_flags; }
	TCP_Flags() { flags = 0; }

	bool SYN() const { return flags & TH_SYN; }
	bool FIN() const { return flags & TH_FIN; }
	bool RST() const { return flags & TH_RST; }
	bool ACK() const { return flags & TH_ACK; }
	bool URG() const { return flags & TH_URG; }
	bool PUSH() const { return flags & TH_PUSH; }
	bool ECE() const { return flags & TH_ECE; }
	bool CWR() const { return flags & TH_CWR; }

	std::string AsString() const;

protected:
	u_char flags;
	};

inline std::string TCP_Flags::AsString() const
	{
	char tcp_flags[10];
	char* p = tcp_flags;

	if ( SYN() )
		*p++ = 'S';

	if ( FIN() )
		*p++ = 'F';

	if ( RST() )
		*p++ = 'R';

	if ( ACK() )
		*p++ = 'A';

	if ( PUSH() )
		*p++ = 'P';

	if ( URG() )
		*p++ = 'U';

	if ( ECE() )
		*p++ = 'E';

	if ( CWR() )
		*p++ = 'C';

	*p++ = '\0';
	return tcp_flags;
	}

	} // namespace zeek::analyzer::tcp
