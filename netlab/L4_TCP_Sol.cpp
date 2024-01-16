#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#ifndef WINSOCK2
#define WINSOCK2
#include <WinSock2.h>
#endif

#include <algorithm>
#include <sstream>
#include <iostream>
#include <Shlobj.h>
#include <random>

#ifdef IN
#undef IN
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#include "NIC.h"
#include "L4_TCP.h"
#include "L2.h"
#include "L5.h"

#include <iomanip>

#define FIXBUG_959

/************************************************************************/
/*                         L4_TCP::tcpcb                                */
/************************************************************************/




L4_TCP::tcpcb::tcpcb(inet_os &inet) 
	: inpcb_impl(inet), seg_next(nullptr), seg_prev(nullptr), t_state(0),
	t_rxtshift(0), t_rxtcur(0), t_dupacks(0), t_maxseg(0), t_force(0),
	t_flags(0), t_template(nullptr), t_inpcb(dynamic_cast<inpcb_impl*>(this)),
	snd_una(0), snd_nxt(0), snd_up(0), snd_wl1(0), snd_wl2(0), iss(0), snd_wnd(0),
	rcv_wnd(0), rcv_nxt(0), rcv_up(0), irs(0), rcv_adv(0), snd_max(0), 
	snd_ssthresh(0), t_idle(0), t_rtt(0), t_rtseq(0), t_srtt(0), t_rttvar(0), 
	t_rttmin(0), max_sndwnd(0), t_oobflags(0), t_iobc(0), t_softerror(0),
	snd_scale(0), rcv_scale(0), request_r_scale(0), requested_s_scale(0),
	ts_recent(0), ts_recent_age(0), last_ack_sent(0), t_tuba_pcb(nullptr),
	log(tcpcb_logger()) { }

L4_TCP::tcpcb::tcpcb(socket &so, inpcb_impl &head)
	: inpcb_impl(so, head), seg_next(nullptr), seg_prev(nullptr), t_state(0),
	t_rxtshift(0), t_rxtcur(0), t_dupacks(0), t_maxseg(0), t_force(0),
	t_flags(0), t_template(nullptr), t_inpcb(dynamic_cast<inpcb_impl*>(this)),
	snd_una(0), snd_nxt(0), snd_up(0), snd_wl1(0), snd_wl2(0), iss(0), snd_wnd(0),
	rcv_wnd(0), rcv_nxt(0), rcv_up(0), irs(0), rcv_adv(0), snd_max(0),
	snd_ssthresh(0), t_idle(0), t_rtt(0), t_rtseq(0), t_srtt(0), t_rttvar(0),
	t_rttmin(0), max_sndwnd(0), t_oobflags(0), t_iobc(0), t_softerror(0),
	snd_scale(0), rcv_scale(0), request_r_scale(0), requested_s_scale(0),
	ts_recent(0), ts_recent_age(0), last_ack_sent(0), t_tuba_pcb(nullptr),
	log(tcpcb_logger()){ }

/*!
    \fn	L4_TCP::tcpcb::~tcpcb()

    \brief	Destructor. free the reassembly queue, if any, and gets rid of all other allocated stuff.
*/
L4_TCP::tcpcb::~tcpcb() 
{
	/* free the reassembly queue, if any */
	struct L4_TCP::tcpiphdr *t(seg_next);
	while (t != reinterpret_cast<struct L4_TCP::tcpiphdr *>(this))
		delete reinterpret_cast<struct L4_TCP::tcpiphdr *>(t->ti_next());
	if (t_template)
		delete t_template;
	if (this != dynamic_cast<class L4_TCP::tcpcb*>(t_inpcb))
		delete t_inpcb;
	inp_ppcb = nullptr;
	dynamic_cast<socket*>(inp_socket)->soisdisconnected();
}

void L4_TCP::tcpcb::log_snd_cwnd(u_long snd_cwnd) { log.update(snd_cwnd); }

int L4_TCP::tcpcb::tcpcb_logger::log_number(0);

L4_TCP::tcpcb::tcpcb_logger::tcpcb_logger()
	: log(std::ofstream(std::string("log/connection_") + std::to_string(log_number++) + std::string(".txt"), std::ios_base::out | std::ios_base::trunc)),
	start(std::chrono::high_resolution_clock::now()) 
{
  
}

void L4_TCP::tcpcb::tcpcb_logger::update(u_long snd_cwnd)
{
	log << std::chrono::duration_cast<seconds>(std::chrono::high_resolution_clock::now() - start).count()
		<< "\t" << std::to_string(snd_cwnd) << std::endl;
}

inline bool L4_TCP::tcpcb::TCPS_HAVERCVDSYN() const { return t_state >= TCPS_SYN_RECEIVED; }

inline bool L4_TCP::tcpcb::TCPS_HAVERCVDFIN() const { return t_state >= TCPS_TIME_WAIT; }

inline const u_char L4_TCP::tcpcb::tcp_outflags() const
{
	switch (t_state) {
	case TCPS_CLOSED:
		return static_cast<u_char>(tcphdr::TH_RST | L4_TCP::tcphdr::TH_ACK);
		break;
	case TCPS_LISTEN:
		return 0;
		break;
	case TCPS_SYN_SENT:
		return static_cast<u_char>(tcphdr::TH_SYN);
		break;
	case TCPS_SYN_RECEIVED:
		return static_cast<u_char>(tcphdr::TH_SYN | L4_TCP::tcphdr::TH_ACK);
		break;
	case TCPS_ESTABLISHED:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	case TCPS_CLOSE_WAIT:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	case TCPS_FIN_WAIT_1:
		return static_cast<u_char>(tcphdr::TH_FIN | L4_TCP::tcphdr::TH_ACK);
		break;
	case TCPS_CLOSING:
		return static_cast<u_char>(tcphdr::TH_FIN | L4_TCP::tcphdr::TH_ACK);
		break;
	case TCPS_LAST_ACK:
		return static_cast<u_char>(tcphdr::TH_FIN | L4_TCP::tcphdr::TH_ACK);
		break;
	case TCPS_FIN_WAIT_2:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	case TCPS_TIME_WAIT:
		return static_cast<u_char>(tcphdr::TH_ACK);
		break;
	default:
		break;
	}
	throw std::runtime_error("tcp_outflags: No such state!");
}

inline class L4_TCP::tcpcb* L4_TCP::tcpcb::intotcpcb(class inpcb_impl *ip) { return dynamic_cast<class L4_TCP::tcpcb *>(ip); }

inline class L4_TCP::tcpcb* L4_TCP::tcpcb::intotcpcb(class inpcb *ip) { return dynamic_cast<class L4_TCP::tcpcb *>(ip); }

inline class L4_TCP::tcpcb* L4_TCP::tcpcb::sototcpcb(socket *so) { return dynamic_cast<class L4_TCP::tcpcb *>(so->so_pcb); }

template<typename T>
inline bool L4_TCP::tcpcb::SEQ_LT(T a, T b) { return static_cast<int>(a - b) < 0; }

template<typename T>
inline bool L4_TCP::tcpcb::SEQ_LEQ(T a, T b) { return static_cast<int>(a - b) <= 0; }

template<typename T>
static inline bool L4_TCP::tcpcb::SEQ_GT(T a, T b) { return static_cast<int>(a - b) > 0; }

template<typename T>
static inline bool L4_TCP::tcpcb::SEQ_GEQ(T a, T b) { return static_cast<int>(a - b) >= 0; }

class L4_TCP::tcpcb* L4_TCP::tcpcb::in_pcblookup(struct in_addr faddr, u_int fport_arg, struct in_addr laddr, u_int lport_arg, int flags)
{
	return dynamic_cast<class L4_TCP::tcpcb *>(inpcb_impl::in_pcblookup(faddr, fport_arg, laddr, lport_arg, flags));
}

void L4_TCP::tcpcb::tcp_template()
{
	if (t_template == nullptr)
		t_template = new tcpiphdr();
	t_template->tcp_template(t_inpcb->inp_faddr(), t_inpcb->inp_fport(), t_inpcb->inp_laddr(), t_inpcb->inp_lport());
}

inline void L4_TCP::tcpcb::tcp_rcvseqinit() { rcv_adv = rcv_nxt = irs + 1; }

inline void L4_TCP::tcpcb::tcp_sendseqinit() { snd_una = snd_nxt = snd_max = snd_up = iss; }

inline void L4_TCP::tcpcb::tcp_quench() { log_snd_cwnd(snd_cwnd = t_maxseg); }

inline short L4_TCP::tcpcb::TCP_REXMTVAL() const
{
	return (t_srtt >> L4_TCP_impl::TCP_RTT_SHIFT) + t_rttvar;
}

void L4_TCP::tcpcb::tcp_xmit_timer(short rtt)	
{
	if (t_srtt != 0) {
		/*
		* srtt is stored as fixed point with 3 bits after the
		* binary point (i.e., scaled by 8).  The following magic
		* is equivalent to the smoothing algorithm in rfc793 with
		* an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
		* point).  Adjust rtt to origin 0.
		*/
		short delta(rtt - 1 - (t_srtt >> L4_TCP_impl::TCP_RTT_SHIFT));
		if ((t_srtt += delta) <= 0)
			t_srtt = 1;
		/*
		* We accumulate a smoothed rtt variance (actually, a
		* smoothed mean difference), then set the retransmit
		* timer to smoothed rtt + 4 times the smoothed variance.
		* rttvar is stored as fixed point with 2 bits after the
		* binary point (scaled by 4).  The following is
		* equivalent to rfc793 smoothing with an alpha of .75
		* (rttvar = rttvar*3/4 + |delta| / 4).  This replaces
		* rfc793's wired-in beta.
		*/
		if (delta < 0)
			delta = -delta;
		if ((t_rttvar += (delta -= (t_rttvar >> L4_TCP_impl::TCP_RTTVAR_SHIFT))) <= 0)
			t_rttvar = 1;
	}
	else {
		/*
		* No rtt measurement yet - use the unsmoothed rtt.
		* Set the variance to half the rtt (so our first
		* retransmit happens at 3*rtt).
		*/
		t_srtt = rtt << L4_TCP_impl::TCP_RTT_SHIFT;
		t_rttvar = rtt << (L4_TCP_impl::TCP_RTTVAR_SHIFT - 1);
	}
	t_rtt = t_rxtshift = 0;

	/*
	* the retransmit should happen at rtt + 4 * rttvar.
	* Because of the way we do the smoothing, srtt and rttvar
	* will each average +1/2 tick of bias.  When we compute
	* the retransmit timer, we want 1/2 tick of rounding and
	* 1 extra tick because of +-1/2 tick uncertainty in the
	* firing of the timer.  The bias will give us exactly the
	* 1.5 tick we need.  But, because the bias is
	* statistical, we have to test that we don't drop below
	* the minimum feasible timer (which is 2 ticks).
	*/
	L4_TCP_impl::TCPT_RANGESET(t_rxtcur, TCP_REXMTVAL(), t_rttmin, L4_TCP_impl::TCPTV_REXMTMAX);

	/*
	* We received an ack for a packet that wasn't retransmitted;
	* it is probably safe to discard any error indications we've
	* received recently.  This isn't quite right, but close enough
	* for now (a route might have failed after we sent a segment,
	* and the return path might not be symmetrical).
	*/
	t_softerror = 0;
}

void L4_TCP::tcpcb::tcp_canceltimers()	{
	for (int i = 0; i < TCPT_NTIMERS; i++)
		t_timer[i] = 0;
}

/************************************************************************/
/*                         L4_TCP::tcphdr                               */
/************************************************************************/

std::ostream& operator<<(std::ostream &out, const L4_TCP::tcphdr &tcp) {
	std::ios::fmtflags f(out.flags());
	out << "< TCP (" << static_cast<uint32_t>(tcp.th_off() << 2) <<
		" bytes) :: SourcePort = " << std::dec << ntohs(static_cast<uint16_t>(tcp.th_sport)) <<
		" , DestinationPort = " << std::dec << ntohs(static_cast<uint16_t>(tcp.th_dport)) <<
		" , Seq # = " << std::dec << static_cast<uint32_t>(tcp.th_seq) <<
		" , ACK # = " << std::dec << static_cast<uint32_t>(tcp.th_ack) <<
		" , HeaderLength = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint16_t>(tcp.th_off()) <<
		" , Flags = 0x" << std::setfill('0') << std::setw(3) << std::hex << static_cast<uint16_t>(tcp.th_flags) <<
		" (";
	if (tcp.th_flags & tcp.TH_URG)
		out << "URG, ";
	if (tcp.th_flags & tcp.TH_ACK)
		out << "ACK, ";
	if (tcp.th_flags & tcp.TH_PUSH)
		out << "PUSH, ";
	if (tcp.th_flags & tcp.TH_RST)
		out << "RST, ";
	if (tcp.th_flags & tcp.TH_SYN)
		out << "SYN, ";
	if (tcp.th_flags & tcp.TH_FIN)
		out << "FIN, ";
	out << ")" <<
		" , WinSize = " << std::dec << static_cast<uint16_t>(tcp.th_win) <<
		" , Checksum = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(tcp.th_sum) <<
		" , UrgentPointer = 0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<uint16_t>(tcp.th_urp) <<
		" , >";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                         L4_TCP::tcpiphdr		                        */
/************************************************************************/

L4_TCP::tcpiphdr::tcpiphdr() : ti_i(ipovly()), ti_t(tcphdr()) { }

L4_TCP::tcpiphdr::tcpiphdr(byte *m, const u_char& ih_pr, const short &ip_len, const in_addr &ip_src, const in_addr &ip_dst)
	: ti_i(ih_pr, ip_len, ip_src, ip_dst), ti_t(*reinterpret_cast<struct L4_TCP::tcphdr*>(m)) {	}

std::ostream& operator<<(std::ostream &out, const struct L4_TCP::tcpiphdr &ti)
{
	return out << ti.ti_i << ti.ti_t;
}

void L4_TCP::tcpiphdr::tcp_template(const struct in_addr &inp_faddr, const u_short &inp_fport, const struct in_addr &inp_laddr, const u_short &inp_lport)
{
	ti_seq() = ti_ack() = ti_ack() = 0;
	ti_flags() = 0;
	ti_win() = ti_sum() = ti_urp() = 0;
	ti_x2(0);
	ti_off(5);
	ti_sport() = inp_lport;
	ti_dport() = inp_fport;
	ti_next(0);
	ti_prev(0);
	ti_x1() = 0;
	ti_pr() = IPPROTO_TCP;
	ti_len() = htons(sizeof(struct L4_TCP::tcpiphdr) - sizeof(struct L3::iphdr));
	ti_src() = inp_laddr;
	ti_dst() = inp_faddr;
}

inline std::shared_ptr<std::vector<byte>> L4_TCP::tcpiphdr::REASS_MBUF() { return *reinterpret_cast<std::shared_ptr<std::vector<byte>>*>(&ti_t); }

inline void L4_TCP::tcpiphdr::insque(struct L4_TCP::tcpiphdr &head)
{
	ti_next(head.ti_next());
	head.ti_next(this);
	ti_prev(&head);
	if (ti_next())
		ti_next()->ti_prev(this);
}

inline void L4_TCP::tcpiphdr::remque()
{
	if (ti_next())
		ti_next()->ti_prev(ti_prev());
	if (ti_prev()) {
		ti_prev()->ti_next(ti_next());
		ti_prev(nullptr);
	}
}

/************************************************************************/
/*                         L4_TCP::tcpiphdr::ipovly                     */
/************************************************************************/

L4_TCP::tcpiphdr::ipovly::ipovly() 
	: ih_pr(0), ih_len(0), ih_src(struct in_addr()), ih_dst(struct in_addr()), ih_x1(0x00), ih_next(nullptr), ih_prev(nullptr) { }

L4_TCP::tcpiphdr::ipovly::ipovly(const u_char& ih_pr, const short &ih_len, const in_addr &ih_src, const in_addr &ih_dst)
	: ih_pr(ih_pr), ih_len(ih_len), ih_src(ih_src), ih_dst(ih_dst), ih_x1(0x00), ih_next(nullptr), ih_prev(nullptr) { }

std::ostream& operator<<(std::ostream &out, const struct L4_TCP::tcpiphdr::ipovly &ip) {
	std::ios::fmtflags f(out.flags());
	out << "< Pseudo IP (" << static_cast<uint32_t>(sizeof(struct L4_TCP::tcpiphdr::ipovly)) <<
		" bytes) :: Unsused = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint8_t>(ip.ih_x1) <<
		" , Protocol = 0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<uint8_t>(ip.ih_pr) <<
		" , Protocol Length = " << std::dec << htons(static_cast<uint16_t>(ip.ih_len)) <<
		" , SourceIP = " << inet_ntoa(ip.ih_src);
	out << " , DestinationIP = " << inet_ntoa(ip.ih_dst) <<
		" , >";
	out.flags(f);
	return out;
}

/************************************************************************/
/*                         L4_TCP_impl				                    */
/************************************************************************/

L4_TCP_impl::L4_TCP_impl(class inet_os &inet)
	: L4_TCP(inet), tcb(inet), tcp_saveti(nullptr), tcp_last_inpcb(nullptr) { }

L4_TCP_impl::~L4_TCP_impl()
{
	if (tcp_saveti)
		delete tcp_saveti;
	if (tcp_last_inpcb)
		delete tcp_last_inpcb;
}

void L4_TCP_impl::pr_init()
{
	tcp_saveti = nullptr;
	tcp_last_inpcb = nullptr;
	tcb.inp_next = tcb.inp_prev = &tcb;
	tcp_last_inpcb = dynamic_cast<class inpcb_impl *>(&tcb);
	std::random_device rd;
	tcp_iss = rd();	/* An improvement, may be wrong, but better than a constant */

	tcp_sendspace = TCP_MAXWIN;
	tcp_recvspace = TCP_MAXWIN;
}

void L4_TCP_impl::pr_fasttimo() 
{
	std::lock_guard<std::mutex> lock(inet._splnet);

	class inpcb_impl *inp(dynamic_cast<class inpcb_impl *>(tcb.inp_next));
	if (inp) {
		class L4_TCP::tcpcb *tp;
		for (; inp != &tcb; inp = dynamic_cast<class inpcb_impl *>(inp->inp_next))
			if ((tp = dynamic_cast<class L4_TCP::tcpcb *>(inp->inp_ppcb)) && (tp->t_flags & L4_TCP::tcpcb::TF_DELACK)) {
				tp->t_flags &= ~tcpcb::TF_DELACK;
				tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
				(void)tcp_output(*tp);
			}
	}
}

void L4_TCP_impl::pr_slowtimo() 
{
	std::lock_guard<std::mutex> lock(inet._splnet);
	
	/*
	*	tcp_rnaxidle is initialized to 10 minutes. This is the maximum amount of time
	*	TCP will send keepalive probes to another host, waiting for a response from that host.
	*	This variable is also used with the FIN_WAIT_2 timer, as we describe in Section 25.6.
	*	This initialization statement could be moved to tcp_ini t, since it only needs to be
	*	evaluated when the system is initialized (see Exercise 25.2).
	*/
	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;

	/*
	*	Check each timer counter In all TCP control blocks:
	*		Each Internet PCB on the TCP list that has a corresponding TCP control block is
	*	checked. Each of the four timer counters for each connection is tested, and if nonzero,
	*	the counter is decremented. When the timer reaches 0, a PRU_SLOWTIMO request is
	*	issued. We'll see that this request calls the function tcp_tirners, which we describe
	*	later in this chapter.
	*		The fourth argument to tcp_usrreq is a pointer to an mbuf. But this argument is
	*	actually used for different purposes when the mbuf pointer is not required. Here we
	*	see the index i is passed, telling the request which timer has expired. The funnylooking
	*	cast of i to an mbuf pointer is to avoid a compile-time error.
	*		Notice that if there are no TCP connections active on the host (tcb. inp_next is
	*	null), neither tcp_iss nor tcp_now is incremented. This would occur only when the
	*	system is being initialized, since it would be rare to find a Unix system attached to a
	*	network without a few TCP servers active.
	*
	* Search through tcb's and update active timers.
	*/
	class inpcb_impl *ip(dynamic_cast<inpcb_impl*>(tcb.inp_next));
	if (ip == nullptr)
		return;
	class inpcb_impl *ipnxt;
	for (; ip != &tcb; ip = ipnxt) {
		ipnxt = dynamic_cast<inpcb_impl*>(ip->inp_next);
		class L4_TCP::tcpcb *tp(L4_TCP::tcpcb::intotcpcb(ip));
		if (tp == nullptr || tp->t_state == L4_TCP::tcpcb::TCPS_LISTEN)
			continue;
		for (size_t i = 0; i < TCPT_NTIMERS; i++) 
			if (tp->t_timer[i] && --tp->t_timer[i] == 0) {
				(void)pr_usrreq(dynamic_cast<socket*>(tp->t_inpcb->inp_socket), PRU_SLOWTIMO, std::shared_ptr<std::vector<byte>>(nullptr), reinterpret_cast<struct sockaddr *>(i), sizeof(i), std::shared_ptr<std::vector<byte>>(nullptr));

				/*
				*	Check If TCP control block has been deleted:
				*	Before examining the timers for a control block, a pointer to the next Internet PCB is
				*	saved in ipnxt. Each time the PRU_SLOWTIMO request returns, tcp_slowtirno checks
				*	whether the next PCB in the TCP list still points to the PCB that's being processed. If
				*	not, it means the control block has been deleted-perhaps the 2MSL timer expired or
				*	the retransmission timer expired and TCP is giving up on this connection-causing a
				*	jump to tpgone, skipping the remaining timers for this control block, and moving on to
				*	the next PCB.
				*/
				if (ipnxt->inp_prev != ip)
					goto tpgone;
			}
		
		/*
		*	Count Idle time:
		*	t_idle is incremented for the control block. This counts the number of 500-ms
		*	clock ticks since the last segment was received on this connection. It is set to 0 by
		*	tcp_input when a segment is received on the connection and used for three purposes:
		*		(1)	by the keepalive algorithm to send a probe after the connection is idle for 2 hours,
		*		(2)	to drop a connection in the FIN_WAIT_2 state that is idle for 10 minutes and 75 seconds, and
		*		(3)	by tcp_output to return to the slow start algorithm after the connection has
		*			been idle for a while.
		*/
		tp->t_idle++;

		/*
		*	Increment RTT counter:
		*	If this connection is timing an outstanding segment, t_rtt is nonzero and counts
		*	the number of 500-ms clock ticks until that segment is acknowledged. It is initialized to
		*	1 by tcp_output when a segment is transmitted whose KIT should be timed.
		*	tcp_slowtimo increments this counter.
		*/
		if (tp->t_rtt)
			tp->t_rtt++;
	tpgone:
		;
	}

	/*
	*	Increment initial send sequence number:
	*	tcp_iss was initialized to 1 by tcp_ini t. Every 500 ms it is incremented by
	*	64,000: 128,000 (TCP ISSINCR) divided by 2 (PR_SLOWHZ). This is a rate of about once
	*	every 8 microseconds, although tcp_iss is incremented only twice a second. We'll see
	*	that tcp_iss is also incremented by 64,000 each time a connection is established, either
	*	actively or passively.
	*		Remark:	RFC 793 specifies that the initial sequence number should increment roughly every 4 microseconds,
	*				or 250,000 times a second. The Net/3 value increments at about one-half this rate.
	*/
	TCP_ISSINCR(PR_SLOWHZ);	/* increment iss */

	/*
	*	Increment RFC 1323 timestamp value:
	*	tcp_now is initialized to 0 on bootstrap and incremented every 500 ms. It is used
	*	by the timestamp option defined in RFC 1323 [Jacobson, Braden, and Borman 1992),
	*	which we describe in Section 26.6.
	*/
	tcp_now++;	/* for timestamps */
}

/************************************************************************/
/*				  L4_TCP_impl pr_usrreq						            */
/************************************************************************/

int L4_TCP_impl::pr_usrreq(class netlab::L5_socket *so, int req, std::shared_ptr<std::vector<byte>> &m,
struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) {
	/*
	*	Control Information Is Invalid
	*	A call to sendmsg specifying control information is invalid for a TCP socket. If this
	*	happens, the mbufs are released and EINVAL is returned.
	*/
	if (control)
		return (EINVAL);

	/*
	*	This remainder of the function executes at splnet. This is overly conservative
	*	locking to avoid sprinkling the individual case statements with calls to splnet when
	*	the calls are really necessary. As we mentioned with Figure 23.15, setting the processor
	*	priority to splnet only stops a software interrupt from causing the IP input routine to
	*	be executed (which could call tcp_input). It does not prevent the interface layer from
	*	accepting incoming packets and placing them onto IP's input queue.
	*	The pointer to the Internet PCB is obtained from the socket structure pointer. The
	*	only time the resulting PCB pointer is allowed to be a null pointer is when the
	*	PRU_ATTACH request is issued, which occurs in response to the socket system call.
	*/
	class inpcb *inp(so->so_pcb);

	/*
	*	If inp is nonnull, the current connection state is saved in ostate for the call to
	*	tcp_trace at the end of the function.
	*
	* When a TCP is attached to a socket, then there will be
	* a (struct inpcb) pointed at by the socket, and this
	* structure will point at a subsidary (struct L4_TCP::tcpcb).
	*/
	if (inp == nullptr && req != PRU_ATTACH)
		return (EINVAL);		/* XXX */

	class L4_TCP::tcpcb *tp(nullptr);
	int ostate(0);
	/*!
		\bug
		WHAT IF TP IS 0?
	*/
	if (inp && (tp = L4_TCP::tcpcb::intotcpcb(inp)))
		ostate = tp->t_state;

	int error(0);
	switch (req) {

		/*
		* TCP attaches to socket via PRU_ATTACH, reserving space,
		* and an internet control block.
		*/
	case PRU_ATTACH:
		if (inp) {
			error = EISCONN;
			break;
		}
		if (error = tcp_attach(*dynamic_cast<socket*>(so)))
			break;
		if ((so->so_options & SO_LINGER) && so->so_linger == 0)
			so->so_linger = TCP_LINGERTIME;
		tp = L4_TCP::tcpcb::sototcpcb(dynamic_cast<socket*>(so));
		break;

		/*
		* PRU_DETACH detaches the TCP protocol from the socket.
		* If the protocol state is non-embryonic, then can't
		* do this directly: have to initiate a PRU_DISCONNECT,
		* which may finish later; embryonic TCB's can just
		* be discarded here.
		*/
	case PRU_DETACH:
		if (tp && tp->t_state > L4_TCP::tcpcb::TCPS_LISTEN)
			tp = tcp_disconnect(*tp);
		else
			tp = tcp_close(*tp);
		break;

		/*
		* Give the socket an address.
		*/
	case PRU_BIND:
		if (error = inp->in_pcbbind(reinterpret_cast<struct sockaddr_in *>(nam), nam_len))
			break;
		break;

		/*
		* Prepare to accept connections.
		*/
	case PRU_LISTEN:
		if (inp->inp_lport() == 0)
			error = inp->in_pcbbind(nullptr, 0);
		if (error == 0)
			tp->t_state = L4_TCP::tcpcb::TCPS_LISTEN;
		break;

		/*
		* Initiate connection to peer.
		* Create a template for use in transmissions on this connection.
		* Enter SYN_SENT state, and mark socket as connecting.
		* Start keep-alive timer, and seed output sequence space.
		* Send initial segment on connection.
		*/
	case PRU_CONNECT:
		if (inp->inp_lport() == 0)
			if (error = inp->in_pcbbind(nullptr, 0))
				break;
		if (error = inp->in_pcbconnect(reinterpret_cast<sockaddr_in *>(const_cast<struct sockaddr *>(nam)), nam_len))
			break;
		tp->tcp_template();
		if (tp->t_template == 0) {
			inp->in_pcbdisconnect();
			error = ENOBUFS;
			break;
		}
		/* Compute window scaling to request.  */
		while (tp->request_r_scale < TCP_MAX_WINSHIFT && static_cast<u_long>(TCP_MAXWIN << tp->request_r_scale) < dynamic_cast<socket*>(so)->so_rcv.capacity())
			tp->request_r_scale++;
		dynamic_cast<socket*>(so)->soisconnecting();
		tp->t_state = L4_TCP::tcpcb::TCPS_SYN_SENT;
		tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
		tp->iss = tcp_iss;
		TCP_ISSINCR();
		tp->tcp_sendseqinit();
		error = tcp_output(*tp);
		break;

		/*
		* Create a TCP connection between two sockets.
		*/
	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

		/*
		* Initiate disconnect from peer.
		* If connection never passed embryonic stage, just drop;
		* else if don't need to let data drain, then can just drop anyways,
		* else have to begin TCP shutdown process: mark socket disconnecting,
		* drain unread data, state switch to reflect user close, and
		* send segment (e.g. FIN) to peer.  Socket will be really disconnected
		* when peer sends FIN and acks ours.
		*
		* SHOULD IMPLEMENT LATER PRU_CONNECT VIA REALLOC L4_TCP::tcpcb.
		*/
	case PRU_DISCONNECT:
		tp = tcp_disconnect(*tp);
		break;

		/*
		* Accept a connection.  Essentially all the work is
		* done at higher levels; just return the address
		* of the peer, storing through addr.
		*/
	case PRU_ACCEPT:
		inp->in_setpeeraddr(reinterpret_cast<struct sockaddr_in *>(nam), nam_len);
		break;

		/*
		* Mark the connection as being incapable of further output.
		*/
	case PRU_SHUTDOWN:
		dynamic_cast<socket*>(so)->socantsendmore();
		tcp_usrclosed(*tp);
		if (tp)
			error = tcp_output(*tp);
		break;

		/*
		* After a receive, possibly send window update to peer.
		*/
	case PRU_RCVD:
		(void)tcp_output(*tp);
		break;

		/*
		* Do a send by putting data in output queue and updating urgent
		* marker if URG set.  Possibly send more data.
		*/
	case PRU_SEND:
		dynamic_cast<socket*>(so)->so_snd.sbappend(m->begin(), m->end());
		error = tcp_output(*tp);
		break;

		/*
		* Abort the TCP.
		*/
	case PRU_ABORT:
		tcp_drop(*tp, ECONNABORTED);
		break;

	case PRU_SENSE:
		return (0);

	case PRU_RCVOOB:
		if ((so->so_oobmark == 0 &&
			(so->so_state & socket::SS_RCVATMARK) == 0) ||
			so->so_options & SO_OOBINLINE ||
			tp->t_oobflags & L4_TCP::tcpcb::TCPOOB_HADDATA)
		{
			error = EINVAL;
			break;
		}
		if ((tp->t_oobflags & L4_TCP::tcpcb::TCPOOB_HAVEDATA) == 0) {
			error = EWOULDBLOCK;
			break;
		}

		m.reset(new std::vector<byte>(tp->t_iobc));

		if ((reinterpret_cast<int>(nam)& MSG_PEEK) == 0)
			tp->t_oobflags ^= (L4_TCP::tcpcb::TCPOOB_HAVEDATA | L4_TCP::tcpcb::TCPOOB_HADDATA);
		break;

	case PRU_SENDOOB:
		if (dynamic_cast<socket*>(so)->so_snd.sbspace() < -512) {
			error = ENOBUFS;
			break;
		}

		/*
		* According to RFC961 (Assigned Protocols),
		* the urgent pointer points to the last octet
		* of urgent data.  We continue, however,
		* to consider it to indicate the first octet
		* of data past the urgent section.
		* Otherwise, snd_up should be one lower.
		*/
		dynamic_cast<socket*>(so)->so_snd.sbappend(m->begin(), m->end());
		tp->snd_up = tp->snd_una + dynamic_cast<socket*>(so)->so_snd.size();
		tp->t_force = 1;
		error = tcp_output(*tp);
		tp->t_force = 0;
		break;

	case PRU_SOCKADDR:
		//in_setsockaddr(inp, nam);
		break;

	case PRU_PEERADDR:
		//in_setpeeraddr(inp, nam);
		break;

		/*
		* TCP slow timer went off; going through this
		* routine for tracing's sake.
		*/
	case PRU_SLOWTIMO:
		tp = tcp_timers(tp, reinterpret_cast<int>(nam));
		req |= reinterpret_cast<int>(nam) << 8;		/* for debug's sake */
		break;

	default:
		throw std::runtime_error("panic(''tcp_usrreq'')");
		break;
	}
	return (error);
}

int L4_TCP_impl::tcp_attach(socket &so)
{	
	/*	
	 *	Allocate space for send buffer and receive buffer:
	 *	If space has not been allocated for the socket's send and receive buffers,
	 *	sbreserve sets them both to 8192, the default values of the global variables
	 *	tcp_sendspace and tcp_recvspace (Figure 24.3).
	 *	Whether these defaults are adequate depends on the MSS for each direction of the connection,
	 *	which depends on the MTU. For example, [Comer and Lin 1994] show that anomalous behavior
	 *	occurs if the send buffer is less than three times the MSS, which drastically reduces performance.
	 *	Some implementations have much higher defaults, such as 61,444 bytes, realizing the
	 *	effect these defaults have on performance, especially with higher MTUs (e.g., FOOi and ATM).
	 */
	int error;
	if ((dynamic_cast<socket*>(&so)->so_snd.capacity() == 0 || dynamic_cast<socket*>(&so)->so_rcv.capacity() == 0) &&
		(error = dynamic_cast<socket*>(&so)->soreserve(tcp_sendspace, tcp_recvspace)))
		return (error);

	/*	
	 *	Allocate Internet PCB and TCP control block:
	 *	inpcb allocates an Internet PCB and tcp_newtcpcb allocates a TCP control
	 *	block and links it to the PCB.
	 */
	class L4_TCP::tcpcb *tp(tcp_newtcpcb(*dynamic_cast<socket*>(&so)));

	/*	
	 *	The code with the comment xxx is executed if the allocation in
	 *	tcp_newtcpcb fails. Remember that the PRU_ATTACH request is issued as a result of
	 *	the socket system call, and when a connection request arrives for a listening socket
	 *	(sonewconn). In the latter case the socket flag SS_NOFDREF is set. If this flag is left on,
	 *	the call to sofree by in_pcbdetach releases the socket structure. As we saw in
	 *	tcp_input, this structure should not be released until that function is done with the
	 *	received segment (the dropsocket flag in Figure 29.27). Therefore the current value of
	 *	the SS_NOFDREF flag is saved in the variable nofd when in_pcbdetach is called, and
	 *	reset before tcp_attach returns.
	 */
	if (tp == nullptr) {
		const int nofd(so.so_state & socket::SS_NOFDREF);	/* XXX */
		so.so_state &= ~socket::SS_NOFDREF;	/* don't free the socket yet */
		so.so_state |= nofd;
		return (ENOBUFS);
	}

	/*	
	 *	The TCP connection state is initialized to CLOSED.
	 */
	tp->t_state = L4_TCP::tcpcb::TCPS_CLOSED;
	return (0);
}

class L4_TCP::tcpcb* L4_TCP_impl::tcp_newtcpcb(socket &so)
{
	class L4_TCP::tcpcb *tp(new L4_TCP::tcpcb(so, tcb));
	 /*
	*	The two variables seg_next and seg_prev point to the reassembly queue for out-of-order
	*	segments received for this connection. We discuss this queue in detail in Section 27.9.
	*/
	tp->seg_next = tp->seg_prev = reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp);

	/*
	*	The maximum segment size to send, t_maxseg, defaults to 512 (tcp_mssdflt).
	*	This value can be changed by the tcp_mss function after an MSS option is received
	*	from the other end. (TCP also sends an MSS option to the other end when a new connection
	*	is established.) The two flags TF REQ_SCALE and TF_REQ_TSTMP are set if the
	*	system is configured to request window scaling and timestamps as defined in RFC 1323
	*	(the global tcp_do_rfc1323 from Figure 24.3, which defaults to 1). The t_inpcb
	*	pointer in the TCP control block is set to point to the Internet PCB passed in by the
	*	caller.
	*/
	tp->t_maxseg = tcp_mssdflt;
	tp->t_flags = tcp_do_rfc1323 ?
		(L4_TCP::tcpcb::TF_REQ_SCALE | L4_TCP::tcpcb::TF_REQ_TSTMP) :
		0;
	
	if (tp->t_inpcb == nullptr)
		tp->t_inpcb = dynamic_cast<class inpcb_impl *>(tp);

	/*
	*	The four variables t_srtt, t_rttvar, t_rttmin, and t_rxtcur, described in
	*	Figure 25.19, are initialized. First, the smoothed RTT estimator t_srtt is set to 0
	*	(TCPTV_SRTTBASE), which is a special value that means no RTT measurements have
	*	been made yet for this connection. tcp_xmit_timer recognizes this special value
	*	when the first RTT measurement is made.
	*
	* Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	* rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
	* reasonable initial retransmit time.
	*/
	tp->t_srtt = TCPTV_SRTTBASE;

	/*
	*	The smoothed mean deviation estimator t_rttvar is set to 24: 3 (tcp_rttdflt,
	*	from Figure 24.3) times 2 (PR_SLOWHZ) multiplied by 4 (the left shift of 2 bits). Since
	*	this scaled estimator is 4 times the variable rttvar, this value equals 6 clock ticks, or 3
	*	seconds. The minimum RTO, stored in t_rttmin, is 2 ticks (TCPTV MIN).
	*/
	tp->t_rttvar = tcp_rttdflt * PR_SLOWHZ << 2;
	tp->t_rttmin = TCPTV_MIN;

	/*
	*	The current RTO in clock ticks is calculated and stored in t_rxtcur. It is bounded
	*	by a minimum value of 2 ticks (TCPTV_MIN) and a maximum value of 128 ticks
	*	(TCPTV_REXMTMAX). The value calculated as the second argument to TCPT_RANGESET
	*	is 12 ticks, or 6 seconds. This is the first RTO for the connection.
	*	Understanding these C expressions involving the scaled RIT estimators can be a
	*	challenge. It helps to start with the unscaled equation and substitute the scaled variables.
	*	The unscaled equation we're solving is
	*			RTO = srtt + 2*rttvar
	*	where we use the multiplier of 2 instead of 4 to calculate the first RTO.
	*		Remark:	The use of the multiplier 2 instead of 4 appears to be a leftover from the original 4.3850 Tahoe
	*		code (Paxson 1994).
	*	Substituting the two scaling relationships
	*			t_srtt = 8 * srtt
	*			t_rttvar = 4 * rttvar
	*	We get
	*			RTO = t_srtt / 8 + 2 * t_rttvar / 4 = (t_srtt / 8 + t_rttvar) / 2
	*	which is the C code for the second argument to TCPT_RANGESET. In this code the variable
	*	t_rttvar is not used-the constant TCPTV_SRTTDFLT, whose value is 6 ticks, is
	*	used instead, and it must be multiplied by 4 to have the same scale as t_rttvar.
	*/
	TCPT_RANGESET(
		tp->t_rxtcur,
		((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
		TCPTV_MIN,
		TCPTV_REXMTMAX);

	/*
	*	The congestion window (snd_cwnd) and slow start threshold (snd_ssthresh) are
	*	set to l,073,725MO (approximately one gigabyte), which is the largest possible TCP
	*	window if the window scale option is in effect. (Slow start and congestion avoidance
	*	are described in Section 21.6 of Volume 1.) It is calculated as the maximum value for the
	*	window size field in the TCP header (65535, TCP MAXWIN) times 214, where 14 is the
	*	maximum value for the window scale factor (TCP J4AX_WINSHIFT). We'll see that
	*	when a SYN is sent or received on the connection, tcp_rnss resets snd_cwnd to a single
	*	segment.
	*/
	tp->log_snd_cwnd(tp->snd_cwnd = tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT);

	/*
	*	The default IP TTL in the Internet PCB is set to 64 (ip_defttl) and the PCB is set
	*	to point to the new TCP control block.
	*	Not shown in this code is that numerous variables, such as the shift variable
	*	t_rxtshift, are implicitly initialized to 0 since the control block is initialized by
	*	bzero.
	*/
	tp->t_inpcb->inp_ip.ip_ttl = L3_impl::IPDEFTTL;
	tp->t_inpcb->inp_ppcb = dynamic_cast<class inpcb_impl *>(tp);
	return tp;
}

class L4_TCP::tcpcb* L4_TCP_impl::tcp_timers(class L4_TCP::tcpcb *tp, int timer)	
{
	switch (timer) {

		/*	
		 *	FIN_WAIT_2 and 2MSL Timers:
		*	TCP's TCPT_2MSL counter implements two of TCP's timers.
		*		1.	FIN_WAIT_2 timer. When tcp_input moves from the FIN_WAIT_l state to
		*			the FIN_ WAIT_2 state and the socket cannot receive any more data (implying
		*			the process called close, instead of taking advantage of TCP's half-close with
		*			shutdown), the FIN_WAIT_2 timer is set to 10 minutes (tcp_maxidle). We'll
		*			see that this prevents the connection from staying in the FIN_WAIT_2 state forever.
		*		2.	2MSL timer. When TCP enters the TWE_WAIT state, the 2MSL timer is set to
		*			60 seconds (TCPTV_MSL times 2).
		*
		*	2MSL timer
		*	The puzzling logic in the conditional is because the two different uses of the
		*	TCPT_2MSL counter are intermixed (Exercise 25.4). Let's first look at the TIME_WAIT
		*	state. When the timer expires after 60 seconds, tcp_close is called and the control
		*	blocks are released. We have the scenario shown in Figure 25.11. This figure shows the
		*	series of function calls that occurs when the 2MSL timer expires. We also see that setting
		*	one of the timers for N seconds in the future (2 x N ticks), causes the timer to expire
		*	somewhere between 2 x N - 1 and 2 x N ticks in the future, since the time until the first
		*	decrement of the counter is between 0 and 500 ms in the future.
		*
		*	FIN_WAIT_2 timer:
		*	If the connection state is not TIME_ WAIT, the TCPT_2MSL counter is the
		*	FIN_WAIT_2 timer. As soon as the connection has been idle for more than 10 minutes
		*	(tcp_maxidle) the connection is dosed. But if the connection has been idle for less
		*	than or equal to 10 minutes, the FIN_WAIT_2 timer is reset for 75 seconds in the future.
		*	Figure 25.12 shows the typical scenario.
		*
		* 2 MSL timeout in shutdown went off.  If we're closed but
		* still waiting for peer to close and connection has been idle
		* too long, or if 2MSL time is up from TIME_WAIT, delete connection
		* control block.  Otherwise, check again in a bit.
		*/
	case TCPT_2MSL:
		if (tp->t_state != L4_TCP::tcpcb::TCPS_TIME_WAIT && tp->t_idle <= tcp_maxidle)
			tp->t_timer[TCPT_2MSL] = tcp_keepintvl;
		else
			tp = tcp_close(*tp);
		break;

		/*
		* Retransmission timer went off.  Message has not
		* been acked within retransmit interval.  Back off
		* to a longer retransmit interval and retransmit one segment.
		*/
	case TCPT_REXMT:
		if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
			tp->t_rxtshift = TCP_MAXRXTSHIFT;
			tcp_drop(*tp, tp->t_softerror ? tp->t_softerror : ETIMEDOUT);
			break;
		}

		TCPT_RANGESET(tp->t_rxtcur, static_cast<int>(tp->TCP_REXMTVAL() * tcp_backoff(tp->t_rxtshift)),
			tp->t_rttmin, static_cast<int>(TCPTV_REXMTMAX));
		tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
		
		/*
		* If losing, let the lower level know and try for
		* a better route.  Also, if we backed off this far,
		* our srtt estimate is probably bogus.  Clobber it
		* so we'll take the next rtt measurement as our srtt;
		* move the current srtt into rttvar to keep the current
		* retransmit times until then.
		*/
		if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
			tp->t_inpcb->in_losing();
			tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
			tp->t_srtt = 0;
		}
		
		tp->snd_nxt = tp->snd_una;
		
		/*
		* If timing a segment in this window, stop the timer.
		*/
		tp->t_rtt = 0;
		
		/*
		* Close the congestion window down to one segment
		* (we'll open it by one segment for each ack we get).
		* Since we probably have a window's worth of unacked
		* data accumulated, this "slow start" keeps us from
		* dumping all that data as back-to-back packets (which
		* might overwhelm an intermediate gateway).
		*
		* There are two phases to the opening: Initially we
		* open by one mss on each ack.  This makes the window
		* size increase exponentially with time.  If the
		* window is larger than the path can handle, this
		* exponential growth results in dropped packet(s)
		* almost immediately.  To get more time between
		* drops but still "push" the network to take advantage
		* of improving conditions, we switch from exponential
		* to linear window opening at some threshhold size.
		* For a threshhold, we use half the current window
		* size, truncated to a multiple of the mss.
		*
		* (the minimum cwnd that will give us exponential
		* growth is 2 mss.  We don't allow the threshhold
		* to go below this.)
		*/
		{
			u_int win(std::min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg);
			if (win < 2)
				win = 2;
			tp->log_snd_cwnd(tp->snd_cwnd = tp->t_maxseg);
			tp->snd_ssthresh = win * tp->t_maxseg;
			tp->t_dupacks = 0;
		}

		(void)tcp_output(*tp);
		break;

		/*
		*	Persist Timer:
		*	Force window probe segment:
		*	When the persist timer expires, there is data to send on the connection but TCP has
		*	been stopped by the other end's advertisement of a zero-sized window.
		*	tcp_setpersist calculates the next value for the persist timer and stores it in the
		*	TCPT_PERSIST counter. The flag t_force is set to 1, forcing tcp_output to send 1
		*	byte, even though the window advertised by the other end is 0.
		*
		* Persistence timer into zero window.
		* Force a byte to be output, if possible.
		*/
	case TCPT_PERSIST:
		/*
		* Hack: if the peer is dead/unreachable, we do not
		* time out if the window is closed.  After a full
		* backoff, drop the connection if the idle time
		* (no responses to probes) reaches the maximum
		* backoff that we would use if retransmitting.
		*/
		if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
			(tp->t_idle >= tcp_maxpersistidle || tp->t_idle >= tp->TCP_REXMTVAL() * tcp_totbackoff)) {
			tcp_drop(*tp, ETIMEDOUT);
			break;
		}

		tcp_setpersist(*tp);
		tp->t_force = 1;
		(void)tcp_output(*tp);
		tp->t_force = 0;
		break;

		/*
		*	Connection Establishment and keepalive Timers
		*	TCP's TCPT_KEEP counter implements two timers:
		*		1.	When a SYN is sent, the connection-establishment timer is set to 75 seconds
		*			(TCPTV KEEP INIT). This happens when connect is called, putting a connection
		*			into the SYN_SENT state (active open), or when a connection moves from
		*			the LISTEN to the SYN_RCVD state (passive open). If the connection doesn't
		*			enter the ESTABLISHED state within 75 seconds, the connection is dropped.
		*		2.	When a segment is received on a connection, tcp_input resets the keepalive
		*			timer for that connection to 2 hours (tcp_keepidle), and the t_idle counter
		*			for the connection is reset to 0. This happens for every TCP connection on the
		*			system, whether the keepalive option is enabled for the socket or not. If the
		*			keepalive timer expires (2 hours after the last segment was received on the connection),
		*			and if the socket option is set, a keepalive probe is sent to the other
		*			end. If the timer expires and the socket option is not set, the keepalive timer is
		*			just reset for 2 hours in the future.
		*	Figure 25.16 shows the case for TCP's TCPT_KEEP counter.
		*
		*	Connection-establishment timer expires after 75 seconds:
		*	If the state is less than ESTABLISHED (Figure 24.16), the TCPT_KEEP counter is the
		*	connection-establishment timer. At the label dropit, tcp_drop is called to terminate
		*	the connection attempt with an error of ETIMEOOUT. We'll see that this error is the
		*	default error-if, for example, a soft error such as an ICMP host unreachable was
		*	received on the connection, the error returned to the process will be changed to
		*	EHOSTUNREACH instead of the default.
		*
		* Keep-alive timer went off; send something
		* or drop connection if idle for too long.
		*/
	case TCPT_KEEP:
		if (tp->t_state < L4_TCP::tcpcb::TCPS_ESTABLISHED) {
			tcp_drop(*tp, ETIMEDOUT);
			break;
		}

		/*
		*	Keepalive timer expires after 2 hours of Idle time
		*	This timer expires after 2 hours of idle time on every connection, not just ones with
		*	the SOKEEPALIVE socket option enabled. If the socket option is set, probes are sent
		*	only if the connection is in the ESTABLISHED or CLOSE_WAIT states (Figure 24.15).
		*	Once the process calls close (the states greater than CLOSE_WAIT), keepalive probes
		*	are not sent, even if the connection is idle for 2 hours.
		*/
		if (tp->t_inpcb->inp_socket->so_options & SO_KEEPALIVE &&
			tp->t_state <= L4_TCP::tcpcb::TCPS_CLOSE_WAIT) {

			/*
			*	Drop connection when no response:
			*	If the total idle time for the connection is greater than or equal to 2 hours
			*	(tcp_keepidle) plus 10 minutes (tcp_maxidle}, the connection is dropped. This
			*	means that TCP has sent its limit of nine keepalive probes, 75 seconds apart
			*	(tcp_keepintvl), with no response. One reason TCP must send multiple keepalive
			*	probes before considering the connection dead is that the ACKs sent in response do not
			*	contain data and therefore are not reliably transmitted by TCP. An ACK that is a
			*	response to a keepalive probe can get lost.
			*/
			if (tp->t_idle >= tcp_keepidle + tcp_maxidle) {
				tcp_drop(*tp, ETIMEDOUT);
				break;
			}

			/*
			*	Send a keepalive probe:
			*	If TCP hasn't reached the keepalive limit, tcp_respond sends a keepalive packet.
			*	The acknowledgment field of the keepalive packet (the fourth argument to
			*	tcp_respond) contains rcv _nxt, the next sequence number expected on the connection.
			*	The sequence number field of the keepalive packet (the fifth argument) deliberately
			*	contains snd_una minus l, which is the sequence number of a byte of data that
			*	the other end has already acknowledged (Figure 24.17). Since this sequence number is
			*	outside the lvi.ndow, the other end must respond with an ACK, specifying the next
			*	sequence number it expects.
			*
			* Send a packet designed to force a response
			* if the peer is up and reachable:
			* either an ACK if the connection is still alive,
			* or an RST if the peer has closed the connection
			* due to timeout or reboot.
			* Using sequence number tp->snd_una-1
			* causes the transmitted zero-length segment
			* to lie outside the receive window;
			* by the protocol spec, this requires the
			* correspondent TCP to respond.
			*/
			tcp_respond(tp, tp->t_template, nullptr, std::vector<byte>::iterator(), tp->rcv_nxt, tp->snd_una - 1, 0);
			tp->t_timer[TCPT_KEEP] = tcp_keepintvl;
		}

		/*
		*	Reset keepalive timer
		*	If the socket option is not set or the connection state is greater than CLOSE_WAIT,
		*	the keepalive timer for this connection is reset to 2 hours (tcp_keepidle).
		*		Remark:	Unfortunately the counter tcps_keepdrops (line 253) counts both uses of the TCPT_KEEP
		*				counter: the connection-establishment timer and the keepalive timer.
		*/
		else
			tp->t_timer[TCPT_KEEP] = tcp_keepidle;
		break;
	}
	return (tp);
}

inline void L4_TCP_impl::tcp_setpersist(class L4_TCP::tcpcb &tp)
{
	if (tp.t_timer[TCPT_REXMT])
		throw std::runtime_error("tcp_output REXMT");
	/*
	* Start/restart persistence timer.
	*/
	TCPT_RANGESET(
		tp.t_timer[TCPT_PERSIST],
		(((tp.t_srtt >> 2) + tp.t_rttvar) >> 1) * tcp_backoff(tp.t_rxtshift),
		TCPTV_PERSMIN,
		TCPTV_PERSMAX);
	if (tp.t_rxtshift < TCP_MAXRXTSHIFT)
		tp.t_rxtshift++;
}

int L4_TCP_impl::tcp_backoff(const int backoff)
{
	if (0 <= backoff && backoff <= 5)
		return 0x1 << backoff;
	else if (6 <= backoff && backoff <= TCP_MAXRXTSHIFT)
		return 64;
	return 0;
}

class L4_TCP::tcpcb* L4_TCP_impl::tcp_disconnect(class L4_TCP::tcpcb &tp) 
{
	socket *so(dynamic_cast<socket*>(tp.t_inpcb->inp_socket));
	if (tp.t_state < L4_TCP::tcpcb::TCPS_ESTABLISHED)
		tcp_close(tp);
	else if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		tcp_drop(tp, 0);
	else {
		so->soisdisconnecting();
		so->so_rcv.sbflush();
		tcp_usrclosed(tp);
		if (&tp)
			(void)tcp_output(tp);
	}
	return (&tp);
}

void L4_TCP_impl::tcp_usrclosed(class L4_TCP::tcpcb &tp) 
{
	switch (tp.t_state) {

	case L4_TCP::tcpcb::TCPS_CLOSED:
	case L4_TCP::tcpcb::TCPS_LISTEN:
	case L4_TCP::tcpcb::TCPS_SYN_SENT:
		tp.t_state = L4_TCP::tcpcb::TCPS_CLOSED;
		tcp_close(tp);
		break;

	case L4_TCP::tcpcb::TCPS_SYN_RECEIVED:
	case L4_TCP::tcpcb::TCPS_ESTABLISHED:
		tp.t_state = L4_TCP::tcpcb::TCPS_FIN_WAIT_1;
		break;

	case L4_TCP::tcpcb::TCPS_CLOSE_WAIT:
		tp.t_state = L4_TCP::tcpcb::TCPS_LAST_ACK;
		break;
	}
	if (&tp && tp.t_state >= L4_TCP::tcpcb::TCPS_FIN_WAIT_2)
		dynamic_cast<socket*>(tp.t_inpcb->inp_socket)->soisdisconnected();
	
	return;
}

void L4_TCP_impl::tcp_drop(class L4_TCP::tcpcb &tp, const int err)
{
	if (tp.t_inpcb)	{
		socket *so(dynamic_cast<socket*>(tp.t_inpcb->inp_socket));

		/*
		*	If TCP has received a SYN, the connection is synchronized and an RST must be sent
		*	to the other end. This is done by setting the state to CLOSED and calling tcp_output.
		*	In Figure 24.16 the value of tcp_outflags for the CLOSED state includes the RST flag.
		*/
		if (tp.TCPS_HAVERCVDSYN()) {
			tp.t_state = L4_TCP::tcpcb::TCPS_CLOSED;
			(void)tcp_output(tp);
		}

		/*
		*	If the error is ETIMEDOUT but a soft error was received on the connection (e.g.,
		*	EHOSTUNREACH), the soft error becomes the socket error, instead of the less specific
		*	ETIMEDOUT.
		*/
		int newErr(err);
		if (newErr == ETIMEDOUT && tp.t_softerror)
			newErr = tp.t_softerror;
		so->so_error = newErr;

		/*	tcp_close finishes closing the socket.	*/
		return (void)tcp_close(tp);
	}
}

class L4_TCP::tcpcb* L4_TCP_impl::tcp_close(class L4_TCP::tcpcb &tp)
{
	/*
	*	Check If enough data sent to update statistics
	*	The default send buffer size is 8192 bytes (sb_hiwat), so the first test is whether
	*	131,072 bytes (16 full buffers) have been transferred across the connection. The initial
	*	send sequence number is compared to the maximum sequence number sent on the connection.
	*	Additionally, the socket must have a cached route and that route cannot be the
	*	default route. (See Exercise 19.2.)
	*		Remark:	Notice there is a small chance for an error in the first test, because of sequence number wrap, if
	*				the amount of data transferred is within N x 232 and N x 232 + 131072, for any N greater than 1.
	*				But few connections (today) transfer 4 gigabytes of data.
	*				Despite the prevalence of default routes in the Internet, this information is still useful to maintain
	*				in the routing table. If a host continuaJJy exchanges data with another host (or network),
	*				even if a default route can be used, a host-specific or network-specific route can be entered into
	*				the routing table with the route command just to maintain this information access connections.
	*				(See Exercise 19.2.) This information is lost when the system is rebooted.
	*
	* If we sent enough data to get some meaningful characteristics,
	* save them in the routing entry.  'Enough' is arbitrarily
	* defined as the sendpipesize (default 4K) * 16.  This would
	* give us 16 rtt samples assuming we only get one sample per
	* window (the usual case on a long haul net).  16 samples is
	* enough for the srtt filter to converge to within 5% of the correct
	* value; fewer samples and we could save a very bogus rtt.
	*
	* Don't update the default route's characteristics and don't
	* update anything that the user "locked".
	*/
	class inpcb_impl *inp(tp.t_inpcb);
	struct L3::rtentry *rt;
	socket *so(dynamic_cast<socket*>(inp->inp_socket));

	if (L4_TCP::tcpcb::SEQ_LT(tp.iss + dynamic_cast<socket*>(so)->so_snd.capacity() * 16, tp.snd_max) &&
		(rt = inp->inp_route.ro_rt) &&
		reinterpret_cast<struct sockaddr_in *>(rt->rt_key())->sin_addr.s_addr != INADDR_ANY)
	{
		u_long i(0);
		if ((rt->rt_rmx.rmx_locks & L3::rtentry::RTV_RTT) == 0)
			rt->rt_rmx.rmx_rtt =
			(rt->rt_rmx.rmx_rtt &&
			(i = tp.t_srtt * (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTT_SCALE)))) ?
			/*
			* filter this update to half the old & half
			* the new values, converting scale.
			* See route.h and tcp_var.h for a
			* description of the scaling constants.
			*/
			(rt->rt_rmx.rmx_rtt + i) / 2 :
		i;
		if ((rt->rt_rmx.rmx_locks & L3::rtentry::RTV_RTTVAR) == 0)
			rt->rt_rmx.rmx_rttvar =
			(rt->rt_rmx.rmx_rttvar &&
			(i = tp.t_rttvar * (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTTVAR_SCALE)))) ?
			(rt->rt_rmx.rmx_rttvar + i) / 2 :
			i;

		/*
		* update the pipelimit (ssthresh) if it has been updated
		* already or if a pipesize was specified & the threshhold
		* got below half the pipesize.  I.e., wait for bad news
		* before we start updating, then update on both good
		* and bad news.
		*/
		if ((rt->rt_rmx.rmx_locks & L3::rtentry::RTV_SSTHRESH) == 0 &&
			(i = tp.snd_ssthresh) &&
			rt->rt_rmx.rmx_ssthresh ||
			i < (rt->rt_rmx.rmx_sendpipe / 2))
		{
			/*
			* convert the limit from user data bytes to
			* packets then to packet data bytes.
			*/
			if ((i = (i + tp.t_maxseg / 2) / tp.t_maxseg) < 2)
				i = 2;

			i *= static_cast<u_long>(tp.t_maxseg + sizeof(struct L4_TCP::tcpiphdr));

			rt->rt_rmx.rmx_ssthresh =
				rt->rt_rmx.rmx_ssthresh ?
				(rt->rt_rmx.rmx_ssthresh + i) / 2 :
				i;
		}
	}

	/* free the reassembly queue, if any */
	struct L4_TCP::tcpiphdr *t(tp.seg_next),
		*t_old;
	while (t)
	{
		t_old = t;
		t = t->ti_next();
		t_old->remque();
		delete t_old;
	}

	if (tp.t_template)
		delete tp.t_template;

	if (inp->inp_ppcb != inp) {
		delete inp->inp_ppcb;
		inp->inp_ppcb = nullptr;
	}

	dynamic_cast<socket*>(so)->soisdisconnected();

	/* clobber input pcb cache if we're closing the cached connection */
	if (inp == tcp_last_inpcb)
		tcp_last_inpcb = &tcb;

	delete inp;
	return nullptr;
}

/************************************************************************/
/*				  L4_TCP_impl pr_output						            */
/************************************************************************/

L4_TCP_impl::tcp_output_args::tcp_output_args(L4_TCP::tcpcb &tp) : tp(tp) { }

int L4_TCP_impl::pr_output(const struct pr_output_args &args) 
{
	return tcp_output(reinterpret_cast<const struct tcp_output_args*>(&args)->tp);
}

int L4_TCP_impl::tcp_output(class L4_TCP::tcpcb &tp) 
{
	/*
	*	Is an ACK expected from the other end?
	*	idle is true if the maximum sequence number sent (snd_max) equals the oldest
	*	unacknowledged sequence number (snd_una), that is, if an ACK is not expected from
	*	the other end.
	*
	* Determine length of data that should be transmitted,
	* and flags that will be used.
	* If there is some data or critical controls (SYN, RST)
	* to send, then transmit; otherwise, investigate further.
	*/
	bool idle(tp.snd_max == tp.snd_una);
	if (idle && tp.t_idle >= tp.t_rxtcur)

		/*	
		 *	Go back to slow start:
		 *	If an ACK is not expected from the other end and a segment has not been received
		 *	from the other end in one RTO, the congestion window is set to one segment
		 *	t_maxseg bytes). This forces slow start to occur for this connection the next time a
		 *	segment is sent. When a significant pause occurs in the data transmission ("significant"
		 *	being more than the RTf), the network conditions can change from what was previously
		 *	measured on the connection. Net/3 assumes the worst and returns to slow start.
		 *	
		* We have been idle for "a while" and no acks are
		* expected to clock out any data we send --
		* slow start to get ack "clock" running again.
		*/
		tp.log_snd_cwnd(tp.snd_cwnd = tp.t_maxseg);

	/*
	*	Send more than one segment:
	*	When send is jumped to, a single segment is sent by calling ip_output. But if
	*	tcp_output determines that more than one segment can be sent, sendalot is set to 1,
	*	and the function tries to send another segment. Therefore, one call to tcp_output can
	*	result in multiple segments being sent.
	*/
	return again(tp, idle, *dynamic_cast<socket*>(tp.t_inpcb->inp_socket));
}

int L4_TCP_impl::again(L4_TCP::tcpcb &tp, const bool idle, socket& so)
{
	/*	
	 *	Determine if a Segment Should be Sent:
	 *	Sometimes tcp_output is called but a segment is not generated. For example, the
	 *	PRU_RCVD request is generated when the socket layer removes data from the socket's
	 *	receive buffer, passing the data to a process. It is possible that the process removed
	 *	enough data that TCP should send a segment to the other end with a new window
	 *	advertisement, but this is just a possibility, not a certainty. The first half of tcp_output
	 *	determines if there is a reason to send a segment to the other end. If not, the function
	 *	returns without sending a segment.
	 *	
	 *	off is the offset in bytes from the beginning of the send buffer of the first data byte
	 *	to send. The first off bytes in the send buffer, starting with snd_una, have already
	 *	been sent and are waiting to be ACKed.
	 *		win is the minimum of the window advertised by the receiver (snd_wnd) and the
	 *	congestion window (snd_cwnd).
	 */
	int off(tp.snd_nxt - tp.snd_una);
	long win(std::min(tp.snd_wnd, tp.snd_cwnd));

	/* 
	 *	The value of tcp_outflags array that is fetched and stored in flags depends on the current
	 *	state of the connection. flags contains the combination of the TH_ACK, TH_FIN, TH_RST,
	 *	and TH_SYN flag bits to send to the other end.The other two flag bits, TH_PUSH and TH_URG,
	 *	will be logically ORed into flags if necessary before the segment is sent.
	 */
	int flags(tp.tcp_outflags());

	/*	
	 *	The flag t_force is set nonzero when the persist timer expires or when out-of-band
	 *	data is being sent. These two conditions invoke tcp_output as follows:
	 *		tp->t_force = l;
	 *		error = tcp_output(tp);
	 *		tp->t_force = O;
	 *	This forces TCP to send a segment when it normally wouldn't send anything.
	 *	
	* If in persist timeout with window of 0, send 1 byte.
	* Otherwise, if window is small but nonzero
	* and timer expired, we will send what we can
	* and go to transmit state.
	*/
	if (tp.t_force)
		/*	
		 *	If win is 0, the connection is in the persist state(since t_force is nonzero).
		 *	The FIN flag is cleared if there is more data in the socket's send buffer. 
		 *	win must be set to 1 byte to force out a single byte.
		 */
		if (win == 0) {

			/*
			* If we still have some data to send, then
			* clear the FIN bit.  Usually this would
			* happen below when it realizes that we
			* aren't sending all the data. However,
			* if we have exactly 1 byte of unset data,
			* then it won't clear the FIN bit below,
			* and if we are in persist state, we wind
			* up sending the packet without recording
			* that we sent the FIN bit.
			*
			* We can't just blindly clear the FIN bit,
			* because if we don't have any more data
			* to send then the probe will be the FIN
			* itself.
			*/
			if (off < static_cast<int>(so.so_snd.size()))
				flags &= ~tcphdr::TH_FIN;

			/*
			*	win must be set to 1 byte to force out a single byte.
			*/
			win = 1;
		}
		/*	
		 *	If win is nonzero, out-of-band data is being sent, so the persist timer is cleared and
		 *	the exponential backoff index, t_rxtshift, is set to 0.
		 */
		else {
			tp.t_timer[TCPT_PERSIST] = 0;
			tp.t_rxtshift = 0;
		}

	/*	
	 *	Calculate amount of data to send:
	 *	len is the minimum of the number of bytes in the send buffer and win (which is
	 *	the minimum of the receiver's advertised window and the congestion window, perhaps
	 *	1 byte if output is being forced). off is subtracted because that many bytes at the
	 *	beginning of the send buffer have already been sent and are awaiting acknowledgment.
	 */
	long len(std::min(static_cast<long>(so.so_snd.size()), win) - off);

	/*
	*	Check for window shrink:
	*	One way for len to be less than 0 occurs if the receiver shrinks the window, that is,
	*	the receiver moves the right edge of the window to the left. For example, assume that
	*	first the receiver advertises a window of 6 bytes and TCP transmits a segment with
	*	bytes 4, 5, and 6. TCP immediately transmits another segment with bytes 7, 8, and 9.
	*	Then an ACK is received with an acknowledgment field of 7 (acknowledging all data
	*	up through and including byte 6) but with a window of 1. The receiver has shrunk the
	*	window.
	*	Performing the calculations of tcp_output up to now, after the window is shrunk, we
	*	have:
	*		off = snd_nxt - snd_una = 10 - 7 = 3
	*		win = 1
	*		len = min<so_snd.sb_cc, win) - off * min(3, 1) - 3 = -2
	*	assuming the send buffer contains only bytes 7, 8, and 9.
	*		Remark:	Both RFC 793 and RFC 1122 strongly discourage shrinking the window. Nevertheless,
	*				implementations must be prepared for this. Handling scenarios such as this comes
	*				under the Robustness Principle, first mentioned in RFC 791:
	*					"Be liberal in what you accept, and conservative in what you send."
	*
	*	Another way for len to be less than 0 occurs if the FIN has been sent but not acknowledged
	*	and not retransmitted. We take the previous example, but assuming the final segment with
	*	bytes 7, 8, and 9 is acknowledged, which sets snd_una to 10. The process then doses the
	*	connection, causing the FIN to be sent. We'll see later that when the FIN is sent, snd_nxt
	*	is incremented by 1 (since the FIN takes a sequence number), which in this example sets
	*	snd_nxt to 11. The sequence number of the FIN is 10. Performing the calculations, we have
	*		off = snd_nxt - snd_una ~ 11 - 10 = 1
	*		win = 6
	*		len = min{so_snd.sb_cc, win) - off = rnin(O, 6) - 1 = -1
	*	We assume that the receiver advertises a window of 6, which makes no difference, since
	*	the number of bytes in the send buffer (O) is less than this.
	*/
	if (len < 0) {

		/*
		*	Enter persist state:
		*	len is set to 0.
		* If FIN has been sent but not acked,
		* but we haven't been called to retransmit,
		* len will be -1.  Otherwise, window shrank
		* after we sent into it.  If window shrank to 0,
		* cancel pending retransmit and pull snd_nxt
		* back to (closed) window.  We will enter persist
		* state below.  If the window didn't close completely,
		* just wait for an ACK.
		*/
		len = 0;

		/*
		*	If the advertised window is 0, any pending retransmission is canceled by setting the
		*	retransmission timer to 0. snd_nxt is also pulled to the left of the window by setting
		*	it to the value of snd_una. The connection will enter the persist state later in this
		*	function, and when the receiver finally opens its window, TCP starts retransmitting
		*	from the left of the window.
		*/
		if (win == 0) {
			tp.t_timer[TCPT_REXMT] = 0;
			tp.snd_nxt = tp.snd_una;
		}
	}

	/*
	*	Send one segment at a time:
	*	If the amount of data to send exceeds one segment, len is set to a single segment
	*	and the sendalot flag is set to 1. This causes another loop through tcp_output
	*	after the segment is sent.
	*/
	bool sendalot(false);
	if (len > tp.t_maxseg) {
		len = tp.t_maxseg;
		sendalot = true;
	}

	/*
	*	Turn off FIN flag If send buffer not emptied:
	*	If the send buffer is not being emptied by this output operation, the FIN flag must
	*	be cleared (in case it is set in flags). For example, assume the first 512-byte
	*	segment has already been sent (and is waiting to be
	*	acknowledged) and TCP is about to send the next 512-byte segment (bytes 512-1024).
	*	There is still 1 byte left in the send buffer (byte 1025) and the process closes the connection.
	*	len equals 512 (one segment), and the C expression becomes
	*		SEQ_LT(l025, 1026}
	*	which is true, so the FIN flag is cleared. If the FIN flag were mistakenly left on, TCP
	*	couldn't send byte 1025 to the receiver.
	*/
	if (L4_TCP::tcpcb::SEQ_LT(tp.snd_nxt + len, tp.snd_una + so.so_snd.size()))
		flags &= ~tcphdr::TH_FIN;

	/*
	*	Calculate window advertisement:
	*	win is set to the amount of space available in the receive buffer, which becomes
	*	TCP's window advertisement to the other end. Be aware that this is the second use of
	*	this variable in this function. Earlier it contained the maximum amount of data TCP
	*	could send, but for the remainder of this function it contains the receive window advertised
	*	by this end of the connection.
	*	The silly window syndrome (called SWS and described in Section 22.3 of Volume 1)
	*	occurs when small amounts of data, instead of full-sized segments, are exchanged
	*	across a connection. It can be caused by a receiver who advertises small windows and
	*	by a sender who transmits small segments. Correct avoidance of the silly window syndrome
	*	must be performed by both the sender and the receiver.
	*/
	win = so.so_rcv.sbspace();

	/*
	* Sender silly window avoidance.  If connection is idle
	* and can send all data, a maximum segment,
	* at least a maximum default-size segment do it,
	* or are forced, do it; otherwise don't bother.
	* If peer's buffer is tiny, then send
	* when window is at least half open.
	* If retransmitting (possibly after persist timer forced us
	* to send into a small window), then must resend.
	*/
	if (len) {

		/*
		*	If a full-sized segment can be sent, it is sent.
		*/
		if (len == tp.t_maxseg)
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If an ACK is not expected (idle is true), or if the Nagle algorithm is disabled
		*	(TF_NODELAY is true) and TCP is emptying the send buffer, the data is sent. The Nagle
		*	algorithm (Section 19.4 of Volume 1) prevents TCP from sending less than a full-sized
		*	segment when an ACK is expected for the connection. It can be disabled using the
		*	TCP_NODELAY socket option. For a normal interactive connection (e.g., Telnet or
		*	Rlogin), if there is unacknowledged data, this if statement is false, since the Nagle
		*	algorithm is enabled by default .
		*/
		else if ((idle || tp.t_flags & L4_TCP::tcpcb::TF_NODELAY) &&
			len + off >= static_cast<long>(so.so_snd.size()))
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If output is being forced by either the persist timer or sending out-of-band data,
		*	some data is sent.
		*/
		else if(tp.t_force)
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If the receiver's window is at least half open, data is sent. This is to deal with peers
		*	that always advertise tiny windows, perhaps smaller than the segment size. The variable
		*	max_sndwnd is calculated by tcp_input as the largest window advertisement ever advertised
		*	by the other end. It is an attempt to guess the size of the other end's receive buffer
		*	and assumes the other end never reduces the size of its receive buffer.
		*/
		else if(len >= static_cast<long>(tp.max_sndwnd / 2))
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If the retransmission timer expired, then a segment must be sent. snd_max is the
		*	highest sequence number that has been transmitted. We saw that when the retransmission
		*	timer expires, snd_nxt is set to snd_una, that is, snd_nxt is moved to the left edge
		*	of the window, making it less than snd_max.
		*/
		else if(L4_TCP::tcpcb::SEQ_LT(tp.snd_nxt, tp.snd_max))
			return send(tp, idle, so, sendalot, off, flags, win, len);
	}

	/*
	*	The next portion of tcp_output determines if TCP must send a segment just to advertise a
	*	new window to the other end. This is called a window update.
	*	
	* Compare available window to amount of window
	* known to peer (as advertised window less
	* next expected input). If the difference is at least two
	* max size segments, or at least 50% of the maximum possible
	* window, then want to send a window update to peer.
	*/
	if (win > 0) {

		/*
		*	The expression
		*		min(win, (long)TCP_MAXWIN << tp->rcv_scale)
		*	is the smaller of the amount of available space in the socket's receive buffer (win) and
		*	the maximum size of the window allowed for this connection. This is the maximum
		*	window TCP can currently advertise to the other end. The expression
		*		(tp->rcv_adv - tp->rcv_nxt)
		*	is the number of bytes remaining in the last window advertisement that TCP sent to the
		*	other end. Subtracting this from the maximum window yields adv, the number of bytes by
		*	which the window has opened. rcv_nxt is incremented by tcp_input
		*	when data is received in sequence, and rev_adv is incremented by tcp_output when the
		*	edge of the advertised window moves to the right.
		*	For example, assume that a segment with bytes 4, 5, and 6 is received and that these
		*	three bytes are passed to the process. The value of adv is 3, since there are 3 more
		*	bytes of the receive space (bytes 10, 11, and 12) for the other end to fill.
		*	
		* "adv" is the amount we can increase the window,
		* taking into account that we are limited by
		* TCP_MAXWIN << tp->rcv_scale.
		*/
		long adv(std::min(
			win, 
			static_cast<long>(TCP_MAXWIN << tp.rcv_scale)) - (tp.rcv_adv - tp.rcv_nxt));

		/*
		*	If the window has opened by two or more segments, a window update is sent.
		*	When data is received as full-sized segments, this code causes every other received
		*	segment to be acknowledged: TCP's ACK-every-other-segment property. (We show an
		*	example of this shortly.)
		*/
		if (adv >= static_cast<long>(2 * tp.t_maxseg))
			return send(tp, idle, so, sendalot, off, flags, win, len);

		/*
		*	If the window has opened by at least 50% of the maximum possible window (the
		*	socket's receive buffer high-water mark), a window update is sent.
		*/
		else if(2 * adv >= static_cast<long>(so.so_rcv.capacity()))
			return send(tp, idle, so, sendalot, off, flags, win, len);
	}

	/*
	*	Check whether various flags require TCP to send a segment.
	*	Send if we owe peer an ACK.
	*	If an immediate ACK is required, a segment is sent. The TF_ACKNOW flag is set by
	*	various functions: when the 200-ms delayed ACK timer expires, when a segment is
	*	received out of order (for the fast retransmit algorithm), when a SYN is received during
	*	the three-way handshake, when a persist probe is received, and when a FIN is received.
	*/
	if (tp.t_flags & L4_TCP::tcpcb::TF_ACKNOW)
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	If flags specifies that a SYN or RST should be sent, a segment is sent.
	*/
	else if(flags & (tcphdr::TH_SYN | L4_TCP::tcphdr::TH_RST))
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	If the urgent pointer, snd_up, is beyond the start of the send buffer, a segment is
	*	sent. The urgent pointer is set by the PRU_SENDOOB request (Figure 30.9).
	*/
	else if(L4_TCP::tcpcb::SEQ_GT(tp.snd_up, tp.snd_una))
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	If flags specifies that a FIN should be sent, a segment is sent only if the FIN has
	*	not already been sent, or if the FIN is being retransmitted. The flag TF_SENTFIN is set
	*	later in this function when the FIN is sent.
	*/
	else if(flags &tcphdr::TH_FIN &&
		((tp.t_flags & L4_TCP::tcpcb::TF_SENTFIN) == 0 || tp.snd_nxt == tp.snd_una))
		return send(tp, idle, so, sendalot, off, flags, win, len);

	/*
	*	At this point in tcp_output there is no need to send a segment. Next, we show the final
	*	piece of code before tcp_output returns.
	*	If there is data in the send buffer to send (so_snd.sb_cc is nonzero) and both the
	*	retransmission timer and the persist timer are off, turn the persist timer on. This scenario
	*	happens when the window advertised by the other end is too small to receive a
	*	full-sized segment, and there is no other reason to send a segment.
	*	
	* TCP window updates are not reliable, rather a polling protocol
	* using ''persist'' packets is used to insure receipt of window
	* updates. The three ''states'' for the output side are:
	*	idle				not doing retransmits or persists
	*	persisting			to move a small or zero window
	*	(re)transmitting	and thereby not persisting
	*
	* tp->t_timer[TCPT_PERSIST]
	*	is set when we are in persist state.
	* tp->t_force
	*	is set when we are called to send a persist packet.
	* tp->t_timer[TCPT_REXMT]
	*	is set when we are retransmitting
	* The output side is idle when both timers are zero.
	*
	* If send window is too small, there is data to transmit, and no
	* retransmit or persist is pending, then go to persist state.
	* If nothing happens soon, send when timer expires:
	* if window is nonzero, transmit what we can,
	* otherwise force out a byte.
	*/
	if (so.so_snd.size() && tp.t_timer[TCPT_REXMT] == 0 &&
		tp.t_timer[TCPT_PERSIST] == 0) 
	{
		tp.t_rxtshift = 0;
		tcp_setpersist(tp);
	}

	/*
	*	No reason to send a segment, just return.
	*/
	return (0);
}

int L4_TCP_impl::send(L4_TCP::tcpcb &tp, const bool idle, socket &so, bool sendalot, int &off, int &flags, long &win, long &len)
{
	/*
	*	The TCP options are built in the array opt, and the integer optlen keeps a count of
	*	the number of bytes accumulated (since multiple options can be sent at once).
	*	If	the SYN flag bit is set, snd_nxt is set to the initial send sequence number (iss).
	*	If	TCP is performing an active open, iss is set by the PRU_CONNECT request when the
	*		TCP control block is created.
	*	If	this is a passive open, tcp_input creates the TCP control block and sets iss.
	*	In both cases, iss is set from the global tcp_iss.
	*
	* Before ESTABLISHED, force sending of initial options
	* unless TCP set not to do any options.
	* NOTE: we assume that the IP/TCP header plus TCP options
	* always fit in a single mbuf, leaving room for a maximum
	* link header, i.e.
	*	max_linkhdr + sizeof (struct L4_TCP::tcpiphdr) + optlen <= MHLEN
	*/
	unsigned optlen(0);
	unsigned hdrlen(sizeof(tcpiphdr));
	u_char opt[MAX_TCPOPTLEN];
	
	if (flags & L4_TCP::tcphdr::TH_SYN) {
		tp.snd_nxt = tp.iss;

		/*
		*	The flag TF_NOOPT is checked, but this flag is never enabled and there is no way to
		*	turn it on. Hence, the MSS option is always sent with a SYN segment.
		*		Remark: In the Net/1 version of tcp_newtcpcb, the comment "send options!" appeared on the line
		*				that initialized t_f lags to 0. The TF _NOOPT flag is probably a historical artifact from
		*				a preNet/1 system that had problems inter-operating with other hosts when it sent the
		*				MSS option, so the default was to not send the option.
		*/
		if ((tp.t_flags & L4_TCP::tcpcb::TF_NOOPT) == 0) {

			/*
			*	Build MSS option:
			*	opt[0] is set to 2 (TCPOPTJIAXSEG) and opt [1] is set to 4, the length of the MSS option in bytes.
			*/
			opt[0] = TCPOPT_MAXSEG;
			opt[1] = 4;

			/*
			*	The function tcp_mss calculates the MSS to announce to the other end;
			*	The 16-bit MSS is stored in opt [2] and opt [3] by bcopy.
			*	Notice that Net/3 always sends an MSS announcement with the SYN for a connection.
			*/
			u_short mss(htons(static_cast<u_short>(tcp_mss(tp, 0))));
			std::memcpy(&opt[2], &mss, sizeof(mss));
			optlen = 4;

			/*
			*	Should window scale option be sent?
			*	If TCP is to request the window scale option, this option is sent only if this is an
			*	active open (TH_ACK is not set) or if this is a passive open and the window scale option
			*	was received in the SYN from the other end. Recall that t_flags was set to
			*	TF_REQ_SCALE | TF_REQ_TSTMP when the TCP control block was created, if the global variable
			*	tcp_do_rfc1323 was nonzero (its default value).
			*/
			if ((tp.t_flags & L4_TCP::tcpcb::TF_REQ_SCALE) && ((flags & L4_TCP::tcphdr::TH_ACK) == 0 ||	(tp.t_flags & L4_TCP::tcpcb::TF_RCVD_SCALE))) {

				/*
				*	Build window scale option:
				*	Since the window scale option occupies 3 bytes, a 1-byte NOP is stored before the option,
				*	forcing the option length to be 4 bytes. This causes the data in the segment that follows
				*	the options to be aligned on a 4-byte boundary.
				*	If this is an active open, request_r_scale is calculated by the PRU_CONNECT request.
				*	If this is a passive open, the window scale factor is calculated by tcp_input when the
				*	SYN is received.
				*	RFC 1323 specifies that if TCP is prepared to scale windows it should send this option
				*	even if its own shift count is 0. This is because the option serves two purposes:
				*	1. to notify the other end that it supports the option
				*	2. to announce its shift count.
				*	Even though TCP may calculate its own shift count as 0, the other end might want to use a
				*	different value.
				*/
				*reinterpret_cast<u_long *>(&opt[optlen]) = htonl(TCPOPT_NOP << 24 | TCPOPT_WINDOW << 16 | TCPOLEN_WINDOW << 8 | tp.request_r_scale);
				optlen += 4;
			}
		}
	}

	/*
	*	The next part of tcp_output finishes building the options in the outgoing segment.
	*
	*	Should timestamp option be sent?
	*	If the following three conditions are all true, a timestamp option is sent:
	*	(1) TCP is configured to request the timestamp option,
	*	(2) the segment being formed does not contain the RST flag, and
	*	(3) either this is an active open (i.e., flags specifies the SYN flag but not the
	*		ACK flag) or TCP has received a timestamp from the other end (TF RCVD_TSTMP).
	*	Unlike the MSS and window scale options, a timestamp option can be sent with every
	*	segment once both ends agree to use the option.
	*
	* Send a timestamp and echo-reply if this is a SYN and our side
	* wants to use timestamps (TF_REQ_TSTMP is set) or both our side
	* and our peer have sent timestamps in our SYN's.
	*/
	if ((tp.t_flags & (L4_TCP::tcpcb::TF_REQ_TSTMP | L4_TCP::tcpcb::TF_NOOPT)) == L4_TCP::tcpcb::TF_REQ_TSTMP &&
		(flags & L4_TCP::tcphdr::TH_RST) == 0 &&
		((flags & (tcphdr::TH_SYN | L4_TCP::tcphdr::TH_ACK)) == L4_TCP::tcphdr::TH_SYN ||
		(tp.t_flags & L4_TCP::tcpcb::TF_RCVD_TSTMP))) 
	{
		u_long *lp(reinterpret_cast<u_long *>(&opt[optlen]));

		/*
		*	Build timestamp option:
		*	The timestamp option (Section 26.6) consists of 12 bytes (TCPOLEN_TSTAMP_APPA).
		*	The first 4 bytes are Ox0101080a (the constant TCPOPT_TSTAMP_HDR).
		*	The timestamp value is taken from tcp_now (the number of 500-ms clock ticks
		*	since the system was initialized), and the timestamp echo reply is taken from
		*	ts_recent, which is set by tcp_input.
		*	Form timestamp option as shown in appendix A of RFC 1323.
		*/
		*lp++ = htonl(TCPOPT_TSTAMP_HDR);
		*lp++ = htonl(tcp_now);
		*lp = htonl(tp.ts_recent);
		optlen += TCPOLEN_TSTAMP_APPA;
	}

	hdrlen += optlen;

	/*
	*	Check If options have overflowed segment:
	*	The size of the TCP header is incremented by the number of option bytes (optlen).
	*	If the amount of data to send (len) exceeds the MSS minus the size of the options
	*	(opt len), the data length is decreased accordingly and the sendalot flag is set,
	*	to force another loop through this function after this segment is sent.
	*	The MSS and window scale options only appear in SYN segments, which Net/3 always
	*	sends without data, so this adjustment of the data length doesn't apply. When the
	*	timestamp option is in use, however, it appears in all segments. This reduces the
	*	amount of data in each full-sized data segment from the announced MSS to the
	*	announced MSS minus 12 bytes.
	*	
	* Adjust data length if insertion of options will
	* bump the packet length beyond the t_maxseg length.
	*/
	if (len > static_cast<long>(tp.t_maxseg - optlen)) {
		len = tp.t_maxseg - optlen;
		sendalot = true;
		flags &= ~tcphdr::TH_FIN;
	}

	/*
	*	Allocate an mbuf for IP and TCP headers:
	*	An mbuf with a packet header is allocated by MGETHDR. This is for the IP and TCP
	*	headers, and possibly the data (if there's room). Although tcp_output is often called
	*	as part of a system call (e.g., write) it is also called at the software interrupt level by
	*	tcp_input, and as part of the timer processing. Therefore M_DONTWAIT is specified.
	*	If an error is returned, a jump is made to the label out. This label is near the end of the
	*	function.
	*/
	std::shared_ptr<std::vector<byte>> m(new std::vector<byte>(hdrlen + sizeof(struct L2::ether_header) + len));
	if (m == nullptr)
		return out(tp, ENOBUFS);
	
	std::vector<byte>::iterator it(m->begin() + sizeof(struct L2::ether_header));
	
	if (len) {

		/*
		*	Copy data Into mbuf:
		*	If the amount of data is less than 44 bytes (100-40-16, assuming no TCP options),
		*	the data is copied directly from the socket send buffer into the new packet header mbuf
		*	by m_copydata. Otherwise m_copy creates a new mbuf chain with the data from the
		*	socket send buffer and this chain is linked to the new packet header mbuf. Recall our
		*	description of m_copy in Section 2.9, where we showed that if the data is in a cluster,
		*	m_copy just references that cluster and doesn't make a copy of the data.
		*/
		std::copy(so.so_snd.begin(), so.so_snd.begin() + len, it + hdrlen);

		/*
		*	Set PSH flag:
		*	If TCP is sending everything it has from the send buffer, the PSH flag is set.
		*	As the comment indicates, this is intended for receiving systems that only
		*	pass received data to an application when the PSH flag is received or when
		*	a buffer fills. We'll see in tcp_input that Net/3 never holds data in a
		*	socket receive buffer waiting for a received PSH flag.
		*
		* If we're sending everything we've got, set PUSH.
		* (This will keep happy those implementations which only
		* give data to the user when a buffer fills or
		* a PUSH comes in.)
		*/
		if (off + len == so.so_snd.size())
			flags |= L4_TCP::tcphdr::TH_PUSH;
	}

	struct L4_TCP::tcpiphdr *ti(reinterpret_cast<struct L4_TCP::tcpiphdr *>(&m->data()[it - m->begin()]));

	/*
	*	Copy IP and TCP header templates Into mbuf:
	*	The template of the IP and TCP headers is copied from t_template into the mbuf
	*	by bcopy. This template was created by tcp_template.
	*/
	if (tp.t_template == nullptr)
		throw std::runtime_error("tcp_output: t_template is null!");
	std::memcpy(ti, tp.t_template, sizeof(struct L4_TCP::tcpiphdr));

	/*
	*	The next part of tcp_output fills in some remaining fields in the TCP header.
	*
	*	Decrement snd_nxt If FIN Is being retransmitted:
	*	If TCP has already transmitted the FIN, the send sequence space appears.
	*	Therefore, if the FIN flag is set, and if the TF SENTFIN flag is set, and if snd_nxt
	*	equals snd_max, TCP knows the FIN is being retransmitted. We'll see shortly that when
	*	a FIN is sent, snd_nxt is incremented 1 one (since the FIN occupies a sequence number),
	*	so this piece of code decrements snd_nxt by 1.
	*
	* Fill in fields, remembering maximum advertised
	* window for use in delaying messages about window sizes.
	* If resending a FIN, be sure not to use a new sequence number.
	*/
	if (flags & L4_TCP::tcphdr::TH_FIN && tp.t_flags & L4_TCP::tcpcb::TF_SENTFIN &&	tp.snd_nxt == tp.snd_max)
		tp.snd_nxt--;

	/*
	*	Set sequence number field of segment:
	*	The sequence number field of the segment is normally set to snd_nxt, but is set to
	*	snd_max if:
	*	(1) there is no data to send (len equals 0),
	*	(2) neither the SYN flag nor the FIN flag is set, and
	*	(3) the persist timer is not set.
	*
	* If we are doing retransmissions, then snd_nxt will
	* not reflect the first unsent octet.  For ACK only
	* packets, we do not want the sequence number of the
	* retransmitted packet, we want the sequence number
	* of the next unsent octet.  So, if there is no data
	* (and no SYN or FIN), use snd_max instead of snd_nxt
	* when filling in ti_seq.  But if we are in persist
	* state, snd_max might reflect one byte beyond the
	* right edge of the window, so use snd_nxt in that
	* case, since we know we aren't doing a retransmission.
	* (retransmit and persist are mutually exclusive...)
	*/
	ti->ti_seq() =
		(len || (flags & (tcphdr::TH_SYN | L4_TCP::tcphdr::TH_FIN)) || tp.t_timer[TCPT_PERSIST]) ?
		htonl(tp.snd_nxt) :
		htonl(tp.snd_max);

	/*
	*	Set acknowledgment field of segment:
	*	The acknowledgment field of the segment is always set to rev _nxt, the next
	*	expected receive sequence number.
	*/
	ti->ti_ack() = htonl(tp.rcv_nxt);

	/*
	*	Set header length If options present:
	*	If TCP options are present (optlen is greater than 0), the options are copied into
	*	the TCP header and the 4-bit header length in the TCP header (th_off) is set to the
	*	fixed size of the TCP header (20 bytes) plus the length of the options, divided by
	*	4. This field is the number of 32-bit words in the TCP header, including options.
	*/
	if (optlen) {
		std::memcpy(&ti[1], opt, optlen);
		ti->ti_off((sizeof(struct L4_TCP::tcphdr) + optlen) >> 2);
	}

	/*
	*	The flags field in the TCP header is set from the variable flags.
	*/
	ti->ti_flags() = flags;

	/*
	*	The next part of code fills in more fields in the TCP header and calculates the TCP checksum.
	*
	*	Don't advertise less than one full-sized segment:
	*	Avoidance of the silly window syndrome is performed, this time in calculating the
	*	window size that is advertised to the other end (ti_win). Recall that win was set at the
	*	amount of space in the socket's receive buffer. If win is less than one fourth of the
	*	receive buffer size (so_rcv.sb_hiwat) and less than one full sized segment, the advertised
	*	window will be 0. This is subject to the later test that prevents the window from shrinking.
	*	In other words, when the amount of available space reaches either one-fourth of the receive
	*	buffer size or one full-sized segment, the available space will be advertised.
	*
	* Calculate receive window. Don't shrink window,
	* but avoid silly window syndrome.
	*/
	if (win < static_cast<long>(so.so_rcv.capacity() / 4) &&
		win < static_cast<long>(tp.t_maxseg))
		win = 0;

	/*
	*	Observe upper limit for advertised window on this connection:
	*	If win is larger than the maximum value for this connection, reduce it to its maximum value.
	*/
	if (win > static_cast<long>(TCP_MAXWIN) << tp.rcv_scale)
		win = static_cast<long>(TCP_MAXWIN) << tp.rcv_scale;

	/*
	*	Do not shrink window:
	*	Recall that rcv_adv minus rcv_nxt is the amount of space still available to the sender that
	*	was previously advertised. If win is less than this value, win is set to this value, because
	*	we must not shrink the window. This can happen when the available space is less than one
	*	full-sized segment (hence win was set to 0 at the beginning), but there is room in the
	*	receive buffer for some data. Figure 223 of Volume 1 shows an example of this scenario.
	*/
	if (win < static_cast<long>(tp.rcv_adv - tp.rcv_nxt))
		win = static_cast<long>(tp.rcv_adv - tp.rcv_nxt);

	ti->ti_win() = htons(static_cast<u_short>(win >> tp.rcv_scale));

	/*
	*	Set urgent offset:
	*	If the urgent pointer (snd_up) is greater than snd_nxt, TCP is in urgent mode.
	*	The urgent offset in the TCP header is set to the 16·bit offset of the urgent pointer from
	*	the starting sequence number of the segment, and the URG flag bit is set. TCP sends the
	*	urgent offset and the URG flag regardless of whether the referenced byte of urgent data
	*	is contained in this segment or not.
	*	For example of how the urgent offset is calculated, assuming the  process executes:
	*		send(fd, buf, 3, MSG_OOB);
	*	and the send buffer is empty when this call to send takes place. This shows that Berkeley-
	*	derived systems consider the urgent pointer to point to the first byte of data after the
	*	out-of-band byte. We distinguished between the 32-bit urgent pointer in the data stream
	*	(snd_up), and the 16-bit urgent offset in the TCP header (ti_urp).
	*		Remark:	There is a subtle bug here. The bug occurs when the send buffer Is larger than
	*				65535, regardless of whether the window scale option is in use or not. If the
	*				send buffer is greater than 65535 and is nearly full, and the process sends
	*				out-of-band data, the offset of the urgent pointer from snd_nxt can exceed
	*				65535. But the urgent pointer is a 16 bit unsigned value, and if the
	*				calculated value exceeds 65535, the 16 high-order bits are discarded,
	*				delivering a bogus urgent pointer to the other end.
	*/
	if (L4_TCP::tcpcb::SEQ_GT(tp.snd_up, tp.snd_nxt)) {
		ti->ti_urp() = htons(static_cast<u_short>(tp.snd_up - tp.snd_nxt));
		ti->ti_flags() |= L4_TCP::tcphdr::TH_URG;
	}
	else

		/*
		*	If TCP is not in urgent mode, the urgent pointer is moved to the left edge of the
		*	window (snd_una).
		*
		* If no urgent pointer to send, then we pull
		* the urgent pointer to the left edge of the send window
		* so that it doesn't drift into the send window on sequence
		* number wraparound.
		*/
		tp.snd_up = tp.snd_una;		/* drag it along */

	/*
	*	The TCP length is stored in the pseudo-header and the TCP checksum is calculated.
	*	All the fields in the TCP header have been filled in, and when the IP and TCP header
	*	template were copied from t_template, the fields in the IP header that are used as
	*	the pseudo-header were initialized.
	*
	* Put TCP length in extended header, and then
	* checksum extended header and data.
	*/
	if (len + optlen)
		ti->ti_len() = htons(static_cast<u_short>(sizeof(struct L4_TCP::tcphdr) + optlen + len));
	
	ti->ti_sum() = inet.in_cksum(&m->data()[it - m->begin()], static_cast<int>(hdrlen + len));

	/*	The next part of tcp_output updates the sequence number if the SYN or FIN flags
	*	are set and initializes the retransmission timer.
	*
	*	Remember starting sequence number:
	*	If TCP is not in the persist state, the starting sequence number is saved in
	*	start seq. This is used later in Figure 26.31 if the segment is timed.
	*
	* In transmit state, time the transmission and arrange for
	* the retransmit.  In persist state, just set snd_max.
	*/
	if (tp.t_force == 0 || tp.t_timer[TCPT_PERSIST] == 0) {
		tcp_seq startseq(tp.snd_nxt);

		/*
		*	Increment snd_nxt:
		*	Since both the SYN and FIN flags take a sequence number, snd_nxt is incremented
		*	if either is set. TCP also remembers that the FIN has been sent, by setting the flag
		*	TF_SENTFIN. snd_nxt is then incremented by the number of bytes of data (len),
		*	which can be 0.
		* Advance snd_nxt over sequence space of this segment.
		*/
		if (flags & (tcphdr::TH_SYN | L4_TCP::tcphdr::TH_FIN)) {
			if (flags & L4_TCP::tcphdr::TH_SYN)
				tp.snd_nxt++;
			if (flags & L4_TCP::tcphdr::TH_FIN) {
				tp.snd_nxt++;
				tp.t_flags |= L4_TCP::tcpcb::TF_SENTFIN;
			}
		}
		
		tp.snd_nxt += len;

		/*
		*	Update and_max:
		*	If the new value of snd_nxt is larger than snd_rnax, this is not a retransmission.
		*	The new value of snd_max is stored.
		*/
		if (L4_TCP::tcpcb::SEQ_GT(tp.snd_nxt, tp.snd_max)) {
			tp.snd_max = tp.snd_nxt;

			/*
			*	If a segment is not currently being timed for this connection (t_rtt equals 0), the
			*	timer is started (t_rtt is set to 1) and the starting sequence number of the segment
			*	being timed is saved in t_rtseq. This sequence number is used by tcp_input to
			*	determine when the segment being timed is acknowledged, to update the RIT estimators.
			*	The sample code looked like
			*		if (tp->t_rtt && SEQ_GT(ti->ti_ack, tp->t_rtseq))
			*			tcp_xmit_timer{tp, tp->t_rtt);
			*
			* Time this transmission if not a retransmission and
			* not currently timing anything.
			*/
			if (tp.t_rtt == 0) {
				tp.t_rtt = 1;
				tp.t_rtseq = startseq;
			}
		}

		/*	Set retransmission timer:
		*	If the retransmission timer is not currently set, and if this segment contains data, the
		*	retransmission timer is set to t_rxtcur. Recall that t_rxtcur is set by
		*	tcp_xmit_timer, when an RIT measurement is made. This is an ACK-only segment
		*	if snd_nxt equals snd_una (since len was added to snd_nxt earlier in this figure),
		*	and the retransmission timer is set only for segments containing data.
		*
		* Set retransmit timer if not currently set,
		* and not doing an ack or a keep-alive probe.
		* Initial value for retransmit timer is smoothed
		* round-trip time + 2 * round-trip time variance.
		* Initialize shift counter which is used for backoff
		* of retransmit time.
		*/
		if (tp.t_timer[TCPT_REXMT] == 0 &&
			tp.snd_nxt != tp.snd_una) 
		{
			tp.t_timer[TCPT_REXMT] = tp.t_rxtcur;

			/*
			*	If the persist timer is enabled, it is disabled. Either the retransmission timer or the
			*	persist timer can be enabled at any time for a given connection, but not both.
			*/
			if (tp.t_timer[TCPT_PERSIST]) {
				tp.t_timer[TCPT_PERSIST] = 0;
				tp.t_rxtshift = 0;
			}
		}
	}

	/*
	*	Persist state:
	*	The connection is in the persist state since t_force is nonzero and the persist timer
	*	is enabled. (This else clause is associated with the if at the beginning.)
	*	snd_rnax is updated, if necessary. In the persist state, len will be one.
	*/
	else if (L4_TCP::tcpcb::SEQ_GT(tp.snd_nxt + len, tp.snd_max))
		tp.snd_max = tp.snd_nxt + len;

	/*
	*	The final part of tcp_output completes the formation of the outgoing segment and calls
	*	ip_output to send the datagram.
	*	
		*	Set IP length, TTL, and TOS:
		*	The final three fields in the IP header that must be set by the transport layer are
		*	stored: IP length, TIL, and TOS.
		*		Remark:	The comments XXX are because the latter two fields normally remain constant for
		*				a connection and should be stored in the header template, instead of being
		*				assigned explicitly each time a segment is sent. But these two fields cannot
		*				be stored in the IP header until after the TCP checksum is calculated.
		*
		* Fill in IP length and desired time to live and
		* send to IP level.  There should be a better way
		* to handle ttl and tos; we could keep them in
		* the template, but need a way to checksum without them.
		*/
	reinterpret_cast<struct L3::iphdr *>(ti)->ip_len = static_cast<short>(hdrlen + len);
	reinterpret_cast<struct L3::iphdr *>(ti)->ip_ttl = tp.t_inpcb->inp_ip.ip_ttl;	/* XXX */
	reinterpret_cast<struct L3::iphdr *>(ti)->ip_tos = tp.t_inpcb->inp_ip.ip_tos;	/* XXX */

	/*
	*	Pass datagram to IP:
	*	ip_output sends the datagram containing the TCP segment. The socket options
	*	are logically ANDed with SO_DONTROUTE, which means that the only socket option
	*	passed to ip_output is so_oONTROUTE. The only other socket option examined by
	*	ip_output is SO_BROADCAST, so this logical AND turns off the SO_BROADCAST bit, if
	*	set. This means that a process cannot issue a connect to a broadcast address, even if it
	*	sets the SO_BROADCAST socket option.
	*/
	int error(
		inet.inetsw(protosw::SWPROTO_IP_RAW)->
		pr_output(
		*dynamic_cast<const struct pr_output_args*>(
		&L3_impl::ip_output_args(m, it, tp.t_inpcb->inp_options, &tp.t_inpcb->inp_route, so.so_options & SO_DONTROUTE, nullptr)
		)));
	if (error)
		return out(tp, error);

	/*
	*	Update rev_adv and last_ack_sent:
	*	If the highest sequence number advertised in this segment (rcv_nxt plus win) is
	*	larger than rev_adv, the new value is saved. Recall that rev_adv was used to
	*	determine how much the window had opened since the last segment that was sent,
	*	and to make certain TCP was not shrinking the window.
	*
	* Data sent (as far as we can tell).
	* If this advertises a larger window than any other segment,
	* then remember the size of the advertised window.
	* Any pending ACK has now been sent.
	*/
	if (win > 0 && L4_TCP::tcpcb::SEQ_GT(tp.rcv_nxt + win, tp.rcv_adv))
		tp.rcv_adv = tp.rcv_nxt + win;

	/*
	*	The value of the acknowledgment field in the segment is saved in
	*	last_ack_sent. This variable is used by tcp_input with the timestamp option
	*/
	tp.last_ack_sent = tp.rcv_nxt;

	/*
	*	Any pending ACK has been sent, so the TF_ACKNOW and TF_DELACK flags are cleared.
	*/
	tp.t_flags &= ~(L4_TCP::tcpcb::TF_ACKNOW | L4_TCP::tcpcb::TF_DELACK);

	/*	More data to send?
	*	If the sendalot flag is set, a jump is made back to the label again.
	*	This occurs if the send buffer contains more than one full-sized segment that can be sent
	*	or if a full-sized segment was being sent and TCP options were included that reduced the
	*	amount of data in the segment.
	*/
	if (sendalot)
		return again(tp, idle, so);

	return (0);
}

int L4_TCP_impl::out(L4_TCP::tcpcb &tp, int error)
{
	/*
	*	The error ENOBUFS is returned if the interface queue is full or if IP needs to obtain
	*	an mbuf and can't. The function tcp_quench pulls the connection into slow start, by
	*	setting the congestion window to one full-sized segment. Notice that tcp_output still
	*	returns 0 (OK) in this case, instead of the error, even though the datagram was discarded.
	*	This differs from udp_output, which returned the error. The difference is that UDP is
	*	unreliable, so the ENOBUFS error return is the only indication to the process that the
	*	datagram was discarded. TCP, however, will time out (if the segment contains data) and
	*	retransmit the datagram, and it is hoped that there will be space on the interface output
	*	queue or more available mbufs. If the TCP segment doesn't contain data, the other end
	*	will time out when the ACK isn't received and will retransmit the data whose ACK was
	*	discarded.
	*/
	if (error == ENOBUFS) {
		tp.tcp_quench();
		return (0);
	}

	/*
	*	If a route can't be located for the destination, and if the connection has received a
	*	SYN, the error is recorded as a soft error for the connection.
	*	When tcp_output is called by tcp_usrreq as part of a system call by a process
	*	(Chapter 30, the PRU_CONNECT, PRU_SEND, PRU_SENDOOB, and PRU_SHUTDOWN
	*	requests), the process receives the return value from tcp_output. Other functions that
	*	call tcp_output, such as tcp_input and the fast and slow timeout functions, ignore
	*	the return value (because these functions don't return an error to a process).
	*/
	else if ((error == EHOSTUNREACH || error == ENETDOWN) && tp.TCPS_HAVERCVDSYN()) {
		tp.t_softerror = error;
		return (0);
	}
	return (error);
}

/************************************************************************/
/*				  L4_TCP_impl pr_input						            */
/************************************************************************/

void L4_TCP_impl::pr_input(const struct pr_input_args &args)
{
	std::shared_ptr<std::vector<byte>> &m(args.m);
	std::vector<byte>::iterator &it(args.it);
	const int &iphlen(args.iphlen);

	/*	
	 *	Get IP and TCP headers In first mbuf
	 *	The argument iphlen is the length of the IP header, including possible IP options.
	 *	If the length is greater than 20 bytes, options are present, and ip_stripoptions discards
	 *	the options. TCP ignores all IP options other than a source route, which is saved
	 *	specially by IP (Section 9.6) and fetched later by TCP in Figure 28.7. If the number of
	 *	bytes in the first mbuf in the chain is less than the size of the combined IP /TCP header
	 *	(40 bytes), m_pullup moves the first 40 bytes into the first mbuf.
	 *	
	* Get IP and TCP header together in first mbuf.
	* Note: IP leaves IP header in first mbuf.
	*/
	struct L4_TCP::tcpiphdr* ti(reinterpret_cast<struct L4_TCP::tcpiphdr*>(&m->data()[it - m->begin()]));
	
	if (iphlen > sizeof(struct L3::iphdr))
		L3_impl::ip_stripoptions(m, it);
	
	if (m->end() - it < sizeof(struct L4_TCP::tcpiphdr))
		return drop(nullptr, 0);

	/*	
	 *	Verify TCP checksum
	 *	tlen is the TCP length, the number of bytes following the IP header. Recall that IP
	 *	has already subtracted the IP header length from ip_len. The variable len is then set
	 *	to the length of the IP datagram, the number of bytes to be checksummed, including the
	 *	pseudo-header. The fields in the pseudo-header are set, as required for the checksum
	 *	calculation, as shown in Figure 23.19.
	 *	
	* Checksum extended TCP header and data.
	*/
	int tlen(reinterpret_cast<struct L3::iphdr *>(ti)->ip_len),
		len(sizeof(struct L3::iphdr) + tlen);
	
	ti->ti_next(0);
	ti->ti_prev(0);
	ti->ti_x1() = 0;
	ti->ti_len() = htons(static_cast<u_short>(tlen));
	
	u_short checksum(ti->ti_sum());
	if (((ti->ti_sum() = 0) = checksum ^ inet.in_cksum(&m->data()[it - m->begin()], len)) != 0)
		return drop(nullptr, 0);

	/*	
	 *	Verify TCP offset field
	 *	The TCP offset field, ti_off, is the number of 32-bit words in the TCP header,
	 *	including any TCP options. It is multiplied by 4 (to become the byte offset of the first
	 *	data byte in the TCP segment) and checked for sanity. It must be greater than or equal
	 *	to the size of the standard TCP header (20) and less than or equal to the TCP length.
	 *	
	* Check that TCP offset makes sense,
	* pull out TCP options and adjust length.		XXX
	*/
	int off(ti->ti_off() << 2);
	if (off < sizeof(struct L4_TCP::tcphdr) || off > tlen)
		return drop(nullptr, 0);

	/*	
	 *	The byte offset of the first data byte is subtracted from the TCP length, leaving tlen
	 *	with the number of bytes of data in the segment (possibly 0). This value is stored back
	 *	into the TCP header, in the variable ti_len, and will be used throughout the function.
	 */
	ti->ti_len() = (tlen -= off);
	
	/*
	*	Get headers plus option Into first mbuf
	*	If the byte offset of the first data byte is greater than 20, TCP options are present.
	*/
	u_char *optp(nullptr);
	int optlen, 
		ts_present(0);
	u_long ts_val, 
		ts_ecr;

	if (off > sizeof(struct L4_TCP::tcphdr)) {

		/*
		*	Process timestamp option quickly:
		*	optlen is the number of bytes of options, and optp is a pointer to the first option
		*	byte.
		*/
		optlen = off - sizeof(struct L4_TCP::tcphdr);
		optp = &m->data()[it - m->begin() + sizeof(struct L4_TCP::tcpiphdr)];

		/*	
		 *	If the following three conditions are all true, only the timestamp option is present
		 *	and it is in the desired format
		 *		1.	(a) The TCP option length equals 12 (TCPOLEN_TSTAMP_APPA), or 
		 *			(b) the TCP Option length is greater than 12 and optp[12] equals the end-0f-option byte.
		 *		2.	The first 4 bytes of options equals Ox0101080a (TCPOPT_TSTAMP_HDR)
		 *		3.	The SYN flag is not set (i.e., this segment is for an established connection, hence
		 *			if a timestamp option is present, we know both sides have agreed to use the
		 *			option).
		 *					 
		* Do quick retrieval of timestamp options ("options
		* prediction?").  If timestamp is the only option and it's
		* formatted as recommended in RFC 1323 appendix A, we
		* quickly get the values now and not bother calling
		* tcp_dooptions(), etc.
		*/
		if ((optlen == TCPOLEN_TSTAMP_APPA ||
			(optlen > TCPOLEN_TSTAMP_APPA &&
			optp[TCPOLEN_TSTAMP_APPA] == TCPOPT_EOL)) &&
			*reinterpret_cast<u_long *>(optp) == htonl(TCPOPT_TSTAMP_HDR) &&
			(ti->ti_flags() & L4_TCP::tcphdr::TH_SYN) == 0) 
		{

			/*
			 *	If all three conditions are true, ts_present is set to 1;
			 *	the two timestamp values are fetched and stored in ts_ val and ts_ecr;
			 *	and optp is set to null, since all the options have been parsed.
			 *	The benefit in recognizing the timestamp option this way is to avoid
			 *	calling the general option processing function tcp_dooptions later in the code. The
			 *	general option processing function is OK for the other options that appear only with the
			 *	SYN segment that creates a connection (the MSS and window scale options), but when
			 *	the timestamp option is being used, it will appear with almost every segment on an
			 *	established connection, so the faster it can be recognized, the better.
			 */
			ts_present = 1;
			ts_val = ntohl(*reinterpret_cast<u_long *>(&optp[4]));
			ts_ecr = ntohl(*reinterpret_cast<u_long *>(&optp[8]));
			optp = nullptr;	/* we've parsed the options */
		}
	}
	
	int tiflags(ti->ti_flags());

	/*	
	 *	Save Input flags and convert fields to host byte order:
	 *	The received flags (SYN, FIN, etc.) are saved in the local variable ti_flags, since
	 *	they are referenced throughout the code. Two 16-bit values and the two 32-bit values in
	 *	the TCP header are converted from network byte order to host byte order. The two
	 *	16-bit port numbers are left in network byte order, since the port numbers in the Internet
	 *	PCB are in that order.
	 *	
	* Convert TCP protocol specific fields to host format.
	*/
	ti->ti_seq() = ntohl(ti->ti_seq());
	ti->ti_ack() = ntohl(ti->ti_ack());
	ti->ti_win() = ntohs(ti->ti_win());
	ti->ti_urp() = ntohs(ti->ti_urp());

#ifdef NETLAB_L4_TCP_DEBUG
		print(ti->ti_t, htons(checksum));
#endif
	
	/* 
	 *	Locate Internet PCB:
	 *	TCP maintains a one-behind cache (tcp_last_inpcb) containing the address of
	 *	the PCB for the last received TCP segment. This is the same technique used by UDP.
	 *	The comparison of the four elements in the socket pair is in the same order as done by
	 *	udp_input. If the cache entry does not match, in_pcblookup is called, and the cache
	 *	is set to the new PCB entry.
	 *	TCP does not have the same problem that we encountered with UDP: wildcard
	 *	entries in the cache causing a high miss rate. The only time a TCP socket has a wildcard
	 *	entry is for a server listening for connection requests. Once a connection is made, all 
	 *	four entries in the socket pair contain nonwildcard values. In Figure 24.5 we see a cache
	 *	hit rate of almost 80°/o.
	* Locate pcb for segment.
	*/
	int dropsocket(0),
		iss(0);
	class inpcb_impl *inp(nullptr);

findpcb:
	inp = tcp_last_inpcb;
	if ((inp->inp_lport() != ti->ti_dport() ||	
		inp->inp_fport() != ti->ti_sport() ||
		inp->inp_faddr().s_addr != ti->ti_src().s_addr ||
		inp->inp_laddr().s_addr != ti->ti_dst().s_addr) &&
		(inp = tcb.in_pcblookup(ti->ti_src(), ti->ti_sport(), ti->ti_dst(), ti->ti_dport(), inpcb::INPLOOKUP_WILDCARD)))
		tcp_last_inpcb = inp;

	/*	
	 *	Drop segment and generate RST:
	 *	If the PCB was not found, the input segment is dropped and an RST is sent as a
	 *	reply. This is how TCP handles SYNs that arrive for a server that doesn't exist, for
	 *	example. Recall that UDP sends an ICMP port unreachable in this case.
	 *	
	* If the state is CLOSED (i.e., TCB does not exist) then
	* all data in the incoming segment is discarded.
	* If the TCB exists but is in CLOSED state, it is embryonic,
	* but should either do a listen or a connect soon.
	*/
	if (inp == nullptr)
		return dropwithreset(nullptr, dropsocket, tiflags, m, it, ti);
	
	/*	
	 *	If the PCB exists but a corresponding TCP control block does not exist, the socket is
	 *	probably being closed (tcp_close releases the TCP control block first, and then
	 *	releases the PCB), so the input segment is dropped and an RST is sent as a reply.
	 */
	class L4_TCP::tcpcb *tp = L4_TCP::tcpcb::intotcpcb(inp);
	if (tp == nullptr)
		return dropwithreset(inp, dropsocket, tiflags, m, it, ti);

	/*	
	 *	Silently drop segment:
	 *	If the TCP control block exists, but the connection state is CLOSED, the socket has
	 *	been created and a local address and local port may have been assigned, but neither
	 *	connect nor listen has been called. The segment is dropped but nothing is sent as a
	 *	reply. This scenario can happen if a client catches a sender between the server's call to
	 *	bind and listen. By silently dropping the segment and not replying with an RST, the
	 *	client's connection request should time out, causing the client to retransmit the SYN.
	 */
	if (tp->t_state == L4_TCP::tcpcb::TCPS_CLOSED)
		return drop(tp, dropsocket);

	/* 
	 *	Unscale advertised window into a 32-bit value:
	 *	If window scaling is to take place for this connection, both ends must specify their
	 *	send scale factor using the window scale option when the connection is established. If
	 *	the segment contains a SYN, the window scale factor has not been established yet, so
	 *	tiwin is copied from the value in the TCP header. Otherwise the 16-bit value in the
	 *	header is left shifted by the send scale factor into a 32-bit value.
	 */
	u_long tiwin(ti->ti_win());
	if ((tiflags & L4_TCP::tcphdr::TH_SYN) == 0)
		tiwin <<= tp->snd_scale;

	socket *so(dynamic_cast<socket*>(tp->inp_socket));
	if (so && so->so_options & (SO_DEBUG | SO_ACCEPTCONN)) {

		/*	
		 *	Save connection state and IP/TCP headers If socket debug option enabled:
		 *	If the SO_DEBUG socket option is enabled the current connection state is saved
		 *	(ostate) as well as the IP and TCP headers (tcp_saveti). These become arguments
		 *	to tcp_trace when it is called at the end of the function (Figure 29.26).
		 */
		if (so->so_options & SO_DEBUG)
			tcp_saveti = ti;

		/*	
		 *	Create new socket If segment arrives for listening socket:
		 *	When a segment arrives for a listening socket (SO_ACCEPTCONN is enabled by
		 *	listen), a new socket is created by sonewconn. 
		 *	This issues the protocol's PRU_ATTACH request (Figure 30.2), which allocates an 
		 *	Internet PCB and a TCP control block. 
		 *	But more processing is needed before TCP commits to accept the connection
		 *	request (such as the fundamental question of whether the segment contains a SYN or
		 *	not), so the flag dropsocket is set, to cause the code at the labels drop and
		 *	dropwithreset to discard the new socket if an error is encountered. If the received
		 *	segment is OK, dropsocket is set back to 0 in Figure 28.17.
		 */
		if (so->so_options & SO_ACCEPTCONN) {
			if ((tiflags & (tcphdr::TH_RST | L4_TCP::tcphdr::TH_ACK | L4_TCP::tcphdr::TH_SYN)) != L4_TCP::tcphdr::TH_SYN)
				
				/*
				* Note: dropwithreset makes sure we don't
				* send a reset in response to a RST.
				*/
				if (tiflags & L4_TCP::tcphdr::TH_ACK) 
					return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
				else 
					return drop(tp, dropsocket);
			else if ((so = so->sonewconn(*so, 0)) == nullptr)
				return drop(tp, dropsocket);
			
			/*
			* This is ugly, but ....
			*
			* Mark socket as temporary until we're
			* committed to keeping it. The code at
			* "drop" and "dropwithreset" check the
			* flag dropsocket to see if the temporary
			* socket created here should be discarded.
			* We mark the socket as discardable until
			* we're committed to it below in TCPS_LISTEN.
			*/
			dropsocket++;

			/*	
			 *	inp and tp point to the new socket that has been created. The local address and
			 *	local port are copied from the destination address and destination port of the IP and
			 *	TCP headers. If the input datagram contained a source route, it was saved by
			 *	save_rte. TCP calls ip_srcroute to fetch that source route, saving a pointer to the
			 *	mbuf containing the source route option in inp_options. This option is passed to
			 *	ip_output by tcp_output, and the reverse route is used for datagrams sent on this
			 *	connection.
			 */
			tp = L4_TCP::tcpcb::sototcpcb(so);
			tp->inp_laddr() = ti->ti_dst();
			tp->inp_lport() = ti->ti_dport();

			/*	
			 *	The state of the new socket is set to LISTEN. If the received segment contains a
			 *	SYN, the code in Figure 28.16 completes the connection request.
			 */
			tp->t_state = L4_TCP::tcpcb::TCPS_LISTEN;

			/*	
			 *	Compute window scale factor:
			 *	The window scale factor that will be requested is calculated from the size of the
			 *	receive buffer. 65535 (TCP_MAXWIN) is left shifted until the result exceeds the size of the
			 *	receive buffer, or until the maximum window scale factor is encountered (14, TCP MAX_WINSHIFT).
			 *	Notice that the requested window scale factor is chosen based on the size of the listening 
			 *	socket's receive buffer. This means the process must set the SO_RCVBUF socket option before
			 *	listening for incoming connection requests or it inherits the default value in tcp_recvspace.
			 */
			while (tp->request_r_scale < TCP_MAX_WINSHIFT && 
				static_cast<u_long>(TCP_MAXWIN) << tp->request_r_scale < so->so_rcv.capacity())
				tp->request_r_scale++;
		}
	}

	/*	
	 *	Reset t_idle time and keepalive timer:
	 *	t_idle is set to 0 since a segment has been received on the connection. 
	 *	The keepalive timer is also reset to 2 hours.
	* Segment received on connection.
	* Reset idle time and keep-alive timer.
	*/
	tp->t_idle = 0;
	tp->t_timer[TCPT_KEEP] = tcp_keepidle;

	/*	
	 *	Process options if not in LISTEN state, else do it below (after getting remote address):
	 *	If options are present in the TCP header, and if the connection state is not LISTEN,
	 *	tcp_dooptions processes the options. Recall that if only a timestamp option appears
	 *	for an established connection, and that option is in the format recommended by Appendix
	 *	A of RFC 1323, it was already processed in Figure 28.4 and optp was set to a null
	 *	pointer. If the socket is in the LISTEN state, tcp_dooptions is called in Figure 28.17
	 *	after the peer's address has been recorded in the PCB, because processing the MSS
	 *	option requires knowledge of the route that will be used to this peer.
	 */
	if (optp && tp->t_state != L4_TCP::tcpcb::TCPS_LISTEN)
		tcp_dooptions(*tp, optp, optlen, *ti, ts_present, ts_val, ts_ecr);
	
	/*	
	 * Header prediction: check for the two common cases
	 * of a uni-directional data xfer. If the packet has
	 * no control flags, is in-sequence, the window didn't
	 * change and we're not retransmitting, it's a
	 * candidate. If the length is zero and the ack moved
	 * forward, we're the sender side of the xfer. Just
	 * free the data acked & wake any higher level process
	 * that was blocked waiting for space. If the length
	 * is non-zero and the ack didn't move, we're the
	 * receiver side. If we're getting packets in-order
	 * (the reassembly queue is empty), add the data to
	 * the socket buffer and note that we need a delayed ack.
	 * 
	 *	Check If segment is the next expected:
	 *	The following six conditions must all be true for the segment to be the next expected
	 *	data segment or the next expected ACK:
	 *		1.	The connection state must be ESTABLISHED.
	 *		2.	The following four control flags must not be on: SYN, FIN, RST, or URG. 
	 *			The	ACK flag must be on. 
	 *			In other words, of the six TCP control flags, the ACK flag must be set,
	 *			the four just listed must be cleared, and it doesn't matter whether PSH
	 *			is set or cleared. (Normally in the ESTABLISHED state the ACK flag is 
	 *			always on unless the RST flag is on.)
	 *		3.	If the segment contains a timestamp option, the timestamp value from the other
	 *			end (ts_val) must be greater than or equal to the previous timestamp received
	 *			for this connection (ts_recent). This is basically the PAWS test, which we
	 *			describe in detail in Section 28.7. If ts_val is less than ts_recent, this segment
	 *			is out of order because it was sent before the most previous segment
	 *			received on this connection. Since the other end always sends its timestamp
	 *			clock (the global variable tcp_now in Net/3) as its timestamp value, the
	 *			received timestamps of in-order segments always form a monotonic increasing
	 *			sequence.
	 *			The timestamp need not increase with every in-order segment. Indeed, on a
	 *			Net/3 system that increments the timestamp clock (tcp_now) every 500 ms,
	 *			multiple segments are often sent on a connection before that clock is incremented.
	 *			Think of the timestamp and sequence number as forming a 64-bit
	 *			value, with the sequence number in the low-order 32 bits and the timestamp in
	 *			the high-order 32 bits. This 64-bit value always increases by at least 1 for every
	 *			in-order segment (taking into account the modulo arithmetic).
	 *		4.	The starting sequence number of the segment (ti_seq) must equal the next
	 *			expected receive sequence number (rcv_nxt ). If this test is false, then the
	 *			received segment is either a retransmission or a segment beyond the one
	 *			expected.
	 *		5.	The window advertised by the segment (tiwin) must be nonzero, and must
	 *			equal the current send window (snd_wnd). This means the window has not changed.
	 *		6.	The next sequence number to send (snd_nxt) must equal the highest sequence
	 *			number sent (snd_max). This means the last segment sent by TCP was not a retransmission.
	*/
	if (tp->t_state == L4_TCP::tcpcb::TCPS_ESTABLISHED &&
		(tiflags & (tcphdr::TH_SYN | L4_TCP::tcphdr::TH_FIN | L4_TCP::tcphdr::TH_RST | L4_TCP::tcphdr::TH_URG | L4_TCP::tcphdr::TH_ACK)) == L4_TCP::tcphdr::TH_ACK &&
		(!ts_present || TSTMP_GEQ(ts_val, tp->ts_recent)) &&
		ti->ti_seq() == tp->rcv_nxt &&
		tiwin && tiwin == tp->snd_wnd &&
		tp->snd_nxt == tp->snd_max) 
	{
		/*	
		 *	Update ts_recent from received timestamp:
		 *	If a timestamp option is present and if its value passes the test described with Figure
		 *	26.18, the received timestamp (ts_val) is saved in ts_recent. Also, the current
		 *	time (tcp_now) is recorded in ts_recent_age.
		 *	Recall our discussion with Figure 26.18 on how this test for a valid timestamp is flawed, and
		 *	the correct test presented in Figure 26.20. In this header prediction code the TSTMP_GEQ test in
		 *	Figure 26.20 is redundant, since it was already done as step 3 of the if test at the beginning of
		 *	Figure 28.11.
		 *	
		* If last ACK falls within this segment's sequence numbers,
		*  record the timestamp.
		*/
		if (ts_present && L4_TCP::tcpcb::SEQ_LEQ(ti->ti_seq(), tp->last_ack_sent) &&
			tcpcb::SEQ_LT(tp->last_ack_sent, ti->ti_seq() + ti->ti_len())) 
		{
			tp->ts_recent_age = tcp_now;
			tp->ts_recent = ts_val;
		}

		/*
		*	Test for pure ACK:
		*	If the following four conditions are all true, this segment is a pure ACK.
		*		1.	The segment contains no data (ti_len is 0).
		*		2.	The acknowledgment field in the segment (ti_ack) is greater than the largest
		*			unacknowledged sequence number (snd_una). Since this test is "greater than"
		*			and not "greater than or equal to," it is true only if some positive amount of
		*			data is acknowledged by the ACK.
		*		3.	The acknowledgment field in the segment (ti_ack) is less than or equal to the
		*			maximum sequence number sent (snd_max).
		*		4.	The congestion window (snd_cwnd) is greater than or equal to the current send
		*			window (snd_wnd). This test is true only if the window is fully open, that is,
		*			the connection is not in the middle of slow start or congestion avoidance.
		*/
		if ((ti->ti_len() == 0) &&
			(L4_TCP::tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_una) &&
			tcpcb::SEQ_LEQ(ti->ti_ack(), tp->snd_max) &&
			tp->snd_cwnd >= tp->snd_wnd))
		{
			/*	This is a pure ack for outstanding data.
			*
			*	Update RTT estimators:
			*	If the segment contains a timestamp option, or if a segment was being timed and
			*	the acknowledgment field is greater than the starting sequence number being timed,
			*	tcp_xmi t_timer updates the RTT estimators.
			*/
			if (ts_present)
				tp->tcp_xmit_timer(static_cast<short>(tcp_now - ts_ecr + 1));
			else if (tp->t_rtt && L4_TCP::tcpcb::SEQ_GT(ti->ti_ack(), tp->t_rtseq))
				tp->tcp_xmit_timer(tp->t_rtt);

			/*
			*	Delete acknowledged bytes from send buffer:
			*	acked is the number of bytes acknowledged by the segment. sbdrop deletes those
			*	bytes from the send buffer. The largest unacknowledged sequence number (snd_una)
			*	is set to the acknowledgment field and the received mbuf chain is released. (Since the
			*	length is 0, there should be just a single mbuf containing the headers.)
			*/
			so->so_snd.sbdrop(ti->ti_ack() - tp->snd_una);
			tp->snd_una = ti->ti_ack();

			/*
			*	Stop retransmit timer:
			*	If the received segment acknowledges all outstanding data (snd_una equals
			*	snd_max), the retransmission timer is turned off. Otherwise, if the persist timer is off,
			*	the retransmit timer is restarted using t_rxtcur as the timeout.
			*	Recall that when tcp_output sends a segment, it sets the retransmit timer only if
			*	the timer is not currently enabled. If two segments arc sent one right after the other, the
			*	timer is set when the first is sent, but not touched when the second is sent. But if an
			*	ACK is received only for the first segment, the retransmit timer must be restarted, in
			*	case the second was lost.
			*
			* If all outstanding data are acked, stop
			* retransmit timer, otherwise restart timer
			* using current (possibly backed-off) value.
			* If process is waiting for space,
			* wakeup/selwakeup/signal.  If data
			* are ready to send, let tcp_output
			* decide between more output or persist.
			*/
			if (tp->snd_una == tp->snd_max)
				tp->t_timer[TCPT_REXMT] = 0;
			else if (tp->t_timer[TCPT_PERSIST] == 0)
				tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

			/*
			*	Awaken waiting processes:
			*	If a process must be awakened when the send buffer is modified, sowwakeup is
			*	called. From Figure 16.5, SB_NOTIFY is true if a process is waiting for space in the buffer,
			*	if a process is selecting on the buffer, or if a process wants the SIGIO signal for
			*	this socket.
			*/
			if (so->so_snd.sb_flags & netlab::L5_socket::sockbuf::SB_NOTIFY)
				so->sowwakeup();

			/*
			*	Generate more output:
			*	If there is data in the send buffer, tcp_output is called because the sender's window
			*	has moved to the right. snd_una was just incremented and snd_wnd did not
			*	change, so in Figure 24.17 the entire window has shifted to the right.
			*/
			if (so->so_snd.size())
				(void)tcp_output(*tp);

			return;
		}
		
		/*	
		 *	The next part of header prediction is the receiver processing when the segment is the next in-sequence data segment.
		 *
		 *	Test for next In-sequence data segment:
		 *	If the following four conditions are all true, this segment is the next expected data
		 *	segment for the connection, and there is room in the socket buffer for the data:
		 *		1.	The amount of data in the segment (ti_len) is greater than 0. This is the else
		 *			portion of the if at the beginning of Figure 28.12.
		 *		2.	The acknowledgment field (ti_ack) equals the largest unacknowledged
		 *			sequence number. This means no data is acknowledged by this segment.
		 *		3.	The reassembly list of out-of-order segments for the connection is empty
		 *			(seg_next equals tp).
		 *		4.	There is room in the receive buffer for the data in the segment.
		 */
		else if (ti->ti_ack() == tp->snd_una &&
			tp->seg_next == reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp) &&
			ti->ti_len() <= static_cast<short>(so->so_rcv.sbspace())) 
		{		
			/*	
			 *	Complete processing of received data:
			 *	The next expected receive sequence number (rcv_nxt) is incremented by the number
			 *	of bytes of data. The IP header, TCP header, and any TCP options are dropped from
			 *	the mbuf, and the mbuf chain is appended to the socket's receive buffer. The receiving
			 *	process is awakened by sorwakeup. Notice that this code avoids calling the
			 *	TCP _REASS macro, since the tests performed by that macro have already been performed
			 *	by the header prediction tests. The delayed-ACK flag is set and the input processing
			 *	is complete.
			 *	
			* this is a pure, in-sequence data packet
			* with nothing on the reassembly queue and
			* we have enough buffer space to take it.
			*/
			tp->rcv_nxt += ti->ti_len();

			/*
			* Drop TCP, IP headers and TCP options then add data
			* to socket buffer.
			*/
			so->so_rcv.sbappend(it + (sizeof(struct L4_TCP::tcpiphdr) + off - sizeof(struct L4_TCP::tcphdr)), m->end());
			so->sorwakeup();
			tp->t_flags |= L4_TCP::tcpcb::TF_DELACK;
			return;
		}
	}

	/*	
	 *	TCP Input: Slow Path Processing:
	 *	We continue with the code that's executed if header prediction fails, the slow path
	 *	through tcp_input. Figure 28.14 shows the next piece of code, which prepares the
	 *	received segment for input processing.
	 *	
	 *	Drop IP and TCP headers, Including TCP options:
	 *	The data pointer and length of the first mbuf in the chain are updated to skip over
	 *	the IP header, TCP header, and any TCP options. Since off is the number of bytes in
	 *	the TCP header, including options, the size of the normal TCP header (20) must be subtracted
	 *	from the expression.
	 *
	* Drop TCP, IP headers and TCP options.
	*/
	it += sizeof(struct L4_TCP::tcpiphdr) + off - sizeof(struct L4_TCP::tcphdr);

	/*	
	 *	Calculate receive window
	 *	win is set to the number of bytes available in the socket's receive buffer. 
	 *	rcv_adv - rcv_nxt is the current advertised window. 
	 *	The receive window is the maximum of these two values. 
	 *	The max is taken to ensure that the value is not less than the currently advertised window.
	 *	Also, if the process has taken data out of the socket receive buffer since the window was
	 *	last advertised, win could exceed the advertised window, so TCP accepts up to win
	 *	bytes of data (even though the other end should not be sending more than the advertised window).
	 *	This value is calculated now, since the code later in this function must determine
	 *	how much of the received data (if any) fits within the advertised window. Any received
	 *	data outside the advertised window is dropped: data to the left of the window is duplicate
	 *	data that has already been received and acknowledged, and data to the right	should not be sent 
	 *	by the other end.
	 *	
	* Calculate amount of space in receive window,
	* and then do TCP input processing.
	* Receive window is amount of space in rcv queue,
	* but not less than advertised window.
	*/
	{ 
		int win(so->so_rcv.sbspace());
		if (win < 0) 
			win = 0;
		tp->rcv_wnd = std::max(win, static_cast<int>(tp->rcv_adv - tp->rcv_nxt));
	}

	int needoutput(0);
	switch (tp->t_state) {

		/*	Now we show the processing when the connection is in the LISTEN state. In this
		 *	code the variables tp and inp refer to the new socket that was created in Figure 28.7,
		 *	not the server's listening socket.
		 *	
		* If the state is LISTEN then ignore segment if it contains a RST.
		* If the segment contains an ACK then it is bad and send a RST.
		* If it does not contain a SYN then it is not interesting; drop it.
		* Don't bother responding if the destination was a broadcast.
		* Otherwise initialize tp->rcv_nxt, and tp->irs, select an initial
		* tp->iss, and send a segment:
		*     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
		* Also initialize tp->snd_nxt to tp->iss+1 and tp->snd_una to tp->iss.
		* Fill in remote peer address fields if not previously specified.
		* Enter SYN_RECEIVED state, and process any other fields of this
		* segment in this state.
		*/
	case L4_TCP::tcpcb::TCPS_LISTEN: {

		/*	
		 *	Drop if RST, ACK, or no SYN
		 *	If the received segment contains the RST flag, it is dropped.
		 *	If it contains an ACK, it is dropped and an RST is sent as the reply. 
		 *	(The initial SYN to open a connection is one of the few segments that 
		 *	does not contain an ACK.) 
		 *	If the SYN flag is not set, the segment is dropped. 
		 *	The remaining code for this case handles the reception of a SYN for 
		 *	a connection in the LISTEN state. The new state will be SYN_RCVD.
		 */
		if (tiflags & L4_TCP::tcphdr::TH_RST)
			return drop(tp, dropsocket);
		else if (tiflags & L4_TCP::tcphdr::TH_ACK)
			return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
		else if((tiflags & L4_TCP::tcphdr::TH_SYN) == 0)
			return drop(tp, dropsocket);
	
		/*	
		 *	Get mbuf for client's IP address and port:
		 *	An mbuf is allocated to hold a sockaddr_in structure, and the structure is filled in
		 *	with the client's IP address and port number. The IP address is copied from the source
		 *	address in the IP header and the port number is copied from the source port number in
		 *	the TCP header. This structure is used shortly to connect the server's PCB to the client,
		 *	and then the mbuf is released.
		 *	The XXX comment is probably because of the cost associated with obtaining an mbuf just for
		 *	the call to in_pcbconnect that follows. But this is the slow processing path for TCP input.
		 *	Figure 24.5 shows that less than 2% of all received segments execute this code.
		 */	
		struct sockaddr_in sin;
		size_t sin_len(sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = ti->ti_src();
		sin.sin_port = ti->ti_sport();
		std::memset(sin.sin_zero, 0, sizeof(sin.sin_zero));

		/*	
		 *	Set local address In PCB:
		 *	laddr is the local address bound to the socket. If the server bound the wildcard
		 *	address to the socket (the normal scenario), the destination address from the IP header
		 *	becomes the local address in the PCB. Note that the destination address from the IP
		 *	header is used, regardless of which local interface the datagram was received on.
		 *		Notice that laddr cannot be the wildcard address, because in Figure 28.7 it is explicitly set to
		 *		the destination IP address from the received datagram.
		 */
		const struct in_addr laddr(tp->inp_laddr());
		if (tp->inp_laddr().s_addr == INADDR_ANY)
			tp->inp_laddr() = ti->ti_dst();

		/*	
		 *	Connect PCB to peer:
		 *	in_pcbconnect connects the server's PCB to the client. This fills in the foreign
		 *	address and foreign process in the PCB.
		 */
		if (tp->in_pcbconnect(&sin, sin_len)) {
			tp->inp_laddr() = laddr;
			return drop(tp, dropsocket);
		}

		/*	Allocate and initialize IP and TCP header template
		 *	A template of the IP and TCP headers is created by tcp_template. The call to
		 *	sonewconn in Figure 28.7 allocated the PCB and TCP control block for the new connection,
		 *	but not the header template.
		 */
		tp->tcp_template();
		if (tp->t_template == nullptr) {
			tcp_drop(*tp, ENOBUFS);
			/* socket is already gone */
			return drop(tp, 0);
		}
		
		/*	
		 *	Process any TCP options:
		 *	If TCP options are present, they are processed by tcp_dooptions. The call to this
		 *	function in Figure 28.8 was done only if the connection was not in the LISTEN state.
		 *	This function is called now for a listening socket, after the foreign address is set in the
		 *	PCB, since the foreign address is used by the tcp_mss function: to get a route to the
		 *	peer, and to check if the peer is "local" or "foreign" (with regard to the peer's network
		 *	ID and subnet ID, used to select the MSS).
		 */
		if (optp)
			tcp_dooptions(*tp, optp, optlen, *ti, ts_present, ts_val, ts_ecr);
		
		/*	
		 *	Initialize ISS:
		 *	The initial send sequence number is normally copied from the global tcp_iss,
		 *	which is then incremented by 64,000 (TCP ISSINCR divided by 2). If the local variable
		 *	iss is nonzero, however, its value is used instead of tcp_iss to initialize the send
		 *	sequence number for the connection.
		 *	The local iss variable is used for the following scenario.
		 *		a.	A server is started on port 27 on the host with an IP address of 128.1.2.3.
		 *		b.	A client on host 192.3.4.5 establishes a connection with this server. The client's
		 *			ephemeral port is 3000. The socket pair on the server is {128.1.2.3, 27, 192.3.4.5, 3000}.
		 *		c.	The server actively closes the connection, putting this socket pair into the
		 *			TIME_ WAIT state. While the connection is in this state, the last receive sequence
		 *			number is remembered in the TCP control block. Assume its value is 100,000.
		 *		d.	Before this connection leaves the TIME_WAIT state, a new SYN is received from
		 *			the same port on the same client host (192.3.4.5, port 3000), which locates the
		 *			PCB corresponding to the connection in the TIME_WAIT state, not the PCB for
		 *			the listening server. Assume the sequence number of this new SYN is 200,000.
		 *		e.	Since this connection does not correspond to a listening socket in the LISTEN
		 *			state, the code we just looked at is not executed. Instead, the code in Figure
		 *			28.29 is executed, and we'll see that it contains the following logic: if the
		 *			sequence number of the new SYN (200,000) is greater than the last sequence
		 *			number received from this client (100,000), then 
		 *				(1)	the local variable iss is set to 100,000 plus 128,000, 
		 *				(2) the connection in the TIME_ WAIT state is completely closed 
		 *					(its PCB and TCP control block are deleted), and 
		 *				(3) a jump is made to findpcb (Figure 28.5).
		 *		f.	This time the server's listening PCB will be located (assuming the listening
		 *			server is still running), causing the code in this section to be executed. The local
		 *			variable iss (now 228,000) is used in Figure 28.17 to initialize tcp_iss for the
		 *			new connection.
		 *	This logic, which is allowed by RFC 1122, lets the same client and server reuse the same
		 *	socket pair as long as the server does the active close. This also explains why the global
		 *	variable tcp_iss is incremented by 64,000 each time any process issues a connect
		 *	(Figure 30.4): to ensure that if a single client reopens the same connection with the same
		 *	server repeatedly, a larger ISS is used each time, even if no data was transferred on the
		 *	previous connection, and even if the 500-ms timer (which increments tcp_iss) has not
		 *	expired since the last connection.
		 */
		tp->iss = iss ? iss : tcp_iss;
		TCP_ISSINCR();

		/*	
		 *	Initialize sequence number variables In control block:
		 *	In Figure 28.17, the initial receive sequence number (irs) is copied from the
		 *	sequence number in the SYN segment. The following two macros initialize the appropriate
		 *	variables in the TCP control block:
		 *		inline void tcp_rcvseqinit() {rcv_adv = rcv_nxt = irs + 1; }
		 *		inline void tcp_sendseqinic() {snd_una = snd_nxt = snd_max = snd_up = iss; }
		 *	The addition of 1 in the first inline is because the SYN occupies a sequence number.
		 */
		tp->irs = ti->ti_seq();
		tp->tcp_sendseqinit();
		tp->tcp_rcvseqinit();

		/*	
		 *	ACK the SYN and change state
		 *	The TF_ACKNOW flag is set since the ACK of a SYN is not delayed. The connection
		 *	state becomes TCPS_SYN_RECEIVED, and the connection-establishment timer is set to 75 seconds
		 *	(TCPTV_KEEP_INIT). Since the TF_ACKNOW flag is set, at the bottom of this function
		 *	tcp_output will be called. Looking at Figure 24.16 we see that tcp_outflags will
		 *	cause a segment with the SYN and ACK flags to be sent.
		 */
		tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
		tp->t_state = L4_TCP::tcpcb::TCPS_SYN_RECEIVED;
		tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;

		/*	
		 *	TCP is now committed to the new socket created in Figure 28.7, so the dropsocket
		 *	flag is cleared. The code at trimthenstep6 is jumped to, to complete processing of
		 *	the SYN segment. Remember that a SYN segment can contain data, although the data
		 *	cannot be passed to the application until the connection enters the ESTABLISHED state.
		 */
		dropsocket = 0;		/* committed to socket */
		return trimthenstep6(tp, tiflags, ti, m, it, tiwin, needoutput);
	}

	/*	
	 *	Completion of Active Open:
	 *	the first part of processing when the connection is in the SYN_SENT state. TCP is expecting to receive a SYN.
	* If the state is SYN_SENT:
	*	if seg contains an ACK, but not for our SYN, drop the input.
	*	if seg contains a RST, then drop the connection.
	*	if seg does not contain SYN, then drop it.
	* Otherwise this is an acceptable SYN segment
	*	initialize tp->rcv_nxt and tp->irs
	*	if seg contains ack then advance tp->snd_una
	*	if SYN has been acked change to ESTABLISHED else SYN_RCVD state
	*	arrange for segment to be acked (eventually)
	*	continue processing rest of data/controls, beginning with URG
	*/
	case L4_TCP::tcpcb::TCPS_SYN_SENT:

		/*	
		 *	Verify received ACK:
		 *	When TCP sends a SYN in response to an active open by a process, we'll see in Figure
		 *	30.4 that the connection's iss is copied from the global tcp_iss and the inline
		 *	tcp_sendseqinit (shown at the end of the previous section) is executed. 
		 *	For example, Assuming the ISS is 365, the send sequence variables after the SYN is sent by tcp_output:
		 *			SYN				366				367
		 *			 /\				 /\
		 *			 ||				 ||
		 *			snd_una = 365	snd_nxt = 366
		 *			snd_up = 365	snd_max = 366
		 *	Figure 28.19 Send variables after SYN is sent with sequence number 365.
		 *	
		 *	tcp_sendseqinit sets all four of these variables to 365, then Figure 26.31 increments
		 *	two of them to 366 when the SYN segment is output. Therefore, if the received
		 *	segment in Figure 28.18 contains an ACK, and if the acknowledgment field is less than
		 *	or equal to iss (365) or greater than snd_max (366), the ACK is invalid, causing the
		 *	segment to be dropped and an RST sent in reply. Notice that the received segment for a
		 *	connection in the SYN_SENT state need not contain an ACK. It can contain only a SYN,
		 *	which is called a simultaneous open (Figure 24.15), and is described shortly.
		 */
		if ((tiflags & L4_TCP::tcphdr::TH_ACK) &&
			(L4_TCP::tcpcb::SEQ_LEQ(ti->ti_ack(), tp->iss) || L4_TCP::tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_max)))
			return dropwithreset(tp, dropsocket, tiflags, m, it, ti);

		/*	
		 *	Process and drop RST segment:
		 *	If the received segment contains an RST, it is dropped. But the ACK flag was
		 *	checked first because receipt of an acceptable ACK (which was just verified) and an RST
		 *	in response to a SYN is how the other end tells TCP that its connection request was
		 *	refused. Normally this is caused by the server process not being started on the other
		 *	host. In this case tcp_drop sets the socket's so_error variable, causing an error to be
		 *	returned to the process that called connect.
		 */
		if (tiflags & L4_TCP::tcphdr::TH_RST)
			if (tiflags & L4_TCP::tcphdr::TH_ACK)
				tcp_drop(*tp, ECONNREFUSED);
			else
				return drop(tp, dropsocket);

		/*	
		 *	Verify SYN flag set:
		 *	If the SYN flag is not set in the received segment, it is dropped.
		 */
		if ((tiflags & L4_TCP::tcphdr::TH_SYN) == 0)
			return drop(tp, dropsocket);

		/*	
		 *	The remainder of this case handles the receipt of a SYN (with an optional ACK) in
		 *	response to TCP's SYN. The next part of tcp_input, shown in Figure 28.20, continues
		 *	processing the SYN.
		 *	
		 *	Process ACK:
		 *	If the received segment contains an ACK, snd_una is set to the acknowledgment
		 *	field. In Figure 28.19, snd_una becomes 366, since 366 is the only acceptable value for
		 *	the acknowledgment field. If snd_nxt is less than snd_una (which shouldn't happen,
		 *	given Figure 28.19), snd_nxt is set to snd_una.
		 */
		if (tiflags & L4_TCP::tcphdr::TH_ACK) {
			tp->snd_una = ti->ti_ack();
			if (L4_TCP::tcpcb::SEQ_LT(tp->snd_nxt, tp->snd_una))
				tp->snd_nxt = tp->snd_una;
		}

		/*	
		 *	Tum off retransmission timer:
		 *	The retransmission timer is turned off.
		 *		This is a bug. This timer should be turned off only if the ACK flag is set, since the receipt of a
		 *		SYN without an ACK is a simultaneous open, and doesn't mean the other end received TCP's
		 *		SYN.
		 */
		tp->t_timer[TCPT_REXMT] = 0;

		/*	
		 *	Initialize receive sequence numbers:
		 *	The initial receive sequence number is copied from the sequence number of the
		 *	received segment. The tcp_rcvseqini t macro (shown at the end of the previous section)
		 *	initializes rcv_adv and rcv_nxt to the receive sequence number, plus 1. The
		 *	TF ACKNOW flag is set, causing tcp_output to be called at the bottom of this function.
		 *	The segment it sends will contain rcv_nxt as the acknowledgment field (Figure 26.27),
		 *	which acknowledges the SYN just received.
		 */
		tp->irs = ti->ti_seq();
		tp->tcp_rcvseqinit();
		tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;

		/*	
		 *	If the received segment contains an ACK, and if snd_una is greater than the ISS for
		 *	the connection, the active open is complete, and the connection is established.
		 *	This second test appears superfluous. At the beginning of Figure 28.20 snd_una was set to the
		 *	received acknowledgment field if the ACK flag was on. Also the if following the case
		 *	statement in Figure 28.18 verified that the received acknowledgment field is greater than the
		 *	ISS. So at this point in the code, if the ACK flag is set, we're already guaranteed that snd_una
		 *	is greater than the ISS.
		 */
		if (tiflags & L4_TCP::tcphdr::TH_ACK && L4_TCP::tcpcb::SEQ_GT(tp->snd_una, tp->iss)) {
			
			/*	
			 *	Connection Is established:
			 *	soisconnected sets the socket state to connected, and the state of the TCP connection
			 *	is set to ESTABLISHED.
			 */
			so->soisconnected();
			tp->t_state = L4_TCP::tcpcb::TCPS_ESTABLISHED;

			/* 
			 * Check for window scale option:
			 * If TCP sent the window scale option in its SYN and the received SYN also contains
			 * the option, the option is enabled and the two variables snd_scale and rcv_scale are
			 * set. Since the TCP control block is initialized to 0 by tcp_newtcpcb, these two variables
			 * correctly default to 0 if the window scale option is not used.
			 * 
			 * Do window scaling on this connection?
			 */
			if ((tp->t_flags & (L4_TCP::tcpcb::TF_RCVD_SCALE | L4_TCP::tcpcb::TF_REQ_SCALE)) ==
				(L4_TCP::tcpcb::TF_RCVD_SCALE | L4_TCP::tcpcb::TF_REQ_SCALE)) 
			{
				tp->snd_scale = tp->requested_s_scale;
				tp->rcv_scale = tp->request_r_scale;
			}

			/*	
			 *	Pass any queued data to process:
			 *	Since data can arrive for a connection before the connection is established, any such
			 *	data is now placed in the receive buffer by calling tcp_reass with a null pointer as the
			 *	second argument.
			 *		Remark: This test is unnecessary. In this piece of code, TCP has just received the SYN with an ACK that
			 *				moves it from the SYN_SENT state to the ESTABLISHED state. If data appears with this
			 *				received SYN segment, it isn't processed until the label dodata near the end of the function. If
			 *				TCP just received a SYN without an ACK (a simultaneous open) but with some data, that data
			 *				is handled later (Figure 29.2) when the ACK is received that moves the connection from the
			 *				SYN_RCVD state to the ESTABLISHED state.
			 *				Although it is valid for data to accompany a SYN, and Net/3 handles this type of received segment
			 *				correctly, Net/3 never generates such a segment.
			 */
			(void)tcp_reass(tp, nullptr, nullptr, std::vector<byte>::iterator());

			/*	
			 *	Update RTT estimators:
			 *	If the SYN that is ACKed was being timed, tcp_xrnit_timer initializes the RIT
			 *	estimators based on the measured RTT for the SYN.
			 *		Remark:	TCP ignores a received timestamp option here, and checks only the t_rtt counter. TCP sends
			 *				a timestamp in a SYN generated by an active open (Figure 26.24) and if the other end agrees to
			 *				the option, the other end should echo the received timestamp in its SYN. (Net/3 echoes the
			 *				received timestamp in a SYN in Figure 28.10.) This would allow TCP to use the received timestamp
			 *				here, instead of t_rtt, but since both have the same precision (500 ms) there's no
			 *				advantage in using the timestamp value. The real advantage in using the timestamp option,
			 *				instead of the t_rtt counter, is with large pipes, when lots of segments are in flight at once,
			 *				providing more RTT timings and (it is hoped) better estimators.
			 *				
			* if we didn't have to retransmit the SYN,
			* use its rtt as our initial srtt & rtt var.
			*/
			if (tp->t_rtt)
				tp->tcp_xmit_timer(tp->t_rtt);
		}

		/*	
		 *	Simultaneous open:
		 *	When TCP receives a SYN without an ACK in the SYN_SENT state, it is a simultaneous
		 *	open and the connection moves to the SYN_RCVD state.
		 */
		else
			tp->t_state = L4_TCP::tcpcb::TCPS_SYN_RECEIVED;
		
		return trimthenstep6(tp, tiflags, ti, m, it, tiwin, needoutput);
	}

	/*	
	 *	PAWS: Protection Against Wrapped Sequence Numbers:
	 *	The next part of tcp_input, shown in Figure 28.22, provides protection against
	 *	wrapped sequence numbers: the PAWS algorithm from RFC 1323. Also recall our discussion
	 *	of the timestamp option in Section 26.6.
	 *	
	 *	Basic PAWS test:
	 *	ts_present was set by tcp_dooptions if a timestamp option was present. If
	 *	the following three conditions are all true, the segment is dropped:
	 *		1.	the RST flag is not set (Exercise 28.8),
	 *		2.	TCP has received a valid timestamp from this peer (ts_recent is nonzero), and
	 *		3.	the received timestamp in this segment (ts_val) is less than the previously
	 *			received timestamp from this peer.
	 *	PAWS is built on the premise that the 32-bit timestamp values wrap around at a much
	 *	lower frequency than the 32-bit sequence numbers, on a high-speed connection. Exercise
	 *	28.6 shows that even at the highest possible timestamp counter frequency (incrementing
	 *	by 1 bit every millisecond), the sign bit of the timestamp wraps around only
	 *	every 24 days. On a high-speed network such as a gigabit network, the sequence
	 *	number can wrap in 17 seconds (Section 24.3 of Volume 1). Therefore, if the received
	 *	timestamp value is less than the most recent one from this peer, this segment is old and
	 *	must be discarded (subject to the outdated timestamp test that follows). The packet
	 *	might be discarded later in the input processing because the sequence number is "old,"
	 *	but PAWS is intended for high-speed connections where the sequence numbers can
	 *	wrap quickly.
	 *	Notice that the PAWS algorithm is symmetric: it not only discards duplicate data
	 *	segments but also discards duplicate ACKs. All received segments are subject to PAWS.
	 *	Recall that the header prediction code also applied the PAWS test (Figure 28.11).
	 *	
	* States other than LISTEN or SYN_SENT.
	* First check timestamp, if present.
	* Then check that at least some bytes of segment are within
	* receive window.  If segment begins before rcv_nxt,
	* drop leading data (and SYN); if nothing left, just ack.
	*
	* RFC 1323 PAWS: If we have a timestamp reply on this segment
	* and it's less than ts_recent, drop it.
	*/
	if (ts_present && 
		(tiflags & L4_TCP::tcphdr::TH_RST) == 0 && 
		tp->ts_recent &&
		TSTMP_LT(ts_val, tp->ts_recent))

		/*
		 *	Check for outdated timestamp:
		 *	There is a small possibility that the reason the PAWS test fails is because the connection
		 *	has been idle for a long time. The received segment is not a duplicate; it is just that
		 *	because the connection has been idle for so long, the peer's timestamp value has
		 *	wrapped around when compared to the most recent timestamp from that peer.
		 *	Whenever ts_recent is copied from the timestamp in a received segment,
		 *	ts_recent_age records the current time (tcp_now). If the time at which ts_recent
		 *	was saved is more than 24 days ago, it is set to 0 to invalidate it. The constant
		 *	TCP_PAWS_IDLE is defined to be (24 x 24 x 60 x 60 x 2), the final 2 being the number of
		 *	ticks per second. The received segment is not dropped in this case, since the problem is
		 *	not a duplicated segment, but an outdated timestamp. See also Exercises 28.6 and 28.7.
		 *	Figure 28.23 shows an example of an outdated timestamp. The system on the left is
		 *	a non-Net/3 system that increments its timestamp clock at the highest frequency
		 *	allowed by RFC 1323: once every millisecond. The system on the right is a Net/3 system.
		 *					data, timestamp = 1
		 *	timestamp = 1	----------------------------------------->		\ts_recent = ts_val = 1
		 *					<-----------------------------------------		/ts_recent_age = tcp_now = N
		 *							ACK										\
		 *																	|
		 *																	|	connection idle
		 *																	 >	for 25 days =
		 *	timestamp = 2,147,483,649	\	timestamp						|	4,320,000 ticb
		 *	timestamp = 2,147,483,650	/	changes sign					|
		 *																	/
		 *								data, timestamp = 2,160,000,001		\	ts_ val= 2,160,000,001
		 *	timestamp = 2,160,000,001	------------------------------>		 >			< ts_recent = l					
		 *																	/	tcp_now = N + 4,320,000
		 *	Figure 28.23 Example of outdated timestamp.
		 *	
		 *	When the data segment arrives with a timestamp of 1, that value is saved in
		 *	ts_recent and ts_recent_age is set to the current time (tcp_now), as shown in
		 *	Figures 28.11 and 28.35. The connection is then idle for 25 days, during which time
		 *	tcp_now will increase by 4,320,000 (25 x 24 x 60 x 60 x 2). During these 25 days the
		 *	other end's timestamp clock will increase by 2,160,000,000 (25 x 24 x 60 x 60 x 1000).
		 *	During this interval the timestamp "changes sign" with regard to the value 1, that is,
		 *	2,147,483,649 is greater than 1, but 2,147,483,650 is less than 1 (recall Figure 24.26).
		 *	Therefore, when the data segment is received with a timestamp of 2,160,000,001, this
		 *	value is less than ts_recent (1), when compared using the TSTMP_LT macro, so the
		 *	PAWS test fails. But since tcp_now minus ts_recent_age is greater than 24 days, the
		 *	reason for the failure is that the connection has been idle for more than 24 days, and the
		 *	segment is accepted.
		 *	
		 * Check to see if ts_recent is over 24 days old.  */
		if (static_cast<int>(tcp_now - tp->ts_recent_age) > TCP_PAWS_IDLE) 

			/*
			* Invalidate ts_recent.  If this segment updates
			* ts_recent, the age will be reset later and ts_recent
			* will get a valid value.  If it does not, setting
			* ts_recent to zero will at least satisfy the
			* requirement that zero be placed in the timestamp
			* echo reply when ts_recent isn't valid.  The
			* age isn't reset until we get a valid ts_recent
			* because we don't want out-of-order segments to be
			* dropped when ts_recent is old.
			*/
			tp->ts_recent = 0;
		else 

			/*	
			 *	Drop duplicate segment:
			 *	The segment is determined to be a duplicate based on the PAWS algorithm, and the
			 *	timestamp is not outdated. It is dropped, after being acknowledged (since all duplicate
			 *	segments are acknowledged).
			 *		Remark:	Figure 24.S shows a much smaller value for tcps_pawsdrop (22) than for
			 *				tcps_rcvduppack (46,953). This is probably because fewer systems support the timestamp
			 *				option today, causing most duplicate packets to be discarded by later tests in TCP's input processing
			 *				instead of by PAWS.
			 */
			 return dropafterack(tp, dropsocket, tiflags);

	/*	
	 *	Trim Segment so Data Is Within Window:
	 *	This section trims the received segment so that it contains only data that is within the
	 *	advertised window:
	 *		a.	duplicate data at the beginning of the received segment is discarded, and
	 *		b.	data that is beyond the end of the window is discarded from the end of the segment.
	 *	What remains is new data within the window. The code shown in Figure 28.24 checks if
	 *	there is any duplicate data at the beginning of the segment.
	 *	
	 *	Check If any duplicate data at front of segment:
	 *	If the starting sequence number of the received segment (ti_seq) is less than the
	 *	next receive sequence number expected (rcv_nxt), data at the beginning of the segment
	 *	is old and todrop will be greater than 0. These data bytes have already been
	 *	acknowledged and passed to the application (Figure 24.18).
	 */
	int todrop(tp->rcv_nxt - ti->ti_seq());
	if (todrop > 0) {

		/*	
		 *	Remove duplicate SYN:
		 *	If the SYN flag is set, it refers to the first sequence number in the segment, which is
		 *	known to be old. The SYN flag is cleared and the starting sequence number of the segment
		 *	is incremented by 1 to skip over the duplicate SYN. Furthermore, if the urgent offset
		 *	in the received segment (ti_urp) is greater than 1, it must be decremented by 1,
		 *	since the urgent offset is relative to the starting sequence number, which was just incremented.
		 *	If the urgent offset is 0 or 1, it is left alone, but in case it was 1, the URG flag is
		 *	cleared. Finally todrop is decremented by 1 (since the SYN occupies a sequence number).
		 *	The handling of duplicate data at the front of the segment continues in Figure 28.25.
		 */
		if (tiflags & L4_TCP::tcphdr::TH_SYN) 
		{
			tiflags &= ~tcphdr::TH_SYN;
			ti->ti_seq()++;
			if (ti->ti_urp() > 1)
				ti->ti_urp()--;
			else
				tiflags &= ~tcphdr::TH_URG;
			todrop--;
		}

#ifdef FIXBUG_959

		/*
		*	When to Drop an ACK:
		*	The code in Figure 28.25 has a bug that causes a jump to dropafterack in several
		*	cases when the code should fall through for further processing of the segment [Carlson
		*	1993; Lanciani 1993). In an actual scenario, when both ends of a connection had a hole
		*	in the data on the reassembly queue and both ends enter the persist state, the connection
		*	becomes deadlocked as both ends throw away perfectly good ACKs.
		*	The fix is to simplify the code at the beginning of Figure 28.25. Instead of jumping
		*	to dropafterack, a completely duplicate segment causes the FIN flag to be turned off
		*	and an immediate ACK to be generated at the end of the function. Lines 646-676 in
		*	Figure 28.25 are replaced with the code shown in Figure 28.30. This code also corrects
		*	another bug present in the original code (Exercise 28.9).
		*/
		if (todrop > ti->ti_len() ||
			todrop == ti->ti_len() && (tiflags & L4_TCP::tcphdr::TH_FIN) == 0) {

			/*
			* Any valid FIN must be to the left of the window.
			* At this point the FIN must be a duplicate or
			* out of sequence; drop it.
			*/
			tiflags &= ~tcphdr::TH_FIN;

			/*
			* Send an ACK to resynchronize and drop any data.
			* But keep on processing for RST or ACK.
			*/
			tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
			todrop = ti->ti_len();
		}
#else
		/*
		*	Check for entire duplicate packet:
		*	If the amount of duplicate data at the front of the segment is greater than or equal to
		*	the size of the segment, the entire segment is a duplicate.
		*/
		if (todrop >= ti->ti_len()) {

			/*
			*	Check for duplicate FIN:
			*	The next check is whether the FIN is duplicated. Figure 28.26 shows an example of
			*	this.
			*	In this example todrop equals 5, which is greater than or equal to ti_len (4). Since
			*	the FIN flag is set and todrop equals ti_len plus 1, todrop is set to 4, the FIN flag is
			*	cleared, and the T_ ACKNOW flag is set, forcing an immediate ACK to be sent at the end
			*	of this function. This example also works for other segments if ti_seq plus ti_len
			*	equals 10.
			*		Remark:	The code contains the comment regarding 4.2850 keepalives. This code (another test within
			*				the if statement) is omitted.
			*
			* If segment is just one to the left of the window,
			* check two special cases:
			* 1. Don't toss RST in response to 4.2-style keepalive.
			* 2. If the only thing to drop is a FIN, we can drop
			*    it, but check the ACK or we will get into FIN
			*    wars if our FINs crossed (both CLOSING).
			* In either case, send ACK to resynchronize,
			* but keep on processing for RST or ACK.
			*/
			if ((tiflags & L4_TCP::tcphdr::TH_FIN && todrop == ti->ti_len() + 1)
#ifdef TCP_COMPAT_42
				|| (tiflags & L4_TCP::tcphdr::TH_RST && ti->ti_seq() == tp->rcv_nxt - 1)
#endif
				) {
				todrop = ti->ti_len();
				tiflags &= ~tcphdr::TH_FIN;
			}

			/*
			 *	Generate duplicate ACK:
			 *	If todrop is nonzero (the completely duplicate segment contains data) or the ACK
			 *	flag is not set, the segment is dropped and an ACK is generated by dropafterack.
			 *	This normally occurs when the other end did not receive our ACK, causing the other
			 *	end to retransmit the segment. TCP generates another ACK.
			 *
			 *	Handle simultaneous open or self-connect:
			 *	This code also handles either a simultaneous open or a socket that connects to itself.
			 *	We go over both of these scenarios in the next section. If todrop equals 0 (there is no
			 *	data in the completely duplicate segment) and the ACK flag is set, processing is allowed
			 *	to continue.
			 *		Remark:	This if statement is new with 4.4BSD. Earlier Berkeley-derived systems just had a jump to
			 *				dropafterack. These systems could not handle either a simultaneous open or a socket connecting to itself.
			 *				Nevertheless, the piece of code in this figure still has bugs, which we describe at the end of this section.
			 *
			 * Handle the case when a bound socket connects
			 * to itself. Allow packets with a SYN and
			 * an ACK to continue with the processing.
			 */
			else if (todrop != 0 || (tiflags & L4_TCP::tcphdr::TH_ACK) == 0)
				return dropafterack(tp, dropsocket, tiflags);
		}
		tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
#endif

		/*	
		 *	Remove duplicate data and update urgent offset:
		 *	The duplicate bytes are removed from the front of the mbuf chain by m_adj and the
		 *	starting sequence number and length adjusted appropriately. If the urgent offset points
		 *	to data still in the mbuf, it is also adjusted. Otherwise the urgent offset is set to 0 and
		 *	the URG flag is cleared.
		 */
		std::move(it + todrop, m->end(), it);
		m->resize(m->size() - todrop);
		ti->ti_seq() += todrop;
		ti->ti_len() -= todrop;
		if (ti->ti_urp() > todrop)
			ti->ti_urp() -= todrop;
		else {
			tiflags &= ~tcphdr::TH_URG;
			ti->ti_urp() = 0;
		}
	}

	/*	
	 *	The next part of input processing handles data that arrives after the process has terminated.
	 *	
	 *	If the socket has no descriptor referencing it, the process has closed the connection
	 *	(the state is any one of the five with a value greater than CLOSE_WAIT in Figure 24.16),
	 *	and there is data in the received segment, the connection is closed. The segment is then
	 *	dropped and an RST is output.
	 *	Because of TCP's half-close, if a process terminates unexpectedly (perhaps it is terminated
	 *	by a signal), when the kernel closes all open descriptors as part of process termination,
	 *	a FIN is output by TCP. The connection moves into the FIN_WAIT_l state.
	 *	But the receipt of the FIN by the other end doesn't tell TCP whether this end performed
	 *	a half-close or a full-close. If the other end assumes a half-close, and sends more data, it
	 *	will receive an RST from the code in Figure 28.27.
	 *	
	* If new data are received on a connection after the
	* user processes are gone, then RST the other end.
	*/
	if ((so->so_state & socket::SS_NOFDREF) &&
		tp->t_state > L4_TCP::tcpcb::TCPS_CLOSE_WAIT && ti->ti_len()) 
	{
		(void)tcp_close(*tp);
		return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
	}

	/*	
	 *	The next piece of code removes any data from the end of the 
	 *	received segment that is beyond the right edge of the advertised window.
	 *	
	 *	Calculate number of bytes beyond right edge of window:
	 *	todrop contains the number of bytes of data beyond the right edge of the window.
	 *	For example, in Figure 28.28, todrop would be (6 + 5) minus (4 + 6), or 1.
	 *	
	* If segment ends after window, drop trailing data
	* (and PUSH and FIN); if nothing left, just ACK.
	*/
	if ((todrop = (ti->ti_seq() + ti->ti_len()) - (tp->rcv_nxt + tp->rcv_wnd)) > 0) {
		if (todrop >= ti->ti_len()) 

			/*
			*	Check for new Incarnation of a connection in the TIME_WAIT state:
			*	If todrop is greater than or equal to the length of the segment, the entire segment
			*	will be dropped. If the following three conditions are all true:
			*		1.	the SYN flag is set, and
			*		2.	the connection is in the TIME_ WAIT state, and
			*		3.	the new starting sequence number is greater than the final sequence number for
			*			the connection,
			*	this is a request for a new incarnation of a connection that was recently terminated and
			*	is currently in the TIME_WAIT state. This is allowed by RFC 1122, but the ISS for the
			*	new connection must be greater than the last sequence number used (rcv_nxt). TCP
			*	adds 128,000 (TCP_ISSINCR), which becomes the ISS when the code in Figure 28.17 is
			*	executed. The PCB and TCP control block for the connection in the TIME_WAIT state is
			*	discarded by tcp_close. A jump is made to findpcb (Figure 28.5) to locate the PCB
			*	for the listening server, assuming it is still running. The code in Figure 28.7 is then executed,
			*	creating a new socket for the new connection, and finally the code in Figures
			*	28.16 and 28.17 will complete the new connection request.
			*
			* If a new connection request is received
			* while in TIME_WAIT, drop the old connection
			* and start over if the sequence numbers
			* are above the previous ones.
			*/
			if (tiflags & L4_TCP::tcphdr::TH_SYN &&
				tp->t_state == L4_TCP::tcpcb::TCPS_TIME_WAIT &&
				tcpcb::SEQ_GT(ti->ti_seq(), tp->rcv_nxt)) 
			{
				iss = tp->snd_nxt;
				TCP_ISSINCR();
				(void)tcp_close(*tp);
				goto findpcb;
			}

		/*
		*	Check for probe of closed window:
		*	If the receive window is closed (rcv_wnd equals 0) and the received segment starts
		*	at the left edge of the window (rcv_nxt), then the other end is probing TCP's closed
		*	window. An immediate ACK is sent as the reply, even though the ACK may still advertise
		*	a window of 0. Processing of the received segment also continues for this case.
		*
		* If window is closed can only take segments at
		* window edge, and have to drop data and PUSH from
		* incoming segments.  Continue processing, but
		* remember to ack.  Otherwise, drop segment
		* and ack.
		*/
			else if (tp->rcv_wnd == 0 && ti->ti_seq() == tp->rcv_nxt)
				tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
			else

				/*
				*	Drop other segments that are completely outside window
				*	The entire segment lies outside the window and it is not a window probe, so the
				*	segment is discarded and an ACK is sent as the reply. This ACK will contain the
				*	expected sequence number.
				*/
				return dropafterack(tp, dropsocket, tiflags);		

		/*	
		 *	Handle segments that contain some valid data:
		 *	The data to the right of the window is discarded from the mbuf chain by m_adj and
		 *	ti_len is updated. In the case of a probe into a closed window, this discards all the
		 *	data in the mbuf chain and sets ti_len to 0. Finally the FIN and PSH flags are cleared.
		 */
		m->resize(m->size() - todrop);
		ti->ti_len() -= todrop;
		tiflags &= ~(tcphdr::TH_PUSH | L4_TCP::tcphdr::TH_FIN);
	}

	/*
	 *	Record Timestamp:
	 *	The next part of tcp_input handles a received timestamp option.
	 *	
	 *	If the received segment contains a timestamp, the timestamp value is saved in
	 *	ts_recent. We discussed in Section 26.6 how this code used by Net/3 is flawed. 
	 *	The expression:
	 *					((tiflags & (TH_SYN || TH_FIN)) != 0)
	 *	is 0 if neither of the two flags is set, or 1 if either is set. This effectively adds 1 to
	 *	ti_len if either flag is set.
	 *	
	* If last ACK falls within this segment's sequence numbers,
	* record its timestamp.
	*/
	if (ts_present && L4_TCP::tcpcb::SEQ_LEQ(ti->ti_seq(), tp->last_ack_sent) &&
		tcpcb::SEQ_LT(tp->last_ack_sent, ti->ti_seq() + ti->ti_len() + ((tiflags & (tcphdr::TH_SYN | L4_TCP::tcphdr::TH_FIN)) != 0))) 
	{
		tp->ts_recent_age = tcp_now;
		tp->ts_recent = ts_val;
	}

	/*	
	 *	RST Processing:
	 *	Figure 28.36 shows the switch statement to handle the RST flag, which depends on the
	 *	connection state.
	 *	
	* If the RST bit is set examine the state:
	*    SYN_RECEIVED STATE:
	*	If passive open, return to LISTEN state.
	*	If active open, inform user that connection was refused.
	*    ESTABLISHED, FIN_WAIT_1, FIN_WAIT2, CLOSE_WAIT STATES:
	*	Inform user that connection was reset, and close tcb.
	*    CLOSING, LAST_ACK, TIME_WAIT STATES
	*	Close the tcb.
	*/
	if (tiflags & L4_TCP::tcphdr::TH_RST) 
		switch (tp->t_state) {

		/*
		 *	SYN_RCVD state:
		 *	The socket's error code is set to ECONNREFUSED, and a jump is made a few lines forward
		 *	to close the socket.
		 *	This state can be entered from two directions. Normally it is entered from the LISTEN state,
		 *	after a SYN has been received. TCP replied with a SYN and an ACK but received an RST in reply.
		 *	Perhaps the other end sent its SYN and then terminated before the reply arrived, causing it
		 *	to send an RST. In this case the socket referred to by so is the new socket created by sonewconn
		 *	in Figure 28.7. Since dropsocket will still be true, the socket is discarded at the label drop.
		 *	The listening descriptor isn't affected at all. This is why we show the state transition from
		 *	SYN_RCVD back to LISTEN in Figure 24.15.
		 *	This state can also be entered by a simultaneous open, after a process has called connect.
		 *	In this case the socket error is returned to the process.
		 */
		case L4_TCP::tcpcb::TCPS_SYN_RECEIVED :
			so->so_error = ECONNREFUSED;
			tp->t_state = L4_TCP::tcpcb::TCPS_CLOSED;
			(void)tcp_close(*tp);
			return drop(tp, dropsocket);

			/*	
			 *	Other states:
			 *	The receipt of an RST in the ESTABLISHED, FIN_WAIT_l, FIN_WAIT_2, or
			 *	CLOSE_WAIT states returns the error ECONNRESET. In the CLOSING, LAST_ACK, and
			 *	TIME_WAIT state an error is not generated, since the process has closed the socket.
			 *		Remark:	Allowing an RST to terminate a connection in the TIME_WAIT state circumvents the reason
			 *				this state exists. RFC 1337 [Braden 1992] discusses this and other forms of "TIME_WAIT
			 *				assassination hazards" and recommends not letting an RST prematurely terminate the TIME_WAIT
			 *				state. See Exercise 28.10 for an example.
			 */
		case L4_TCP::tcpcb::TCPS_ESTABLISHED :
		case L4_TCP::tcpcb::TCPS_FIN_WAIT_1 :
		case L4_TCP::tcpcb::TCPS_FIN_WAIT_2 :
		case L4_TCP::tcpcb::TCPS_CLOSE_WAIT :
			so->so_error = ECONNRESET;
			tp->t_state = L4_TCP::tcpcb::TCPS_CLOSED;
			(void)tcp_close(*tp);
			return drop(tp, dropsocket);

		case L4_TCP::tcpcb::TCPS_CLOSING:
		case L4_TCP::tcpcb::TCPS_LAST_ACK:
		case L4_TCP::tcpcb::TCPS_TIME_WAIT:
			(void)tcp_close(*tp);
			return drop(tp, dropsocket);
	}

	/*
	 *	The next piece of code checks for erroneous SYNs and verifies that an ACK is present.
	 *	If the SYN flag is still set, this is an error and the connection is dropped with the
	 *	error ECONNRESET.
	 *	
	* If a SYN is in the window, then this is an
	* error and we send an RST and drop the connection.
	*/
	if (tiflags & L4_TCP::tcphdr::TH_SYN) {
		tcp_drop(*tp, ECONNRESET);
		return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
	}

	/*	
	 *	If the ACK flag is not set, the segment is dropped. The remainder of this function,
	 *	which we continue in the next chapter, assumes the ACK flag is set.
	 *	
	* If the ACK bit is off we drop the segment and return.
	*/
	if ((tiflags & L4_TCP::tcphdr::TH_ACK) == 0)
		return drop(tp, dropsocket);

	/*	
	 *	ACK Processing Overview:
	 *	We begin this chapter with ACK processing, a summary of which is shown in Figure
	 *	29.1. The SYN_RCVD state is handled specially, followed by common processing
	 *	for all remaining states. (Remember that a received ACK in either the LISTEN or
	 *	SYN_SENT state was discussed in the previous chapter.) This is followed by special
	 *	processing for the three states in which a received ACK causes a state transition, and for
	 *	the TIME_WAIT state, in which the receipt of an ACK causes the 2MSL timer to be
	 *	restarted.
	 *	
	 *	
	 *	Completion of Passive Opens and Simultaneous Opens:
	 *	The first part of the ACK processing, shown in Figure 29.2, handles the SYN_RCVD
	 *	state. As mentioned in the previous chapter, this handles the completion of a passive
	 *	open (the common case) and also handles simultaneous opens and self-connects (the
	 *	infrequent case).
	 */
	std::vector<byte>::iterator tcpreass;
	switch (tp->t_state) {

		/*
		* In SYN_RECEIVED state if the ack ACKs our SYN then enter
		* ESTABLISHED state and continue processing, otherwise
		* send an RST.
		*/
	case L4_TCP::tcpcb::TCPS_SYN_RECEIVED:
		
		/*	
		 *	Verify received ACK:
		 *	For the ACK to acknowledge the SYN that was sent, it must be greater than
		 *	snd_una (which is set to the ISS for the colUlection, the sequence number of the SYN,
		 *	by tcp_sendseqinit) and less than or equal to snd_max. If so, the socket is marked
		 *	as connected and the state becomes ESTABLISHED.
		 *	Since soisconnected wakes up the process that performed the passive open (normally
		 *	a server), we see that this doesn't occur until the last of the three segments in the
		 *	three-way handshake has been received. If the server is blocked in a call to accept,
		 *	that call now returns; if the server is blocked in a call to select ·waiting for the listening
		 *	descriptor to become readable, it is now readable.
		 */
		if (L4_TCP::tcpcb::SEQ_GT(tp->snd_una, ti->ti_ack()) || L4_TCP::tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_max))
			return dropwithreset(tp, dropsocket, tiflags, m, it, ti);
		
		so->soisconnected();
		tp->t_state = L4_TCP::tcpcb::TCPS_ESTABLISHED;
		
		/*	
		 *	Check for window scale option:
		 *	If TCP sent a window scale option and received one, the send and receive scale factors
		 *	are saved in the TCP control block. Otherwise the default values of snd_scale
		 *	and rcv_scale in the TCP control block are 0 (no scaling).
		 *	
		 * Do window scaling? 
		 */
		if ((tp->t_flags & (L4_TCP::tcpcb::TF_RCVD_SCALE | L4_TCP::tcpcb::TF_REQ_SCALE)) ==
			(L4_TCP::tcpcb::TF_RCVD_SCALE | L4_TCP::tcpcb::TF_REQ_SCALE)) 
		{
			tp->snd_scale = tp->requested_s_scale;
			tp->rcv_scale = tp->request_r_scale;
		}

		/*	
		 *	Pass queued data to process
		 *	Any data queued for the connection can now be passed to the process. This is done
		 *	by tcp_reass with a null pointer as the second argument. This data would have
		 *	arrived with the SYN that moved the connection into the SYN_RCVD state.
		 */
		(void)tcp_reass(tp, nullptr, nullptr, tcpreass);

		/*	
		 *	snd_wl1 is set to the received sequence number minus 1. We'll see in Figure 29.15
		 *	that this causes the three window update variables to be updated.
		 */
		tp->snd_wl1 = ti->ti_seq() - 1;

		/* fall into ... 
		 * 
		 *	Fast Retransmit and Fast Recovery Algorithms:
		 *	The next part of ACK processing, shown in Figure 29.3, handles duplicate ACKs and
		 *	determines if TCP's fast retransmit and fast recovery algorithms [Jacobson 1990c]
		 *	should come into play. The two algorithms are separate but are normally implemented
		 *	together [Floyd 1994).
		 *		a.	The fast retransmit algorithm occurs when TCP deduces from a small number
		 *			(normally 3) of consecutive duplicate ACKs that a segment has been lost and
		 *			deduces the starting sequence number of the missing segment. The missing segment
		 *			is retransmitted. The algorithm is mentioned in Section 4.2.2.21 of
		 *			RFC 1122, which states that TCP may generate an immediate ACK when an out-of-order
		 *			segment is received. We saw that Net/3 generates the immediate
		 *			duplicate ACKs in Figure 27.15. This algorithm first appeared in the 4.3BSD
		 *			Tahoe release and the subsequent Net/1 release. In these two implementations,
		 *			after the missing segment was retransmitted, the slow start phase was entered.
		 *		b.	The fast recovery algorithm says that after the fast retransmit algorithm (that is,
		 *			after the missing segment has been retransmitted), congestion avoidance but not
		 *			slow start is performed. This is an improvement that allows higher throughput
		 *			under moderate congestion, especially for large windows. This algorithm
		 *			appeared in the 4.3BSD Reno release and the subsequent Net/2 release.
		 *	
		 *	Net/3 implements both fast retransmit and fast recovery, as we describe shortly.
		 *	In the discussion of Figure 24.17 we noted that an acceptable ACK must be in the range:
		 *			snd_una < acknowledgment field <= snd_max
		 *	This first test of the acknowledgment field compares it only to snd_una. The comparison
		 *	against snd_max is in Figure 29.5. The reason for separating the tests is so that the
		 *	following five tests can be applied to the received segment:
		 *		1.	If the acknowledgment field is less than or equal to snd_una, and
		 *		2.	the length of the received segment is 0, and
		 *		3.	the advertised window (tiwin) has not changed, and
		 *		4.	TCP has outstanding data that has not been acknowledged (the retransmission timer is nonzero), and
		 *		5.	the received segment contains the biggest ACK TCP has seen (the acknowledgment field equals snd_una),
		 *		
		 *	then this segment is a completely duplicate ACK. (Tests l, 2, and 3 are in Figure 29.3;
		 *	tests 4 and 5 are at the beginning of Figure 29.4.)
		 *		TCP counts the number of these duplicate ACKs that are received in a row (in the
		 *	variable t_dupacks), and when the number reaches a threshold of 3
		 *	(tcprexmtthresh), the lost segment is retransmitted. This is the fast retransmit algorithm
		 *	described in Section 21.7 of Volume 1. It works in conjunction with the code we
		 *	saw in Figure 27.15: when TCP receives an out-of-order segment, it is required to generate
		 *	an immediate duplicate ACK, telling the other end that a segment might have been
		 *	lost and telling it the value of the next expected sequence number. The goal of the fast
		 *	retransmit algorithm is for TCP to retransmit immediately what appears to be the missing
		 *	segment, instead of waiting for the retransmission timer to expire. Figure 21.7 of
		 *	Volume 1 gives a detailed example of how this algorithm works.
		 *		The receipt of a duplicate ACK also tells TCP that a packet has "left the network,"
		 *	because the other end had to receive an out-of-order segment to send the duplicate
		 *	ACK. The fast recovery algorithm says that after some number of consecutive duplicate
		 *	ACKs have been received, TCP should perform congestion avoidance (i.e., slow down)
		 *	but need not wait for the pipe to empty between the two connection end points (slow
		 *	start). The expression "a packet has left the network" means a packet has been received
		 *	by the other end and has been added to the out-of-order queue for the connection. The
		 *	packet is not still in transit somewhere between the two end points.
		 *		If only the first three tests shown earlier are true, the ACK is still a duplicate and is
		 *	counted by the statistic tcps_rcvdupack, but the counter of the number of consecutive
		 *	duplicate ACKs for this connection (t_dupacks) is reset to O. If only the first test is
		 *	true, the counter t_dupacks is reset to O.
		 *		The remainder of the fast recovery algorithm is shown in Figure 29.4. When all five
		 *	tests are true, the fast recovery algorithm processes the segment depending on the number
		 *	of these consecutive duplicate ACKs that have been received.
		 *		1.	t_dupacks equals 3 (tcprexmtthresh). Congestion avoidance is performed
		 *			and the missing segment is retransmitted.
		 *		2.	t_dupacks exceeds 3. Increase the congestion window and perform normal TCP output.
		 *		3.	t_dupacks is less than 3. Do nothing.
		 *		
		* In ESTABLISHED state: drop duplicate ACKs; ACK out of range
		* ACKs.  If the ack is in the range
		*	tp->snd_una < ti->ti_ack <= tp->snd_max
		* then advance tp->snd_una to ti->ti_ack and drop
		* data from the retransmission queue.  If this ACK reflects
		* more up to date window information we update our window information.
		*/
	case L4_TCP::tcpcb::TCPS_ESTABLISHED:
	case L4_TCP::tcpcb::TCPS_FIN_WAIT_1:
	case L4_TCP::tcpcb::TCPS_FIN_WAIT_2:
	case L4_TCP::tcpcb::TCPS_CLOSE_WAIT:
	case L4_TCP::tcpcb::TCPS_CLOSING:
	case L4_TCP::tcpcb::TCPS_LAST_ACK:
	case L4_TCP::tcpcb::TCPS_TIME_WAIT:

		if (L4_TCP::tcpcb::SEQ_LEQ(ti->ti_ack(), tp->snd_una)) {
			if (ti->ti_len() == 0 && tiwin == tp->snd_wnd) {

				/*
				* If we have outstanding data (other than
				* a window probe), this is a completely
				* duplicate ack (ie, window info didn't
				* change), the ack is the biggest we've
				* seen and we've seen exactly our rexmtthreshhold
				* of them, assume a packet
				* has been dropped and retransmit it.
				* Kludge snd_nxt & the congestion
				* window so we send only this one
				* packet.
				*
				* We know we're losing at the current
				* window size so do congestion avoidance
				* (set ssthresh to half the current window
				* and pull our congestion window back to
				* the new ssthresh).
				*
				* Dupacks mean that packets have left the
				* network (they're now cached at the receiver)
				* so bump cwnd by the amount in the receiver
				* to keep a constant cwnd packets in the
				* network.
				*/
				if (tp->t_timer[TCPT_REXMT] == 0 ||	ti->ti_ack() != tp->snd_una)
					tp->t_dupacks = 0;

				/*	
				 *	Number of consecutive duplicate ACKs reaches threshold of 3:
				 *	When t_dupacks reaches 3 (tcprexmtthresh), the value of snd_nxt is saved in
				 *	onxt and the slow start threshold (ssthresh) is set to one-half the current congestion
				 *	window, with a minimum value of two segments. This is what was done with the slow
				 *	start threshold when the retransmission timer expired in Figure 25.27, but we'll see later
				 *	in this piece of code that the fast recovery algorithm does not set the congestion window
				 *	to one segment, as was done with the timeout.
				 */
				else if (++tp->t_dupacks == tcprexmtthresh) {
					u_int win(std::min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg);
					if (win < 2)
						win = 2;
					
					tp->snd_ssthresh = win * tp->t_maxseg;

					/*	
					 *	Turn off retransmission timer:
					 *	The retransmission timer is turned off and, in case a segment is currently being
					 *	timed, t_rtt is set to 0.
					 */
					tp->t_timer[TCPT_REXMT] = 0;
					tp->t_rtt = 0;

					/*	
					 *	Retransmit missing segment:
					 *	snd_nxt is set to the starting sequence number of the segment that appears to have
					 *	been lost (the acknowledgment field of the duplicate ACK) and the congestion window
					 *	is set to one segment. This causes tcp_output to send only the missing segment.
					 *	(This is shown by segment 63 in Figure 21.7 of Volume 1.)
					 */
					tcp_seq onxt(tp->snd_nxt);
					tp->snd_nxt = ti->ti_ack();
					tp->log_snd_cwnd(tp->snd_cwnd = tp->t_maxseg);
					(void)tcp_output(*tp);

					/*	
					 *	Set congestion window:
					 *	The congestion window is set to the slow start threshold plus the number of segments
					 *	that the other end has cached. By cached we mean the number of out-of-order
					 *	segments that the other end has received and generated duplicate ACKs for. These cannot
					 *	be passed to the process at the other end until the missing segment (which was just
					 *	sent) is received. Figures 21.10 and 21.11 in Volume 1 show what happens with the congestion
					 *	window and slow start threshold when the fast recovery algorithm is in effect.
					 */
					tp->log_snd_cwnd(tp->snd_cwnd = tp->snd_ssthresh + tp->t_maxseg * tp->t_dupacks);

					/*	
					 *	Set snd_nxt:
					 *	The value of the next sequence number to send is set to the maximum of its previous
					 *	value (onxt) and its current value. Its current value was modified by tcp_output
					 *	when the segment was retransmitted. Normally this causes snd_nxt to be set back to
					 *	its previous value, which means that only the missing segment is retransmitted, and
					 *	that future calls to tcp_output carry on with the next segment in sequence.
					 */
					if (L4_TCP::tcpcb::SEQ_GT(onxt, tp->snd_nxt))
						tp->snd_nxt = onxt;
					return drop(tp, dropsocket);
				}

				/*	
				 *	Number of consecutive duplicate ACKs exceeds threshold of 3:
				 *	The missing segment was retransmitted when t_dupacks equaled 3, so the receipt
				 *	of each additional duplicate ACK means that another packet has left the network. The
				 *	congestion window is incremented by one segment. tcp_output sends the next segment
				 *	in sequence, and the duplicate ACK is dropped. (This is shown by segments 67,
				 *	69, and 71 in Figure 21.7 of Volume 1.)
				 */
				else if(tp->t_dupacks > tcprexmtthresh) {
					tp->log_snd_cwnd(tp->snd_cwnd += tp->t_maxseg);
					(void)tcp_output(*tp);
					return drop(tp, dropsocket);
				}
			}

			/*	
			 *	This statement is executed when the received segment contains a duplicate ACK,
			 *	but either the length is nonzero or the advertised window changed. Only the first of the
			 *	five tests described earlier is true. The counter of consecutive duplicate ACI<s is set to 0.
			 */
			else
				tp->t_dupacks = 0;
				
			/*
				*	Skip remainder of ACK processing:
				*	This break is executed in three cases:
				*		(1)	only the first of the five tests described earlier is true, or
				*		(2)	only the first three of the five tests is true, or
				*		(3)	the ACK is a duplicate, but the number of consecutive duplicates
				*			is less than the threshold of 3.
				*	For any of these cases the ACK is still a duplicate and the break goes to the end of the switch
				*	that started in Figure 29.2, which continues processing at the label step6.
				*	To understand the purpose in this aggressive window manipulation, consider the
				*	following example. Assume the window is eight segments, and segments 1 through 8
				*	are sent. Segment 1 is lost, but the remainder arrive OK and arc acknowledged. After
				*	the ACKs for segments 2, 3, and 4 arrive, the missing segment (1) is retransmitted. TCP
				*	would like the subsequent ACKs for 5 through 8 to allow some of the segments starting
				*	with 9 to be sent, to keep the pipe full. But the window is 8, which prevents segments 9
				*	and above from being sent. Therefore, the congestion window is temporarily inflated
				*	by one segment each time another duplicate ACK is received, since the receipt of the
				*	duplicate ACK tells TCP that another segment has left the pipe at the other end. When
				*	the acknowledgment of segment 1 is finally received, the next figure reduces the congestion
				*	window back to the slow start threshold. This increase in the congestion window
				*	as the duplicate ACKs arrive, and its subsequent decrease when the fresh ACK
				*	arrives, can be seen visually in Figure 21.10 of Volume 1.
				*/
			break;	/* beyond ACK processing (to step 6) */
		}

		/*	
		 *	Adjust congestion window:
		 *	If the number of consecutive duplicate ACKs exceeds the threshold of 3, this is the
		 *	first nonduplicate ACK after a string of four or more duplicate ACKs. The fast recovery
		 *	algorithm is complete. Since the congestion window was incremented by one segment
		 *	for every consecutive duplicate after the third, if it now exceeds the slow start threshold,
		 *	it is set back to the slow start threshold. The counter of consecutive duplicate ACKs is
		 *	set to 0.
		 *	
		* If the congestion window was inflated to account
		* for the other side's cached packets, retract it.
		*/
		if (tp->t_dupacks > tcprexmtthresh && tp->snd_cwnd > tp->snd_ssthresh)
			tp->log_snd_cwnd(tp->snd_cwnd = tp->snd_ssthresh);
		
		tp->t_dupacks = 0;

		/*	
		 *	Check for out-of-range ACK:
		 *	Recall the definition of an acceptable ACK,
		 *		snd_una < acknowledgment field <= snd_max
		 *	If the acknowledgment field is greater than snd_max, the other end is acknowledging
		 *	data that TCP hasn't even sent yet! This probably occurs on a high-speed connection
		 *	when the sequence numbers wrap and a missing ACK reappears later. As we can see in
		 *	Figure 24.5, this rarely happens (since today's networks aren't fast enough).
		 */
		if (L4_TCP::tcpcb::SEQ_GT(ti->ti_ack(), tp->snd_max))
			return dropafterack(tp, dropsocket, tiflags);
		
		/*	
		 *	Calculate number of bytes acknowledged:
		 *	At this point TCP knows that it has an acceptable ACK. acked is the number of
		 *	bytes acknowledged.
		 */
		int acked(ti->ti_ack() - tp->snd_una);

		/*	
		 *	The next part of ACK processing deals with RIT measurements and the retransmission timer.
		 *	
		 *	Update RTT estimators:
		 *	If either:
		 *		(1)	a timestamp option was present, or 
		 *		(2)	a segment was being timed and the
		 *			acknowledgment number is greater than the starting sequence number of the segment being timed,
		 *	tcp_xmit_timer updates the RTI estimators. Notice that the second
		 *	argument to this function when timestamps are used is the current time (tcp_now)
		 *	minus the timestamp echo reply (ts_ecr) plus 1 (since the function subtracts 1).
		 *	Delayed ACKs are the reason for the greater-than test of the sequence numbers. For
		 *	example, if TCP sends and times a segment with bytes 1-1024, followed by a segment
		 *	with bytes 1025-2048, if an ACK of 2049 is returned, this test will consider whether 2049
		 *	is greater than 1 (the starting sequence number of the segment being timed), and since
		 *	this is true, the RTT estimators are updated.
		 *	
		* If we have a timestamp reply, update smoothed
		* round trip time. If no timestamp is present but
		* transmit timer is running and timed sequence
		* number was acked, update smoothed round trip time.
		* Since we now have an rtt measurement, cancel the
		* timer backoff (cf., Phil Karn's retransmit alg.).
		* Recompute the initial retransmit timer.
		*/
		if (ts_present)
			tp->tcp_xmit_timer(static_cast<short>(tcp_now - ts_ecr + 1));
		else if (tp->t_rtt && L4_TCP::tcpcb::SEQ_GT(ti->ti_ack(), tp->t_rtseq))
			tp->tcp_xmit_timer(tp->t_rtt);

		/*	
		 *	Check If all outstanding data has been acknowledged:
		 *	If the acknowledgment field of the received segment (ti_ack) equals the maximum
		 *	sequence number that TCP has sent (snd_max), all outstanding data has been
		 *	acknowledged. The retransmission timer is turned off and the needoutput flag is set
		 *	to 1. This flag forces a call to tcp_output at the end of this function. Since there is no
		 *	more data waiting to be acknowledged, TCP may have more data to send that it has not
		 *	been able to send earlier because the data was beyond the right edge of the window.
		 *	Now that a new ACK has been received, the window will probably move to the right
		 *	(snd_una is updated in Figure 29.8), which could allow more data to be sent.
		 *	
		* If all outstanding data is acked, stop retransmit
		* timer and remember to restart (more output or persist).
		* If there is more data to be acked, restart retransmit
		* timer, using current (possibly backed-off) value.
		*/
		if (ti->ti_ack() == tp->snd_max) {
			tp->t_timer[TCPT_REXMT] = 0;
			needoutput = 1;
		}

		/*	
		 *	Unacknowledged data outstanding:
		 *	Since there is additional data that has been sent but not acknowledged, if the persist
		 *	timer is not on, the retransmission timer is restarted using the current value of t_rxtcur.
		 */
		else if (tp->t_timer[TCPT_PERSIST] == 0)
			tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
		
		/*	
		 *	Karn's Algorithm and Timestamps:
		 *	Notice that timestamps overrule the portion of Karn's algorithm (Section 21.3 of
		 *	Volume 1) that says: when a timeout and retransmission occurs, the RTT estimators cannot
		 *	be updated when the acknowledgment for the retransmitted data is received (the
		 *	retransmission ambiguity problem). In Figure 25.26 we saw that t_rtt was set to 0 when
		 *	a retransmission took place, because of Karn's algorithm. If timestamps are not present
		 *	and it is a retransmission, the code in Figure 29.6 does not update the RTT estimators
		 *	because t_rtt will be 0 from the retransmission. But if a timestamp is present, t_rtt
		 *	isn't examined, allowing the RTT estimators to be updated using the received timestamp
		 *	echo reply. With RFC 1323 timestamps the ambiguity is gone since the ts_ecr
		 *	value was copied by the other end from the segment being acknowledged. The other
		 *	half of Karn's algorithm, specifying that an exponential backoff must be used with
		 *	retransmissions, still holds, of course.
		 *	
		 *	Update congestion window:
		 *	One of the rules of slow start and congestion avoidance is that a received ACK
		 *	increases the congestion window. By default the congestion window is increased by
		 *	one segment for each received ACK (slow start). But if the current congestion window
		 *	is greater than the slow start threshold, it is increased by 1 divided by the congestion
		 *	window, plus a constant fraction of a segment. The term
		 *		incr * incr / cw
		 *	is
		 *		t_maxseg * t_maxseg I snd_cwnd
		 *	which is 1 divided by the congestion window, taking into account that snd_cwnd is
		 *	maintained in bytes, not segments. The constant fraction is the segment size divided by
		 *	8. The congestion window is then limited by the maximum value of the send window
		 *	for this connection. Example calculations of this algorithm are in Section 21.8 of Volume 1.
		 *		Remark:	Adding in the constant fraction (the segment size divided by 8) is wrong [Floyd 1994]. But it
		 *				has been in the BSD sources since 4.3BSD Reno and is still in 4.4BSD and Net/3. It should be removed.
		 *	
		* When new data is acked, open the congestion window.
		* If the window gives us less than ssthresh packets
		* in flight, open exponentially (maxseg per packet).
		* Otherwise open linearly: maxseg per window
		* (maxseg * (maxseg / cwnd) per packet).
		*/
		{
			u_int cw(tp->snd_cwnd);
			u_int incr(tp->t_maxseg);
			if (cw > tp->snd_ssthresh)
				incr *= incr / cw
				// + incr / 8		/*	REMOVED	*/
				;
			tp->log_snd_cwnd(tp->snd_cwnd = std::min(cw + incr, static_cast<u_int>(TCP_MAXWIN << tp->snd_scale)));
		}

		/*	
		 *	The next part of tcp_input removes the acknowledged data from the send buffer.
		 *	
		 *	Remove acknowledged bytes from the send buffer:
		 *	If the number of bytes acknowledged exceeds the number of bytes on the send buffer,
		 *	snd_wnd is decremented by the number of bytes in the send buffer and TCP knows
		 *	that its FIN has been ACKcd. That nu1nber of bytes is then removed from the send
		 *	buffer by sbdrop. This method for detecting the ACK of a FIN works only because the
		 *	FIN occupies 1 byte in the sequence number space.
		 */
		int ourfinisacked;
		if (static_cast<u_long>(acked) > so->so_snd.size()) {
			tp->snd_wnd -= so->so_snd.size();
			so->so_snd.sbdrop(static_cast<int>(so->so_snd.size()));
			ourfinisacked = 1;
		}

		/*	
		 *	Otherwise the number of bytes acknowledged is less than or equal to the number of
		 *	bytes in the send buffer, so ourfinisacked is set to 0, and acked bytes of data are
		 *	dropped from the send buffer.
		 */
		else {
			so->so_snd.sbdrop(acked);
			tp->snd_wnd -= acked;
			ourfinisacked = 0;
		}

		/*	
		 *	Wakeup processes waiting on send buffer:
		 *	sowwakeup awakens any processes waiting on the send buffer. snd_una is
		 *	updated to contain the oldest unacknowledged sequence number. If this new value of
		 *	snd_una exceeds snd_nxt, the latter is updated, since the intervening bytes have been
		 *	acknowledged.
		 *	Figure 29.9 shows how snd_nxt can end up with a sequence number that is less
		 *	than snd_una. assume two segments are transmitted, the first with bytes 1-512 and
		 *	the second with bytes 513-1024.
		 *	1 2 ...	512				513 514 ... 1024 1025
		 *	-------------------->	-------------------->
		 *	/\	one segment				one segment		/\
		 *	||											||
		 *	snd_una										snd_nxt
		 *												snd_max
		 *	Figure 29.9 Two segments sent on a connection.
		 *	
		 *	The retransmission timer then expires before an acknowledgment is returned. The code
		 *	in Figure 25.26 sets snd_nxt back to snd_una, slow start is entered, tcp_output is
		 *	called, and one segment containing bytes 1-512 is retransmitted. tcp_output
		 *	increases snd_nxt to 513, and we have the scenario shown in Figure 29.10.
		 *	1 2 ...	512					513 514 ... 1024 1025
		 *	-------------------->	
		 *	/\	segment retransmitted	/\					/\
		 *	||							||					||
		 *	snd_una						snd_nxt				snd_max
		 *	
		 *	Figure 29.10 Continuation of Figure 29.9 after retransmission timer expires.
		 *	
		 *	At this point an ACK of 1025 arrives (either the two original segments or the ACK was
		 *	delayed somewhere in the network). The ACK is valid since it is less than or equal to
		 *	snd_max, but snd_nxt will be less than the updated value of snd_una.
		 */
		if (so->so_snd.sb_flags & socket::sockbuf::SB_NOTIFY)
			so->sowwakeup();

		if (L4_TCP::tcpcb::SEQ_LT(tp->snd_nxt, (tp->snd_una = ti->ti_ack())))
			tp->snd_nxt = tp->snd_una;

		/*	
		 *	The general ACK processing is now complete, and the switch handles four special cases.
		 */
		switch (tp->t_state) {

			/*	
			 *	Receipt of ACK In FIN_WAIT_1 state:
			 *	In this state the process has closed the connection and TCP has sent the FIN. But
			 *	other ACKs can be received for data segments sent before the FIN. Therefore the connection
			 *	moves into the FIN_WAIT_2 state only when the FIN has been acknowledged.
			 *	The flag ourfinisacked is set in Figure 29.8; this depends on whether the number of
			 *	bytes ACKed exceeds the amount of data in the send buffer or not.
			 *	
			* In FIN_WAIT_1 STATE in addition to the processing
			* for the ESTABLISHED state if our FIN is now acknowledged
			* then enter FIN_WAIT_2.
			*/
		case L4_TCP::tcpcb::TCPS_FIN_WAIT_1:
			if (ourfinisacked) {
				
				/*
				 *	Set FIN_WAIT_2 timer:
				 *	We also described in Section 25.6 how Net/3 sets a FIN_WAIT_2 timer to prevent
				 *	an infinite wait in the FIN_WAIT_2 state. This timer is set only if the process completely
				 *	closed the connection (i.e., the close system call or its kernel equivalent if the
				 *	process was terminated by a signal), and not if the process performed a half-close (i.e.,
				 *	the FIN was sent but the process can still receive data on the connection).
				 *	
				* If we can't receive any more
				* data, then closing user can proceed.
				* Starting the timer is contrary to the
				* specification, but if we don't get a FIN
				* we'll hang forever.
				*/
				if (so->so_state & socket::SS_CANTRCVMORE) {
					so->soisdisconnected();
					tp->t_timer[TCPT_2MSL] = tcp_maxidle;
				}
				tp->t_state = L4_TCP::tcpcb::TCPS_FIN_WAIT_2;
			}
			break;

			/*	
			 *	Receipt of ACK in CLOSING state:
			 *	If the ACK is for the FIN (and not for some previous data segment), the connection
			 *	moves into the TIME_WAIT state. Any pending timers are cleared (such as a pending
			 *	retransmission timer), and the TIME_WAIT timer is started with a value of twice the MSL.
			 *	
			* In CLOSING STATE in addition to the processing for
			* the ESTABLISHED state if the ACK acknowledges our FIN
			* then enter the TIME-WAIT state, otherwise ignore
			* the segment.
			*/
		case L4_TCP::tcpcb::TCPS_CLOSING:
			if (ourfinisacked) {
				tp->t_state = L4_TCP::tcpcb::TCPS_TIME_WAIT;
				tp->tcp_canceltimers();
				tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
				so->soisdisconnected();
			}
			break;

			/*	
			 *	Receipt of ACK In LAST_ACK state:
			 *	If the FIN is ACKed, the new state is CLOSED. This state transition is handled by
			 *	tcp_close, which also releases the Internet PCB and TCP control block.
			 *	
			* In LAST_ACK, we may still be waiting for data to drain
			* and/or to be acked, as well as for the ack of our FIN.
			* If our FIN is now acknowledged, delete the TCB,
			* enter the closed state and return.
			*/
		case L4_TCP::tcpcb::TCPS_LAST_ACK:
			if (ourfinisacked) {
				(void)tcp_close(*tp);
				return drop(tp, dropsocket);
			}
			break;

			/*	
			 *	Receipt of ACK In TIME_WAIT state:
			 *	In this state both ends have sent a FIN and both FINs have been acknowledged. If
			 *	TCP's ACK of the remote FIN was lost, however, the other end will retransmit the FIN
			 *	(with an ACK). TCP drops the segment and resends the ACK. Additionally, the
			 *	TIME_WAIT timer must be restarted with a value of twice the MSL.
			 *	
			* In TIME_WAIT state the only thing that should arrive
			* is a retransmission of the remote FIN.  Acknowledge
			* it and restart the finack timer.
			*/
		case L4_TCP::tcpcb::TCPS_TIME_WAIT:
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			return dropafterack(tp, dropsocket, tiflags);
		}
	}

	return step6(tp, tiflags, ti, m, it, tiwin, needoutput);
}

void L4_TCP_impl::drop(class inpcb_impl *inp, const int dropsocket)
{
	/*
	* Drop space held by incoming segment and return.
	*
	* destroy temporarily created socket 
	*/
	if (dropsocket && inp)
		(void)dynamic_cast<socket*>(inp->inp_socket)->soabort();
	return;
}

void L4_TCP_impl::dropafterack(class L4_TCP::tcpcb *tp, const int &dropsocket, const int &tiflags)
{
	/*
	* Generate an ACK dropping incoming segment if it occupies
	* sequence space, where the ACK reflects our state.
	*/
	if (tiflags & L4_TCP::tcphdr::TH_RST)
		return drop(tp, dropsocket);
	tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
	(void)tcp_output(*tp);
	return;
}

void L4_TCP_impl::dropwithreset(class inpcb_impl *inp, const int &dropsocket, const int &tiflags, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, tcpiphdr *ti)
{
	/*
	* Generate a RST, dropping incoming segment.
	* Make ACK acceptable to originator of segment.
	* Don't bother to respond if destination was broadcast/multicast.
	*/
	if ((tiflags & L4_TCP::tcphdr::TH_RST) || IN_MULTICAST(ntohl(ti->ti_dst().s_addr)))
		return drop(inp, dropsocket);

	/*
	*	Sequence number and acknowledgment number of RST segment:
	*	The values of the sequence number field, the acknowledgment field, and the ACK
	*	flag of the RST segment depend on whether the received segment contained an ACK.
	*	Realize that the ACK flag is normally set in all segments except when an initial SYN is
	*	sent (Figure 24.16). The fourth argument to tcp_respond is th.e acknowledgment
	*	field, and the fifth argument is the sequence number.
	*/
	if (tiflags & L4_TCP::tcphdr::TH_ACK)
		tcp_respond(L4_TCP::tcpcb::intotcpcb(inp),
		ti,
		m,
		it,
		tcp_seq(0),
		ti->ti_ack(),
		tcphdr::TH_RST);
	else {

		/*
		*	Rejecting connections:
		*	If the SYN flag is set, ti_len must be incremented by 1, causing the acknowledgment
		*	field of the RST to be 1 greater than the received sequence number of the SYN.
		*	This code is executed when a SYN arrives for a nonexistent server. When the Internet
		*	PCB is not found in Figure 28.6, a jump is made to dropwithreset. But for the
		*	received RST to be acceptable to the other end, the acknowledgment field must ACK the
		*	SYN (Figure 28.18). Figure 18.14 of Volume 1 contains an example of this type of RST
		*	segment.
		*		Finally note that tcp_respond builds the RST in the first mbuf of the received
		*		chain and releases any remaining mbufs in the chain. When that mbuf finally makes its
		*		way to the device driver, it will be discarded.
		*/
		if (tiflags & L4_TCP::tcphdr::TH_SYN)
			ti->ti_len()++;
		
		tcp_respond(
			tcpcb::intotcpcb(inp),
			ti,
			m,
			it,
			ti->ti_seq() + ti->ti_len(),
			tcp_seq(0),
			tcphdr::TH_RST | L4_TCP::tcphdr::TH_ACK);
	}

	/*
	*	Destroy temporarily created socket:
	*	If a temporary socket was created in Figure 28.7 for a listening server, but the code
	*	in Figure 28.16 found the received segment to contain an error, dropsocket will be 1.
	*	If so, that socket is now destroyed.destroy temporarily created socket
	*/
	return drop(inp, dropsocket);
}

void L4_TCP_impl::step6(class L4_TCP::tcpcb *tp, int &tiflags, struct L4_TCP::tcpiphdr *ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, u_long &tiwin, int &needoutput) 
{
	/*
	* Update window information.
	* Don't look at window if no ACK: TAC's send garbage on first SYN.
	*/
	if ((tiflags & L4_TCP::tcphdr::TH_ACK) &&
		(L4_TCP::tcpcb::SEQ_LT(tp->snd_wl1, ti->ti_seq()) ||
		tp->snd_wl1 == ti->ti_seq() && (L4_TCP::tcpcb::SEQ_LT(tp->snd_wl2, ti->ti_ack()) ||
		tp->snd_wl2 == ti->ti_ack() && tiwin > tp->snd_wnd))) 
	{
		/*	Update variables:
		*	The send window is updated and new values of snd_wll and snd_wl2 are
		*	recorded. Additionally, if this advertised window is the largest one TCP has received
		*	from this peer, the new value is recorded in max_sndwnd. This is an attempt to guess
		*	the size of the other end's receive buffer, and it is used in Figure 26.8. needoutput is
		*	set to 1 since the new value of snd_wnd might enable a segment to be sent.
		*/
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = ti->ti_seq();
		tp->snd_wl2 = ti->ti_ack();
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		needoutput = 1;
	}

	/*
	*	Check If URG flag should be processed:
	*	These segments must have the URG flag set, a nonzero urgent offset (ti_urp), and
	*	the connection must not have received a FIN. The macro TCPS_HAVERCVDFIN is true
	*	only for the TIME_ WAIT state, so the URG is processed in any other state. This is contrary
	*	to a comment appearing later in the code stating that the URG flag is ignored in
	*	the CLOSE_ WAIT, CLOSING, LAST_ACK, or TIME_ WAIT states.
	*
	* Process segments with URG.
	*/
	if ((tiflags & L4_TCP::tcphdr::TH_URG) && ti->ti_urp() && tp->TCPS_HAVERCVDFIN() == 0) {

		/*
		*	Ignore bogus urgent offsets:
		*	If the urgent offset plus the number of bytes already in the receive buffer exceeds
		*	the maximum size of a socket buffer, the urgent notification is ignored. The urgent offset
		*	is set to 0, the URG flag is cleared, and the rest of the urgent mode processing is skipped.
		*
		* This is a kludge, but if we receive and accept
		* random urgent pointers, we'll crash in
		* soreceive. It's hard to imagine someone
		* actually wanting to send this much urgent data.
		*/
		socket *so(dynamic_cast<socket*>(tp->inp_socket));
		if (ti->ti_urp() + so->so_rcv.size() > netlab::L5_socket::sockbuf::SB_MAX) {
			ti->ti_urp() = 0;			/* XXX */
			tiflags &= ~L4_TCP::tcphdr::TH_URG;		/* XXX */
			return dodata(tp, tiflags, ti, m, it, needoutput);			/* XXX */
		}

		/*
		*	If the starting sequence number of the received segment plus the urgent offset
		*	exceeds the current receive urgent pointer, a new urgent pointer has been received. For
		*	example, when the 3-byte segment that was sent in Figure 26.30 arrives at the receiver,
		*	we have the scenario shown in Figure 29.18.
		*
		*		received segment
		*	<---------------------->
		*			tlen = 3
		*		4		5		6
		*		/\
		*		||
		*		rcv_nxt
		*		rcv_up
		*		ti_seq
		*					ti_urp=3
		*				(urgent offset)
		*	Figure 29.18 Receiver side when segment from Figure 26.30 arrives.
		*
		*	Normally the receive urgent pointer (rcv_up) equals rcv_nxt. In this example, since
		*	the if test is true (4 plus 3 is greater than 4), the new value of rev_up is calculated as 7.
		*
		* If this segment advances the known urgent pointer,
		* then mark the data stream.  This should not happen
		* in CLOSE_WAIT, CLOSING, LAST_ACK or TIME_WAIT STATES since
		* a FIN has been received from the remote side.
		* In these states we ignore the URG.
		*
		* According to RFC961 (Assigned Protocols),
		* the urgent pointer points to the last octet
		* of urgent data.  We continue, however,
		* to consider it to indicate the first octet
		* of data past the urgent section as the original
		* spec states (in one of two places).
		*/
		if (L4_TCP::tcpcb::SEQ_GT(ti->ti_seq() + ti->ti_urp(), tp->rcv_up)) {

			/*
			*	Calculate receive urgent pointer:
			*	The out-of-band mark in the socket's receive buffer is calculated, taking into
			*	account any data bytes already in the receive buffer (so_rcv.sb_cc). In our example,
			*	assuming there is no data already in the receive buffer, so_oobmark is set to 2: that is,
			*	the byte with the sequence number 6 is considered the out-of-band byte. If this out-of-band
			*	mark is 0, the socket is currently at the out-of-band mark. This happens if the
			*	send system call that sends the out-of-band byte specifies a length of 1, and if the
			*	receive buffer is empty when this segment arrives at the other end. This reiterates that
			*	Berkeley-derived systems consider the urgent pointer to point to the first byte of data
			*	after the out-of-band byte.
			*/
			tp->rcv_up = ti->ti_seq() + ti->ti_urp();
			if ((so->so_oobmark = so->so_rcv.size() + (tp->rcv_up - tp->rcv_nxt) - 1) == 0)
				so->so_state |= socket::SS_RCVATMARK;

			/*
			*	Notify process of TCP's urgent mode:
			*	sohasoutofband notifies the process that out-of-band data has arrived for the
			*	socket. The two flags TCPOOB_HAVEDATA and TCPOOB_HADDATA are cleared. These
			*	two flags are used with the PRU_RCVOOB request in Figure 30.8.
			*/
			//so->sohasoutofband();
			tp->t_oobflags &= ~(L4_TCP::tcpcb::TCPOOB_HAVEDATA | L4_TCP::tcpcb::TCPOOB_HADDATA);
		}

		/*
		*	Pull out-of-band byte out of normal data stream:
		*	If the urgent offset is less than or equal to the number of bytes in the received segment,
		*	the out-of-band byte is contained in the segment. With TCP's urgent mode it is
		*	possible for the urgent offset to point to a data byte that has not yet been received. If the
		*	SO_OOBINLINE constant is defined (which it always is for Net/3), and if the corresponding
		*	socket option is not enabled, the receiving process wants the out-of-band byte
		*	pulled out of the normal stream of data and placed into the variable t_iobc. This is
		*	done by tcp_pulloutofband, which we cover in the next section.
		*		Notice that the receiving process is notified that the sender has entered urgent
		*	mode, regardless of whether the byte pointed to by the urgent pointer is readable or not.
		*	This is a feature of TCP's urgent mode.
		*
		* Remove out of band data so doesn't get presented to user.
		* This can happen independent of advancing the URG pointer,
		* but if two URG's are pending at once, some out-of-band
		* data may creep in... ick.
		*/
		if (ti->ti_urp() <= ti->ti_len() && (so->so_options & SO_OOBINLINE) == 0)
			tcp_pulloutofband(*so, *ti, m, it);
	}

	/*
	*	Adjust receive urgent pointer If not urgent mode:
	*	When the receiver is not processing an urgent pointer, if rcv_nxt is greater than
	*	the receive urgent pointer, rcv_up is moved to the right and set equal to rcv_nxt.
	*	This keeps the receive urgent pointer at the left edge of the receive window so that the
	*	comparison using SEQ_GT at the beginning of Figure 29.17 will work correctly when an
	*	URG flag is received.
	*		Remark:	If the solution to Exercise 26.6 is implemented, corresponding changes will have to go into Figures
	*				29.16 and 29.17 also.
	*
	* If no out of band data is expected,
	* pull receive urgent pointer along
	* with the receive window.
	*/
	else if (L4_TCP::tcpcb::SEQ_GT(tp->rcv_nxt, tp->rcv_up))
		tp->rcv_up = tp->rcv_nxt;

	return dodata(tp, tiflags, ti, m, it, needoutput);
}

void L4_TCP_impl::tcp_pulloutofband(socket &so, const L4_TCP::tcpiphdr &ti, std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it)
{
	int cnt(ti.ti_urp() - 1);
	if (cnt >= 0) {

		/*
		*	cp points to the shaded byte with a sequence number of 6. This is placed into the
		*	variable t_iobc, which contains the out-of-band byte. The TCPOOB_HAVEDATA flag is
		*	set and bcopy moves the next 2 bytes (with sequence numbers 7 and 8) left 1 byte, giving
		*	the arrangement shown in Figure 29.21.
		*
		*
		*/
		int m_len(m->end() - it);
		if (m_len > cnt) {
			char *cp(reinterpret_cast<char*>(&m->data()[it - m->begin()]) + cnt);
			L4_TCP::tcpcb *tp(L4_TCP::tcpcb::sototcpcb(&so));
			tp->t_iobc = *cp;
			tp->t_oobflags |= L4_TCP::tcpcb::TCPOOB_HAVEDATA;
			std::memcpy(cp, &cp[1], static_cast<unsigned>(m_len - cnt - 1));
			m->resize(m->size() - 1);
			return;
		}
	}
	throw std::runtime_error("panic(''tcp_pulloutofband''");
}

void L4_TCP_impl::dodata(class L4_TCP::tcpcb *tp, int &tiflags, struct L4_TCP::tcpiphdr *ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, const int &needoutput) /* XXX */
{							
	socket *so(dynamic_cast<socket*>(tp->inp_socket));

	/*
	* Process the segment text, merging it into the TCP sequencing queue,
	* and arranging for acknowledgment of receipt if necessary.
	* This process logically involves adjusting tp->rcv_wnd as data
	* is presented to the user (this happens in tcp_usrreq.c,
	* case PRU_RCVD).  If a FIN has already been received on this
	* connection then we just ignore the text.
	*/
	if ((ti->ti_len() || (tiflags & L4_TCP::tcphdr::TH_FIN)) && tp->TCPS_HAVERCVDFIN() == 0)
		TCP_REASS(tp, ti, m, it, so, tiflags);

	/*
	*	If the length is 0 and the FIN flag is not set, or if a FIN has already been received for
	*	the connection, the received mbuf chain is discarded and the FIN flag is cleared.
	*/
	else
		tiflags &= ~tcphdr::TH_FIN;

	/*
	*	Process first FIN received on connection:
	*	If the FIN flag is set and this is the first FIN received for this connection,
	*	socantrcvmore marks the socket as write-only, TF ACKNOW is set to acknowledge the
	*	FIN immediately (i.e., it is not delayed), and rcv_nxt steps over the FIN in the
	*	sequence space.
	*
	* If FIN is received ACK the FIN and let the user know
	* that the connection is closing.
	*/
	if (tiflags & L4_TCP::tcphdr::TH_FIN) {
		if (tp->TCPS_HAVERCVDFIN() == 0) {
			so->socantrcvmore();
			tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
			tp->rcv_nxt++;
		}

		/*
		*	The remainder of FIN processing is handled by a switch that depends on the connection
		*	state. Notice that the FIN is not processed in the CLOSED, LISTEN, or
		*	SYN_SENT states, since in these three states a SYN has not been received to synchronize
		*	the received sequence number, making it impossible to validate the sequence number of
		*	the FIN. A FIN is also ignored in the CLOSING, CLOSE_WAIT, and LAST_ACK states,
		*	because in these three states the FIN is a duplicate.
		*/
		switch (tp->t_state) {

			/*	
			 *	SYN_RCVD or ESTABLISHED states:
			*	From either the ESTABLISHED or SYN_RCVD states, the CLOSE_WAIT state is entered.
			*		Remark:	The receipt of a FIN in the SYN_RCVD state is unusual, but legal. It is not shown in Figure
			*				24.15. It means a socket is in the LISTEN state when a segment containing a SYN and a
			*				FIN is received. Alternatively, a SYN is received for a listening socket, moving the connection
			*				to the SYN_RCVD state but before the ACK is received a FIN is received. (We know the segment
			*				does not contain a valid ACK, because if it did the code in Figure 29.2 would have
			*				moved the connection to the ESTABLISHED state.)
			*
			* In SYN_RECEIVED and ESTABLISHED STATES
			* enter the CLOSE_WAIT state.
			*/
		case L4_TCP::tcpcb::TCPS_SYN_RECEIVED:
		case L4_TCP::tcpcb::TCPS_ESTABLISHED:
			tp->t_state = L4_TCP::tcpcb::TCPS_CLOSE_WAIT;
			break;

			/*
			*	FIN_WAIT_1 state:
			*	Since ACK processing is already complete for this segment, if the connection is in
			*	the FIN_WAIT_1 state when the FIN is processed, it means a simultaneous close is taking
			*	place-the two FINs from each end have passed in the network. The connection
			*	enters the CLOSING state.
			*
			* If still in FIN_WAIT_1 STATE FIN has not been acked so
			* enter the CLOSING state.
			*/
		case L4_TCP::tcpcb::TCPS_FIN_WAIT_1:
			tp->t_state = L4_TCP::tcpcb::TCPS_CLOSING;
			break;

			/*	FIN_WAIT_2 state:
			*	The receipt of the FIN moves the connection into the TIME_WAIT state. When a
			*	segment containing a FIN and an ACK is received in the FIN_ WAIT 1 state (the typical
			*	scenario), although Figure 24.15 shows the transition directly from the FIN_WAIT_1
			*	state to the TIME_WAIT state, the ACK is processed in Figure 29.11, moving the connection
			*	to the FIN_WAIT_2 state. The FIN processing here moves the connection into the
			*	TIME_WAIT state. Because the ACK is processed before the FIN, the FIN_WAIT_2 state
			*	is always passed through, albeit momentarily.
			*
			* In FIN_WAIT_2 state enter the TIME_WAIT state,
			* starting the time-wait timer, turning off the other
			* standard timers.
			*/
		case L4_TCP::tcpcb::TCPS_FIN_WAIT_2:
			tp->t_state = L4_TCP::tcpcb::TCPS_TIME_WAIT;

			/*
			*	Start TIME_WAIT Timer:
			*	Any pending TCP timer is turned off and the TIME_WAIT timer is started with a
			*	value of twice the MSL. (If the received segment contained a FIN and an ACK, Figure
			*	29.11 started the FIN_WAIT_2 timer.) The socket is disconnected.
			*/
			tp->tcp_canceltimers();
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			so->soisdisconnected();
			break;

			/*
			*	TIME_WAIT state:
			*	If a FIN arrives in the TIME_WAIT state, it is a duplicate, and similar to Figure
			*	29.14, the TIME_WAIT timer is restarted with a value of twice the MSL.
			*
			* In TIME_WAIT state restart the 2 MSL time_wait timer.
			*/
		case L4_TCP::tcpcb::TCPS_TIME_WAIT:
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			break;
		}
	}

	/*
	*	Call tcp_output
	*	If either the needoutput flag was set (Figures 29.6 and 29.15) or if an immediate
	*	ACK is required, tcp_output is called.
	*
	* Return any desired output.
	*/
	if (needoutput || (tp->t_flags & L4_TCP::tcpcb::TF_ACKNOW))
		(void)tcp_output(*tp);
	return;
}

void L4_TCP_impl::TCP_REASS(class L4_TCP::tcpcb *tp, struct L4_TCP::tcpiphdr *ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, socket *so, int &flags)
{
	if (ti->ti_seq() == tp->rcv_nxt &&
		tp->seg_next == reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp) &&
		tp->t_state == L4_TCP::tcpcb::TCPS_ESTABLISHED) 
	{
		tp->t_flags |= L4_TCP::tcpcb::TF_DELACK;
		tp->rcv_nxt += ti->ti_len();
		flags = ti->ti_flags() & L4_TCP::tcphdr::TH_FIN;
		so->so_rcv.sbappend(it, it + ti->ti_len());
		so->sorwakeup();
	}
	else {
		flags = tcp_reass(tp, ti, m, it);
		tp->t_flags |= L4_TCP::tcpcb::TF_ACKNOW;
	}
}

int L4_TCP_impl::tcp_reass(class L4_TCP::tcpcb *tp, struct L4_TCP::tcpiphdr *ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it) 
{
	/*
	*	We'll see that tcp_input calls tcp_reass with a null ti pointer when a SYN is
	*	acknowledged (Figures 28.20 and 29.2). This means the connection is now established,
	*	and any data that might have arrived with the SYN (which tcp_reass had to queue
	*	earlier) can now be passed to the application. Data that arrives with a SYN cannot be
	*	passed to the process until the connection is established. The label present is in Figure
	*	27.23.
	*
	* Call with ti==0 after become established to
	* force pre-ESTABLISHED data up to user socket.
	*/
	if (ti == nullptr)
		return present(tp, ti, m, it);
#ifndef NETLAB_NO_REASS_MBUF
	/*
	*	Go through the list of segments for this connection, starting at seg_next, to find
	*	the first one with a sequence number that is greater than the received sequence number
	*	(ti_seq). Note that the if statement is the entire body of the for loop.
	*
	* Find a segment which begins after this one does.
	*/
	struct L4_TCP::tcpiphdr *q;
	for (q = tp->seg_next; q->ti_next() != nullptr/*q != reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp)*/; q = q->ti_next())
		if (L4_TCP::tcpcb::SEQ_GT(q->ti_seq(), ti->ti_seq()))
			break;

	/*
	*	If there is a segment before the one pointed to by q, that segment may overlap the
	*	new segment. The pointer q is moved to the previous segment on the list (the one with
	*	bytes 4-8 in Figure 27.18) and the number of bytes of overlap is calculated and stored
	*	in i:
	*			i	= q->ti_seq + q->ti_len - ti->ti_seq;
	*				= 4 + 5 - 7
	*				= 2
	*
	*	If i is greater than 0, there is overlap, as we have in our example. If the number of bytes
	*	of overlap in the previous segment on the list (i) is greater than or equal to the size of
	*	the new segment, then all the data bytes in the new segment are already contained in
	*	the previous segment on the list. In this case the duplicate segment is discarded.
	*
	* If there is a preceding segment, it may provide some of
	* our data already.  If so, drop the data from the incoming
	* segment.  If it provides all of our data, drop us.
	*/
	if (q->ti_prev() != reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp)) {
		q = q->ti_prev();
		/* conversion to int (in i) handles seq wraparound */
		int i(q->ti_seq() + q->ti_len() - ti->ti_seq());
		if (i > 0) {
			if (i >= ti->ti_len())
				return (0);

			/*
			*	If there is only partial overlap (as there is in Figure 27.18), m_adj discards i bytes of
			*	data from the beginning of the new segment. The sequence number and length of the
			*	new segment arc updated accordingly. q is moved to the next segment on the list. Figure
			*	27.20 shows our example at this point.
			*/
			std::move(it + i, m->end(), it);
			m->resize(m->size() - i);
			ti->ti_len() -= i;
			ti->ti_seq() += i;
		}
		q = q->ti_next();
	}

	/*
	*	The address of the mbuf m is stored in the TCP header, over the source and destination
	*	TCP ports. We mentioned earlier in this section that this provides a back pointer
	*	from the TCP header to the mbuf, in case the TCP header is stored in a duster, meaning
	*	that the macro dtom won't work. The macro REASS_MBUF is
	*		#define REASS_MBUF(ti) {*(struct mbuf **)&((ti)->ti_t)}
	*	ti_t is the L4_TCP::tcphdr structure (Figure 24.12) and the first two members of the structure
	*	are the two 16-bit port numbers. The comment XXX in Figure 27.19 is because this hack
	*	assumes that a pointer fits in the 32 bits occupied by the two port numbers.
	*/
	ti->REASS_MBUF() = m;		/* XXX */

	/*
	*	The third part of tcp_reass is shown in Figure 27.21. It removes any overlap from
	*	the next segment in the queue.
	*	If there is another segment on the list, the number of bytes of overlap between the
	*	new segment and that segment is calculated in i. In our example we have
	*			i	= 9 + 2 - 10
	*				= 1
	*	since byte number 10 overlaps the two segments.
	*	Depending on the value of i, one of three conditions exists:
	*		1.	If i is less than or equal to 0, there is no overlap.
	*		2.	If i is less than the number of bytes in the next segment (q->ti_len), there is
	*			partial overlap and rn_adj removes the first i bytes from the next segment on
	*			the list.
	*		3.	If i is greater than or equal to the number of bytes in the next segment, there is
	*			complete overlap and that next segment on the list is deleted.
	*
	* While we overlap succeeding segments trim them or,
	* if they are completely covered, dequeue them.
	*/
	while (q != nullptr/*reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp)*/) {
		int i((ti->ti_seq() + ti->ti_len()) - q->ti_seq());
		if (i <= 0)
			break;
		if (i < q->ti_len()) {
			q->ti_seq() += i;
			q->ti_len() -= i;
			std::shared_ptr<std::vector<byte>> adj(q->REASS_MBUF());
			std::move(adj->begin() + i, adj->end(), adj->begin());
			m->resize(m->size() - i);
			break;
		}
		q = q->ti_next();
		m = q->ti_prev()->REASS_MBUF();
		q->ti_prev()->remque();
	}


	/*
	*	The new segment is inserted into the reassembly list for this connection by insque.
	*	Figure 27.22 shows the state of our example at this point.
	*
	* Stick new segment in its place.
	*/
	q->ti_prev()->insque(*ti);
#endif
	return present(tp, ti, m, it);
}

int L4_TCP_impl::present(class L4_TCP::tcpcb *tp, struct L4_TCP::tcpiphdr *ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it)
{
	if (tp->TCPS_HAVERCVDSYN() == false ||
		(ti = tp->seg_next) == reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp) ||
		ti->ti_seq() != tp->rcv_nxt ||
		(tp->t_state == L4_TCP::tcpcb::TCPS_SYN_RECEIVED && ti->ti_len()))
		return (0);

	int flags(0);
#ifndef NETLAB_NO_REASS_MBUF
	socket *so(dynamic_cast<socket*>(tp->t_inpcb->inp_socket));
	do {
		tp->rcv_nxt += ti->ti_len();
		flags = ti->ti_flags() & L4_TCP::tcphdr::TH_FIN;
		ti->remque();
		m = ti->REASS_MBUF();
		ti = ti->ti_next();
		if (!(so->so_state & socket::SS_CANTRCVMORE))
			so->so_rcv.sbappend(m->begin(), m->end());
	} while (ti != reinterpret_cast<struct L4_TCP::tcpiphdr *>(tp) && ti->ti_seq() == tp->rcv_nxt);
	so->sorwakeup();
#endif
	return (flags);
}

void  L4_TCP_impl::tcp_respond(class L4_TCP::tcpcb *tp, struct L4_TCP::tcpiphdr *ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, const tcp_seq &ack, const tcp_seq &seq, const int &flags) 
{
	int win(tp ? dynamic_cast<socket*>(tp->t_inpcb->inp_socket)->so_rcv.sbspace() : 0),
		tlen;
	struct L3::route *ro(tp ? &tp->t_inpcb->inp_route : nullptr);
	if (m) {
		m.reset(new std::vector<byte>(sizeof(struct L4_TCP::tcpiphdr) + sizeof(struct L2::ether_header)));
		std::copy(
			reinterpret_cast<byte*>(ti),
			reinterpret_cast<byte*>(ti) + sizeof(struct L4_TCP::tcpiphdr),
			it = m->begin() + sizeof(struct L2::ether_header)
			);

		ti = reinterpret_cast<struct L4_TCP::tcpiphdr*>(&m->data()[it - m->begin()]);
		tlen = 0;
		std::swap(ti->ti_dst(), ti->ti_src());
		std::swap(ti->ti_dport(), ti->ti_sport());
	}
	else
		return;

	ti->ti_len() = htons(static_cast<u_short>(sizeof(struct L4_TCP::tcphdr) + tlen));
	
	tlen += sizeof(struct L4_TCP::tcpiphdr);
	
	ti->ti_next(nullptr);
	ti->ti_prev(nullptr);
	ti->ti_x1() = 0;
	
	ti->ti_seq() = htonl(seq);
	ti->ti_ack() = htonl(ack);
	
	ti->ti_x2(0);
	ti->ti_off(sizeof(struct L4_TCP::tcphdr) >> 2);
	ti->ti_flags() = flags;
	
	ti->ti_win() = 
		(tp ?
		htons(static_cast<u_short>(win >> tp->rcv_scale)) :
		htons(static_cast<u_short>(win)));
	
	ti->ti_urp() = 0;
	ti->ti_sum() = 0;
	
	ti->ti_sum() = inet.in_cksum(&m->data()[it - m->begin()], tlen);
	
	reinterpret_cast<struct L3::iphdr *>(ti)->ip_len = tlen;
	reinterpret_cast<struct L3::iphdr *>(ti)->ip_ttl = L3_impl::IPDEFTTL;

#ifndef NETLAB_NO_TCP_RESPOND
	(void)inet.inetsw(protosw::SWPROTO_IP_RAW)->pr_output(*dynamic_cast<const struct pr_output_args*>(
		&L3_impl::ip_output_args(
		m,
		it,
		std::shared_ptr<std::vector<byte>>(nullptr),
		ro,
		0,
		nullptr)
		));
#endif
}

void L4_TCP_impl::tcp_dooptions(L4_TCP::tcpcb &tp, u_char *cp, int cnt, tcpiphdr &ti, int &ts_present, u_long &ts_val, u_long &ts_ecr) 
{
	u_short mss;
	int opt,
		optlen;

	/*
	*	Fetch option type and length:
	*	The options are scanned and an EOL (end-of-options) terminates the processing,
	*	causing the function to return. The length of a NOP is set to l, since this option is not
	*	followed by a length byte (Figure 26.16). The NOP will be ignored via the default in
	*	the switch statement.
	*/
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		if ((opt = cp[0]) == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;

		/*
		*	All other options have a length byte that is stored in optlen.
		*	Any new options that are not understood by this implementation of TCP are also
		*	ignored. This occurs because:
		*		1.	Any new options defined in the future will have an option length (NOP and
		*			EOL are the only two without a length), and the for loop skips optlen bytes
		*			each time around the loop.
		*		2.	The default in the switch statement ignores unknown options.
		*/
		else if ((optlen = cp[1]) <= 0)
			break;

		/*
		*	The final part of tcp_dooptions handles the MSS, window
		*	scale, and timestamp options.
		*/
		switch (opt) {

		default:
			continue;

			/*
			*	MSS option:
			*	If the length is not 4 (TCPOLEN_MAXSEG), or the segment does not have the SYN
			*	flag set, the option is ignored. Otherwise the 2 MSS bytes are copied into a local variable,
			*	converted to host byte order, and processed by tcp_mss. This has the side effect
			*	of setting the variable t_rnaxseg in the control block, the maximum number of bytes
			*	that can be sent in a segment to the other end.
			*/
		case TCPOPT_MAXSEG:
			if ((optlen != TCPOLEN_MAXSEG) || !(ti.ti_flags() & L4_TCP::tcphdr::TH_SYN))
				continue;

			std::memcpy(&mss, &cp[2], sizeof(mss));
			(void)tcp_mss(tp, mss = ntohs(mss));	/* sets t_maxseg */
			
			break;

			/*
			*	Window scale option
			*	If the length is not 3 (TCPOLEN_WINDOW), or the segment does not have the SYN
			*	flag set, the option is ignored. Net/3 remembers that it received a window scale
			*	request, and the scale factor is saved in requested_s_scale. Since only 1 byte is referenced
			*	by cp[2], there can't be alignment problems. When the ESTABLISHED state is
			*	entered, if both ends requested window scaling, it is enabled.
			*/
		case TCPOPT_WINDOW:
			if ((optlen != TCPOLEN_WINDOW) ||!(ti.ti_flags() & L4_TCP::tcphdr::TH_SYN))
				continue;

			tp.t_flags |= L4_TCP::tcpcb::TF_RCVD_SCALE;
			tp.requested_s_scale = std::min(cp[2], static_cast<u_char>(TCP_MAX_WINSHIFT));
			
			break;

			/*
			*	Timestamp option:
			*	If the length is not 10 (TCPOLEN_TIMESTAMP), the segment is ignored. Otherwise
			*	the flag pointed to by ts_present is set to 1, and the two timestamps are saved in the
			*	variables pointed to by ts_val and ts_ecr. If the received segment contains the SYN
			*	flag, Net/3 remembers that a timestamp request was received. ts_recent. is set to the
			*	received timestamp and ts_recent_age is set to tcp_now, the counter of the number
			*	of 500-ms clock ticks since the system was initialized.
			*/
		case TCPOPT_TIMESTAMP:
			if (optlen != TCPOLEN_TIMESTAMP)
				continue;
			
			ts_present = 1;
			std::memcpy(&ts_val, &cp[2], sizeof(ts_val));
			ts_val = ntohl(ts_val);
			
			std::memcpy(&ts_ecr, &cp[6], sizeof(ts_ecr));
			ts_ecr = ntohl(ts_ecr);

			/*
			* A timestamp received in a SYN makes
			* it ok to send timestamp requests and replies.
			*/
			if (ti.ti_flags() & L4_TCP::tcphdr::TH_SYN) {
				tp.t_flags |= L4_TCP::tcpcb::TF_RCVD_TSTMP;
				tp.ts_recent = ts_val;
				tp.ts_recent_age = tcp_now;
			}
			break;
		}
	}
}

int L4_TCP_impl::tcp_mss(class L4_TCP::tcpcb &tp, u_int offer) 
{	

	/*	
	 *	Acquire a route If necessary:
	 *	If the socket does not have a cached route, rtalloc acquires one. The interface
	 *	pointer associated wi th the outgoing route is saved in if p. Knowing the outgoing
	 *	interface is important, since its associated MTU can affect the MSS announced by TCP.
	 *	If a route is not acquired, the default of 512 (tcp_rossdfl t) is returned immediately.
	 */
	class inpcb *inp(tp.t_inpcb);
	struct L3::route &ro(inp->inp_route);
	struct L3::rtentry *rt(ro.ro_rt);
	if (rt == nullptr) {
		/* No route yet, so try to acquire one */
		if (inp->inp_faddr().s_addr != INADDR_ANY) {
			ro.ro_dst.sa_family = AF_INET;
			reinterpret_cast<struct sockaddr_in *>(&ro.ro_dst)->sin_addr = inp->inp_faddr();
			ro.rtalloc(&inet);
		}
		if ((rt = ro.ro_rt) == nullptr)
			return (tcp_mssdflt);
	}

	class inet_os *ifp(rt->rt_ifp);
	socket *so(dynamic_cast<socket*>(inp->inp_socket));

	/*	
	 *	The next part of tcp_ross, shown in Figure 27.8, checks whether the route has metrics
	 *	associated with it; if so, the variables t_rttmin, t_srtt, and t_rttvar can be
	 *	initialized from the metrics.
	 *	
	 *	Initialize smoothed RTT estimator:
	 *	If there are no RTT measurements yet for the connection (t_srtt is 0) and
	 *	rmx_rt t is nonzero, the latter initializes the smoothed RTT estimator t_srt t. If the
	 *	RTV_RTT bit in the routing metric lock flag is set, it indicates that rmx_rt t should also
	 *	be used to initialize the minimum RTT for this connection (t_rttmin). We saw that
	 *	tcp_newtcpcb initializes t_rttmin to 2 ticks.
	 *		rmx_rt t (in units of microseconds) is converted to t_srt t (in units of ticks x 8).
	 *	This is the reverse of the conversion done in Figure 27.4. Notice that t_rttrnin is set to
	 *	one-eighth the value of t_srtt, since the former is not divided by the scale factor
	 *	TCP_RTT SCALE.
	 *	
	* While we're here, check if there's an initial rtt
	* or rttvar. Convert from the route-table units
	* to scaled multiples of the slow timeout timer.
	*/
	if (tp.t_srtt == 0 && rt->rt_rmx.rmx_rtt) {
		int rtt(rt->rt_rmx.rmx_rtt);
		
		/*!
			\bug the lock bit for MTU indicates that the value is also a minimum value; this is subject to time.
		 */
		if (rt->rt_rmx.rmx_locks & L3::rtentry::RTV_RTT)
			tp.t_rttmin = rtt / (L3::rtentry::RTM_RTTUNIT / PR_SLOWHZ);
		tp.t_srtt = rtt / (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTT_SCALE));

		/*	
		 *	Initialize smoothed mean deviation estimator:
		 *	If the stored value of rmx_rttvar is nonzero, it is converted from units of
		 *	microseconds into ticks x 4 and stored in t_rttvar. But if the value is 0, t_rttvar is
		 *	set to t_rtt, that is, the variation is set to the mean. This defaults the variation to ± 1
		 *	RTT. Since the units of the former are ticks x 4 and the units of the latter are ticks x 8,
		 *	the value of t_srt t is converted accordingly.
		 */
		if (rt->rt_rmx.rmx_rttvar)
			tp.t_rttvar = static_cast<short>(rt->rt_rmx.rmx_rttvar / (L3::rtentry::RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTTVAR_SCALE)));
		else
			/* default variation is +- 1 rtt */
			tp.t_rttvar = tp.t_srtt * TCP_RTTVAR_SCALE / TCP_RTT_SCALE;

		/*	
		 *	calculate initial RTO
		 *	The current RTO is calculated and stored in t_rxtcur, using the unscaled equation
		 *				RTO = srtt + 2 * rttvar
		 *	A multiplier of 2, instead of 4, is used to calculate the first RTO. This is the same equation
		 *	that was used in Figure 25.21. Substituting the scaling relationships we get
		 *				RTO = t_srtt + 2 * t_rttvar = (t_srtt / 4 + t_rttvar) / 2
		 *	which is the second argument to TCPT_RANGESET.
		 */
		TCPT_RANGESET(
			tp.t_rxtcur,
			((tp.t_srtt >> 2) + tp.t_rttvar) >> 1,
			tp.t_rttmin,
			TCPTV_REXMTMAX);
	}

	/*	
	 *	The next part of tcp_mss, shown in Figure 27.9, calculates the MSS.
	 *	Use MSS from routing table MTU:
	 *	If the MTU is set in the routing table, mss is set to that value. Otherwise mss starts
	 *	at the value of the outgoing interface MTU minus 40 (the default size of the IP and TCP
	 *	headers). For an Ethernet, mss would start at 1460.
	 *	
	* if there's an mtu associated with the route, use it
	*/
	int mss(
		rt->rt_rmx.rmx_mtu ?
		rt->rt_rmx.rmx_mtu - sizeof(struct L4_TCP::tcpiphdr) :
		(ifp ?
		ifp->nic()->if_mtu() - sizeof(struct L4_TCP::tcpiphdr) :
		inet.nic()->if_mtu() - sizeof(struct L4_TCP::tcpiphdr)));

	/*
	*	Round MSS down to multiple of MCLBYTBS
	*	The goal of these lines of code is to reduce the value of mss to the next-lower multiple
	*	of the mbuf cluster size, if mss exceeds MCLBYTES. If the value of MCLBYTES (typically
	*	1024 or 2048) logically ANDed with the value minus 1 equals 0, then MCLBYTES is
	*	a power of 2. For example, 1024 (Ox400) logically ANDed with 1023 (Ox3ff) is 0.
	*		The value of mss is reduced to the next-lower multiple of MCLBYTES by clearing the
	*	appropriate number of low-order bits: if the cluster size is 1024, logically ANDing mss
	*	with the one's complement of 1023 (Oxfffffc00) clears the low-order 10 bits. For an
	*	Ethernet, this reduces mss from 1460 to 1024. If the duster size is 2048, logically ANDing
	*	mss with the one's complement of 2047 (Oxffff8000) clears the low-order 11 bits.
	*	For a token ring with an MTU of 4464, this reduces the value of mss from 4424 to 4096.
	*	If MCLBYTES is not a power of 2, the rounding down to the next-lower multiple of
	*	MCLBYTES is done with an integer division followed by a multiplication.
	*/
#define	MCLBYTES	2048		/* large enough for ether MTU */
#if (MCLBYTES & (MCLBYTES - 1)) == 0
	if (mss > MCLBYTES)
		mss &= ~(MCLBYTES - 1);
#else
	if (mss > MCLBYTES)
		mss /= MCLBYTES * MCLBYTES;
#endif

	/*
	*	Check If destination local or nonlocal
	*	If the foreign IP address is not local (in_localaddr returns 0), and if mss is
	*	greater than 512 (tcp_mssdflt), it is set to 512.
	*		Remark:	Whether an IP address is "local" or not depends on the value of the global
	*				subnetsarelocal, which is initialized from the symbol SUBNETSARELOCAL when the kernel
	*				is compiled. The default value is 1, meaning that an IP address with the same network ID
	*				as one of the host's interfaces is considered local. If the value is 0, an IP address must have the
	*				same network ID and the same subnet ID as one of the host's interfaces to be considered local.
	*
	*				This minimization for nonlocal hosts is an attempt to avoid fragmentation across wide-area
	*				networks. It is a historical artifact from the ARPANET when the MTU across most WAN links
	*				was 1006. As discussed in Section 11.7 of Volume 1, most WANs today support an MTU of
	*				1500 or greater. See also the discussion of the path MTU discovery feature (RFC 1191 [Mogul
	*				and Deering 1990]), in Section 24.2 of Volume 1. Net/3 does not support path MTU discovery.
	*/
	if (!inet.nic()->in_localaddr(inp->inp_faddr()))
		mss = std::min(mss, tcp_mssdflt);

	/*	
	 *	The final part of tcp_mss is shown in Figure 27.10:
	 *	Other end's MSS is upper bound:
	 *	The argument of fer is nonzero when this function is called from tcp_inpuc, and
	 *	its value is the MSS advertised by the other end. If the value of mss is greater than the
	 *	value advertised by the other end, it is set to the value of offer. For example, if the
	 *	function calculates an mss of 1024 but the advertised value from the other end is 512,
	 *	mss must be set to 512. Conversely, if mss is calculated as 536 (say the outgoing MTU is
	 *	576) and the other end advertises an MSS of 1460, TCP will use 536. TCP can always
	 *	use a value less than the advertised MSS, but it can't exceed the advertised value. The
	 *	argument offer is 0 when this function is called by tcp_output to send an MSS
	 *	option. The value of mss is also lower bounded by 32.
	 *	
	* The current mss, t_maxseg, is initialized to the default value.
	* If we compute a smaller value, reduce the current mss.
	* If we compute a larger value, return it for use in sending
	* a max seg size option, but don't store it for use
	* unless we received an offer at least that large from peer.
	* However, do not accept offers under 32 bytes.
	*/
	mss = 
		offer ? 
		std::min(mss, static_cast<int>(offer)) : 
		std::max(mss, 32); /* sanity */

	/*	
	 *	If the value of mss has decreased from the default set by tcp_newtcpcb in the
	 *	variable t_maxseg (512), or if TCP is processing a received MSS option (offer is
	 *	nonzero), the following steps occur: 
	 *		1.	First, if the value of rmx_sendpipe has been stored for the route, 
	 *			its value will be used as the send buffer high-water mark (Figure 16.4).
	 *		2.	If the buffer size is less than mss, the smaller value is used. This should never
	 *			happen unless the application explicitly sets the send buffer size to a small value, or the
	 *			administrator sets rmx_sendpipe to a small value, since the high-water mark of the
	 *			send buffer defaults to 8192, larger than most values for the MSS.
	 */
	if (mss < tp.t_maxseg || offer != 0) {

		/*
		* If there's a pipesize, change the socket buffer
		* to that size.  Make the socket buffers an integral
		* number of mss units; if the mss is larger than
		* the socket buffer, decrease the mss.
		*/
		u_long bufsize(rt->rt_rmx.rmx_sendpipe);
		if (bufsize == 0)
			bufsize = so->so_snd.capacity();
		if (static_cast<int>(bufsize) < mss)
			mss = bufsize;
		else {
			/*	
			 *	Round buffer sizes to multiple of MSS:
			 *	The send buffer size is rounded up to the next integral multiple of the MSS,
			 *	bounded by the value of sb_max (262,144 on Net/3, which is 256 * 1024). The socket's
			 *	high-water mark is set by sbreserve. For example, the default high-water mark is
			 *	8192, but for a local TCP connection on an Ethernet with a cluster size of 2048 (i.e., an
			 *	MSS of 1460) this code increases the high-water mark to 8760 (which is 6x 1460). But
			 *	for a nonlocal connection with an MSS of 512, the high-water mark is left at 8192.
			 */
			if ((bufsize = roundup(bufsize, static_cast<u_long>(mss))) > netlab::L5_socket::sockbuf::SB_MAX)
				bufsize = netlab::L5_socket::sockbuf::SB_MAX;
			(void)so->so_snd.sbreserve(bufsize);
		}

		/*	
		 *	The value of t_maxseg is set, either because it decreased from the default (512) or
		 *	because an MSS option was received from the other end.
		 */
		tp.t_maxseg = mss;

		/*	
		 *	The same logic just applied to the send buffer is also applied to the receive buffer.
		 */
		if ((bufsize = rt->rt_rmx.rmx_recvpipe) == 0)
			bufsize = so->so_rcv.capacity();
		if (static_cast<int>(bufsize) > mss) {
			if ((bufsize = roundup(bufsize, static_cast<u_long>(mss))) > netlab::L5_socket::sockbuf::SB_MAX)
				bufsize = netlab::L5_socket::sockbuf::SB_MAX;
			(void)so->so_rcv.sbreserve(bufsize);
		}
	}

	/*	
	 *	Initialize congestion window and slow start threshold:
	 *	The value of the congestion window, snd_cwnd, is set to one segment. If the
	 *	rmx_ssthresh value in the routing table is nonzero, the slow start threshold
	 *	(snd_ssthresh) is set to that value, but the value must not be less than two segments.
	 */
	tp.log_snd_cwnd(tp.snd_cwnd = mss);
	if (rt->rt_rmx.rmx_ssthresh)
		/*
		* There's some sort of gateway or interface
		* buffer limit on the path.  Use this to set
		* the slow start threshhold, but set the
		* threshold to no less than 2*mss.
		*/
		tp.snd_ssthresh = std::max(2 * mss, static_cast<int>(rt->rt_rmx.rmx_ssthresh));

	/*	
	 *	The value of mss is returned by the function. tcp_input ignores this value in Figure
	 *	28.10 (since it received an MSS from the other end), but tcp_output sends this
	 *	value as the announced MSS in Figure 26.23.
	 */
	return (mss);
}

void L4_TCP_impl::trimthenstep6(class L4_TCP::tcpcb *tp, int &tiflags, tcpiphdr *ti, std::shared_ptr<std::vector<byte>> m, std::vector<byte>::iterator it, u_long &tiwin, int &needoutput) 
{
	/*
	*	The sequence number of the segment is incremented by 1 to account for the SYN. If
	*	there is any data in the segment, ti.ti_seq() now contains the starting sequence number of
	*	the first byte of data.
	*
	* Advance ti->ti_seq to correspond to first data byte.
	* If data, trim to stay within window,
	* dropping FIN if necessary.
	*/
	ti->ti_seq()++;

	/*
	*	Drop any received data that follows receive window:
	*	tlen is the number of data bytes in the segment. If it is greater than the receive
	*	window, the excess data (ti_len minus rcv_wnd) is dropped. The data to be trimmed
	*	from the end of the buf (Figure 2.20). tlen is updated to be the new amount of data
	*	in the mbuf chain and in case the FIN flag was set, it is cleared.
	*	This is because the FIN would follow the final data byte, which was just discarded
	*	because it was outside the receive window.
	*		Remark:	If too much data is received with a SYN, and if the SYN is in response
	*				to an active open the other end received TCP's SYN, which contained a
	*				window advertisement. This means the other end ignored the advertised
	*				window and is exhibiting unsocial behavior. But if too much data
	*				accompanies a SYN performing an active open, the other end has not
	*				received a window advertisement, so it has to guess how much data can
	*				accompany its SYN.
	*/
	if (static_cast<u_long>(ti->ti_len()) > tp->rcv_wnd) {
		ti->ti_len() = static_cast<short>(tp->rcv_wnd);
		tiflags &= ~tcphdr::TH_FIN;
	}

	/*
	*	Force update of window variables:
	*	snd_wl1 is set the received sequence number minus 1. We'll see in Figure 29.15
	*	that this causes the three window update variables, snd_wnd, snd_wll, and snd_wl2,
	*	to be updated. The receive urgent pointer (rcv_up) is set to the received sequence
	*	number. A jump is made to step6, which refers to a step in RFC 793, and we cover this
	*	in Figure 29.15.
	*/
	tp->snd_wl1 = ti->ti_seq() - 1;
	tp->rcv_up = ti->ti_seq();
	
	return step6(tp, tiflags, ti, m, it, tiwin, needoutput);
}



inline void	L4_TCP_impl::TCP_ISSINCR(const int div) { tcp_iss += (250 * 1024) / div; }

void L4_TCP_impl::print(struct L4_TCP::tcpiphdr& tcpip, uint16_t tcp_checksum, std::string intro, std::ostream& str) const
{
	std::swap(tcp_checksum, tcpip.ti_sum());
	std::lock_guard<std::mutex> lock(inet.print_mutex);
	str << intro << std::endl << tcpip << std::endl;
	std::swap(tcp_checksum, tcpip.ti_sum());
}



void L4_TCP_impl::print(struct L4_TCP::tcphdr& tcp, uint16_t tcp_checksum, std::string intro, std::ostream& str) const
{
	std::swap(tcp_checksum, tcp.th_sum);
	std::lock_guard<std::mutex> lock(inet.print_mutex);
	str << intro << std::endl << tcp << std::endl;
	std::swap(tcp_checksum, tcp.th_sum);
}
















































































 



