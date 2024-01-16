/*!
    \file	L3.h
    
	\author	Tom Mahler, contact at tommahler@gmail.com
	
    \brief	Declares the L3 class.
*/
#ifndef L3_H_
#define L3_H_

/*!
	\def	NETLAB_L3_DEBUG
	Define in order to printout the L3 packets for debug
*/
//#define NETLAB_L3_DEBUG

#include "inet_os.hpp"
#include <iostream>

/*!
    \class	L3

    \brief
    Represents a Layer 3 interface (IP).
    
    \pre	First initialize an instance of inet_os.
    \pre	Must define struct L3::iphdr.
    \pre	Must define struct L3::rtentry.
    \pre	Must define struct L3::route.
    \pre	Must define struct L3::ip_moptions.
    \note
    Though we do not support routing, forwarding nor multi-casting,
    we must define these structs for the sake of consistency.

    \sa	protosw
*/
class L3 
	: public protosw {
public:

	/*!
	    \struct	iphdr
	
	    \brief
	    Structure of an internet header, naked of options.
	    
	    \note Defined for the sake of consistency.
	*/
	struct iphdr;

	/*!
	    \struct	rtentry
	
	    \brief
	    Structure of the route entry (in the routing table).
	    
	    We distinguish between routes to hosts and routes to networks, preferring the former if
	    available. For each route we infer the interface to use from the gateway address supplied
	    when the route was entered. Routes that forward packets through gateways are marked so
	    that the output routines know to address the gateway rather than the ultimate destination.
	    
	    \note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rtentry;

	/*!
	    \struct	route
	
	    \brief
	    Structure of a route.
	    
	    A route consists of a destination address and a reference to a routing entry. These are
	    often held by protocols in their control blocks, e.g. \ref inpcb.
	    
		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct route;

	/*!  \relates inpcb
	\struct	ip_moptions

	\brief
	Structure attached to inpcb::ip_moptions and passed to ip_output when IP multicast
	options are in use.

	\note This struct is defined for both consistencies and support multi casting in the future.
	*/
	struct ip_moptions;

	/*!
	    \fn
	    L3::L3(class inet_os &inet, const short &pr_type = 0, const short &pr_protocol = 0, const short &pr_flags = 0)
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	    \param	pr_type			Type of the pr.
	    \param	pr_protocol 	The pr protocol.
	    \param	pr_flags		The pr flags.
	*/
	L3(class inet_os &inet, const short &pr_type = 0, const short &pr_protocol = 0, const short &pr_flags = 0) 
		: protosw(inet, pr_type, nullptr, pr_protocol, pr_flags) {  }

	virtual void pr_init() = 0;
	virtual int pr_output(const struct pr_output_args &args) = 0;
	virtual void pr_input(const struct pr_input_args &args) = 0;

private:
	virtual void pr_ctlinput() { };
	virtual int pr_ctloutput() { return 0; };	
	virtual int pr_usrreq(class netlab::L5_socket *so, int req, std::shared_ptr<std::vector<byte>>m,
		struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> control) {	return 0; }
	virtual void pr_fasttimo() { };	
	virtual void pr_slowtimo() { };	
	virtual void pr_drain() { };		
	virtual int pr_sysctl() { return 0; };		
};









/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

/*!
	\def	NETLAB_L3_FORWARDING
	To enable IP forwarding, currently disabled.
*/
#define NETLAB_L3_FORWARDING
#ifdef NETLAB_L3_FORWARDING
#undef NETLAB_L3_FORWARDING
#endif

/*!
	\def	NETLAB_L3_OPTIONS
	To enable IP options, currently disabled.
*/
#define NETLAB_L3_OPTIONS
#ifdef NETLAB_L3_OPTIONS
#undef NETLAB_L3_OPTIONS
#endif

/*!
	\def	NETLAB_L3_MULTICAST
	To enable IP multi casting, currently disabled.
*/
#define NETLAB_L3_MULTICAST
#ifdef NETLAB_L3_MULTICAST
#undef NETLAB_L3_MULTICAST
#endif

/*!
	\def	NETLAB_L3_FRAGMENTATION
	To enable IPfragmentation, currently disabled.
*/
#define NETLAB_L3_FRAGMENTATION
#ifdef NETLAB_L3_FRAGMENTATION
#undef NETLAB_L3_FRAGMENTATION
#endif



/**
* \class L3
* \brief Represents a Layer 3 interface (IP).
*/
class L3_impl
	: public L3
{
public:

	/*!
	    \typedef	u_short n_short
	
	    \brief	Defines an alias representing the short as received from the net.
	*/
	typedef u_short n_short;
	
	/*!
	    \typedef	u_long n_long
	
	    \brief	Defines an alias representing the long as received from the net.
	*/
	typedef u_long	n_long;

	/*!
	    \typedef	u_long n_time
	
	    \brief	Defines an alias representing the time in ms since 00:00 GMT, byte rev.
	*/
	typedef	u_long	n_time;

	enum ip_things // please rename 
	{ 	
		IPVERSION = 4,					/*!< Definitions for internet protocol version 4. \sa Per RFC 791, September 1981 */
		MAX_IPOPTLEN = 40,				/*!< The actual length of the options (including ipopt_dst). */
		IP_MAX_MEMBERSHIPS = 20,		/*!< per socket; must fit in one mbuf (legacy) */
		IP_MAXPACKET = 65535,			/*!< The maximum packet size */
		IP_MSS = 576,					/*!< The default maximum segment size */
		IP_DEFAULT_MULTICAST_TTL = 1	/*!< normally limit multi casts to 1 hop */
	};	

	/*!
	    \enum	IPOPT_
	
	    \brief	Definitions for options.
	*/
	enum IPOPT_ 
	{
		IPOPT_EOL = 0,			/*!< end of option list */
		IPOPT_NOP = 1,			/*!< no operation */
		IPOPT_RR = 7,			/*!< record packet route */
		IPOPT_TS = 68,			/*!< timestamp */
		IPOPT_SECURITY = 130,	/*!< provide s,c,h,tcc */
		IPOPT_LSRR = 131,		/*!< loose source route */
		IPOPT_SATID = 136,		/*!< satnet id */
		IPOPT_SSRR = 137,		/*!< strict source route */

		/*
		* Offsets to fields in options other than EOL and NOP.
		*/
		IPOPT_OPTVAL = 0,		/*!< option ID */
		IPOPT_OLEN = 1,			/*!< option length */
		IPOPT_OFFSET = 2,		/*!< offset within option */
		IPOPT_MINOFF = 4		/*!< min value of above */
	};

	/*!
	    \enum	IPOPT_SECUR_
	
	    \brief	Security Options for Internet Protocol (IPSO) as defined in RFC 1108.
	    
		\see RFC 1108
	*/
	enum IPOPT_SECUR_ 
	{
		IPOPT_SECUR_UNCLASS = 0x0000,   /*!< The Security Options for Unclassified option */
		IPOPT_SECUR_CONFID = 0xf135,	/*!< The Security Options for Confidential option */
		IPOPT_SECUR_EFTO = 0x789a,		/*!< The Security Options for EFTO option */
		IPOPT_SECUR_MMMM = 0xbc4d,		/*!< The Security Options for MMMM option */
		IPOPT_SECUR_RESTR = 0xaf13,		/*!< The The Security Options for RESTR option */
		IPOPT_SECUR_SECRET = 0xd788,	/*!< The The Security Options for Secret option */
		IPOPT_SECUR_TOPSECRET = 0x6bc5  /*!< The The Security Options for Top Secret option */
	};

	/*!
	    \enum	TTL_
	
	    \brief	Internet implementation parameters for Time-To-Live.
	*/
	enum TTL_ 
	{
		MAXTTL = 255,		/*!< maximum time to live (seconds) */
		IPDEFTTL = 64,		/*!< default ttl, from RFC 1340 */
		IPFRAGTTL = 60,		/*!< time to live for frags, slowhz */
		IPTTLDEC = 1		/*!< subtracted when forwarding */
	};

	/*!
	    \enum	IP_OUTPUT_
	
	    \brief	Flags passed to ip_output as last parameter.
	*/
	enum IP_OUTPUT_ 
	{
		IP_FORWARDING = 0x1,				/*!< most of ip header exists */
		IP_RAWOUTPUT = 0x2,					/*!< raw ip header exists */
		IP_ROUTETOIF = SO_DONTROUTE,		/*!< bypass routing tables */
		IP_ALLOWBROADCAST = SO_BROADCAST	/*!< can send broadcast packets */
	};

	/*!
	    \struct	rt_metrics
	
	    \brief
	    These numbers are used by reliable protocols for determining retransmission behavior and
	    are included in the routing structure.
	        
	    \note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rt_metrics {

		/*!
		    \fn	rt_metrics();
		
		    \brief	Default constructor.
		*/

		rt_metrics();

		u_long	rmx_locks;		/*!< Kernel must leave these values alone */
		u_long	rmx_mtu;		/*!< /* MTU for this path */
		u_long	rmx_hopcount;   /*!< Max hops expected */
		u_long	rmx_expire;		/*!< Lifetime for route, e.g. redirect */
		u_long	rmx_recvpipe;   /*!< Inbound delay-bandwith product */
		u_long	rmx_sendpipe;   /*!< Outbound delay-bandwith product */
		u_long	rmx_ssthresh;   /*!< Outbound gateway buffer limit */
		u_long	rmx_rtt;		/*!< Estimated round trip time */
		u_long	rmx_rttvar;		/*!< Estimated rtt variance */
		u_long	rmx_pksent;		/*!< Packets sent using this route */
	};

	/*!
		\struct	rt_addrinfo

		\brief
		A route addrinfo.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rt_addrinfo {

		/*!
			\enum	RTAX_

			\brief	Index offsets for sockaddr array for alternate internal encoding.
		*/
		enum RTAX_ 
		{
			RTAX_DST = 0,		/*!< destination sockaddr present */
			RTAX_GATEWAY = 1,	/*!< gateway sockaddr present */
			RTAX_NETMASK = 2,	/*!< netmask sockaddr present */
			RTAX_GENMASK = 3,	/*!< cloning mask sockaddr present */
			RTAX_IFP = 4,		/*!< interface name sockaddr present */
			RTAX_IFA = 5,		/*!< interface addr sockaddr present */
			RTAX_AUTHOR = 6,	/*!< sockaddr for author of redirect */
			RTAX_BRD = 7,		/*!< for NEWADDR, broadcast or p-p dest addr */
			RTAX_MAX = 8		/*!< size of array to allocate */
		};

		int	rti_addrs;							/*!< The rti addrs */
		struct sockaddr *rti_info[RTAX_MAX];	/*!< The rti info[rtax max] array */
	};

	/*!
		\struct	rt_msghdr

		\brief
		Structures for routing messages.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct rt_msghdr {

		/*!
			\typedef	int32_t pid_t

			\brief	Defines an alias representing the process id.
		*/
		typedef	int32_t	pid_t;

		u_short	rtm_msglen;			/*!< to skip over non-understood messages */
		u_char	rtm_version;		/*!< future binary compatibility */
		u_char	rtm_type;			/*!< message type */
		u_short	rtm_index;			/*!< index for associated ifp */
		int	rtm_flags;				/*!< flags, including kern & message, e.g. DONE */
		int	rtm_addrs;				/*!< bitmask identifying sockaddrs in msg */
		pid_t	rtm_pid;			/*!< identify sender */
		int	rtm_seq;				/*!< for sender to identify action */
		int	rtm_errno;				/*!< why failed */
		int	rtm_use;				/*!< from rtentry */
		u_long	rtm_inits;			/*!< which metrics we are initializing */
		struct	rt_metrics rtm_rmx; /*!< metrics themselves */
	};

	/*!
		\struct	radix_mask

		\brief
		Annotations to tree concerning potential routes applying to subtrees.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct radix_mask {

		/*!
			\fn	inline char* rm_mask() const

			\brief	Gets the rm_mask.

			\return	rm_rmu.rmu_mask.
		*/
		inline char* rm_mask() const { return rm_rmu.rmu_mask; }

		/*!
			\fn	inline radix_node* rm_leaf() const

			\brief	Gets rm_leaf.

			\return
			rm_rmu.rmu_leaf.

			\note extra field would make 32 bytes.
		*/
		inline struct radix_node* rm_leaf() const { return rm_rmu.rmu_leaf; }

		short	rm_b;					/*!< bit offset; -1-index(netmask) */
		char	rm_unused;				/*!< cf. rn_bmask */
		u_char	rm_flags;				/*!< cf. rn_flags */
		struct	radix_mask *rm_mklist;	/*!< more masks to try */

		union	{
			char	*rmu_mask;				/*!< the mask */
			struct	radix_node *rmu_leaf;	/*!< for normal routes */
		}	rm_rmu;
		
		int	rm_refs;						/*!< # of references to this struct */
	};

	/*!
		\struct	radix_node

		\brief	Radix search tree node layout.

		\note This struct is defined for both consistencies and support routing in the future.
	*/
	struct radix_node {

		/*!
		    \enum	RNF_
		
		    \brief	Flags for #rn_flags.
		*/
		enum RNF_ 
		{
			RNF_NORMAL = 1,	/*!< leaf contains normal route */
			RNF_ROOT = 2,	/*!< leaf is root leaf for tree */
			RNF_ACTIVE = 4	/*!< This node is alive (for rtfree) */
		};

		/*!
			\fn	radix_node();

			\brief	Default constructor.
		*/
		radix_node();

		/*!
			\fn	inline radix_node* rn_dupedkey() const

			\brief	Gets rn_dupedkey.

			\return	rn_u.rn_leaf.rn_Dupedkey.
		*/
		inline struct radix_node* rn_dupedkey() const { return rn_u.rn_leaf.rn_Dupedkey; }

		/*!
			\fn	inline char* rn_key() const

			\brief	Gets rn_key.

			\return	rn_u.rn_leaf.rn_Key.
		*/
		inline char* rn_key() const { return rn_u.rn_leaf.rn_Key; }

		/*!
			\fn	inline char* rn_mask() const

			\brief	Gets rn_mask.

			\return	rn_u.rn_leaf.rn_Mask.
		*/
		inline char* rn_mask() const { return rn_u.rn_leaf.rn_Mask; }

		/*!
			\fn	inline int& rn_off()

			\brief	Gets rn_off.

			\return	rn_u.rn_node.rn_Off;
		*/
		inline int& rn_off() { return rn_u.rn_node.rn_Off; }

		/*!
		    \fn	inline radix_node* rn_l() const
		
		    \brief	Gets rn_l.
		
		    \return	rn_u.rn_node.rn_L.
		*/
		inline struct radix_node* rn_l() const { return rn_u.rn_node.rn_L; }

		/*!
			\fn	inline radix_node* rn_r() const

			\brief	Gets rn_r.

			\return	rn_u.rn_node.rn_R.
		*/
		inline struct radix_node* rn_r() const { return rn_u.rn_node.rn_R; }

		struct	radix_mask *rn_mklist;	/*!< list of masks contained in subtree */
		struct	radix_node *rn_p;		/*!< parent */
		
		short	rn_b;					/*!< bit offset; -1-index(netmask) */
		char	rn_bmask;				/*!< node: mask for bit test*/
		u_char	rn_flags;				/*!< enumerated above */
		
		union {
			struct {								/*!< leaf only data: */
				char	*rn_Key;					/*!< object of search */
				char	*rn_Mask;					/*!< netmask, if present */
				struct	radix_node *rn_Dupedkey;	/*!< The rn dupedkey */
			} rn_leaf;
			struct {						/*!< node only data: */
				int	rn_Off;					/*!< where to start compare */
				struct	radix_node *rn_L;	/*!< progeny */
				struct	radix_node *rn_R;	/*!< progeny */
			} rn_node;
		}		rn_u;
	};

	/*!
	    \struct	radix_node_head
	
	    \brief
	    A radix node head.
	    
	    \note This struct is defined for both consistencies and support routing in the future.
	*/
	struct radix_node_head {
		struct L3_impl::radix_node *rnh_treetop;	/*!< The rnh treetop */
		int	rnh_addrsize;				/*!< permit, but not require fixed keys */
		int	rnh_pktsize;				/*!< permit, but not require fixed keys */
	};

	/*!
	    \struct	ip_srcrt
	
	    \brief
	    We need to save the IP options in case a protocol wants to respond to an incoming packet
	    over the same route if the packet got here using IP source routing.  This allows
	    connection establishment and maintenance when the remote end is on a network that is not
	    known to us.
	    
	    \note This struct is defined for both consistencies and support IP options in the future.
	*/
	struct ip_srcrt {
		struct	in_addr dst;				/*!< final destination */
		char	nop;						/*!< one NOP to align */
		char	srcopt[IPOPT_OFFSET + 1];	/*!< OPTVAL, OLEN and OFFSET */
		struct	in_addr route[MAX_IPOPTLEN / sizeof(struct in_addr)];   /*!< the route address array */
	};

	/*!
	    \struct	ipoption
	
	    \brief
	    Structure stored in mbuf in inpcb::ip_options and passed to ip_output when ip options are
	    in use.
	    
	    \note This struct is defined for both consistencies and support IP options in the future.
	*/
	struct ipoption {
		struct	in_addr ipopt_dst;			/*!< first-hop dst if source routed */
		char	ipopt_list[MAX_IPOPTLEN];	/*!< options proper */
	};

	/*!
	    \struct	ip_timestamp
	
	    \brief	IP Time stamp option structure.
	    
		\note This struct is defined for both consistencies and support IP options in the future.
	*/
	struct	ip_timestamp {

		/*!
		    \typedef	u_char_pack ipt_oflw_flg_pack
		
		    \brief
		    Defines an alias representing the two 4-bit pack of overflow counter then flags,
		    according to windows byte order (BIG_ENDIAN).
		*/
		typedef u_char_pack ipt_oflw_flg_pack;

		/*!
		    \enum	IPOPT_TS_
		
		    \brief	Flag bits for ipt_flg.
		*/
		enum IPOPT_TS_ 
		{
			IPOPT_TS_TSONLY = 0,	/*!< timestamps only */
			IPOPT_TS_TSANDADDR = 1,	/*!< timestamps and addresses */
			IPOPT_TS_PRESPEC = 3	/*!< specified modules only */
		};

		u_char	ipt_code;	/*!< IPOPT_TS */
		u_char	ipt_len;	/*!< size of structure (variable) */
		u_char	ipt_ptr;	/*!< index of current entry */
		ipt_oflw_flg_pack ipt_oflw_flg; /*!< overflow counter then flags defined in #IPOPT_TS_ */

		/*!
		    \union	ipt_timestamp
		
		    \brief	An ipt timestamp.
		*/
		union ipt_timestamp {
			n_long	ipt_time[1];	/*!< network format */
			struct	ipt_ta {
				struct in_addr ipt_addr; /*!< the ipt address */
				n_long ipt_time;	/*!< network format */
			} ipt_ta[1]; 
		} ipt_timestamp;
	};

	/*!
	    \struct	ipq
	
	    \brief
	    Ip reassembly queue structure.  Each fragment being reassembled is attached to one of
	    these structures. They are timed out after ipq_ttl drops to 0, and may also be reclaimed
	    if memory becomes tight.
	    
	    \note This struct is defined for both consistencies and support IP fragmentation in the
	    future.
	*/
	struct ipq {
		enum ifq_len // rename 
		{ 
			IFQ_MAXLEN = 50 /*!< The ifq maxlen */
		};

		struct	ipq *next;	/*!< to other reassembly headers, forward */
		struct	ipq *prev;	/*!< to other reassembly headers, backward */
		u_char	ipq_ttl;	/*!< time for reassembly q to live */
		u_char	ipq_p;		/*!< protocol of this fragment */
		u_short	ipq_id;		/*!< sequence id for reassembly */
		struct	ipasfrag *ipq_next;	/*!< The ip reassembly queue as linked list, forward */
		struct	ipasfrag *ipq_prev;	/*!< The ip reassembly queue as linked list, backward */
		struct	in_addr ipq_src;	/*!< to ip headers of fragments, source address */
		struct	in_addr ipq_dst;	/*!< to ip headers of fragments, destination address */
	};

	/*!
	    \struct	ipasfrag
	
	    \brief
	    Ip header, when holding a fragment.
	    
	    \note ipf_next must be at same offset as ipq_next above.
	*/
	struct	ipasfrag {

		/*!
		    \typedef	u_char_pack ip_v_hl_pack
		
		    \brief
		    Defines an alias representing the two 4-bit pack of version and header length,
		    according to windows byte order (BIG_ENDIAN).
		*/
		typedef u_char_pack ip_v_hl_pack;

		ip_v_hl_pack ip_v_hl;   /*!< version then header length, in a ip_v_hl_pack. \note The IP header length is in 4-bytes unit */
		u_char	ipf_mff;		/*!< copied from (ip_off&IP_MF)	\bug overlays ip_tos: use low bit to avoid destroying tos; */
		short	ip_len;			/*!< total length, including data */
		u_short	ip_id;			/*!< identification */
		short	ip_off;			/*!< fragment offset field \see IP_ */
		u_char	ip_ttl;			/*!< time to live */
		u_char	ip_p;			/*!< protocol */
		u_short	ip_sum;			/*!< checksum */
		struct	ipasfrag *ipf_next;	/*!< next fragment */
		struct	ipasfrag *ipf_prev;	/*!< previous fragment */
	};

	/*!
	\struct	ip_output_args

	\brief	Arguments for IP output.

	\sa	pr_output_args
	*/
	struct ip_output_args
		: public pr_output_args
	{
		/*!
		    \fn	ip_output_args(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, std::shared_ptr<std::vector<byte>> &opt, struct L3::route *ro, int flags, struct L3::ip_moptions *imo);
		
		    \brief	Constructor.
		
		    \param [in,out]	m  	The std::shared_ptr<std::vector<byte>> to process.
		    \param [in,out]	it 	The iterator, maintaining the current offset in the vector.
		    \param [in,out]	opt
		    The IP option \warning Must be std::shared_ptr&lt;std::vector&lt;byte&gt;&gt;
		    (nullptr) as options are not supported.
		    \param [in,out]	ro
		    The route for the packet. Should only use the ro_dst member to hold the sockaddr for
		    the output route.
		    \param	flags	   	The flags \see IP_OUTPUT_.
		    \param [in,out]	imo
		    The IP multicast options \warning Must be nullptr as multicast are not supported.
		*/
		ip_output_args(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, std::shared_ptr<std::vector<byte>> &opt, struct L3::route *ro, int flags, struct  L3::ip_moptions *imo);

		std::shared_ptr<std::vector<byte>> &m;		/*!< The std::shared_ptr<std::vector<byte>> to process. */
		std::vector<byte>::iterator &it;			/*!< The iterator, maintaining the current offset in the vector. */
		std::shared_ptr<std::vector<byte>> &opt;	/*!< The IP option \warning Must be std::shared_ptr<std::vector<byte>>(nullptr) as options are not supported. */
		struct L3::route *ro;						/*!< The route for the packet. Should only use the ro_dst member to hold the sockaddr for the output route. */
		int flags;									/*!< The flags \see IP_OUTPUT_. */
		struct  L3::ip_moptions *imo;				/*!< The IP multicast options \warning Must be nullptr as multicast are not supported. */
	};
	
	/*!
	    \fn	L3_impl::L3_impl(class inet_os &inet, const short &pr_type = 0, const short &pr_protocol = 0, const short &pr_flags = 0);
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	The inet.
	    \param	pr_type			Type of the protocol type.
	    \param	pr_protocol 	The protocol.
	    \param	pr_flags		The protocol flags.
	*/
	L3_impl(class inet_os &inet, const short &pr_type = 0, const short &pr_protocol = 0, const short &pr_flags = 0);

	/*!
	    \fn	static void L3_impl::ip_insertoptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, std::shared_ptr<std::vector<byte>> &opt, int &phlen);
	
	    \brief
	    Insert IP options into preformed packet. Adjust IP destination as required for IP source
	    routing, as indicated by a non-zero in_addr at the start of the options.
	
		\param [in,out]	m 		The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it		The iterator, as the current offset in the vector.
	    \param [in,out]	opt  	The IP option to be inserted.
	    \param [in,out]	phlen	The ip header length.
	*/
	static void ip_insertoptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, std::shared_ptr<std::vector<byte>> &opt, int &iphlen);

	/*!
		\fn	static void L3_impl::ip_stripoptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it);

		\brief
		Strip out IP options, at higher level protocol in the kernel

		\param [in,out]	m 	The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it	The iterator, as the current offset in the vector.
	*/
	static void ip_stripoptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it);

	virtual void pr_init();
	virtual void pr_input(const struct pr_input_args &args);
	virtual int pr_output(const struct pr_output_args &args);

private:

	/*!
	    \fn	void L3_impl::ip_init();
	
	    \brief
	    Fill in IP protocol switch table, and all protocols not implemented in kernel go to raw
	    IP protocol handler. The ip_init function is called once by inet_os::domaininit(const
	    bool start_timer). at system initialization time.
	*/
	void ip_init();

	/*!
	    \brief
	    The IP output code receives packets from two sources: the transport protocols and
	    ip_forward() (which is disabled). For the standard Internet transport protocols, the
	    generality of the protosw structure is not necessary, since the calling functions are not
	    accessing IP in a protocol-independent context, however in order to allow different
	    layers to be used, we access IP output operations to be accessed by inetsw[0].pr_output.
	    We describe ip_output in three sections:
	    	*	header initialization,
	    	*	route selection, and
	    	*	source address selection and fragmentation.
	
	    \param	args	\see ip_output_args.
	
	    \return	An int, for error handling.
	*/
	inline int ip_output(const struct ip_output_args &args);

	/*!
	    \brief	Helper function for #ip_output(), frees the \ref rtentry of #ro
	
	    \param [in,out]	ro	   	If non-null, the route from which to free the \ref rtentry.
	    \param [in,out]	iproute	The iproute.
	    \param	flags		   	The flags.
	    \param	error		   	The error to return.
	
		\return	An int, for error handling.
	*/
	inline int done(struct route *ro, struct route &iproute, const int &flags, const int error);

	/*!   
		\note 	Currently disabled.

	    Do option processing on a datagram, possibly discarding it if bad options are encountered,
	    or forwarding it if source-routed. Returns 1 if packet has been forwarded/freed, 0 if the
	    packet should be processed further.
	
		\param [in,out]	m 		The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it		The iterator, as the current offset in the vector.
	
		\return	An int, for error handling.
	*/

	inline int ip_dooptions(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it);

	/*!
		\note 	Currently disabled.
	
	    \brief
	    Forward a packet. If some error occurs return the sender an icmp packet. Note we can't
	    always generate a meaningful icmp message because icmp doesn't have a large enough
	    repertoire of codes and types.
	    
	    If not forwarding, just drop the packet. This could be confusing if ipforwarding was
	    zero but some routing protocol was advancing us as a gateway to somewhere.  However, we
	    must let the routing protocol deal with that.
	    
	    The srcrt parameter indicates whether the packet is being forwarded via a source route.
	
		\param [in,out]	m 		The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it	The iterator, as the current offset in the vector.
	    \param	srcrt	  	The srcrt.
	*/
	inline void ip_forward(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, const int &srcrt);

	/*!
		\post	m is passed to the upper layer for processing.
		\note 	Currently disabled.
		
	    \brief	#pr_input() helper for reassemble.
	
		\param [in,out]	m 		The std::shared_ptr<std::vector<byte>> to strip.
		\param [in,out]	it		The iterator, as the current offset in the vector.
	    \param [in,out]	ip  	The \ref iphdr.
	    \param [in,out]	hlen	The hlen.
	*/
	inline void ours(std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it, struct iphdr &ip, int &hlen);

	/*!
	    \brief	Prints the \ref iphdr with #checksum as its ip_sum, making sure to use the lock_guard for the print_mutex.
	
	    \param [in,out]	ip 	The IP.
	    \param	checksum   	The checksum.
	    \param [in,out]	str	(Optional) the string.
	*/
	inline void print(struct iphdr& ip, uint16_t checksum, std::ostream& str = std::cout);

	/*!
		\brief
		Calculates the 16-bit checksum of the #buff of length #len.

		\note This routine is very heavily used in the network code and should be modified for
		each CPU to be as fast as possible.

		\note This implementation is 386 version.

		\param	buff	The buffer to checksum.
		\param	len 	The length.

		\return	An uint16_t checksum result.
	*/
	inline uint16_t in_cksum(const byte* buff, size_t len) { return inet.in_cksum(buff, len); }
	

	u_short	ip_id;						/*!< last ID assigned to an outgoing IP packet */
	u_char	ip_protox[IPPROTO_MAX];		/*!< demultiplexing array for IP packets */
	struct ipq ipq_t;					/*!< The reassembly queue */



	virtual void pr_drain() { };
	virtual int pr_sysctl() { return 0; };
	virtual void pr_ctlinput() { };
	virtual int pr_ctloutput() { return 0; };
	virtual int pr_usrreq(class netlab::L5_socket *so, int req, std::shared_ptr<std::vector<byte>> &m,
	struct sockaddr *nam, size_t nam_len, std::shared_ptr<std::vector<byte>> &control) { return 0; };		
	virtual void pr_fasttimo() { };
	virtual void pr_slowtimo() { };
};

/*!
    \struct	L3::iphdr

    \brief
    Structure of an internet header, naked of options. We declare ip_len and ip_off to be short,
    rather than u_short pragmatically since otherwise unsigned comparisons can result against
    negative integers quite easily, and fail in subtle ways.
    
    \note Defined for the sake of consistency.
*/
struct L3::iphdr {

	/*!
	    \typedef	struct u_char_pack ip_v_hl_pack
	
	    \brief
	    Defines an alias representing the two 4-bit pack of version and header length, according
	    to windows byte order (BIG_ENDIAN).
	*/
	typedef struct u_char_pack ip_v_hl_pack;

	/*!
	    \enum	IPTOS_
	
	    \brief	Flags for ip_tos.
	*/
	enum IPTOS_ 
	{
		IPTOS_LOWDELAY = 0x10,				/*!< The ip_tos lowdelay option */
		IPTOS_THROUGHPUT = 0x08,			/*!< The ip_tos throughput option */
		IPTOS_RELIABILITY = 0x04,			/*!< The ip_tos reliability option */
		IPTOS_PREC_NETCONTROL = 0xe0,		/*!< The ip_tos prec netcontrol option (hopefully unused) */
		IPTOS_PREC_INTERNETCONTROL = 0xc0,  /*!< The ip_tos prec internetcontrol option (hopefully unused) */
		IPTOS_PREC_CRITIC_ECP = 0xa0,		/*!< The ip_tos prec critic ecp option (hopefully unused) */
		IPTOS_PREC_FLASHOVERRIDE = 0x80,	/*!< The ip_tos prec flashoverride option (hopefully unused) */
		IPTOS_PREC_FLASH = 0x60,			/*!< The ip_tos prec flash option (hopefully unused) */
		IPTOS_PREC_IMMEDIATE = 0x40,		/*!< The ip_tos prec immediate option (hopefully unused) */
		IPTOS_PREC_PRIORITY = 0x20,			/*!< The ip_tos prec priority option (hopefully unused) */
		IPTOS_PREC_ROUTINE = 0x00			/*!< The ip_tos prec routine option (hopefully unused) */
	};

	/*!
	    \enum	IP_
	
	    \brief	Flags for ip_off.
	*/
	enum IP_ 
	{
		IP_DF = 0x4000,			/*!< don't fragment flag */
		IP_MF = 0x2000,			/*!< more fragments flag */
		IP_OFFMASK = 0x1fff		/*!< mask for fragmenting bits */
	};

	iphdr() 
		: ip_v_hl(ip_v_hl_pack(0, 0)), ip_tos(0), ip_len(0), ip_id(0), ip_off(0),
		ip_ttl(0), ip_p(0), ip_sum(0), ip_src(struct in_addr()),
		ip_dst(struct in_addr()) { }

	/*!
	    \fn	friend std::ostream& operator<<(std::ostream &output, const iphdr &ip);
	
	    \brief	Stream insertion operator.
	
	    \param [in,out]	output	The output stream (usually std::cout).
	    \param	ip			  	The iphdr to printout.
	
	    \return	The output stream, when #ip was inserted and printed.
	*/
	friend std::ostream& operator<<(std::ostream &out, const iphdr &ip);

	/*!
	    \fn	inline const u_char ip_v() const;
	
	    \brief	As the ip version is kept in a #ip_v_hl_pack, this function gets it from there.
	
	    \return	The IP version (always 4).
	*/
	inline	const u_char ip_v() const;

	/*!
	    \fn	inline const u_char ip_hl() const;
	
	    \brief	As the ip header length is kept in a #ip_v_hl_pack,this function gets it from there.
	
	    \return
	    The IP header length, in 4-bytes unit (usually 5).
	    
	    \warning	We need to make sure to multiply by 4 in order to get the size in bytes:
	    
	    \code ip_hl() &lt;&lt; 2 \endcode.
	*/
	inline	const u_char ip_hl() const;

	/*!
	    \fn	inline void ip_v(const u_char& ip_v);
	
	    \brief	As the ip version is kept in a #ip_v_hl_pack, this function sets it.
	
	    \param	ip_v	the IP version (always 4).
	*/
	inline	void ip_v(const u_char& ip_v);

	/*!
	    \fn	inline void ip_hl(const u_char& ip_hl);
	
	    \brief	As the ip header length is kept in a #ip_v_hl_pack,this function sets it.
	
	    \param	ip_hl
	    The IP header length, in 4-bytes unit.
	    
	    \warning	We need to make sure to derive by 4 in order to get the size in bytes:
	    
	    \code ip_hl() >> 2 \endcode.
	*/
	inline	void ip_hl(const u_char& ip_hl);

	ip_v_hl_pack ip_v_hl;		/*!< version then header length, in a ip_v_hl_pack. \note The IP header length is in 4-bytes unit */
	u_char	ip_tos;				/*!< type of service \see IPTOS_ */
	short	ip_len;				/*!< total length, including data */
	u_short	ip_id;				/*!< identification */
	short	ip_off;				/*!< fragment offset field \see IP_ */
	u_char	ip_ttl;				/*!< time to live */
	u_char	ip_p;				/*!< protocol */
	u_short	ip_sum;				/*!< checksum */
	struct	in_addr ip_src;		/*!< source and */
	struct	in_addr ip_dst;		/*!< dest address */
};

/*!
    \struct	L3::route

    \brief
    Structure of a route.
    
    A route consists of a destination address and a reference to a routing entry. These are often
    held by protocols in their control blocks, e.g. \ref inpcb.
    
    \note This struct is defined for both consistencies and support routing in the future.
*/
struct L3::route {

	/*!
	    \fn	route(inet_os *inet);
	
	    \brief	Constructor.
	
	    \param [in,out]	inet	If non-null, the inet.
	*/
	route(inet_os *inet);

	/*!
	    \fn	void rtalloc(inet_os *inet);
	
	    \brief	Partial constructor for #ro_rt.
	
	    \param [in,out]	inet	for #ro_rt.
	*/
	void rtalloc(inet_os *inet);

	struct	L3::rtentry *ro_rt; /*!< The route entry for this route */
	struct	sockaddr ro_dst;	/*!< The route destination */
};

/*!
    \struct	L3::rtentry

    \brief
    Structure of the route entry (in the routing table).
    
    We distinguish between routes to hosts and routes to networks, preferring the former if
    available. For each route we infer the interface to use from the gateway address supplied
    when the route was entered. Routes that forward packets through gateways are marked so that
    the output routines know to address the gateway rather than the ultimate destination.
    
    \note This struct is defined for both consistencies and support routing in the future.
*/
struct L3::rtentry {

	/*!
	    \enum	RTF_
	
	    \brief	Flags for #rt_flags.
	*/
	enum RTF_ 
	{
		RTF_UP = 0x1,				/*!< route usable */
		RTF_GATEWAY = 0x2,			/*!< destination is a gateway */
		RTF_HOST = 0x4,				/*!< host entry (net otherwise) */
		RTF_REJECT = 0x8,			/*!< host or net unreachable */
		RTF_DYNAMIC = 0x10,			/*!< created dynamically (by redirect) */
		RTF_MODIFIED = 0x20,		/*!< modified dynamically (by redirect) */
		RTF_DONE = 0x40,			/*!< message confirmed */
		RTF_MASK = 0x80,			/*!< subnet mask present */
		RTF_CLONING = 0x100,		/*!< generate new routes on use */
		RTF_XRESOLVE = 0x200,		/*!< external daemon resolves name */
		RTF_LLINFO = 0x400,			/*!< generated by ARP or ESIS */
		RTF_STATIC = 0x800,			/*!< manually added */
		RTF_BLACKHOLE = 0x1000,		/*!< just discard pkts (during updates) */
		RTF_PROTO2 = 0x4000,		/*!< protocol specific routing flag */
		RTF_PROTO1 = 0x8000			/*!< protocol specific routing flag */
	};

	/*!
	    \enum	RTM_
	
	    \brief	Flags for #rtm_flags.
	*/
	enum RTM_ 
	{
		RTM_VERSION = 3,		/*!< Up the ante and ignore older versions */
		RTM_ADD = 0x1,			/*!< Add Route */
		RTM_DELETE = 0x2,		/*!< Delete Route */
		RTM_CHANGE = 0x3,		/*!< Change Metrics or flags */
		RTM_GET = 0x4,			/*!< Report Metrics */
		RTM_LOSING = 0x5,		/*!< Kernel Suspects Partitioning */
		RTM_REDIRECT = 0x6,		/*!< Told to use different route */
		RTM_MISS = 0x7,			/*!< Lookup failed on this address */
		RTM_LOCK = 0x8,			/*!< fix specified metrics */
		RTM_OLDADD = 0x9,		/*!< caused by SIOCADDRT */
		RTM_OLDDEL = 0xa,		/*!< caused by SIOCDELRT */
		RTM_RESOLVE = 0xb,		/*!< req to resolve dst to LL addr */
		RTM_NEWADDR = 0xc,		/*!< address being added to iface */
		RTM_DELADDR = 0xd,		/*!< address being removed from iface */
		RTM_IFINFO = 0xe,		/*!< iface going up/down etc. */
		RTM_RTTUNIT = 1000000	/*!< units for rtt, rttvar, as units per sec */
	};

	/*!
	    \enum	RTV_
	
	    \brief	Values that represent rtvs.
	*/
	enum RTV_ 
	{
		RTV_MTU = 0x1,			/*!< init or lock _mtu */
		RTV_HOPCOUNT = 0x2,		/*!< init or lock _hopcount */
		RTV_EXPIRE = 0x4,		/*!< init or lock _hopcount */
		RTV_RPIPE = 0x8,		/*!< init or lock _recvpipe */
		RTV_SPIPE = 0x10,		/*!< init or lock _sendpipe */
		RTV_SSTHRESH = 0x20,	/*!< init or lock _ssthresh */
		RTV_RTT = 0x40,			/*!< init or lock _rtt */
		RTV_RTTVAR = 0x80		/*!< init or lock _rttvar */
	};



	/*!
	    \fn	rtentry(struct sockaddr *dst, int report, class inet_os *inet);
	
	    \brief	Constructor.
	
	    \param [in,out]	dst 	If non-null, the destination route.
	    \param	report			Unused flag.
	    \param [in,out]	inet	The inet_os owning the route.
	*/
	rtentry(struct sockaddr *dst, int report, class inet_os *inet);

	/*!
	    \fn	~rtentry();
	
	    \brief	Destructor.
	*/
	~rtentry();

	/*!
	    \fn	void RTFREE();
	
	    \brief	Partial destructor, C-style for this object.
	*/
	void RTFREE();

	/*!
	    \fn	inline sockaddr* rt_key() const
	
	    \brief	Caster for rt_key.
	
	    \return	sockaddr* cast of rt_nodes->rn_key() using reinterpret_cast.
	*/
	inline struct sockaddr* rt_key() const { return reinterpret_cast<struct sockaddr *>(rt_nodes->rn_key()); }

	/*!
	    \fn	inline sockaddr* rt_mask() const
	
	    \brief	Caster for rt_mask.
	
	    \return	sockaddr* cast of rt_nodes->rn_mask() using reinterpret_cast.
	*/
	inline struct sockaddr* rt_mask() const { return reinterpret_cast<struct sockaddr *>(rt_nodes->rn_mask()); }

	/*!
	    \fn	inline u_long rt_expire() const
	
	    \brief	Gets rt_expire.
	
	    \return	rt_rmx.rmx_expire.
	*/
	inline u_long rt_expire() const { return rt_rmx.rmx_expire; }

	struct L3_impl::radix_node rt_nodes[2];		/*!< Radix search tree node layout. Tree glue, and other values */
	struct sockaddr *rt_gateway;				/*!< The route's gateway. */

	short				rt_flags;		/*!< up/down?, host/net */
	short				rt_refcnt;		/*!< # held references */
	u_long				rt_use;			/*!< raw # packets forwarded */
	inet_os				*rt_ifp;		/*!< the answer: interface to use */
	struct	sockaddr	*rt_genmask;	/*!< for generation of cloned routes */
	char				*rt_llinfo;		/*!< pointer to link level info cache */

	/*!
		\note	These numbers are used by reliable protocols for determining retransmission
		behavior and are included in the routing structure.
	*/
	struct	L3_impl::rt_metrics	rt_rmx;		/*!< metrics used by rx'ing protocols */
	struct	rtentry		*rt_gwroute;		/*!< implied entry for gatewayed routes */
};

struct L3::ip_moptions {
	inet_os *imo_multicast_ifp;		/*!< OS for outgoing multi casts */
	u_char	imo_multicast_ttl;		/*!< TTL for outgoing multi casts */
	u_char	imo_multicast_loop;		/*!< 1 => hear sends if a member */
	u_short	imo_num_memberships;	/*!< no. memberships this socket */
	struct	in_multi *imo_membership[L3_impl::IP_MAX_MEMBERSHIPS];  /*!< The imo membership array of size L3_impl::IP_maximum_memberships (20) */



};







#endif /* L3_H_ */