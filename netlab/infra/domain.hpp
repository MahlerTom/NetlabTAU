#ifndef NETLAB_DOMAIN_H
#define NETLAB_DOMAIN_H

#include "protosw.hpp"

/*!
    \class	domain

    \brief	A domain for the inet_os and the protocols.
*/
class domain 
{
public:
	friend class protosw;
	friend class inet_os;

	/*!
	    \fn	const int domain::dom_family() const
	
	    \brief	Gets the #_dom_family.
	
	    \return	The #_dom_family.
	*/
	const int dom_family() const { return _dom_family; }		
	
	class protosw *dom_protosw[protosw::SWPROTO_LEN];			/*!< point to the start and end of an array of protosw structures. */
	class protosw *dom_protoswNPROTOSW[protosw::SWPROTO_LEN];	/*!< point to the start and end of an array of protosw structures. */
	
private:


	/*!
	    \fn
	    domain::domain(const int &dom_family, const char *dom_name, class protosw *dom_protosw[protosw::SWPROTO_LEN], class protosw *dom_protoswNPROTOSW[protosw::SWPROTO_LEN], const int &dom_rtoffset, const int &dom_maxrtkey)
	
	    \brief	Constructor, can only be called by inet_os or protosw.
	
	    \param	dom_family				   	The domain family AF_xxx.
	    \param	dom_name				   	Name of the domain.
	    \param [in,out]	dom_protosw		   	If non-null, the domain protosw.
	    \param [in,out]	dom_protoswNPROTOSW	If non-null, the domain protosw nprotosw.
	    \param	dom_rtoffset			   	The domain rtoffset (Unused).
	    \param	dom_maxrtkey			   	The domain maxrtkey (Unused).
	*/
	domain::domain(const int &dom_family, const char *dom_name, class protosw *dom_protosw[protosw::SWPROTO_LEN],
	class protosw *dom_protoswNPROTOSW[protosw::SWPROTO_LEN], const int &dom_rtoffset, const int &dom_maxrtkey)
		: _dom_family(dom_family), dom_name(dom_name), dom_rtoffset(dom_rtoffset), dom_maxrtkey(dom_maxrtkey), dom_next(nullptr)
	{
		for (size_t i = 0; i < protosw::SWPROTO_LEN; i++) {
			this->dom_protosw[i] = dom_protosw[i];
			this->dom_protoswNPROTOSW[i] = dom_protoswNPROTOSW[i];
		}
	}

	/*!
	    \fn	domain::~domain()
	
	    \brief	Destructor.
	*/
	~domain() 
	{ 
		const class domain *dp(nullptr);
		for (dp = this; dp; dp = dp->dom_next)
			for (class protosw **pr = reinterpret_cast<class protosw **>(const_cast<class domain *>(dp)->dom_protosw); pr < dp->dom_protoswNPROTOSW; pr++)
				if (*pr)
					delete *pr;
	};
	
	int	_dom_family;		/*!< AF_xxx */
	std::string dom_name;	/*!< Name of the domain. */
	const class domain *dom_next;  /*!< (DISABELED) points to the next domain in a linked list of domains supported by the kernel. */
	int	dom_rtoffset;	/*!< (DISABELED) an arg to rtattach, in bits */
	int	dom_maxrtkey;	/*!< (DISABELED) for routing layer */
};

#endif /* NETLAB_DOMAIN_H */