#include "domain.hpp"


const int protosw::dom_family() const { return _pr_domain ? _pr_domain->dom_family() : 0; }