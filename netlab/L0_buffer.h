/*!
\file	L3.h

\author	Tom Mahler, contact at tommahler@gmail.com

\brief	Declares the L3 class.
*/
#ifndef L0_buffer_H_
#define L0_buffer_H_

/*!
\def	NETLAB_L3_L0_buffer_DEBUG
Define in order to printout the L3 packets for debug
*/
#define NETLAB_L0_DROP_DEBUG
#define NETLAB_L0_DELAY_DEBUG

#include <random>
#include <chrono>
#include <memory>

#include "NetworkInterface.h"

class NIC_Cable;

class inet_os;

/************************************************************************/
/*                         SOLUTION                                     */
/************************************************************************/

/*!
    \class	L3_L0_buffer_impl

    \brief	Represents a Layer 3 interface (IP).

    \sa	L3_L0_buffer
*/
class L0_buffer 
{
public:
	enum distribution
	{
		no_dist,
		exponential_distribution,
		chi_squared_distribution,
		uniform_real_distribution,
		constant
	};

	enum DIRECTION
	{
		INCOMING,
		OUTGOING,
		BOTH
	};

	/*!
	\fn	L3_impl::L3_impl(class inet_os &inet, const short &pr_type = 0, const short &pr_protocol = 0, const short &pr_flags = 0);

	\brief	Constructor.

	\param [in,out]	inet	The inet.
	\param	pr_type			Type of the protocol type.
	\param	pr_protocol 	The protocol.
	\param	pr_flags		The protocol flags.
	*/
	
	L0_buffer(class inet_os &inet, double reliability, DIRECTION d = INCOMING);

	struct exponential_distribution_args 
	{
		exponential_distribution_args(double lambda = 1.0) : lambda(lambda) { }
		double lambda; 
	};
	L0_buffer(class inet_os &inet, double reliability, const exponential_distribution_args &args, DIRECTION d = INCOMING);
	
	struct uniform_real_distribution_args 
	{ 
		uniform_real_distribution_args(double a = 0, double b = 0) : a(a), b(b) { }
		double a;
		double b;
	};
	L0_buffer(class inet_os &inet, double reliability, const uniform_real_distribution_args &args, DIRECTION d = INCOMING);
	
	struct chi_squared_distribution_args 
	{ 
		chi_squared_distribution_args(double n = 1.0) : n(n) { }
		double n; 
	};
	L0_buffer(class inet_os &inet, double reliability, const chi_squared_distribution_args &args, DIRECTION d = INCOMING);

	struct constant_args
	{
		constant_args(double c = 1.0) : c(c) { }
		double c;
	};
	L0_buffer(class inet_os &inet, double reliability, const constant_args &args, DIRECTION d = INCOMING);

	~L0_buffer();

	void set_reliability(double new_reliability) { reliability = new_reliability; }

	void set_exponential_distribution(double lambda = 1.0)
	{ 
		exp_delay = std::exponential_distribution<>(lambda); 
		dist_delay = exponential_distribution;
	}

	void set_chi_squared_distribution(double n = 1.0)
	{
		chi_squared_delay = std::chi_squared_distribution<>(n);
		dist_delay = chi_squared_distribution;
	}

	void set_uniform_real_distribution(double a = 0, double b = 0)
	{
		uniform_real_delay = std::uniform_real_distribution<>(a, b);
		dist_delay = uniform_real_distribution;
	}


private:
	friend class NIC_Cable;
	typedef std::chrono::duration<double> seconds;
	typedef std::chrono::nanoseconds nanoseconds;
	typedef std::random_device generator;
	//typedef std::minstd_rand generator;

	L0_buffer(class inet_os &inet, double reliability, distribution dist_delay, DIRECTION d);

	virtual	void send_l2_helper(const std::shared_ptr<std::vector<byte>> &m, const std::vector<byte>::iterator &it, const class netlab::NetworkInterface &iface);

	virtual void leread(class std::shared_ptr<std::vector<byte>> &m, std::vector<byte>::iterator &it);

	void process();
	std::exponential_distribution<> exp_delay;
	std::chi_squared_distribution<> chi_squared_delay;
	std::uniform_real_distribution<> uniform_real_delay;
	double const_delay;
	distribution dist_delay;

	generator gen;

	std::uniform_real_distribution<> uniform_real_reli;
	double reliability;

	NIC_Cable &cable;

	DIRECTION d;
};








#endif /* L0_buffer_H_ */