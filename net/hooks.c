/* Copyright (c) 2002 Olaf Dietsche
 *
 * Networking hooks. Currently for IPv4 and IPv6 only.
 */

#include <linux/module.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>

int default_ip_prot_sock(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *) uaddr;
	unsigned short snum = ntohs(addr->sin_port);
	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;

	return 0;
}

int default_ip6_prot_sock(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) uaddr;
	unsigned short snum = ntohs(addr->sin6_port);
	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;

	return 0;
}

EXPORT_SYMBOL(default_ip_prot_sock);
EXPORT_SYMBOL(default_ip6_prot_sock);

#ifdef CONFIG_NET_HOOKS
static struct net_hook_operations default_net_ops = {
	.ip_prot_sock =	default_ip_prot_sock,
	.ip6_prot_sock =	default_ip6_prot_sock,
};

struct net_hook_operations *net_ops = &default_net_ops;

void net_hooks_register(struct net_hook_operations *ops)
{
	net_ops = ops;
}

void net_hooks_unregister(struct net_hook_operations *ops)
{
	net_ops = &default_net_ops;
}

EXPORT_SYMBOL(net_ops);
EXPORT_SYMBOL(net_hooks_register);
EXPORT_SYMBOL(net_hooks_unregister);
#endif
