/* Copyright (c) 2002-2006 Olaf Dietsche
 *
 * User permission based port access for Linux.
 */

#include <linux/accessfs_fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/sock.h>

#ifndef CONFIG_ACCESSFS_IGNORE_NET_BIND_SERVICE
#define CONFIG_ACCESSFS_IGNORE_NET_BIND_SERVICE 0
#endif

static int max_prot_sock = CONFIG_ACCESSFS_PROT_SOCK;
static int ignore_net_bind_service = CONFIG_ACCESSFS_IGNORE_NET_BIND_SERVICE;
static struct access_attr *bind_to_port;

static int accessfs_ip_prot_sock(struct socket *sock,
				 struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *) uaddr;
	unsigned short snum = ntohs(addr->sin_port);
	if (snum && snum < max_prot_sock
	    && !accessfs_permitted(&bind_to_port[snum], MAY_EXEC)
	    && (ignore_net_bind_service || !capable(CAP_NET_BIND_SERVICE)))
		return -EACCES;

	return 0;
}

static int accessfs_ip6_prot_sock(struct socket *sock,
				  struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) uaddr;
	unsigned short snum = ntohs(addr->sin6_port);
	if (snum && snum < max_prot_sock
	    && !accessfs_permitted(&bind_to_port[snum], MAY_EXEC)
	    && (ignore_net_bind_service || !capable(CAP_NET_BIND_SERVICE)))
		return -EACCES;

	return 0;
}

static struct net_hook_operations ip_net_ops = {
	.ip_prot_sock =	accessfs_ip_prot_sock,
	.ip6_prot_sock =	accessfs_ip6_prot_sock,
};

static int __init init_ip(void)
{
	struct accessfs_direntry *dir = accessfs_make_dirpath("net/ip/bind");
	int i;

	if (max_prot_sock < PROT_SOCK)
		max_prot_sock = PROT_SOCK;
	else if (max_prot_sock > 65536)
		max_prot_sock = 65536;

	bind_to_port = kmalloc(max_prot_sock * sizeof(*bind_to_port),
			       GFP_KERNEL);
	if (bind_to_port == NULL)
		return -ENOMEM;

	for (i = 1; i < max_prot_sock; ++i) {
		char	buf[sizeof("65536")];
		bind_to_port[i].uid = 0;
		bind_to_port[i].gid = 0;
		bind_to_port[i].mode = i < PROT_SOCK ? S_IXUSR : S_IXUGO;
		sprintf(buf, "%d", i);
		accessfs_register(dir, buf, &bind_to_port[i]);
	}

	net_hooks_register(&ip_net_ops);
	return 0;
}

static void __exit exit_ip(void)
{
	struct accessfs_direntry *dir = accessfs_make_dirpath("net/ip/bind");
	int i;
	net_hooks_unregister(&ip_net_ops);
	for (i = 1; i < max_prot_sock; ++i) {
		char	buf[sizeof("65536")];
		sprintf(buf, "%d", i);
		accessfs_unregister(dir, buf);
	}

	if (bind_to_port != NULL)
		kfree(bind_to_port);
}

module_init(init_ip)
module_exit(exit_ip)

MODULE_AUTHOR("Olaf Dietsche");
MODULE_DESCRIPTION("User based IP ports permission");
MODULE_LICENSE("GPL v2");
module_param(max_prot_sock, int, 0);
MODULE_PARM_DESC(max_prot_sock, "Number of protected ports");
module_param(ignore_net_bind_service, bool, 0644);
MODULE_PARM_DESC(ignore_net_bind_service, "Ignore CAP_NET_BIND_SERVICE capability");
