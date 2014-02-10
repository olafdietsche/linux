/* Copyright (c) 2002-2006 Olaf Dietsche
 *
 * User based capabilities for Linux.
 */

#include <linux/accessfs_fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/security.h>

static const char *names[] = {
	"chown",
	"dac_override",
	"dac_read_search",
	"fowner",
	"fsetid",
	"kill",
	"setgid",
	"setuid",
	"setpcap",
	"linux_immutable",
	"net_bind_service",
	"net_broadcast",
	"net_admin",
	"net_raw",
	"ipc_lock",
	"ipc_owner",
	"sys_module",
	"sys_rawio",
	"sys_chroot",
	"sys_ptrace",
	"sys_pacct",
	"sys_admin",
	"sys_boot",
	"sys_nice",
	"sys_resource",
	"sys_time",
	"sys_tty_config",
	"mknod",
	"lease"
};

static struct access_attr caps[ARRAY_SIZE(names)];

static int accessfs_capable(struct task_struct *tsk, int cap)
{
	if (accessfs_permitted(&caps[cap], MAY_EXEC)) {
		/* capability granted */
		tsk->flags |= PF_SUPERPRIV;
		return 0;
	}

	/* capability denied */
	return -EPERM;
}

static struct security_operations accessfs_security_ops = {
	.capable =	accessfs_capable,
};

static void unregister_capabilities(struct accessfs_direntry *dir, int n)
{
	int	i;
	for (i = 0; i < n; ++i)
		accessfs_unregister(dir, names[i]);
}

static int __init init_capabilities(void)
{
	struct accessfs_direntry *dir;
	int i, err;
	dir = accessfs_make_dirpath("capabilities");
	if (dir == 0)
		return -ENOTDIR;

	for (i = 0; i < ARRAY_SIZE(caps); ++i) {
		caps[i].uid = 0;
		caps[i].gid = 0;
		caps[i].mode = S_IXUSR;
		err = accessfs_register(dir, names[i], &caps[i]);
		if (err) {
			unregister_capabilities(dir, i);
			return err;
		}
	}

	err = register_security(&accessfs_security_ops);
	if (err != 0)
		unregister_capabilities(dir, ARRAY_SIZE(names));

	return err;
}

module_init(init_capabilities)

MODULE_AUTHOR("Olaf Dietsche");
MODULE_DESCRIPTION("User based capabilities");
MODULE_LICENSE("GPL");
