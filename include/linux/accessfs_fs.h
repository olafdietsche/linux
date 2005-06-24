/* -*- mode: c -*- */
#ifndef __accessfs_fs_h_included__
#define __accessfs_fs_h_included__	1

/* Copyright (c) 2001 Olaf Dietsche
 *
 * Access permission filesystem for Linux.
 */

#include <linux/config.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <net/sock.h>

struct access_attr {
	uid_t	uid;
	gid_t	gid;
	mode_t	mode;
};

struct accessfs_entry {
	char	*name;
	struct list_head	hash;
	struct list_head	siblings;
	ino_t	ino;
	struct access_attr	*attr;
};

struct accessfs_direntry {
	struct accessfs_entry	node;
	struct accessfs_direntry	*parent;
	struct list_head	children;
	struct access_attr	attr;
};

extern int accessfs_permitted(struct access_attr *p, int mask);
extern struct accessfs_direntry *accessfs_make_dirpath(const char *name);
extern int accessfs_register(struct accessfs_direntry *dir, const char *name, struct access_attr *attr);
extern void accessfs_unregister(struct accessfs_direntry *dir, const char *name);

#if  CONFIG_ACCESSFS_PROT_SOCK < PROT_SOCK
#define CONFIG_ACCESSFS_PROT_SOCK	PROT_SOCK
#elseif CONFIG_ACCESSFS_PROT_SOCK > 65536
#define CONFIG_ACCESSFS_PROT_SOCK	65536
#endif

#endif
