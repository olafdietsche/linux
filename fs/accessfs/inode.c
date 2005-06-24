/* Copyright (c) 2001 Olaf Dietsche
 *
 * Access permission filesystem for Linux.
 *
 * 2002 Ben Clifford, create mount point at /proc/access
 * 2002 Ben Clifford, trying to make it work under 2.5.5-dj2
 *          (see comments: BENC255 for reminders and todos)
 *
 *
 * BENC255: the kernel doesn't lock BKL for us when entering methods 
 *          (see Documentation/fs/porting.txt)
 *          Need to look at code here and see if we need either the BKL
 *          or our own lock - I think probably not.
 *
 */

#include <linux/accessfs_fs.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <asm/statfs.h>
#include <asm/semaphore.h>
#include <asm/uaccess.h>

#define ACCESSFS_MAGIC	0x3c1d36e7

#ifdef CONFIG_PROC_FS           
static struct proc_dir_entry *mountdir = NULL;
#endif

static DECLARE_MUTEX(accessfs_sem);

static struct inode_operations accessfs_inode_operations;
static struct file_operations accessfs_dir_file_operations;
static struct inode_operations accessfs_dir_inode_operations;

static inline void accessfs_readdir_aux(struct file *filp, struct accessfs_direntry *dir, int start, void *dirent, filldir_t filldir)
{
	struct list_head *list;
	int i;

	list = dir->children.next;
	for (i = 2; i < start && list != &dir->children; ++i)
		list = list->next;

	while (list != &dir->children) {
		struct accessfs_entry *de;
		de = list_entry(list, struct accessfs_entry, siblings);
		if (filldir(dirent, de->name, strlen(de->name), filp->f_pos, de->ino, DT_UNKNOWN) < 0)
			break;

		++filp->f_pos;
		list = list->next;
	}
}

static int accessfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	int i;
	struct dentry *dentry = filp->f_dentry;
	struct accessfs_direntry *dir;

	i = filp->f_pos;
	switch (i) {
	case 0:
		if (filldir(dirent, ".", 1, i, dentry->d_inode->i_ino, DT_DIR) < 0)
			break;

		++i;
		++filp->f_pos;
		/* NO break; */
	case 1:
		if (filldir(dirent, "..", 2, i, dentry->d_parent->d_inode->i_ino, DT_DIR) < 0)
			break;

		++i;
		++filp->f_pos;
		/* NO break; */
	default:
		down(&accessfs_sem);
		dir = (struct accessfs_direntry *) dentry->d_inode->u.generic_ip;
		accessfs_readdir_aux(filp, dir, i, dirent, filldir);
		up(&accessfs_sem);
		break;
	}

	return 0;
}

static struct accessfs_entry *accessfs_lookup_entry(struct accessfs_entry *pe, const char *name, int len)
{
	struct list_head *list;
	struct accessfs_direntry *dir;
	struct accessfs_entry *de;
	if (!S_ISDIR(pe->attr->mode))
		return NULL;

	dir = (struct accessfs_direntry *) pe;
	de = NULL;
	list_for_each(list, &dir->children) {
		de = list_entry(list, struct accessfs_entry, siblings);
		if (strncmp(de->name, name, len) == 0 && de->name[len] == 0)
			break;
	}

	return de;
}

static struct dentry *accessfs_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = NULL;
	struct accessfs_entry *pe;
	down(&accessfs_sem);
	pe = accessfs_lookup_entry(dir->u.generic_ip, dentry->d_name.name, dentry->d_name.len);
	up(&accessfs_sem);
	if (pe)
		inode = iget(dir->i_sb, pe->ino);

	d_add(dentry, inode);
	return NULL;
}

static struct accessfs_direntry	accessfs_rootdir = {
	{ "/", 
	  LIST_HEAD_INIT(accessfs_rootdir.node.hash), 
	  LIST_HEAD_INIT(accessfs_rootdir.node.siblings), 
	  1, &accessfs_rootdir.attr },
	NULL, LIST_HEAD_INIT(accessfs_rootdir.children), 
	{ 0, 0, S_IFDIR | 0755 }
};

static void accessfs_init_inode(struct inode *inode, struct accessfs_entry *pe)
{
	static const struct timespec epoch = {0, 0};
	inode->u.generic_ip = pe;
	inode->i_uid = pe->attr->uid;
	inode->i_gid = pe->attr->gid;
	inode->i_mode = pe->attr->mode;
/*
	inode->i_blksize = PAGE_CACHE_SIZE;
	inode->i_blocks = 0;
	inode->i_rdev = NODEV;
*/
	inode->i_atime = inode->i_mtime = inode->i_ctime = epoch;
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &accessfs_inode_operations;
		break;
	case S_IFDIR:
		inode->i_op = &accessfs_dir_inode_operations;
		inode->i_fop = &accessfs_dir_file_operations;
		break;
	default:
		BUG();
		break;
	}
}

static struct inode *accessfs_get_root_inode(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);
	if (inode) {
		down(&accessfs_sem);
/* 		inode->i_ino = accessfs_rootdir.node.ino; */
		accessfs_init_inode(inode, &accessfs_rootdir.node);
		accessfs_rootdir.node.ino = inode->i_ino;
		up(&accessfs_sem);
	}

	return inode;
}

static LIST_HEAD(hash);

static int accessfs_node_init(struct accessfs_direntry *parent, struct accessfs_entry *de, const char *name, size_t len, struct access_attr *attr, mode_t mode)
{
	static unsigned long ino = 1;
	de->name = kmalloc(len + 1, GFP_KERNEL);
	if (de->name == NULL)
		return -ENOMEM;

	strncpy(de->name, name, len);
	de->name[len] = 0;
	de->ino = ++ino;
	de->attr = attr;
	de->attr->uid = 0;
	de->attr->gid = 0;
	de->attr->mode = mode;

	list_add_tail(&de->hash, &hash);
	list_add_tail(&de->siblings, &parent->children);
	return 0;
}

static int accessfs_mknod(struct accessfs_direntry *dir, const char *name, struct access_attr *attr)
{
	struct accessfs_entry *pe;
	pe = kmalloc(sizeof(struct accessfs_entry), GFP_KERNEL);
	if (pe == NULL)
		return -ENOMEM;

	accessfs_node_init(dir, pe, name, strlen(name), attr, S_IFREG | attr->mode);
	return 0;
}

static struct accessfs_direntry	*accessfs_mkdir(struct accessfs_direntry *parent, const char *name, size_t len)
{
	int err;
	struct accessfs_direntry *dir;
	dir = kmalloc(sizeof(struct accessfs_direntry), GFP_KERNEL);
	if (dir == NULL)
		return NULL;

	dir->parent = parent;
	INIT_LIST_HEAD(&dir->children);
	err = accessfs_node_init(parent, &dir->node, name, len, &dir->attr, S_IFDIR | 0755);
	if (err) {
		kfree(dir);
		dir = 0;
	}

	return dir;
}

struct accessfs_direntry *accessfs_make_dirpath(const char *name)
{
	struct accessfs_direntry *dir = &accessfs_rootdir;
	const char *slash;
	down(&accessfs_sem);
	do {
		struct accessfs_entry *de;
		size_t len;
		while (*name == '/')
			++name;

		slash = strchr(name, '/');
		len = slash ? slash - name : strlen(name);
		de = accessfs_lookup_entry(&dir->node, name, len);
		if (de == NULL) {
			dir = accessfs_mkdir(dir, name, len);
		} else if (S_ISDIR(de->attr->mode)) {
			dir = (struct accessfs_direntry *) de;
		} else {
			dir = NULL;
		}

		if (dir == NULL)
			break;

		name = slash  + 1;
	} while (slash != NULL);

	up(&accessfs_sem);
	return dir;
}

static void accessfs_unlink(struct accessfs_entry *pe)
{
	list_del_init(&pe->hash);
	list_del_init(&pe->siblings);
	kfree(pe->name);
	kfree(pe);
}

static int accessfs_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *i = dentry->d_inode;
	int err = inode_setattr(i, iattr);
	if (!err) {
		struct accessfs_entry *pe;
		pe = (struct accessfs_entry *) i->u.generic_ip;
		pe->attr->uid = i->i_uid;
		pe->attr->gid = i->i_gid;
		pe->attr->mode = i->i_mode;
	}

	return err;
}

static void accessfs_read_inode(struct inode *inode)
{
	ino_t	ino = inode->i_ino;
	struct list_head	*list;
	down(&accessfs_sem);
	list_for_each(list, &hash) {
		struct accessfs_entry *pe;
		pe = list_entry(list, struct accessfs_entry, hash);
		if (pe->ino == ino) {
			accessfs_init_inode(inode, pe);
			break;
		}
	}

	up(&accessfs_sem);
}

static struct inode_operations accessfs_inode_operations = {
	.setattr =	accessfs_notify_change,
};

static struct inode_operations accessfs_dir_inode_operations = {
	.lookup =	accessfs_lookup,
	.setattr =	accessfs_notify_change,
};

static struct file_operations accessfs_dir_file_operations = {
	.readdir =	accessfs_readdir,
};

static struct super_operations accessfs_ops = {
	.read_inode =	accessfs_read_inode,
	.statfs =	simple_statfs,
};

static int accessfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct dentry *root;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = ACCESSFS_MAGIC;
	sb->s_op = &accessfs_ops;
	inode = accessfs_get_root_inode(sb);
	if (!inode)
		return -ENOMEM;

	root = d_alloc_root(inode);
	if (!root) {
		iput(inode);
		return -ENOMEM;
	}

	sb->s_root = root;
	return 0;
}

static struct super_block *accessfs_get_sb(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
	return get_sb_single(fs_type, flags, data, accessfs_fill_super);
}

int accessfs_permitted(struct access_attr *p, int mask)
{
	mode_t mode = p->mode;
	if (current->fsuid == p->uid)
		mode >>= 6;
	else if (in_group_p(p->gid))
		mode >>= 3;

	return (mode & mask) == mask;
}

int accessfs_register(struct accessfs_direntry *dir, const char *name, struct access_attr *attr)
{
	int err;
	if (dir == 0)
		return -EINVAL;

	down(&accessfs_sem);
	err = accessfs_mknod(dir, name, attr);
	up(&accessfs_sem);
	return err;
}

void accessfs_unregister(struct accessfs_direntry *dir, const char *name)
{
	struct accessfs_entry *pe;
	down(&accessfs_sem);
	pe = accessfs_lookup_entry(&dir->node, name, strlen(name));
	if (pe) {
		accessfs_unlink(pe);
	}

	up(&accessfs_sem);
}

static struct file_system_type accessfs_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"accessfs",
	.get_sb =	accessfs_get_sb,
	.kill_sb =	kill_anon_super,
};

static int __init init_accessfs_fs(void)
{

#ifdef CONFIG_PROC_FS
	/* create mount point for accessfs */
	mountdir = proc_mkdir("access",&proc_root);
#endif
	return register_filesystem(&accessfs_fs_type);
}

static void __exit exit_accessfs_fs(void)
{
	unregister_filesystem(&accessfs_fs_type);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("access",&proc_root);
#endif
}

module_init(init_accessfs_fs)
module_exit(exit_accessfs_fs)

MODULE_AUTHOR("Olaf Dietsche");
MODULE_DESCRIPTION("Access Filesystem");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(accessfs_permitted);
EXPORT_SYMBOL(accessfs_make_dirpath);
EXPORT_SYMBOL(accessfs_register);
EXPORT_SYMBOL(accessfs_unregister);
