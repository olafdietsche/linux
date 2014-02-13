/* Copyright (c) 2001-2006 Olaf Dietsche
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
#include <asm/uaccess.h>

#define ACCESSFS_MAGIC	0x3c1d36e7

static struct proc_dir_entry *mountdir = NULL;

static DEFINE_MUTEX(accessfs_sem);

static struct inode_operations accessfs_inode_operations;
static struct file_operations accessfs_dir_file_operations;
static struct inode_operations accessfs_dir_inode_operations;

static inline void accessfs_readdir_aux(struct file *filp,
					struct accessfs_direntry *dir,
					int start, struct dir_context *ctx)
{
	struct list_head *list;
	int i = 2;
	list_for_each(list, &dir->children) {
		struct accessfs_entry *de;
		if (i++ < start)
			continue;

		de = list_entry(list, struct accessfs_entry, siblings);
		if (!dir_emit(ctx, de->name, strlen(de->name), de->ino, DT_UNKNOWN))
			break;

		++ctx->pos;
	}
}

static int accessfs_readdir(struct file *filp, struct dir_context *ctx)
{
	int i;
	struct dentry *dentry = filp->f_dentry;
	struct accessfs_direntry *dir;

	i = ctx->pos;
	switch (i) {
	case 0:
		if (!dir_emit_dot(filp, ctx))
			break;

		++i;
		++ctx->pos;
		/* NO break; */
	case 1:
		if (!dir_emit_dotdot(filp, ctx))
			break;

		++i;
		++ctx->pos;
		/* NO break; */
	default:
		mutex_lock(&accessfs_sem);
		dir = dentry->d_inode->i_private;
		accessfs_readdir_aux(filp, dir, i, ctx);
		mutex_unlock(&accessfs_sem);
		break;
	}

	return 0;
}

static struct accessfs_entry *accessfs_lookup_entry(struct accessfs_entry *pe,
						    const char *name, int len)
{
	struct list_head *list;
	struct accessfs_direntry *dir;
	if (!S_ISDIR(pe->attr->mode))
		return NULL;

	dir = (struct accessfs_direntry *) pe;
	list_for_each(list, &dir->children) {
		struct accessfs_entry *de = list_entry(list, struct accessfs_entry, siblings);
		if (strncmp(de->name, name, len) == 0 && de->name[len] == 0)
			return de;
	}

	return NULL;
}

static struct accessfs_direntry	accessfs_rootdir = {
	{ "/", 
	  LIST_HEAD_INIT(accessfs_rootdir.node.hash), 
	  LIST_HEAD_INIT(accessfs_rootdir.node.siblings), 
	  1, &accessfs_rootdir.attr },
	NULL, LIST_HEAD_INIT(accessfs_rootdir.children), 
	{ GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, S_IFDIR | 0755 }
};

static void accessfs_init_inode(struct inode *inode, struct accessfs_entry *pe)
{
	static const struct timespec epoch = {0, 0};
	inode->i_private = pe;
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
		mutex_lock(&accessfs_sem);
/* 		inode->i_ino = accessfs_rootdir.node.ino; */
		accessfs_init_inode(inode, &accessfs_rootdir.node);
		accessfs_rootdir.node.ino = inode->i_ino;
		mutex_unlock(&accessfs_sem);
	}

	return inode;
}

static LIST_HEAD(hash);

static int accessfs_node_init(struct accessfs_direntry *parent,
			      struct accessfs_entry *de, const char *name,
			      size_t len, struct access_attr *attr, mode_t mode)
{
	static unsigned long ino = 1;
	de->name = kmalloc(len + 1, GFP_KERNEL);
	if (de->name == NULL)
		return -ENOMEM;

	strncpy(de->name, name, len);
	de->name[len] = 0;
	de->ino = ++ino;
	de->attr = attr;
	de->attr->uid = GLOBAL_ROOT_UID;
	de->attr->gid = GLOBAL_ROOT_GID;
	de->attr->mode = mode;

	list_add_tail(&de->hash, &hash);
	list_add_tail(&de->siblings, &parent->children);
	return 0;
}

static int accessfs_mknod(struct accessfs_direntry *dir, const char *name,
			  struct access_attr *attr)
{
	struct accessfs_entry *pe;
	pe = kmalloc(sizeof(struct accessfs_entry), GFP_KERNEL);
	if (pe == NULL)
		return -ENOMEM;

	accessfs_node_init(dir, pe, name, strlen(name), attr,
			   S_IFREG | attr->mode);
	return 0;
}

static struct accessfs_direntry	*accessfs_mkdir(struct accessfs_direntry *parent,
						const char *name, size_t len)
{
	int err;
	struct accessfs_direntry *dir;
	dir = kmalloc(sizeof(struct accessfs_direntry), GFP_KERNEL);
	if (dir == NULL)
		return NULL;

	dir->parent = parent;
	INIT_LIST_HEAD(&dir->children);
	err = accessfs_node_init(parent, &dir->node, name, len, &dir->attr,
				 S_IFDIR | 0755);
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
	mutex_lock(&accessfs_sem);
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

	mutex_unlock(&accessfs_sem);
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
	struct accessfs_entry *pe;
	struct inode *i = dentry->d_inode;
	int err;
	err = inode_change_ok(i, iattr);
	if (err)
		return err;

	setattr_copy(i, iattr);

	pe = (struct accessfs_entry *) i->i_private;
	pe->attr->uid = i->i_uid;
	pe->attr->gid = i->i_gid;
	pe->attr->mode = i->i_mode;
	return 0;
}

static struct inode *accessfs_iget(struct super_block *sb, unsigned long ino)
{
	struct list_head *list;
	struct inode *inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	
	if (!(inode->i_state & I_NEW))
		return inode;
	
	mutex_lock(&accessfs_sem);
	list_for_each(list, &hash) {
		struct accessfs_entry *pe;
		pe = list_entry(list, struct accessfs_entry, hash);
		if (pe->ino == ino) {
			accessfs_init_inode(inode, pe);
			break;
		}
	}

	unlock_new_inode(inode);
	mutex_unlock(&accessfs_sem);
	return inode;
}

static struct dentry *accessfs_lookup(struct inode *dir, struct dentry *dentry,
				      unsigned int flags)
{
	struct inode *inode = NULL;
	struct accessfs_entry *pe;
	mutex_lock(&accessfs_sem);
	pe = accessfs_lookup_entry(dir->i_private, dentry->d_name.name,
				   dentry->d_name.len);
	mutex_unlock(&accessfs_sem);
	if (pe)
		inode = accessfs_iget(dir->i_sb, pe->ino);

	d_add(dentry, inode);
	return NULL;
}

static struct inode_operations accessfs_inode_operations = {
	.setattr =	accessfs_notify_change,
};

static struct inode_operations accessfs_dir_inode_operations = {
	.lookup =	accessfs_lookup,
	.setattr =	accessfs_notify_change,
};

static struct file_operations accessfs_dir_file_operations = {
	.iterate =	accessfs_readdir,
};

static struct super_operations accessfs_ops = {
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

	root = d_make_root(inode);
	if (!root)
		return -ENOMEM;

	sb->s_root = root;
	return 0;
}

static struct dentry *accessfs_mount(struct file_system_type *fs_type,
			   int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, accessfs_fill_super);
}

int accessfs_permitted(struct access_attr *p, int mask)
{
	mode_t mode = p->mode;
	if (uid_eq(current_fsuid(), p->uid))
		mode >>= 6;
	else if (in_group_p(p->gid))
		mode >>= 3;

	return (mode & mask) == mask;
}

int accessfs_register(struct accessfs_direntry *dir, const char *name,
		      struct access_attr *attr)
{
	int err;
	if (dir == 0)
		return -EINVAL;

	mutex_lock(&accessfs_sem);
	err = accessfs_mknod(dir, name, attr);
	mutex_unlock(&accessfs_sem);
	return err;
}

void accessfs_unregister(struct accessfs_direntry *dir, const char *name)
{
	struct accessfs_entry *pe;
	mutex_lock(&accessfs_sem);
	pe = accessfs_lookup_entry(&dir->node, name, strlen(name));
	if (pe)
		accessfs_unlink(pe);

	mutex_unlock(&accessfs_sem);
}

static struct file_system_type accessfs_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"accessfs",
	.mount =	accessfs_mount,
	.kill_sb =	kill_anon_super,
};

static int __init init_accessfs_fs(void)
{
	/* create mount point for accessfs */
	mountdir = proc_mkdir("access", NULL);
	return register_filesystem(&accessfs_fs_type);
}

static void __exit exit_accessfs_fs(void)
{
	unregister_filesystem(&accessfs_fs_type);
	remove_proc_entry("access", NULL);
}

module_init(init_accessfs_fs)
module_exit(exit_accessfs_fs)

MODULE_AUTHOR("Olaf Dietsche");
MODULE_DESCRIPTION("Access Filesystem");
MODULE_LICENSE("GPL v2");

EXPORT_SYMBOL(accessfs_permitted);
EXPORT_SYMBOL(accessfs_make_dirpath);
EXPORT_SYMBOL(accessfs_register);
EXPORT_SYMBOL(accessfs_unregister);
