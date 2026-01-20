
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/pseudo_fs.h>
#include <linux/list.h>
#include <linux/slab.h>

static DEFINE_MUTEX(vtfs_lock);
#define MODULE_NAME "vtfs"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

#define VTFS_MAX_FILE_SIZE (PAGE_SIZE * 4)

static int vtfs_mkdir(
    struct mnt_idmap *idmap,
    struct inode *parent_inode,
    struct dentry *child_dentry,
    umode_t mode
);

static void vtfs_evict_inode(struct inode *inode);

struct vtfs_inode_info {
    char *data;
    size_t size;
    size_t capacity;
};


static int vtfs_rmdir(
    struct inode *parent_inode,
    struct dentry *child_dentry
);

struct vtfs_node {
    char name[NAME_MAX];
    struct inode *inode;
    bool is_dir;
    struct list_head list;
};



static int vtfs_mkdir(
    struct mnt_idmap *idmap,
    struct inode *parent_inode,
    struct dentry *child_dentry,
    umode_t mode
);

static int vtfs_link(
    struct dentry *old_dentry,
    struct inode *parent_inode,
    struct dentry *new_dentry
);


static int vtfs_drop_inode(struct inode *inode);

static LIST_HEAD(vtfs_files);

static ssize_t vtfs_read(
    struct file *file,
    char __user *buf,
    size_t len,
    loff_t *ppos
) {
    struct inode *inode = file_inode(file);
    struct vtfs_inode_info *info = inode->i_private;
    size_t to_read;

    if (!info)
        return -EIO;

    mutex_lock(&vtfs_lock);

    if (*ppos >= info->size) {
        mutex_unlock(&vtfs_lock);
        return 0;
    }

    to_read = min(len, info->size - *ppos);

    if (copy_to_user(buf, info->data + *ppos, to_read)) {
        mutex_unlock(&vtfs_lock);
        return -EFAULT;
    }

    *ppos += to_read;
    mutex_unlock(&vtfs_lock);
    return to_read;
}

static ssize_t vtfs_write(
    struct file *file,
    const char __user *buf,
    size_t len,
    loff_t *ppos
) {
    struct inode *inode = file_inode(file);
    struct vtfs_inode_info *info = inode->i_private;
    size_t to_write;

    if (!info)
        return -EIO;

    mutex_lock(&vtfs_lock);

    if (*ppos >= info->capacity) {
        mutex_unlock(&vtfs_lock);
        return -ENOSPC;
    }

    to_write = min(len, info->capacity - *ppos);

    if (copy_from_user(info->data + *ppos, buf, to_write)) {
        mutex_unlock(&vtfs_lock);
        return -EFAULT;
    }

    *ppos += to_write;
    info->size = max(info->size, (size_t)*ppos);
    inode->i_size = info->size;

    mutex_unlock(&vtfs_lock);
    return to_write;
}

static const struct file_operations vtfs_file_fops = {
    .read  = vtfs_read,
    .write = vtfs_write,
};

static int vtfs_iterate(
    struct file *file,
    struct dir_context *ctx
);

static int vtfs_iterate(
    struct file *file,
    struct dir_context *ctx
) {
    struct vtfs_node *node;
    loff_t index = 0;

    /* . и .. */
    if (ctx->pos == 0) {
        if (!dir_emit_dots(file, ctx))
            return 0;
        ctx->pos = 2;
    }

    mutex_lock(&vtfs_lock);

    list_for_each_entry(node, &vtfs_files, list) {

        /* пропускаем уже выданные элементы */
        if (index++ < ctx->pos - 2)
            continue;

        if (!dir_emit(
                ctx,
                node->name,
                strlen(node->name),
                node->inode->i_ino,
                node->is_dir ? DT_DIR : DT_REG
            )) {
            mutex_unlock(&vtfs_lock);
            return 0;
        }

        ctx->pos++;
    }

    mutex_unlock(&vtfs_lock);
    return 0;
}




static struct inode* vtfs_get_inode(
    struct super_block* sb,
    const struct inode* dir,
    umode_t mode,
    int i_ino
);

static struct file_operations vtfs_dir_fops = {
    .iterate_shared = vtfs_iterate,
};

static int vtfs_fill_super(struct super_block *sb, void *data, int silent);

static struct dentry* vtfs_lookup(
    struct inode* parent_inode,
    struct dentry* child_dentry,
    unsigned int flags
);

static struct dentry* vtfs_mount(
    struct file_system_type *fs_type,
    int flags,
    const char *token,
    void *data
) {
    struct dentry *ret;

    ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
    if (!ret) {
        LOG("Can't mount file system\n");
        return ERR_PTR(-ENOMEM);
    }

    LOG("Mounted successfully\n");
    return ret;
}


static void vtfs_kill_sb(struct super_block *sb) {
    kill_litter_super(sb);
    LOG("VTFS super block destroyed\n");
}

static struct file_system_type vtfs_fs_type = {
    .owner   = THIS_MODULE,
    .name    = "vtfs",
    .mount   = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};


static int vtfs_create(
    struct mnt_idmap *idmap,
    struct inode *parent_inode,
    struct dentry *child_dentry,
    umode_t mode,
    bool excl
);

static int vtfs_unlink(
    struct inode *parent_inode,
    struct dentry *child_dentry
);

static struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir  = vtfs_mkdir,  
    .rmdir  = vtfs_rmdir,
     .link   = vtfs_link,   
};


static const struct super_operations vtfs_super_ops = {
    .statfs      = simple_statfs,
    .drop_inode  = vtfs_drop_inode,
    .evict_inode = vtfs_evict_inode,
};


static struct inode* vtfs_get_inode(
    struct super_block* sb,
    const struct inode* dir,
    umode_t mode,
    int i_ino
);



static int vtfs_create(
    struct mnt_idmap *idmap,
    struct inode *parent_inode,
    struct dentry *child_dentry,
    umode_t mode,
    bool excl
) {
    struct inode *inode;
    struct vtfs_node *node;
    struct vtfs_inode_info *info;

    inode = vtfs_get_inode(
        parent_inode->i_sb,
        parent_inode,
        S_IFREG | mode,
        get_next_ino()
    );
    if (!inode)
        return -ENOMEM;

    info = kzalloc(sizeof(*info), GFP_KERNEL);
    if (!info) {
        iput(inode);
        return -ENOMEM;
    }

    info->capacity = VTFS_MAX_FILE_SIZE;
    info->size = 0;
    info->data = kzalloc(info->capacity, GFP_KERNEL);
    if (!info->data) {
        kfree(info);
        iput(inode);
        return -ENOMEM;
    }

    inode->i_private = info;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) {
        kfree(info->data);
        kfree(info);
        iput(inode);
        return -ENOMEM;
    }

    node->inode = inode;
    node->is_dir = false;
    strscpy(node->name, child_dentry->d_name.name, NAME_MAX);

    mutex_lock(&vtfs_lock);
    list_add(&node->list, &vtfs_files);
    mutex_unlock(&vtfs_lock);

    d_add(child_dentry, inode);
    return 0;
}


static int vtfs_link(
    struct dentry *old_dentry,
    struct inode *parent_inode,
    struct dentry *new_dentry
) {
    struct inode *inode = d_inode(old_dentry);
    struct vtfs_node *node;

    if (S_ISDIR(inode->i_mode))
        return -EPERM;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;

    node->inode = inode;
    node->is_dir = false;
    strscpy(node->name, new_dentry->d_name.name, NAME_MAX);

    inode_inc_link_count(inode);

    mutex_lock(&vtfs_lock);
    list_add(&node->list, &vtfs_files);
    mutex_unlock(&vtfs_lock);

    d_add(new_dentry, inode);
    return 0;
}

static int vtfs_unlink(
    struct inode *parent_inode,
    struct dentry *child_dentry
) {
    struct vtfs_node *node, *tmp;
    struct inode *inode = d_inode(child_dentry);

    mutex_lock(&vtfs_lock);

    list_for_each_entry_safe(node, tmp, &vtfs_files, list) {
        if (strcmp(node->name, child_dentry->d_name.name) == 0) {
            list_del(&node->list);
            kfree(node);

            inode_dec_link_count(inode);


            mutex_unlock(&vtfs_lock);
            return 0;
        }
    }

    mutex_unlock(&vtfs_lock);
    return -ENOENT;
}

static int vtfs_drop_inode(struct inode *inode)
{
    /*
     * НЕ удаляем inode, пока он есть в нашем списке vtfs_files
     */
    if (inode->i_nlink > 0)
        return 0;

    return generic_drop_inode(inode);
}








static struct inode* vtfs_get_inode(
    struct super_block* sb,
    const struct inode* dir,
    umode_t mode,
    int i_ino
) {
    struct inode *inode = new_inode(sb);
    if (!inode)
        return NULL;

    inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
    inode->i_ino = i_ino;

if (S_ISDIR(mode)) {
    inode->i_op  = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_fops;
} else if (S_ISREG(mode)) {
    inode->i_op  = &vtfs_inode_ops;
    inode->i_fop = &vtfs_file_fops;
}


    return inode;
}

static void vtfs_evict_inode(struct inode *inode)
{
    struct vtfs_inode_info *info = inode->i_private;

    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);

    if (info) {
        kfree(info->data);
        kfree(info);
    }
}


static int vtfs_fill_super(
    struct super_block *sb,
    void *data,
    int silent
) {
    struct inode *inode;

    sb->s_magic = 0x20240518;               // любое уникальное число
    sb->s_op = &vtfs_super_ops;  //  КЛЮЧЕВАЯ СТРОКА

    inode = vtfs_get_inode(sb, NULL, S_IFDIR | S_IRWXUGO, 100);
    if (!inode)
        return -ENOMEM;

    sb->s_root = d_make_root(inode);
    if (!sb->s_root)
        return -ENOMEM;

    return 0;
}


static struct dentry* vtfs_lookup(
    struct inode *parent_inode,
    struct dentry *child_dentry,
    unsigned int flags
) {
    struct vtfs_node *node;

    mutex_lock(&vtfs_lock);

    list_for_each_entry(node, &vtfs_files, list) {
        if (strcmp(node->name, child_dentry->d_name.name) == 0) {
            d_add(child_dentry, node->inode);
            mutex_unlock(&vtfs_lock);
            return NULL;
        }
    }

    mutex_unlock(&vtfs_lock);
    return NULL;
}

static int vtfs_mkdir(
    struct mnt_idmap *idmap,
    struct inode *parent_inode,
    struct dentry *child_dentry,
    umode_t mode
) {
    struct vtfs_node *node;
    struct inode *inode;

    if (parent_inode->i_ino != 100)
        return -EPERM;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;

    inode = vtfs_get_inode(
        parent_inode->i_sb,
        parent_inode,
        S_IFDIR | mode,
        get_next_ino()
    );

    if (!inode) {
        kfree(node);
        return -ENOMEM;
    }

    node->inode = inode;
    node->is_dir = true;
    strscpy(node->name, child_dentry->d_name.name, NAME_MAX);

    mutex_lock(&vtfs_lock);
    list_add(&node->list, &vtfs_files);
    mutex_unlock(&vtfs_lock);

    d_add(child_dentry, inode);

    LOG("directory created: %s\n", node->name);
    return 0;
}

static int vtfs_rmdir(
    struct inode *parent_inode,
    struct dentry *child_dentry
) {
    struct vtfs_node *node, *tmp;

    mutex_lock(&vtfs_lock);

    list_for_each_entry_safe(node, tmp, &vtfs_files, list) {
        if (strcmp(node->name, child_dentry->d_name.name) == 0 &&
            node->is_dir) {

            list_del(&node->list);
            mutex_unlock(&vtfs_lock);

            kfree(node);
            LOG("directory removed: %s\n", child_dentry->d_name.name);
            return 0;
        }
    }

    mutex_unlock(&vtfs_lock);
    return -ENOENT;
}

static int __init vtfs_init(void)
{
    int ret;

    ret = register_filesystem(&vtfs_fs_type);
    if (ret) {
        LOG("Failed to register filesystem: %d\n", ret);
        return ret;
    }

    LOG("VTFS joined the kernel\n");
    return 0;
}

static void __exit vtfs_exit(void) {
  unregister_filesystem(&vtfs_fs_type);

  LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);
