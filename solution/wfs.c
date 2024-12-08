#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wfs.h" // Ensure wfs.h is included for super_block reads

#define MAX_PATH_LEN 10
#define MAX_NAME_LEN 26
#define ROOT_INODE_NUM 0 // Assuming the root inode is 0

#define MAX_DISKS (10)

// Global variables
FILE *logfp;
int num_disks = 0;
void **disk_maps;
struct wfs_sb *sb; // Superblock
size_t disk_size;
int *disk_fds; // Array to hold file descriptors for each disk
uint64_t fs_id = 0;

char *mount_point = NULL;
void *disk;

// Helper functions prototypes
int check_disk(char *disk_path, int index);
int find_free(int is_inode);
void copy_disk(int inode_num, struct wfs_inode *source_inode);
int find_dir_block(struct wfs_inode *dir_inode);
void add_dir_entry(int block_num, const char *filename, int inode_num);
off_t get_block_num(struct wfs_inode *inode, int index);
int set_block_num(struct wfs_inode *inode, int index, off_t block_num);
void write_block(int block_num, const char *data, size_t offset, size_t size);
char *get_block_addr(int block_num);
char *find_majority();
int remove_dentry(struct wfs_inode *dir_inode, const char *filename);
void free_inode_and_blocks(struct wfs_inode *inode, int inode_num);
void clear_bitmap_bit(off_t bitmap_offset, int item_num);
void process_dir_entries(int block_num, void *buf, fuse_fill_dir_t filler);
int cfree_entry_r0(int block_num);
int cfree_entry_r1(int block_num);
void init_new_r0(int new_block);
void init_new_r1(int new_block);

int wfs_getattr(const char *path, struct stat *stbuf);
int wfs_mknod(const char *path, mode_t mode, dev_t dev);
int wfs_mkdir(const char *path, mode_t mode);
int wfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
int wfs_unlink(const char *path);
int wfs_rmdir(const char *path);
int wfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int wfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

int find_inode(const char *path);

int wfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    printf("[FUNCTION] wfs_mknod\n");
    fprintf(logfp, "GOT INTO mknod");
    char *path_copy = strdup(path);
    char *last_slash = strrchr(path_copy, '/');
    *last_slash = '\0';
    char *parent_path = path_copy;
    char *filename = last_slash + 1;

    if (parent_path[0] == '\0')
    {
        parent_path = "/";
    }

    int parent_inum = find_inode(parent_path);
    if (parent_inum < 0)
    {
        free(path_copy);
        return -ENOENT;
    }

    // find new free inode
    int new_inum = find_free(1);
    if (new_inum < 0)
    {
        return -ENOSPC;
    }

    // init new inode
    struct wfs_inode *new_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + (new_inum * BLOCK_SIZE));

    // Set inode properties
    new_inode->num = new_inum;
    new_inode->mode = S_IFREG | mode;
    new_inode->uid = getuid();
    new_inode->gid = getgid();
    new_inode->size = 0;
    new_inode->nlinks = 1;
    new_inode->atim = time(NULL);
    new_inode->mtim = new_inode->atim;
    new_inode->ctim = new_inode->atim;

    for (int i = 0; i < N_BLOCKS; i++)
    {
        new_inode->blocks[i] = -1;
    }

    // Mirror inode to all disks
    copy_disk(new_inum, new_inode);
    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + parent_inum * BLOCK_SIZE);

    // find block for new entry
    int block_num = find_dir_block(parent_inode);
    if (block_num < 0)
    {
        return -ENOSPC;
    }

    add_dir_entry(block_num, filename, new_inum);

    parent_inode->size += sizeof(struct wfs_dentry);
    parent_inode->mtim = time(NULL);
    parent_inode->ctim = parent_inode->mtim;

    // mirror parent inode to all disk
    copy_disk(parent_inum, parent_inode);
    free(path_copy);

    return EXIT_SUCCESS; // Success
}

int wfs_unlink(const char *path)
{
    printf("[FUNCTION] wfs_unlink %s\n", path);
    fprintf(logfp, "UNLINK: Starting for path %s\n", path);
    fflush(logfp);

    char *path_copy = strdup(path);
    char *last_slash = strrchr(path_copy, '/');
    *last_slash = '\0';
    char *parent_path = path_copy;
    char *filename = last_slash + 1;

    if (parent_path[0] == '\0')
    {
        parent_path = "/";
    }

    int parent_inum = find_inode(parent_path);
    fprintf(logfp, "UNLINK: Found parent inode %d\n", parent_inum);
    if (parent_inum < 0)
    {
        free(path_copy);
        return -ENOENT;
    }

    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + parent_inum * BLOCK_SIZE);

    fprintf(logfp, "UNLINK: Attempting to remove entry %s\n", filename);
    int file_inum = remove_dentry(parent_inode, filename);
    fprintf(logfp, "UNLINK: File inode to remove: %d\n", file_inum);

    if (file_inum < 0)
    {
        free(path_copy);
        return -ENOENT;
    }

    struct wfs_inode *file_inode = (struct wfs_inode *)((char *)disk_maps[0] +
                                                        sb->i_blocks_ptr + file_inum * BLOCK_SIZE);

    fprintf(logfp, "UNLINK: About to free blocks for inode %d with size %ld\n",
            file_inum, file_inode->size);
    for (int i = 0; i < N_BLOCKS; i++)
    {
        if (file_inode->blocks[i] != -1)
        {
            fprintf(logfp, "UNLINK: Found block to free: blocks[%d] = %ld\n",
                    i, file_inode->blocks[i]);
            fflush(logfp);
        }
    }

    // Now actually free the blocks
    free_inode_and_blocks(file_inode, file_inum);
    fprintf(logfp, "UNLINK: Blocks freed\n");

    // Update parent directory
    parent_inode->size -= sizeof(struct wfs_dentry);
    parent_inode->mtim = time(NULL);
    parent_inode->ctim = parent_inode->mtim;
    copy_disk(parent_inum, parent_inode);
    fprintf(logfp, "UNLINK: Parent inode updated\n");

    free(path_copy);
    fprintf(logfp, "UNLINK: Complete\n");
    fflush(logfp);

    return EXIT_SUCCESS;
}

int wfs_rmdir(const char *path)
{
    printf("Entering wfs_rmdir %s\n", path);
    fprintf(logfp, "GOT INTO rmdir");
    if (strcmp(path, "/") == 0)
    {
        fprintf(logfp, "root node, permission denied\n");
        return -EACCES;
    }

    char *path_copy = strdup(path);
    char *last_slash = strrchr(path_copy, '/');
    *last_slash = '\0';
    char *parent_path = path_copy;
    char *dirname = last_slash + 1;

    if (parent_path[0] == '\0')
    {
        parent_path = "/";
    }

    int parent_inum = find_inode(parent_path);
    if (parent_inum < 0)
    {
        free(path_copy);
        return -ENOENT;
    }

    int dir_inum = find_inode(path);
    if (dir_inum < 0)
    {
        free(path_copy);
        return -ENOENT;
    }

    struct wfs_inode *dir_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + dir_inum * BLOCK_SIZE);

    if (!S_ISDIR(dir_inode->mode))
    {
        free(path_copy);
        return -ENOTDIR;
    }

    if (dir_inode->size > 0)
    {
        free(path_copy);
        return -ENOTEMPTY;
    }

    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + parent_inum * BLOCK_SIZE);

    int remove_result = remove_dentry(parent_inode, dirname);
    if (remove_result < 0)
    {
        free(path_copy);
        return -ENOENT;
    }

    free_inode_and_blocks(dir_inode, dir_inum);

    // Update parent
    parent_inode->nlinks--;
    parent_inode->size -= sizeof(struct wfs_dentry);
    parent_inode->mtim = time(NULL);
    parent_inode->ctim = parent_inode->mtim;
    copy_disk(parent_inum, parent_inode);

    free(path_copy);

    return EXIT_SUCCESS;
}

int wfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("Entering wfs_read %s\n", path);
    fprintf(logfp, "GOT INTO READ: path=%s, size=%zu, offset=%ld\n", path, size, offset);
    int inum = find_inode(path);

    if (inum < 0)
    {
        return -ENOENT;
    }

    struct wfs_inode *inode;

    if (sb->raid_mode == 2)
    {
        fprintf(logfp, "sb mode = 2");
        inode = (struct wfs_inode *)(find_majority() + sb->i_blocks_ptr + inum * BLOCK_SIZE);
    }
    else
    {
        inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + inum * BLOCK_SIZE);
    }

    if (!S_ISREG(inode->mode))
    {
        return -EISDIR;
    }

    if (offset >= inode->size)
    {
        return EXIT_SUCCESS; // EOF
    }

    if (offset + size > inode->size)
    {
        size = inode->size - offset;
    }

    int start_block = offset / BLOCK_SIZE;
    int block_offset = offset % BLOCK_SIZE;
    size_t bytes_read = 0;

    fprintf(logfp, "READ: starting at block %d offset %d, size %zu\n",
            start_block, block_offset, size);

    while (bytes_read < size)
    {
        // Get block number using get_block_num helper
        off_t block_num = get_block_num(inode, start_block);
        if (block_num == -1)
        {
            fprintf(logfp, "READ: reached end of blocks at block %d\n", start_block);
            break;
        }

        size_t bytes_to_read = BLOCK_SIZE - block_offset;
        if (bytes_to_read > (size - bytes_read))
        {
            bytes_to_read = size - bytes_read;
        }

        char *block_addr = get_block_addr(block_num);
        memcpy(buf + bytes_read, block_addr + block_offset, bytes_to_read);

        fprintf(logfp, "READ: read %zu bytes from block %ld\n", bytes_to_read, block_num);

        bytes_read += bytes_to_read;
        block_offset = 0;
        start_block++;

        // Check if we've hit the maximum blocks
        if (start_block >= (D_BLOCK + BLOCK_SIZE / sizeof(off_t)))
        {
            break;
        }
    }

    inode->atim = time(NULL);
    copy_disk(inum, inode);

    fprintf(logfp, "READ: total bytes read: %zu\n", bytes_read);
    return bytes_read;
}

int wfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    fprintf(logfp, "GOT INTO WRITE");
    printf("Entering wfs_write %s\n", path);
    int inum = find_inode(path);
    if (inum < 0)
    {
        return -ENOENT;
    }

    struct wfs_inode *inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + inum * BLOCK_SIZE);

    if (!S_ISREG(inode->mode))
    {
        return -EISDIR;
    }

    int start_block = offset / BLOCK_SIZE;
    int block_offset = offset % BLOCK_SIZE;
    size_t bytes_written = 0;

    while (bytes_written < size)
    {
        // Get current block number
        off_t curr_block = get_block_num(inode, start_block);

        // Allocate new block if needed
        if (curr_block == -1)
        {
            int new_block = find_free(0);
            if (new_block < 0)
            {
                break;
            }
            if (set_block_num(inode, start_block, new_block) < 0)
            {
                break;
            }
            curr_block = new_block;
        }

        size_t bytes_to_write = BLOCK_SIZE - block_offset;
        if (bytes_to_write > (size - bytes_written))
        {
            bytes_to_write = size - bytes_written;
        }

        write_block(curr_block, buf + bytes_written, block_offset, bytes_to_write);
        bytes_written += bytes_to_write;
        block_offset = 0;
        start_block++;

        // Check both direct and indirect block limits
        if (start_block >= (D_BLOCK + BLOCK_SIZE / sizeof(off_t)))
        {
            break;
        }
    }

    if (offset + bytes_written > inode->size)
    {
        inode->size = offset + bytes_written;
    }

    inode->mtim = time(NULL);
    inode->ctim = inode->mtim;
    copy_disk(inum, inode);

    return bytes_written;
}

// /**
//  * Retrieves attributes of a file or directory.
//  */
int wfs_getattr(const char *path, struct stat *stbuf)
{
    fprintf(logfp, "GOT INTO GETATTR");
    fflush(logfp);

    memset(stbuf, 0, sizeof(struct stat));
    fprintf(logfp, "GETATTR called for path: %s\n", path);
    fflush(logfp);

    int inode_num = find_inode(path);
    if (inode_num < 0)
    {
        fprintf(logfp, "GETATTR: Path not found, returning -ENOENT\n");
        fflush(logfp);
        return -ENOENT;
    }

    // Calculate inode pointer
    struct wfs_inode *inode = (struct wfs_inode *)((char *)disk_maps[0] +
                                                   sb->i_blocks_ptr + (inode_num * BLOCK_SIZE));

    fprintf(logfp, "GETATTR: Found inode number: %d\n", inode_num);
    fflush(logfp);

    // Fill stat buffer
    stbuf->st_mode = inode->mode;
    stbuf->st_nlink = inode->nlinks;
    stbuf->st_uid = inode->uid;
    stbuf->st_gid = inode->gid;
    stbuf->st_size = inode->size;
    stbuf->st_atim.tv_sec = inode->atim;
    stbuf->st_atim.tv_nsec = 0;
    stbuf->st_mtim.tv_sec = inode->mtim;
    stbuf->st_mtim.tv_nsec = 0;
    stbuf->st_ctim.tv_sec = inode->ctim;
    stbuf->st_ctim.tv_nsec = 0;

    fprintf(logfp, "GETATTR: Retrieved attributes - mode: %o, nlink: %u, uid: %d, gid: %d, size: %ld\n",
            inode->mode, inode->nlinks, inode->uid, inode->gid, inode->size);
    fprintf(logfp, "GETATTR: Timestamps - atime: %ld, mtime: %ld, ctime: %ld\n",
            inode->atim, inode->mtim, inode->ctim);
    fflush(logfp);

    return EXIT_SUCCESS;
}

// directory entries are successfully retrieved and filled into the buffer.
int wfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    printf("[DEBUG] Entering wfs_readdir for path: %s\n", path);
    printf("[DEBUG] Offset: %ld\n", offset);
    printf("[DEBUG] fuse_file_info (fi) details: \n");

    fprintf(logfp, "GOT INTO READDIR");
    fprintf(logfp, "READDIR called for path: %s\n", path);
    fflush(logfp);
    printf("got into readdir");
    int dir_inum = find_inode(path);
    fprintf(logfp, "Directory inode number: %d\n", dir_inum);
    fflush(logfp);

    if (dir_inum < 0)
    {
        return -ENOENT;
    }

    struct wfs_inode *dir_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + dir_inum * BLOCK_SIZE);
    fprintf(logfp, "Directory size: %ld\n", dir_inode->size);

    for (int i = 0; i < N_BLOCKS; i++)
    {
        //fprintf(logfp, "Block[%d] = %ld\n", i, dir_inode->blocks[i]);
    }

    fflush(logfp);
    if (!S_ISDIR(dir_inode->mode))
    {
        return -ENOTDIR;
    }

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    for (int i = 0; i < N_BLOCKS && dir_inode->blocks[i] != -1; i++)
    {
        process_dir_entries(dir_inode->blocks[i], buf, filler);
    }

    return EXIT_SUCCESS; // Success
}

/**
 * Splits a path into its parent directory and new entry name.
 *
 * @param path: The input path (e.g., "/home/user").
 * @param parent_path: Buffer to hold the parent path (e.g., "/home").
 * @param new_dir_name: Buffer to hold the new directory name (e.g., "user").
 */
void get_path(const char *path, char *parent_path, char *new_dir_name)
{
    printf("get_path: Splitting path '%s'\n", path);

    const char *last_slash = strrchr(path, '/');
    if (!last_slash || last_slash == path)
    {
        // Root case or single-level name
        strncpy(parent_path, "/", 2);
        strncpy(new_dir_name, path + 1, MAX_NAME); // Skip leading '/'
    }
    else
    {
        size_t parent_len = last_slash - path;
        strncpy(parent_path, path, parent_len);
        parent_path[parent_len] = '\0';
        strncpy(new_dir_name, last_slash + 1, MAX_NAME);
    }

    printf("get_path: Parent path = '%s', New name = '%s'\n", parent_path, new_dir_name);
}

// // Function to create a new directory
int wfs_mkdir(const char *path, mode_t mode)
{
    fprintf(logfp, "[DEBUG] mkdir called for path: %s with mode: %o\n", path, mode);

    fflush(logfp);
    char *path_copy = strdup(path);
    char *last_slash = strrchr(path_copy, '/');
    *last_slash = '\0';
    char *parent_path = path_copy;
    char *dirname = last_slash + 1;

    fprintf(logfp, "Path copied\n");
    fflush(logfp);

    fprintf(logfp, "Split path: parent=%s, name=%s\n", parent_path, dirname);
    fflush(logfp);

    if (parent_path[0] == '\0')
    {
        parent_path = "/";
        fprintf(logfp, "Using root as parent\n");
        fflush(logfp);
    }

    int parent_inum = find_inode(parent_path);
    fprintf(logfp, "Parent inode result: %d\n", parent_inum);
    fflush(logfp);

    if (parent_inum < 0)
    {
        fprintf(logfp, "Invalid parent inode number");
        free(path_copy);
        return -ENOENT;
    }

    int new_inum = find_free(1);
    fprintf(logfp, "New Inode number: %d\n", new_inum);
    fflush(logfp);

    if (new_inum < 0)
    {
        fprintf(logfp, "Invalid new inode number");
        free(path_copy);
        return -ENOSPC;
    }

    // Calculating location of new inode
    struct wfs_inode *new_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + (new_inum * BLOCK_SIZE));

    // Initiliazing new inode's metadata
    new_inode->num = new_inum;
    new_inode->mode = S_IFDIR | mode; // Directory type + permissions
    new_inode->uid = getuid();
    new_inode->gid = getgid();
    new_inode->size = 0;
    new_inode->nlinks = 1;
    new_inode->atim = time(NULL);
    new_inode->mtim = new_inode->atim;
    new_inode->ctim = new_inode->atim;

    // Setting all blicks to -1, indicates uninitialized
    for (int i = 0; i < N_BLOCKS; i++)
    {
        new_inode->blocks[i] = -1;
    }

    copy_disk(new_inum, new_inode); // Copy metadata over to all disks regardless of RAID

    // Calculating location of parent inode
    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_maps[0] + sb->i_blocks_ptr + parent_inum * BLOCK_SIZE);

    int parent_block = find_dir_block(parent_inode);
    if (parent_block < 0)
    {
        fprintf(logfp, "fail3\n");
        free(path_copy);
        return -ENOSPC;
    }

    // Update parent inode's directory entry
    add_dir_entry(parent_block, dirname, new_inum);
    parent_inode->nlinks++; // Still increment for directories
    parent_inode->mtim = time(NULL);
    parent_inode->ctim = parent_inode->mtim;
    parent_inode->size += sizeof(struct wfs_dentry);

    copy_disk(parent_inum, parent_inode);

    fprintf(logfp, "MKDIR finished\n");
    fflush(logfp);

    free(path_copy);
    return EXIT_SUCCESS; // Success
}

static struct fuse_operations wfs_operations = {
    .getattr = wfs_getattr,
    .mknod = wfs_mknod,
    .mkdir = wfs_mkdir,
    .unlink = wfs_unlink,
    .rmdir = wfs_rmdir,
    .read = wfs_read,
    .write = wfs_write,
    .readdir = wfs_readdir,
};

// Main function
int main(int argc, char *argv[])
{
    printf("wfs main program started\n");
    logfp = fopen("wfs.log", "w");
    fprintf(logfp, "Program started\n");
    fflush(logfp);

    char **disk_paths = NULL;

    int i = 1; // indexes argv but also tells us how many args are available for fuse arg

    //printf("Line 560\n");
    while (i < argc && argv[i][0] != '-')
    {
        num_disks++;
        disk_paths = realloc(disk_paths, num_disks * sizeof(char *));

        if (!disk_paths)
        {
            return EXIT_FAILURE;
        }

        disk_paths[num_disks - 1] = strdup(argv[i]);
        i++;
    }

    for (int d = 0; d < num_disks; d++) {
        printf("Disk[%d]: %s\n", d, disk_paths[d]);
    }

    disk_maps = malloc(num_disks * sizeof(void *));
    disk_fds = malloc(num_disks * sizeof(int));
    if (!disk_maps || !disk_fds)
    {
        perror("Failed to allocate arrays");
        return EXIT_FAILURE;
    }
    // Initialize arrays
    memset(disk_maps, 0, num_disks * sizeof(void *));
    memset(disk_fds, -1, num_disks * sizeof(int));

    for (int j = 0; j < num_disks; j++)
    {
        if (check_disk(disk_paths[j], j) != 0)
        {
            for (int k = 0; k < j; k++)
            {
                munmap(disk_maps[k], disk_size);
                close(disk_fds[k]);
            }
            return EXIT_FAILURE;
        }
    }
    //printf("Line 600\n");

    sb = (struct wfs_sb *)disk_maps[0];

    int fuse_argc = argc - i + 1;
    char **fuse_argv = malloc(fuse_argc * sizeof(char *));
    if (!fuse_argv)
    {
        perror("Failed to allocate memory for fuse_argv\n");
        return EXIT_FAILURE;
    }

    fuse_argv[0] = argv[0]; // 1st argument will always be the name of program
    for (int j = 1; j < fuse_argc; j++)
    {
        fuse_argv[j] = argv[i++];
    }

    for (int j = 0; j < fuse_argc; j++)
    {
        printf("fuse_argv[%d]: %s\n", j, fuse_argv[j]);
    }

    // printf("\n[INFO] Mount point: %s\n", mount_point);
    fprintf(logfp, "starting fuse_main\n");
    int rc = fuse_main(fuse_argc, fuse_argv, &wfs_operations, NULL);
    fprintf(logfp, "fuse_main rc: %d\n", rc);
    return rc;
}

int check_disk(char *disk_path, int index)
{
    printf("Opening file: %s at index %d\n", disk_path, index);
    int fd = open(disk_path, O_RDWR, 0777);

    if (fd < 0)
    {
        printf("Failed to open disk: %s\n", disk_path);
        fprintf(logfp, "Failed to open disk: %s\n", disk_path);
        return EXIT_FAILURE;
    }

    //printf("LINE 647\n");
    struct wfs_sb sb;
    if (pread(fd, &sb, sizeof(struct wfs_sb), 0) != sizeof(struct wfs_sb))
    {
        printf("Failed to read contents of superblock in %s\n", disk_path);
        fprintf(logfp, "Failed to read contents of superblock in %s\n", disk_path);
        close(fd);
        return EXIT_FAILURE;
    }
    //printf("LINE 656\n");
    printf("sb num disks = %d\n", sb.num_disks);
    printf("num disks = %d\n", num_disks);
    if (sb.num_disks != num_disks)
        return EXIT_FAILURE;

    //printf("LIEN 660\n");
    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        printf("Failed to fstat in %s\n", disk_path);
        close(fd);
        return EXIT_FAILURE;
    }

    disk_size = st.st_size;

    printf("LINE 670\n");
    disk_fds[index] = fd;
    disk_maps[index] = mmap(NULL, disk_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (disk_maps[index] == MAP_FAILED)
    {
        printf("Failed map in %s at index %d\n", disk_path, index);
        close(fd);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int find_inode(const char *path)
{
    fprintf(logfp, "FIND_INODE: Looking for %s\n", path);
    fflush(logfp);

    if (strcmp(path, "/") == 0)
    {
        return EXIT_SUCCESS; // Root inode
    }

    path++; // Skip leading /
    char *path_copy = strdup(path);
    char *component = strtok(path_copy, "/");

    // Start at root inode
    int curr_inum = 0;
    struct wfs_inode *curr_inode = (struct wfs_inode *)((char *)disk_maps[0] +
                                                        sb->i_blocks_ptr + curr_inum * BLOCK_SIZE);

    while (component)
    {
        fprintf(logfp, "FIND_INODE: Looking for component: %s in inode %d\n",
                component, curr_inum);
        fflush(logfp);

        int found = 0;
        for (int i = 0; i < N_BLOCKS && curr_inode->blocks[i] != -1; i++)
        {
            int block_num = curr_inode->blocks[i];
            struct wfs_dentry *entries;

            if (sb->raid_mode == 0)
            { // RAID 0
                int disk_num = block_num % num_disks;
                int block_offset = block_num / num_disks;
                entries = (struct wfs_dentry *)((char *)disk_maps[disk_num] +
                                                sb->d_blocks_ptr + block_offset * BLOCK_SIZE);
            }
            else
            { // RAID 1
                entries = (struct wfs_dentry *)((char *)disk_maps[0] +
                                                sb->d_blocks_ptr + block_num * BLOCK_SIZE);
            }

            for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
            {
                if (entries[j].num != -1 && strcmp(entries[j].name, component) == 0)
                {
                    curr_inum = entries[j].num;
                    curr_inode = (struct wfs_inode *)((char *)disk_maps[0] +
                                                      sb->i_blocks_ptr + curr_inum * BLOCK_SIZE);
                    found = 1;
                    fprintf(logfp, "FIND_INODE: Found component %s at inode %d\n",
                            component, curr_inum);
                    fflush(logfp);
                    break;
                }
            }
            if (found)
                break;
        }

        if (!found)
        {
            free(path_copy);
            return -1;
        }

        component = strtok(NULL, "/");
    }

    free(path_copy);
    return curr_inum;
}

int find_free(int is_inode)
{
    off_t bitmap_offset = is_inode ? sb->i_bitmap_ptr : sb->d_bitmap_ptr;
    int total_items = is_inode ? sb->num_inodes : sb->num_data_blocks;

    fprintf(logfp, "find_free: is_inode=%d, total_items=%d, bitmap_offset=%ld\n", is_inode, total_items, bitmap_offset);
    int free_num = -1;

    // For RAID 0 data blocks, we need to check each disk separately
    if (!is_inode && sb->raid_mode == 0)
    {
        // Check each disk in order
        for (int disk = 0; disk < num_disks; disk++)
        {
            unsigned char *bitmap = (unsigned char *)((char *)disk_maps[disk] + bitmap_offset);
            // Look for first free bit in this disk
            for (int byte = 0; byte < (total_items + 7) / 8; byte++)
            {
                if (bitmap[byte] != 0xFF)
                {
                    for (int bit = 0; bit < 8; bit++)
                    {
                        if (!(bitmap[byte] & (1 << bit)))
                        {
                            free_num = byte * 8 + bit;
                            if (free_num >= total_items)
                                continue;

                            // Set bit only on this disk
                            bitmap[byte] |= (1 << bit);

                            // Calculate global block number
                            free_num = free_num * num_disks + disk;
                            return free_num;
                        }
                    }
                }
            }
        }
    }
    else
    {
        // Original code for inodes and RAID 1
        // Start from disk 0 since we'll set all disks
        unsigned char *bitmap = (unsigned char *)((char *)disk_maps[0] + bitmap_offset);
        for (int byte = 0; byte < (total_items + 7) / 8; byte++)
        {
            if (bitmap[byte] != 0xFF)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    if (!(bitmap[byte] & (1 << bit)))
                    {
                        free_num = byte * 8 + bit;
                        if (free_num >= total_items)
                            continue;

                        // Set bit on all disks
                        for (int d = 0; d < num_disks; d++)
                        {
                            unsigned char *disk_bitmap = (unsigned char *)((char *)disk_maps[d] + bitmap_offset);
                            disk_bitmap[byte] |= (1 << bit);
                        }
                        return free_num;
                    }
                }
            }
        }
    }
    return -1;
}

void copy_disk(int inode_num, struct wfs_inode *source_inode)
{
    // Mirror to ALL disks
    for (int disk = 0; disk < num_disks; disk++)
    {
        void *copy_disk = (void *)((char *)disk_maps[disk] + sb->i_blocks_ptr + inode_num * BLOCK_SIZE);
        memcpy(copy_disk, source_inode, BLOCK_SIZE);
    }
}

int cfree_entry_r0(int block_num) {
    fprintf(logfp, "Checking block %d (RAID 0)\n", block_num);
    fflush(logfp);

    int disk_num = block_num % num_disks;
    int block_offset = block_num / num_disks;
    struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[disk_num] +
                                                       sb->d_blocks_ptr + block_offset * BLOCK_SIZE);

    for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++) {
        fprintf(logfp, "Checking entry %d: num=%d\n", j, entries[j].num);
        fflush(logfp);
        if (entries[j].num == -1) {
            fprintf(logfp, "Found free entry in existing block (RAID 0)\n");
            fflush(logfp);
            return 1; // Found free entry
        }
    }
    return 0; // No free entry found
}

int cfree_entry_r1(int block_num) {
    fprintf(logfp, "Checking block %d (RAID 1)\n", block_num);
    fflush(logfp);

    struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[0] +
                                                       sb->d_blocks_ptr + block_num * BLOCK_SIZE);

    for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++) {
        fprintf(logfp, "Checking entry %d: num=%d\n", j, entries[j].num);
        fflush(logfp);
        if (entries[j].num == -1) {
            fprintf(logfp, "Found free entry in existing block (RAID 1)\n");
            fflush(logfp);
            return 1; // Found free entry
        }
    }
    return 0; // No free entry found
}

void init_new_r0(int new_block) {
    fprintf(logfp, "Initializing new block %d (RAID 0)\n", new_block);
    fflush(logfp);

    int disk_num = new_block % num_disks;
    int block_offset = new_block / num_disks;
    struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[disk_num] +
                                                       sb->d_blocks_ptr + block_offset * BLOCK_SIZE);

    for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++) {
        entries[j].num = -1;       // Mark as free
        entries[j].name[0] = '\0'; // Clear name
    }
}

void init_new_r1(int new_block) {
    fprintf(logfp, "Initializing new block %d (RAID 1)\n", new_block);
    fflush(logfp);

    for (int disk = 0; disk < num_disks; disk++) {
        struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[disk] +
                                                           sb->d_blocks_ptr + new_block * BLOCK_SIZE);
        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++) {
            entries[j].num = -1;       // Mark as free
            entries[j].name[0] = '\0'; // Clear name
        }
    }
}

int find_dir_block(struct wfs_inode *dir_inode) {
    fprintf(logfp, "Entering find_dir_block -------------\n");
    fflush(logfp);

    // Check all existing blocks
    for (int i = 0; i < N_BLOCKS && dir_inode->blocks[i] != -1; i++) {
        int block_num = dir_inode->blocks[i];

        // Check for free entry in the block based on RAID mode
        int free_entry_found = 0;
        if (sb->raid_mode == 0) {
            free_entry_found = cfree_entry_r0(block_num); // RAID 0
        } else {
            free_entry_found = cfree_entry_r1(block_num); // RAID 1
        }

        if (free_entry_found) {
            return block_num; // Found block with free entry
        }
    }

    // No free entry found in existing blocks, find first empty block slot
    fprintf(logfp, "No free entries found, allocating new block\n");
    fflush(logfp);

    for (int i = 0; i < N_BLOCKS; i++) {
        fprintf(logfp, "Index = %d, Block = %ld\n", i, dir_inode->blocks[i]);
        if (dir_inode->blocks[i] == -1) {
            // Allocate new block
            int new_block = find_free(0);
            if (new_block < 0) {
                return -1; // Directory is full or allocation failed
            }

            // Initialize the new block based on RAID mode
            if (sb->raid_mode == 0) {
                init_new_r0(new_block); // RAID 0
            } else {
                init_new_r1(new_block); // RAID 1
            }

            // Assign the new block to the directory inode
            dir_inode->blocks[i] = new_block;
            fprintf(logfp, "New block allocated and initialized\n");
            fflush(logfp);
            return new_block;
        }
    }

    fprintf(logfp, "Directory is full\n");
    fflush(logfp);
    return -1; // Directory is full (no more block slots)
}

// Updates parent directory to link new child (file / directory)
void add_dir_entry(int block_num, const char *filename, int inode_num)
{
    fprintf(logfp, "got into add_dir_entry with block=%d, filename=%s, inode=%d\n",
            block_num, filename, inode_num);
    fflush(logfp);

    if (sb->raid_mode == 0)
    { // RAID 0
        int disk_num = block_num % num_disks;
        int block_offset = block_num / num_disks;
        fprintf(logfp, "RAID 0: disk_num=%d, block_offset=%d\n", disk_num, block_offset);
        fflush(logfp);

        struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[disk_num] +
                                                           sb->d_blocks_ptr + block_offset * BLOCK_SIZE);

        for (int i = 0; i < BLOCK_SIZE / sizeof(struct wfs_dentry); i++)
        {
            fprintf(logfp, "Checking entry %d: num=%d\n", i, entries[i].num);
            fflush(logfp);

            if (entries[i].num == -1)
            {
                fprintf(logfp, "Found free entry at index %d\n", i);
                fflush(logfp);

                strncpy(entries[i].name, filename, 27);
                entries[i].name[27] = '\0';
                entries[i].num = inode_num;

                fprintf(logfp, "Added entry: name='%s', inode=%d\n",
                        entries[i].name, entries[i].num);
                fflush(logfp);
                return;
            }
        }
    }
    else
    { // RAID 1
        fprintf(logfp, "RAID 1: mirroring to all disks\n");
        fflush(logfp);

        for (int disk = 0; disk < num_disks; disk++)
        {
            fprintf(logfp, "Writing to disk %d\n", disk);
            fflush(logfp);

            struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[disk] +
                                                               sb->d_blocks_ptr + block_num * BLOCK_SIZE);

            for (int i = 0; i < BLOCK_SIZE / sizeof(struct wfs_dentry); i++)
            {
                if (entries[i].num == -1)
                {
                    fprintf(logfp, "Found free entry at index %d\n", i);
                    fflush(logfp);

                    strncpy(entries[i].name, filename, 27);
                    entries[i].name[27] = '\0';
                    entries[i].num = inode_num;

                    fprintf(logfp, "Added entry: name='%s', inode=%d\n",
                            entries[i].name, entries[i].num);
                    fflush(logfp);
                    break;
                }
            }
        }
    }
}

off_t get_block_num(struct wfs_inode *inode, int index)
{
    if (index < 0)
        return -1;
    // Direct blocks (0 to 5)
    if (index < D_BLOCK)
    {
        return inode->blocks[index];
    }

    // Check indirect blocks
    if (inode->blocks[IND_BLOCK] != -1)
    {
        // Get indirect block table
        off_t *indirect_table = (off_t *)get_block_addr(inode->blocks[IND_BLOCK]);
        if (index < (D_BLOCK + BLOCK_SIZE / sizeof(off_t)))
        {
            return indirect_table[index - D_BLOCK];
        }
    }
    return -1;
}

int set_block_num(struct wfs_inode *inode, int index, off_t block_num)
{
    if (index < 0)
        return -1;

    // Direct blocks (0 to 5)
    if (index < D_BLOCK)
    {
        inode->blocks[index] = block_num;
        return EXIT_SUCCESS;
    }

    // Indirect blocks
    if (index < (D_BLOCK + BLOCK_SIZE / sizeof(off_t)))
    {
        // Allocate indirect block if needed
        if (inode->blocks[IND_BLOCK] == -1)
        {
            off_t indirect_block = find_free(0); // 0 for data block
            if (indirect_block == -1)
                return -1;

            // Initialize indirect block
            off_t *indirect_table = (off_t *)get_block_addr(indirect_block);
            for (int i = 0; i < BLOCK_SIZE / sizeof(off_t); i++)
            {
                indirect_table[i] = -1;
            }
            // Write to all disks for RAID 1
            if (sb->raid_mode == 1)
            {
                for (int disk = 1; disk < num_disks; disk++)
                {
                    off_t *mirror_table = (off_t *)((char *)disk_maps[disk] + sb->d_blocks_ptr + indirect_block * BLOCK_SIZE);
                    memcpy(mirror_table, indirect_table, BLOCK_SIZE);
                }
            }
            inode->blocks[IND_BLOCK] = indirect_block;
        }

        // Set block number in indirect block
        off_t *indirect_table = (off_t *)get_block_addr(inode->blocks[IND_BLOCK]);
        indirect_table[index - D_BLOCK] = block_num;

        // Mirror to all disks for RAID 1
        if (sb->raid_mode == 1)
        {
            for (int disk = 1; disk < num_disks; disk++)
            {
                off_t *mirror_table = (off_t *)((char *)disk_maps[disk] + sb->d_blocks_ptr + inode->blocks[IND_BLOCK] * BLOCK_SIZE);
                memcpy(mirror_table, indirect_table, BLOCK_SIZE);
            }
        }
        return EXIT_SUCCESS;
    }

    return -1;
}

void write_block(int block_num, const char *data, size_t offset, size_t size)
{

    if (sb->raid_mode == 0)
    { // RAID 0
        // Get block address and write once
        char *block_addr = get_block_addr(block_num);
        memcpy(block_addr + offset, data, size);
    }
    else
    { // RAID 1
        // Write to all disks
        for (int disk = 0; disk < num_disks; disk++)
        {
            char *block_addr = (char *)disk_maps[disk] + sb->d_blocks_ptr + block_num * BLOCK_SIZE;
            memcpy(block_addr + offset, data, size);
        }
    }
}

char *get_block_addr(int block_num)
{
    if (sb->raid_mode == 0)
    { // RAID 0
        int disk_num = block_num % num_disks;
        int block_offset = block_num / num_disks;
        return (char *)disk_maps[disk_num] + sb->d_blocks_ptr + block_offset * BLOCK_SIZE;
    }
    else if (sb->raid_mode == 1)
    { // RAID 1
        return (char *)disk_maps[0] + sb->d_blocks_ptr + block_num * BLOCK_SIZE;
    }
    else
    {
        return find_majority() + sb->d_blocks_ptr + block_num * BLOCK_SIZE;
    }
}

char *find_majority()
{
    int disk_major[num_disks];
    memset(&disk_major, 0, num_disks * sizeof(int));
    for (int disk = 0; disk < num_disks; disk++)
    {
        char *curr_block = (char *)(disk_maps[disk]);
        for (int comp_disk = 0; comp_disk < num_disks; comp_disk++)
        {
            if (disk == comp_disk)
                continue;

            char *comp_block = (char *)(disk_maps[comp_disk]);
            if (memcmp(curr_block, comp_block, disk_size) == 0)
                disk_major[disk]++;
        }
    }

    int max_matches = disk_major[0];
    int majority_disk = 0;
    for (int disk = 0; disk < num_disks; disk++)
    {
        if (disk_major[disk] >= max_matches)
        {
            max_matches = disk_major[disk];
            majority_disk = disk;
        }
    }

    fprintf(logfp, "Majority Disk: %d", majority_disk);

    return (char *)disk_maps[majority_disk];
}

int remove_dentry(struct wfs_inode *dir_inode, const char *filename)
{
    fprintf(logfp, "REMOVE_DENTRY: Looking for %s\n", filename);

    for (int i = 0; i < N_BLOCKS && dir_inode->blocks[i] != -1; i++)
    {
        int block_num = dir_inode->blocks[i];
        fprintf(logfp, "REMOVE_DENTRY: Checking block %ld\n", dir_inode->blocks[i]);

        if (sb->raid_mode == 0)
        { // RAID 0
            int disk_num = block_num % num_disks;
            int block_offset = block_num / num_disks;
            struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[disk_num] +
                                                               sb->d_blocks_ptr + block_offset * BLOCK_SIZE);

            for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
            {
                if (entries[j].num != -1 && strcmp(entries[j].name, filename) == 0)
                {
                    int inode_num = entries[j].num;
                    entries[j].num = -1; // Mark entry as free
                    fprintf(logfp, "REMOVE_DENTRY: Found entry at block %d, returning inode %d\n",
                            block_num, inode_num);
                    return inode_num;
                }
            }
        }
        else
        { // RAID 1
            int found_inum = -1;
            for (int disk = 0; disk < num_disks; disk++)
            {
                struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_maps[disk] +
                                                                   sb->d_blocks_ptr + block_num * BLOCK_SIZE);

                for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
                {
                    if (entries[j].num != -1 && strcmp(entries[j].name, filename) == 0)
                    {
                        found_inum = entries[j].num;
                        entries[j].num = -1;
                        break;
                    }
                }
            }
            if (found_inum != -1)
                return found_inum;
        }
    }
    return -1;
}

void free_inode_and_blocks(struct wfs_inode *inode, int inode_num)
{
    fprintf(logfp, "FREE_BLOCKS: Starting to free inode %d\n", inode_num);
    fprintf(logfp, "FREE_BLOCKS: Mode is %s\n", sb->raid_mode == 0 ? "RAID 0" : "RAID 1");

    // Free direct blocks (0 to 5)
    for (int i = 0; i < D_BLOCK && inode->blocks[i] != -1; i++)
    {
        fprintf(logfp, "FREE_BLOCKS: Freeing direct block %ld from disk %d\n",
                inode->blocks[i], (int)(inode->blocks[i] % num_disks));
        clear_bitmap_bit(sb->d_bitmap_ptr, inode->blocks[i]);
    }

    // Handle indirect blocks at IND_BLOCK (index 6)
    if (inode->blocks[IND_BLOCK] != -1)
    {
        fprintf(logfp, "FREE_BLOCKS: Processing indirect block %ld\n", inode->blocks[IND_BLOCK]);
        off_t *indirect_table = (off_t *)get_block_addr(inode->blocks[IND_BLOCK]);
        // Free all blocks pointed to by indirect block
        for (int i = 0; i < BLOCK_SIZE / sizeof(off_t) && indirect_table[i] != -1; i++)
        {
            fprintf(logfp, "FREE_BLOCKS: Freeing indirect data block %ld\n", indirect_table[i]);
            clear_bitmap_bit(sb->d_bitmap_ptr, indirect_table[i]);
        }
        // Free the indirect block itself
        fprintf(logfp, "FREE_BLOCKS: Freeing indirect block itself\n");
        clear_bitmap_bit(sb->d_bitmap_ptr, inode->blocks[IND_BLOCK]);
    }

    // Free the inode
    fprintf(logfp, "FREE_BLOCKS: Freeing inode %d\n", inode_num);
    clear_bitmap_bit(sb->i_bitmap_ptr, inode_num);
    fprintf(logfp, "FREE_BLOCKS: Complete\n");
    fflush(logfp);
}

void clear_bitmap_bit(off_t bitmap_offset, int item_num)
{
    fprintf(logfp, "CLEAR_BIT: Clearing item %d at offset %ld\n", item_num, bitmap_offset);
    fprintf(logfp, "CLEAR_BIT: RAID mode %d\n", sb->raid_mode);

    if (bitmap_offset == sb->i_bitmap_ptr || sb->raid_mode == 1)
    {
        // For inodes or RAID 1, clear on all disks
        for (int disk = 0; disk < num_disks; disk++)
        {
            unsigned char *bitmap = (unsigned char *)((char *)disk_maps[disk] + bitmap_offset);
            int byte = item_num / 8;
            int bit = item_num % 8;
            bitmap[byte] &= ~(1 << bit);
        }
    }
    else
    {
        // For RAID 0 data blocks
        // Calculate which disk owns this block
        int disk_num = item_num % num_disks;
        // Calculate local block number within that disk
        int local_num = item_num / num_disks;
        int byte = local_num / 8;
        int bit = local_num % 8;

        unsigned char *bitmap = (unsigned char *)((char *)disk_maps[disk_num] + bitmap_offset);
        fprintf(logfp, "CLEAR_BIT: RAID 0 - Clearing block %d (local %d) on disk %d\n",
                item_num, local_num, disk_num);
        bitmap[byte] &= ~(1 << bit);
    }
    fflush(logfp);
}

void process_dir_entries(int block_num, void *buf, fuse_fill_dir_t filler)
{
    struct wfs_dentry *entries = (struct wfs_dentry *)get_block_addr(block_num);
    fprintf(logfp, "Reading block %d\n", block_num);
    for (int i = 0; i < BLOCK_SIZE / sizeof(struct wfs_dentry); i++)
    {
        if (entries[i].num > 0)
        {
            fprintf(logfp, "Found entry: name='%s', inode=%d\n",
                    entries[i].name, entries[i].num);
            fflush(logfp);
            filler(buf, entries[i].name, NULL, 0);
        }
    }
}