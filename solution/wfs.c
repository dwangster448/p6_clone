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
#include <dirent.h>
#include "wfs.h" // Ensure wfs.h is included for super_block reads

#define MAX_PATH_LEN 10
#define MAX_NAME_LEN 26
#define ROOT_INODE_NUM 0 // Assuming the root inode is 0

#define MAX_DISKS (10)

// Global variables
int num_disks = 0;
void **disk_mappings;
struct wfs_sb *sb; // Superblock
size_t disk_size;
int *disk_file_desc; // Array to hold file descriptors for each disk
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
void process_dir_entries(int block_num, void *buffer, fuse_fill_dir_t filler);
int cfree_entry_r0(int block_num);
int cfree_entry_r1(int block_num);
void init_new_r0(int new_block);
void init_new_r1(int new_block);
struct wfs_dentry *get_dentry_entries(int block_num);
int find_inode(const char *path);

int wfs_getattr(const char *path, struct stat *statbuffer);
int wfs_mknod(const char *path, mode_t mode, dev_t dev);
int wfs_mkdir(const char *path, mode_t mode);
int wfs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
int wfs_unlink(const char *path);
int wfs_rmdir(const char *path);
int wfs_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi);
int wfs_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi);

int wfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    printf("[FUNCTION] wfs_mknod -------------- \n");
    printf("Entered mknod\n");

    char *curr_path = strdup(path);
    char *last_slash = strrchr(curr_path, '/');
    *last_slash = '\0';
    char *parent_path = curr_path;
    char *filename = last_slash + 1;

    if (parent_path[0] == '\0')
    {
        parent_path = "/";
    }

    int parent_inum = find_inode(parent_path);
    if (parent_inum < 0)
    {
        free(curr_path);
        return -ENOENT;
    }

    // find new free inode
    int new_inum = find_free(1);
    if (new_inum < 0)
    {
        return -ENOSPC;
    }

    // init new inode
    struct wfs_inode *new_inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + (new_inum * BLOCK_SIZE));

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
    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + parent_inum * BLOCK_SIZE);

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
    free(curr_path);

    return EXIT_SUCCESS; // Success
}

int wfs_unlink(const char *path)
{
    printf("[FUNCTION] wfs_unlink %s ---------- \n", path);
    printf("Entered unlink, path =  %s\n", path);

    char *curr_path = strdup(path);
    char *last_slash = strrchr(curr_path, '/');
    *last_slash = '\0';
    char *parent_path = curr_path;
    char *filename = last_slash + 1;

    if (parent_path[0] == '\0')
    {
        parent_path = "/";
    }

    int parent_inum = find_inode(parent_path);
    printf("WFS_UNLINK Parent's inode number = %d\n", parent_inum);
    if (parent_inum < 0)
    {
        free(curr_path);
        return -ENOENT;
    }

    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + parent_inum * BLOCK_SIZE);

    printf("Trying to remove entry %s\n", filename);
    int file_inum = remove_dentry(parent_inode, filename);
    printf("File inode to remove: %d\n", file_inum);

    if (file_inum < 0)
    {
        free(curr_path);
        return -ENOENT;
    }

    struct wfs_inode *file_inode = (struct wfs_inode *)((char *)disk_mappings[0] +
                                                        sb->i_blocks_ptr + file_inum * BLOCK_SIZE);

    printf("Freeing blocks for Inode %d with size %ld\n",
           file_inum, file_inode->size);
    for (int i = 0; i < N_BLOCKS; i++)
    {
        if (file_inode->blocks[i] != -1)
        {
            printf("Block to free = blocks[%d] = %ld\n",
                   i, file_inode->blocks[i]);
        }
    }

    // Now actually free the blocks
    free_inode_and_blocks(file_inode, file_inum);
    printf("Blocks freed in wfs_unlink\n");

    // Update parent directory
    parent_inode->size -= sizeof(struct wfs_dentry);
    parent_inode->mtim = time(NULL);
    parent_inode->ctim = parent_inode->mtim;
    copy_disk(parent_inum, parent_inode);
    printf("Parent inode successfully updated\n");

    free(curr_path);
    printf("wfs_unlink finished\n");

    return EXIT_SUCCESS;
}

int wfs_rmdir(const char *path)
{
    // Debug logging
    printf("Entering wfs_rmdir %s --------------- \n", path);
    printf("Entering rmdir\n");

    // Root node cannot be removed
    if (strcmp(path, "/") == 0)
    {
        perror("Cannot remove root node\n");
        return -EACCES;
    }

    // Parse the path into parent and directory name
    char *curr_path = strdup(path); // Duplicate path for manipulation
    if (!curr_path)
        return -ENOMEM;

    char *last_slash = strrchr(curr_path, '/');
    if (!last_slash)
    {
        free(curr_path);
        return -EINVAL; // Invalid path
    }

    *last_slash = '\0'; // Split path into parent and directory
    char *parent_path = curr_path;
    char *dirname = last_slash + 1;

    if (parent_path[0] == '\0') // Handle case where parent is root
        parent_path = "/";

    // Check if the parent directory exists
    int parent_inum = find_inode(parent_path);
    if (parent_inum < 0)
    {
        free(curr_path);
        return -ENOENT; // Parent not found
    }

    // Check if the directory to remove exists
    int dir_inum = find_inode(path);
    if (dir_inum < 0)
    {
        free(curr_path);
        return -ENOENT; // Directory not found
    }

    // Retrieve the directory inode
    struct wfs_inode *dir_inode = (struct wfs_inode *)((char *)disk_mappings[0] +
                                                       sb->i_blocks_ptr +
                                                       dir_inum * BLOCK_SIZE);

    // Validate that the target is a directory
    if (!S_ISDIR(dir_inode->mode))
    {
        free(curr_path);
        return -ENOTDIR; // Not a directory
    }

    // Check if the directory is empty
    if (dir_inode->size > 0)
    {
        free(curr_path);
        return -ENOTEMPTY; // Directory is not empty
    }

    // Retrieve the parent inode
    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_mappings[0] +
                                                          sb->i_blocks_ptr +
                                                          parent_inum * BLOCK_SIZE);

    // Remove the directory entry from the parent
    int remove_result = remove_dentry(parent_inode, dirname);
    if (remove_result < 0)
    {
        free(curr_path);
        return -ENOENT; // Failed to remove directory entry
    }

    // Free the directory inode and its blocks
    free_inode_and_blocks(dir_inode, dir_inum);

    // Update parent directory metadata
    parent_inode->nlinks--;
    parent_inode->size -= sizeof(struct wfs_dentry);
    parent_inode->mtim = time(NULL);
    parent_inode->ctim = parent_inode->mtim;

    // Persist parent inode changes to disk
    copy_disk(parent_inum, parent_inode);

    // Cleanup
    free(curr_path);

    return EXIT_SUCCESS;
}

int wfs_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("Entering wfs_read %s ------------- \n", path);
    printf("Entering read: path: %s, size: %zu, offset: %ld\n", path, size, offset);
    int inum = find_inode(path);

    if (inum < 0)
    {
        return -ENOENT;
    }

    struct wfs_inode *inode;

    if (sb->raid_mode == 2)
    {
        printf("sb mode = 2");
        inode = (struct wfs_inode *)(find_majority() + sb->i_blocks_ptr + inum * BLOCK_SIZE);
    }
    else
    {
        inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + inum * BLOCK_SIZE);
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

    printf("Start reading at block number %d with offset %d, size = %zu\n",
           start_block, block_offset, size);

    while (bytes_read < size)
    {
        // Get block number using get_block_num helper
        off_t block_num = get_block_num(inode, start_block);
        if (block_num == -1)
        {
            break;
        }

        size_t bytes_to_read = BLOCK_SIZE - block_offset;
        if (bytes_to_read > (size - bytes_read))
        {
            bytes_to_read = size - bytes_read;
        }

        char *block_addr = get_block_addr(block_num);
        memcpy(buffer + bytes_read, block_addr + block_offset, bytes_to_read);

        printf("Read %zu bytes from block number %ld\n", bytes_to_read, block_num);

        bytes_read += bytes_to_read;
        block_offset = 0;
        start_block++;

        // Don't read beyond maximum direct blocks
        if (start_block >= (D_BLOCK + BLOCK_SIZE / sizeof(off_t)))
        {
            break;
        }
    }

    inode->atim = time(NULL);
    copy_disk(inum, inode);

    printf("bytes read: %zu\n", bytes_read);
    return bytes_read;
}

int wfs_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("Entered write ------- \n");
    printf("Entering wfs_write %s\n", path);
    int inum = find_inode(path);
    if (inum < 0)
    {
        return -ENOENT;
    }

    struct wfs_inode *inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + inum * BLOCK_SIZE);

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

        write_block(curr_block, buffer + bytes_written, block_offset, bytes_to_write);
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
int wfs_getattr(const char *path, struct stat *statbuffer)
{
    printf("Entering wfs_getattr %s", path);

    memset(statbuffer, 0, sizeof(struct stat));

    int inode_num = find_inode(path);
    if (inode_num < 0)
    {
        perror("Failed to find inode\n");
        return -ENOENT;
    }

    // Locate the inode using the inode number
    struct wfs_inode *inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + (inode_num * BLOCK_SIZE));

    // Fill the stat buffer
    statbuffer->st_mode = inode->mode;                                   // File mode
    statbuffer->st_nlink = inode->nlinks;                                // Number of hard links
    statbuffer->st_uid = inode->uid;                                     // User ID of owner
    statbuffer->st_gid = inode->gid;                                     // Group ID of owner
    statbuffer->st_size = inode->size;                                   // File size in bytes
    statbuffer->st_blocks = (inode->size + BLOCK_SIZE - 1) / BLOCK_SIZE; // Number of 512B blocks
    statbuffer->st_blksize = BLOCK_SIZE;                                 // Block size (filesystem-defined)
    statbuffer->st_atime = inode->atim;                                  // Last access time
    statbuffer->st_mtime = inode->mtim;                                  // Last modification time
    statbuffer->st_ctime = inode->ctim;                                  // Last status change time

    printf("[INFO] wfs_getattr succeeded for path: %s\n", path);

    return EXIT_SUCCESS;
}

// directory entries are successfully retrieved and filled into the buffer.
int wfs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    printf("[DEBUG] Entering wfs_readdir for path: %s\n", path);
    printf("[DEBUG] Offset: %ld\n", offset);

    printf("got into readdir");
    int dir_inum = find_inode(path);
    printf("Directory inode number: %d\n", dir_inum);

    if (dir_inum < 0)
    {
        return -ENOENT;
    }

    struct wfs_inode *dir_inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + dir_inum * BLOCK_SIZE);
    printf("Size of directory: %ld\n", dir_inode->size);

    for (int i = 0; i < N_BLOCKS; i++)
    {
        // printf("Block[%d] = %ld\n", i, dir_inode->blocks[i]);
    }

    if (!S_ISDIR(dir_inode->mode))
    {
        return -ENOTDIR;
    }

    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);

    for (int i = 0; i < N_BLOCKS; i++)
    {
        if (dir_inode->blocks[i] != -1)
        {
            process_dir_entries(dir_inode->blocks[i], buffer, filler);
        }
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
    printf("[DEBUG] mkdir called for path: %s with mode: %o\n", path, mode);

    char *curr_path = strdup(path);
    char *last_slash = strrchr(curr_path, '/');
    *last_slash = '\0';
    char *parent_path = curr_path;
    char *dirname = last_slash + 1;

    if (parent_path[0] == '\0')
    {
        parent_path = "/";
        printf("Parent is null, using root as parent\n");
    }

    int parent_inum = find_inode(parent_path);

    if (parent_inum < 0)
    {
        perror("Invalid parent inode number");
        free(curr_path);
        return -ENOENT;
    }

    int new_inum = find_free(1);
    printf("New Inode number: %d\n", new_inum);

    if (new_inum < 0)
    {
        perror("Invalid new inode number");
        free(curr_path);
        return -ENOSPC;
    }

    // Calculating location of new inode
    struct wfs_inode *new_inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + (new_inum * BLOCK_SIZE));

    // Initiliazing new inode's metadata
    new_inode->num = new_inum;
    new_inode->mode = S_IFDIR | mode; // Directory type + permissions
    new_inode->uid = getuid();
    new_inode->gid = getgid();
    new_inode->size = 0;
    new_inode->nlinks = 1;
    new_inode->atim = time(NULL);
    new_inode->mtim = new_inode->atim;
    new_inode->ctim = new_inode->atim; //Needed to update current time for new inode initialization

    // Setting all blicks to -1, indicates uninitialized
    for (int i = 0; i < N_BLOCKS; i++)
    {
        new_inode->blocks[i] = -1;
    }

    copy_disk(new_inum, new_inode); // Copy metadata over to all disks regardless of RAID

    // Calculating location of parent inode
    struct wfs_inode *parent_inode = (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + parent_inum * BLOCK_SIZE);

    int parent_block = find_dir_block(parent_inode);
    if (parent_block < 0)
    {
        perror("Parent block could not be found\n");
        free(curr_path);
        return -ENOSPC;
    }

    // Update parent inode's directory entry
    add_dir_entry(parent_block, dirname, new_inum);
    parent_inode->nlinks++; // Still increment for directories
    parent_inode->mtim = time(NULL);
    parent_inode->ctim = parent_inode->mtim;
    parent_inode->size += sizeof(struct wfs_dentry);

    copy_disk(parent_inum, parent_inode);

    printf("wfs_mkdir finished ---------- \n");

    free(curr_path);
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
    char **disk_paths = NULL;

    int i = 1; // indexes argv but also tells us how many args are available for fuse arg

    // printf("Line 560\n");
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

    for (int d = 0; d < num_disks; d++)
    {
        printf("Disk[%d]: %s\n", d, disk_paths[d]);
    }

    char temp[MAX_DISKS];

    // Bubble sort
    for (int a = 0; a < num_disks - 1; a++) {
        for (int j = 0; j < num_disks - a - 1; j++) {
            if (strcmp(disk_paths[j], disk_paths[j + 1]) > 0) {
                // Swap strings
                strcpy(temp, disk_paths[j]);
                strcpy(disk_paths[j], disk_paths[j + 1]);
                strcpy(disk_paths[j + 1], temp);
            }
        }
    }

    for (int i = 0; i < num_disks; i++) {
        printf("Disk[%d]:%s\n", i, disk_paths[i]);
    }

    disk_mappings = malloc(num_disks * sizeof(void *));
    disk_file_desc = malloc(num_disks * sizeof(int));
    if (!disk_mappings || !disk_file_desc)
    {
        perror("Failed to allocate arrays");
        return EXIT_FAILURE;
    }
    // Initialize arrays
    memset(disk_mappings, 0, num_disks * sizeof(void *));
    memset(disk_file_desc, -1, num_disks * sizeof(int));

    for (int j = 0; j < num_disks; j++)
    {
        if (check_disk(disk_paths[j], j) != 0)
        {
            for (int k = 0; k < j; k++)
            {
                munmap(disk_mappings[k], disk_size);
                close(disk_file_desc[k]);
            }
            return EXIT_FAILURE;
        }
    }
    // printf("Line 600\n");

    // size_t disk_size = ftell(disk_paths[0]);
    // qsort(disk_paths, num_disks, sizeof(disk_size), comp);

    

    sb = (struct wfs_sb *)disk_mappings[0];

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
    printf("starting fuse_main\n");
    int rc = fuse_main(fuse_argc, fuse_argv, &wfs_operations, NULL);
    return rc;
}

int check_disk(char *disk_path, int index)
{
    printf("Opening file: %s at index %d\n", disk_path, index);
    int fd = open(disk_path, O_RDWR, 0777);

    if (fd < 0)
    {
        printf("Failed to open disk: %s\n", disk_path);
        return EXIT_FAILURE;
    }

    // printf("LINE 647\n");
    struct wfs_sb sb;
    if (pread(fd, &sb, sizeof(sb), 0) != sizeof(sb))
    {
        printf("Failed to read contents of superblock in %s\n", disk_path);
        close(fd);
        return EXIT_FAILURE;
    }
    // printf("LINE 656\n");
    printf("sb num disks = %d\n", sb.num_disks);
    printf("num disks = %d\n", num_disks);
    if (sb.num_disks < num_disks)
    {
        perror("Not enough disks\n");
        return EXIT_FAILURE;
    }
    else if (sb.num_disks > num_disks)
    {
        perror("Too many disks\n");
        return EXIT_FAILURE;
    }

    // printf("LIEN 660\n");
    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        printf("Failed to fstat in %s\n", disk_path);
        close(fd);
        return EXIT_FAILURE;
    }

    disk_size = st.st_size;

    //printf("LINE 670\n");
    disk_file_desc[index] = fd;
    disk_mappings[index] = mmap(NULL, disk_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (disk_mappings[index] == MAP_FAILED)
    {
        printf("Failed mapping in %s at index %d\n", disk_path, index);
        close(fd);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

struct wfs_inode *get_inode(int inum)
{
    return (struct wfs_inode *)((char *)disk_mappings[0] + sb->i_blocks_ptr + inum * BLOCK_SIZE);
}

// Helper function to find a directory entry in the given inode
int find_entry_in_inode(struct wfs_inode *inode, const char *name, int *entry_inum)
{
    for (int i = 0; i < N_BLOCKS && inode->blocks[i] != -1; i++)
    {
        struct wfs_dentry *entries = get_dentry_entries(inode->blocks[i]);

        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            if (entries[j].num != -1 && strcmp(entries[j].name, name) == 0)
            {
                *entry_inum = entries[j].num; // Store the inode number of the found entry
                return 1; // Entry found
            }
        }
    }
    return 0; // Entry not found
}

// Helper function to get directory entries from block
struct wfs_dentry *get_dentry_entries(int block_num)
{
    struct wfs_dentry *entries;

    if (sb->raid_mode == 0) // RAID 0
    {
        int disk_num = block_num % num_disks;
        int block_offset = block_num / num_disks;
        entries = (struct wfs_dentry *)((char *)disk_mappings[disk_num] + sb->d_blocks_ptr + block_offset * BLOCK_SIZE);
    }
    else // RAID 1
    {
        entries = (struct wfs_dentry *)((char *)disk_mappings[0] + sb->d_blocks_ptr + block_num * BLOCK_SIZE);
    }

    return entries;
}

int find_inode(const char *path)
{
    printf("Finding inode with path %s\n", path);

    if (strcmp(path, "/") == 0)
    {
        return EXIT_SUCCESS; // Root inode
    }

    path++; // Skip leading /
    char *curr_path = strdup(path);
    char *component = strtok(curr_path, "/");

    // Start at root inode
    int curr_inum = 0;
 
    struct wfs_inode *curr_inode = get_inode(curr_inum);

    while (component)
    {
        printf("FIND_INODE: Looking for component: %s in inode %d\n", component, curr_inum);

        if (!find_entry_in_inode(curr_inode, component, &curr_inum))
        {
            free(curr_path);
            return -1; // Component not found
        }

        // Update inode for the next component
        curr_inode = get_inode(curr_inum);
        component = strtok(NULL, "/");
    }

    free(curr_path);
    return curr_inum;
}

// Function to find the first free bit in the bitmap and set it for a specific disk
int find_and_set_free_bit(unsigned char *bitmap, int total_items, int *free_num)
{
    for (int byte = 0; byte < (total_items + 7) / 8; byte++)
    {
        if (bitmap[byte] != 0xFF)  // Skip fully used bytes
        {
            for (int bit = 0; bit < 8; bit++)
            {
                if (!(bitmap[byte] & (1 << bit)))  // Free bit found
                {
                    *free_num = byte * 8 + bit;
                    if (*free_num >= total_items)
                        continue;

                    bitmap[byte] |= (1 << bit);  // Set the bit
                    return 1;  // Successfully set the bit
                }
            }
        }
    }
    return 0;  // No free bit found
}

// Function to handle setting the free bit for RAID 0 (data blocks)
int handle_raid0(int disk, unsigned char *bitmap, int total_items, int *free_num)
{
    if (find_and_set_free_bit(bitmap, total_items, free_num))
    {
        *free_num = *free_num * num_disks + disk;  // Calculate global block number
        return *free_num;
    }
    return -1;
}

// Function to handle setting the free bit for RAID 1 (or inode handling)
int handle_raid1_or_inode(unsigned char *bitmap, int total_items, int *free_num)
{
    if (find_and_set_free_bit(bitmap, total_items, free_num))
    {
        return *free_num;
    }
    return -1;
}

// Function to find the free block for inodes or data blocks
int find_free(int is_inode)
{
    off_t bitmap_offset;
    int total_items;

    // Set bitmap_offset and total_items based on whether it's inode or data block
    if (is_inode) {
        bitmap_offset = sb->i_bitmap_ptr;
        total_items = sb->num_inodes;
    } else {
        bitmap_offset = sb->d_bitmap_ptr;
        total_items = sb->num_data_blocks;
    }

    int free_num = -1;

    // For RAID 0 data blocks, we need to check each disk separately
    if (!is_inode && sb->raid_mode == 0)
    {
        // Check each disk in order for free block
        for (int disk = 0; disk < num_disks; disk++)
        {
            unsigned char *bitmap = (unsigned char *)((char *)disk_mappings[disk] + bitmap_offset);
            int result = handle_raid0(disk, bitmap, total_items, &free_num);
            if (result != -1)
                return result;
        }
    }
    else
    {
        // Start from disk 0 since we'll set all disks
        unsigned char *bitmap = (unsigned char *)((char *)disk_mappings[0] + bitmap_offset);
        int result = handle_raid1_or_inode(bitmap, total_items, &free_num);
        if (result != -1)
        {
            // Set bit on all disks for RAID 1 or inode
            for (int d = 0; d < num_disks; d++)
            {
                unsigned char *disk_bitmap = (unsigned char *)((char *)disk_mappings[d] + bitmap_offset);
                disk_bitmap[free_num / 8] |= (1 << (free_num % 8));  // Set the bit on all disks
            }
            return free_num;
        }
    }
    return -1;  // No free block found
}


void copy_disk(int inode_num, struct wfs_inode *source_inode)
{
    // Mirror to ALL disks
    for (int disk = 0; disk < num_disks; disk++)
    {
        void *copy_disk = (void *)((char *)disk_mappings[disk] + sb->i_blocks_ptr + inode_num * BLOCK_SIZE);
        memcpy(copy_disk, source_inode, BLOCK_SIZE);
    }
}

int cfree_entry_r0(int block_num)
{
    printf("Checking block %d (r0)\n", block_num);

    int disk_num = block_num % num_disks;
    int block_offset = block_num / num_disks;
    struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[disk_num] +
                                                       sb->d_blocks_ptr + block_offset * BLOCK_SIZE);

    for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
    {
        printf("Checking entry index %d: entry number= %d\n", j, entries[j].num);
        if (entries[j].num == -1)
        {
            printf("Found a free entry in existing block (r0)\n");
            return 1; // Found free entry
        }
    }
    return EXIT_SUCCESS; // No free entry found
}

int cfree_entry_r1(int block_num)
{
    printf("Checking block %d (R1)\n", block_num);

    struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[0] +
                                                       sb->d_blocks_ptr + block_num * BLOCK_SIZE);

    for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
    {
        if (entries[j].num == -1)
        {
            printf("Found free entry in existing block (RAID 1)\n");
            return 1; // Found free entry
        }
    }
    return EXIT_SUCCESS; // No free entry found
}

void init_new_r0(int new_block)
{
    printf("Initializing new block %d (R0)\n", new_block);

    int disk_num = new_block % num_disks;
    int block_offset = new_block / num_disks;
    struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[disk_num] +
                                                       sb->d_blocks_ptr + block_offset * BLOCK_SIZE);

    for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
    {
        entries[j].num = -1;       // Mark as free
        entries[j].name[0] = '\0'; // Clear name
    }
}

void init_new_r1(int new_block)
{
    printf("Initializing new block %d (R1)\n", new_block);

    for (int disk = 0; disk < num_disks; disk++)
    {
        struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[disk] +
                                                           sb->d_blocks_ptr + new_block * BLOCK_SIZE);
        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            entries[j].num = -1;       // Mark as free
            entries[j].name[0] = '\0'; // Clear name
        }
    }
}

// Finds parent inode
int find_dir_block(struct wfs_inode *dir_inode)
{
    printf("Entering find_dir_block -------------\n");

    // Check all existing blocks
    for (int i = 0; i < N_BLOCKS && dir_inode->blocks[i] != -1; i++)
    {
        int block_num = dir_inode->blocks[i];

        // Check for free entry in the block based on RAID mode
        int free_entry_found = 0;
        if (sb->raid_mode == 0)
        {
            free_entry_found = cfree_entry_r0(block_num); // RAID 0
        }
        else
        {
            free_entry_found = cfree_entry_r1(block_num); // RAID 1
        }

        if (free_entry_found)
        {
            return block_num; // Found block with free entry
        }
    }

    // No free entry found in existing blocks, find first empty block slot
    printf("No free entries available\n");

    for (int i = 0; i < N_BLOCKS; i++)
    {
        printf("Index = %d, Block = %ld\n", i, dir_inode->blocks[i]);
        if (dir_inode->blocks[i] == -1)
        {
            // Allocate new block
            int new_block = find_free(0);
            if (new_block < 0)
            {
                return -1; // Directory is full or allocation failed
            }

            // Initialize the new block based on RAID mode
            if (sb->raid_mode == 0)
            {
                init_new_r0(new_block); // RAID 0
            }
            else
            {
                init_new_r1(new_block); // RAID 1
            }

            // Assign the new block to the directory inode
            dir_inode->blocks[i] = new_block;
            printf("New block allocated and initialized\n");
            return new_block;
        }
    }

    printf("Directory is full\n");
    return -1; // Directory is full (no more block slots)
}

// Updates parent directory to link new child (file / directory)
void add_dir_entry(int block_num, const char *filename, int inode_num)
{
    printf("[DEBUG] Entering add_dir_entry\n");
    printf("[INFO] Block=%d, Filename=%s, Inode=%d\n", block_num, filename, inode_num);

    // Helper variables for the directory entry size
    size_t entry_count = BLOCK_SIZE / sizeof(struct wfs_dentry);

    // RAID 0: Single disk mapping
    if (sb->raid_mode == 0)
    {
        int disk_num = block_num % num_disks;
        int block_offset = block_num / num_disks;

        // Locate entries
        struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[disk_num] +
                                                           sb->d_blocks_ptr +
                                                           block_offset * BLOCK_SIZE);

        // Add the directory entry
        for (int i = 0; i < entry_count; i++)
        {
            if (entries[i].num == -1) // Free entry found
            {
                printf("[INFO] Found free entry at index %d on disk %d\n", i, disk_num);

                strncpy(entries[i].name, filename, sizeof(entries[i].name) - 1);
                entries[i].name[sizeof(entries[i].name) - 1] = '\0'; // Ensure null termination
                entries[i].num = inode_num;
                return;
            }
        }
    }
    // RAID 1: Mirrored disks
    else if (sb->raid_mode == 1)
    {
        for (int disk = 0; disk < num_disks; disk++)
        {
            struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[disk] +
                                                               sb->d_blocks_ptr +
                                                               block_num * BLOCK_SIZE);

            for (int i = 0; i < entry_count; i++)
            {
                if (entries[i].num == -1) // Free entry found
                {
                    printf("[INFO] Found free entry at index %d on disk %d\n", i, disk);

                    strncpy(entries[i].name, filename, sizeof(entries[i].name) - 1);
                    entries[i].name[sizeof(entries[i].name) - 1] = '\0'; // Ensure null termination
                    entries[i].num = inode_num;

                    break; // Exit inner loop for RAID 1, as all disks must be updated
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
    // Return error if the index is negative
    if (index < 0)
        return -1;

    // Handle direct blocks (0 to D_BLOCK - 1)
    if (index < D_BLOCK)
    {
        inode->blocks[index] = block_num;
        return EXIT_SUCCESS;
    }

    // Handle indirect blocks (D_BLOCK to D_BLOCK + size of indirect block)
    if (index < D_BLOCK + BLOCK_SIZE / sizeof(off_t))
    {
        // Allocate indirect block if not already assigned
        if (inode->blocks[IND_BLOCK] == -1)
        {
            off_t indirect_block = find_free(0); // Allocate a new data block for the indirect block
            if (indirect_block == -1)
                return -1; // No free block available

            // Initialize indirect block with -1 values (indicating empty)
            off_t *indirect_table = (off_t *)get_block_addr(indirect_block);
            memset(indirect_table, -1, BLOCK_SIZE); // Clear the block

            // If RAID 1, write the indirect block to the mirror disks
            if (sb->raid_mode == 1)
            {
                for (int disk = 1; disk < num_disks; disk++)
                {
                    off_t *mirror_table = (off_t *)((char *)disk_mappings[disk] + sb->d_blocks_ptr + indirect_block * BLOCK_SIZE);
                    memcpy(mirror_table, indirect_table, BLOCK_SIZE);
                }
            }

            // Assign the indirect block to the inode
            inode->blocks[IND_BLOCK] = indirect_block;
        }

        // Set the block number in the indirect block's table
        off_t *indirect_table = (off_t *)get_block_addr(inode->blocks[IND_BLOCK]);
        indirect_table[index - D_BLOCK] = block_num;

        // If RAID 1, mirror the change to other disks
        if (sb->raid_mode == 1)
        {
            for (int disk = 1; disk < num_disks; disk++)
            {
                off_t *mirror_table = (off_t *)((char *)disk_mappings[disk] + sb->d_blocks_ptr + inode->blocks[IND_BLOCK] * BLOCK_SIZE);
                memcpy(mirror_table, indirect_table, BLOCK_SIZE);
            }
        }

        return EXIT_SUCCESS;
    }

    // If index is out of range, return an error
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
            char *block_addr = (char *)disk_mappings[disk] + sb->d_blocks_ptr + block_num * BLOCK_SIZE;
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
        return (char *)disk_mappings[disk_num] + sb->d_blocks_ptr + block_offset * BLOCK_SIZE;
    }
    else if (sb->raid_mode == 1)
    { // RAID 1
        return (char *)disk_mappings[0] + sb->d_blocks_ptr + block_num * BLOCK_SIZE;
    }
    else
    {
        return find_majority() + sb->d_blocks_ptr + block_num * BLOCK_SIZE;
    }
}

// returns data block present on majority of disks
char *find_majority()
{
    int disk_major[num_disks];
    memset(disk_major, 0, sizeof(disk_major)); // Initialize disk_major array to 0

    for (int disk = 0; disk < num_disks; disk++)
    {
        char *curr_block = (char *)(disk_mappings[disk]);

        for (int comp_disk = 0; comp_disk < num_disks; comp_disk++)
        {
            if (disk != comp_disk && memcmp(curr_block, (char *)(disk_mappings[comp_disk]), disk_size) == 0)
            {
                disk_major[disk]++;
            }
        }
    }

    // Find the disk with the maximum matches
    int majority_disk = 0;
    for (int disk = 1; disk < num_disks; disk++) // Start from 1, as majority_disk is initialized to 0
    {
        if (disk_major[disk] > disk_major[majority_disk])
        {
            majority_disk = disk;
        }
    }

    return (char *)disk_mappings[majority_disk];
}

// Helper function to process RAID 0 dentry removal
int remove_dentry_raid0(int block_num, const char *filename)
{
    int disk_num = block_num % num_disks;
    int block_offset = block_num / num_disks;

    struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[disk_num] +
                                                       sb->d_blocks_ptr + block_offset * BLOCK_SIZE);

    for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
    {
        if (entries[j].num != -1 && strcmp(entries[j].name, filename) == 0)
        {
            int inode_num = entries[j].num;
            entries[j].num = -1; // Mark entry as free
            return inode_num;
        }
    }
    return -1;
}

// Helper function to process RAID 1 dentry removal
int remove_dentry_raid1(int block_num, const char *filename)
{
    int found_inum = -1;

    for (int disk = 0; disk < num_disks; disk++)
    {
        struct wfs_dentry *entries = (struct wfs_dentry *)((char *)disk_mappings[disk] +
                                                           sb->d_blocks_ptr + block_num * BLOCK_SIZE);

        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            if (entries[j].num != -1 && strcmp(entries[j].name, filename) == 0)
            {
                found_inum = entries[j].num;
                entries[j].num = -1; // Mark entry as free
                break;
            }
        }
    }
    return found_inum;
}

// Main function to remove directory entry
int remove_dentry(struct wfs_inode *dir_inode, const char *filename)
{
    printf("[DEBUG] Removing dentry for %s\n", filename);

    for (int i = 0; i < N_BLOCKS && dir_inode->blocks[i] != -1; i++)
    {
        int block_num = dir_inode->blocks[i];

        if (sb->raid_mode == 0)
        {
            int inode_num = remove_dentry_raid0(block_num, filename);
            if (inode_num != -1)
                return inode_num;
        }
        else
        {
            int inode_num = remove_dentry_raid1(block_num, filename);
            if (inode_num != -1)
                return inode_num;
        }
    }

    return -1; // Dentry not found
}

void free_inode_and_blocks(struct wfs_inode *inode, int inode_num)
{
    printf("[DEBUG] Freeing inode %d\n", inode_num);

    // Free direct blocks
    for (int i = 0; i < D_BLOCK; i++)
    {
        if (inode->blocks[i] != -1)
        {
            printf("[INFO] Freeing direct block %ld\n", inode->blocks[i]);
            clear_bitmap_bit(sb->d_bitmap_ptr, inode->blocks[i]);
        }
    }

    // Free indirect blocks
    if (inode->blocks[IND_BLOCK] != -1)
    {
        printf("[INFO] Freeing indirect block %ld\n", inode->blocks[IND_BLOCK]);
        off_t *indirect_table = (off_t *)get_block_addr(inode->blocks[IND_BLOCK]);

        for (int i = 0; i < BLOCK_SIZE / sizeof(off_t); i++)
        {
            if (indirect_table[i] == -1)
                break;

            printf("[INFO] Freeing indirect data block %ld\n", indirect_table[i]);
            clear_bitmap_bit(sb->d_bitmap_ptr, indirect_table[i]);
        }

        // Free the indirect block itself
        clear_bitmap_bit(sb->d_bitmap_ptr, inode->blocks[IND_BLOCK]);
    }

    // Free the inode itself
    printf("[INFO] Freeing inode %d\n", inode_num);
    clear_bitmap_bit(sb->i_bitmap_ptr, inode_num);
}

void clear_bitmap_bit(off_t bitmap_offset, int item_num)
{
    printf("[DEBUG] Clearing item %d at bitmap offset %ld\n", item_num, bitmap_offset);

    if (bitmap_offset == sb->i_bitmap_ptr || sb->raid_mode == 1)
    {
        // inodes or RAID 1
        for (int disk = 0; disk < num_disks; disk++)
        {
            unsigned char *bitmap = (unsigned char *)((char *)disk_mappings[disk] + bitmap_offset); // clear all disks
            int byte = item_num / 8;
            int bit = item_num % 8;
            bitmap[byte] &= ~(1 << bit);
        }
    }
    else // RAID 0
    {

        // Determine which disk owns this block
        int disk_num = item_num % num_disks;
        // Determine local block number within that disk
        int local_num = item_num / num_disks;
        // Determine the byte and bit position in the bitmap
        int byte = local_num / 8;
        int bit = local_num % 8;

        unsigned char *bitmap = (unsigned char *)((char *)disk_mappings[disk_num] + bitmap_offset);
        // Clear the bit
        bitmap[byte] &= ~(1 << bit);
    }
}

void process_dir_entries(int block_num, void *buffer, fuse_fill_dir_t filler)
{
    struct wfs_dentry *entries = (struct wfs_dentry *)get_block_addr(block_num);
    printf("Reading block %d\n", block_num);
    for (int i = 0; i < BLOCK_SIZE / sizeof(struct wfs_dentry); i++)
    {
        if (entries[i].num > 0)
        {
            printf("Found directory entry with filename'%s', inode=%d\n", entries[i].name, entries[i].num);
            filler(buffer, entries[i].name, NULL, 0);
        }
    }
}