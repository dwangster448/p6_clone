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

#define MAX_DISKS 3
#define MAX_PATH_LEN 10
#define MAX_NAME_LEN 26
#define ENTRIES_PER_BLOCK (BLOCK_SIZE / sizeof(struct wfs_dentry))

#define MAX_FILE_SIZE (26)
#define DIRECTORY_TYPE (S_IFDIR) // Or use S_IFDIR directly
// #define MAX_FILE_SIZE (BLOCK_SIZE * 1)
#define ROOT_INODE_NUM 0 // Assuming the root inode is 0, adjust based on your design

// // Declare global variables
// extern struct wfs_sb superblock;
// extern FILE *disks[];
// extern uint8_t raid_mode;
// extern size_t num_disks;

// Global variable for RAID mode
// int raid_mode = -1; // Default to -1, meaning no RAID mode

// Global variables
int raid_mode = -1;
// char *disk_paths[MAX_DISKS];
int num_disks;
uint8_t *inode_bitmap;
uint8_t *data_bitmap;
struct wfs_inode *inode_table;
void **disk_mappings;
struct wfs_sb *superblock;
int disk_count = 0;
char *disks[MAX_DISKS] = {NULL, NULL, NULL};
//int disks[MAX_DISKS]; // Declare disks as file descriptors

char *mount_point = NULL;

static int disk_fd = -1;           // Disk file descriptor
static struct wfs_sb sb;           // Superblock
static int disk_fds[MAX_DISKS] = { -1 }; // Array to hold file descriptors for each disk

// Helper functions prototypes
int initialize_raid(int raid_mode, char *disks[], int disk_count);
int retrieve_raid_mode(const char *disk_path);
int prepare_fuse_args(int argc, char *argv[], int disk_count, char *fuse_argv[], int *fuse_argc);
int param_check(int argc, char *argv[], char *disks[], int *disk_count, char **mount_point, char *fuse_argv[], int *fuse_argc);
void validate_raid_config(int raid_mode, int disk_count);
int read_superblock(FILE *disk, struct wfs_sb *sb);

int allocate_inode(struct wfs_inode *inode, uint16_t mode);
int find_free_data_block();
void free_inode(int inode_number);
void free_data_block(int block_number);

int resolve_path_to_inode(const char *path, struct wfs_inode *inode);
int wfs_lookup(const char *path);
struct wfs_inode *wfs_get_inode(int inode_num);
int wfs_get_parent_inode(const char *path);
int wfs_lookup_in_dir(int parent_inode, const char *name);
int wfs_read_data_block(int block_num, void *buffer, size_t size);
int read_block(int block_num, void *buffer, size_t size);
int wfs_allocate_inode(struct wfs_inode *inode, uint16_t mode);
int wfs_allocate_data_block(void); // Prototype for allocating a data block
void wfs_write_inode(int inode_num, struct wfs_inode *inode);
void wfs_write_data_block(int block_num, void *data, size_t size);
int wfs_add_dir_entry(int parent_inode, const char *path, int inode_num);
int wfs_read_inode(int inode_num, struct wfs_inode *inode);
void wfs_free_data_block(int block);
void setup_bitmaps();
void initialize_bitmaps();

int read_inode(int inode_num, struct wfs_inode *inode);
off_t calculate_block_offset(int block_num);
int read_data_block(off_t block_offset, void *buffer, size_t size);



static inline int max(int a, int b)
{
    return (a > b) ? a : b;
}

void setup_bitmaps()
{
    size_t inode_bitmap_size = (superblock->num_inodes + 7) / 8; // Rounded up to nearest byte
    size_t data_bitmap_size = (superblock->num_data_blocks + 7) / 8;

    inode_bitmap = malloc(inode_bitmap_size);
    if (!inode_bitmap)
    {
        fprintf(stderr, "[ERROR] Failed to allocate memory for inode bitmap.\n");
        exit(EXIT_FAILURE);
    }

    data_bitmap = malloc(data_bitmap_size);
    if (!data_bitmap)
    {
        fprintf(stderr, "[ERROR] Failed to allocate memory for data bitmap.\n");
        exit(EXIT_FAILURE);
    }

    printf("[INFO] Bitmaps allocated: inode_bitmap_size=%zu, data_bitmap_size=%zu\n",
           inode_bitmap_size, data_bitmap_size);
}

void initialize_bitmaps(int fd)
{
    size_t inode_bitmap_size = (superblock->num_inodes + 7) / 8;
    size_t data_bitmap_size = (superblock->num_data_blocks + 7) / 8;

    // Read inode bitmap from disk
    pread(fd, inode_bitmap, inode_bitmap_size, superblock->i_bitmap_ptr);

    // Read data bitmap from disk
    pread(fd, data_bitmap, data_bitmap_size, superblock->d_bitmap_ptr);

    printf("[INFO] Bitmaps initialized from disk.\n");
}

void save_bitmaps_to_disk(int fd)
{
    size_t inode_bitmap_size = (superblock->num_inodes + 7) / 8;
    size_t data_bitmap_size = (superblock->num_data_blocks + 7) / 8;

    // Write inode bitmap to disk
    pwrite(fd, inode_bitmap, inode_bitmap_size, superblock->i_bitmap_ptr);

    // Write data bitmap to disk
    pwrite(fd, data_bitmap, data_bitmap_size, superblock->d_bitmap_ptr);

    printf("[INFO] Bitmaps saved to disk.\n");
}

int wfs_allocate_data_block()
{
    printf("Entering wfs_allocate_data_block()\n");

    // Get the data block bitmap location
    uint8_t *data_block_bitmap = (uint8_t *)(disk_mappings[0]) + superblock->d_bitmap_ptr;
    printf("Data block bitmap located at: %p\n", data_block_bitmap);

    // Find first free data block in the bitmap
    for (int i = 0; i < superblock->num_data_blocks; i++)
    {
        printf("Checking data block %d\n", i);
        // Check if data block is free (bit is 0)
        if (!(data_block_bitmap[i / 8] & (1 << (i % 8))))
        {
            printf("Found free data block %d\n", i);
            // Mark the data block as used
            data_block_bitmap[i / 8] |= (1 << (i % 8));

            // Return the data block number
            return i;
        }
    }

    printf("No free data blocks found\n");
    return -1; // No free data blocks
}

int wfs_read_inode(int inode_num, struct wfs_inode *inode)
{
    printf("Entering wfs_read_inode(inode_num=%d)\n", inode_num);

    // Check if the inode number is valid
    if (inode_num < 0 || inode_num >= superblock->num_inodes)
    {
        printf("Invalid inode number: %d\n", inode_num);
        return -EINVAL; // Invalid inode number
    }

    // Calculate the position of the inode in the inode table
    size_t inode_table_offset = superblock->i_blocks_ptr + inode_num * sizeof(struct wfs_inode);
    printf("Inode table offset: %zu\n", inode_table_offset);

    // Read the inode data from disk
    printf("Reading inode data into buffer\n");
    memcpy(inode, (uint8_t *)disk_mappings[0] + inode_table_offset, sizeof(struct wfs_inode));

    printf("Inode read successfully\n");
    return EXIT_SUCCESS; // Success
}

int read_block(int block_num, void *buffer, size_t size)
{
    printf("Entering read_block(block_num=%d, size=%zu)\n", block_num, size);

    if (block_num < 0 || block_num >= N_BLOCKS)
    {
        printf("Invalid block number: %d\n", block_num);
        return -EINVAL; // Invalid block number error
    }

    // Calculate the offset in the disk (e.g., block size * block number)
    size_t block_offset = block_num * BLOCK_SIZE;
    printf("Block offset: %zu\n", block_offset);

    FILE *disk = NULL; // Assume you have a mechanism to choose the disk based on RAID mode

    if (raid_mode == 0)
    {
        printf("RAID mode 0: Opening disk %p for reading\n", disk_mappings[0]);
        disk = fopen(disk_mappings[0], "rb"); // Open the first disk for reading (RAID 0)
    }
    else if (raid_mode == 1)
    {
        printf("RAID mode 1: Opening disk %p for reading\n", disk_mappings[0]);
        disk = fopen(disk_mappings[0], "rb"); // Open the first disk for reading (RAID 1)
    }
    else if (raid_mode == 2)
    {
        printf("RAID mode 2: Implement logic for RAID 5 or other modes\n");
        // Implement logic for RAID 5 or other modes if applicable
    }

    if (!disk)
    {
        printf("Error opening disk\n");
        return -EIO; // Error opening the disk
    }

    // Move the file pointer to the correct position to read the block
    fseek(disk, block_offset, SEEK_SET);

    // Read the data from the disk into the buffer
    size_t bytes_read = fread(buffer, 1, size, disk);
    if (bytes_read != size)
    {
        printf("Error reading from the disk, expected %zu bytes, got %zu\n", size, bytes_read);
        fclose(disk);
        return -EIO; // Error reading from the disk
    }

    // Close the disk after reading
    fclose(disk);

    printf("Read block %d successfully\n", block_num);
    return EXIT_SUCCESS; // Success
}

int wfs_add_dir_entry(int parent_inode, const char *path, int inode_num)
{
    printf("Entering wfs_add_dir_entry(parent_inode=%d, path=%s, inode_num=%d)\n", parent_inode, path, inode_num);

    // Step 1: Retrieve the parent inode to access its data blocks
    struct wfs_inode parent_inode_data;
    wfs_read_inode(parent_inode, &parent_inode_data);

    // Declare dir_entries outside the loop so it is accessible in the entire function
    struct wfs_dentry *dir_entries = NULL;

    // Step 2: Find a free space in the parent's data blocks to add the new entry
    for (int i = 0; i < N_BLOCKS; i++)
    {
        printf("Checking parent inode's block %d\n", i);
        if (parent_inode_data.blocks[i] == 0)
        {
            continue; // No block to check
        }

        // Read the directory block to add the new entry
        size_t dir_size = BLOCK_SIZE;
        dir_entries = (struct wfs_dentry *)malloc(dir_size);
        if (dir_entries == NULL)
        {
            printf("Memory allocation failed for directory entries\n");
            return -ENOMEM; // Return error if memory allocation fails
        }

        wfs_read_data_block(parent_inode_data.blocks[i], dir_entries, dir_size);

        // Step 3: Add the new directory entry (name and inode number)
        int entry_idx = 0;
        while (entry_idx < dir_size / sizeof(struct wfs_dentry) && dir_entries[entry_idx].num != 0)
        {
            entry_idx++;
        }

        if (entry_idx < dir_size / sizeof(struct wfs_dentry))
        {
            printf("Adding new entry for %s with inode %d\n", path, inode_num);
            strcpy(dir_entries[entry_idx].name, path);
            dir_entries[entry_idx].num = inode_num;

            // Write the updated directory entries back to the block
            wfs_write_data_block(parent_inode_data.blocks[i], dir_entries, dir_size);
            free(dir_entries); // Free memory after use
            printf("Directory entry added successfully\n");
            return EXIT_SUCCESS; // Successfully added the entry
        }

        // Free the allocated memory before continuing to the next block
        free(dir_entries);
        dir_entries = NULL; // Reset the pointer to prevent using stale memory
    }

    printf("No space found to add directory entry\n");
    return -ENOSPC; // No space to add the directory entry
}

void wfs_write_data_block(int block_num, void *data, size_t size)
{
    printf("Entering wfs_write_data_block(block_num=%d, size=%zu)\n", block_num, size);

    // Get the base address of the disk mapping for disk 0
    uint8_t *disk_base = (uint8_t *)(disk_mappings[0]);

    // Calculate the address of the data block on the disk
    uint8_t *data_block = disk_base + superblock->d_blocks_ptr + block_num * BLOCK_SIZE;
    printf("Data block address: %p\n", data_block);

    // Write the data to the data block
    memcpy(data_block, data, size);
    printf("Data written to block %d\n", block_num);
}

void wfs_write_inode(int inode_num, struct wfs_inode *inode)
{
    printf("Entering wfs_write_inode(inode_num=%d)\n", inode_num);

    // Get the base address of the disk mapping for disk 0
    uint8_t *disk_base = (uint8_t *)(disk_mappings[0]);

    // Calculate the inode table's address using i_blocks_ptr
    uint8_t *inode_table = disk_base + superblock->i_blocks_ptr;

    // Calculate the offset of the inode in the inode table
    uint32_t inode_offset = inode_num * sizeof(struct wfs_inode);
    printf("Inode offset in table: %u\n", inode_offset);

    // Write the inode data to the disk
    memcpy(inode_table + inode_offset, inode, sizeof(struct wfs_inode));
    printf("Inode data written to disk\n");
}

int wfs_read_data_block(int block_num, void *buffer, size_t size)
{
    printf("Entering wfs_read_data_block(block_num=%d, size=%zu)\n", block_num, size);

    if (block_num < 0 || block_num >= N_BLOCKS)
    {
        printf("Error: Invalid block number: %d\n", block_num);
        return -EINVAL; // Invalid block number error
    }

    // Assuming you have some function to read data from storage
    int result = read_block(block_num, buffer, size); // `read_block` would be your actual disk read operation
    if (result != 0)
    {
        printf("Error: Failed to read block %d\n", block_num);
        return -EIO; // Error reading from disk
    }

    printf("Successfully read block %d\n", block_num);
    return EXIT_SUCCESS; // Success
}

int wfs_lookup_in_dir(int parent_inode, const char *name)
{
    printf("Entering wfs_lookup_in_dir(parent_inode=%d, name=%s)\n", parent_inode, name);

    struct wfs_inode *parent_inode_data = wfs_get_inode(parent_inode);
    if (!parent_inode_data)
    {
        printf("Error: Parent inode %d does not exist\n", parent_inode);
        return -ENOENT; // Parent inode doesn't exist
    }

    // Iterate over the blocks associated with the parent directory
    for (int i = 0; i < N_BLOCKS; i++)
    {
        if (parent_inode_data->blocks[i] == 0)
        {
            printf("No more blocks in the parent directory.\n");
            break; // No more blocks
        }

        struct wfs_dentry dir_entries[BLOCK_SIZE / sizeof(struct wfs_dentry)];
        if (wfs_read_data_block(parent_inode_data->blocks[i], dir_entries, sizeof(dir_entries)) != 0)
        {
            printf("Error: Failed to read directory block %d\n", i);
            return -EIO; // Error reading data block
        }

        // Iterate through directory entries to find a match
        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            if (dir_entries[j].num != 0 && strcmp(dir_entries[j].name, name) == 0)
            {
                printf("Found entry %s with inode %d\n", name, dir_entries[j].num);
                return dir_entries[j].num; // Return the inode number of the found entry
            }
        }
    }

    printf("Error: Name %s not found in any of the directory blocks\n", name);
    return -ENOENT; // Name not found in any of the directory blocks
}

int read_data_block(off_t block_offset, void *buffer, size_t size)
{
    if (pread(disk_fd, buffer, size, block_offset) != size)
    {
        perror("[ERROR] Failed to read data block");
        return -EIO;
    }

    return 0;
}


off_t calculate_block_offset(int block_num)
{
    return sb.d_blocks_ptr + (block_num * BLOCK_SIZE);
}

struct wfs_inode *wfs_get_inode(int inode_num)
{
    printf("Entering wfs_get_inode(inode_num=%d)\n", inode_num);

    // Assuming you have a global inode table or array:
    // For example, let's assume inode_table is an array of inodes
    if (inode_num < 0 || inode_num >= superblock->num_inodes)
    {
        printf("Error: Invalid inode number: %d\n", inode_num);
        return NULL; // Invalid inode number
    }

    printf("Returning inode data for inode %d\n", inode_num);
    return &inode_table[inode_num]; // Return the inode structure from the inode table
}

int resolve_path_to_inode(const char *path, struct wfs_inode *inode)
{
    printf("Resolving path %s to inode\n", path);

    int inode_num = wfs_lookup(path);
    if (inode_num == -1)
    {
        printf("Error: Path %s not found\n", path);
        return -ENOENT; // Path not found
    }

    struct wfs_inode *found_inode = wfs_get_inode(inode_num);
    if (!found_inode)
    {
        printf("Error: Failed to retrieve inode for %s\n", path);
        return -EIO; // Error reading inode
    }

    // Copy the inode data to the provided struct
    memcpy(inode, found_inode, sizeof(struct wfs_inode));

    printf("Resolved path %s to inode %d\n", path, inode_num);
    return inode_num; // Return inode number if successful
}

int read_inode(int inode_num, struct wfs_inode *inode)
{
    // Calculate the offset in the inode table
    off_t offset = sb.i_blocks_ptr + (inode_num * sizeof(struct wfs_inode));

    // Read the inode from the disk
    if (pread(disk_fd, inode, sizeof(struct wfs_inode), offset) != sizeof(struct wfs_inode))
    {
        perror("[ERROR] Failed to read inode");
        return -EIO;
    }

    return 0;
}

int get_inode_from_path(const char *path, int *inode_num, struct wfs_inode *inode)
{
    printf("[DEBUG] Resolving path: %s\n", path);

    if (path == NULL || inode_num == NULL || inode == NULL)
    {
        fprintf(stderr, "[ERROR] Invalid arguments to get_inode_from_path.\n");
        return -EINVAL;
    }

    if (strcmp(path, "/") == 0)
    {
        // Root directory special case
        *inode_num = ROOT_INODE_NUM;
        if (read_inode(ROOT_INODE_NUM, inode) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to read root inode.\n");
            return -EIO;
        }
        return 0;
    }

    // Tokenize the path into components
    char *path_copy = strdup(path);
    if (path_copy == NULL)
    {
        perror("[ERROR] strdup failed");
        return -ENOMEM;
    }

    char *token = strtok(path_copy, "/");
    int current_inode_num = ROOT_INODE_NUM;
    struct wfs_inode current_inode;

    if (read_inode(current_inode_num, &current_inode) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to read root inode.\n");
        free(path_copy);
        return -EIO;
    }

    // Traverse the path components
    while (token != NULL)
    {
        if (!S_ISDIR(current_inode.mode))
        {
            fprintf(stderr, "[ERROR] %s is not a directory.\n", token);
            free(path_copy);
            return -ENOTDIR;
        }

        // Find the next component in the directory
        int found = 0;
        for (int i = 0; i < N_BLOCKS && current_inode.blocks[i] != 0; i++)
        {
            struct wfs_dentry entries[BLOCK_SIZE / sizeof(struct wfs_dentry)];
            off_t block_offset = calculate_block_offset(current_inode.blocks[i]);

            if (read_data_block(block_offset, entries, sizeof(entries)) != 0)
            {
                fprintf(stderr, "[ERROR] Failed to read directory block.\n");
                free(path_copy);
                return -EIO;
            }

            // Iterate through entries in the block
            for (size_t j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
            {
                if (entries[j].num != 0 && strcmp(entries[j].name, token) == 0)
                {
                    // Match found
                    current_inode_num = entries[j].num;
                    if (read_inode(current_inode_num, &current_inode) != 0)
                    {
                        fprintf(stderr, "[ERROR] Failed to read inode for %s.\n", token);
                        free(path_copy);
                        return -EIO;
                    }
                    found = 1;
                    break;
                }
            }
            if (found)
                break;
        }

        if (!found)
        {
            fprintf(stderr, "[ERROR] Path component %s not found.\n", token);
            free(path_copy);
            return -ENOENT;
        }

        token = strtok(NULL, "/");
    }

    // Path resolved successfully
    *inode_num = current_inode_num;
    memcpy(inode, &current_inode, sizeof(struct wfs_inode));
    free(path_copy);
    return 0;
}

// Basic getattr implementation
static int wfs_getattr(const char *path, struct stat *stbuf)
{
    printf("[DEBUG] getattr called for path: %s\n", path);

    memset(stbuf, 0, sizeof(struct stat));

    // Root directory handling
    if (strcmp(path, "/") == 0)
    {
        stbuf->st_mode = S_IFDIR | 0755; // Directory with permissions 755
        stbuf->st_nlink = 2;            // "." and ".."
        stbuf->st_uid = getuid();       // User ID of the process
        stbuf->st_gid = getgid();       // Group ID of the process
        stbuf->st_size = BLOCK_SIZE;    // Size of the root directory block
        return EXIT_SUCCESS;
    }

    // Get inode from the path
    int inode_num = -1;
    struct wfs_inode inode;

    if (get_inode_from_path(path, &inode_num, &inode) != 0)
    {
        printf("[DEBUG] Path not found: %s\n", path);
        return -ENOENT;
    }

    // Populate stat structure based on inode type and attributes
    stbuf->st_uid = inode.uid;
    stbuf->st_gid = inode.gid;
    stbuf->st_size = inode.size;
    stbuf->st_nlink = inode.nlinks;

    if (S_ISDIR(inode.mode)) // Directory
    {
        stbuf->st_mode = S_IFDIR | (inode.mode & 0777);
    }
    else if (S_ISREG(inode.mode)) // Regular file
    {
        stbuf->st_mode = S_IFREG | (inode.mode & 0777);
    }
    else
    {
        printf("[DEBUG] Unsupported inode type for path: %s\n", path);
        return -ENOENT; // Unsupported file type
    }

    stbuf->st_atime = inode.atim; // Access time
    stbuf->st_mtime = inode.mtim; // Modification time
    stbuf->st_ctime = inode.ctim; // Status change time

    return EXIT_SUCCESS;
}

// Helper function to get the inode of the parent directory from the given path
int wfs_get_parent_inode(const char *path)
{
    printf("Getting parent inode for path %s\n", path);

    // Special case: If the path is the root directory, return the root inode number
    if (strcmp(path, "/") == 0)
    {
        printf("Path is root, returning ROOT_INODE_NUM\n");
        return ROOT_INODE_NUM; // Assuming ROOT_INODE_NUM is a constant for the root inode
    }

    // Create a mutable copy of the path to work with
    char path_copy[MAX_NAME];
    strncpy(path_copy, path, MAX_NAME);

    // Initialize parent inode as the root inode (for paths not starting with "/")
    int parent_inode = ROOT_INODE_NUM;

    // Tokenize the path to get individual components
    char *token = strtok(path_copy, "/");
    while (token != NULL)
    {
        printf("Looking up component %s in parent inode %d\n", token, parent_inode);

        // Look up the current component in the parent directory
        int inode = wfs_lookup_in_dir(parent_inode, token);
        if (inode == -1)
        {
            printf("Error: Component %s not found in parent inode %d\n", token, parent_inode);
            return -ENOENT; // Component not found, return error
        }

        // Set the current inode as the parent inode for the next iteration
        parent_inode = inode;

        // Get the next path component
        token = strtok(NULL, "/");
    }

    printf("Parent inode for path %s is %d\n", path, parent_inode);
    // Return the parent inode of the final component
    return parent_inode;
}

// Function to perform the lookup of a file or directory in the filesystem
int wfs_lookup(const char *path)
{
    printf("Looking up path %s\n", path);

    // Step 1: Retrieve the parent directory inode
    int parent_inode_num = wfs_get_parent_inode(path);
    if (parent_inode_num == -1)
    {
        printf("Error: Parent directory not found for path %s\n", path);
        return -ENOENT; // Parent directory not found
    }

    // Step 2: Retrieve the inode of the parent directory
    struct wfs_inode *parent_inode = wfs_get_inode(parent_inode_num);
    if (!parent_inode)
    {
        printf("Error: Inode not found for parent directory %d\n", parent_inode_num);
        return -ENOENT; // Inode not found
    }

    // Step 3: Iterate over the directory blocks in the parent directory
    for (int i = 0; i < N_BLOCKS; i++)
    {
        if (parent_inode->blocks[i] == 0)
        {
            printf("No more blocks in parent directory\n");
            break; // No more blocks in the directory
        }

        // Step 4: Read the data block into memory
        struct wfs_dentry dir_entries[BLOCK_SIZE / sizeof(struct wfs_dentry)];
        if (wfs_read_data_block(parent_inode->blocks[i], dir_entries, sizeof(dir_entries)) != 0)
        {
            printf("Error: Failed to read directory block %d\n", i);
            return -EIO; // Error reading data block
        }

        // Step 5: Search for the entry with the matching name
        for (int j = 0; j < BLOCK_SIZE / sizeof(struct wfs_dentry); j++)
        {
            if (dir_entries[j].num != 0 && strcmp(dir_entries[j].name, path) == 0)
            {
                printf("Found directory entry %s with inode %d\n", path, dir_entries[j].num);
                // Entry found, return the inode number
                return dir_entries[j].num;
            }
        }
    }

    // Step 6: If we reach here, the file or directory was not found
    printf("Error: Entry %s not found\n", path);
    return -ENOENT; // Entry not found
}

static int get_bit(uint8_t *bitmap, size_t index) {
    return (bitmap[index / 8] >> (index % 8)) & 1;
}

static void set_bit(uint8_t *bitmap, size_t index) {
    bitmap[index / 8] |= (1 << (index % 8));
}

static int allocate_free_inode() {
    for (size_t i = 0; i < sb.num_inodes; i++) {
        if (!get_bit(inode_bitmap, i)) { // Check if the inode is free
            set_bit(inode_bitmap, i);   // Mark the inode as used
            return i;                   // Return the allocated inode number
        }
    }
    return -1; // No free inode available
}

static int allocate_free_data_block() {
    for (size_t i = 0; i < sb.num_data_blocks; i++) {
        if (!get_bit(data_bitmap, i)) { // Check if the block is free
            set_bit(data_bitmap, i);   // Mark the block as used
            return i;                   // Return the allocated block number
        }
    }
    return -1; // No free block available
}

static int write_inode(int inode_num, const struct wfs_inode *inode) {
    off_t inode_offset = sb.i_blocks_ptr + (inode_num * sizeof(struct wfs_inode));
    if (pwrite(disk_fds[0], inode, sizeof(struct wfs_inode), inode_offset) != sizeof(struct wfs_inode)) {
        perror("[ERROR] Failed to write inode");
        return -1;
    }
    return 0; // Success
}

static int write_data_block(off_t block_offset, const void *data, size_t size) {
    if (pwrite(disk_fds[0], data, size, block_offset) != (ssize_t)size) {
        perror("[ERROR] Failed to write data block");
        return -1;
    }
    return 0; // Success
}

static int add_directory_entry(struct wfs_inode *parent_inode, int parent_inode_num, 
                               int new_inode_num, const char *entry_name) {
    struct wfs_dentry entries[ENTRIES_PER_BLOCK];

    // Step 1: Read the i_bitmap from disk into memory
    uint8_t i_bitmap[superblock->num_inodes / 8 + 1]; // Assuming each inode takes 1 bit in the bitmap
    if (pread(disk_fds[0], i_bitmap, sizeof(i_bitmap), superblock->i_bitmap_ptr) != sizeof(i_bitmap)) {
        perror("[ERROR] Failed to read inode bitmap");
        return -1;
    }

    // Step 2: Find a free inode (using i_bitmap)
    int new_inode = -1;
    for (size_t i = 0; i < superblock->num_inodes; i++) {
        if ((i_bitmap[i / 8] & (1 << (i % 8))) == 0) {
            // Inode i is free, allocate it
            new_inode = i;
            i_bitmap[i / 8] |= (1 << (i % 8));  // Mark inode as allocated
            break;
        }
    }
    if (new_inode == -1) {
        fprintf(stderr, "[ERROR] No free inodes available.\n");
        return -1;
    }

    // Step 3: Read the d_bitmap from disk into memory
    uint8_t d_bitmap[superblock->num_data_blocks / 8 + 1]; // Assuming each data block takes 1 bit in the bitmap
    if (pread(disk_fds[0], d_bitmap, sizeof(d_bitmap), superblock->d_bitmap_ptr) != sizeof(d_bitmap)) {
        perror("[ERROR] Failed to read data block bitmap");
        return -1;
    }

    // Step 4: Look for a free data block (using d_bitmap)
    int free_data_block = -1;
    for (size_t i = 0; i < superblock->num_data_blocks; i++) {
        if ((d_bitmap[i / 8] & (1 << (i % 8))) == 0) {
            // Data block i is free, allocate it
            free_data_block = i;
            d_bitmap[i / 8] |= (1 << (i % 8));  // Mark data block as allocated
            break;
        }
    }

    if (free_data_block == -1) {
        fprintf(stderr, "[ERROR] No free data blocks available.\n");
        return -1;
    }

    // Initialize the new directory block
    memset(entries, 0, sizeof(entries));
    strncpy(entries[0].name, entry_name, MAX_NAME_LEN);
    entries[0].num = new_inode_num;

    off_t new_block_offset = calculate_block_offset(free_data_block);
    if (pwrite(disk_fds[0], entries, sizeof(entries), new_block_offset) != sizeof(entries)) {
        perror("[ERROR] Failed to write new directory block");
        return -1;
    }

    // Step 5: Update the parent inode
    //parent_inode->blocks[parent_inode->blocks_count++] = free_data_block;
    //parent_inode->size += BLOCK_SIZE;

    // Step 6: Write the updated i_bitmap and d_bitmap back to disk
    if (pwrite(disk_fds[0], i_bitmap, sizeof(i_bitmap), superblock->i_bitmap_ptr) != sizeof(i_bitmap)) {
        perror("[ERROR] Failed to write inode bitmap");
        return -1;
    }

    if (pwrite(disk_fds[0], d_bitmap, sizeof(d_bitmap), superblock->d_bitmap_ptr) != sizeof(d_bitmap)) {
        perror("[ERROR] Failed to write data block bitmap");
        return -1;
    }

    // Write the updated parent inode (if required)
    if (write_inode(parent_inode_num, parent_inode) != 0) {
        fprintf(stderr, "[ERROR] Failed to update parent inode.\n");
        return -1;
    }

    return 0; // Success
}


void free_inode(int inode_num) {
    // Your logic for freeing an inode
}

void free_data_block(int block_num) {
    // Your logic for freeing a data block
}

// Function to create a new directory
static int wfs_mkdir(const char *path, mode_t mode) {
    printf("[DEBUG] mkdir called for path: %s with mode: %o\n", path, mode);

    // 1. Validate the input path
    if (strlen(path) == 0 || strlen(path) >= MAX_PATH_LEN) {
        fprintf(stderr, "[ERROR] Invalid path length: %zu\n", strlen(path));
        return -EINVAL;
    }

    // Check if the directory already exists
    struct wfs_inode dummy_inode;
    int dummy_inode_num;
    if (get_inode_from_path(path, &dummy_inode_num, &dummy_inode) == 0) {
        fprintf(stderr, "[ERROR] Directory already exists: %s\n", path);
        return -EEXIST;
    }

    // 2. Parse the path
    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, path, MAX_PATH_LEN);

    char *parent_path = dirname(path_copy); // Parent directory path
    char *new_dir_name = basename(path_copy); // New directory name

    if (strlen(new_dir_name) >= MAX_NAME_LEN) {
        fprintf(stderr, "[ERROR] Directory name too long: %s\n", new_dir_name);
        return -ENAMETOOLONG;
    }

    // 3. Locate the parent directory
    struct wfs_inode parent_inode;
    int parent_inode_num;
    if (get_inode_from_path(parent_path, &parent_inode_num, &parent_inode) != 0) {
        fprintf(stderr, "[ERROR] Parent directory not found: %s\n", parent_path);
        return -ENOENT;
    }

    if ((parent_inode.mode & S_IFDIR) == 0) {
        fprintf(stderr, "[ERROR] Parent is not a directory: %s\n", parent_path);
        return -ENOTDIR;
    }

    // 4. Allocate a free inode and data block for the new directory
    int new_inode_num = allocate_free_inode();
    if (new_inode_num < 0) {
        fprintf(stderr, "[ERROR] No free inode available.\n");
        return -ENOSPC;
    }

    int new_data_block = allocate_free_data_block();
    if (new_data_block < 0) {
        fprintf(stderr, "[ERROR] No free data block available.\n");
        free_inode(new_inode_num); // Free the allocated inode
        return -ENOSPC;
    }

    // 5. Initialize the new directory inode
    struct wfs_inode new_dir_inode = {
        .mode = S_IFDIR | mode,
        .size = BLOCK_SIZE, // 1 block for the initial entries
        .nlinks = 2, // "." and parent ("..")
        .blocks = { new_data_block }
    };

    if (write_inode(new_inode_num, &new_dir_inode) != 0) {
        fprintf(stderr, "[ERROR] Failed to write new directory inode.\n");
        free_inode(new_inode_num);
        free_data_block(new_data_block);
        return -EIO;
    }

    // 6. Write the initial "." and ".." entries to the new directory block
    struct wfs_dentry dot_entries[2] = {
        { .num = new_inode_num, .name = "." },
        { .num = parent_inode_num, .name = ".." }
    };

    if (write_data_block(calculate_block_offset(new_data_block), dot_entries, sizeof(dot_entries)) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize directory entries.\n");
        free_inode(new_inode_num);
        free_data_block(new_data_block);
        return -EIO;
    }

    // 7. Add the new directory to the parent directory
    if (add_directory_entry(&parent_inode, parent_inode_num, new_inode_num, new_dir_name) != 0) {
        fprintf(stderr, "[ERROR] Failed to add entry to parent directory.\n");
        free_inode(new_inode_num);
        free_data_block(new_data_block);
        return -ENOSPC;
    }

    // 8. Update the parent directory inode
    parent_inode.nlinks++; // Increment link count for the new subdirectory
    if (write_inode(parent_inode_num, &parent_inode) != 0) {
        fprintf(stderr, "[ERROR] Failed to update parent directory inode.\n");
        return -EIO;
    }

    printf("[DEBUG] Directory created successfully: %s\n", path);
    return 0; // Success
}

// int wfs_mkdir(const char *path, mode_t mode)
// {
//     // Extract the directory name from the path
//     char *path_copy = strdup(path);  // Duplicate the path to preserve the original
//     char *new_dir_name = basename(path_copy);  // Extract the directory name
//     char *parent_path = dirname(path_copy);  // Extract the parent directory path

//     // Find the parent directory's inode number
//     int parent_inode_num = -1;
//     struct wfs_inode parent_inode;
//     if (get_inode_from_path(parent_path, &parent_inode_num, &parent_inode) != 0) {
//         fprintf(stderr, "Error: Failed to get parent directory's inode.\n");
//         free(path_copy);  // Free the path copy before returning
//         return -ENOENT;
//     }

//     // 1. Find a free inode from the inode bitmap
//     int free_inode_num = -1;
//     for (size_t i = 0; i < superblock->num_inodes; i++)
//     {
//         if (!(inode_bitmap[i / 8] & (1 << (i % 8))))  // Check if bit is unset
//         {
//             free_inode_num = i;
//             inode_bitmap[i / 8] |= (1 << (i % 8));  // Mark it as used
//             break;
//         }
//     }

//     if (free_inode_num == -1)
//     {
//         fprintf(stderr, "Error: No free inode available.\n");
//         free(path_copy);  // Free the path copy before returning
//         return -ENOSPC;
//     }

//     // 2. Allocate and initialize the new directory inode
//     struct wfs_inode new_dir_inode = {
//         .num = free_inode_num,
//         .mode = S_IFDIR | (mode & 0777),
//         .uid = getuid(),
//         .gid = getgid(),
//         .size = BLOCK_SIZE,  // Single block initially
//         .nlinks = 2,         // "." and ".."
//         .atim = time(NULL),
//         .mtim = time(NULL),
//         .ctim = time(NULL),
//     };
//     memset(new_dir_inode.blocks, 0, sizeof(new_dir_inode.blocks));

//     // Find a free data block for the new directory
//     int free_data_block = -1;
//     for (size_t i = 0; i < superblock->num_data_blocks; i++)
//     {
//         if (!(data_bitmap[i / 8] & (1 << (i % 8))))  // Check if bit is unset
//         {
//             free_data_block = i;
//             data_bitmap[i / 8] |= (1 << (i % 8));  // Mark it as used
//             break;
//         }
//     }

//     if (free_data_block == -1)
//     {
//         fprintf(stderr, "Error: No free data block available.\n");
//         inode_bitmap[free_inode_num / 8] &= ~(1 << (free_inode_num % 8));  // Rollback inode allocation
//         free(path_copy);  // Free the path copy before returning
//         return -ENOSPC;
//     }

//     new_dir_inode.blocks[0] = free_data_block;

//     // 3. Open the correct disk file based on RAID and free_inode_num
//     FILE *disk = fopen(disks[free_inode_num % superblock->num_disks], "r+b");
//     if (!disk)
//     {
//         perror("Failed to open disk");
//         free(path_copy);  // Free the path copy before returning
//         return -EIO;
//     }

//     // Write the new inode to the disk
//     int inode_offset = calcoffset(free_inode_num, 1);
//     fseek(disk, inode_offset, SEEK_SET);
//     if (fwrite(&new_dir_inode, sizeof(new_dir_inode), 1, disk) != 1)
//     {
//         perror("Failed to write inode");
//         fclose(disk);
//         free(path_copy);  // Free the path copy before returning
//         return -EIO;
//     }

//     // 4. Write the initial "." and ".." entries to the new directory block
//     struct wfs_dentry dot_entries[2] = {
//         {.num = free_inode_num, .name = "."},
//         {.num = parent_inode_num, .name = ".."}};  // Use parent inode number here

//     int data_block_offset = calcoffset(free_data_block, 2);
//     fseek(disk, data_block_offset, SEEK_SET);
//     if (fwrite(dot_entries, sizeof(dot_entries), 1, disk) != 1)
//     {
//         perror("Failed to write directory entries");
//         fclose(disk);
//         free(path_copy);  // Free the path copy before returning
//         return -EIO;
//     }

//     // 5. Update the parent directory to include the new directory
//     struct wfs_dentry new_entry = {
//         .num = free_inode_num,
//         .name = new_dir_name // Now we use the extracted directory name
//     };

//     // Find a free slot in the parent's directory block
//     for (int i = 0; i < N_BLOCKS && parent_inode.blocks[i] != 0; i++)
//     {
//         int parent_data_offset = calcoffset(parent_inode.blocks[i], 2);
//         struct wfs_dentry parent_entries[BLOCK_SIZE / sizeof(struct wfs_dentry)];
//         fseek(disk, parent_data_offset, SEEK_SET);
//         fread(parent_entries, sizeof(parent_entries), 1, disk);

//         for (size_t j = 0; j < sizeof(parent_entries) / sizeof(parent_entries[0]); j++)
//         {
//             if (parent_entries[j].num == 0)  // Empty slot
//             {
//                 parent_entries[j] = new_entry;
//                 fseek(disk, parent_data_offset, SEEK_SET);
//                 fwrite(parent_entries, sizeof(parent_entries), 1, disk);
//                 fclose(disk);  // Close disk after operation
//                 free(path_copy);  // Free the path copy before returning
//                 return 0;
//             }
//         }
//     }

//     fprintf(stderr, "Error: Failed to add new directory to parent.\n");
//     fclose(disk);
//     free(path_copy);  // Free the path copy before returning
//     return -ENOSPC;
// }


int wfs_allocate_inode(struct wfs_inode *inode, uint16_t mode)
{
    // Get inode bitmap location
    uint8_t *inode_bitmap = (uint8_t *)(disk_mappings[0]) + superblock->i_bitmap_ptr;

    // Find first free inode in bitmap
    for (int i = 0; i < superblock->num_inodes; i++)
    {
        // Check if inode is free (bit is 0)
        if (!(inode_bitmap[i / 8] & (1 << (i % 8))))
        {
            // Mark inode as used
            inode_bitmap[i / 8] |= (1 << (i % 8));

            // Initialize inode metadata
            inode->num = i;
            inode->mode = mode;
            inode->uid = getuid();
            inode->gid = getgid();
            inode->atim = inode->mtim = time(NULL);
            inode->size = 0;
            inode->nlinks = 1;

            // Zero out block pointers
            memset(inode->blocks, 0, sizeof(inode->blocks));

            return i; // Return inode number
        }
    }

    return -1; // No free inodes
}

static int wfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    // Debug: Log function entry
    printf("[DEBUG] wfs_mknod called for path: %s, mode: %d, dev: %ld\n", path, mode, dev);

    // Check if the file already exists
    if (wfs_lookup(path) != -1)
    {
        printf("[DEBUG] File already exists: %s\n", path);
        return -EEXIST; // File already exists
    }

    // Allocate an inode for the new file
    struct wfs_inode new_inode; // Declare the inode
    int inode_num = wfs_allocate_inode(&new_inode, mode);
    if (inode_num == -1)
    {
        printf("[DEBUG] Failed to allocate inode for path: %s\n", path);
        return -ENOSPC; // No space left for a new inode
    }

    // Debug: Log inode allocation success
    printf("[DEBUG] Allocated inode %d for path: %s\n", inode_num, path);

    // Initialize the inode for the new file
    new_inode.mode = mode;
    new_inode.size = 0;                                    // New file starts with size 0
    memset(new_inode.blocks, 0, sizeof(new_inode.blocks)); // No blocks allocated yet

    // Debug: Log inode initialization
    printf("[DEBUG] Initialized inode for path: %s, mode: %d\n", path, new_inode.mode);

    // Write the new file inode to disk
    //int write_inode_result = wfs_write_inode(inode_num, &new_inode);
    wfs_write_inode(inode_num, &new_inode);
    // if (write_inode_result != 0)
    // {
    //     printf("[DEBUG] Failed to write inode %d to disk for path: %s\n", inode_num, path);
    //     return write_inode_result; // Error writing inode to disk
    // }

    // Debug: Log inode write success
    printf("[DEBUG] Written inode %d to disk for path: %s\n", inode_num, path);

    // Add the new file entry to the parent directory
    int parent_inode_num = wfs_get_parent_inode(path); // Get the parent inode number
    if (parent_inode_num < 0)
    {
        printf("[DEBUG] Failed to resolve parent inode for path: %s, error: %d\n", path, parent_inode_num);
        return parent_inode_num; // Error resolving parent inode
    }

    // Debug: Log parent inode number
    printf("[DEBUG] Parent inode number for path %s: %d\n", path, parent_inode_num);

    // Add the directory entry
    int add_entry_result = wfs_add_dir_entry(parent_inode_num, path, inode_num);
    if (add_entry_result != 0)
    {
        printf("[DEBUG] Failed to add directory entry for path: %s\n", path);
        return add_entry_result; // Error adding directory entry
    }

    // Debug: Log directory entry addition success
    printf("[DEBUG] Successfully added directory entry for path: %s\n", path);

    return EXIT_SUCCESS; // Success
}


static int wfs_unlink(const char *path)
{
    printf("Entering wfs_unlink %s\n", path);
    int inode_num = wfs_lookup(path);
    if (inode_num == -1)
    {
        return -ENOENT; // File not found
    }

    struct wfs_inode *inode = wfs_get_inode(inode_num);
    for (int i = 0; i < N_BLOCKS; i++)
    {
        if (inode->blocks[i] != 0)
        {
            // wfs_free_data_block(inode->blocks[i]); // Free data blocks
        }
    }

    // wfs_free_inode(inode_num); // Free inode

    // int parent_inode = wfs_get_parent_inode(path);
    // wfs_remove_dir_entry(parent_inode, path); // Remove directory entry

    return EXIT_SUCCESS;
}

void wfs_free_data_block(int block_num)
{
    if (block_num < 0 || block_num >= N_BLOCKS)
    {
        fprintf(stderr, "[ERROR] Attempt to free invalid block number: %d\n", block_num);
        return;
    }

    // Assume you have a bitmap or similar structure to track free blocks
    if (!data_bitmap[block_num])
    {
        fprintf(stderr, "[WARNING] Block %d is already free.\n", block_num);
        return;
    }

    data_bitmap[block_num] = 0; // Mark block as free

    // Optionally, clear the contents of the block (for debugging or security)
    char zero_block[BLOCK_SIZE] = {0};
    wfs_write_data_block(block_num, zero_block, BLOCK_SIZE);

    printf("[INFO] Freed block number: %d\n", block_num);
}

static int wfs_rmdir(const char *path)
{
    printf("Entering wfs_rmdir %s\n", path);
    int inode_num = wfs_lookup(path);
    if (inode_num == -1)
    {
        return -ENOENT; // Directory not found
    }

    struct wfs_inode *inode = wfs_get_inode(inode_num);
    if (inode->size > 2 * sizeof(struct wfs_dentry))
    {                      // More than "." and ".."
        return -ENOTEMPTY; // Directory is not empty
    }

    wfs_free_data_block(inode->blocks[0]);
    wfs_free_data_block(inode->blocks[1]);
    // wfs_free_inode(inode_num);

    // int parent_inode = wfs_get_parent_inode(path);
    // wfs_remove_dir_entry(parent_inode, path);

    return EXIT_SUCCESS;
}

static int wfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("Entering wfs_read %s\n", path);
    int inode_num = wfs_lookup(path);
    if (inode_num == -1)
    {
        return -ENOENT; // File not found
    }

    struct wfs_inode *inode = wfs_get_inode(inode_num);
    if (offset >= inode->size)
    {
        return EXIT_SUCCESS; // No more data to read
    }

    size_t read_size = size;
    if (offset + size > inode->size)
    {
        read_size = inode->size - offset;
    }

    int block_index = offset / BLOCK_SIZE;
    int block_offset = offset % BLOCK_SIZE;

    char temp_buf[BLOCK_SIZE];
    size_t bytes_read = 0;
    while (bytes_read < read_size)
    {
        int block = inode->blocks[block_index];
        wfs_read_data_block(block, temp_buf, BLOCK_SIZE);

        size_t to_copy = (read_size - bytes_read) < (BLOCK_SIZE - block_offset) ? (read_size - bytes_read) : (BLOCK_SIZE - block_offset);
        memcpy(buf + bytes_read, temp_buf + block_offset, to_copy);

        bytes_read += to_copy;
        block_offset = 0;
        block_index++;
    }

    return bytes_read;
}

static int wfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("Entering wfs_write %s\n", path);
    int inode_num = wfs_lookup(path);
    if (inode_num == -1)
    {
        return -ENOENT; // File not found
    }

    struct wfs_inode *inode = wfs_get_inode(inode_num);

    size_t written_size = size;
    int block_index = offset / BLOCK_SIZE;
    int block_offset = offset % BLOCK_SIZE;

    while (written_size > 0)
    {
        int block = inode->blocks[block_index];
        char temp_buf[BLOCK_SIZE];
        if (block == 0)
        {
            block = wfs_allocate_data_block();
            inode->blocks[block_index] = block;
        }

        wfs_read_data_block(block, temp_buf, BLOCK_SIZE);

        size_t to_write = (written_size < (BLOCK_SIZE - block_offset)) ? written_size : (BLOCK_SIZE - block_offset);
        memcpy(temp_buf + block_offset, buf + written_size - to_write, to_write);

        wfs_write_data_block(block, temp_buf, BLOCK_SIZE);
        written_size -= to_write;
        block_offset = 0;
        block_index++;
    }

    inode->size = max(inode->size, offset + size);
    wfs_write_inode(inode_num, inode);

    return size;
}

static int wfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    printf("Entering wfs_readdir %s\n", path);

    int inode_num = wfs_lookup(path);
    if (inode_num == -1)
    {
        return -ENOENT;
    }

    struct wfs_inode *inode = wfs_get_inode(inode_num);
    if (!(inode->mode & S_IFDIR))
    {
        return -ENOTDIR; // Not a directory
    }

    struct wfs_dentry dir_entries[2];
    wfs_read_data_block(inode->blocks[0], (void *)dir_entries, sizeof(dir_entries));

    filler(buf, ".", NULL, 0);  // Add "." entry
    filler(buf, "..", NULL, 0); // Add ".." entry

    // Add other entries
    return EXIT_SUCCESS;
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

// Function to parse and separate arguments
int parse_arguments(int argc, char *argv[], char *disks[], int *disk_count, char **mount_point, char *fuse_argv[], int *fuse_argc) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s disk1 disk2 [FUSE options] mount_point\n", argv[0]);
        return -1;
    }

    int i;
    *fuse_argc = 0;

    // Parse disks
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            // We've reached FUSE options
            break;
        }
        if (*disk_count < MAX_DISKS) {
            disks[*disk_count] = argv[i];
            (*disk_count)++;
        } else {
            fprintf(stderr, "[ERROR] Too many disks provided. Maximum is %d.\n", MAX_DISKS);
            return -1;
        }
    }

    if (*disk_count < 2) {
        fprintf(stderr, "[ERROR] Insufficient disks. At least 2 disks are required.\n");
        return -1;
    }

    // Parse FUSE options and mount point
    int found_mount_point = 0;
    for (; i < argc; i++) {
        if (!found_mount_point && argv[i][0] != '-') {
            *mount_point = argv[i];
            found_mount_point = 1;
        } else {
            fuse_argv[*fuse_argc] = argv[i];
            (*fuse_argc)++;
        }
    }

    if (!found_mount_point) {
        fprintf(stderr, "[ERROR] Mount point not specified.\n");
        return -1;
    }

    // Prepend program name to FUSE argv
    memmove(&fuse_argv[1], fuse_argv, (*fuse_argc) * sizeof(char *));
    fuse_argv[0] = argv[0];
    (*fuse_argc)++;

    // Append mount point to FUSE argv
    fuse_argv[*fuse_argc] = *mount_point;
    (*fuse_argc)++;

    return 0;
}

int main(int argc, char *argv[]) {
    char *fuse_argv[argc + 1]; // Allocate enough space for FUSE arguments
    int fuse_argc = 0;

    // Parse arguments
    if (parse_arguments(argc, argv, disks, &disk_count, &mount_point, fuse_argv, &fuse_argc) != 0) {
        return EXIT_FAILURE;
    }

    // Debug output
    printf("[DEBUG] Parsed disks:\n");
    for (int i = 0; i < disk_count; i++) {
        printf("  Disk[%d]: %s\n", i, disks[i]);
    }
    printf("[DEBUG] Mount point: %s\n", mount_point);
    printf("[DEBUG] FUSE arguments:\n");
    for (int i = 0; i < fuse_argc; i++) { 
        printf("  fuse_argv[%d]: %s\n", i, fuse_argv[i]);
    }

    // Step 1: Open disk files
    for (int i = 0; i < disk_count; i++) {
        disk_fds[i] = open(disks[i], O_RDWR);
        if (disk_fds[i] < 0) {
            perror("[ERROR] Failed to open disk");
            return EXIT_FAILURE;
        }
    }

    // Step 2: Read the superblock from the first disk
    if (pread(disk_fds[0], &sb, sizeof(sb), 0) != sizeof(sb)) {
        perror("[ERROR] Failed to read superblock");
        return EXIT_FAILURE;
    }
    printf("[DEBUG] Superblock read successfully.\n");
    printf("[DEBUG] RAID Mode: %d, Number of disks: %d\n", sb.raid_mode, sb.num_disks);

    // Step 3: Set up RAID mode
    switch (sb.raid_mode) {
        case 0:
            printf("[INFO] RAID 0 configuration.\n");
            break;
        case 1:
            printf("[INFO] RAID 1 configuration.\n");
            break;
        case 10:
            printf("[INFO] RAID 1v configuration.\n");
            break;
        default:
            fprintf(stderr, "[ERROR] Unsupported RAID mode: %d\n", sb.raid_mode);
            return EXIT_FAILURE;
    }

    // Step 4: Initialize other global structures if needed
    // For example, set up in-memory inode or block caches

    // Step 5: Call fuse_main
    int rc = fuse_main(fuse_argc, fuse_argv, &wfs_operations, NULL);
    if (rc != 0) {
        fprintf(stderr, "[ERROR] fuse_main failed with return code: %d\n", rc);
        return EXIT_FAILURE;
    }

    // Step 6: Cleanup
    for (int i = 0; i < disk_count; i++) {
        if (disk_fds[i] >= 0) {
            close(disk_fds[i]);
        }
    }

    return EXIT_SUCCESS;
}

int read_superblock(FILE *disk, struct wfs_sb *sb)
{
    // Seek to the start of the disk (superblock is at offset 0)
    fseek(disk, 0, SEEK_SET);

    // Read the superblock data
    size_t bytes_read = fread(sb, sizeof(struct wfs_sb), 1, disk);

    if (bytes_read != 1)
    {
        fprintf(stderr, "[ERROR] Failed to read the superblock.\n");
        return -1; // Return an error if reading failed
    }

    return EXIT_SUCCESS; // Success
}

int initialize_raid(int raid_mode, char *disks[], int disk_count)
{
    printf("[INFO] Initializing RAID mode: %d\n", raid_mode);

    FILE *disk = fopen(disks[0], "rb");
    if (!disk)
    {
        fprintf(stderr, "[ERROR] Failed to open disk: %s\n", disks[0]);
        return EXIT_FAILURE;
    }

    struct wfs_sb sb;

    // Read the superblock from the disk
    if (read_superblock(disk, &sb) != 0)
    {
        fclose(disk);
        return EXIT_FAILURE;
    }

    printf("[INFO] RAID mode from superblock: %d\n", sb.raid_mode);

    fclose(disk);

    if (sb.raid_mode == 0)
    {
        printf("[INFO] RAID 0 configuration.\n");
    }
    else if (sb.raid_mode == 1)
    {
        printf("[INFO] RAID 1 configuration.\n");
    }
    else if (sb.raid_mode == 2)
    {
        printf("[INFO] RAID 1v configuration.\n");
    }
    else
    {
        fprintf(stderr, "[ERROR] Invalid RAID mode in superblock: %d\n", sb.raid_mode);
        return EXIT_FAILURE;
    }

    printf("[INFO] RAID initialized successfully.\n");
    return EXIT_SUCCESS;
}

// Function to retrieve RAID mode from the superblock
int retrieve_raid_mode(const char *disk_path)
{
    // Open the disk file
    FILE *disk = fopen(disk_path, "rb");
    if (!disk)
    {
        fprintf(stderr, "[ERROR] Failed to open disk: %s\n", disk_path);
        exit(EXIT_FAILURE); // Exit if the disk can't be opened
    }

    struct wfs_sb sb;
    // Read the superblock from the disk
    printf("[DEBUG] Reading superblock from disk...\n");
    if (read_superblock(disk, &sb) != 0)
    {
        fclose(disk);
        exit(EXIT_FAILURE); // Exit if reading superblock fails
    }

    // Set RAID mode from superblock (global variable)
    printf("RAID found: %d\n", sb.raid_mode);
    raid_mode = sb.raid_mode;
    printf("[INFO] Retrieved RAID mode from superblock: %d\n", raid_mode);

    fclose(disk); // Close the disk file after reading the superblock

    if (raid_mode < 0 || raid_mode > 2)
    {
        fprintf(stderr, "[ERROR] Invalid RAID mode in superblock: %d\n", raid_mode);
        return EXIT_FAILURE;
    }

    printf("[INFO] Retrieved RAID mode from superblock: %d\n", raid_mode);
    return EXIT_SUCCESS;
}

int prepare_fuse_args(int argc, char *argv[], int disk_count, char *fuse_argv[], int *fuse_argc)
{
    printf("[DEBUG] Preparing FUSE arguments...\n");
    *fuse_argc = 0;

    // Add program name (argv[0]) to FUSE arguments
    fuse_argv[(*fuse_argc)++] = argv[0];

    // Find and copy FUSE options (everything after "-s" and the mount point)
    for (int i = 1 + disk_count; i < argc; i++)
    {
        fuse_argv[(*fuse_argc)++] = argv[i];
    }

    // Ensure the array is null-terminated (FUSE expects this)
    fuse_argv[*fuse_argc] = NULL;

    // Debug output for FUSE arguments
    for (int i = 0; i < *fuse_argc; i++)
    {
        printf("[DEBUG] fuse_argv[%d]: %s\n", i, fuse_argv[i]);
    }

    return EXIT_SUCCESS;
}

// Function to check and validate parameters
int param_check(int argc, char *argv[], char *disks[], int *disk_count, char **mount_point, char *fuse_argv[], int *fuse_argc)
{
    printf("[DEBUG] Parsing parameters:\n");
    for (int i = 0; i < argc; i++)
    {
        printf("  argv[%d]: %s\n", i, argv[i]);
    }

    *disk_count = 0;
    *fuse_argc = 1;  // Start by adding the program name

    // The first argument is the program itself (./wfs), so add it to fuse_argv[0]
    fuse_argv[0] = argv[0];

    // Iterate over arguments to find disks, RAID mode, FUSE options, and the mount point
    for (int i = 1; i < argc; i++)
    {
        // Check for RAID mode flag
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
        {
            raid_mode = atoi(argv[++i]); // Set global raid_mode
        }
        // Check for the start of FUSE options
        else if (strcmp(argv[i], "-s") == 0)
        {
            // Mark the mount point (next argument) and add -s to fuse_argv
            if (i + 1 < argc)
            {
                *mount_point = argv[++i];  // Set the mount point
            }
            fuse_argv[*fuse_argc] = argv[i - 1];  // Add -s to fuse_argv
            (*fuse_argc)++;
        }
        // Handle FUSE arguments (other than -s)
        else if (argv[i][0] == '-' && argv[i][1] != 's')
        {
            fuse_argv[*fuse_argc] = argv[i];
            (*fuse_argc)++;
        }
        // Otherwise, treat as a disk argument
        else
        {
            if (*disk_count < 3)
            {
                disks[*disk_count] = argv[i];
                (*disk_count)++;
            }
            else
            {
                fprintf(stderr, "[ERROR] Too many disks provided.\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    // After processing all arguments, add the mount point to fuse_argv
    if (*mount_point != NULL)
    {
        fuse_argv[*fuse_argc] = *mount_point;
        (*fuse_argc)++;
    }

    printf("[DEBUG] Disk count: %d\n", *disk_count);
    for (int i = 0; i < *disk_count; i++)
    {
        printf("[DEBUG] Disk[%d]: %s\n", i, disks[i]);
    }
    printf("[DEBUG] Mount point: %s\n", *mount_point ? *mount_point : "None");

    // Print FUSE arguments for debugging
    printf("[DEBUG] FUSE arguments:\n");
    for (int i = 0; i < *fuse_argc; i++)
    {
        printf("  fuse_argv[%d]: %s\n", i, fuse_argv[i]);
    }

    // Validate RAID mode and disks
    if (raid_mode == -1 && *disk_count > 0)
    {
        printf("[DEBUG] Attempting to retrieve RAID mode from disk: %s\n", disks[0]);
        if (retrieve_raid_mode(disks[0]) != EXIT_SUCCESS)
        {
            fprintf(stderr, "[ERROR] Failed to retrieve RAID mode from disk.\n");
            return EXIT_FAILURE;
        }
    }

    if (*disk_count < 2)
    {
        fprintf(stderr, "[ERROR] Insufficient disks. At least 2 disks are required.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


// Function to validate RAID configuration
void validate_raid_config(int raid_mode, int disk_count)
{
    // RAID 1 requires exactly 2 disks
    if (raid_mode == 1 && disk_count != 2)
    {
        fprintf(stderr, "[ERROR] RAID 1 requires exactly 2 disks.\n");
        exit(EXIT_FAILURE);
    }

    // RAID 0 requires at least 2 disks
    if (raid_mode == 0 && disk_count < 2)
    {
        fprintf(stderr, "[ERROR] RAID 0 requires at least 2 disks.\n");
        exit(EXIT_FAILURE);
    }
}
