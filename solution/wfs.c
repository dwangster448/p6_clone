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
int raid_mode;
// char *disk_paths[MAX_DISKS];
int num_disks;
uint8_t *inode_bitmap;
uint8_t *data_bitmap;
struct wfs_inode *inode_table;
void **disk_mappings;
struct wfs_sb *superblock;
char *disks[3] = {NULL, NULL, NULL};
int disk_count = 0;

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

// Basic getattr implementation
// Basic getattr implementation
static int wfs_getattr(const char *path, struct stat *stbuf)
{
    printf("[DEBUG] getattr called for path: %s\n", path);

    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0)
    {
        stbuf->st_mode = S_IFDIR | 0755; // Directory with permissions 755
        stbuf->st_nlink = 2;
    }
    else if (strcmp(path, "/file") == 0)
    {
        stbuf->st_mode = S_IFREG | 0644; // Regular file with permissions 644
        stbuf->st_nlink = 1;
        stbuf->st_size = 1024; // File size 1 KB
    }
    else
    {
        printf("[DEBUG] Path not found: %s\n", path);
        return -ENOENT; // File or directory does not exist
    }

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



// Function to create a new directory
static int wfs_mkdir(const char *path, mode_t mode)
{

    fprintf(stdout, "Creating directory %s with mode %d\n", path, mode);

    // Step 1: Check if the directory already exists
    if (wfs_lookup(path) != -1)
    {
        printf("Error: Directory %s already exists\n", path);
        return -EEXIST; // Directory already exists
    }

    // Step 2: Allocate an inode for the new directory
    struct wfs_inode new_dir_inode;  // Declare the inode to be passed to wfs_allocate_inode
    int inode_num = wfs_allocate_inode(&new_dir_inode, S_IFDIR | mode);  // Pass the inode and mode
    if (inode_num == -1)
    {
        printf("Error: No space left for a new inode\n");
        return -ENOSPC; // No space left for a new inode
    }

    // Step 3: Allocate data blocks for the new directory (at least two for "." and "..")
    int block1 = wfs_allocate_data_block();
    int block2 = wfs_allocate_data_block();
    if (block1 == -1 || block2 == -1)
    {
        printf("Error: No space left for data blocks\n");
        return -ENOSPC; // No space left for data blocks
    }

    // Step 4: Initialize the inode for the new directory
    new_dir_inode.mode = S_IFDIR | mode;                // Set the directory type (S_IFDIR) and permissions
    new_dir_inode.size = 2 * sizeof(struct wfs_dentry); // 2 entries: '.' and '..'
    new_dir_inode.blocks[0] = block1;                   // First data block
    new_dir_inode.blocks[1] = block2;                   // Second data block

    // Write the new directory inode to disk
    wfs_write_inode(inode_num, &new_dir_inode);

    // Step 5: Create the directory entries for "." and ".."
    struct wfs_dentry dir_entries[2];

    // Entry for "."
    strcpy(dir_entries[0].name, ".");
    dir_entries[0].num = inode_num; // Self reference

    // Entry for ".."
    int parent_inode_num = wfs_get_parent_inode(path); // Get the parent inode number
    strcpy(dir_entries[1].name, "..");
    dir_entries[1].num = parent_inode_num;

    // Write the directory entries to the first data block
    wfs_write_data_block(block1, (void *)dir_entries, sizeof(dir_entries));

    // Step 6: Add the new directory entry to the parent directory
    int parent_inode = wfs_get_parent_inode(path);    // Get parent inode number
    wfs_add_dir_entry(parent_inode, path, inode_num); // Add the new directory entry in the parent

    printf("Directory %s created successfully\n", path);
    // Step 7: Return success
    return EXIT_SUCCESS;
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
    // Check if the file already exists
    if (wfs_lookup(path) != -1)
    {
        return -EEXIST; // File already exists
    }

    // Allocate an inode for the new file
    struct wfs_inode new_inode; // Declare the inode
    int inode_num = wfs_allocate_inode(&new_inode, mode);
    if (inode_num == -1)
    {
        return -ENOSPC; // No space left for a new inode
    }

    // Initialize the inode for the new file
    new_inode.mode = mode;
    new_inode.size = 0;                                    // New file starts with size 0
    memset(new_inode.blocks, 0, sizeof(new_inode.blocks)); // No blocks allocated yet

    // Write the new file inode to disk
    wfs_write_inode(inode_num, &new_inode);

    // Add the new file entry to the parent directory
    int parent_inode_num = wfs_get_parent_inode(path); // Get the parent inode number
    if (parent_inode_num < 0)
    {
        return parent_inode_num; // Error resolving parent inode
    }
    wfs_add_dir_entry(parent_inode_num, path, inode_num);

    return EXIT_SUCCESS; // Success
}

static int wfs_unlink(const char *path)
{
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

int main(int argc, char *argv[])
{
    char *mount_point = NULL;
    char *fuse_argv[argc]; // Array to store FUSE arguments
    int fuse_argc = 0;

    // Parse the command-line arguments
    if (param_check(argc, argv, disks, &disk_count, &mount_point, fuse_argv, &fuse_argc) != EXIT_SUCCESS)
    {
        printf("failed param_check\n");
        return EXIT_FAILURE;
    }

    validate_raid_config(raid_mode, disk_count);

    if (initialize_raid(raid_mode, disks, disk_count) != EXIT_SUCCESS)
    {
        printf("FAILED TO INITIALIZE RAID MODE: %d\n", raid_mode);
        return EXIT_FAILURE;
    }

    // Check if mount point exists; create it if not
    
    /*
    struct stat st;
    if (stat(mount_point, &st) == -1)
    {
        if (errno == ENOENT)
        {
            printf("[INFO] Mount point '%s' does not exist. Creating it.\n", mount_point);
            if (mkdir(mount_point, 0755) != 0)
            {
                perror("[ERROR] Failed to create mount point");
                return EXIT_FAILURE;
            }
        }
        else
        {
            perror("[ERROR] Failed to access mount point");
            return EXIT_FAILURE;
        }
    }
    else if (!S_ISDIR(st.st_mode))
    {
        fprintf(stderr, "[ERROR] Mount point '%s' exists but is not a directory.\n", mount_point);
        return EXIT_FAILURE;
    }
    */

    // Open the first disk file (or use appropriate logic for RAID mode)
    int fd = open(disks[0], O_RDWR);
    if (fd < 0)
    {
        perror("Failed to open disk");
        return EXIT_FAILURE;
    }

    // Initialize bitmaps (if needed)
    // initialize_bitmaps(fd);

    // Prepare FUSE arguments
    if (prepare_fuse_args(argc, argv, disk_count, fuse_argv, &fuse_argc) != EXIT_SUCCESS)
    {
        printf("failed prepare_fuse_args\n");
        close(fd); // Clean up file descriptor
        return EXIT_FAILURE;
    }

    // Print FUSE arguments for debugging
    printf("[DEBUG] Initializing FUSE with arguments:\n");
    for (int i = 0; i < fuse_argc; i++)
    {
        printf("  fuse_argv[%d]: %s\n", i, fuse_argv[i]);
    }

    // Initialize FUSE
    int rc = fuse_main(fuse_argc, fuse_argv, &wfs_operations, NULL);
    if (rc != 0)
    {
        fprintf(stderr, "[ERROR] fuse_main failed with return code: %d\n", rc);
        fprintf(stderr, "[HINT] Check the following:\n");
        fprintf(stderr, "  - Are all required disk files (%d) accessible?\n", disk_count);
        fprintf(stderr, "  - Does the mount point directory (%s) exist and is it empty?\n", mount_point);
        fprintf(stderr, "  - Are FUSE arguments correct? Debug them above.\n");
        close(fd); // Clean up file descriptor
        return EXIT_FAILURE;
    }

    printf("[INFO] FUSE initialized successfully.\n");

    // Clean up
    close(fd); // Close disk file before exiting
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
