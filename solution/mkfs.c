#define FUSE_USE_VERSION 30
#include "wfs.h" // Ensure wfs.h is included for wfs_inode definition
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
// #include <stdint.h>
#include <unistd.h>
// #include <errno.h>
// #include <sys/stat.h>

// #include <fuse.h> //Not needed in mkfs

#define MAX_DISKS 10

struct wfs_sb superblock;

uint8_t raid_mode = 0;
size_t num_inodes = 0, num_data_blocks = 0;
FILE *disks[10];
int num_disks = 0;

void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s -r <raid_mode> -d <disk1> -d <disk2> ... -i <num_inodes> -b <num_data_blocks>\n", prog_name);
    // exit(EXIT_FAILURE);
}

int paramcheck(int argc, char *argv[])
{
    num_disks = 0; // Reset number of disks to 0
    raid_mode = 0; // Default RAID 0 (not checked here)

    // Parse the arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: Missing value for -d\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            FILE *disk = fopen(argv[++i], "r+b"); // Read and write mode
            if (!disk)
            {
                perror("Failed to open disk");
                exit(EXIT_FAILURE);
            }
            disks[num_disks++] = disk;
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: Missing value for -i\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            num_inodes = atoi(argv[++i]);
            if (num_inodes <= 0)
            {
                fprintf(stderr, "Error: Number of inodes must be a positive integer.\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "-b") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: Missing value for -b\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            num_data_blocks = atoi(argv[++i]);
            if (num_data_blocks <= 0)
            {
                fprintf(stderr, "Error: Number of data blocks must be a positive integer.\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
        // else if (strcmp(argv[i], "-r") == 0)
        // {
        //     // Skip RAID option since it's not needed for validation
        //     i++;
        // }
        else if (strcmp(argv[i], "-r") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: Missing value for -r\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            raid_mode = atoi(argv[++i]);          // Set RAID mode from argument
            if (raid_mode != 0 && raid_mode != 1) // Only support RAID 0 and RAID 1
            {
                fprintf(stderr, "Error: Unsupported RAID mode. Only RAID 0 and RAID 1 are supported.\n");
                return EXIT_FAILURE;
            }
        }
        else
        {
            fprintf(stderr, "Error: Unknown argument %s\n", argv[i]);
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // We only check that there are at least 2 disks for RAID 0
    if (num_disks < 2)
    {
        fprintf(stderr, "Error: RAID 0 requires at least 2 disks.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int calcoffset(int num, int node_db)
{ // TAKES IN INODE / DB NUM, also takes in
    int offset = BLOCK_SIZE * num;
    if (node_db == 1)
    {                                      // It's an inode
        offset += superblock.i_blocks_ptr; // INODE OFFSET
    }
    else if (node_db == 2)
    {
        offset += superblock.d_blocks_ptr; // DB OFFSET
    }
    return offset;
}

// Function to read an inode from the disk
int read_inode(FILE *disk, int inode_num, struct wfs_inode *inode)
{
    int offset = calcoffset(inode_num, 1); // 1 indicates it's an inode
    if (fseek(disk, offset, SEEK_SET) != 0)
    {
        perror("Failed to seek to inode position");
        return -1; // Error in seeking
    }

    if (fread(inode, sizeof(struct wfs_inode), 1, disk) != 1)
    {
        perror("Failed to read inode data");
        return -1; // Error in reading
    }

    return 0; // Success
}

void read_filesystem(FILE **disks, int num_disks)
{
    for (int i = 0; i < num_disks; i++)
    {
        rewind(disks[i]); // Reset the file pointer to the beginning of the disk

        // Read superblock
        struct wfs_sb read_superblock;
        if (fread(&read_superblock, sizeof(read_superblock), 1, disks[i]) != 1)
        {
            perror("Failed to read superblock");
            exit(EXIT_FAILURE);
        }
        // printf("Superblock read from disk %d:\n", i);
        // printf("num_inodes: %zu, num_data_blocks: %zu\n", read_superblock.num_inodes, read_superblock.num_data_blocks);
        // printf("i_bitmap_ptr: %zu, d_bitmap_ptr: %zu, i_blocks_ptr: %zu, d_blocks_ptr: %zu\n", read_superblock.i_bitmap_ptr, read_superblock.d_bitmap_ptr, read_superblock.i_blocks_ptr, read_superblock.d_blocks_ptr);

        // Read inode bitmap
        size_t inode_bitmap_size = (superblock.num_inodes + 7) / 8;
        // char inode_bitmap[inode_bitmap_size];
        char *inode_bitmap = malloc(inode_bitmap_size);
        if (!inode_bitmap)
        {
            perror("Failed to allocate memory for bitmaps");
            exit(EXIT_FAILURE);
        }

        if (fread(inode_bitmap, inode_bitmap_size, 1, disks[i]) != 1)
        {
            perror("Failed to read inode bitmap");
            exit(EXIT_FAILURE);
        }
        // printf("Inode bitmap read from disk %d:\n", i);
        for (size_t j = 0; j < inode_bitmap_size; j++)
        {
            // printf("inode_bitmap[%zu] = 0x%02x\n", j, inode_bitmap[j]);
        }

        // Read data bitmap
        size_t data_bitmap_size = (superblock.num_data_blocks + 7) / 8;
        // char data_bitmap[data_bitmap_size];
        char *data_bitmap = malloc(data_bitmap_size);
        if (!inode_bitmap)
        {
            perror("Failed to allocate memory for bitmaps");
            exit(EXIT_FAILURE);
        }

        if (fread(data_bitmap, data_bitmap_size, 1, disks[i]) != 1)
        {
            perror("Failed to read data bitmap");
            exit(EXIT_FAILURE);
        }
        // printf("Data bitmap read from disk %d:\n", i);
        //  for (size_t j = 0; j < data_bitmap_size; j++)
        //  {
        //      printf("data_bitmap[%zu] = 0x%02x\n", j, data_bitmap[j]);
        //  }

        // Read root inode (inode 0)
        struct wfs_inode root_inode;
        if (read_inode(disks[i], 0, &root_inode) == 0)
        {
            // printf("Root inode read from disk %d:\n", i);
            // printf("Inode number: %d\n", root_inode.num);
            // printf("Inode mode: %o\n", root_inode.mode);
            // printf("Inode UID: %u\n", root_inode.uid);
            // printf("Inode GID: %u\n", root_inode.gid);
            // printf("Inode nlinks: %u\n", root_inode.nlinks);
            // printf("Inode access time: %ld\n", root_inode.atim);
            // printf("Inode modification time: %ld\n", root_inode.mtim);
            // printf("Inode change time: %ld\n", root_inode.ctim);
        }
        else
        {
            fprintf(stderr, "Failed to read root inode from disk %d.\n", i);
        }
    }
}

void initialize_filesystem(FILE **disks, int num_disks, size_t num_inodes, size_t num_data_blocks, uint8_t raid_mode)
{
    // Round up num_inodes to the nearest multiple of 32
    size_t adjusted_num_inodes = (num_inodes + 31) & ~31; // Round up to next multiple of 32
    if (adjusted_num_inodes != num_inodes)
    {
        printf("Adjusted num_inodes from %zu to %zu to align with 32-block size.\n", num_inodes, adjusted_num_inodes);
        num_inodes = adjusted_num_inodes; // Update the value of num_inodes
    }

    // Round up num_data_blocks to the nearest multiple of 32
    size_t adjusted_num_data_blocks = (num_data_blocks + 31) & ~31; // Round up to next multiple of 32
    if (adjusted_num_data_blocks != num_data_blocks)
    {
        printf("Adjusted num_data_blocks from %zu to %zu to align with 32-block size.\n", num_data_blocks, adjusted_num_data_blocks);
        num_data_blocks = adjusted_num_data_blocks; // Update the value of num_data_blocks
    }

    // Calculate the required disk space
    size_t superblock_size = BLOCK_SIZE; // Assuming the superblock occupies one block
    // printf("Superblock size: %zu bytes\n", superblock_size);

    size_t inode_bitmap_size = (num_inodes + 7) / 8; // Size in bytes (1 bit per inode, rounded up)
    // printf("Inode bitmap size: %zu bytes\n", inode_bitmap_size);

    size_t data_bitmap_size = (num_data_blocks + 7) / 8; // Size in bytes (1 bit per data block, rounded up)
    // printf("Data bitmap size: %zu bytes\n", data_bitmap_size);

    // Assuming `wfs_inode` represents an inode structure
    // size_t inode_size = sizeof(struct wfs_inode);  // Fixed the structure reference to 'struct wfs_inode'
    size_t inodes_size = num_inodes * BLOCK_SIZE;
    // printf("Inodes size: %zu bytes\n", inodes_size);

    // size_t inodes_blocks = (inodes_size + BLOCK_SIZE - 1) / BLOCK_SIZE; // Rounded up to block size
    // printf("Inodes blocks: %zu blocks\n", inodes_blocks);

    size_t data_blocks_size = num_data_blocks * BLOCK_SIZE;
    // printf("data block size: %zu bytes\n", data_blocks_size);

    size_t required_disk_space = superblock_size + inode_bitmap_size + data_bitmap_size + inodes_size + data_blocks_size;
    // printf("Required disk space: %zu bytes\n", required_disk_space);

    // Validate the size of each disk
    for (int i = 0; i < num_disks; i++)
    {
        fseek(disks[i], 0, SEEK_END);
        size_t disk_size = ftell(disks[i]);
        rewind(disks[i]);

        // printf("Disk size: %ld, ", disk_size);
        // printf("Disk space required: %ld\n", required_disk_space);

        if (disk_size < required_disk_space)
        {
            fprintf(stderr, "Error: Disk %d is too small. Required: %zu bytes, Available: %zu bytes\n",
                    i, required_disk_space, disk_size);

            // Close all opened disk files before exiting
            for (int j = 0; j < num_disks; j++)
            {
                fclose(disks[j]);
            }
            exit(-1); // Exit with an error code
        }
    }

    // Calculate bitmap sizes
    // size_t inode_bitmap_size = (num_inodes + 7) / 8;
    // printf("Calculated inode bitmap size: %zu bytes\n", inode_bitmap_size);
    // char inode_bitmap[inode_bitmap_size];
    char *inode_bitmap = malloc(inode_bitmap_size);
    if (!inode_bitmap)
    {
        perror("Failed to allocate memory for bitmaps");
        exit(EXIT_FAILURE);
    }
    memset(inode_bitmap, 0, inode_bitmap_size); // Allocate and zero-initialize bitmaps

    // size_t data_bitmap_size = (num_data_blocks + 7) / 8;
    //  char data_bitmap[data_bitmap_size];
    char *data_bitmap = malloc(data_bitmap_size);
    if (!inode_bitmap)
    {
        perror("Failed to allocate memory for bitmaps");
        exit(EXIT_FAILURE);
    }
    memset(data_bitmap, 0, data_bitmap_size); // Allocate and zero-initialize bitmaps

    for (size_t i = 0; i < data_bitmap_size; i++)
    {
        // printf("data_bitmap[%zu] = 0x%02x\n", i, data_bitmap[i]);
    }

    // Mark root inode as allocated in inode bitmap
    inode_bitmap[0] |= 1;

    // Initialize the root inode
    struct wfs_inode root_inode = {
        .num = 0,               // Root inode number
        .mode = S_IFDIR | 0755, // Directory with rwxr-xr-x permissions
        // .uid = getuid(),                // Owner UID
        // .gid = getgid(),               // Owner GID
        .uid = getuid(), // Owner UID
        .gid = getgid(),
        .size = 0,          // Initially empty
        .nlinks = 2,        // "." and parent link
        .atim = time(NULL), // Access time
        .mtim = time(NULL), // Modification time
        .ctim = time(NULL), // Change time
    };
    memset(root_inode.blocks, 0, sizeof(root_inode.blocks));

    // printf("Root inode initialization:\n");
    // printf("mode: %o, uid: %u, gid: %u, nlinks: %u\n", root_inode.mode, root_inode.uid, root_inode.gid, root_inode.nlinks);
    // printf("atim: %ld, mtim: %ld, ctim: %ld\n", root_inode.atim, root_inode.mtim, root_inode.ctim);

    // Initialize the superblock
    superblock.num_inodes = num_inodes;
    superblock.num_data_blocks = num_data_blocks;

    // printf("size of superblock %ld\n", sizeof(superblock));

    superblock.i_bitmap_ptr = sizeof(superblock);

    // Align inode bitmap pointer
    // size_t i_bitmap_end = superblock.i_bitmap_ptr + inode_bitmap_size;
    superblock.d_bitmap_ptr = sizeof(superblock) + inode_bitmap_size;

    // Align data bitmap pointer
    size_t d_bitmap_end = superblock.d_bitmap_ptr + data_bitmap_size;
    superblock.i_blocks_ptr = (d_bitmap_end + BLOCK_SIZE - 1) & ~(BLOCK_SIZE - 1);

    // Align data blocks pointer
    size_t i_blocks_end = superblock.i_blocks_ptr + num_inodes * BLOCK_SIZE;
    superblock.d_blocks_ptr = (i_blocks_end + BLOCK_SIZE - 1) & ~(BLOCK_SIZE - 1);

    superblock.raid_mode = raid_mode;
    superblock.num_disks = num_disks;

    // printf("Aligned inode bitmap starts at: %zu\n", superblock.i_bitmap_ptr);
    // printf("Aligned data bitmap starts at: %zu\n", superblock.d_bitmap_ptr);
    // printf("Aligned inode blocks start at: %zu\n", superblock.i_blocks_ptr);
    // printf("Aligned data blocks start at: %zu\n", superblock.d_blocks_ptr);
    /*
    ROUNDUP(num_data_blocks / num_inodes)*/
    // printf("%ld", superblock.d_blocks_ptr);

    // Write superblock, bitmaps, and root inode to each disk
    for (int i = 0; i < num_disks; i++)
    {
        // rewind(disks[i]); // Reset file pointer to the beginning of the disk

        // Write structures to the disk
        if (fwrite(&superblock, sizeof(superblock), 1, disks[i]) != 1)
        {
            perror("Failed to write superblock");
            exit(EXIT_FAILURE);
        }

        // old writes to disk, failed to properly reset pointer to beginning of file for correct pointer notation
        //  if (fwrite(inode_bitmap, inode_bitmap_size, 1, disks[i]) != 1)
        //  {
        //      perror("Failed to write inode bitmap");
        //      exit(EXIT_FAILURE);
        //  }

        // printf("Data Bitmap before write:\n");
        // for (size_t i = 0; i < data_bitmap_size; i++)
        // {
        //     printf("data_bitmap[%zu] = 0x%02x\n", i, data_bitmap[i]);
        // }
        // if (fwrite(data_bitmap, data_bitmap_size, 1, disks[i]) != 1)
        // {
        //     perror("Failed to write data bitmap");
        //     exit(EXIT_FAILURE);
        // }

        // if (fwrite(&root_inode, sizeof(root_inode), 1, disks[i]) != 1)
        // {
        //     perror("Failed to write root inode");
        //     exit(EXIT_FAILURE);
        // }

        // Write bitmaps
        fseek(disks[i], superblock.i_bitmap_ptr, SEEK_SET);
        if (fwrite(inode_bitmap, inode_bitmap_size, 1, disks[i]) != 1)
        {
            perror("Failed to write inode bitmap");
            exit(EXIT_FAILURE);
        }

        fseek(disks[i], superblock.d_bitmap_ptr, SEEK_SET);
        if (fwrite(data_bitmap, (num_data_blocks + 7) / 8, 1, disks[i]) != 1)
        {
            perror("Failed to write data bitmap");
            exit(EXIT_FAILURE);
        }

        // Write root inode
        fseek(disks[i], superblock.i_blocks_ptr, SEEK_SET);
        if (fwrite(&root_inode, sizeof(root_inode), 1, disks[i]) != 1)
        {
            perror("Failed to write root inode");
            exit(EXIT_FAILURE);
        }
    }

    printf("Filesystem initialized successfully with RAID mode %d on %d disk(s).\n", raid_mode, num_disks);
}

int main(int argc, char *argv[])
{
    // Ensure correct number of arguments is passed
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s [-r <raid_mode>] -d <disk1> -d <disk2> ... -i <num_inodes> -b <num_data_blocks>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Debug: Print all arguments for checking
    //printf("Debug: Received %d arguments:\n", argc);
    for (int i = 0; i < argc; i++)
    {
        //printf("  argv[%d]: %s\n", i, argv[i]);
    }

    // Parse and validate arguments
    if (paramcheck(argc, argv) == EXIT_FAILURE)
    {
        printf("Failed paramcheck\n");
        // exit(EXIT_FAILURE);
        return EXIT_FAILURE;
    }

    // Ensure number of inodes and data blocks are valid
    if (num_inodes == 0 || num_data_blocks == 0)
    {
        fprintf(stderr, "Error: Number of inodes and data blocks must be greater than 0.\n");
        exit(EXIT_FAILURE);
    }

    // Initialize the filesystem with the given parameters
    initialize_filesystem(disks, num_disks, num_inodes, num_data_blocks, raid_mode);
    printf("Finished initialization\n");

    // Read back and verify data from the disks
    read_filesystem(disks, num_disks);

    // Close the disk files
    for (int i = 0; i < num_disks; i++)
    {
        fclose(disks[i]);
    }

    printf("Finished main\n");
    return EXIT_SUCCESS;
}
