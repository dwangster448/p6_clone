#include "wfs.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
// #include <stdint.h>
// #include <unistd.h>
// #include <errno.h>
// #include <sys/stat.h>
#include <fuse.h>

void initialize_filesystem(FILE **disks, int num_disks, size_t num_inodes, size_t num_data_blocks, uint8_t raid_mode) {
    // Calculate bitmap sizes
    size_t inode_bitmap_size = (num_inodes + 7) / 8; // Rounded up to nearest byte
    size_t data_bitmap_size = (num_data_blocks + 7) / 8;

    // Allocate and zero-initialize bitmaps
    char inode_bitmap[inode_bitmap_size];
    char data_bitmap[data_bitmap_size];
    memset(inode_bitmap, 0, inode_bitmap_size);
    memset(data_bitmap, 0, data_bitmap_size);

    // Mark root inode as allocated in inode bitmap
    inode_bitmap[0] |= 1;

    // Initialize the root inode
    struct wfs_inode root_inode = {
        .num = 0,                      // Root inode number
        .mode = S_IFDIR | 0755,        // Directory with rwxr-xr-x permissions
        .uid = getuid(),               // Owner UID
        .gid = getgid(),               // Owner GID
        .size = 0,                     // Initially empty
        .nlinks = 2,                   // "." and parent link
        .atim = time(NULL),            // Access time
        .mtim = time(NULL),            // Modification time
        .ctim = time(NULL),            // Change time
    };
    memset(root_inode.blocks, 0, sizeof(root_inode.blocks));

    // Initialize the superblock
    struct wfs_sb superblock = {
        .num_inodes = num_inodes,
        .num_data_blocks = num_data_blocks,
        .i_bitmap_ptr = sizeof(superblock),
        .d_bitmap_ptr = sizeof(superblock) + inode_bitmap_size,
        .i_blocks_ptr = sizeof(superblock) + inode_bitmap_size + data_bitmap_size,
        .d_blocks_ptr = sizeof(superblock) + inode_bitmap_size + data_bitmap_size + num_inodes * sizeof(struct wfs_inode),
        .raid_mode = raid_mode,
        .num_disks = num_disks
    };

    // Write superblock, bitmaps, and root inode to each disk
    for (int i = 0; i < num_disks; i++) {
        rewind(disks[i]); // Reset file pointer to the beginning of the disk

        // Write structures to the disk
        if (fwrite(&superblock, sizeof(superblock), 1, disks[i]) != 1) {
            perror("Failed to write superblock");
            exit(EXIT_FAILURE);
        }
        if (fwrite(inode_bitmap, inode_bitmap_size, 1, disks[i]) != 1) {
            perror("Failed to write inode bitmap");
            exit(EXIT_FAILURE);
        }
        if (fwrite(data_bitmap, data_bitmap_size, 1, disks[i]) != 1) {
            perror("Failed to write data bitmap");
            exit(EXIT_FAILURE);
        }
        if (fwrite(&root_inode, sizeof(root_inode), 1, disks[i]) != 1) {
            perror("Failed to write root inode");
            exit(EXIT_FAILURE);
        }
    }

    printf("Filesystem initialized successfully with RAID mode %d on %d disk(s).\n", raid_mode, num_disks);
}

int main(int argc, char *argv[]) {
    //return 1000;
    if (argc < 5) {
        fprintf(stderr, "Usage: %s -r <raid_mode> -d <disk1> -d <disk2> ... -i <num_inodes> -b <num_data_blocks>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Debug: Print all arguments
    printf("Debug: Received %d arguments:\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("  argv[%d]: %s\n", i, argv[i]);
    }

    uint8_t raid_mode = 0;
    size_t num_inodes = 0, num_data_blocks = 0;
    FILE *disks[10];
    int num_disks = 0;

//return 1000;
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            raid_mode = (uint8_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0) {
            if (num_disks >= 10) {
                fprintf(stderr, "Too many disks specified. Maximum supported is 10.\n");
                return EXIT_FAILURE;
            }
            disks[num_disks] = fopen(argv[++i], "r+b");
            if (!disks[num_disks]) {
                perror("Failed to open disk file");
                return EXIT_FAILURE;
            }
            num_disks++;
        } else if (strcmp(argv[i], "-i") == 0) {
            num_inodes = (size_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0) {
            num_data_blocks = (size_t)atoi(argv[++i]);
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }
    //return 1000;
    if (raid_mode == 0 && num_disks < 2) {
        fprintf(stderr, "Error: RAID 0 requires at least 2 disks.\n");
        return EXIT_FAILURE;
    }

    //return 1000;

    if (raid_mode > 0 && num_disks < 1) {
        fprintf(stderr, "Error: RAID 1/1v requires at least 1 disk.\n");
        return EXIT_FAILURE;
    }

    if (num_inodes == 0 || num_data_blocks == 0) {
        fprintf(stderr, "Error: Number of inodes and data blocks must be greater than 0.\n");
        return EXIT_FAILURE;
    }

    initialize_filesystem(disks, num_disks, num_inodes, num_data_blocks, raid_mode);

    // Close disk files
    for (int i = 0; i < num_disks; i++) {
        fclose(disks[i]);
    }

    return EXIT_SUCCESS;
}
