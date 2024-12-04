#define FUSE_USE_VERSION 30
#include "wfs.h" // Ensure wfs.h is included for super_block reads
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

// Global variable for RAID mode
int raid_mode = -1; // Default to -1, meaning no RAID mode

// Function prototypes
void param_check(int argc, char *argv[], int *raid_mode, char *disks[], int *disk_count, char **mount_point, char *fuse_argv[], int *fuse_argc);
void validate_raid_config(int raid_mode, int disk_count);
void initialize_raid(int raid_mode, char *disks[], int disk_count);
void prepare_fuse_args(int argc, char *argv[], int disk_count, char *fuse_argv[], int *fuse_argc);

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

static int wfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    printf("[DEBUG] mknod called for path: %s\n", path);
    // Create a new file in RAID
    return EXIT_SUCCESS; // return EXIT_SUCCESS on success
}

static int wfs_mkdir(const char *path, mode_t mode)
{
    printf("[DEBUG] mkdir called for path: %s\n", path);
    // Create a new directory in RAID
    return EXIT_SUCCESS; // return EXIT_SUCCESS on success
}

static int wfs_unlink(const char *path)
{
    printf("[DEBUG] unlink called for path: %s\n", path);
    // Delete a file in RAID
    return EXIT_SUCCESS; // return EXIT_SUCCESS on success
}

static int wfs_rmdir(const char *path)
{
    printf("[DEBUG] rmdir called for path: %s\n", path);
    // Delete a directory in RAID
    return EXIT_SUCCESS; // return EXIT_SUCCESS on success
}

static int wfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("[DEBUG] read called for path: %s\n", path);
    // Read data from RAID
    return size; // Return number of bytes read
}

static int wfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    printf("[DEBUG] write called for path: %s\n", path);
    // Write data to RAID
    return size; // Return number of bytes written
}

static int wfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    printf("[DEBUG] readdir called for path: %s\n", path);

    // Example: adding "." and ".." to directory
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    // Add other files/directories
    filler(buf, "file", NULL, 0); // Example

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

int read_superblock(FILE *disk, struct wfs_sb *sb)
{
    // Seek to the start of the disk (superblock is at offset 0)
    fseek(disk, 0, SEEK_SET);

    // Read the superblock data
    size_t bytes_read = fread(sb, sizeof(struct wfs_sb), 1, disk);
    
    if (bytes_read != 1)
    {
        fprintf(stderr, "[ERROR] Failed to read the superblock.\n");
        return -1;  // Return an error if reading failed
    }

    return EXIT_SUCCESS;  // Success
}

void initialize_raid(int raid_mode, char *disks[], int disk_count)
{
    printf("[INFO] Initializing RAID mode: %d\n", raid_mode);

    FILE *disk = fopen(disks[0], "rb");
    if (!disk)
    {
        fprintf(stderr, "[ERROR] Failed to open disk: %s\n", disks[0]);
        exit(EXIT_FAILURE);
    }

    struct wfs_sb sb;

    // Read the superblock from the disk
    if (read_superblock(disk, &sb) != 0)
    {
        fclose(disk);
        exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }

    printf("[INFO] RAID initialized successfully.\n");
}

// Function to retrieve RAID mode from the superblock
void retrieve_raid_mode(const char *disk_path)
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
    raid_mode = sb.raid_mode;
    printf("[INFO] Retrieved RAID mode from superblock: %d\n", raid_mode);

    fclose(disk); // Close the disk file after reading the superblock
}

int main(int argc, char *argv[])
{
    char *disks[3] = {NULL, NULL, NULL};
    int disk_count = 0;
    char *mount_point = NULL;
    char *fuse_argv[argc];  // Array to store FUSE arguments
    int fuse_argc = 0;

    // Debug output for arguments
    printf("argv[1]: %s\n", argv[1]);

    // Parse the command-line arguments
    param_check(argc, argv, &raid_mode, disks, &disk_count, &mount_point, fuse_argv, &fuse_argc);

    printf("RAID MODE before paramcheck: %d\n", raid_mode);

    validate_raid_config(raid_mode, disk_count);

    initialize_raid(raid_mode, disks, disk_count);

    // Print FUSE arguments for debugging
    printf("[DEBUG] Initializing FUSE with arguments:\n");
    for (int i = 0; i < fuse_argc; i++)
    {
        printf("  fuse_argv[%d]: %s\n", i, fuse_argv[i]);
    }

    fuse_main(fuse_argc, fuse_argv, &wfs_operations, NULL);

    printf("[INFO] FUSE initialized successfully.\n");
    return EXIT_SUCCESS;
}

// Function to check and validate parameters
void param_check(int argc, char *argv[], int *raid_mode, char *disks[], int *disk_count, char **mount_point, char *fuse_argv[], int *fuse_argc)
{
    printf("[DEBUG] Parsing parameters:\n");
    for (int i = 0; i < argc; i++)
    {
        printf("  argv[%d]: %s\n", i, argv[i]);
    }

    // Initialize disk_count first
    *disk_count = 0;

    // Parse the arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
        {
            *raid_mode = atoi(argv[++i]);  // Set RAID mode if passed via -r
        }
        else if (strncmp(argv[i], "-d", 2) == 0 && i + 1 < argc)
        {
            // Assign disks to the array
            if (*disk_count < 3)
            {
                disks[*disk_count] = argv[i + 1];
                (*disk_count)++;
                i++;  // Skip next argument (the disk path)
            }
            else
            {
                fprintf(stderr, "[ERROR] Too many disks provided.\n");
                exit(EXIT_FAILURE);
            }
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            break;  // Stop parsing when "-s" is encountered
        }
        else if (argv[i][0] != '-')  // Last argument is the mount point
        {
            *mount_point = argv[i];
        }
    }

    // If no RAID mode is provided, attempt to retrieve it from the first disk's superblock
    if (*raid_mode == -1 && *disk_count > 0)
    {
        printf("[DEBUG] Attempting to retrieve RAID mode from disk: %s\n", disks[0]);
        retrieve_raid_mode(disks[0]);  // This should update raid_mode globally
        printf("[INFO] Retrieved RAID mode from superblock: %d\n", *raid_mode);
    }

    // Validate RAID mode
    if (*raid_mode != 0 && *raid_mode != 1)
    {
        fprintf(stderr, "[ERROR] Invalid RAID mode: %d\n", *raid_mode);
        exit(EXIT_FAILURE);
    }

    // Print disk count for debugging
    printf("Disk_count: %d\n", *disk_count);

    // Ensure at least 2 disks are provided
    if (*disk_count < 2)
    {
        fprintf(stderr, "[ERROR] Insufficient disks. At least 2 disks are required.\n");
        exit(EXIT_FAILURE);
    }
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

void prepare_fuse_args(int argc, char *argv[], int disk_count, char *fuse_argv[], int *fuse_argc)
{
    fuse_argv[(*fuse_argc)++] = argv[0]; // Program name

    // Skip over disk arguments and collect FUSE options
    for (int i = disk_count * 2 + 1; i < argc; i++)
    {
        fuse_argv[(*fuse_argc)++] = argv[i];
    }
    fuse_argv[(*fuse_argc)++] = "-o";
    fuse_argv[(*fuse_argc)++] = "nonempty";
}
