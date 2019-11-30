//Filename: main.c
//Team Members: Ryan Harmon
//UTD_ID: rxh107020
//NetID: rxh107020
//Class: Operating Systems
//Project: 3

#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>


#define FREE_SIZE 152
#define I_SIZE 200
#define BLOCK_SIZE 1024
#define ADDR_SIZE 11
#define INPUT_SIZE 256

// Superblock Structure
// need to make packed so it is exactly 1024 bytes
typedef struct __attribute__ ((__packed__)) {
  unsigned short isize;
  unsigned short fsize;
  unsigned short nfree;
  unsigned int free[FREE_SIZE];
  unsigned short ninode;
  unsigned short inode[I_SIZE];
  char flock;
  char ilock;
  unsigned short fmod;
  unsigned short time[2];
} superblock_type;

superblock_type superBlock;

void print_super_block(superblock_type *sp) {
    printf("SUPER BLOCK\n");
    printf("isize: %d\n", sp->isize);
    printf("fsize: %d\n", sp->fsize);
    printf("nfree: %d\n", sp->nfree);
    printf("free block: %d\n", sp->free[0]);
    printf("ninode: %d\n", sp->ninode);
    printf("flock: %d\n", sp->flock);
    printf("ilock: %d\n", sp->ilock);
    printf("fmod: %d\n", sp->fmod);
    printf("time0: %d\n", sp->time[0]);
    printf("time1: %d\n", sp->time[1]);
}

// I-Node Structure

typedef struct {
unsigned short flags;
unsigned short nlinks;
unsigned short uid;
unsigned short gid;
unsigned int size;
unsigned int addr[ADDR_SIZE];
unsigned short actime[2];
unsigned short modtime[2];
} inode_type;

typedef struct {
  unsigned short inode;
  unsigned char filename[14];
} dir_type;

int initfs(char* path, unsigned short total_blcks,unsigned short total_inodes);
void add_block_to_free_list( int blocknumber , unsigned int *empty_buffer );
int get_block_from_free_list();
void create_root();
int preInitialization(); // need to declare this function before we can use it
void print_dir(int data_block);
void print_inode(inode_type inode);
void print_raw(void* buf, int size);
void create_dir(char* dirname, int inum);
void get_free(inode_type *in, int* block, int* offset);
int read_inode(inode_type *in, int inum);
int write_inode(inode_type *in, int inum);
int write_dir(dir_type *dir, int block, int offset);
int get_block(inode_type *in, int desired_byte, int *block, int *offset);
int file_exists(char* newfilename, int inum, int* byte_offset);
void remove_dir(char* dir_name, int curr_dir);
int get_free_inode();
void create_dir_inode(int inode_num, int parent_inode_num);
int change_dir(char *new_dir);
void print_working_dir(int curr_dir);
void get_dir_by_inode(int inum, int seek_inum);

#define NUM2BLOCK(X)    (X*(BLOCK_SIZE))

int inum_to_byte(int inum) {
    return 2*BLOCK_SIZE + (inum - 1)*sizeof(inode_type);
}

inode_type inode;
unsigned short curr_dir;

dir_type root;

int fileDescriptor ;		//file descriptor
const unsigned short inode_alloc_flag = 0100000;
const unsigned short dir_flag = 040000;
const unsigned short dir_large_file = 010000;
const unsigned short dir_access_rights = 000777; // User, Group, & World have all access privileges
const unsigned short INODE_SIZE = 64; // inode has been doubled

int main() {
  char input[INPUT_SIZE];
  char *splitter, *tmp_name;
  unsigned int numBlocks = 0, numInodes = 0;

  while(1) {
    // command prompt should go here, without newline at end
    printf("> ");

    scanf(" %[^\n]s", input);
    splitter = strtok(input," ");

    if(strcmp(splitter, "initfs") == 0) {

        int res = preInitialization();
        if(res < 0) {
            curr_dir = 0;
        }
        else {
            curr_dir = 1;
        }

        splitter = NULL;
    }
    else if(strcmp(splitter, "cpin") == 0 ) {
        printf("cpin not yet implemented\n");
        splitter = NULL;
    }
    else if(strcmp(splitter, "cpout") == 0 ) {
        printf("cpout not yet implemented\n");
        splitter = NULL;
    }
    else if(strcmp(splitter, "mkdir") == 0 ) {
        tmp_name = strtok(NULL, " ");
        if(strlen(tmp_name) > 15) {
            fprintf(stderr, "Directory name is too long!\n");
        }
        else {
            create_dir(tmp_name, curr_dir);
        }
        splitter = NULL;
    }
    else if(strcmp(splitter, "rm") == 0 ) {
        printf("rm not yet implemented\n");
        splitter = NULL;
    }
    else if(strcmp(splitter, "ls") == 0 ) {
        print_dir(curr_dir);
        splitter = NULL;
    }
    else if(strcmp(splitter, "pwd") == 0 ) {
        int pres_dir = curr_dir;
        print_working_dir(curr_dir);
        printf("\n");
        curr_dir = pres_dir;

        splitter = NULL;
    }
    else if(strcmp(splitter, "cd") == 0 ) {
        tmp_name = strtok(NULL, " ");

        int orig_dir = curr_dir;
        if(tmp_name[0] == '/') {
            curr_dir = 1;
            if(tmp_name[1] == 0) {
                continue;
            }
        }

        char* next_dir = strtok(tmp_name, "/");
        if(next_dir == NULL) {
            if(change_dir(tmp_name) != 0) {
                curr_dir = orig_dir;
            }
        }
        else {
            if(change_dir(next_dir) != 0) {
                curr_dir = orig_dir;
            }
            while((next_dir = strtok(NULL, "/")) != NULL) {
                if(change_dir(next_dir) != 0) {
                    curr_dir = orig_dir;
                }
            }
        }

        splitter = NULL;
    }
    else if(strcmp(splitter, "rmdir") == 0 ) {
        tmp_name = strtok(NULL, " ");
        if(strlen(tmp_name) > 15) {
            fprintf(stderr, "Directory name is too long!\n");
        }
        else {
            remove_dir(tmp_name, curr_dir);
        }

        splitter = NULL;
    }
    else if(strcmp(splitter, "open") == 0 ) {
        printf("open not yet implemented\n");
        splitter = NULL;
    }
    else if (strcmp(splitter, "q") == 0) {

       lseek(fileDescriptor, BLOCK_SIZE, 0);
       write(fileDescriptor, &superBlock, BLOCK_SIZE);
       return 0;

    }
    else {
        printf("Unknown command received\n");
        splitter = NULL;
    }
  }
}

int preInitialization(){

    char *n1, *n2;
    unsigned int numBlocks = 0, numInodes = 0;
    char *filepath;

    filepath = strtok(NULL, " ");
    n1 = strtok(NULL, " ");
    n2 = strtok(NULL, " ");


    if(access(filepath, F_OK) != -1) {

        if((fileDescriptor = open(filepath, O_RDWR, 0700)) == -1){
            printf("\n filesystem already exists but open() failed with error [%s]\n", strerror(errno));
            return -1;
        }

        printf("filesystem already exists and the same will be used\n");

        // read superBlock
        lseek(fileDescriptor, BLOCK_SIZE, 0);
        read(fileDescriptor, &superBlock, BLOCK_SIZE);
        return 1;

    }
    else {
        if (!n1 || !n2) {
            printf(" All arguments(path, number of inodes and total number of blocks) have not been entered\n");
            return -2;
        }
        else {
            numBlocks = atoi(n1);
            numInodes = atoi(n2);

            if( initfs(filepath,numBlocks, numInodes )){
                printf("The file system is initialized\n");
                lseek(fileDescriptor, BLOCK_SIZE, 0);
                read(fileDescriptor, &superBlock, BLOCK_SIZE);
                // print_super_block(&superBlock);
                // printf("superBlock read\n");
                // print_raw(&superBlock, BLOCK_SIZE);
                return 0;
            }
            else {
                printf("Error initializing file system. Exiting... \n");
                return -3;
            }
        }
    }
}

int initfs(char* path, unsigned short blocks,unsigned short inodes) {

   unsigned int buffer[BLOCK_SIZE/4];
   int bytes_written;

   unsigned short i = 0;
   superBlock.fsize = blocks;
   unsigned short inodes_per_block= BLOCK_SIZE/INODE_SIZE;

   if((inodes%inodes_per_block) == 0){
      superBlock.isize = inodes/inodes_per_block;
   }
   else
      superBlock.isize = (inodes/inodes_per_block) + 1;

   if((fileDescriptor = open(path,O_RDWR|O_CREAT,0700))== -1) {
       printf("\n open() failed with the following error [%s]\n",strerror(errno));
       return 0;
   }

   for (i = 0; i < FREE_SIZE; i++)
      superBlock.free[i] =  0;			//initializing free array to 0 to remove junk data. free array will be stored with data block numbers shortly.

   superBlock.nfree = 0;
   superBlock.ninode = I_SIZE;

   for (i = 0; i < I_SIZE; i++)
	    superBlock.inode[i] = i + 1;		//Initializing the inode array to inode numbers

   superBlock.flock = 'a'; 					//flock,ilock and fmode are not used.
   superBlock.ilock = 'b';
   superBlock.fmod = 0;
   superBlock.time[0] = 0;
   superBlock.time[1] = 1970;

   // writing zeroes to all inodes in ilist
   for (i = 0; i < BLOCK_SIZE/4; i++)
   	  buffer[i] = 0;

   for (i = 0; i < superBlock.isize; i++)
   	  write(fileDescriptor, buffer, BLOCK_SIZE);

   int data_blocks = blocks - 2 - superBlock.isize;
   int data_blocks_for_free_list = data_blocks - 1;

   // Create root directory
   create_root();

   for(i = 2 + superBlock.isize + 1; i < data_blocks_for_free_list; i++) {
      add_block_to_free_list(i , buffer);
   }

   lseek(fileDescriptor, BLOCK_SIZE, 0);
   write(fileDescriptor, &superBlock, BLOCK_SIZE); // writing superblock to file system

   return 1;
}

// Add Data blocks to free list
void add_block_to_free_list(int block_number,  unsigned int *empty_buffer){

  if(superBlock.nfree == FREE_SIZE) {
    int free_list_data[BLOCK_SIZE / 4], i;
    free_list_data[0] = FREE_SIZE;

    for(i = 0; i < BLOCK_SIZE / 4; i++) {
       if(i < FREE_SIZE) {
         free_list_data[i + 1] = superBlock.free[i];
       } else {
         free_list_data[i + 1] = 0; // getting rid of junk data in the remaining unused bytes of header block
       }
    }

    lseek( fileDescriptor, (block_number) * BLOCK_SIZE, 0 );
    write( fileDescriptor, free_list_data, BLOCK_SIZE ); // Writing free list to header block

    superBlock.nfree = 0;

  } else {

	lseek( fileDescriptor, (block_number) * BLOCK_SIZE, 0 );
    write( fileDescriptor, empty_buffer, BLOCK_SIZE );  // writing 0 to remaining data blocks to get rid of junk data
  }

  superBlock.free[superBlock.nfree] = block_number;  // Assigning blocks to free array
  ++superBlock.nfree;
}

int get_block_from_free_list() {
    // printf("nfree before decrement: %d\n", superBlock.nfree);
    superBlock.nfree--;
    if(superBlock.nfree == 0) {
        int new_block = superBlock.free[superBlock.nfree];
        if(new_block == 0) {
            printf("No free blocks left!\n");
            return 0;
        }

        superBlock.nfree = new_block;
        lseek(fileDescriptor, new_block*BLOCK_SIZE, 0);
        unsigned int new_free_list[100];
        read(fileDescriptor, &new_free_list, 200);
        for(int i = 0; i < 100; i++) {
            superBlock.free[i] = new_free_list[i];
        }
        return new_block;
    }

    return superBlock.free[superBlock.nfree];
}

// Create root directory
void create_root() {

  int root_data_block = 2 + superBlock.isize; // Allocating first data block to root directory
  int i;

  root.inode = 1;   // root directory's inode number is 1.
  root.filename[0] = '.';
  root.filename[1] = '\0';

  inode.flags = inode_alloc_flag | dir_flag | dir_large_file | dir_access_rights;   		// flag for root directory
  inode.nlinks = 0;
  inode.uid = 0;
  inode.gid = 0;
  inode.size = 2*sizeof(dir_type);
  inode.addr[0] = root_data_block;

  for( i = 1; i < ADDR_SIZE; i++ ) {
    inode.addr[i] = 0;
  }

  inode.actime[0] = 0;
  inode.modtime[0] = 0;
  inode.modtime[1] = 0;

  lseek(fileDescriptor, inum_to_byte(root.inode), 0);
  write(fileDescriptor, &inode, INODE_SIZE);

  // print_inode(inode);

  lseek(fileDescriptor, root_data_block*BLOCK_SIZE, 0);
  write(fileDescriptor, &root, 16);

  root.filename[0] = '.';
  root.filename[1] = '.';
  root.filename[2] = '\0';

  write(fileDescriptor, &root, 16);

}

void print_inode(inode_type inode) {
    printf("Inode:\n");
    printf("\tFlags: 0x%08X\n", inode.flags);
    printf("\tnlinks: %u\n", inode.nlinks);
    printf("\tuid: %u\n", inode.uid);
    printf("\tgid: %u\n", inode.gid);
    printf("\tSize: %d\n", inode.size);
    for(uint8_t i = 0; i < ADDR_SIZE; i++) {
        printf("\tADDR%u: %u\n", i, inode.addr[i]);
    }
    printf("\tactime: 0x%08X%08X\n", inode.actime[0], inode.actime[1]);
    printf("\tmodtime: 0x%08X%08X\n", inode.modtime[0], inode.modtime[1]);
}

void print_dir(int inum) {
    read_inode(&inode, inum);

    dir_type dir;
    int bytes_to_read = inode.size;
    int current_byte = 0;
    while(bytes_to_read > 0) {
        int block = 0, offset = 0;
        get_block(&inode, current_byte, &block, &offset);

        lseek(fileDescriptor, block*BLOCK_SIZE + offset, 0);
        ssize_t bytes_read = 0;
        if((bytes_read = read(fileDescriptor, &dir, sizeof(dir_type))) < 0) {
            fprintf(stderr, "An error occured while reading from file\n");
            return;
        }

        bytes_to_read -= bytes_read;
        current_byte += sizeof(dir_type);

        if(dir.inode != 0)
            printf(" %s\n", dir.filename);
    }
}

int file_exists(char* newfilename, int inum, int* byte_offset) {
    read_inode(&inode, inum);

    dir_type dir;
    int bytes_to_read = inode.size;
    int current_byte = 0;
    while(bytes_to_read > 0) {
        int block = 0, offset = 0;
        get_block(&inode, current_byte, &block, &offset);

        lseek(fileDescriptor, block*BLOCK_SIZE + offset, 0);
        ssize_t bytes_read = 0;
        if((bytes_read = read(fileDescriptor, &dir, sizeof(dir_type))) < 0) {
            fprintf(stderr, "An error occured while reading from file\n");
            return -1;
        }

        bytes_to_read -= bytes_read;
        current_byte += sizeof(dir_type);
        if(dir.inode == 0) {
            continue;
        }
        if(strcmp(newfilename, dir.filename) == 0) {
            *byte_offset = block*BLOCK_SIZE + offset;
            return 0;
        }
    }

    return 1;
}

int read_inode(inode_type *in, int inum) {
    lseek(fileDescriptor, inum_to_byte(inum), 0);
    if(read(fileDescriptor, in, sizeof(inode_type)) < 0) {
        fprintf(stderr, "An error occured while reading from file\n");
        return -1;
    }

    return 0;
}

int write_inode(inode_type *in, int inum) {
    lseek(fileDescriptor, inum_to_byte(inum), 0);
    if(write(fileDescriptor, in, sizeof(inode_type)) < 0) {
        fprintf(stderr, "An error occured while writing file\n");
        return -1;
    }

    return 0;
}

int write_dir(dir_type *dir, int block, int offset) {
    lseek(fileDescriptor, block*BLOCK_SIZE + offset, 0);
    write(fileDescriptor, dir, sizeof(dir_type));

    return 0;
}

void print_raw(void* buf, int size) {
    for(int i = 0; i < size; i++) {
        printf("%u: 0x%02X\n", i, *((uint8_t*)&buf + i));
    }
}

void create_dir(char* dirname, int inum) {
    int tmp;
    if(file_exists(dirname, inum, &tmp) == 0) {
        printf("A file with that name already exists\n");
        return;
    }

    read_inode(&inode, inum);

    int block = 0, offset = 0;
    get_free(&inode, &block, &offset);

    if(block == -1) {
        printf("Can't create file entry!\n");
        return;
    }

    int new_node = get_free_inode();

    create_dir_inode(new_node, inum);

    dir_type new_dir;
    new_dir.inode = new_node;
    memcpy(new_dir.filename, dirname, strlen(dirname) + 1);
    inode.size += sizeof(dir_type);

    write_inode(&inode, inum);
    write_dir(&new_dir, block, offset);
}

void get_free(inode_type *in, int* block, int* offset) {
    // TODO: check for large file
    if(((in->size + *offset) % 512) == 0) {
        printf("Need to allocate new block!\n");
    }

    get_block(in, in->size, block, offset);
}

int get_block(inode_type *in, int desired_byte, int *block, int *offset) {
    int idx = desired_byte/BLOCK_SIZE;
    if(idx < ADDR_SIZE) {
        *block = in->addr[idx];
        *offset = desired_byte % BLOCK_SIZE;
        return 0;
    }
    else {
        printf("File has become too large!\n");
        *block = -1;
        return -1;
    }
}

void remove_dir(char* dir_name, int curr_dir) {
    int location = 0;
    if(file_exists(dir_name, curr_dir, &location) != 0) {
        printf("Directory %s does not exist!\n", dir_name);
        return;
    }

    dir_type new_dir;
    new_dir.inode = 0;
    lseek(fileDescriptor, location, 0);
    write(fileDescriptor, &new_dir, sizeof(new_dir));

    // printf("File cleared at offset: %d\n", location);
}

int get_free_inode() {
    unsigned short inodes_per_block= BLOCK_SIZE/INODE_SIZE;
    unsigned short num_inodes = inodes_per_block * superBlock.isize;
    int inum = 2;
    // printf("Num inodes: %d\n", num_inodes);
    while(inum < num_inodes) {
        lseek(fileDescriptor, inum_to_byte(inum), 0);
        // printf("Going to offset: %d\n", inum_to_byte(inum));
        inode_type node;
        if(read(fileDescriptor, &node, sizeof(inode_type)) < 0) {
            fprintf(stderr, "Error reading\n");
            return -1;
        }

        if(node.flags & inode_alloc_flag) {
            // printf("inode %d already allocated\n", inum - 1);
        }
        else {
            return inum;
        }

        inum++;
    }

    printf("There are no more inodes to allocate!\n");
    return -1;
}

void create_dir_inode(int inode_num, int parent_inode_num) {
    int new_block = get_block_from_free_list();

    dir_type dir;
    dir.inode = inode_num;
    dir.filename[0] = '.';
    dir.filename[1] = '\0';

    inode_type in;
    in.flags = inode_alloc_flag | dir_flag | dir_large_file | dir_access_rights;
    in.nlinks = 0;
    in.uid = 0;
    in.gid = 0;
    in.size = 2*sizeof(dir_type);
    in.addr[0] = new_block;

    for(int i = 1; i < ADDR_SIZE; i++ ) {
      in.addr[i] = 0;
    }

    in.actime[0] = 0;
    in.modtime[0] = 0;
    in.modtime[1] = 0;

    lseek(fileDescriptor, inum_to_byte(dir.inode), 0);
    write(fileDescriptor, &in, INODE_SIZE);

    // print_inode(inode);

    lseek(fileDescriptor, new_block*BLOCK_SIZE, 0);
    write(fileDescriptor, &dir, sizeof(dir_type));

    dir.inode = parent_inode_num;
    dir.filename[0] = '.';
    dir.filename[1] = '.';
    dir.filename[2] = '\0';

    write(fileDescriptor, &dir, sizeof(dir_type));
}

int change_dir(char *new_dir) {
    int location = 0;
    if(file_exists(new_dir, curr_dir, &location) != 0) {
        printf("Directory %s does not exist!\n", new_dir);
        return -1;
    }

    dir_type dir;
    lseek(fileDescriptor, location, 0);
    read(fileDescriptor, &dir, sizeof(dir_type));
    curr_dir = dir.inode;
    return 0;
}

void print_working_dir(int dir) {
    if(curr_dir == 1) {
        printf("/");
        return;
    }

    int tmp_dir = curr_dir;
    change_dir("..");
    int parent_dir = curr_dir;
    print_working_dir(curr_dir);
    get_dir_by_inode(parent_dir, tmp_dir);
}

void get_dir_by_inode(int inum, int seek_inum) {
    read_inode(&inode, inum);

    dir_type dir;
    int bytes_to_read = inode.size;
    int current_byte = 0;
    while(bytes_to_read > 0) {
        int block = 0, offset = 0;
        get_block(&inode, current_byte, &block, &offset);

        lseek(fileDescriptor, block*BLOCK_SIZE + offset, 0);
        ssize_t bytes_read = 0;
        if((bytes_read = read(fileDescriptor, &dir, sizeof(dir_type))) < 0) {
            fprintf(stderr, "An error occured while reading from file\n");
            return;
        }

        bytes_to_read -= bytes_read;
        current_byte += sizeof(dir_type);
        if(dir.inode == 0) {
            continue;
        }
        if(dir.inode == seek_inum) {
            printf("%s/", dir.filename);
            return;
        }
    }

    printf("AAAAAAAAARG!!\n");
}
