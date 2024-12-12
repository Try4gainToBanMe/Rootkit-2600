obj-m += rootkit.o

all:
 # Faites attention à utiliser des tabulations et pas des espaces !
 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
 # Notez bien la tabulation avant "make" svp
 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
