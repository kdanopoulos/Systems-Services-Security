
Σύμφωνα με το Task F πραγματοποιήθηκαν οι παρακάτω εκτελέσεις. Τα αποτελέσματα αποθηκέθτηκαν στον φάκελο src όπου βρίσκεται και ο κώδικας με το makefile. Τα δύο verify του τελαυταίου ερωτήματος του Task F δεν επαληθεύτικαν κανένα από τα δύο για αυτό και δεν έχουν αποθηκευτεί τα αρχέια τους. Η λειτουργία verify και sign δοκιμάστηκαν και σε πρόχειρα αρχεία και λειτουργεί κανονικά. 

./assign_1 -i ../files/hpy414_verifyme_128.txt -o verify_output_128 -p hpy414 -b 128 -v
./assign_1 -i ../files/hpy414_verifyme_256.txt -o verify_output_256 -p hpy414 -b 256 -v
./assign_1 -i ../files/signme_128.txt -o verifyme_128.txt -p TUC2016030131 -b 128 -s
./assign_1 -i ../files/hpy414_decryptme_128.txt -o hpy414_encryptme_128.txt -p hpy414 -b 128 -d
./assign_1 -i ../files/encryptme_256.txt -o decryptme_256.txt -p TUC2016030131 -b 256 -e

Ο κώδικας λειτουργεί και πραγματοποιεί όλες τις απαιτήσεις της εκφώνησης. Για την δημιουργγία του χρειάστηκε να υλοποιηθούν αρκετές συναρτήσεις. Μεσα στον κώδικα υπάρχουν και εξτρα συναρτήσεις που υλοποιήθηκαν αρχικά αλλα τελικα χρήση του δεν είχε κάποιο λόγο. Για την υλοποίηση του sign και verify αρχικά είχα σχεδιάσει να ενώνονται το κείμενο με το cmac του με τους χαρακτήρες : \n|k και είχα δημιουργήσει αντίστοιχες συναρτήσεις για να τα διαβάζουμε από αρχεία και να τα αποθηκεύουμε αλλα στην συνέχεια αντιληφθηκα ότι τα κρυπτογραφημένα αρχεία χρειάζεται να έχουν συγκεκριμένα μήκη (Πολλαπλασιο του 16) οπότε αυτή η υλοποίηση καταργήθηκε. Για τις 4 διαφορετικές περιπτώσεις (-e -d -s -v) έχουν υλοποιηθεί 4 συναρτήσεις που συνοψίζουν όλες τις λειτουργίες τους. Οι συναρτήσεις αυτές οι οποίες καλούνται μέσα στην main είναι οι εξής :

void encryptAndStore(char *,char *,unsigned char *, unsigned char *,int );

void decryptAndStore(char *,char *,unsigned char *, unsigned char *,int );

void encryptAndStoreWithCMAC(char *,char *,unsigned char *, unsigned char *,int );

int decryptVerifyAndStore(char *,char *,unsigned char *, unsigned char *,int );


Author : Konstantinos Danopoulos 2016030131
