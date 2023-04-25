# Kriptografija
Projekat urađen na predmetu Kriptografija i računarska zaštita, 2023. godine.

Aplikacija predstavlja siguran repozitorijum za skladištenje povjerljivih dokumenata. Aplikacija omogućuje skladištenje dokumenata za veći broj korisnika tako da je pristup određenom dokumentu dozvoljen samo njegovom vlasniku. 
Aplikacija podrazumijeva postojanje infrastrukture javnog ključa, dvofaktorsku autentikaciju na osnovu korisničkog imena i lozinke i na osnovu digitalnog sertifikata. . .

.
.
.
 
To ensure that file fragments are not changed (file integrity), we could calculate hash of each fragment - digital signature.
To make decryption easier, instead of a random key for file fragments encryption, we could use user's public key for encryption and his private key for decryption.
To save the symmetric key, we use digital envelope mechanism (encrypting the symmetric key with asymmetric one).
 

