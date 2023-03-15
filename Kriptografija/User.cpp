#include "User.h"






string User::getCommonName() const
{
    return this->commonName;
}

void User::setCommonName(string commonName)
{
    this->commonName = commonName;
}

string User::getPassword() const
{
    return this->password;
}

void User::setPassword(string password)
{
    this->password = password;
}

string User::getCountry() const
{
    return this->country;
}

void User::setCountry(string country)
{
    this->country = country;
}

string User::getState() const
{
    return this->state;
}

void User::setState(string state)
{
    this->state = state;
}

string User::getLocality() const
{
    return this->locality;
}

void User::setLocality(string locality)
{
    this->locality = locality;
}

string User::getOrganisationName() const
{
    return this->organisationName;
}

void User::setOrganisationName(string organisationName)
{
    this->organisationName = organisationName;
}

string User::getOrganisationalUnit() const
{
    return this->organisationalUnit;
}

void User::setOrganisationalUnit(string organizationalUnit)
{
    this->organisationalUnit = organisationalUnit;
}

string User::getEmailAddress() const
{
    return this->emailAddress;
}

void User::setEmailAddress(string emailAddress)
{
    this->emailAddress = emailAddress;
}

EVP_PKEY* User::getPkey() const
{
    return this->pkey;
}

void User::setPkey(EVP_PKEY *pkey)
{
    this->pkey = pkey;
}

// -----------------------------------  


User::User() : country("XX"), state("XX"), locality("XX"), organisationName("XX"), 
                organisationalUnit("XX"), emailAddress("XX"), commonName("NN"), password(""), 
                 userCertificate(nullptr), pkey(nullptr) {}

User::~User()
{
    if (userCertificate != nullptr)
        X509_free(userCertificate);
    if (pkey != nullptr)
        EVP_PKEY_free(pkey);
}

// -----------------------------------

int User::setAllCredentials()
{
    string password = "x", repeatPassword = "o";		// Login credentials are commonName and password



    std::cout << "\nOdaberite vase korisnicko ime: ";
    std::cin >> this->commonName;

    while (password != repeatPassword) {
        std::cout << "\nOdaberite vasu lozinku: ";
        std::cin >> password;

        std::cout << "\nPotvrdite unos lozinke: ";
        std::cin >> repeatPassword;
    }
    this->password = password;

    std::cout << "\nUnesite email: ";
    std::cin >> this->emailAddress;

    std::cout << "\nUnesite drzavu: ";
    std::cin >> this->country;

    std::cout << "\nUnesite entitet: ";
    std::cin >> this->state;

    std::cout << "\nUnesite grad: ";
    std::cin >> this->locality;

    std::cout << "\nUnesite ime organizacije: ";
    std::cin >> this->organisationName;

    std::cout << "\nUnesite ime organizacione jedinice: ";
    std::cin >> this->organisationalUnit;

    return 0;
}

int User::writeUser()
{
    string pathToFolder = "./Korisnici/" + this->commonName + "/";
    string filename = pathToFolder + this->commonName + "_user.dat";
    
    std::ofstream myFile(filename.c_str(), std::ios::out | std::ios::binary);
    if (!myFile) return 0;

    myFile.write((char*)this, sizeof(User));



    myFile.close();
    return 1;
}

int User::readUser()
{
    string pathToFolder = "./Korisnici/" + this->commonName + "/";
    string filename = pathToFolder + this->commonName + "_user.dat";

    std::ifstream myFile(filename.c_str(), std::ios::in | std::ios::binary);
    if (!myFile) return 0;

    myFile.read((char*)this, sizeof(User));



    myFile.close();
    return 1;
}

int User::writePrivateKey()
{
    string pathToFolder = "./Korisnici/" + this->commonName + "/";
    string filename = pathToFolder + this->commonName + ".key";

    
    int rc;
    if (pkey == nullptr) return 0;

    BIO* bio_out = BIO_new_file(filename.c_str(), "w");

    rc = PEM_write_bio_PrivateKey(bio_out, pkey, NULL, NULL, 0, 0, (void*)PASSPHRASE);            //       --- PROVJERITI MOGUCNOST ENKRIPCIJE KLJUCA ---


    BIO_free(bio_out);
    return 1;       //return rc;
}

int User::writeCertificate()
{
    string pathToFolder = "./Korisnici/" + this->commonName + "/";
    string filename = pathToFolder + this->commonName + ".crt";

    int rc = 0;
    BIO* bio_out = NULL;
    if (userCertificate == nullptr) return 0;

    bio_out = BIO_new_file(filename.c_str(), "w");

    rc = PEM_write_bio_X509(bio_out, userCertificate);


    BIO_free(bio_out);
    return 1;
}

