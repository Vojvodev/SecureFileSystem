

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
    int control = 0;

    do {

        std::cout << "\nChoose your user name: ";
        std::cin >> this->commonName;


        
        string pathToFolder = "./Data/Korisnici/" + this->commonName + "/";
        string filename = pathToFolder + this->commonName + "_user.dat";



        std::ifstream isDuplicate(filename.c_str(), std::ios::in);
        if (isDuplicate.is_open()) { isDuplicate.close(); std::cout << "Name not available. Try a different one. \n"; control = 0; }
        else control = 1;
    } while (!control);






    while (password != repeatPassword) {
        std::cout << "\nChoose your password: ";
        std::cin >> password;

        std::cout << "\nRepat password: ";
        std::cin >> repeatPassword;
    }
    this->password = password;

    std::cout << "\nWrite your email: ";
    std::cin >> this->emailAddress;

    std::cout << "\nWrite your country name: ";
    std::cin >> this->country;

    std::cout << "\nWrite your state name: ";
    std::cin >> this->state;

    std::cout << "\nWrite your town name [locality]: ";
    std::cin >> this->locality;

    std::cout << "\nWrite your organisation name: ";
    std::cin >> this->organisationName;

    std::cout << "\nWrite your organisational unit name: ";
    std::cin >> this->organisationalUnit;

    return 0;
}

int User::writeUser()
{
    string pathToFolder = "./Data/Korisnici/" + this->commonName + "/";
    string filename = pathToFolder + this->commonName + "_user.dat";
    

    std::ofstream myFile(filename.c_str(), std::ios::out | std::ios::binary);
    if (!myFile) return 0;

    myFile.write((this->country).c_str(),            sizeof(this->country));
    myFile.write((this->state).c_str(),              sizeof(this->state));
    myFile.write((this->locality).c_str(),           sizeof(this->locality));
    myFile.write((this->organisationName).c_str(),   sizeof(this->organisationName));
    myFile.write((this->organisationalUnit).c_str(), sizeof(this->organisationalUnit));
    myFile.write((this->emailAddress).c_str(),       sizeof(this->emailAddress));
    myFile.write((this->commonName).c_str(),         sizeof(this->commonName));
    myFile.write((this->password).c_str(),           sizeof(this->password));



    myFile.close();
    return 1;
}

int User::readUser(string commonName)
{
    string pathToFolder = "./Data/Korisnici/" + commonName + "/";
    string filename = pathToFolder + commonName + "_user.dat";

    std::ifstream myFile(filename.c_str(), std::ios::in | std::ios::binary);
    if (!myFile) return 0;

    myFile.read(&(this->country)[0], sizeof(this->country));   // To convert string to char*
    myFile.read(&(this->state)[0], sizeof(this->state));
    myFile.read(&(this->locality)[0], sizeof(this->locality));
    myFile.read(&(this->organisationName)[0], sizeof(this->organisationName));
    myFile.read(&(this->organisationalUnit)[0], sizeof(this->organisationalUnit));
    myFile.read(&(this->emailAddress)[0], sizeof(this->emailAddress));
    myFile.read(&(this->commonName)[0], sizeof(this->commonName));
    myFile.read(&(this->password)[0], sizeof(this->password));


    myFile.close();
    return 1;
}

int User::writePrivateKey()
{
    string pathToFolder = "./Data/Korisnici/" + this->commonName + "/";
    string filename = pathToFolder + this->commonName + ".key";

    
    int rc;
    if (pkey == nullptr) return 0;

    BIO* bio_out = BIO_new_file(filename.c_str(), "w");

    // Kljuc je zapisan u datoteku i kriptovan je korisnickom sifrom i u datoteci pise --begin encrypted private key-- unmjesto samo private key
    rc = PEM_write_bio_PrivateKey(bio_out, pkey, EVP_aes_256_cbc(), reinterpret_cast<const unsigned char*>((this->password).c_str()), strlen((this->password).c_str()), NULL, NULL);


    BIO_free(bio_out);
    return 1;       //return rc;
}

int User::writeCertificate()
{
    string pathToFolder = "./Data/Korisnici/" + this->commonName + "/";
    string filename = pathToFolder + this->commonName + ".crt";

    int rc = 0;
    BIO* bio_out = NULL;
    if (userCertificate == nullptr) return 0;

    bio_out = BIO_new_file(filename.c_str(), "w");

    rc = PEM_write_bio_X509(bio_out, userCertificate);


    BIO_free(bio_out);
    return 1;
}

