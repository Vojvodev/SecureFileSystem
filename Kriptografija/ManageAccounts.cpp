

#include "ManageAccounts.h"





int registrate()
{

	X509Certificate myCertificate;
	User newUser;

		// User adds his name, password, country, ...
		if (newUser.setAllCredentials()) {
			std::cout << "CAN NOT SET CREDENTIALS \n";
			return -1;
		}
		
		// Creating a key pair
		newUser.pkey = myCertificate.generatePkey();
		if (!newUser.pkey) {
			std::cout << "CAN NOT GENERATE KEY \n";
			return -1;
		}
	
		
		// Creating new certificate
		newUser.userCertificate = myCertificate.generateCertificate(&newUser);
		if (!newUser.userCertificate) {
			std::cout << "CAN NOT GENERATE CERTIFICATE \n";
			return -1;
		}
	
		
		// Storing user's private key to a binary file
		if (!newUser.writePrivateKey()) {
			std::cout << "CAN NOT STORE PRIVATE KEY \n";
			return -1;
		}
	
		
		// Storing user certificate to a binary file
		if (!newUser.writeCertificate()) {
			std::cout << "CAN NOT STROTE CERTIFICATE \n";
			return -1;
		};
	
	
	//																		TODO:   ------------ Sacuvati korisnika u fajl sistem ---------------


	

	return 0;
}



EVP_PKEY* X509Certificate::generatePkey()
{
	/*
			---Deprecated way---

	// Structure for storing the private key
	EVP_PKEY* pkey = EVP_PKEY_new();

	if (!pkey) return NULL;

	// The key itself (doesn't need to be freed explicitly)
	RSA* rsaKey = RSA_generate_key(2048, RSA_F4, NULL, NULL);


	if (!rsaKey) {
		EVP_PKEY_free(pkey);
		throw std::exception("CAN NOT CREATE RSA KEY! \n");
	}


	EVP_PKEY_assign(pkey, 6, rsaKey);
			
			---Deprecated way---
	*/


	
	//				---Jos jedan nacin---
	//	int rc;
	//	
	//	/*  Step 1 : Initancialize EVP_PKEY Object, allocate memory for p_pkey*/
	//	
	//	EVP_PKEY *p_pkey = EVP_PKEY_new();
	//	if (p_pkey == nullptr) {
	//		std::cout << "generate_rsa_key->EVP_PKEY_new() error" << std::endl;;
	//		return NULL;
	//	}
	//	
	//	/*  Step 2 : Create EVP_PKEY_CTX object,  allocate memory for ctx */
	//	
	//	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	//	if (ctx == nullptr) {
	//		std::cout << "generate_rsa_key->EVP_PKEY_CTX_new_id() error" << std::endl;;
	//		return NULL;
	//	}
	//	
	//	/*  Step 3 : Initializ ctx object */
	//	
	//	rc = EVP_PKEY_keygen_init(ctx);
	//	if (rc != 1) {
	//		std::cout << "generate_rsa_key->EVP_PKEY_keygen_init() error" << std::endl;;
	//		return NULL;
	//	}
	//	
	//	/*  Step 4 : sets the RSA key bits. If not specified 1024 bits is used.  */
	//	
	//	rc = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
	//	if (rc <= 0) {
	//		std::cout << "generate_rsa_key->EVP_PKEY_CTX_set_rsa_keygen_bits() error" << std::endl;;
	//		return NULL;
	//	}
	//	
	//	/*  Step 5 : Generate Key */
	//	
	//	rc = EVP_PKEY_keygen(ctx, &p_pkey);
	//	if (rc != 1) {
	//		std::cout << "generate_rsa_key->EVP_PKEY_keygen() error" << std::endl;;
	//		return NULL;
	//	}
	//	
	//	/*  Step 6 : free ctx allocated memory */
	//	
	//	EVP_PKEY_CTX_free(ctx);
	//	
	//	return p_pkey;
	//				---Jos jedan nacin---

	return EVP_RSA_gen(2048);
}


X509* X509Certificate::generateCertificate(User* newUser)
{
	X509_NAME* p_name = X509_NAME_new();

	// Creating a new certificate
	X509* userCertRequest = X509_new();
	if (!userCertRequest) return NULL;


	int rc = X509_set_version(userCertRequest, 1L);
	if (rc != 1) {
		std::cout << "generate_x509->X509_set_version() error" << std::endl;
	}
	ASN1_INTEGER_set(X509_get_serialNumber(userCertRequest), 1L);
	X509_gmtime_adj(X509_get_notBefore(userCertRequest), 0L);
	X509_gmtime_adj(X509_get_notAfter(userCertRequest), 15768000L);		// Half a year

	X509_set_pubkey(userCertRequest, newUser->pkey);



	// First, we open the CA certificate to read the name
	const char* pathToCACert = "CAcert/rootca.pem";
	X509* CAcert = X509Certificate::loadCertificate(pathToCACert);
	X509_NAME* issuerName = X509_get_issuer_name(CAcert);


	//X509_NAME* issuerName = this->readCertIssuerName(pathToCACert);

	

	// Then we open it to read the private key
	const char* pathToPrivateKey = "CAcert/kljuc.key";
	EVP_PKEY* CApkey = this->readCertPrivKey(pathToPrivateKey);
	


	//												???			-----		Dekriptovati kljuc			------		passphrase == password?		 ???


	// Adding respectively countryName, stateOrProvinceName, location, organizationName, organizationUnit, commonName, issuerName
	X509_NAME_add_entry_by_txt(p_name, "C",  MBSTRING_ASC, reinterpret_cast<const unsigned char*>((newUser->country).c_str()),			  -1, -1, 0);
	X509_NAME_add_entry_by_txt(p_name, "ST", MBSTRING_ASC, reinterpret_cast<const unsigned char*>((newUser->state).c_str()),			  -1, -1, 0);
	X509_NAME_add_entry_by_txt(p_name, "L",  MBSTRING_ASC, reinterpret_cast<const unsigned char*>((newUser->locality).c_str()),			  -1, -1, 0);
	X509_NAME_add_entry_by_txt(p_name, "O",  MBSTRING_ASC, reinterpret_cast<const unsigned char*>((newUser->organisationName).c_str()),   -1, -1, 0);
	X509_NAME_add_entry_by_txt(p_name, "OU", MBSTRING_ASC, reinterpret_cast<const unsigned char*>((newUser->organisationalUnit).c_str()), -1, -1, 0);
	X509_NAME_add_entry_by_txt(p_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>((newUser->commonName).c_str()),		  -1, -1, 0);
	X509_NAME_add_entry_by_txt(p_name, "IN", MBSTRING_ASC, (unsigned char*)issuerName, -1, -1, 0);


	X509_set_subject_name(userCertRequest, p_name);
	X509_set_issuer_name(userCertRequest, issuerName);									


	if (newUser->country == "BA" && newUser->state == "RS" && newUser->locality == "BL" && newUser->organisationName == "ETF") {
		// Signing a certificate using a CA key
		X509_sign(userCertRequest, CApkey, EVP_sha1());
	}
	else
	{
		EVP_PKEY_free(CApkey);
		X509_free(CAcert);
		
		std::cout << "Wrong data, can't issue a certificate to you. \n";
		return NULL;
	}


	EVP_PKEY_free(CApkey);
	X509_free(CAcert);
	return userCertRequest;
}

X509_NAME* X509Certificate::readCertIssuerName(const char* pathToCert)
{
	BIO* bio_x509 = NULL;
	bio_x509 = BIO_new_file(pathToCert, "r");

	X509* newCertificate = PEM_read_bio_X509(bio_x509, NULL, NULL, NULL);

	BIO_free(bio_x509);
	if (newCertificate == nullptr) {
		std::cout << "load_x509_certificate->PEM_read_bio_X509() Error" << std::endl;
		return NULL;
	}

	X509_NAME *issuerName = X509_get_issuer_name(newCertificate);


	X509_free(newCertificate);
	return  issuerName;
}

X509* X509Certificate::loadCertificate(const char* pathToCert)
{
	BIO* bio_x509 = NULL;
	bio_x509 = BIO_new_file(pathToCert, "r");

	X509* newCertificate = PEM_read_bio_X509(bio_x509, NULL, NULL, NULL);

	BIO_free(bio_x509);
	if (newCertificate == nullptr) {
		std::cout << "load_x509_certificate->PEM_read_bio_X509() Error" << std::endl;
		return NULL;
	}

	
	return  newCertificate;
}

EVP_PKEY* X509Certificate::readCertPrivKey(const char *pathToPrivateKey)
{
	EVP_PKEY* privKey = EVP_PKEY_new();

	BIO* bio_key = NULL;

	bio_key = BIO_new_file(pathToPrivateKey, "r");

	privKey = PEM_read_bio_PrivateKey(bio_key, &privKey, NULL, (void*)PASSPHRASE);					//				--- PROVJERITI MOGUCNOSTI DEKRIPCIJE KLJUCA ---

	if (privKey == nullptr) {
		std::cout << "My_X509_Certificate->load_key() Error" << std::endl;
	}


	BIO_free(bio_key);
	return privKey;
}








int login(void)
{
	//								----	KORISTITI KLASU USER	----
	string userCertificate;
	string userName;
	string password, passwordRepeat;

	std::cout << "Unesite putanju do vaseg sertifikata npr 'certs/Darijo.crt': ";
	std::cin >> userCertificate;

	// Verifikacija sertifikata

	std::cout << "Unesite vase korisnicko ime: ";
	std::cin >> userName;


	std::cout << "Unesite vasu lozinku: ";
	std::cin >> password;

	// Verifikacija lozinke pa return 1;


	return 0;
}



int logout(void)
{
	return 0;
}

