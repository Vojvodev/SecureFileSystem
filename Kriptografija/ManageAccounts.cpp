

#include "ManageAccounts.h"


int registrate(void)
{

						// KORISTITI KLASU  USER ----------------------------------------------
	char* commonName;
	char* emailAddress;

	std::cout << "Unesite ime: ";
	std::cin >> commonName;

	std::cout << "Unesite email: ";
	std::cin >> emailAddress;



	// Creating a key pair
	EVP_PKEY* pkey = generatePkey();
	if(!pkey) throw std::exception("Unable to create EVP_PKEY structure. \n");


	// Creating new certificate
	X509* userCert = generateCertificate(pkey, commonName, emailAddress);
	if (!userCert) {
		EVP_PKEY_free(pkey);
		throw std::exception("CAN NOT CREATE USER CERTIFICATE! \n");
	}


	// Storing user's private key to a binary file
	if (!writePkey(pkey, commonName)) {

		EVP_PKEY_free(pkey);
		X509_free(userCert);

		throw std::exception("CAN NOT CREATE FILE TO WRITE OUT THE KEY!");
	}


	// Storing user certificate to a binary file
	if (!writeCertificate(userCert, commonName)) {

		EVP_PKEY_free(pkey);
		X509_free(userCert);

		throw std::exception("CAN NOT CREATE FILE TO WRITE OUT THE CERTIFICATE!");
	}
	



	EVP_PKEY_free(pkey);
	X509_free(userCert);
	
	return 0;
}

EVP_PKEY* generatePkey()
{
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

	return pkey;
}


X509* generateCertificate(EVP_PKEY *pkey, char *commonName, char *emailAddress)
{
	X509* userCert = X509_new();

	if (!userCert) return NULL;

	ASN1_INTEGER_set(X509_get_serialNumber(userCert), 1);
	X509_gmtime_adj(X509_get_notBefore(userCert), 0);
	X509_gmtime_adj(X509_get_notAfter(userCert), 15768000L);		// Half a year

	X509_set_pubkey(userCert, pkey);



	//							HOW to work with requests

	// not sure
	X509_NAME* name;
	name = X509_get_subject_name(userCert);


	// Adding respectively countryName, stateOrProvinceName, organizationName, commonName, emailAddress
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
		(unsigned char*)"BA", -1, -1, 0);

	X509_NAME_add_entry_by_txt(name, "S", MBSTRING_ASC,
		(unsigned char*)"RS", -1, -1, 0);				// NOT SURE IF "S" WORKS

	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
		(unsigned char*)"Elektrotehnicki fakultet", -1, -1, 0);

	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(unsigned char*)commonName, -1, -1, 0);

	X509_NAME_add_entry_by_txt(name, "E", MBSTRING_ASC,
		(unsigned char*)emailAddress, -1, -1, 0);		// NOT SURE IF "E" WORKS


	// Ovdje ide ime CAcert tijela
	//X509_set_issuer_name(userCert, name);


	// Ovdje ide moj kljuc iz CAcert
	//X509_sign(userCert, pkey, EVP_sha1());

	return userCert;
}


bool writePkey(EVP_PKEY* pkey, char *commonName)
{
	const char* extension1 = ".key";
	char* PrivKeyName = strcat(commonName, extension1);

	FILE* outputPrivKeyFile = fopen(PrivKeyName, "wb");


	if (outputPrivKeyFile) {
		PEM_write_PrivateKey(outputPrivKeyFile, pkey, EVP_des_ede3_cbc(), "sigurnost", 9, NULL, NULL);
	}
	else return false;



	fclose(outputPrivKeyFile);
	return true;
}


bool writeCertificate(X509* userCert, char* commonName)
{
	const char* extension2 = ".crt";
	char* certName = strcat(commonName, extension2);

	FILE* outputCertFile = fopen(certName, "wb");

	if (outputCertFile) {
		PEM_write_X509(outputCertFile, userCert);
	}
	else return false;


	return true;
}




int login(void)
{
	return 0;
}



int logout(void)
{
	return 0;
}
