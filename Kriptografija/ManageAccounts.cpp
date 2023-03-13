

#include "ManageAccounts.h"


int registrate(void)
{

						// KORISTITI KLASU  USER ----------------------------------------------
	string inputName;
	string inputEmail;

	std::cout << "Unesite ime: ";
	std::cin >> inputName;

	std::cout << "Unesite email: ";
	std::cin >> inputEmail;

	char* commonName = _strdup(inputName.c_str());
	char* emailAddress = _strdup(inputEmail.c_str());


	// Creating a key pair
	EVP_PKEY* pkey = generatePkey();
	if(!pkey) throw std::exception("Unable to create EVP_PKEY structure. \n");


	// Creating new certificate
	X509* userCertRequest = generateCertificate(pkey, commonName, emailAddress);
	if (!userCertRequest) {
		EVP_PKEY_free(pkey);
		throw std::exception("CAN NOT CREATE USER CERTIFICATE! \n");
	}
	
	std::cout << "Napravio sertifikat! \n\n";

	// Storing user's private key to a binary file
	if (!writePkey(pkey, commonName)) {

		EVP_PKEY_free(pkey);
		X509_free(userCertRequest);

		throw std::exception("CAN NOT CREATE FILE TO WRITE OUT THE KEY!");
	}
	
	
	// Storing user certificate to a binary file
	if (!writeCertificate(userCertRequest, commonName)) {

		EVP_PKEY_free(pkey);
		X509_free(userCertRequest);

		throw std::exception("CAN NOT CREATE FILE TO WRITE OUT THE CERTIFICATE!");
	}



	EVP_PKEY_free(pkey);
	X509_free(userCertRequest);
	
	free(commonName);
	free(emailAddress);
	return 0;
}


EVP_PKEY* generatePkey()
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

	*/


	return EVP_RSA_gen(2048);
}


X509* generateCertificate(EVP_PKEY *pkey, char *commonName, char *emailAddress)
{
	X509* userCertRequest = X509_new();
	if (!userCertRequest) return NULL;


	ASN1_INTEGER_set(X509_get_serialNumber(userCertRequest), 1);
	X509_gmtime_adj(X509_get_notBefore(userCertRequest), 0);
	X509_gmtime_adj(X509_get_notAfter(userCertRequest), 15768000L);		// Half a year

	X509_set_pubkey(userCertRequest, pkey);

	X509* userCertificate = signRequest(&userCertRequest, commonName, emailAddress);


	return userCertificate;
}

X509* signRequest(X509 **userCertRequest, char* commonName, char* emailAddress)
{
	// First, we open the CA certificate to read the name
	const char* pathToCACert = "CAcert/rootca.pem";
	X509_NAME* issuerName = X509_NAME_new();

	
	FILE* CAfile;
	fopen_s(&CAfile, pathToCACert, "r");
	if (CAfile) {

		X509* CAcertificate = PEM_read_X509(CAfile, NULL, NULL, NULL);

		std::cout << "1\n";
		if (CAcertificate) {

			issuerName = X509_get_issuer_name(CAcertificate);

		}
		else {
			std::cout << "Could not parse certificate \n";
		}

		X509_free(CAcertificate);
	}
	else {
		std::cout << "COULD NOT OPEN CERT FILE! \n";
		return NULL;
	}

	fclose(CAfile);


	// Then we open it to read the private key
	const char* pathToPrivateKey = "CAcert/kljuc.key";
	EVP_PKEY* pkey = EVP_PKEY_new();


	FILE* CAfile2;
	fopen_s(&CAfile2, pathToPrivateKey, "r");
	if (CAfile2) {
		PEM_read_PrivateKey(CAfile2, &pkey, NULL, (void*)PASSPHRASE);
		if (!pkey) {
			std::cout << "CAN NOT LOAD KEY! \n";
			return NULL;
		}
	}
	else {
		std::cout << "COULD NOT OPEN KEY FILE! \n";
		return NULL;
	}


	fclose(CAfile2);

	//						-----		Dekriptovati kljuc			------


	// Adding respectively countryName, stateOrProvinceName, organizationName, commonName, emailAddress
	X509_NAME_add_entry_by_txt(issuerName, "C", MBSTRING_ASC,
		(unsigned char*)"BA", -1, -1, 0);

	//X509_NAME_add_entry_by_txt(issuerName, "S", MBSTRING_ASC,
		//(unsigned char*)"RS", -1, -1, 0);				// NOT SURE IF "S" WORKS

	X509_NAME_add_entry_by_txt(issuerName, "O", MBSTRING_ASC,
		(unsigned char*)"Elektrotehnicki fakultet", -1, -1, 0);

	X509_NAME_add_entry_by_txt(issuerName, "CN", MBSTRING_ASC,
		(unsigned char*)commonName, -1, -1, 0);

	//X509_NAME_add_entry_by_txt(issuerName, "E", MBSTRING_ASC,
		//(unsigned char*)emailAddress, -1, -1, 0);		// NOT SURE IF "E" WORKS



	X509_set_issuer_name(*userCertRequest, issuerName);
	X509_sign(*userCertRequest, pkey, EVP_sha1());


	EVP_PKEY_free(pkey);
	return *userCertRequest;
}





bool writePkey(EVP_PKEY* pkey, char *privKeyName)
{
	const char* extension1 = ".key";
	strcat_s(privKeyName, 16, extension1);

	//const unsigned char* passphrase = reinterpret_cast < const unsigned char*>("sigurnost"); je alternativa
	const unsigned char* passphrase;
	const unsigned char p[] = "sigurnost";
	passphrase = p;


	FILE* outputPrivKeyFile;
	fopen_s(&outputPrivKeyFile, privKeyName, "wb");


	if (outputPrivKeyFile) {
		PEM_write_PrivateKey(outputPrivKeyFile, pkey, EVP_des_ede3_cbc(), passphrase, 9, NULL, NULL);
	}
	else return false;



	fclose(outputPrivKeyFile);
	return true;
}


bool writeCertificate(X509* userCertRequest, char* certName)
{
	const char* extension2 = ".crt";
	strcat_s(certName, 16, extension2);

	FILE* outputCertFile;
	fopen_s(&outputCertFile, certName, "wb");

	if (outputCertFile) {
		PEM_write_X509(outputCertFile, userCertRequest);
	}
	else return false;


	fclose(outputCertFile);
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

