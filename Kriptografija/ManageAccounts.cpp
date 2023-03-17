

#include "ManageAccounts.h"


X509Certificate::X509Certificate() : myCertificate(nullptr), pkey(nullptr) {}

X509Certificate::~X509Certificate() {
	if (myCertificate != nullptr)
		X509_free(myCertificate);
	if (pkey != nullptr)
		EVP_PKEY_free(pkey);
}


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
	

		
		// Creates a directory to save all the information about one user
		std::filesystem::create_directory("./Korisnici/" + newUser.commonName);					// In project properties c++17 or higher

		// Storing user's information to a file
		if (!newUser.writeUser()) {
			std::cout << "CAN NOT STORE USER'S INFORMATION! \n";
			return -1;
		}


		// Storing user's private key to a file
		if (!newUser.writePrivateKey()) {
			std::cout << "CAN NOT STORE USER'S PRIVATE KEY \n";
			return -1;
		}
	
		
		// Storing user certificate to a file
		if (!newUser.writeCertificate()) {
			std::cout << "CAN NOT STORE USER'S CERTIFICATE \n";
			return -1;
		};
	
	


	

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

	long serialNumber = readSerialNumber();
	ASN1_INTEGER_set(X509_get_serialNumber(userCertRequest), serialNumber);
	X509_gmtime_adj(X509_get_notBefore(userCertRequest), 0L);
	X509_gmtime_adj(X509_get_notAfter(userCertRequest), 15768000L);		// Half a year
	incrementSerialNumber(serialNumber);

	X509_set_pubkey(userCertRequest, newUser->pkey);


	// Specifying key usage to digital signature
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
	X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature");
	X509_add_ext(userCertRequest, ext, -1);
	X509_EXTENSION_free(ext);



	// First, we open the CA certificate to read the name
	X509* CAcert = X509Certificate::loadCertificate((const char*)pathToCACert);
	X509_NAME* issuerName = X509_get_issuer_name(CAcert);


	//X509_NAME* issuerName = this->readCertIssuerName(pathToCACert);

	

	// Then we open it to read the private key
	EVP_PKEY* CApkey = this->readCertPrivKey((const char*)pathToPrivateKey);


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
		return NULL;
	}

	
	return  newCertificate;
}

EVP_PKEY* X509Certificate::readCertPrivKey(const char *pathToPrivateKey)
{


	EVP_PKEY* privKey = EVP_PKEY_new();

	BIO* bio_key = NULL;

	bio_key = BIO_new_file(pathToPrivateKey, "r");

	privKey = PEM_read_bio_PrivateKey(bio_key, &privKey, NULL, (void*)PASSPHRASE);		// Zna automatski na osnovu hedera u fajlu koji je algoritam koristen

	if (privKey == nullptr) {
		std::cout << "COULD NOT READ PRIVATE KEY" << std::endl;
	}


	BIO_free(bio_key);
	return privKey;
}


int login()
{
	int rc = 1, i = 3;
	
	string userCertificatePath;
	string userName;
	string password;

	EVP_PKEY* publicCAkey = nullptr;
	EVP_PKEY* privateCAkey = nullptr;

	User newUser;

	X509Certificate userCertificate;
	X509Certificate CAcertificate;



	std::cout << "Unesite sertifikat za provjeru(vase korisnicko ime): ";
	std::cin >> userName;


	userCertificatePath = "./Data/Korisnici/" + userName + "/" + userName + ".crt";

	userCertificate.myCertificate = userCertificate.loadCertificate(userCertificatePath.c_str());

	CAcertificate.myCertificate = CAcertificate.loadCertificate((const char*)pathToCACert);


	if (!userCertificate.myCertificate)
	{ std::cout << "Could not load your certificate.\n ---Try again later--- \n\n"; return 0; }


	// Extracting keys from the certificate 
	publicCAkey = X509_get_pubkey(CAcertificate.myCertificate);
	privateCAkey = CAcertificate.readCertPrivKey(pathToPrivateKey);



	// Verifying the certificate
	if (userCertificate.verifyTheCertificate(publicCAkey)) { std::cout << "\n---Certificate verified---\n\n"; }
	else
	{
		std::cout << "\n--Login unsuccessful.-- \nCould not verify your certificate. \n ---Try again later--- \n\n";
		return 0;
	}


	// Certificate is already verified
	do {
		
		std::cout << "Unesite vase korisnicko ime: ";
		std::cin >> userName;

		std::cout << "Unesite vasu lozinku: ";
		std::cin >> password;

		
		if (newUser.readUser(userName)) {
			if (newUser.getPassword() == password && newUser.getCommonName() == userName)
			{
				if (!publicCAkey) EVP_PKEY_free(publicCAkey);
				if (!privateCAkey) EVP_PKEY_free(privateCAkey);
				return rc;
			}
			else
			{ std::cout << "Wrong username or password\n ---Try again--- \n"; i--; continue; }
		}
		else { std::cout << "Wrong username or password\n ---Try again--- \n"; i--; continue; }

		} while (i < 3 && i > 0);


		if (i == 0)
		{	
			// Certificate gets revoked
			if (userCertificate.myCertificate)
			{
				userCertificate.revokeCertificate(privateCAkey);
			}
			else 
			{ std::cout << "Three unsuccessful login attempts. Try again later. \n"; }


			rc = 0;
		}



	if(!publicCAkey) EVP_PKEY_free(publicCAkey);
	if (!privateCAkey) EVP_PKEY_free(privateCAkey);
	return rc;
}

int readSerialNumber()
{
	int i = 0;
	FILE* myfile;
	
	fopen_s(&myfile, pathToSerial, "r");
	if (myfile)
	{

		fscanf_s(myfile, "%d", &i);


		fclose(myfile);
	}
	else std::cout << "CAN NOT OPEN SERIAL.TXT FOR READ \n";


	return i;
}

void incrementSerialNumber(int i)
{
	i++;
	FILE* myfile;

	fopen_s(&myfile, pathToSerial, "w");
	if (!myfile) std::cout << "CAN NOT OPEN SERIAL.TXT FOR READ \n";


	fprintf(myfile, "%d", i);
	fclose(myfile);
}


int X509Certificate::verifyTheCertificate(EVP_PKEY *publicCAkey)
{
	int rc = 1, rc1 = 0, rc2 = 0;

	X509_CRL *crl = nullptr;
	BIO *bio_out = NULL;

	bio_out = BIO_new_file(pathToCrlList, "r");

	if (bio_out)
	{
		X509_CRL* crl = PEM_read_bio_X509_CRL(bio_out, NULL, NULL, NULL);
		BIO_free(bio_out);

		X509_STORE* store = X509_STORE_new();
		if (store) X509_STORE_add_crl(store, crl);

		X509_STORE_CTX* ctx = X509_STORE_CTX_new();
		if (ctx)
		{
			X509_STORE_CTX_init(ctx, store, this->myCertificate, NULL);

			// Verify the certificate against the crl
			rc = X509_verify_cert(ctx);

			X509_STORE_CTX_free(ctx);
		}

		X509_STORE_free(store);
		X509_CRL_free(crl);
	}

	// Verify for CA key
	rc1 = X509_verify(this->myCertificate, publicCAkey);


	if (rc == 1 && rc1 == 1) { return 1; }
	else { return 0; }
}


void X509Certificate::revokeCertificate(EVP_PKEY* privateCAkey)
{

	X509_CRL* crl = X509_CRL_new();

	X509_NAME* issuerName = X509_get_issuer_name(this->myCertificate);
	X509_CRL_set_issuer_name(crl, issuerName);

	X509_REVOKED* revokedCert = X509_REVOKED_new();
	ASN1_INTEGER* serial = X509_get_serialNumber(this->myCertificate);
	X509_REVOKED_set_serialNumber(revokedCert, serial);

	X509_CRL_add0_revoked(crl, revokedCert);

	// Set the time of revocation
	ASN1_TIME* tm = ASN1_TIME_new();
	ASN1_TIME_set(tm, time(NULL));
	X509_REVOKED_set_revocationDate(revokedCert, tm);
	

	// Set revocation reason to PRIVILEGE_WITHDRAWN
	ASN1_ENUMERATED* reasonCode = ASN1_ENUMERATED_new();
	if (reasonCode)
	{
		ASN1_ENUMERATED_set(reasonCode, CRL_REASON_PRIVILEGE_WITHDRAWN);
		X509_EXTENSION* ext = X509_EXTENSION_create_by_NID(NULL, NID_crl_reason, 0, reasonCode);

		if (ext)
		{
			X509_REVOKED_add_ext(revokedCert, ext, -1);
			X509_EXTENSION_free(ext);
		}
		ASN1_ENUMERATED_free(reasonCode);
	}


	// Sign the CRL using CA's private key
	X509_CRL_set_version(crl, 1);
	X509_CRL_sign(crl, privateCAkey, EVP_sha256());

	// Write crl list to a file
	BIO* bio_out = NULL;
	bio_out = BIO_new_file(pathToCrlList, "a");
		
	PEM_write_bio_X509_CRL(bio_out, crl);


	BIO_free(bio_out);
	
	std::cout << "Three unsuccessful login attempts -> your certificate has been revoked. \n";
	std::cout << "You can recover your certificate later or register a new account. \n";
}



int X509Certificate::certRecovery()
{
	return 0;
}