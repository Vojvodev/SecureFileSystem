

#include "ManageAccounts.h"
#include "FileHandling.h"



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
		std::filesystem::create_directory("./Data/Korisnici/" + newUser.commonName);					// In project properties c++17 or higher


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
	ASN1_INTEGER* ASNserial = ASN1_INTEGER_new();
	ASN1_INTEGER_set(ASNserial, serialNumber);

	X509_set_serialNumber(userCertRequest, ASNserial);
	X509_gmtime_adj(X509_get_notBefore(userCertRequest), 0L);
	X509_gmtime_adj(X509_get_notAfter(userCertRequest), 15768000L);		// Half a year

	//ASN1_INTEGER_free(ASNserial);			// Do not free this

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


	incrementSerialNumber(serialNumber);
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



	std::cout << "Write your certificate for verification(your user name): ";
	std::cin >> userName;


	userCertificatePath = "./Data/Korisnici/" + userName + "/" + userName + ".crt";

	userCertificate.myCertificate = userCertificate.loadCertificate(userCertificatePath.c_str());

	CAcertificate.myCertificate = CAcertificate.loadCertificate((const char*)pathToCACert);


	if (!userCertificate.myCertificate)
	{ 
		std::cout << "Could not load your certificate.\n ---Try again later--- \n\n";
		
		if (publicCAkey) EVP_PKEY_free(publicCAkey);
		if (privateCAkey) EVP_PKEY_free(privateCAkey);
		return 0; 
	}


	// Extracting keys from the certificate 
	publicCAkey = X509_get_pubkey(CAcertificate.myCertificate);
	privateCAkey = CAcertificate.readCertPrivKey(pathToPrivateKey);



	// Verifying the certificate
	if (userCertificate.verifyTheCertificate(publicCAkey)) { std::cout << "\n---Certificate verified---\n\n"; }
	else
	{
		std::cout << "\n ---Login unsuccessful.--- \nCould not verify your certificate. \n ---Try again later--- \n\n";

		
		if (publicCAkey) EVP_PKEY_free(publicCAkey);
		if (privateCAkey) EVP_PKEY_free(privateCAkey);
		return 0;
	}


	// Certificate is already verified
	do {
		
		std::cout << "Write your name: ";
		std::cin >> userName;

		std::cout << "Write your password: ";
		std::cin >> password;

		
		if (newUser.readUser(userName)) {
			if (newUser.getPassword() == password && newUser.getCommonName() == userName)
			{
				if (publicCAkey) EVP_PKEY_free(publicCAkey);
				if (privateCAkey) EVP_PKEY_free(privateCAkey);


				// Call to function loggedIn to continue the program in a logged in manner
				std::cout << "\n\n\n ---login successful---      \n\n";
				loggedIn(userName);

				std::cout << "\n ---logged out---      \n\n";


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


			rc = 0;
		}




	if(publicCAkey) EVP_PKEY_free(publicCAkey);
	if(privateCAkey) EVP_PKEY_free(privateCAkey);
	return rc;
}

int readSerialNumber()
{
	int i = 0;
	
	std::ifstream inputFile(pathToSerial, std::ios::in);
	if (inputFile.is_open())
	{
		inputFile >> i;

		inputFile.close();
	}
	else std::cout << "CAN NOT OPEN SERIAL.TXT FOR READ";
	

	return i;
}

void incrementSerialNumber(int i)
{
	i++;

	std::ofstream outputFile(pathToSerial, std::ios::out);
	if (outputFile.is_open())
	{
		outputFile << i;

		outputFile.close();
	}else std::cout << "CAN NOT OPEN SERIAL.TXT FOR WRITE \n";

}


int X509Certificate::verifyTheCertificate(EVP_PKEY *publicCAkey)				
{
	int rc = 0, rc1 = 0;
	int crlSerialNumber, userSerialNumber;
	string line;

	ASN1_INTEGER* serial = X509_get_serialNumber(this->myCertificate);
	userSerialNumber = ASN1_INTEGER_get(serial);



	std::ifstream inputFile(pathToCrlList, std::ios::in);
	if (inputFile.is_open())
	{
		while (std::getline(inputFile, line))
		{
			crlSerialNumber = std::stoi(line);
			if (userSerialNumber == crlSerialNumber)
			{
				rc = 1; if (inputFile) inputFile.close(); break;
			}
		}
		

		if(inputFile) inputFile.close();
	}
	else std::cout << "CAN NOT OPEN CRL FOR READ \n";

	//ASN1_INTEGER_free(serial);		// NO
	

	//		X509_CRL *crl = nullptr;
	//		BIO *bio_out = NULL;
	//		
	//		bio_out = BIO_new_file(pathToCrlList, "r");
	//		
	//		if (bio_out)
	//		{
	//			X509_CRL* crl = X509_CRL_new();
	//			crl = PEM_read_bio_X509_CRL(bio_out, &crl, NULL, NULL);
	//			if (!crl) {
	//				
	//				unsigned long err = ERR_get_error();
	//				char err_buff[256];
	//			
	//				ERR_error_string_n(err, err_buff, sizeof(err_buff));
	//			
	//				std::cout << err_buff;
	//		
	//				std::cout << "ERROR WHILE READING CRL LIST! \n";
	//			}
	//			BIO_free(bio_out);
	//		
	//		
	//			ASN1_INTEGER *serial = X509_get_serialNumber(this->myCertificate);
	//			X509_REVOKED *revokedCertificate = X509_REVOKED_new();
	//		
	//			// Search if the serial number of the certificate exists in the CRL list, rc = 0 if revokedCertificate is NOT FOUND
	//			rc = X509_CRL_get0_by_serial(crl, &revokedCertificate, serial);
	//
	//	
	//
	//	//X509_STORE* store = X509_STORE_new();
		//if (store) X509_STORE_add_crl(store, crl);
		//X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
		//
		//X509_STORE_CTX* ctx = X509_STORE_CTX_new();
		//if (ctx)
		//{
		//	X509_STORE_CTX_init(ctx, store, this->myCertificate, NULL);
		//
		//	// Verify the certificate against the crl
		//	rc = X509_verify_cert(ctx);
		//
		//	X509_STORE_CTX_free(ctx);
		//}
	//
	//	//X509_STORE_free(store);
	//	X509_CRL_free(crl);
	//}





	// Verify for CA key
	rc1 = X509_verify(this->myCertificate, publicCAkey);		// 1 - if good


	if (rc == 0 && rc1 == 1) { return 1; }						// Good
	else { return 0; }
}


void X509Certificate::revokeCertificate(EVP_PKEY* privateCAkey)
{

	//			X509_CRL* crl = X509_CRL_new();
	//			
	//			X509_NAME* issuerName = X509_get_issuer_name(this->myCertificate);
	//			X509_CRL_set_issuer_name(crl, issuerName);
	//			
	//			
	//			
	//			
	//			X509_REVOKED* revokedCert = X509_REVOKED_new();
	//			ASN1_INTEGER* serial = ASN1_INTEGER_new();
	//			serial = X509_get_serialNumber(this->myCertificate);
	//			X509_REVOKED_set_serialNumber(revokedCert, serial);
	//			
	//			
	//			X509_CRL_add0_revoked(crl, revokedCert);
	//			
	//			// Set the time of revocation
	//			ASN1_TIME* tm = ASN1_TIME_new();
	//			ASN1_TIME_set(tm, time(NULL));
	//			X509_REVOKED_set_revocationDate(revokedCert, tm);
	//			
	//			
	//			// Set revocation reason to PRIVILEGE_WITHDRAWN
	//			ASN1_ENUMERATED* reasonCode = ASN1_ENUMERATED_new();
	//			if (reasonCode)
	//			{
	//				ASN1_ENUMERATED_set(reasonCode, CRL_REASON_PRIVILEGE_WITHDRAWN);
	//				X509_EXTENSION* ext = X509_EXTENSION_create_by_NID(NULL, NID_crl_reason, 0, reasonCode);
	//			
	//				if (ext)
	//				{
	//					X509_REVOKED_add_ext(revokedCert, ext, -1);
	//					X509_EXTENSION_free(ext);
	//				}
	//				ASN1_ENUMERATED_free(reasonCode);
	//			}
	//			
	//			
	//			// Sign the CRL using CA's private key
	//			X509_CRL_set_version(crl, 1L);
	//			X509_CRL_sign(crl, privateCAkey, EVP_sha256());
	//			
	//			// Write crl list to a file
	//			BIO* bio_out = NULL;
	//			bio_out = BIO_new_file(pathToCrlList, "a");
	//				
	//			PEM_write_bio_X509_CRL(bio_out, crl);
	//			
	//			
	//			
	//			X509_CRL_free(crl);
	//			//X509_NAME_free(issuerName);						// These should not be freed for some reason
	//			//X509_REVOKED_free(revokedCert);
	//			//ASN1_INTEGER_free(serial);
	//			//ASN1_TIME_free(tm);
	//			BIO_free(bio_out);
	
	ASN1_INTEGER* serial = X509_get_serialNumber(this->myCertificate);
	

	std::ofstream outputFile(pathToCrlList, std::ios::out | std::ios::app);
	if (outputFile.is_open())
	{
		outputFile << std::to_string(ASN1_INTEGER_get(serial)) << std::endl;

		outputFile.close();
	}
	else std::cout << "CAN NOT OPEN CRL FOR WRITE \n";


	//ASN1_INTEGER_free(serial);			// Should not free ASN1_INTEGER

	std::cout << "Three unsuccessful login attempts -> your certificate has been revoked. \n";
	std::cout << "You can recover your certificate later or register a new account. \n";
}



int X509Certificate::certRecovery()
{
	string line, userName, password, userCertificatePath;
	X509Certificate userCertificate;
	User newUser;

	std::cout << "-Write your credentials correctly in order to recover your account- \n";

	std::cout << "Write your name: ";
	std::cin >> userName;

	std::cout << "Write your password: ";
	std::cin >> password;

	// Checking if the user name exists
	userCertificatePath = "./Data/Korisnici/" + userName + "/" + userName + ".crt";
	userCertificate.myCertificate = userCertificate.loadCertificate(userCertificatePath.c_str());

	if (!userCertificate.myCertificate)
	{
		std::cout << "Could not load your certificate.\n ---Try again later--- \n\n"; return 0;
	}

	// Checking the password
	if (newUser.readUser(userName)) {
		if (newUser.getPassword() == password && newUser.getCommonName() == userName)
		{
			// Everything correct


			std::ifstream inputFile(pathToCrlList, std::ios::in);
			if (inputFile.is_open())
			{
				ASN1_INTEGER* serial = X509_get_serialNumber(userCertificate.myCertificate);
				int userSerialNumber = ASN1_INTEGER_get(serial);
				string serialNumber = std::to_string(userSerialNumber);

				inputFile.close();

				// Erases the serial number of the certificate from CRL list
				eraseFileLine(pathToCrlList, serialNumber);
				
			}
			else std::cout << "CAN NOT OPEN CRL FOR READ \n";



		}
		else
		{
			std::cout << "Wrong username or password\n ---Try again--- \n"; return 0;;
		}
	}





	return 1;
}


void eraseFileLine(string path, string eraseLine) {
	
	string line;

	std::ifstream fin(path);
	std::ofstream temp("./Data/temp.txt");

	
	while (getline(fin, line))
	{
		if (strcmp(line.c_str(), eraseLine.c_str()))
			temp << line << std::endl;
	}
	
	temp.close();
	fin.close();

	if (std::remove("./Data/crl.txt") != 0)
		perror("Error deleting file");
	std::rename("./Data/temp.txt", "./Data/crl.txt");
}


void loggedIn(string userName)
{
	string option;


	std::cout << "\n          - Welcome: "<< userName <<" -         \n";
	std::cout << "What do you want to do ? \n\n";

	std::cout << "To download your files, enter		-download \n";
	std::cout << "To upload your files, enter		-upload \n";
	std::cout << "To log out, enter			-logout \n\n\n";



	do {
		std::cout << "Enter one of the options above:  ";

		std::cout << "\n\n";
		std::cin >> option;


		if (option == "-upload") {
			if(upload()) std::cout << "\n ---Upload successful---      \n";
			else std::cout << "\n ---Could not upload files---        \n";
		}

		// TODO: implement -download

	} while (option != "-logout");


}
