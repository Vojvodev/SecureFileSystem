#pragma once




#include <string>
#include <iostream>

#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>



// For the CA private key
// Ne moze korisnik znati koja sifra je koristena za stvaranje CA tijela, trebalo bi da neki unos vrsi administrator koji zna sifru da ona ne stoji ovako
constexpr auto PASSPHRASE = "sigurnost";

using std::string;

class User {

	friend class X509Certificate;
	friend int registrate();

	public:
		string getCountry() const;
		void setCountry(string);

		string getState() const;
		void setState(string);

		string getLocality() const;
		void setLocality(string);

		string getOrganisationName() const;
		void setOrganisationName(string);

		string getOrganisationalUnit() const;
		void setOrganisationalUnit(string);

		string getEmailAddress() const;
		void setEmailAddress(string);

		string getCommonName() const;
		void setCommonName(string);

		string getPassword() const;
		void setPassword(string);

		EVP_PKEY* getPkey() const;
		void setPkey(EVP_PKEY*);	// Dereferencing EVP_PKEY* type is not allowed so I don't know how to copy the content from one pointer to another

		User();
		~User();


		int setAllCredentials();

		// Stores a User object in a file, param. fileName WITHOUT HIS PRIVATE KEY
		//int writeUser(char*);

		// Reads a User object from a binary file, param. filename
		// User* readUser(char*);

	private:
		string country, state, locality, organisationName, organisationalUnit, emailAddress;
		string commonName, password;		// login credentials

		X509* userCertificate;
		EVP_PKEY* pkey;			

		// Stores the private key in filesystem
		int writePrivateKey();

		// Stores the certificate in filesystem
		int writeCertificate();

};
