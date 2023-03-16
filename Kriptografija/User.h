#pragma once




#include <string>
#include <iostream>
#include <exception>
#include <fstream>


#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>





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
		// Shallow copy
		void setPkey(EVP_PKEY*);	// Dereferencing EVP_PKEY* type is not allowed so I don't know how to copy the content from one pointer to another

		User();
		~User();


		int setAllCredentials();

		// Stores a User object in a file WITHOUT HIS PRIVATE KEY AND CERTIFICATE
		int writeUser();

		// Reads a User object from a binary file
		int readUser(string);

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
