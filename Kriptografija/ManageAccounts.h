#pragma once

/*
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif                          // Da se ukinu neka upozorenja
*/


// For the CA private key
// Ne moze korisnik znati koja sifra je koristena za stvaranje CA tijela, trebalo bi da neki unos vrsi administrator koji zna sifru da ona ne stoji ovako
constexpr auto PASSPHRASE = "sigurnost";

constexpr auto pathToCACert = "./CAcert/rootca.pem";
constexpr auto pathToPrivateKey = "./CAcert/kljuc.key";


#include "User.h"

#include <filesystem>
#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <fstream>
#include <string>
#include <exception>
#include <cstdint>
#include <cassert>


#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>



using std::string;


class X509Certificate {

	friend class User;
	friend int login();

	public:

		X509Certificate();
		~X509Certificate();

		EVP_PKEY* generatePkey();

		// Returns a certficate, param. key 
		X509* generateCertificate(User*);
		
		// Returns the issuer name from a certificate, param. filename
		X509_NAME* readCertIssuerName(const char*);

		// Returns a certificate from a file, param. filename
		X509* loadCertificate(const char*);

		// Returns the private key of a certificate, param. filename
		EVP_PKEY* readCertPrivKey(const char*);

		// Verifies the X509 Certificate, returns 1 if the certificate is valid
		int verifyCertificate();

		// Recoveres certificate from the crl list, returns 1 if successfully recovered, static - does not need object to be called
		static int certRecovery();

	private:
		X509* myCertificate;
		EVP_PKEY* pkey;
};



// Sve ovo dolje bi moglo u drugi heder fajl...


// Friend to 'User' class
int registrate();

// Friend to 'User' class
int getCredentials(User*);

// Friend to 'X509Certificate'
int login();


int logout();
