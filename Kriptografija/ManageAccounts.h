#pragma once

/*
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif                          // Da se ukinu neka upozorenja
*/


// For the CA private key
// Ne moze korisnik znati koja sifra je koristena za stvaranje CA tijela, trebalo bi da neki unos vrsi administrator koji zna sifru da ona ne stoji ovako
constexpr auto PASSPHRASE =		  "sigurnost";
constexpr auto pathToCACert =	  "./Data/CAcert/rootca.pem";
constexpr auto pathToPrivateKey = "./Data/CAcert/kljuc.key";
constexpr auto pathToCrlList =	  "./Data/crl.txt";
constexpr auto pathToSerial =	  "./Data/serial.txt";


#include "User.h"


#include <filesystem>
#include <iostream>
#include <stdio.h>
#include <fstream>
#include <string>


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
#include <openssl/asn1.h>


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

		// Verifies the certificate includes checking the crl list
		int verifyTheCertificate(EVP_PKEY*);

		// Revokes a certificate
		void revokeCertificate(EVP_PKEY*);

		// Recoveres certificate from the crl list, returns 1 if successfully recovered, static - does not need object to be called
		static int certRecovery();


		X509* myCertificate;

	private:
		EVP_PKEY* pkey;
};



// Sve ovo dolje bi moglo u drugi heder fajl...


// Friend to 'User' class
int registrate();

// Friend to 'User' class
int getCredentials(User*);

// Friend to 'X509Certificate'
int login();

// Gets the serial number to be assigned to the certificate
int readSerialNumber();

// Increments the value inside the serial number file
void incrementSerialNumber(int);

// Removes a line of text from a txt file, param. path and line to be removed
void eraseFileLine(string, string);

// Show options for logged in user, param. userName
void loggedIn(string);
