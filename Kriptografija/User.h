#pragma once




class User {
private:
	char* commonName;
	char* emailAddress;
	//char* password;

public:
	char* getCommonName() const;
	char* setCommonName(char* userName);

	char* getEmailAddress() const;
	char* setEmailAddress(char* emailAddress);
};
