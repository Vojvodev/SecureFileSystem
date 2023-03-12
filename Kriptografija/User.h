#pragma once

#include <string>

using std::string;

class User {
private:
	string commonName;
	string emailAddress;

public:
	string getCommonName() const;
	string setCommonName(string userName);

	string getEmailAddress() const;
	string setEmailAddress(string emailAddress);
};
