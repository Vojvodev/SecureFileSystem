#pragma once

#include <string>

using std::string;

class User {
private:
	string userName;

public:
	string getUserName() const;
	string setUserName(string userName);
};
