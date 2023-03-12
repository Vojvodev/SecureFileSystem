#include "User.h"

string User::getCommonName() const
{
    return this->commonName;
}

string User::setCommonName(string commonName)
{
    return this->commonName = commonName;
}

string User::getEmailAddress() const
{
    return this->emailAddress;
}

string User::setEmailAddress(string emailAddress)
{
    return this->emailAddress = emailAddress;
}
