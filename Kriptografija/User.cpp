#include "User.h"

char* User::getCommonName() const
{
    return this->commonName;
}

char* User::setCommonName(char* commonName)
{
    return this->commonName = commonName;
}

char* User::getEmailAddress() const
{
    return this->emailAddress;
}

char* User::setEmailAddress(char* emailAddress)
{
    return this->emailAddress = emailAddress;
}
