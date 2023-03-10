#include "User.h"

string User::getUserName() const
{
    return this->userName;
}

string User::setUserName(string userName)
{
    return this->userName = userName;
}
