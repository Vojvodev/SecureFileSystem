#include "ManageAccounts.h"



int main()
{
    
    string option = "-exit";


    std::cout << "\n          - Welcome -         \n";
    std::cout << "What do you want to do ? \n\n";

    std::cout << "To registrate, enter  -registrate \n";
    std::cout << "To log in, enter      -login \n";
    std::cout << "To log out, enter     -logout \n";
    std::cout << "To exit, enter        -exit \n\n";

    std::cout << "Enter one of the options above:  ";

    do {
        std::cout << "\n\n";
        std::cin >> option;

        if (option == "-registrate") {
            if (registrate()) std::cout << "\n-registration is successful-\n";
            else std::cout << "\n-registration error-\n";
        }

        if (option == "-login") {
            if (login()) {
                std::cout << "\n- is successful-\n";
                
                //TODO
            }
            else std::cout << "\n-login error-\n";
        }

        if (option == "-logout") {
            if (!logout()) std::cout << "\n-logout error-\n";
            
            //TODO
        }


    } while (option != "-exit");
}
