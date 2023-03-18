

#include "ManageAccounts.h"




int main()
{
    
    string option = "-exit";


    std::cout << "\n          - Welcome -         \n";
    std::cout << "What do you want to do ? \n\n\n";

    std::cout << "To registrate, enter                  -registrate \n";
    std::cout << "To log in, enter                      -login \n";
    std::cout << "To recover your certificate, enter    -recover \n";
    std::cout << "To exit, enter                        -exit \n\n\n";

   
    do {
        std::cout << "Enter one of the options above:  ";

        std::cout << "\n\n";
        std::cin >> option;


        if (option == "-registrate") {
            if (!registrate()) std::cout << "\n ---Registration successful---      \n";
            else std::cout << "\n ---Registration error---        \n";
            
        }


        if (option == "-login") {
            login();        // Main part of the program
        }


        // Could implement some email verification code sending...
        if (option == "-recover") {
            if (! (X509Certificate::certRecovery()) ) {
                std::cout << "Could not recover your certificate. \n";
            }
            else {
                std::cout << "\n ---Certificate recovery successful---       \n";
            }
        }

        
    } while (option != "-exit");


    return 0;
}
