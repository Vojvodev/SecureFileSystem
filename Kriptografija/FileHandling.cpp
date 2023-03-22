

#include "ManageAccounts.h"
#include "FileHandling.h"



// To ensure that file fragments are not changed (file integrity), we could calculate hash of each fragment - digital signature
// To make decryption easier, istead of a random key, we could use user's public key for encryption and his private key for decryption
// To save the symmetric key, we can use digital envelope mechanism (encrypting the symmetric key with asymmetric one)


int upload(string userName)
{
	string pathForUpload, fileName, extension;
	long long fileSize;
	long long currentVectorPosition = 0;
	int control, numberOfComponents;


	std::cout << "\nWrite the path to your file: \n";
	std::cin >> pathForUpload;

	do {
		std::cout << "\nHow do you want to save it [file name]: \n";
		std::cin >> fileName;

		control = 0;

		std::ifstream checkFilesForName("./Data/Korisnici/" + userName + "/" + "Files/" + fileName, std::ios::in);
		if (checkFilesForName.is_open()) {
			std::cout << "Choose a different name. \n\n";  control = 1; checkFilesForName.close();
		}

		std::ifstream checkFilesForNames("./Data/Korisnici/" + userName + "/" + "Files/" + fileName + "0.dat", std::ios::in);
		if (checkFilesForNames.is_open()) {
			std::cout << "Choose a different name. \n\n";  control = 1; checkFilesForNames.close();
		}

	} while (control);

	//	 std::cout << "\nWrite your file's extension: \n";
	//	 std::cin >> extension;



	// Reading the file data in binary mode and storing it's contents in a vector
	std::vector<BYTE> fileData = readFile(pathForUpload.c_str());
	

	// Read file size
	std::ifstream inputFile(pathForUpload, std::ios::in, std::ios::binary);
	if (inputFile.is_open())
	{
		inputFile.seekg(0, std::ios::end);
		fileSize = inputFile.tellg();

		// Return the pointer to the beginning
		inputFile.seekg(0, std::ios::beg);


		inputFile.close();
	}
	else {
		std::cout << "Could not find your file, try again \n"; return 0;
	}



	// Getting a random number for the number of components after dissecting the file, the number is between 4 and 10
	srand(time(NULL));
	numberOfComponents = rand() % 7 + 4;	


	// Create random key and iv values for this user file
	std::vector<BYTE> key(32); // 256-bit key
	std::vector<BYTE> iv(EVP_MAX_IV_LENGTH); // random IV (Salt value)

	// Key and IV values are random
	RAND_bytes(key.data(), key.size());
	RAND_bytes(iv.data(), iv.size());



	for (int i = 0; i < numberOfComponents; i++)
	{
		string smallFilePath = "./Data/Korisnici/" + userName + "/" + "Files/" + fileName + std::to_string(i) + ".dat";
	
		// Number of bytes in each small file
		long long numberOfBytes = fileSize / numberOfComponents;


		// Takes more bytes 
		if (i == 0)
		{
			numberOfBytes += fileSize - numberOfComponents * numberOfBytes;
		}
		


		std::vector<BYTE> smallVector(fileData.begin() + currentVectorPosition, fileData.begin() + currentVectorPosition + numberOfBytes - 1);

		
		// Encrypting file contents
		std::vector<BYTE> smallVectorEncrypted = encrypt(smallVector, key, iv);


		// New file is created with the contents of smallVectorEncrypted
		std::ofstream smallFile(smallFilePath, std::ios::out, std::ios::binary);
		if (smallFile.is_open())
		{

			smallFile.write( reinterpret_cast<const char*>(&smallVectorEncrypted[0]), smallVectorEncrypted.size() * sizeof(BYTE));

			smallFile.close();
		}
		else std::cout << "Error creating small file. \n";




		currentVectorPosition += numberOfBytes;

	}


	return 1;	// Good
}


std::vector<BYTE> readFile(const char *inputFile)
{
	std::streampos fileSize;
	std::ifstream fileName(inputFile, std::ios::binary);

	if (fileName.is_open())
	{
		// Get the size
		fileName.seekg(0, std::ios::end);
		fileSize = fileName.tellg();

		// Return the pointer to the beginning
		fileName.seekg(0, std::ios::beg);

		std::vector<BYTE> fileData(fileSize);

		fileName.read((char*)&fileData[0], fileSize);



		fileName.close();
		return fileData;
	}
}


std::vector<BYTE> encrypt(std::vector<BYTE> smallVector, std::vector<BYTE> key, std::vector<BYTE> iv)
{

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

	std::vector<BYTE> ciphertext(smallVector.size() + EVP_MAX_BLOCK_LENGTH);

	// Encrypt the plaintext
	int len;
	EVP_EncryptUpdate(ctx, ciphertext.data(), &len, smallVector.data(), smallVector.size());
	int ciphertext_len = len;

	// Finalize the encryption.
	EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len);
	ciphertext_len += len;

	
	EVP_CIPHER_CTX_free(ctx);


	return ciphertext;
}


void listFiles(string userName)
{
	std::filesystem::path pathToDir = "./Data/Korisnici/" + userName + "/Files/";
	string noRepeat = "xxxxxxxxxxxxxxxxx";


	for (const auto& entry : std::filesystem::directory_iterator(pathToDir))
	{
		if (entry.is_regular_file())
		{
			 string path = entry.path().string();
			 string filename = path.substr(path.rfind("/") + 1);

			 filename = filename.substr(0, filename.rfind("."));	// Removes extension
			 filename.pop_back();									// Removes last character
			 
			 if(filename != noRepeat)
			 {
				std::cout << filename << std::endl;
				
				noRepeat = filename;
			 }

		}
	}

}

