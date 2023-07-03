#include<iostream>
#include<fstream>
#include<sstream>
#include<iomanip>
#include<unistd.h>
#include<cstdlib>
#include<ctime>                     //potrebbe essere inutile
#include<limits.h>                  //potrebbe essere inutile
#include<vector>
#include<string.h>
#include<openssl/rand.h>
#include<openssl/evp.h>
#include<openssl/pem.h>
#include"lib/gcm.hpp"
#include"lib/utils.hpp"
#include"lib/hash.hpp"

#define MIN_LENGTH 8                                             //minimum length for password
#define MAX_LENGTH 20                                            //maximum length used for username
#define SPECIAL_LENGTH 8                                         //length of special characters string

using namespace std;

/*
    Per compilare:
    g++ DBHandler.cpp -o DB.exe -lssl -lcrypto
*/

void saveInfo(  const char* filename, 
                const unsigned char* data, size_t dataSize,
                const unsigned char* tag, size_t tagSize, 
                int bankID);
void removeUser(ifstream &fr, ofstream &fw, vector<string> user);
bool checkUsername(string username);
bool checkPassword(string pwd);
int init_bankID(ifstream &fr);
void gen_salt(unsigned char* salt);

int main()
{
    /* Utility Variables */
    unsigned char* tag_buf = (unsigned char*)malloc(16);
    unsigned char* salt = (unsigned char*) malloc(16);
    unsigned char* key = (unsigned char*) malloc(16);
    unsigned char* iv = (unsigned char*) malloc(12);
    unsigned char* cphr_buf;
    unsigned char init_tl[] = "00000000";                       //initial value for the transaction list
    vector<string> user;                                        //temporary variable used for unicity check
    vector<string> par;                                         //used for cli parameters
    string command;
    string s_key;
    string hash;
    string s;
    ifstream fr;                                                //to read the DB
    ofstream fw;                                                //to write the DB
    int msg_len = sizeof(init_tl);
    int bankId;
    int err;

    /* Allocating variable */
    cphr_buf = (unsigned char*)malloc(msg_len);

    /*  (Generation of the Key for the transaction list's encryption)
        fw.open("Server/DBKey.txt", ios::app);

        RAND_poll();
        if(RAND_bytes(key, 16) != 1){
            cout << "Error in iv generation";
            return 1;
        }

        fw << ucharToHex(key, 16) << endl;
    */

    /*  Generation of p and g
        system("openssl dhparam -check -out params.pem 2048");
    */

    /* Reading the file to initialize bankId */
    fr.open("Server/Database.txt");

    bankId = init_bankID(fr);

    fr.close();

    fr.open("Server/DBKey.txt");

    s_key = initKey(fr);

    if(s_key == "")
    {
        cout << "Error in reading DBKey\n";
        return 1;
    }

    key = hexToChar(s_key);

    fr.close();

    do{
        cout << "\nHi! This is the application to manage the Database.\nHere's the list of the commands:\n\nAdd user: \tadd [username] [password]\nRemove user: \trmv [username]\nShow DB: \tshow\n\nType \"exit\" to close the app.\n\n> ";

        getline(cin, command);

        par = split(command, ' ');

        if(par[0] == "add" && par.size() == 3)
        {
            /* Add */
            if(checkUsername(par[1]))
            {
                /* Opens Database file, if it does not exists it will be created */
                fr.open("Server/Database.txt", ios::app);
                    
                user = findInFile(fr, par[1]);

                fr.close();

                /* Checking if the username is unique */
                if(user.empty())
                {
                    /* Checking password validity */
                    if(checkPassword(par[2]))
                    {
                        /* Writing in the Database the new user */
                        fw.open("Server/Database.txt", ios::app);

                        if(!fw.is_open())
                        {
                            /* Putting the response into sendbuf */
                            cout << "There was an error in opening the file\n";
                        }
                        else
                        {
                            /* Computing hash in cli by using SHA-256 */

                            if(RAND_bytes(salt, 16) != 1)
                            {
                                // Handle error in salt generation
                                throw runtime_error("Error generating salt.");
                            }

                            hash = SHA256WithSalt(par[2], salt, 16);

                            /* Removing \n from the char array */
                            s = toString(hash);

                            RAND_poll();

                            /* Generating a random IV for the encryption */
                            if(RAND_bytes(iv, 12) != 1)
                            {
                                cout << "Error in IV generation";
                                return 1;
                            }

                            /* Encrypting the initial setting for the transaction list */
                            err = gcm_encrypt(init_tl, msg_len, iv, 12, key, iv, 12, cphr_buf, tag_buf);

                            if(err == -1)
                            {
                                cout << "Error in encrypting";
                                return 1;
                            }

                            fw << par[1]+":"+ucharToHex(salt, 16)+"$"+hash+":"+toString(bankId)+":0:"+ucharToHex(cphr_buf, err)+"\n";

                            fw.close();

                            /* Saving bankID, used IV and relative tag in IV's file */
                            fw.open("Server/T_IV.txt", ios::app);

                            fw << toString(bankId)+":"+ucharToHex(iv, 12)+":"+ucharToHex(tag_buf, 16)+"\n";

                            fw.close();

                            bankId++;

                            /* Creating User's folder to store the private key */
                            system(("mkdir Users/"+par[1]).c_str());

                            /* Generating Private Key */
                            system(("openssl genrsa -out Users/"+par[1]+"/secret.pem 8192").c_str());

                            /* Generating Public Key */
                            system(("openssl rsa -pubout -in Users/"+par[1]+"/secret.pem -out PublicKeys/"+par[1]+".pem").c_str());

                            cout << "\nUser was added successfully\n";
                        }
                    }
                    else{
                        cout << "\nThe password is too weak\n";
                    }
                }
                else{
                    cout << "\nUsername already exists\n";
                }     
            }
            else{
                cout << "\nUsername is not valid\n";
            }
        }       /* Remove */
        else if(par[0] == "rmv" && par.size() == 2)
        {
            /* Opens Database file */
            fr.open("Server/Database.txt", ios::app);
                
            user = findInFile(fr, par[1]);

            fr.close();

            /* Checking if the username exists */
            if(!user.empty())
            {
                fr.open("Server/Database.txt");
                fw.open("Server/temp.txt", ios::app);

                /* Removing the user from the database */
                removeUser(fr, fw, user);
            }
            else
                cout << "\nUser does not exists\n";
        }
        else if(par[0] == "show" && par.size() == 1)
        {
            cout << endl;
            system("cat Server/Database.txt");

            sleep(2);
        }

        clearscreen();

    }while(command != "exit");

    return 0;
}

/* 
    Input: a given string, checks if the string contains digit or uppercase characters
    Output: true if the checks are respected, false otherwise.
*/
bool checkUsername(string username)
{
    for(unsigned int i=0; i<username.length(); i++){

        /* Checking if the i-th character is a lowercase */
        if(username.at(i) < 97 || username.at(i) > 122)
            return false;
    }

    /* Checking user input size */
    if(username.length() > MAX_LENGTH)
    {
        cout << "Username too long!\n";
        return false;
    }

    return true;
}

/*
    Input: a string, it checks if it contains:
            - at least one number
            - at least one lowercase character
            - at least one uppercase character
            - at least one special character
    
    Output: true if all the checks are respected
*/
bool checkPassword(string pwd)
{
    bool hasDigit = false;          
    bool hasLower = false;
    bool hasUpper = false;
    bool hasSpecial = false;        
    bool hasIllegal = false;
    string special = "#$%&!?@_";
    unsigned int i;

    /* Checking if the string contains digit */
    for(i = 0; i < pwd.length(); i++)
    {
        if(isdigit(pwd.at(i)))
            hasDigit = true;
    }
    /* Checking if the string contains lowercase character */
    for(i = 0; i < pwd.length(); i++)
    {
        if(islower(pwd.at(i)))
            hasLower = true;
    }
    /* Checking if the string contains uppercase character */
    for(i = 0; i < pwd.length(); i++)
    {
        if(isupper(pwd.at(i)))
            hasUpper = true;
    }
    /* Checking if the string contains special characters */
    for(i = 0; i < pwd.length(); i++)
    {
        for(unsigned int j = 0; j < SPECIAL_LENGTH; j++)
            if(pwd.at(i) == special.at(j))
                hasSpecial = true;
    }

    /* A character is illegal if it is something that has not been considered */
    for(i = 0; i < pwd.length(); i++)
    {
        if(!isdigit(pwd.at(i)))
        {
            if(!islower(pwd.at(i)))
            {
                if(!isupper(pwd.at(i)))
                {
                    if(pwd.at(i) != '#' && pwd.at(i) != '$' && pwd.at(i) != '%' && pwd.at(i) != '&' && pwd.at(i) != '!' && pwd.at(i) != '?' && pwd.at(i) != '@' && pwd.at(i) != '_')
                    {
                        hasIllegal = true;
                    }
                }
            }
        }
    }

    if (pwd.length() < MIN_LENGTH)
        return false;
    else
    {
        if (hasDigit == true && hasLower == true && hasUpper == true && hasSpecial == true && hasIllegal == false)
            return true;
        else
            return false;
    }
}

/*
    Input: input and output stream for a file, a vector of strings
    Output: 
*/
void removeUser(ifstream &fr, ofstream &fw, vector<string> user)
{
    string line;
    bool found = false;
    vector<string> temp_usr;

    while (!fr.eof())
    {
        /* reading a line of the DB */
        getline(fr, line);

        if(!line.empty())
        {
            if(!found){
                
                temp_usr = split(line, ':');

                if(temp_usr[0] == user[0])
                    found = true;
                else
                    fw << line+"\n";
            }
            else
                fw << line+"\n";
        }
    }

    fr.close();
    fw.close();

    /* Deleting the old DB */
    std::remove("Server/Database.txt");

    /* Renaming the new one */
    std::rename("Server/temp.txt", "Server/Database.txt");
}

/*
    Input: takes the DB file
    Output: the first usable ID
*/
int init_bankID(ifstream &fr)
{
    int id;
    string line;
    vector<string> user;    

    if(!fr)
        return 0;
    else{
        while(!fr.eof())
        {
            getline(fr, line);

            if(!line.empty())
                user = split(line, ':');
        }
        
        id = str_to_int(user[2]) + 1;
    }

    return id;
}

void saveInfo(  const char* filename, 
                const unsigned char* iv, size_t ivSize, 
                const unsigned char* tag, size_t tagSize, 
                int bankID)
{
    ofstream file(filename, ios::binary | ios::app);

    if(!file)
    {
        cerr << "Failed to open file for writing: " << filename << endl;
        return;
    }

    /* Convert binary data to hex string */
    ostringstream iv_oss, tag_oss;

    iv_oss << hex << setfill('0');

    for (size_t i = 0; i < ivSize; ++i)
    {
        iv_oss << setw(2) << static_cast<unsigned>(iv[i]);
    }

    tag_oss << hex << setfill('0');

    for (size_t i = 0; i < tagSize; ++i)
    {
        tag_oss << setw(2) << static_cast<unsigned>(tag[i]);
    }

    /* Write the bank ID, IV, Tag, and newline to the file */
    file << bankID << ":" << iv_oss.str() << ":" << tag_oss.str() << "\n";

    file.close();

    if(!file)
    {
        cerr << "Error occurred while closing the file: " << filename << endl;
        return;
    }
}

