#include<string.h>
#include<sstream>
#include<unistd.h>
#include<vector>
#include<iostream>
#include<iomanip>

using namespace std;

template <typename T>

/* Converts the input x into a string type */
string toString(T x)
{    
    stringstream ss;
    ss << x;

    return ss.str();
}

/* Converts the input string into an integer value */
int str_to_int (string s)
{
    stringstream ss;
    int res;

    ss << s;

    /* Converting into int */
    ss >> res;

    return res;
}

/* Clears the screen */
void clearscreen()
{
    sleep(2);
    system("clear");
}

/* 
    Input: a string, a token and the size of the returning vector
    Output: a vector which contains the strings delimited by the token
*/
vector<string> split(string str, char tok)
{
    vector<string> temp;
    unsigned int pos, i = 0;

    /* Searching the occurence of the token in str */
    pos = str.find(tok);

    while(pos != -1){

        /* saving the substring */
        temp.push_back(str.substr(0, pos));

        /* erasing found substring from str to continue */
        str.erase(0, pos + 1);

        i++;

        /* Searching the occurence of the token in str */
        pos = str.find(tok);
    }

    temp.push_back(str);

    return temp;
}

/* 
    Input: an hexadecimal string
    Output: unsigned char* of the inputted string
*/
unsigned char* hexToChar(const string& hexString)
{
    size_t length = hexString.length();

    if (length % 2 != 0)
    {
        cerr << "Invalid hex string: odd number of characters" << endl;
        return nullptr;
    }

    size_t charLength = length / 2;
    unsigned char* data = new unsigned char[charLength];

    for (size_t i = 0; i < charLength; ++i)
    {
        istringstream iss(hexString.substr(2 * i, 2));
        int value;
        if (!(iss >> hex >> value))
        {
            cerr << "Invalid hex string: failed to convert" << endl;
            delete[] data;
            return nullptr;
        }
        data[i] = static_cast<unsigned char>(value);
    }

    return data;
}

/* 
    Input: a string
    Output: unsigned char* of the inputted string
*/
unsigned char* string_ref(string str)
{
    unsigned char* data = new unsigned char[str.size()];
    
    for (size_t i = 0; i < str.size(); ++i)
    {
        data[i] = static_cast<unsigned char>(str.at(i));
    }

    return data;
}

/* 
    Input: const unsigned char* data, its size
    Output: string rappresentation of the inputted data
*/
string ucharToHex(const unsigned char* data, size_t dataSize) 
{
    stringstream ss;
    ss << hex << setfill('0');

    for (size_t i = 0; i < dataSize; ++i) {
        ss << setw(2) << static_cast<unsigned int>(data[i]);
    }

    return ss.str();
}

/* This function updates fr file by inserting in it: the string id, iv and tag_buf */
void updateIV(ifstream &fr, ofstream &fw, string id, unsigned char* iv, unsigned char* tag_buf)
{
    string line;
    bool found = false;
    vector<string> temp_iv;

    while (!fr.eof())
    {
        /* reading a line of the DB */
        getline(fr, line);

        if(!line.empty())
        {
            if(!found)
            {    
                temp_iv = split(line, ':');

                if(temp_iv[0] == id){
                    found = true;

                    fw << id+":"+ucharToHex(iv, 12)+":"+ucharToHex(tag_buf, 16)+"\n";
                }
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
    std::remove("Server/T_IV.txt");

    /* Renaming the new one */
    std::rename("Server/temp.txt", "Server/T_IV.txt");
}

/*
    Input: an inputstream for a file and a string
    Output: if the string is in the file it returns a vector containing the line of the file splitted by ':', otherwise an empty vector 
*/
vector<string> findInFile(ifstream &fr, string str)
{
    vector<string> temp;
    string line;
    bool found = false;

    /* Searching for existing string in the file */
    while(!fr.eof() && !found)
    {    
        /* reading a line of the DB */
        getline(fr, line);

        if(!line.empty())
        {
            temp = split(line, ':');

            if(str == temp[0])
                found = true;
        }
    }

    if(found)
        return temp;
    else
    {
        temp.clear();
        return temp;
    }

}

/* The function updates the fr file by adding in it user's informations */
void updateDB(ifstream &fr, ofstream &fw, vector<string> user)
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
            if(!found)
            {    
                temp_usr = split(line, ':');

                if(temp_usr[0] == user[0]){
                    found = true;

                    fw << user[0]+":"+user[1]+":"+user[2]+":"+user[3]+":"+user[4]+"\n";
                }
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
    Input: a file to read
    Output: the first line of the file, or "" if there is no one
*/
string initKey(ifstream &fr)
{
    string line;

    if(fr)
    {
        getline(fr, line);

        if(!line.empty())
            return line;
    }

    return "";
}

/* This function returns a timestamp value into as a string containing: day-month-year hour:minuts:seconds */
string get_time()
{
    // Get the current time
    time_t currentTime = time(nullptr);
    
    // Convert the time to a struct tm
    tm* localTime = localtime(&currentTime);

    // Define the format you want
    const char* format = "%d %B %Y %H:%M:%S";

    // Create a char array to hold the formatted date
    char formattedDate[100];

    // Format the date using strftime()
    strftime(formattedDate, sizeof(formattedDate), format, localTime);

    return toString(formattedDate);
}