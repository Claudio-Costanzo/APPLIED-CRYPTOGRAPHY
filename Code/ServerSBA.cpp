#define DEFAULT_BUFLEN 4096
#define DEFAULT_PORT 51729

/*-------------------------------------------------------------*/

#include<iostream>
#include<fstream>
#include<iomanip>
#include<unistd.h>
#include<vector>
#include<string>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<algorithm>
#include<openssl/rand.h>
#include<openssl/evp.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<openssl/err.h>
#include<openssl/dh.h>
#include<openssl/bn.h>
#include"lib/gcm.hpp"
#include"lib/rsa.hpp"
#include"lib/hash.hpp"
#include"lib/utils.hpp"

using namespace std;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/*
    Per compilare:
    g++ ServerSBA.cpp -o Server.exe -lssl -lcrypto
*/

bool check_nonce(vector<string> v, string nonce)
{
    auto it = find(v.begin(), v.end(), nonce);

    if (it == v.end()) {
        /* Element not found */
        return true;
    } else {
        /* Element found */
        return false;
    }
}

string encryptResult(string result, unsigned char* sessionKey, vector<string> nonce_list)
{
    string t, nonce;
    unsigned char* plaintext;
    unsigned char* gcm_ciphertext;
    unsigned char* message_nonce = (unsigned char*) malloc(12);

    unsigned char* s_iv = (unsigned char*) malloc(12);
    unsigned char* s_tag_buf = (unsigned char*) malloc(16);

    string gcm_result;
    int err = 0;

    RAND_poll();

    do
    {
        /* Generating a random IV for the encryption */
        if(RAND_bytes(message_nonce, 12) != 1)
        {
            cout << "Error in IV generation";
            return "";
        }
        
        nonce = ucharToHex(message_nonce, 12);

    }while(!check_nonce(nonce_list, nonce));

    nonce_list.push_back(nonce);

    t = result+" "+nonce;
    plaintext = string_ref(t);

    gcm_ciphertext = new unsigned char[t.size()]();

    /* Generating a random IV for the encryption */
    if(RAND_bytes(s_iv, 12) != 1)
    {
        cout << "Error in IV generation";
        return "";
    }

    /* Encrypting with aes_gcm with sessionkey */
    err = gcm_encrypt(plaintext, t.size(), s_iv, 12, sessionKey, s_iv, 12, gcm_ciphertext, s_tag_buf);

    gcm_result = ucharToHex(gcm_ciphertext, err)+" "+ucharToHex(s_iv, 12)+" "+ucharToHex(s_tag_buf, 16);

    delete[] gcm_ciphertext;

    return gcm_result;
}

/*
    Input: user history and the new transaction committed
    Output: updated user history
*/
string updateHistory(string userHistory, string transaction){

    vector<string> currentHistory;
    vector<string> newHistory;
    string res;

    if(userHistory != "00000000")
    {
        currentHistory = split(userHistory, ';');

        if(currentHistory.size() == 1){
            newHistory.push_back(transaction);
            newHistory.push_back(currentHistory[0]);

            /* creating the returning string */
            res = newHistory[0]+";"+newHistory[1];
        }
        else if(currentHistory.size() == 2 || currentHistory.size() == 3){
            newHistory.push_back(transaction);
            newHistory.push_back(currentHistory[0]);
            newHistory.push_back(currentHistory[1]);

            /* creating the returning string */
            res = newHistory[0]+";"+newHistory[1]+";"+newHistory[2];
        }
    }
    else
        res = transaction;

    return res;
}

int main()
{
    /* PFS Variables */
    const unsigned char* nonce_a = (unsigned char*) malloc(12);
    unsigned char* nonce_b = (unsigned char*) malloc(12);
    unsigned char* serialized_Yb;
    unsigned char* session_key;
    unsigned char* shared_key;
    unsigned char* p;
    EVP_PKEY_CTX* derive_ctx;
    EVP_PKEY_CTX* dh_ctx;
    EVP_PKEY* dhe_server_pub_key;
    EVP_PKEY* server_prv_key;
    EVP_PKEY* client_pub_key;
    EVP_PKEY* dh_key_pair;
    EVP_PKEY* params;
    EVP_PKEY* Yb;
    EVP_PKEY* Ya;
    size_t shared_key_len;
    DH* dh = DH_new();
    string nonce;
    string m2;
    string m3;
    FILE* p1w;
    BIO* bio;

    /* RSA Variables */
    const unsigned char* rsa_ciphertext;
    const unsigned char* rsa_plaintext;
    unsigned char ciphertext[4096];
    unsigned char* plaintext;
    size_t rsa_plaintext_len;
    size_t rsa_ciphertext_len = sizeof(ciphertext);

    /* GCM Variables */
    unsigned char* transaction_tag_buf = (unsigned char*)malloc(16);
    unsigned char* session_tag_buf = (unsigned char*)malloc(16);
    unsigned char* transaction_iv = (unsigned char*) malloc(12);
    unsigned char* session_iv = (unsigned char*) malloc(12);
    unsigned char* transaction_key = (unsigned char*) malloc(16);
    unsigned char* gcm_ciphertext;
    unsigned char* gcm_plaintext;
    vector<string> gcm_par; 
    string server_result;
    int result_len;

    /* Serialize Variables */
    const unsigned char* serialized_data;
    int Ya_serialized_length;
    int Yb_serialized_length;

    /* Hash Variables */
    unsigned char* salt = (unsigned char*)malloc(16);
    vector<string> hash_par;
    string hash;
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(DEFAULT_PORT);

    /* Communication Variables */
    sockaddr_in client;
    socklen_t clientSize = sizeof(client);
    char recvbuf[DEFAULT_BUFLEN];
    char service[NI_MAXSERV];                                   // Service (i.e. port) the client is connect on
    char host[NI_MAXHOST];                                      // Client's remote name
    const char *sendbuf;
    int clientSocket;
    int listening;

    /* Utility variables */
    vector<string> nonce_list;
    vector<string> temp_usr;                                    //used when we have to modify the DB file
    vector<string> iv_info;                                     //used when we need to work with the transactions
    vector<string> user;                                        //temporary variable used for unicity check
    vector<string> par;                                         //used for user's command parameters
    string transaction;
    string res_decrypt;
    string choice;
    string temp;
    string key;
    ifstream fr;    
    ofstream fw; 
    bool logged = false;
    int bytes_received;                         
    int bytes_sent;
    int balance;
    FILE* file; 

    /* Initialization of p and g */
    /* Load the DH parameters from file */
    file = fopen("params.pem", "r");
    if(!file) 
    {
        cerr << "Error opening file: params.pem" << endl;
        return 1;
    }

    bio = BIO_new_fp(file, BIO_NOCLOSE);                                        //needed to read openssl data structure
    dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
    fclose(file);

    if(!dh)
    {
        cerr << "Error reading DH parameters from file." << endl;
        BIO_free(bio);
        return 1;
    }

    params = EVP_PKEY_new();
    if (!params) 
    {
        cerr << "Error creating EVP_PKEY object." << endl;
        DH_free(dh);
        BIO_free(bio);
        return 1;
    }

    /* Setting p and g in dh */
    if (1 != EVP_PKEY_set1_DH(params, dh)) 
    {
        cerr << "Error setting DH parameters in EVP_PKEY." << endl;
        EVP_PKEY_free(params);
        DH_free(dh);
        BIO_free(bio);
        return 1;
    }

    dh_ctx = EVP_PKEY_CTX_new(params, NULL);
    if (!dh_ctx) 
    {
        cerr << "Error creating EVP_PKEY_CTX object." << endl;
        EVP_PKEY_free(params);
        DH_free(dh);
        BIO_free(bio);
        return 1;
    }

    /* Initialize DBKey */
    fr.open("Server/DBKey.txt");

    key = initKey(fr);

    if(key == "")
    {
        cout << "Error in reading DBKey\n";
        return 1;
    }

    transaction_key = hexToChar(key);

    fr.close();

    /* Loading server's private key */
    file = fopen("Server/secret.pem", "r");
    if(!file)
    {
        cerr << "Error opening file: secret.pem" << endl;
        return 1;
    }

    server_prv_key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);

    if(!server_prv_key)
    {
        cerr << "Error reading private key from file." << endl;
        return 1;
    }

    /* Initializating the socket for communication */
    listening = socket(AF_INET, SOCK_STREAM, 0);
    if(listening == -1)
    {
        cerr << "Can't create a socket! Quitting\n" ;
        return -1;
    }

    // Bind the ip address and port to a socket
    inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);
 
    bind(listening, (sockaddr*)&hint, sizeof(hint));
   
    // Tell Winsock the socket is for listening
    listen(listening, SOMAXCONN);

    while(true)
    {
        // Accept a client socket
        clientSocket = accept(listening, (sockaddr*)&client, &clientSize);
 
        memset(host, 0, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
        memset(service, 0, NI_MAXSERV);

        if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
        {
            cout << endl << host << " connected on port " << service << endl;
        }
        else
        {
            inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
            cout << endl << host << " connected on port " << ntohs(client.sin_port) << endl;
        }

        do
        {
            memset(recvbuf, 0, sizeof(recvbuf));

            /* Receving the command from the user */
            bytes_received = recv(clientSocket, recvbuf, DEFAULT_BUFLEN, 0);

            if(bytes_received > 0)
            {
                /* If all the checks are alright we convert recvbuf into a string type */
                choice.assign(recvbuf, bytes_received);

                if(choice != "exit")
                {
                    /* Decrypting using server's private key if no one is logged, session key if this is established */
                    if(!logged)
                    {
                        rsa_ciphertext = string_ref(choice);
                        plaintext = new unsigned char[choice.size()]();
                        rsa_plaintext_len = choice.size();

                        if(!rsaDecrypt(rsa_ciphertext, rsa_plaintext_len, server_prv_key, plaintext, rsa_plaintext_len))
                        {
                            cerr << "Error decrypting data." << endl;
                            EVP_PKEY_free(server_prv_key);
                            return 1;
                        }

                        par = split(toString(plaintext), ' ');

                        nonce = par[3];

                        /* Saving user's nonce */
                        nonce_a = new unsigned char[nonce.size()];
                        nonce_a = reinterpret_cast<const unsigned char*>(nonce.c_str());

                        /* Checking for replay attack */
                        if(!check_nonce(nonce_list, ucharToHex(nonce_a, 12)))
                        {
                            cout << "Nonce is not fresh. Replay attack detected.\n";
                            return 1;
                        }
                        else
                            nonce_list.push_back(ucharToHex(nonce_a, 12));

                        /* Free */
                        choice.clear();
                        delete[] plaintext;

                        if(par[0] == "login")
                            cout << "\nReceived command1: "+par[0]+"\n";
                        else
                            cout << "\nReceived command2: "+res_decrypt+"\n";
                    }
                    else
                    {
                        /* Decrypting using aesgcm and session key */
                        gcm_par = split(choice,' ');
                        session_iv = hexToChar(gcm_par[1]);
                        session_tag_buf = hexToChar(gcm_par[2]);

                        gcm_ciphertext = new unsigned char[gcm_par[0].size()]();
                        gcm_ciphertext = hexToChar(gcm_par[0]);

                        gcm_plaintext = new unsigned char[gcm_par[0].size()]();

                        /* Decrypting using session key */
                        result_len = gcm_decrypt(gcm_ciphertext, gcm_par[0].size()/2, session_iv, 12, session_tag_buf, session_key, session_iv, 12, gcm_plaintext);
                        if(result_len == -1)
                        {
                            cout << "Error in decrypting file" << endl;
                            return 1;
                        }

                        par = split(toString(gcm_plaintext), ' ');

                        /* Checking for replay attack */
                        if(!check_nonce(nonce_list, par.back()))
                        {
                            cout << "Nonce is not fresh. Replay attack detected.\n";
                            return 1;
                        }
                        else
                        {
                            /* Saving nonce */
                            nonce_list.push_back(par.back());
                            par.pop_back();
                        }
                            
                        cout << "\nReceived command: "+par[0]+"\n";

                        delete[] gcm_plaintext;
                        delete[] gcm_ciphertext;
                    }
                }
                else
                {
                    cout << "\nReceived command: "+choice << endl;
                    par = split(choice, ' ');
                }

                /* Parsing the command */
                /* Login */
                if(par[0] == "login" && par.size() == 4 && !logged)
                {
                    /* Opens Database file */
                    fr.open("Server/Database.txt");
                        
                    user = findInFile(fr, par[1]);

                    fr.close();

                    if(!user.empty())
                    {
                        /* Taking hash parameters from DB */
                        hash_par = split(user[1], '$');

                        salt = hexToChar(hash_par[0]);

                        hash = SHA256WithSalt(par[2], salt, 16);

                        /* Checking if the two hashs are equal */
                        if(hash == hash_par[1])
                        {
                            /* M2 */
                            
                            RAND_poll();

                            /* Generating a random Nonce for the encryption */
                            if(RAND_bytes(nonce_b, 12) != 1)
                            {
                                cout << "Error in nonce generation";
                                return 1;
                            }

                            /* Load the public key from file */ 
                            file = fopen(("PublicKeys/"+par[1]+".pem").c_str(), "r");
                            if(!file)
                            {
                                cerr << "Error opening file: "+par[1]+".pem" << endl;
                                return 1;
                            }

                            /* Free */
                            par.clear();

                            client_pub_key = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
                            fclose(file);

                            if(!client_pub_key)
                            {
                                cerr << "Error reading public key from file." << endl;
                                return 1;
                            }

                            /* Ensure the key is an RSA key */
                            if(EVP_PKEY_id(client_pub_key) != EVP_PKEY_RSA)
                            {
                                cerr << "Public key is not an RSA key." << endl;
                                EVP_PKEY_free(client_pub_key);
                                return 1;
                            }

                            /* Generating private-public key pair for DH */
                            dh_key_pair = NULL;
                            if(1 != EVP_PKEY_keygen_init(dh_ctx)) 
                            reportErrors();

                            if(1 != EVP_PKEY_keygen(dh_ctx, &dh_key_pair)) 
                            reportErrors();

                            /* Put the dhe public key in a file */
                            p1w = fopen("temp_key.pem", "w");
                            if(!p1w){ cerr << "Error: cannot open file temp_key.pem' (missing?)\n"; exit(1); }
                            PEM_write_PUBKEY(p1w, dh_key_pair);
                            fclose(p1w);

                            /* Load the dhe public key in a variable*/
                            p1w = fopen("temp_key.pem", "r");
                            if (!p1w) {
                                cerr << "Error: cannot open file 'temp_key.pem' (missing?)\n";
                                exit(1);
                            }

                            dhe_server_pub_key = PEM_read_PUBKEY(p1w, NULL, NULL, NULL);
                            fclose(p1w);
                            system("rm temp_key.pem");

                            /* Serializing the key */
                            Yb = dhe_server_pub_key;

                            /* Determine the length of the serialized data */
                            Yb_serialized_length = i2d_PUBKEY(Yb, nullptr);

                            if (Yb_serialized_length < 0)
                                reportErrors();

                            /* Allocate memory to store the serialized data */ 
                            serialized_Yb = new unsigned char[Yb_serialized_length];

                            /* Serialize the EVP_PKEY object */ 
                            p = serialized_Yb;
                            int result = i2d_PUBKEY(Yb, &p);

                            if (result < 0)
                                reportErrors();

              
                            /* Init M2 */
                            m2 = toString(nonce_a)+' '+ucharToHex(nonce_b, 12)+' '+ucharToHex(serialized_Yb, Yb_serialized_length)+' '+toString(Yb_serialized_length);

                            rsa_plaintext = string_ref(m2);
                            rsa_plaintext_len = m2.size();

                            /* Encrypt the plaintext using the RSA public key */
                            if (!rsaEncrypt(rsa_plaintext, rsa_plaintext_len, client_pub_key, ciphertext, rsa_ciphertext_len))
                            {
                                cerr << "Error encrypting data." << endl;
                                return 1;
                            }

                            /* Sending M2 to the client */
                            bytes_sent = send(clientSocket, ciphertext, rsa_ciphertext_len, 0);
                            if (bytes_sent == -1)
                            {
                                cout << "Could not send to client!\n";
                                continue;
                            }

                            /* Free */
                            memset(ciphertext, 0, rsa_ciphertext_len);
                            memset(recvbuf, 0, DEFAULT_BUFLEN);
                            m2.clear();

                            /* Waiting for M3 */
                            bytes_received = recv(clientSocket, recvbuf, DEFAULT_BUFLEN, 0);

                            if(bytes_received > 0)
                            {
                                m3.assign(recvbuf, bytes_received);

                                rsa_ciphertext = string_ref(m3);
                                plaintext = new unsigned char[m3.size()]();
                                rsa_plaintext_len = m3.size();

                                if(!rsaDecrypt(rsa_ciphertext, rsa_plaintext_len, server_prv_key, plaintext, rsa_plaintext_len))
                                {
                                    cerr << "Error decrypting data." << endl;
                                    EVP_PKEY_free(server_prv_key);
                                    return 1;
                                }

                                /* Checking if the nonce sended is the same of the one we received */
                                par = split(toString(plaintext), ' ');

                                /* Free */
                                delete[] plaintext;

                                if(par[0] != "Incorrect")
                                {
                                    /* Checking received nonce */
                                    if(par[0] == ucharToHex(nonce_b, 12))
                                    {
                                        /* Deserialize the DH public key */
                                        serialized_data = hexToChar(par[1]); 
                                        Ya_serialized_length = str_to_int(par[2]);

                                        nonce_list.push_back(ucharToHex(nonce_b, 12));

                                        /* Create a pointer to hold the EVP_PKEY object */ 
                                        Ya = nullptr;

                                        /* Deserialize the data into an EVP_PKEY object */ 
                                        Ya = d2i_PUBKEY(&Ya, &serialized_data, Ya_serialized_length);

                                        if (!Ya)
                                            reportErrors();              

                                        /* Generate Kab the shared secret */
                                        derive_ctx = EVP_PKEY_CTX_new(dh_key_pair, NULL);

                                        if(!derive_ctx)
                                            reportErrors();

                                        
                                        if(EVP_PKEY_derive_init(derive_ctx) <= 0)
                                            reportErrors();
                                        
                                        if(EVP_PKEY_derive_set_peer(derive_ctx, Ya) <= 0)
                                            reportErrors();
                                        
                                        EVP_PKEY_derive(derive_ctx, NULL, &shared_key_len);
                                        shared_key = (unsigned char*) (malloc(int (shared_key_len)));

                                        if(!shared_key)
                                            reportErrors();

                                        if(EVP_PKEY_derive(derive_ctx, shared_key, &shared_key_len) <= 0)
                                            reportErrors();
                                        
                                        /* Deriving session key K from Kab */
                                        session_key = SHA256(shared_key, shared_key_len);
                    
                                        /* Destroy private key b */
                                        EVP_PKEY_free(dh_key_pair);

                                        /* Destroy Kab after creating session key K */
                                        delete[] shared_key; 

                                        /* User is now logged in */
                                        logged = true;
                                    }
                                    else
                                    {
                                        temp = "Error in key establishment.";

                                        rsa_plaintext = string_ref(temp);
                                        rsa_plaintext_len = temp.size();

                                        /* Encrypt the plaintext using the RSA public key */ 
                                        if (!rsaEncrypt(rsa_plaintext, rsa_plaintext_len, client_pub_key, ciphertext, rsa_ciphertext_len))
                                        {
                                            cerr << "Error encrypting data." << endl;
                                            EVP_PKEY_free(client_pub_key);
                                            return 1;
                                        }

                                        /* Sending error to the client */
                                        bytes_sent = send(clientSocket, ciphertext, rsa_ciphertext_len, 0);
                                        if (bytes_sent == -1)
                                        {
                                            cout << "Could not send to client!\n";
                                            continue;
                                        }
                                    }
                                }
                                else
                                    cout << "Error in key establishment. 2" << endl;
                            }
                        }
                        else
                        {
                            /* Putting the response into sendbuf */
                            sendbuf = "Error\n";
                            cout << "404: Not Found\n";

                            /* Send the response */
                            send(clientSocket, sendbuf,(int)strlen(sendbuf)+1, 0);
                        }
                    }
                    else
                    {
                        /* Putting the response into sendbuf */
                        sendbuf = "Error\n";
                        cout << "404: Not Found\n";

                        /* Send the response */
                        send(clientSocket, sendbuf,(int)strlen(sendbuf)+1, 0);
                    }

                }    /* Logout */
                else if(par[0] == "logout" && par.size() == 1 && logged)
                {
                    server_result = encryptResult("200: OK", session_key, nonce_list);

                    /* Putting the response into sendbuf */
                    sendbuf = server_result.c_str();
                    cout << "200: OK\n";

                    /* Send the response */
                    send(clientSocket, sendbuf, strlen(sendbuf), 0);

                    logged = false;

                }   /* Balance */
                else if(par[0] == "balance" && par.size() == 1 && logged)
                {
                    temp = "\nYour bank ID is: "+user[2]+"\nYour balance is: "+user[3]+"\n";
                    server_result = encryptResult(temp, session_key, nonce_list);

                    sendbuf = server_result.c_str();

                    cout << "200: OK\n";

                    /* Send the response */
                    send(clientSocket, sendbuf, strlen(sendbuf), 0);

                    temp.clear();

                }   /* Transfer */
                else if(par[0] == "transfer" && par.size() == 3 && logged)
                {
                    /* Checking if the target user is the user himself */
                    if(par[1] != user[0])
                    {
                        /* Checking if the user has enough money */
                        if(str_to_int(par[2]) > 0 && str_to_int(par[2]) <= str_to_int(user[3]))
                        {
                            fr.open("Server/Database.txt");

                            temp_usr = findInFile(fr, par[1]);

                            fr.close();

                            if(!temp_usr.empty())
                            {
                                if(str_to_int(temp_usr[3]) > (INT_MAX - str_to_int(par[2])))
                                {
                                    /* Putting the response into sendbuf */
                                    server_result = encryptResult("500: Internal Server Error\n", session_key, nonce_list);
                                    sendbuf = server_result.c_str();

                                    cout << "500: Internal Server Error\n";

                                    /* Send the response */
                                    send(clientSocket, sendbuf, strlen(sendbuf), 0);
                                }
                                else
                                {
                                    fr.open("Server/T_IV.txt", ios::app);

                                    /* Searching for the user's bankId */
                                    iv_info = findInFile(fr, user[2]);

                                    fr.close();

                                    /* Initializating the variables */
                                    transaction_iv = hexToChar(iv_info[1]);
                                    transaction_tag_buf = hexToChar(iv_info[2]);

                                    /* Ciphertext */
                                    gcm_ciphertext = hexToChar(user[4]);

                                    gcm_plaintext = new unsigned char[user[4].size()]();

                                    /* Decrypting transaction list */
                                    result_len = gcm_decrypt(gcm_ciphertext, user[4].size()/2, transaction_iv, 12, transaction_tag_buf, transaction_key, transaction_iv, 12, gcm_plaintext);

                                    if(result_len == -1)
                                    {
                                        cout << "Error in decrypting file" << endl;
                                        return 1;
                                    }

                                    /* This is the new transaction that has to be inserted */
                                    transaction = par[1]+","+par[2]+","+get_time();

                                    user[4] = updateHistory(toString(gcm_plaintext), transaction);

                                    delete[] gcm_plaintext;
                                    delete[] gcm_ciphertext;

                                    /* Updating sender's balance */
                                    user[3] = toString(str_to_int(user[3]) - str_to_int(par[2]));

                                    /* Plaintext */
                                    plaintext = (unsigned char*) user[4].c_str();

                                    gcm_ciphertext = new unsigned char[user[4].size()]();

                                    /* Encrypting again the transaction list  */
                                    RAND_poll();

                                    /* Generating a random IV for the encryption */
                                    if(RAND_bytes(transaction_iv, 12) != 1)
                                    {
                                        cout << "Error in IV generation";
                                        return 1;
                                    }

                                    /* Encrypting the initial setting for the transaction list */
                                    result_len = gcm_encrypt(plaintext, user[4].size(), transaction_iv, 12, transaction_key, transaction_iv, 12, gcm_ciphertext, transaction_tag_buf);

                                    /* Updating user info with encrypted transactions */
                                    user[4] = ucharToHex(gcm_ciphertext, result_len);

                                    delete[] gcm_ciphertext;

                                    /* Updating IV info */
                                    fr.open("Server/T_IV.txt");
                                    fw.open("Server/temp.txt");

                                    updateIV(fr, fw, user[2], transaction_iv, transaction_tag_buf);

                                    /* Updating DB with sender info */
                                    fr.open("Server/Database.txt");
                                    fw.open("Server/temp.txt", ios::app);

                                    updateDB(fr, fw, user);

                                    /* Updating receiver's balance */
                                    temp_usr[3] = toString(str_to_int(temp_usr[3]) + str_to_int(par[2]));

                                    /* Updating DB with receiver info */
                                    fr.open("Server/Database.txt");
                                    fw.open("Server/temp.txt", ios::app);

                                    updateDB(fr, fw, temp_usr);

                                    /* Putting the response into sendbuf */
                                    server_result = encryptResult("200: OK", session_key, nonce_list);

                                    sendbuf = server_result.c_str();
                                    cout << "200: OK\n";

                                    /* Send the response */
                                    send(clientSocket, sendbuf, strlen(sendbuf), 0);
                                }
                            }
                            else
                            {
                                /* Error if the receiver does not exists */
                                server_result = encryptResult("400: Bad Request\n", session_key, nonce_list);
                                sendbuf = server_result.c_str();
                                
                                cout << "400: Bad Request\n";

                                /* Send the response */
                                send(clientSocket, sendbuf, strlen(sendbuf), 0);
                            }
                        }
                        else
                        {
                            /* Error if the user does not have enough money */
                            server_result = encryptResult("400: Bad Request\n", session_key, nonce_list);
                            sendbuf = server_result.c_str();
                            
                            cout << "400: Bad Request\n";

                            /* Send the response */
                            send(clientSocket, sendbuf, strlen(sendbuf), 0);
                        }
                    }
                    else
                    {
                        /* Error if the user is trying to send money to him/herself */
                        server_result = encryptResult("400: Bad Request\n", session_key, nonce_list);
                        sendbuf = server_result.c_str();

                        cout << "400: Bad Request\n";

                        /* Send the response */
                        send(clientSocket, sendbuf, strlen(sendbuf), 0);
                    }

                }   /* History */
                else if(par[0] == "history" && par.size() == 1 && logged)
                {
                    fr.open("Server/T_IV.txt");

                    /* Searching for the user's bankId */
                    iv_info = findInFile(fr, user[2]);

                    fr.close();

                    /* Initializing IV and Tag */
                    transaction_iv = hexToChar(iv_info[1]);
                    transaction_tag_buf = hexToChar(iv_info[2]);

                    /* Ciphertext */
                    gcm_ciphertext = hexToChar(user[4]);

                    gcm_plaintext = new unsigned char[user[4].size()]();

                    result_len = gcm_decrypt(gcm_ciphertext, user[4].size()/2, transaction_iv, 12, transaction_tag_buf, transaction_key, transaction_iv, 12, gcm_plaintext);

                    if(result_len == -1)
                    {
                        cout << "Error in decrypting file" << endl;
                        return 1;
                    }

                    /* Putting the response into sendbuf */
                    temp = "\nYour transaction list is: "+toString(gcm_plaintext)+"\n";

                    server_result = encryptResult(temp, session_key, nonce_list);

                    sendbuf = server_result.c_str();
                    
                    cout << "200: OK\n";

                    /* Send the response */
                    send(clientSocket, sendbuf, strlen(sendbuf), 0);

                    temp.clear();
                    delete[] gcm_ciphertext;
                    delete[] gcm_plaintext;

                }   /* Deposit */
                else if(par[0] == "deposit" && par.size() == 2 && logged)
                {
                    if(!par[1].empty() && str_to_int(par[1]) > 0)
                    {
                        balance = str_to_int(user[3]);
                        
                        if(balance > (INT_MAX - str_to_int(par[1])))
                        {
                            server_result = encryptResult("500: Internal Server Error\n", session_key, nonce_list);
                            sendbuf = server_result.c_str();
                            
                            cout << "500: Internal Server Error\n";

                            /* Send the response */
                            send(clientSocket, sendbuf, strlen(sendbuf), 0);
                        }
                        else
                        {
                            balance += str_to_int(par[1]);

                            /* Updating also temp_usr */
                            user[3] = toString(balance);

                            fr.open("Server/Database.txt");
                            fw.open("Server/temp.txt", ios::app);

                            updateDB(fr, fw, user);

                            server_result = encryptResult("200: OK", session_key, nonce_list);

                            /* Putting the response into sendbuf */
                            sendbuf = server_result.c_str();
                            cout << "200: OK\n";

                            /* Send the response */
                            send(clientSocket, sendbuf,(int)strlen(sendbuf), 0);
                        }
                    }
                    else
                    {
                        /* Error due to negative amount */
                        server_result = encryptResult("400: Bad Request\n", session_key, nonce_list);
                        sendbuf = server_result.c_str();
                        
                        cout << "400: Bad Request\n";

                        /* Send the response */
                        send(clientSocket, sendbuf, strlen(sendbuf), 0);
                    }

                }   /* Exit */
                else if(par[0] == "exit" && par.size() == 1)
                {
                    if(logged)
                    {
                        /* Putting the response into sendbuf */
                        server_result = encryptResult("200: OK", session_key, nonce_list);
                        sendbuf = server_result.c_str();

                        /* Delete session key */
                        delete[] session_key;
                    }
                    else
                        sendbuf = "200: OK";
                    
                    cout << "200: OK\n";

                    /* Setting logged to false 'cause the user is no more online */
                    logged = false;

                    /* Send the response */
                    send(clientSocket, sendbuf, strlen(sendbuf), 0);
                }
                else
                {
                    if(logged)
                    {
                        /* Putting the response into sendbuf */
                        server_result = encryptResult("400: Bad Request\n", session_key, nonce_list);

                        sendbuf = server_result.c_str();
                    }
                    else
                        sendbuf = "400: Bad Request\n";

                    cout << "400: Bad Request\n";

                    /* Send the response */
                    send(clientSocket, sendbuf, strlen(sendbuf), 0);
                }

                par.clear();  
            }
            else
            {
                if(bytes_received == 0)
                {
                    /* If bytesReceived is 0, the user is gone */
                    choice = "exit";
                }
                else
                {
                    cout << "recv failed\n " ;
                    return 1;
                }
            }
        }
        while(choice != "exit");

        /* Cleanup */ 
        close(clientSocket);
    }

    /* No longer need server socket */ 
    close(listening);

    /* Deallocating dh variables */
    DH_free(dh);
    BIO_free(bio);

    /* Deallocating rsa variable */
    EVP_PKEY_free(server_prv_key);

    return 0;
}

#pragma GCC diagnostic pop