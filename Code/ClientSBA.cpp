#define DEFAULT_BUFLEN 4096
#define DEFAULT_PORT 51729

#include<iostream>
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<vector>
#include<iomanip>
#include<fstream>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<string.h>
#include<algorithm>
#include<openssl/conf.h>
#include<openssl/evp.h>
#include<openssl/err.h>
#include<openssl/crypto.h>
#include<openssl/ssl.h>
#include<openssl/rand.h>
#include<openssl/pem.h>
#include<openssl/dh.h>
#include<openssl/bio.h>
#include<openssl/hmac.h>
#include"lib/gcm.hpp"
#include"lib/rsa.hpp"
#include"lib/hash.hpp"
#include"lib/utils.hpp"

using namespace std;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/*
    Per compilare:
    g++ ClientSBA.cpp -o Client.exe -lssl -lcrypto 
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

int main(int argc, char **argv) 
{
    /* PFS Variables */
    const unsigned char* nonce_b = (unsigned char*) malloc(12);
    unsigned char* nonce_a = (unsigned char*) malloc(12);
    unsigned char* serialized_Ya;
    unsigned char* session_key;
    unsigned char* shared_key;
    unsigned char* p;
    EVP_PKEY_CTX* derive_ctx;
    EVP_PKEY_CTX* dh_ctx;
    EVP_PKEY* dhe_client_pub_key;
    EVP_PKEY* server_pub_key;
    EVP_PKEY* client_prv_key;
    EVP_PKEY* dh_key_pair;
    EVP_PKEY* params;
    EVP_PKEY* Yb;
    EVP_PKEY* Ya;
    size_t shared_key_len;
    DH* dh = DH_new();
    string m1;
    string m2;
    string m3;
    FILE* p1w;
    BIO* bio;

    /* RSA Variables */
    const unsigned char* rsa_ciphertext;
    const unsigned char* rsa_plaintext;
    unsigned char ciphertext[4096];                 //buffer to memorize encrypted data
    unsigned char* plaintext;
    size_t rsa_plaintext_len;
    size_t rsa_ciphertext_len = sizeof(ciphertext);

    /* GCM Variables */
    unsigned char* session_tag_buf = (unsigned char*) malloc(sizeof(16));
    unsigned char* session_iv = (unsigned char*) malloc(sizeof(12));
    unsigned char* message_nonce = (unsigned char*) malloc(16);
    unsigned char* gcm_ciphertext;
    unsigned char* gcm_plaintext;
    vector<string> gcm_par;
    string gcm_command;
    int result_len;

    /* Serialize Variables */
    const unsigned char* serialized_data;
    int Ya_serialized_length;
    int Yb_serialized_length;

    /* Communication Variables */
    string ipAddress = "127.0.0.1";
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int sock;
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(DEFAULT_PORT);

    /* Utility Variables */
    vector<string> response_par;
    vector<string> command_par;
    vector<string> nonce_list;
    string server_result;
    string session_message;
    string response;
    string command;
    string nonce;
    bool logged = false;
    int bytes_received;
    int bytes_sent;
    FILE* file;

    /* Load public key from file */ 
    file = fopen("PublicKeys/Server.pem", "r");
    if(!file)
    {
        cerr << "Error opening file: Server.pem" << endl;
        return 1;
    }

    server_pub_key = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);

    if(!server_pub_key)
    {
        cerr << "Error reading public key from file." << endl;
        return 1;
    }

    /* Ensure the key is an RSA key */ 
    if(EVP_PKEY_id(server_pub_key) != EVP_PKEY_RSA)
    {
        cerr << "Public key is not an RSA key." << endl;
        EVP_PKEY_free(server_pub_key);
        return 1;
    }

    /* Create a socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        cout << "Unable to create socket\n";
        return 1;
    }

    /* Setting receiving buffer to 0 */
    memset(recvbuf, 0, sizeof(recvbuf));
    
    inet_pton(AF_INET, ipAddress.c_str(), &hint.sin_addr);

    /* Load the DH parameters from file */
    file = fopen("params.pem", "r");
    if(!file) 
    {
        cerr << "Error opening file: params.pem" << endl;
        return 1;
    }

    bio = BIO_new_fp(file, BIO_NOCLOSE);                       //needed to read openssl data structure
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

    /* Initialization of p and g */
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

    /* Connect to the server on the socket */
    int connectRes = connect(sock, (sockaddr*)&hint, sizeof(hint));
    if(connectRes == -1)
    {
        cout << "Unable to connect to server!\n";
        return 1;
    }

    do{
        if(logged)
            cout << "\nHi! this is the list of commands\n\nBalance: \t\tbalance\nTransfer: \t\ttransfer [username] [amount]\nHistory: \t\thistory\nDeposit: \t\tdeposit [amount]\nLog out: \t\tlogout\n\nIf you need more info type \"help\".\n\nType \"exit\" to close the app.\n\n> ";
        else
            cout << "\nWelcome to SBA!\n\nLogin: \t\tlogin [username] [password]\n\nIf you need more info type \"help\".\n\nType \"exit\" to close the app.\n\n> ";

        getline(cin, command);

        /* Taking command's parameters */
        command_par = split(command, ' ');

        /* Login */
        if(command_par[0] == "login" && !logged)
        {
            /* M1 */
            RAND_poll();

            /* Generating a random Nonce for the encryption */
            if(RAND_bytes(nonce_a, 12) != 1)
            {
                cout << "Error in nonce generation";
                return 1;
            }

            /* Attaching the nonce to the command */
            m1 = command+" "+ucharToHex(nonce_a, 12);

            rsa_plaintext = string_ref(m1);
            rsa_plaintext_len = m1.size();

            /* Encrypt the plaintext using the RSA server public key */
            if (!rsaEncrypt(rsa_plaintext, rsa_plaintext_len, server_pub_key, ciphertext, rsa_ciphertext_len))
            {
                cerr << "Error encrypting data." << endl;
                EVP_PKEY_free(server_pub_key);
                return 1;
            }

            /* Sending M1 to the server */
            bytes_sent = send(sock, ciphertext, rsa_ciphertext_len, 0);
            if (bytes_sent == -1)
            {
                cout << "Could not send to server!\n";
                continue;
            }

            /* Free */
            memset(ciphertext, 0, rsa_ciphertext_len);
            delete[] rsa_plaintext;

            /* Wait for M2 */ 
            bytes_received = recv(sock, recvbuf, DEFAULT_BUFLEN, 0);
            if(bytes_received > 0 && toString(recvbuf) != "Error\n")
            {
                /* Loading Client's private key */
                file = fopen(("Users/"+command_par[1]+"/secret.pem").c_str(), "r");
                if(!file)
                {
                    cerr << "Error opening file: "+command_par[1]+"/secret.pem" << endl;
                    return 1;
                }

                /* command_par is no longer needed */
                command_par.clear();

                client_prv_key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
                fclose(file);

                if(!client_prv_key)
                {
                    cerr << "Error reading private key from file." << endl;
                    return 1;
                }

                /* Decrypting recvbuf using client's private key */
                m2.assign(recvbuf, bytes_received);

                rsa_ciphertext = string_ref(m2);
                plaintext = new unsigned char[m2.size()]();
                rsa_plaintext_len = m2.size();

                if(!rsaDecrypt(rsa_ciphertext, rsa_plaintext_len, client_prv_key, plaintext, rsa_plaintext_len))
                {
                    cerr << "Error decrypting data." << endl;
                    EVP_PKEY_free(client_prv_key);
                    return 1;
                }

                /* Checking if the nonce sended is the same of the one we received */
                command_par = split(toString(plaintext), ' ');

                /* Free */
                delete[] rsa_ciphertext;
                delete[] plaintext;

                if(command_par[0] == ucharToHex(nonce_a, 12))
                {
                    /* Deserialize the DH public key */
                    nonce_b = new unsigned char[command_par[1].size()]();                          
                    nonce_b = reinterpret_cast<const unsigned char*>(command_par[1].c_str());

                    /* Checking for replay attack */
                    if(!check_nonce(nonce_list, ucharToHex(nonce_b, 12)))
                    {
                        cout << "Nonce is not fresh. Replay attack detected.\n";
                        return 1;
                    }
                    else
                    {
                        nonce_list.push_back(ucharToHex(nonce_a, 12));
                        nonce_list.push_back(ucharToHex(nonce_b, 12));
                    }

                    serialized_data = hexToChar(command_par[2]);                                    
                    Yb_serialized_length = str_to_int(command_par[3]);                              

                    /* Create a pointer to hold the EVP_PKEY object */ 
                    Yb = nullptr;

                    /* Deserialize the data into an EVP_PKEY object */ 
                    Yb = d2i_PUBKEY(&Yb, &serialized_data, Yb_serialized_length);

                    if(!Yb)
                        reportErrors();

                    /* Generating private-public key pair for DH */
                    dh_key_pair = NULL;
                    if(1 != EVP_PKEY_keygen_init(dh_ctx)) 
                        reportErrors();

                    if(1 != EVP_PKEY_keygen(dh_ctx, &dh_key_pair)) 
                        reportErrors();

                    /* Put the dhe public key in a file */
                    p1w = fopen("temp_key1.pem", "w");
                    if(!p1w){ cerr << "Error: cannot open file temp_key.pem' (missing?)\n"; exit(1); }
                    PEM_write_PUBKEY(p1w, dh_key_pair);
                    fclose(p1w);

                    /* Load the dhe public key in a variable*/
                    p1w = fopen("temp_key1.pem", "r");
                    if (!p1w) {
                        cerr << "Error: cannot open file 'temp_key.pem' (missing?)\n";
                        exit(1);
                    }

                    dhe_client_pub_key = PEM_read_PUBKEY(p1w, NULL, NULL, NULL);
                    fclose(p1w);
                    system("rm temp_key1.pem");
  
                    /* Serializing the key */
                    Ya = dhe_client_pub_key;                                            

                    /* Determine the length of the serialized data */ 
                    Ya_serialized_length = i2d_PUBKEY(Ya, nullptr);

                    if(Ya_serialized_length < 0)
                        reportErrors();

                    /* Allocate memory to store the serialized data */ 
                    serialized_Ya = new unsigned char[Ya_serialized_length];

                    /* Serialize the EVP_PKEY object */ 
                    p = serialized_Ya;
                    int result = i2d_PUBKEY(Ya, &p);

                    if(result < 0)
                        reportErrors();

                    /* Generate the shared secret Kab */
                    derive_ctx = EVP_PKEY_CTX_new(dh_key_pair, NULL);

                    if(!derive_ctx)
                        reportErrors();
                    
                    if(EVP_PKEY_derive_init(derive_ctx) <= 0)
                        reportErrors();

                    if(EVP_PKEY_derive_set_peer(derive_ctx, Yb) <= 0)
                        reportErrors();

                    EVP_PKEY_derive(derive_ctx, NULL, &shared_key_len);
                    shared_key = (unsigned char*) (malloc(int (shared_key_len)));

                    if(!shared_key)
                        reportErrors();

                    if(EVP_PKEY_derive(derive_ctx, shared_key, &shared_key_len) <= 0)
                        reportErrors();

                    /* Deriving session key K from Kab */
                    session_key = SHA256(shared_key, shared_key_len);

                    /* Destroy private key a */
                    EVP_PKEY_free(dh_key_pair);

                    /* Destroy Kab after creating session key K */
                    delete[] shared_key;

                    /* Init M3 */
                    m3 = toString(nonce_b)+' '+ucharToHex(serialized_Ya, Ya_serialized_length)+' '+toString(Ya_serialized_length);

                    rsa_plaintext = string_ref(m3);
                    rsa_plaintext_len = m3.size();

                    /* Encrypt the plaintext using the RSA server public key */
                    if (!rsaEncrypt(rsa_plaintext, rsa_plaintext_len, server_pub_key, ciphertext, rsa_ciphertext_len))
                    {
                        cerr << "Error encrypting data." << endl;
                        EVP_PKEY_free(server_pub_key);
                        return 1;
                    }

                    /* Send M3 */
                    bytes_sent = send(sock, ciphertext, rsa_ciphertext_len, 0);

                    if (bytes_sent == -1)
                    {
                        cout << "Could not send to server!\n";
                        continue;
                    }

                    /* Free */
                    delete[] rsa_plaintext;
                    memset(recvbuf, 0, DEFAULT_BUFLEN);

                    /* User is now logged in */
                    logged = true;
                }
                else
                {
                    /* Sending error in checking nonce to the server */
                    response = "Incorrect nonce.";

                    plaintext = (unsigned char*) response.c_str();
                    rsa_plaintext_len = strlen((const char*) plaintext);

                    /* Encrypt the plaintext using the RSA server public key */
                    if (!rsaEncrypt(plaintext, rsa_plaintext_len, server_pub_key, ciphertext, rsa_ciphertext_len))
                    {
                        cerr << "Error encrypting data." << endl;
                        EVP_PKEY_free(server_pub_key);
                        return 1;
                    }

                    bytes_sent = send(sock, ciphertext, rsa_ciphertext_len, 0);
                    if (bytes_sent == -1)
                    {
                        cout << "Could not send to server!\n";
                        continue;
                    }
                }
            }
            else
                cout << "\nThere was an error getting response from server\n";

        }else if(command == "help")
        {
            clearscreen();

            if(logged){
                cout << "\n- balance: returns the amount of money in your bank account";
                cout << "\n- transfer [username] [amount]: transfer from your bank account [amount] money to the indicated [username] account";
                cout << "\n- history: returns the last three transaction you have committed";
                cout << "\n- deposit [amount]: deposit [amount] money in your bank account";
                cout << "\n- logout: logs you out from this application";
                cout << "\n- exit: logs you out and close the application\n\n";
            }else{
                cout << "\n- login [username] [password]: this command is used to sign in.";
                cout << "\n- exit: logs you out and close the application\n\n";
            }
            sleep(2);

            clearscreen();
        }
        else
        {     
            if(logged)
            {
                /* If logged the command is encrypted using session key */
                RAND_poll();

                do
                {
                    /* Generating a random IV for the encryption */
                    if(RAND_bytes(message_nonce, 12) != 1)
                    {
                        cout << "Error in IV generation";
                        return 1;
                    }
                    
                    nonce = ucharToHex(message_nonce, 12);

                }while(!check_nonce(nonce_list, nonce));

                nonce_list.push_back(nonce);
                session_message = command+" "+nonce;
                plaintext = string_ref(session_message);

                gcm_ciphertext = new unsigned char[session_message.size()]();

                /* Generating a random IV for the encryption */
                if(RAND_bytes(session_iv, 12) != 1)
                {
                    cout << "Error in IV generation";
                    return 1;
                }

                /* Encrypting with aes_gcm with sessionkey */
                result_len = gcm_encrypt(plaintext, session_message.size(), session_iv, 12, session_key, session_iv, 12, gcm_ciphertext, session_tag_buf);

                gcm_command = ucharToHex(gcm_ciphertext, result_len)+" "+ucharToHex(session_iv, 12)+" "+ucharToHex(session_tag_buf, 16);
            
                delete[] gcm_ciphertext;

                /* Sending the command to the server */
                bytes_sent = send(sock, gcm_command.c_str(), gcm_command.size(), 0);
                if (bytes_sent == -1)
                {
                    cout << "Could not send to server!\n";
                    continue;
                }

                /* Wait for response */ 
                bytes_received = recv(sock, recvbuf, 4096, 0);
                if(bytes_received > 0)
                {
                    response.assign(recvbuf, bytes_received);

                    /* Decrypting using aesgcm and session key */
                    gcm_par = split(response, ' ');
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

                    server_result = toString(gcm_plaintext);
                    response_par = split(server_result, ' ');

                    if(!check_nonce(nonce_list, response_par.back()))
                    {
                        cout << "Nonce is not fresh. Replay attack detected.\n";
                        return 1;
                    }
                    else
                        nonce_list.push_back(response_par.back());

                    /* Removing nonce from server's answer */
                    server_result.erase(server_result.find(response_par.back()) - 1);

                    delete[] gcm_plaintext;
                    delete[] gcm_ciphertext;

                    if(command.substr(0, 7) == "balance" || command.substr(0, 7) == "history")
                        cout << server_result;
                    else 
                        if(server_result == "200: OK")
                        {
                            if(command.substr(0, 6) == "logout")
                            {
                                logged = false;

                                /* Free Session Key */
                                delete [] session_key;
                            }
                        }
                        else
                            cout << "Ops! Server reported this error: "+server_result;
                }
                else if ( bytes_received  == 0 )
                    cout << "\nConnection closed\n";
                else
                    cout << "\nrecv failed";
            }
            else
            {
                /* Sending the command to the server */
                bytes_sent = send(sock, command.c_str(), command.size(), 0);
                if (bytes_sent == -1)
                {
                    cout << "Could not send to server!\n";
                    continue;
                }

                /* Wait for response */ 
                bytes_received = recv(sock, recvbuf, 4096, 0);
                if(bytes_received > 0)
                {
                    response.assign(recvbuf, bytes_received);

                    cout << "Server reported: "+response;
                }
            }

            /* Reset receiving buffer */
            memset(recvbuf, 0, sizeof(recvbuf));
        }

        clearscreen();

    }while(command != "exit");

    logged = false;

    cout << "\nSee you soon!\n";

    /* shutdown the connection since no more data will be sent */
    close(sock);

    /* Deallocating dh variables */
    DH_free(dh);
    BIO_free(bio);

    /* Deallocating rsa variables */
    EVP_PKEY_free(server_pub_key);

    return 0;
}

#pragma GCC diagnostic pop