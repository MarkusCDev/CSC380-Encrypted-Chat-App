#include <curses.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <getopt.h>
#include <string>
#include <openssl/rand.h>
using std::string;
#include <deque>
using std::deque;
#include <pthread.h>
#include <utility>
using std::pair;
#include "dh.h"
#include <random>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <ctime>


// Public, Secret key
mpz_t A_pk;
mpz_t B_pk;
mpz_t A_sk;
// DHF
char hmac_key[256+1];
unsigned char aes_key[256+1];
// IV for AES generated via SYN request
unsigned char iv_val[16+1];



static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */
static pthread_t tcurses;   /* setup curses and draw messages from queue */
void* cursesthread(void*);  /* for tcurses */
/* tcurses will get a queue full of these and redraw the appropriate windows */
struct redraw_data {
	bool resize;
	string msg;
	string sender;
	WINDOW* win;
};
static deque<redraw_data> mq; /* messages and resizes yet to be drawn */
/* manage access to message queue: */
static pthread_mutex_t qmx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcv = PTHREAD_COND_INITIALIZER;

/* XXX different colors for different senders */

// generate iv from SYN request 
unsigned char* ivgen(unsigned long input) {
    std::mt19937_64 rng(input); //mersenne twister random gen
    std::uniform_int_distribution<int> dist(0, 35); 
    unsigned char* randomChar = new unsigned char[17];

    for (int i = 0; i < 16; i++) {
        int randomNum = dist(rng);
        if (randomNum < 10) {
            randomChar[i] = '0' + randomNum;
        } else {
            randomChar[i] = 'a' + randomNum - 10; 
        }
    }

    return randomChar;
}


/* record chat history as deque of strings: */
static deque<string> transcript;

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

int listensock, sockfd;

[[noreturn]] static void fail_exit(const char *msg);

[[noreturn]] static void error(const char *msg)
{
	perror(msg);
	fail_exit("");
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    /* NOTE: might not need the above if you make sure the client closes first */
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n",port);
    listen(listensock,1);
    socklen_t clilen;
    struct sockaddr_in  cli_addr;
    sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    /* at this point, should be able to send/recv on sockfd */

	/* ----------Handshake setup----------- */

	//----- Sending SYN+1,ACK -----

		/* Server sends SYN+1, ACK back to Client when SYN is recieved*/
		char bufferSYN[11];
		recv(sockfd, bufferSYN, 10, 0);
		int bufferSYNp1 = atoi(bufferSYN) + 1;
		string bufferSYNp1_str = std::to_string(bufferSYNp1) + "ACK";
		const char *bufferSYNp1_char = bufferSYNp1_str.c_str();

		/* Generate the same iv from ISN seed passed over*/
		int bufferSYNiv = atoi(bufferSYN);
		unsigned char* iv_temp = ivgen(bufferSYNiv);
		memcpy(iv_val, iv_temp, 16);

		// SYN recived should be within 32bit unsigned range
		if (bufferSYNp1 >= 0 && bufferSYNp1 <= 4294967295)  {
			// send(sockfd, bufferSYN, 11, 0);
			send(sockfd, bufferSYNp1_char, bufferSYNp1_str.length(), 0);
		} else {
			error("Server failed to recieve SYN from client");
		}

		char buff[10];
		recv(sockfd, buff, 10, 0);

	/* ----------DiffieHellman Setup----------- */

		//generate private & public keys
		init("params");
		NEWZ(a);
		NEWZ(A);
		dhGen(a, A);

		//send public key
		char S[1024];	
		mpz_get_str(S, 16, A);
		send(sockfd, S, 1024, 0);

		mpz_set(A_pk, A);
		mpz_set(A_sk, a);

		//reieve incoming user's public key
		char buf[1024];
		recv(sockfd, buf, 1024, 0);
		mpz_set_str(B_pk, buf, 16);
			
		//shared key is calcualted 
		const size_t klen = 256;
		unsigned char kA[klen];
		dhFinal(A_sk, A_pk, B_pk, kA, klen);
		char dhf[512+1];
		for(size_t i=0; i < 256; i++) {
			sprintf(&dhf[i*2], "%02x", kA[i]);
		}

		//split 512 DHF for two 256 keys (AES & HMAC)
		memcpy(hmac_key, dhf, 256);
		memcpy(aes_key, dhf + 256, 256);


    return 0;
}


static int initClientNet(char* hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    /* at this point, should be able to send/recv on sockfd */

	/* ----------Handshake setup----------- */

	// ----- Sending SYN -----

		/* ISN Generation - 32 bit unsigned max*/
		srand(time(0));
		unsigned long ISN = rand() % 4294967294 + 0;


		/* ISN is used as seed to generate IV for AES*/
		unsigned char* iv_temp = ivgen(ISN);
		memcpy(iv_val, iv_temp, 16);

		/* Foramted Initial Sequence Number for sending */
		string ISN_str = std::to_string(ISN);
		char const *ISN_char = ISN_str.c_str();

		//memcpy(checking, ISN_char, ISN_str.length());

		/* Client sends ISN as SYN request*/
		send(sockfd, ISN_char, ISN_str.length(), 0);

	// ----- Sending ACK -----

		/* Client sends ACK when SYN+1, ACK is recieved back */
		char bufferACK[14]; // size char to recieve the SYN+1, ACK from the server
		recv(sockfd, bufferACK, 14, 0);
		string bfA_str(bufferACK);

		
		size_t index = bfA_str.find("ACK");
		while (index != std::string::npos) {
			bfA_str.erase(index,3); // removes "ACK" from string
			index = bfA_str.find("ACK", index);
		}

		unsigned long bufferACK_int = stoi(bfA_str) - 1; //convert str to int
		
		if(bufferACK_int == ISN) {
			send(sockfd, "ACK", 3, 0);
		} else {
			error("Client failed to recieve SYN+1 ACK from server");
		}

	/* ----------DiffieHellman Setup----------- */

		//generate private & public keys
		init("params");
		NEWZ(a);
		NEWZ(A);
		dhGen(a, A);

		//recieve incoming user's public key
		char buf[1024];
		recv(sockfd, buf, 1024, 0);

		mpz_set(A_pk, A);
		mpz_set(A_sk, a);
		mpz_set_str(B_pk, buf, 16);

		//send public key
		char S[1024];
		mpz_get_str(S, 16, A);
		send(sockfd, S, 1024, 0);

		//shared key is calcualted
		const size_t klen = 256;
		unsigned char kA[klen];
		dhFinal(A_sk, A_pk, B_pk, kA, klen);
		char dhf[512+1];
		for(size_t i=0; i < 256; i++) {
			sprintf(&dhf[i*2], "%02x", kA[i]);
		}

		//split 512 DHF for two 256 key (AES & HMAC)
		memcpy(hmac_key, dhf, 256);
		memcpy(aes_key, dhf + 256, 256);

    return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


[[noreturn]] static void fail_exit(const char *msg)
{
	// Make sure endwin() is only called in visual mode. As a note, calling it
	// twice does not seem to be supported and messed with the cursor position.
	if (!isendwin())
		endwin();
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

// Checks errors for (most) ncurses functions. CHECK(fn, x, y, z) is a checked
// version of fn(x, y, z).
#define CHECK(fn, ...) \
	do \
	if (fn(__VA_ARGS__) == ERR) \
	fail_exit(#fn"("#__VA_ARGS__") failed"); \
	while (false)

static bool should_exit = false;

// Message window
static WINDOW *msg_win;
// Separator line above the command (readline) window
static WINDOW *sep_win;
// Command (readline) window
static WINDOW *cmd_win;

// Input character for readline
static unsigned char input;

static int readline_getc(FILE *dummy)
{
	return input;
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void msg_win_redisplay(bool batch, const string& newmsg="", const string& sender="")
{
	if (batch)
		wnoutrefresh(msg_win);
	else {
		wattron(msg_win,COLOR_PAIR(2));
		wprintw(msg_win,"%s:",sender.c_str());
		wattroff(msg_win,COLOR_PAIR(2));
		wprintw(msg_win," %s\n",newmsg.c_str());
		wrefresh(msg_win);
	}
}

char* hmac(char* msg)
{	
	char hmackey[256+1];
	strcpy(hmackey, hmac_key);
	unsigned char mac[64]; 
	memset(mac,0,64);
	char* message = msg;
	HMAC(EVP_sha512(),hmackey,strlen(hmackey),(unsigned char*)message,
			strlen(message),mac,0);
	char* temp = (char*) malloc(129);

	for (size_t i = 0; i < 64; i++) {
		sprintf(&temp[i*2],"%02x",mac[i]);
	}
	return strdup(temp);
}

unsigned char* ctr_encrypt(char* message, unsigned char* key, unsigned char* iv){
    unsigned char* ct = (unsigned char*) malloc(512);
    memset(ct, 0, 512);
    size_t len = strlen(message);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, key, iv))
        ERR_print_errors_fp(stderr);
    int nWritten;
    if (1 != EVP_EncryptUpdate(ctx, ct, &nWritten, (unsigned char*) message, len))
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);

    return ct;
}

unsigned char* ctr_decrypt(unsigned char* ct, unsigned char* key, unsigned char* iv, size_t length){
	
	unsigned char* pt = (unsigned char*) malloc(512);
	memset(pt, 0, 512);
	size_t ctlen = length;


	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctlen))
		ERR_print_errors_fp(stderr);
	
	
	return pt;
}



static void msg_typed(char *line)
{
	string mymsg;
	unsigned char* cipher;
	if (!line) {
		// Ctrl-D pressed on empty line
		should_exit = true;
		/* XXX send a "goodbye" message so other end doesn't
		 * have to wait for timeout on recv()? */
	} else {
		if (*line) {
			add_history(line);
			mymsg = string(line);
			transcript.push_back("me: " + mymsg);
			ssize_t nbytes;
			
			char* hmac_str = hmac(line);
			char* buf = (char*)malloc(strlen(hmac_str) + strlen(line) + 1);
			strcpy(buf, hmac_str);
			strcat(buf, line);

			int bufsize = strlen(buf);

			cipher = ctr_encrypt(buf, aes_key, iv_val);

			if ((nbytes = send(sockfd,cipher, bufsize, 0)) == -1)
				error("send failed");
		}
		pthread_mutex_lock(&qmx);
		mq.push_back({false,mymsg,"me",msg_win});
		pthread_cond_signal(&qcv);
		pthread_mutex_unlock(&qmx);
	}
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void cmd_win_redisplay(bool batch)
{
	int prompt_width = strnlen(rl_display_prompt, 128);
	int cursor_col = prompt_width + strnlen(rl_line_buffer,rl_point);

	werase(cmd_win);
	mvwprintw(cmd_win, 0, 0, "%s%s", rl_display_prompt, rl_line_buffer);
	/* XXX deal with a longer message than the terminal window can show */
	if (cursor_col >= COLS) {
		// Hide the cursor if it lies outside the window. Otherwise it'll
		// appear on the very right.
		curs_set(0);
	} else {
		wmove(cmd_win,0,cursor_col);
		curs_set(1);
	}
	if (batch)
		wnoutrefresh(cmd_win);
	else
		wrefresh(cmd_win);
}

static void readline_redisplay(void)
{
	pthread_mutex_lock(&qmx);
	mq.push_back({false,"","",cmd_win});
	pthread_cond_signal(&qcv);
	pthread_mutex_unlock(&qmx);
}

static void resize(void)
{
	if (LINES >= 3) {
		wresize(msg_win,LINES-2,COLS);
		wresize(sep_win,1,COLS);
		wresize(cmd_win,1,COLS);
		/* now move bottom two to last lines: */
		mvwin(sep_win,LINES-2,0);
		mvwin(cmd_win,LINES-1,0);
	}

	/* Batch refreshes and commit them with doupdate() */
	msg_win_redisplay(true);
	wnoutrefresh(sep_win);
	cmd_win_redisplay(true);
	doupdate();
}

static void init_ncurses(void)
{
	if (!initscr())
		fail_exit("Failed to initialize ncurses");

	if (has_colors()) {
		CHECK(start_color);
		CHECK(use_default_colors);
	}
	CHECK(cbreak);
	CHECK(noecho);
	CHECK(nonl);
	CHECK(intrflush, NULL, FALSE);

	curs_set(1);

	if (LINES >= 3) {
		msg_win = newwin(LINES - 2, COLS, 0, 0);
		sep_win = newwin(1, COLS, LINES - 2, 0);
		cmd_win = newwin(1, COLS, LINES - 1, 0);
	} else {
		// Degenerate case. Give the windows the minimum workable size to
		// prevent errors from e.g. wmove().
		msg_win = newwin(1, COLS, 0, 0);
		sep_win = newwin(1, COLS, 0, 0);
		cmd_win = newwin(1, COLS, 0, 0);
	}
	if (!msg_win || !sep_win || !cmd_win)
		fail_exit("Failed to allocate windows");

	scrollok(msg_win,true);

	if (has_colors()) {
		// Use white-on-blue cells for the separator window...
		CHECK(init_pair, 1, COLOR_WHITE, COLOR_BLUE);
		CHECK(wbkgd, sep_win, COLOR_PAIR(1));
		/* NOTE: -1 is the default background color, which for me does
		 * not appear to be any of the normal colors curses defines. */
		CHECK(init_pair, 2, COLOR_MAGENTA, -1);
	}
	else {
		wbkgd(sep_win,A_STANDOUT); /* c.f. man curs_attr */
	}
	wrefresh(sep_win);
}

static void deinit_ncurses(void)
{
	delwin(msg_win);
	delwin(sep_win);
	delwin(cmd_win);
	endwin();
}

static void init_readline(void)
{
	// Let ncurses do all terminal and signal handling
	rl_catch_signals = 0;
	rl_catch_sigwinch = 0;
	rl_deprep_term_function = NULL;
	rl_prep_term_function = NULL;

	// Prevent readline from setting the LINES and COLUMNS environment
	// variables, which override dynamic size adjustments in ncurses. When
	// using the alternate readline interface (as we do here), LINES and
	// COLUMNS are not updated if the terminal is resized between two calls to
	// rl_callback_read_char() (which is almost always the case).
	rl_change_environment = 0;

	// Handle input by manually feeding characters to readline
	rl_getc_function = readline_getc;
	rl_redisplay_function = readline_redisplay;

	rl_callback_handler_install("> ", msg_typed);
}

static void deinit_readline(void)
{
	rl_callback_handler_remove();
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat for CSc380.\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

int main(int argc, char *argv[])
{
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;
	bool isclient = true;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = false;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* NOTE: these don't work if called from cursesthread */
	init_ncurses();
	init_readline();
	/* start curses thread */
	if (pthread_create(&tcurses,0,cursesthread,0)) {
		fprintf(stderr, "Failed to create curses thread.\n");
	}
	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	/* put this in the queue to signal need for resize: */
	redraw_data rd = {false,"","",NULL};
	do {
		int c = wgetch(cmd_win);
		switch (c) {
			case KEY_RESIZE:
				pthread_mutex_lock(&qmx);
				mq.push_back(rd);
				pthread_cond_signal(&qcv);
				pthread_mutex_unlock(&qmx);
				break;
				// Ctrl-L -- redraw screen
			// case '\f':
			// 	// Makes the next refresh repaint the screen from scratch
			// 	/* XXX this needs to be done in the curses thread as well. */
			// 	clearok(curscr,true);
			// 	resize();
			// 	break;
			default:
				input = c;
				rl_callback_read_char();
		}
	} while (!should_exit);

	shutdownNetwork();
	deinit_ncurses();
	deinit_readline();
	return 0;
}

/* Let's have one thread responsible for all things curses.  It should
 * 1. Initialize the library
 * 2. Wait for messages (we'll need a mutex-protected queue)
 * 3. Restore terminal / end curses mode? */

/* We'll need yet another thread to listen for incoming messages and
 * post them to the queue. */

void* cursesthread(void* pData)
{
	/* NOTE: these calls only worked from the main thread... */
	// init_ncurses();
	// init_readline();
	while (true) {
		pthread_mutex_lock(&qmx);
		while (mq.empty()) {
			pthread_cond_wait(&qcv,&qmx);
			/* NOTE: pthread_cond_wait will release the mutex and block, then
			 * reaquire it before returning.  Given that only one thread (this
			 * one) consumes elements of the queue, we probably don't have to
			 * check in a loop like this, but in general this is the recommended
			 * way to do it.  See the man page for details. */
		}
		/* at this point, we have control of the queue, which is not empty,
		 * so write all the messages and then let go of the mutex. */
		while (!mq.empty()) {
			redraw_data m = mq.front();
			mq.pop_front();
			if (m.win == cmd_win) {
				cmd_win_redisplay(m.resize);
			} else if (m.resize) {
				resize();
			} else {
				msg_win_redisplay(false,m.msg,m.sender);
				/* Redraw input window to "focus" it (otherwise the cursor
				 * will appear in the transcript which is confusing). */
				cmd_win_redisplay(false);
			}
		}
		pthread_mutex_unlock(&qmx);
	}
	return 0;
}

void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+1];
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		msg[nbytes] = 0; /* make sure it is null-terminated */
		if (nbytes == 0) {
			/* signal to the main loop that we should quit: */
			should_exit = true;
			return 0;
		}
		
		unsigned char* plaintxt = ctr_decrypt((unsigned char*)msg, aes_key, iv_val, nbytes);

		size_t msg_size = strlen((char*)plaintxt) - 128;

		char B_hmac_str[129];
		char message[msg_size+1];
		strncpy(B_hmac_str, (char*)plaintxt, 128);
		B_hmac_str[128] = '\0';
		strncpy(message, (char*)plaintxt + 128, msg_size);
		message[msg_size] = '\0';

		char* A_hmac_str = hmac(message);
		
		if(strcmp(A_hmac_str, B_hmac_str) == 0) {
			pthread_mutex_lock(&qmx);
			mq.push_back({false, message,"Incoming",msg_win});
			pthread_cond_signal(&qcv);
			pthread_mutex_unlock(&qmx);
			} 
		else {
			pthread_mutex_lock(&qmx);
			mq.push_back({false,"HMAC does not match!!","System",msg_win});
			pthread_cond_signal(&qcv);
			pthread_mutex_unlock(&qmx);
			}

	}
	return 0;
}

