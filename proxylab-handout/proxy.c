/*
 * proxy.c - A Simple Sequential Web proxy
 *
 * Course Name: 14:332:456-Network Centric Programming
 * Assignment 2
 * Student Name: Neil M. Patel
 * 

This program implements a simple iterative web proxy. Its functionality is as follows:

1. On program execution, the proxy creates a socket (using socket()), binds that socket to a port specified by
the user as a command-line argument (using bind()), sets up the socket to listen for requests (using 
listen()), and waits for client connections (using accept()). Upon returning from accept() (i.e. getting a 
connection to a client), processing of the request begins in process_request().

2. Upon returning from accept(), the proxy first reads the request, ensures that it is well-formed (i.e.
contains a URI), and prints it to the terminal (stage 1).

3. The proxy then parses the URI from the request and fetches the client IP address, and prints these to the
terminal as well. It also logs this information using the provided format_log_entry() function to the proxy.log
logfile (stage 2).

4. The proxy then parses the domain name, port (if specified), and page (if specified) from the URI, forms an
HTTP request based on this data, creates and connects to a socket to communicate with the server, and writes
the request to this new socket. It then reads the response from the same socket and writes it to the socket
created to communicate with the client for viewing in the browser.

5. After processing this request, the client file descriptor used to communicate with the proxy is closed, and
the proxy calls accept() again to wait for the next client.

Note: Stage 3 of the assignment is implemented in the separate client.c file, which is passed a URI and prints the
HTML response from the corresponding server.

 */ 

#include "csapp.h"

#define PROGRAM_NAME "proxy"
#define LOGFILE_NAME "proxy.log"

/*
 * Function prototypes
 */
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);


void err_exit() {
    perror(PROGRAM_NAME);
    exit(2);
}

/*

Processes a request once a client connection is made. This function does the following:
-Reads the request and ensures it is valid.
-Parses the request for the URI, then parses the URI for the domain and (optionally) port and page.
-Forms a request to the server using the above data.
-Creates a new socket to talk with the server specified by the domain and writes the request to it.
-Reads the server response and writes it back to the client connection descriptor. 

*/
void process_request(int cfd, char* proxy_port, struct sockaddr_in cliaddr) {  
    
    //Read the client's request.
    char reqbuf[10000];
    bzero(reqbuf, sizeof(reqbuf));
    int reqlen = 0;
    if ( (reqlen = read(cfd, reqbuf, sizeof(reqbuf))) == -1 ) {
        err_exit();
    }
    reqbuf[reqlen] = '\0';
    printf("Stage 1: Request read is: %s\n", reqbuf);

    //Verify that the request has at least an HTTP method, URI, and HTTP protocol version.
    int req_token_counter = 0;
    char reqbufcpy[strlen(reqbuf)];
    bzero(reqbufcpy, sizeof(reqbufcpy));
    strcpy(reqbufcpy, reqbuf);

    if(strtok(reqbufcpy, " ") != NULL) {
        req_token_counter++;
    }

    while (strtok(NULL, " ") != NULL) {
        req_token_counter++;
    }

    if (req_token_counter >= 3) {

        //Parse URI and protocol version from request, and IP address from socket address structure.
        strtok(reqbuf, " ");
        char* request_uri = strtok(NULL, " ");
        char* request_protocol = strtok(NULL, " ");

        char* ip_addr = (char*) malloc(INET_ADDRSTRLEN);
        bzero(ip_addr, INET_ADDRSTRLEN);
        if ((ip_addr = inet_ntop(AF_INET, &cliaddr.sin_addr, ip_addr, INET_ADDRSTRLEN)) == NULL) {
            err_exit();
        }

        free(ip_addr);

        //Read log entry into buffer
        //Assumes entries are at most 1000 bytes (characters) long
        char entry_buf[1000];
        bzero(entry_buf, sizeof(entry_buf));
        format_log_entry(entry_buf, &cliaddr, request_uri, 0);

        printf("Now creating flock\n");

        //Create flock struct and file descriptor for locking log file
        struct flock log_file_lock;
        int log_file_fd;

        log_file_lock.l_type = F_WRLCK; //write (exclusive) lock
        log_file_lock.l_whence = SEEK_SET;  //lock the entire file
        log_file_lock.l_start = 0;
        log_file_lock.l_len = 0;
        log_file_lock.l_pid = getpid(); //set to the current process' pid

        //First create file if it doesn't exist by opening a temp file descriptor
        int temp_log_file_fd = 0;

        if ((temp_log_file_fd = open(LOGFILE_NAME, O_WRONLY | O_CREAT)) == -1) {
            err_exit();
        }

        close(temp_log_file_fd);

        //Now create file desc. for use in fcntl()
        if ((log_file_fd = open(LOGFILE_NAME, O_WRONLY)) == -1) {
            err_exit();
        }

        //Acquire the file lock
        fcntl(log_file_fd, F_SETLKW, &log_file_lock);

        //First reposition file offset to end of file.
        if (lseek(log_file_fd, 0, SEEK_END) == -1) {
            err_exit();
        }

        ssize_t log_bytes_wr = write(log_file_fd, entry_buf, strlen(entry_buf) + 1);

        if (log_bytes_wr <= 0) {
            if (log_bytes_wr == 0) {
                printf("write() call wrote 0 bytes to logfile!");
            }
            else {
                err_exit();
            }
        }

        ssize_t new_line_wr = write(log_file_fd, "\n", 1);

        if (new_line_wr <= 0) {
            if (new_line_wr == 0) {
                printf("write() call to add new line char wrote 0 bytes to logfile!");
            }
            else {
                err_exit();
            }
        }

        //Unlock the log file
        log_file_lock.l_type = F_UNLCK;

        if (fcntl(log_file_fd, F_SETLK, &log_file_lock) == -1) {
            err_exit();
        }

        close(log_file_fd);

        //Parse URL to get the domain, port (if included), and requested page.
        char* url = request_uri;

        char domain_buf[strlen(url) + 1];   //buffer to hold the parsed domain 
        char port_buf[6];   //buffer to hold parsed port, if included
        char page_buf[strlen(url) + 1]; //holds parsed page, if included
        bzero(domain_buf, strlen(url) + 1);
        bzero(port_buf, 6);
        bzero(page_buf, strlen(url) + 1);
        char* port; //holds final port after extra processing
        char* page; //holds final page after extra processing

        int index;
        int found_colon = 0;    //booleans used to track occurrences of characters
        int colon_count = 0;
        int slash_count = 0;

        //First parse the domain name by checking for "/" and ":" characters
        for (index = 0; index < strlen(url); index++) {
            if (url[index] == ':') {    //Increment counts of each special character
                colon_count++;
            }
            else if (url[index] == '/') {
                slash_count++;
            }
            if (colon_count == 2) {     //Check if delimiter limits are reached-signals end of domain name
                found_colon = 1;
                break;
            }
            else if (slash_count == 3) {
                break;
            }
            domain_buf[index] = url[index]; //store current character as part of domain
        } 

        char* domain = &domain_buf[7];  //truncate "http://" from domain

        printf("Domain: %s\n", domain);

        //Now check if port and page are specified, and parse them if so
        if (index < (strlen(url) - 1)) {
            index++;    //skip delimiter
            int offset = index;
            if (found_colon == 1) { //port specified- need to parse port
                for (index; index < strlen(url); index++) {
                    if (url[index] == '/') {
                        break;
                    }
                    port_buf[(index-offset)] = url[index];
                }
            }

            if (index < (strlen(url) - 1)) {    //page on server is specified
                index = (found_colon == 1)? index + 1: index; //skip delimiter if port was specified
                int page_offset = index;
                for (index; index < strlen(url); index++) {
                    page_buf[(index - page_offset)] = url[index];
                }
            }
        }

        //Modify port and page numbers as necessary
        page = (char*) malloc(sizeof(page_buf) + 1);
        bzero(page, sizeof(page_buf) + 1);
        strcpy(page, "/");  //all pages begin with "/"

        port = (port_buf[0] == '\0')? "80": port_buf;   //set default port if not passed
        page = (page_buf[0] == '\0')? page: strcat(page, page_buf); //set page buffer

        printf("Port: %s\n", port);
        printf("Page: %s\n\n", page);

        
        //Create socket to connect with specified server.
        int clientfd = 0;
        if((clientfd = Open_clientfd(domain, atoi(port))) < 0) {
            err_exit();
        }

        //Form the HTTP request to send to the server.
        const char* http_method = "GET ";
        char* http_version = " HTTP/1.0\r\n\r\n";

        char request[strlen(http_method) + strlen(page) + strlen(http_version)];
        strcpy(request, http_method);
        strcat(request, page);
        strcat(request, http_version);

        printf("Request to server:%s\n", request);

        //Send request to server.
        int write_resp = 0;
        if ((write_resp = write(clientfd, request, sizeof(request))) <= 0) {
            if (write_resp == 0) {
                printf("write() call wrote 0 bytes to socket!\n");
            }
            else {
                err_exit();
            }
        }

        //Read response from server.
        char resp_buf[100000];
        int offset = 0;
        int read_res = 0;
        while(offset < (sizeof(resp_buf) - 1)) {
            if((read_res = read(clientfd, &resp_buf[offset], 1)) <= 0) {
                if(read_res == 0) {
                    break;
                }
                else {
                    err_exit();
                }
            }
            offset++;
        }
        
        resp_buf[offset] = '\0';

        //printf("Server response: %s\n", resp_buf);
        //printf("Response size (bytes): %d\n", strlen(resp_buf));

        //Write response to original socket for the browser to view.
        int browser_resp = 0;

        if((browser_resp = write(cfd, resp_buf, strlen(resp_buf))) <= 0) {
            if (browser_resp == 0) {
                printf("Writing result to web browser returned 0 bytes!\n");
            }
            else {
                err_exit();
            }
        }
    }
}

/* 
 * main - Main routine for the proxy program 
   
   This function sets up the proxy server by creating and initializing a socket to listen for client requests 
   iteratively, calling process_request() to handle each connection and retreive the server response.

 */
int main(int argc, char **argv)
{

    /* Check arguments */
    if (argc != 2) {
	fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
	exit(0);
    }

    //Clear errno before serving requests
    errno = 0;

    //socket
    int s = 0;
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) //i.e. s = -1
        err_exit();
    
    //bind
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); //0 out all other fields in the struct
    servaddr.sin_family = AF_INET;  //not placed into packet- no need to check order
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // long (4 B) to network byte order
    servaddr.sin_port = htons(atoi(argv[1])); //to convert short (2 bytes) to network byte order

    if ((bind(s, (struct sockaddr *) &servaddr, sizeof(servaddr))) < 0) //nonzero (i.e. -1) means error
        err_exit();

    //listen
    if ((listen(s, 100)) < 0) //2nd param specifies max number of pending connections allowed
        err_exit();
    
    int cfd = 0;
    struct sockaddr_in clientaddr;
    int clientaddr_size = sizeof(clientaddr);
    pid_t childpid = 0;

    //Infinite loop to accept indefinite number of requests
    for(;;) {
    
        //accept
        if ((cfd = accept(s, (struct sockaddr *) &clientaddr, (socklen_t *) &clientaddr_size)) < 0) //don't care who connects to us; returns client file descriptor
            err_exit();  

        childpid = fork();

        if (childpid == -1) {   //Error (now in parent)
            err_exit();
        }

        else if (childpid == 0) { //Child process
            close(s);   //close proxy listening socket
            process_request(cfd, argv[1], clientaddr);
            //Close client socket after processing request            
            if (close(cfd) < 0) {
                err_exit();
            }
            exit(0);    
        }

        else {
            close(cfd); //Parent process- move on to next client
        }
    }

    exit(0);
}

/*
 * format_log_entry - Create a formatted log entry in logstring. 
 * 
 * The inputs are the socket address of the requesting client
 * (sockaddr), the URI from the request (uri), and the size in bytes
 * of the response from the server (size).
 */
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, 
		      char *uri, int size)
{
    time_t now;
    char time_str[MAXLINE];
    unsigned long host;
    unsigned char a, b, c, d;

    /* Get a formatted time string */
    now = time(NULL);
    strftime(time_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    /* 
     * Convert the IP address in network byte order to dotted decimal
     * form. Note that we could have used inet_ntoa, but chose not to
     * because inet_ntoa is a Class 3 thread unsafe function that
     * returns a pointer to a static variable (Ch 13, CS:APP).
     */
    host = ntohl(sockaddr->sin_addr.s_addr);
    a = host >> 24;
    b = (host >> 16) & 0xff;
    c = (host >> 8) & 0xff;
    d = host & 0xff;


    /* Return the formatted log entry string */
    sprintf(logstring, "%s: %d.%d.%d.%d %s", time_str, a, b, c, d, uri);
}


