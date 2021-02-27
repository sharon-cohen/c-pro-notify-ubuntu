#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <stdlib.h>
#include <semaphore.h>
#include <execinfo.h>

#define PORT 10000		//Netcat server port
#define BT_BUF_SIZE 1024
#define TELNET_PORT 12345
int listenOnTelnet = 1;
int listenSock;		
static void handle_events(int fd, int *wd,int htmlFd, char* path)
{
char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event;
	ssize_t len;
	char *ptr;
    	char timeBuffer[32];
    	char operationBuffer[16];
    	char nameBuffer[1024];


	/* Loop while events can be read from inotify file descriptor. */

	for (;;) {

		/* Read some events. */

		len = read(fd, buf, sizeof buf);
		if (len == -1 && errno != EAGAIN) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		if (len <= 0)
			break;

		/* Loop over all events in the buffer */

		for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) 
		{
			memset(nameBuffer, 0, 1024);
    			memset(operationBuffer, 0, 16);
			time_t timer;
    			struct tm* tm_info;

			event = (const struct inotify_event *) ptr;

			if (!(event->mask & IN_OPEN))
			{
			/* Print event time */

			memset(timeBuffer, 0, sizeof (timeBuffer));
			timer = time(NULL);
			tm_info = localtime(&timer);
 	               strftime(timeBuffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
			write(htmlFd, timeBuffer, strlen(timeBuffer));
			write(htmlFd, ": ", strlen(": "));
			
			/* Print event type */
			
			//	write(htmlFd, "FILE ACCESSED: ", strlen("FILE ACCESSED: "));
			if (event->mask & IN_CLOSE_NOWRITE)
				strcpy(operationBuffer, "READ");
			if (event->mask & IN_CLOSE_WRITE)
				strcpy(operationBuffer, "WRITE ");

			write(htmlFd, operationBuffer, strlen(operationBuffer));
			/* Print the name of the watched directory */
	
			if (*wd == event->wd) {
				strcat(nameBuffer, path);
			}
			

			/* Print the name of the file */

			if (event->len)
			{
				write(htmlFd, event->name, strlen(event->name));
				strcat(nameBuffer, event->name);
			}

			/* Print type of filesystem object */

			if(event->mask & IN_ISDIR)
				write(htmlFd, " [directory]<br>", strlen(" [directory]<br>"));
			else
				write(htmlFd, " [file]<br>", strlen(" [file]<br>"));
				
				
			
			}
	
		}

	}
				
}

void createDescriptor(int *fd, int *wdes ,char* path){
*fd = inotify_init1(IN_NONBLOCK);
	if (*fd == -1) {
		perror("inotify_init1");
		exit(EXIT_FAILURE);
	}


	/* Mark directories for events
	   - file was opened
	   - file was closed */

	*wdes = inotify_add_watch(*fd, path, IN_OPEN | IN_CLOSE);
	if (*wdes == -1) {
		fprintf(stderr, "Cannot watch '%s'\n", path);
		perror("inotify_add_watch");
		exit(EXIT_FAILURE);
	}


}

void checkValidArgc(char *path ,char *ip){
 	
 	struct sockaddr_in s = {0};
	s.sin_family = AF_INET;
	s.sin_port = htons(PORT);
	
	if(inet_pton(AF_INET, ip, &s.sin_addr.s_addr)<=0)  
   	{ 
        	perror("\nInvalid address/ Address not supported"); 
        	exit(1); 
   	} 
	DIR* dir = opendir(path);
	if (dir) {
    		/* Directory exists. */
    		printf("%s","Directory exists.\n");
    		closedir(dir);
	} 	else if (ENOENT == errno) {
    			printf("%s","Directory does not exist");
    			/* Directory does not exist. */
	} 	else {
    		printf("%s","* opendir() failed for some other reason.");
    		/* opendir() failed for some other reason. */	
}	



}

int main(int argc, char *argv[]){
   	int htmlFd;
	char buf;
	int fd, poll_num;
	int wdes;
	nfds_t nfds;
	struct pollfd fds[2];
   	int opt;	
   	char ip[21];				
	char path[50];
    if (argc != 5){
    	
    	perror("\n system expected get IP and path. The system close in 3 second"); 
    	sleep(3);
    	exit(-1);
    }
        

    while ((opt = getopt(argc, argv, "i:d:")) != -1)
       {
               
               switch (opt) 
		{
 			case 'i':
 			{
				strcpy(ip, optarg);
				printf("%s",ip);
				break;
			}	
 			case 'd':
 			{
				strcpy(path, optarg);
				break;
			}	
			default:
				printf("Bad arguments was caught\n");
				break;
 		}
 	}

	checkValidArgc(path,ip);
	htmlFd = open("/var/www/html/index.html", O_WRONLY | O_TRUNC);
	if(htmlFd == -1)
		perror("open");
	createDescriptor(&fd,&wdes,path);
	/* Prepare for polling */

	nfds = 2;

	/* Console input */

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;

	/* Inotify input */

	fds[1].fd = fd;
	fds[1].events = POLLIN;

	/* Wait for events and/or terminal input */

	write(htmlFd, "<html><head>  <meta http-equiv= 'refresh' content= '5'></head><body>", strlen("<html><head>  <meta http-equiv= 'refresh' content= '5'></head><body>"));


	printf("Listening for events.\n");
	
	while (1) {
        	
		poll_num = poll(fds, nfds, -1);
		if (poll_num == -1) {
			if (errno == EINTR)
				continue;
			perror("poll");
			exit(EXIT_FAILURE);
		}

		if (poll_num > 0) {

			if (fds[0].revents & POLLIN) {

				/* Console input is available. Empty stdin and quit */

				while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
					continue;
				break;
			}

			if (fds[1].revents & POLLIN) {

				/* Inotify events are available */

				handle_events(fd, &wdes, htmlFd,path);
			}
		}
	}

	printf("Listening for events stopped.\n");

	listenOnTelnet = 0;
	close(listenSock);
	write(htmlFd, "</body></html>", strlen("</body></html>"));
	
	/* Close inotify file descriptor */
	close(htmlFd);
	close(fd);
	exit(EXIT_SUCCESS);

	

}

    © 2021 GitHub, Inc.
    Terms
    Privacy
    Security
    Status
    Docs

    Contact
