
//submitters:
// Sharon Cohen : 208463463
// Dana Daniella Aloni 207907742
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <libcli.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT 10000 // Netcat server port
#define BT_BUF_SIZE 1024
#define TELNET_PORT 12345
int listenOnTelnet = 1;
struct cli_def *cli;
int listenSock;
sem_t semaphore;
int listenSock;
int flagBack = 0;
char ip[21];
char telnetBuffer[1024];

struct infoNotify {
  char time[32];
  char name[2048];
  char typeAcsses[28];
  char memberBuff[2048];
  void (*fun)(struct infoNotify *info);
};
void memberToBuff(struct infoNotify *info) {
  strcpy(info->memberBuff, "\nTHE SYSTEM DETECTED A HACK");
  strcat(info->memberBuff, "\nFILE/FOLDER ACCESSED: ");
  strcat(info->memberBuff, info->name);
  strcat(info->memberBuff, "\nACCESS: ");
  strcat(info->memberBuff, info->typeAcsses);
  strcat(info->memberBuff, "\nTIME OF ACCESS: ");
  strcat(info->memberBuff, info->time);
  strcat(info->memberBuff, "\n");
  strcat(info->memberBuff, "\0");
}

void *backTrace() {
  int j = 0, nptrs = 0;
  void *buffer[BT_BUF_SIZE];
  char **strings;

  memset(telnetBuffer, 0, sizeof(telnetBuffer));
  memset(buffer, 0, sizeof(buffer));

  nptrs = backtrace(buffer, BT_BUF_SIZE);
  printf("backtrace() returned %d addresses\n", nptrs);

  /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
  would produce similar output to the following: */

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }
  for (j = 0; j < nptrs; j++)
    cli_print(cli, "%s\n", strings[j]);

  free(strings);
}

/*
 *	Functions: Instrumentations
 *	Description: Profiling our program with backtracing implementation via
 *cyg_enter.
 *
 */

void __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *this_fn, void *call_site) {
  if (flagBack) {
    flagBack = 0;
    backTrace();
    sem_post(&semaphore);
  }
}

int cmd_backtrace(struct cli_def *cli, char *command, char *argv[], int argc) {
  flagBack = 1;
  sem_wait(&semaphore);

  return CLI_OK;
}

/*
 *	Function: telnetBackTrace()
 *	Description: libcli implementation for telnet client connection.
 *
 */

void *telnetBackTrace() {
  struct sockaddr_in servaddr;
  struct cli_command *c;

  int on = 1, x; // vars for socket handling.

  cli = cli_init();
  cli_set_hostname(cli, "Notify");
  cli_set_banner(cli, "Welcome to the CLI test program.");
  cli_register_command(cli, NULL, "backtrace", cmd_backtrace,
                       PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);

  // Create a socket
  listenSock = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  // Listen on port 12345
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(TELNET_PORT);
  bind(listenSock, (struct sockaddr *)&servaddr, sizeof(servaddr));

  // Wait for a connection
  listen(listenSock, 50);

  while (listenOnTelnet && (x = accept(listenSock, NULL, 0))) {
    // Pass the connection off to libcli
    cli_loop(cli, x);
    close(x);
  }

  // Free data structures
  cli_done(cli);
  pthread_exit(0);
}

/*
 *	Function: sendToUDP()
 *	Description: When theres a notify event, sends a message to the netcat
 *server connection.
 *
 */

void *sendToUDP(void *infoStruct) {
  struct infoNotify *info = (struct infoNotify *)infoStruct;
  int sock, nsent;

  memset(info->memberBuff, 0, sizeof(info->memberBuff));

  struct sockaddr_in s = {0};
  s.sin_family = AF_INET;
  s.sin_port = htons(PORT);

  if (inet_pton(AF_INET, ip, &s.sin_addr.s_addr) <= 0) {
    perror("\nInvalid address/ Address not supported");
    exit(1);
  }

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (connect(sock, (struct sockaddr *)&s, sizeof(s)) < 0) {
    perror("connect");
    exit(1);
  }
  info->fun(info);
  printf("%s", info->memberBuff);
  if ((nsent = send(sock, info->memberBuff, strlen(info->memberBuff), 0)) < 0) {
    perror("not send -error");
    exit(1);
  }

  close(sock);
  pthread_exit(0);
}

static void handle_events(int fd, int *wd, int htmlFd, char *path) {
  char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
  const struct inotify_event *event;
  ssize_t len;
  char *ptr;
  char timeBuffer[32];
  char operationBuffer[16];
  char nameBuffer[1024];
  struct infoNotify info;
  info.fun = memberToBuff;
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

    for (ptr = buf; ptr < buf + len;
         ptr += sizeof(struct inotify_event) + event->len) {
      memset(info.name, 0, 2048);
      memset(info.typeAcsses, 0, 28);
      time_t timer;
      struct tm *tm_info;

      event = (const struct inotify_event *)ptr;

      if (!(event->mask & IN_OPEN)) {
        /* Print event time */

        memset(info.time, 0, sizeof(timeBuffer));
        timer = time(NULL);
        tm_info = localtime(&timer);
        strftime(info.time, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        write(htmlFd, info.time, strlen(timeBuffer));
        write(htmlFd, ": ", strlen(": "));

        /* Print event type */

        write(htmlFd, "FILE ACCESSED: ", strlen("FILE ACCESSED: "));
        if (event->mask & IN_CLOSE_NOWRITE)
          strcpy(info.typeAcsses, "READ");
        if (event->mask & IN_CLOSE_WRITE)
          strcpy(info.typeAcsses, "WRITE ");

        write(htmlFd, info.typeAcsses, strlen(info.typeAcsses));
        /* Print the name of the watched directory */

        if (*wd == event->wd) {
          strcat(info.name, path);
        }

        /* Print the name of the file */

        if (event->len) {
          write(htmlFd, event->name, strlen(event->name));
          strcat(info.name, event->name);
        }

        /* Print type of filesystem object */

        if (event->mask & IN_ISDIR)
          write(htmlFd, " [directory]<br>", strlen(" [directory]<br>"));
        else
          write(htmlFd, " [file]<br>", strlen(" [file]<br>"));

        int bt_thread;
        pthread_t tid;

        if (pthread_create(&tid, NULL, sendToUDP, &info) != 0)
          perror("Failed to create thread");
      }
    }
  }
}

void createDescriptor(int *fd, int *wdes, char *path) {
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

void checkValidArgc(char *path, char *ip) {

  struct sockaddr_in s = {0};
  s.sin_family = AF_INET;
  s.sin_port = htons(PORT);

  if (inet_pton(AF_INET, ip, &s.sin_addr.s_addr) <= 0) {
    perror("\nInvalid address/ Address not supported");
    exit(1);
  }
  DIR *dir = opendir(path);
  if (dir) {
    /* Directory exists. */
    printf("%s", "Directory exists.\n");
    closedir(dir);
  } else if (ENOENT == errno) {
    printf("%s", "Directory does not exist");
    /* Directory does not exist. */
  } else {
    printf("%s", "* opendir() failed for some other reason.");
    /* opendir() failed for some other reason. */
  }
}

int main(int argc, char *argv[]) {
  int htmlFd;
  char buf;
  int fd, poll_num;
  int wdes;
  nfds_t nfds;
  struct pollfd fds[2];
  int opt;

  char path[50];
  if (argc != 5) {

    perror("\n system expected get IP and path. The system close in 3 second");
    sleep(3);
    exit(0);
  }

  int bt_thread;
  pthread_t tid1;

  if (pthread_create(&tid1, NULL, telnetBackTrace, &bt_thread) != 0)
    perror("Failed to create thread");
  while ((opt = getopt(argc, argv, "i:d:")) != -1) {

    switch (opt) {
    case 'i': {
      strcpy(ip, optarg);
      printf("%s", ip);
      break;
    }
    case 'd': {
      strcpy(path, optarg);
      break;
    }
    default:
      printf("Bad arguments was caught\n");
      break;
    }
  }

  checkValidArgc(path, ip);
  htmlFd = open("/var/www/html/index.html", O_WRONLY | O_TRUNC);
  if (htmlFd == -1)
    perror("open");
  createDescriptor(&fd, &wdes, path);
  /* Prepare for polling */

  nfds = 2;

  /* Console input */

  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;

  /* Inotify input */

  fds[1].fd = fd;
  fds[1].events = POLLIN;

  /* Wait for events and/or terminal input */

  write(htmlFd,
        "<html><head>  <meta http-equiv= 'refresh' content= '5'></head><body>",
        strlen("<html><head>  <meta http-equiv= 'refresh' content= "
               "'5'></head><body>"));

  printf("Listening for events.\n");

  while (1) {

    printf("%s", "sharon");
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

        handle_events(fd, &wdes, htmlFd, path);
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
