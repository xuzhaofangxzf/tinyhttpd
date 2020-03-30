/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
 
 /*
     代码中除了用到 C 语言标准库的一些函数，也用到了一些与环境有关的函数(例如POSIX标准)
     具体可以参读《The Linux Programming Interface》，以下简称《TLPI》，页码指示均为英文版
     
     注释者： github: cbsheng
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
//#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"

void accept_request(int);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
void accept_request(int client)
{
 char buf[1024];
 int numchars;
 char method[255];
 char url[255];
 char path[512];
 size_t i, j;
 struct stat st;
 int cgi = 0;      /* becomes true if server decides this is a CGI
                    * program */
 char *query_string = NULL;

 //读http 请求的第一行数据（request line），把请求方法存进 method 中
 numchars = get_line(client, buf, sizeof(buf));
 i = 0; j = 0;
 //对于HTTP报文来说，第一行的内容即为报文的起始行，格式为<method> <request-URL> <version>，
 while (!ISspace(buf[j]) && (i < sizeof(method) - 1))
 {
  method[i] = buf[j];
  i++; j++;
 }
 method[i] = '\0';

 //如果请求的方法不是 GET 或 POST 任意一个的话就直接发送 response 告诉客户端没实现该方法
 //strcasecmp函数为忽略大小写的字符串比较函数，如果相等返回0，前面大，返回大于0，后面大，返回小于0
 if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
 {
  unimplemented(client);
  return;
 }

 //如果是 POST 方法就将 cgi 标志变量置一(true)
 if (strcasecmp(method, "POST") == 0)
  cgi = 1;

 i = 0;
 //跳过所有的空白字符(空格)
 while (ISspace(buf[j]) && (j < sizeof(buf))) 
  j++;
 
 //然后把 URL 读出来放到 url 数组中
 while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf)))
 {
  url[i] = buf[j];
  i++; j++;
 }
 url[i] = '\0';

 //如果这个请求是一个 GET 方法的话，url可能会带有?,有查询参数
 if (strcasecmp(method, "GET") == 0)
 {
  //用一个指针指向 url
  query_string = url;
  
  //去遍历这个 url，查找是否有？字符
  while ((*query_string != '?') && (*query_string != '\0'))
   query_string++;
  
  //退出循环后检查当前的字符是 ？还是字符串(url)的结尾
  if (*query_string == '?')
  {
   //如果是 ？ 的话，证明这个请求需要调用 cgi，将 cgi 标志变量置一(true)
   cgi = 1;
   //从字符 ？ 处把字符串 url 给分隔会两份
   *query_string = '\0';
   //使指针指向字符 ？后面的那个字符
   query_string++;
  }
 }

 //将前面分隔两份的前面那份字符串，拼接在字符串htdocs的后面之后就输出存储到数组 path 中。相当于现在 path 中存储着一个字符串
 sprintf(path, "htdocs%s", url);
 
 //如果 path 数组中的这个字符串的最后一个字符是以字符 / 结尾的话，就拼接上一个"index.html"的字符串。首页的意思
 if (path[strlen(path) - 1] == '/')
  strcat(path, "index.html");
 
 //在系统上去查询该文件是否存在
 /*
 struct stat {
    dev_t         st_dev;       //文件的设备编号
    ino_t         st_ino;       //节点
    mode_t        st_mode;      //文件的类型和存取的权限
    nlink_t       st_nlink;     //连到该文件的硬连接数目，刚建立的文件值为1
    uid_t         st_uid;       //用户ID
    gid_t         st_gid;       //组ID
    dev_t         st_rdev;      //(设备类型)若此文件为设备文件，则为其设备编号
    off_t         st_size;      //文件字节数(文件大小)
    unsigned long st_blksize;   //块大小(文件系统的I/O 缓冲区大小)
    unsigned long st_blocks;    //块数
    time_t        st_atime;     //最后一次访问时间
    time_t        st_mtime;     //最后一次修改时间
    time_t        st_ctime;     //最后一次改变时间(指属性)
};
  函数定义:    int stat(const char *file_name, struct stat *buf);
  函数说明:    通过文件名filename获取文件信息，并保存在buf所指的结构体stat中
  返回值:     执行成功则返回0，失败返回-1，错误代码存于errno（需要include <errno.h>）
  错误代码:
    ENOENT         参数file_name指定的文件不存在
    ENOTDIR        路径中的目录存在但却非真正的目录
    ELOOP          欲打开的文件有过多符号连接问题，上限为16符号连接
    EFAULT         参数buf为无效指针，指向无法存在的内存空间
    EACCESS        存取文件时被拒绝
    ENOMEM         核心内存不足
    ENAMETOOLONG   参数file_name的路径名称太长

    st_mode 则定义了下列数种情况
    S_IFMT   0170000    文件类型的位遮罩
    S_IFSOCK 0140000    scoket
    S_IFLNK 0120000     符号连接
    S_IFREG 0100000     一般文件
    S_IFBLK 0060000     区块装置
    S_IFDIR 0040000     目录
    S_IFCHR 0020000     字符装置
    S_IFIFO 0010000     先进先出
    S_ISUID 04000     文件的(set user-id on execution)位
    S_ISGID 02000     文件的(set group-id on execution)位
    S_ISVTX 01000     文件的sticky位
    S_IRUSR(S_IREAD) 00400     文件所有者具可读取权限
    S_IWUSR(S_IWRITE)00200     文件所有者具可写入权限
    S_IXUSR(S_IEXEC) 00100     文件所有者具可执行权限
    S_IRGRP 00040             用户组具可读取权限
    S_IWGRP 00020             用户组具可写入权限
    S_IXGRP 00010             用户组具可执行权限
    S_IROTH 00004             其他用户具可读取权限
    S_IWOTH 00002             其他用户具可写入权限
    S_IXOTH 00001             其他用户具可执行权限
    上述的文件类型在POSIX中定义了检查这些类型的宏定义：
    S_ISLNK (st_mode)    判断是否为符号连接
    S_ISREG (st_mode)    是否为一般文件
    S_ISDIR (st_mode)    是否为目录
    S_ISCHR (st_mode)    是否为字符装置文件
    S_ISBLK (s3e)        是否为先进先出
    S_ISSOCK (st_mode)   是否为socket
    若一目录具有sticky位(S_ISVTX)，则表示在此目录下的文件只能被该文件所有者、此目录所有者或root来删除或改名。

 */
 if (stat(path, &st) == -1) {
  //如果不存在，那把这次 http 的请求后续的内容(head 和 body)全部读完并忽略
  while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
   numchars = get_line(client, buf, sizeof(buf));
  //然后返回一个找不到文件的 response 给客户端
  not_found(client);
 }
 else
 {
  //文件存在，那去跟常量S_IFMT相与，相与之后的值可以用来判断该文件是什么类型的
  //S_IFMT参读《TLPI》P281，与下面的三个常量一样是包含在<sys/stat.h>
  if ((st.st_mode & S_IFMT) == S_IFDIR)  
   //如果这个文件是个目录，那就需要再在 path 后面拼接一个"/index.html"的字符串
   strcat(path, "/index.html");
   
   //S_IXUSR, S_IXGRP, S_IXOTH三者可以参读《TLPI》P295
  if ((st.st_mode & S_IXUSR) ||       
      (st.st_mode & S_IXGRP) ||
      (st.st_mode & S_IXOTH)    )
   //如果这个文件是一个可执行文件，不论是属于用户/组/其他这三者类型的，就将 cgi 标志变量置一
   cgi = 1;
   
  if (!cgi)
   //如果不需要 cgi 机制的话，
   serve_file(client, path);
  else
   //如果需要则调用
   execute_cgi(client, path, method, query_string);
 }

 close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "Content-type: text/html\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "<P>Your browser sent a bad request, ");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "such as a POST without a Content-Length.\r\n");
 send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client, FILE *resource)
{
 char buf[1024];

 //从文件文件描述符中读取指定内容
 /*
  char *fgets(char *str, int n, FILE *stream)
  从指定的流 stream 读取一行，并把它存储在 str 所指向的字符串内。当读取 (n-1) 个字符时，或者读取到换行符时，或者到达文件末尾时，它会停止，具体视情况而定
  str -- 这是指向一个字符数组的指针，该数组存储了要读取的字符串。
  n -- 这是要读取的最大字符数（包括最后的空字符）。通常是使用以 str 传递的数组长度。
  stream -- 这是指向 FILE 对象的指针，该 FILE 对象标识了要从中读取字符的流。
 */
 fgets(buf, sizeof(buf), resource);
 /*
  int feof(FILE *stream);
  功能是检测流上的文件结束符，如果文件结束，则返回非0值，否则返回0（即，文件结束：返回非0值，文件未结束，返回0值）
  feof判断文件结束是通过读取函数fread/fscanf等返回错误来识别的，故而判断文件是否结束应该是在读取函数之后进行判断。
  比如，在while循环读取一个文件时，如果是在读取函数之前进行判断，则如果文件最后一行是空白行，可能会造成内存错误。
 */
 while (!feof(resource))
 {
  send(client, buf, strlen(buf), 0);
  fgets(buf, sizeof(buf), resource);
 }
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
 //包含于<stdio.h>,基于当前的 errno 值，在标准错误上产生一条错误消息。参考《TLPI》P49
 perror(sc); 
 exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
void execute_cgi(int client, const char *path,
                 const char *method, const char *query_string)
{
 char buf[1024];
 int cgi_output[2];
 int cgi_input[2];
 pid_t pid;
 int status;
 int i;
 char c;
 int numchars = 1;
 int content_length = -1;
 
 //往 buf 中填东西以保证能进入下面的 while
 buf[0] = 'A'; buf[1] = '\0';
 //如果是 http 请求是 GET 方法的话读取并忽略请求剩下的内容
 if (strcasecmp(method, "GET") == 0)
  while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
   numchars = get_line(client, buf, sizeof(buf));
 else    /* POST */
 {
  //只有 POST 方法才继续读内容
  numchars = get_line(client, buf, sizeof(buf));
  //这个循环的目的是读出指示 body 长度大小的参数，并记录 body 的长度大小。其余的 header 里面的参数一律忽略
  while ((numchars > 0) && strcmp("\n", buf))
  {
    //循环读取头信息找到Content-Length字段的值，目的是为了截取Content-Length:
   buf[15] = '\0';
   if (strcasecmp(buf, "Content-Length:") == 0)
    content_length = atoi(&(buf[16])); //记录 body 的长度大小，Content-Length:后面还有一个空格，所以增加‘\0’不影响后面的读取
   numchars = get_line(client, buf, sizeof(buf));
  }
  
  //如果 http 请求的 header 没有指示 body 长度大小的参数，则报错返回
  if (content_length == -1) {
   bad_request(client);
   return;
  }
 }

 sprintf(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);

 //下面这里创建两个管道，用于两个进程间通信
 if (pipe(cgi_output) < 0) {
  cannot_execute(client);
  return;
 }
 if (pipe(cgi_input) < 0) {
  cannot_execute(client);
  return;
 }

 //创建一个子进程
 if ( (pid = fork()) < 0 ) {
  cannot_execute(client);
  return;
 }
 
 //子进程用来执行 cgi 脚本
 if (pid == 0)  /* child: CGI script */
 {
  char meth_env[255];
  char query_env[255];
  char length_env[255];

  //dup2()包含<unistd.h>中，参读《TLPI》P97
  //将子进程的输出由标准输出重定向到 cgi_ouput 的管道写端上
  dup2(cgi_output[1], STDOUT_FILENO);
  //将子进程的输入由标准输入重定向到 cgi_input 的管道读端上
  dup2(cgi_input[0], STDIN_FILENO);
  //关闭 cgi_ouput 管道的读端与cgi_input 管道的写端
  close(cgi_output[0]);
  close(cgi_input[1]);
  
  //构造一个环境变量
  sprintf(meth_env, "REQUEST_METHOD=%s", method);
  //putenv()包含于<stdlib.h>中，参读《TLPI》P128
  //将这个环境变量加进子进程的运行环境中
  /*
  int putenv(char *envvar);
  函数说明:
  putenv()用来改变或增加环境变量的内容。参数envvar的格式为envvar=value，如果该环境变量原先存在，则变量内容会依参数envvar改变，否则此参数内容会成为新的环境变量。
  参数envvar指定的字符串会变成环境变量的一部分，如果修改这个字符串，环境变量也会跟着被修改。
  返回值: 执行成功则返回0，有错误发生则返回-1
  */
  putenv(meth_env);
  
  //根据http 请求的不同方法，构造并存储不同的环境变量
  if (strcasecmp(method, "GET") == 0) {
   sprintf(query_env, "QUERY_STRING=%s", query_string);
   putenv(query_env);
  }
  else {   /* POST */
   sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
   putenv(length_env);
  }
  
  //execl()包含于<unistd.h>中，参读《TLPI》P567
  //最后将子进程替换成另一个进程并执行 cgi 脚本
  /*
  #include<unistd.h>
  int execl(const char *path, const char *arg, ...);
  execl()用来执行参数path字符串所代表的文件路径，接下来的参数代表执行该文件时传递过去的argv(0)、argv[1]……，最后一个参数必须用空指针(NULL)作结束。
  如果执行成功则函数不会返回，执行失败则直接返回-1，失败原因存于errno中。
  */
  execl(path, path, NULL);
  exit(0);
  
 } else {    /* parent */
  //父进程则关闭了 cgi_output管道的写端和 cgi_input 管道的读端
  /*
    综上，父进程以cgi_input写入，子进程从cgi_input读取
    父进程以cgi_output读取，子进程从cgi_output写入
  */
  close(cgi_output[1]);
  close(cgi_input[0]);
  
  //如果是 POST 方法的话就继续读 body 的内容，并写到 cgi_input 管道里让子进程去读
  if (strcasecmp(method, "POST") == 0)
   for (i = 0; i < content_length; i++) {
    recv(client, &c, 1, 0);
    write(cgi_input[1], &c, STDOUT_FILENO);
   }
   
  //然后从 cgi_output 管道中读子进程的输出，并发送到客户端去
  while (read(cgi_output[0], &c, 1) > 0)
   send(client, &c, 1, 0);

  //关闭管道
  close(cgi_output[0]);
  close(cgi_input[1]);
  //等待子进程的退出
  waitpid(pid, &status, 0);
 }
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
 int i = 0;
 char c = '\0';
 int n;

 while ((i < size - 1) && (c != '\n'))
 {
  //recv()包含于<sys/socket.h>,参读《TLPI》P1259, 
  //读一个字节的数据存放在 c 中
  n = recv(sock, &c, 1, 0);
  /* DEBUG printf("%02X\n", c); */
  if (n > 0)
  {
   if (c == '\r')
   {
    /*
      ssize_t recv(int s, void *buf, size_t len, int flags);
      通常flags都设置为0，此时recv函数读取tcp buffer中的数据到buf中，并从tcp buffer中移除已读取的数据。
      把flags设置为MSG_PEEK，仅把tcp buffer中的数据读取到buf中，并不把已读取的数据从tcp buffer中移除，再次调用recv仍然可以读到刚才读到的数据。
    */
    n = recv(sock, &c, 1, MSG_PEEK);
    /* DEBUG printf("%02X\n", c); */
    if ((n > 0) && (c == '\n'))
     recv(sock, &c, 1, 0);
    else
     c = '\n';
   }
   buf[i] = c;
   i++;
  }
  else
   c = '\n';
 }
 buf[i] = '\0';

 return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
 char buf[1024];
 (void)filename;  /* could use filename to determine file type */

 strcpy(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);
 strcpy(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 strcpy(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "your request because the resource specified\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "is unavailable or nonexistent.\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</BODY></HTML>\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
 FILE *resource = NULL;
 int numchars = 1;
 char buf[1024];

 //确保 buf 里面有东西，能进入下面的 while 循环
 buf[0] = 'A'; buf[1] = '\0';
 //循环作用是读取并忽略掉这个 http 请求后面的所有内容
 while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
  numchars = get_line(client, buf, sizeof(buf));

 //打开这个传进来的这个路径所指的文件
 resource = fopen(filename, "r");
 if (resource == NULL)
  not_found(client);
 else
 {
  //打开成功后，将这个文件的基本信息封装成 response 的头部(header)并返回
  headers(client, filename);
  //接着把这个文件的内容读出来作为 response 的 body 发送到客户端
  cat(client, resource);
 }
 
 fclose(resource);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
int startup(u_short *port)
{
 int httpd = 0;
 //sockaddr_in 是 IPV4的套接字地址结构。定义在<netinet/in.h>,参读《TLPI》P1202
 struct sockaddr_in name;
 
 //socket()用于创建一个用于 socket 的描述符，函数包含于<sys/socket.h>。参读《TLPI》P1153
 //这里的PF_INET其实是与 AF_INET同义，具体可以参读《TLPI》P946
 httpd = socket(PF_INET, SOCK_STREAM, 0);
 if (httpd == -1)
  error_die("socket");
  
 memset(&name, 0, sizeof(name));
 name.sin_family = AF_INET;
 //htons()，ntohs() 和 htonl()包含于<arpa/inet.h>, 参读《TLPI》P1199
 //将*port 转换成以网络字节序表示的16位整数
 name.sin_port = htons(*port);
 //INADDR_ANY是一个 IPV4通配地址的常量，包含于<netinet/in.h>
 //大多实现都将其定义成了0.0.0.0 参读《TLPI》P1187
 name.sin_addr.s_addr = htonl(INADDR_ANY);
 
 //bind()用于绑定地址与 socket。参读《TLPI》P1153
 //如果传进去的sockaddr结构中的 sin_port 指定为0，这时系统会选择一个临时的端口号
 if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
  error_die("bind");
  
 //如果调用 bind 后端口号仍然是0，则手动调用getsockname()获取端口号
 if (*port == 0)  /* if dynamically allocating a port */
 {
  int namelen = sizeof(name);
  //getsockname()包含于<sys/socker.h>中，参读《TLPI》P1263
  //调用getsockname()获取系统给 httpd 这个 socket 随机分配的端口号
  if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
   error_die("getsockname");
  *port = ntohs(name.sin_port);
 }
 
 //最初的 BSD socket 实现中，backlog 的上限是5.参读《TLPI》P1156
 if (listen(httpd, 5) < 0) 
  error_die("listen");
 return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</TITLE></HEAD>\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</BODY></HTML>\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

int main(void)
{
 int server_sock = -1;
 u_short port = 0;
 int client_sock = -1;
 //sockaddr_in 是 IPV4的套接字地址结构。定义在<netinet/in.h>,参读《TLPI》P1202
 struct sockaddr_in client_name;
 int client_name_len = sizeof(client_name);
 pthread_t newthread;

 server_sock = startup(&port);
 printf("httpd running on port %d\n", port);

 while (1)
 {
  //阻塞等待客户端的连接，参读《TLPI》P1157
  client_sock = accept(server_sock,
                       (struct sockaddr *)&client_name,
                       &client_name_len);
  if (client_sock == -1)
   error_die("accept");
  //accept_request(client_sock);
 if (pthread_create(&newthread , NULL, accept_request, client_sock) != 0)
   perror("pthread_create");
 }

 close(server_sock);

 return(0);
}
