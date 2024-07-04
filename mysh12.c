#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <libgen.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <limits.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#define MAX_NAME_SZ 1024
#define MAX_TOKENS 1024
#define BUFFER_SIZE 4096
#define MAX_LINE_LENGTH 1024
#define MAX_PROCESSES 1024
#define HISTORY_FILE ".bash_history"


int parse(int in, int ot, char *input, char *output);
void pipes(char *tokens[], int background);

char *tokens[MAX_TOKENS]; // to je tabela stringov
int marker;               // dal je interaktivno ili ne
char prompt[50];          // ime onog ko pise (mysh>)
int level = 0;            // na kome levelu je debug
int num_tokens;
char izpis[100]; // ono sto se ispisuje kad unesem komandu
int status = 0;  // nastavljen status
bool what = false;
char pot[900] = "/proc";
int background = 0; // dal se izvaja u ozadju

int tokenize(char *line)
{
  int token_count = 0;
  char *word;
  if (*line == ' ')
  {
    do
    {
      *line = '\0';
      line++;
    } while (*line == ' ');
  }
  if (*line == '#')
  {
    do
    {
      *line = '\0';
      line++;
    } while (*line != '\0');
  }
  word = line;
  while (*line != '\0')
  {

    if (*line == ' ')
    {
      do
      {
        *line = '\0';
        line++;
      } while (*line == ' ');
      if (*line == '#')
      {
        do
        {
          *line = '\0';
          line++;
        } while (*line != '\0');
      }
      else
      {
        tokens[token_count++] = word;
        // printf("DODALI ako nije nista %s\n", word);
        word = line;
      }
    }

    if (*line == '"')
    {
      // printf("Usao sam u navodnike\n");
      //*line = '\0';
      line++;
      word = line;
      // printf("sta vidim kad udjem %s\n",line);

      do
      {
        line++;
      } while (*line != '"');
      *line = '\0';
      line++;
      // printf("sta vidim kad izadjem %s %s\n",line,word);

      tokens[token_count++] = word;
      // printf("DODALI u navodnicima %s\n", word);
      word = line;
      // printf("Nova vrednost word %s\n", word);

      if (*line == ' ')
      {
        do
        {
          // printf("ima razmak\n");
          *line = '\0';
          line++;
        } while (*line == ' ');
      }
      if (*line == '#')
      {
        do
        {
          *line = '\0';
          line++;
        } while (*line != '\0');
      }
      word = line--;
      // printf("nova vrednost word %s je\n", word);
    }
    line++;
    // printf("prvo slovo %c je\n", *line);
  }

  if (*word != '\0')
  {
    tokens[token_count++] = word;
    // printf("DODALI poslednje %s\n", word);
  }

  // for(int i = 0; i < token_count; i++) {
  //   printf("element %s broj %d\n", tokens[i],i);
  // }

  return token_count;
}

void debug(char *tokens[])
{
  if (level > 0)
  {
    // printf("Input line: \'%s\'\n",izpis);//izpis je ono sto sam uneo kao komandu a krece sa 'debug'
    //  for(int i = 0; i < num_tokens; i++) {
    //    printf("Token %d: \'%s\'\n", i, tokens[i]);//izpisujem rec po rec kao tokene
    //  }
    // printf("Executing builtin \'%s\' in foreground\n", tokens[0]);
  }
  if (num_tokens > 1)
  {
    level = atoi(tokens[1]); // nastavljam level na osovu druge besede v komandi npr. 'debug 1'
  }
  else
  {
    printf("%d\n", level);
  }
}

void prompt_f(char *tokens[])
{ // izpisuje ko pise u terminalu mysh>,  prompt mooj ce ispisivati uvek na pocetku mooj>
  if (num_tokens < 2)
  {
    printf("%s\n", prompt);
    status = 0;
  }
  else
  {
    if (strlen(tokens[1]) < 8)
    {
      strcpy(prompt, tokens[1]);
      status = 0;
    }
    else
    {
      status = 1;
    }
  }
}

void status_f(char *tokens[])
{ // izpisuje status
  printf("%d\n", status);
}

void exit_f(char *tokens[])
{ // nastavljamo status sa onim sto damo kao argument u komandi 'exit'
  if (num_tokens > 1)
  {
    status = atoi(tokens[1]);
  }
  // printf("Exit status: %d\n", status);
  exit(status);
}

void print_f(char *tokens[])
{
  // printf("%d",num_tokens);
  for (int i = 1; i < num_tokens; i++)
  {
    if (i == 1)
    {
      printf("%s", tokens[i]);
    }
    else
      printf(" %s", tokens[i]);

    // fflush(stdout); // Flush the output buffer
  }
}

void echo_f(char *tokens[])
{
  // printf("%d",num_tokens);
  for (int i = 1; i < num_tokens; i++)
  {
    if( i != 1) {
      printf(" ");
    }
    printf("%s", tokens[i]);
    // fflush(stdout); // Flush the output buffer
  }
  printf("\n");
}

void len_f(char *tokens[])
{
  // printf("%d",num_tokens);
  int sum = 0;
  for (int i = 1; i < num_tokens; i++)
  {
    sum += strlen(tokens[i]);
  }
  printf("%d\n", sum);
}

void sum_f(char *tokens[])
{
  // printf("%d",num_tokens);
  int sum = 0;
  for (int i = 1; i < num_tokens; i++)
  {
    sum += atoi(tokens[i]);
  }
  printf("%d\n", sum);
}

void calc_f(char *tokens[])
{
  // printf("%d",num_tokens);
  char *op = tokens[2];
  int res = 0;
  int arg1 = atoi(tokens[1]);
  int arg2 = atoi(tokens[3]);

  if (strcmp(op, "+") == 0)
    res = arg1 + arg2;
  else if (strcmp(op, "-") == 0)
    res = arg1 - arg2;
  else if (strcmp(op, "*") == 0)
    res = arg1 * arg2;
  else if (strcmp(op, "/") == 0)
    res = arg1 / arg2;
  else if (strcmp(op, "%") == 0)
    res = arg1 % arg2;

  printf("%d\n", res);
}

void basename_f(char *tokens[])
{
  char *ukaz = tokens[0];
  char *base = "";
  if (strcmp(ukaz, "basename") == 0)
  {
    if (num_tokens <= 1)
    {
      status = 1;
      return;
    }
    else
    {
      printf("%s\n", basename(tokens[1]));

      status = 0;
    }
  }
}

void dirname_f(char *tokens[])
{
  char *ukaz = tokens[0];
  char *charbase = "";
  if (strcmp(ukaz, "dirname") == 0)
  {
    if (num_tokens <= 1)
    {
      status = 1;
      return;
    }
    char *arg = tokens[1];
    char *last_slash = strrchr(arg, '/');
    if (last_slash != NULL)
    {
      *last_slash = '\0';
      printf("%s\n", arg);
      status = 0;
    }
    else
    {
      printf(".\n");
      status = 0;
    }
  }
}

void dirch_f(char *tokens[])
{
  if (num_tokens < 2)
  {
    status = chdir("/");
  }
  else
  {
    status = chdir(tokens[1]);
    // printf("argumenti %s\n", tokens[1]);
    if (status == -1)
    {
      status = errno;
      perror("dirch");
    }
  }
}

void dirwd_f(char *tokens[])
{
  char cwd[1024];
  getcwd(cwd, sizeof(cwd));
  if (num_tokens < 2)
  {
    printf("%s\n", basename(cwd));
  }
  else
  {
    if (getcwd(cwd, sizeof(cwd)) != NULL)
    {
      if (tokens[1] != NULL && strcmp(tokens[1], "full") == 0)
      {
        printf("%s\n", cwd);
      }
      else
      {
        printf("%s\n", basename(cwd));
      }
    }
    else
    {
      status = errno;
      perror("getcwd");
    }
  }
}

void dirmk_f(char *tokens[])
{
  if (mkdir(tokens[1], 0777) == -1)
  {
    // Preverimo, ali je napaka posledica že obstoječega imenika
    if (errno == EEXIST)
    {
      status = errno;
      // Imenik že obstaja, izpišemo napako in nastavimo status na errno
      perror("dirmk");
      return;
    }
    else
    {
      status = errno;
      // Druga napaka, izpišemo splošno sporočilo o napaki
      perror("mkdir");
      return;
    }
    // Nastavimo status na trenutno vrednost errno
  }
}

void dirrm_f(char *tokens[])
{
  if (rmdir(tokens[1]) == -1)
  {
    status = errno;
    perror("dirrm"); // Izhod iz programa v primeru napake
  }
}

void dirls_f(char *tokens[])
{
  DIR *dir;
  struct dirent *ent;

  // Preveri, ali je bil podan imenik kot argument
  char *directory = num_tokens > 1 ? tokens[1] : ".";

  // Poskusi odpreti imenik
  if ((dir = opendir(directory)) != NULL)
  {
    // Preberi vsebino imenika
    while ((ent = readdir(dir)) != NULL)
    {
      // Izpiši ime datoteke
      printf("%s  ", ent->d_name);
    }
    closedir(dir);
    printf("\n");
  }
  else
  {
    // Če imenika ni bilo mogoče odpreti, izpiši napako
    printf("Napaka pri odpiranju imenika.\n");
  }
}

void rename_f(char *tokens[])
{
  if (rename(tokens[1], tokens[2]) == 0)
  {
    // printf("Datoteka '%s' uspešno preimenovana v '%s'.\n", izvor, ponor);
    return; // Uspeh
  }
  else
  {
    perror("rename");
    return; // Napaka
  }
}

void unlink_f(char *tokens[])
{
  if (unlink(tokens[1]) == 0)
  {
    // printf("Datoteka '%s' uspešno odstranjena.\n", ime);
    status = 0; // Uspeh
  }
  else
  {
    // printf("Napaka pri odstranjevanju datoteke.\n");
    status = errno;
    perror("unlink");
    return; // Napaka
  }
  status = 0;
}

void remove_f(char *tokens[])
{
  if (remove(tokens[1]) == 0)
  {
    // printf("Datoteka '%s' uspešno odstranjena.\n", ime);
    return; // Uspeh
  }
  else
  {
    // printf("Napaka pri odstranjevanju datoteke.\n");
    perror("unlink");
    return; // Napaka
  }
}

void linkhard_f(char *tokens[])
{
  if (link(tokens[1], tokens[2]) == 0)
  {
    // printf("Ustvarjena trda povezava '%s' na '%s'.\n", ime, cilj);
    return; // Uspeh
  }
  else
  {
    // printf("Napaka pri ustvarjanju trde povezave.\n");
    perror("linkhard");
    return; // Napaka
  }
}

void linksoft_f(char *tokens[])
{
  if (symlink(tokens[1], tokens[2]) == 0)
  {
    // printf("Ustvarjena trda povezava '%s' na '%s'.\n", ime, cilj);
    return; // Uspeh
  }
  else
  {
    // printf("Napaka pri ustvarjanju trde povezave.\n");
    perror("linksoft");
    return; // Napaka
  }
}

void linkread_f(char *tokens[])
{
  char *link_name = tokens[1];
  char target[PATH_MAX + 1];

  int len = readlink(link_name, target, sizeof(target) - 1);

  if (len == -1)
  {
    status = errno;
    perror("linkread");
  }
  else
  {
    target[len] = '\0'; // za konec vrstice
    printf("%s\n", target);
    status = 0;
  }
}

void linklist_f(char *tokens[])
{
  struct stat file_stat;
  if (lstat(tokens[1], &file_stat) == -1)
  {
    perror("lstat");
    return;
  }

  DIR *dir;
  struct dirent *entry;
  if ((dir = opendir(".")) == NULL)
  {
    perror("opendir");
    return;
  }

  while ((entry = readdir(dir)) != NULL)
  {
    if (entry->d_type == DT_REG)
    {
      struct stat entry_stat;
      if (lstat(entry->d_name, &entry_stat) == -1)
      {
        perror("lstat");
        closedir(dir);
        return;
      }
      if (entry_stat.st_ino == file_stat.st_ino)
      {
        printf("%s  ", entry->d_name);
      }
    }
  }
  printf("\n");
  closedir(dir);
}

void cpcat_f(int num_tokens, char *tokens[])
{
  int fin = STDIN_FILENO;
  int fout = STDOUT_FILENO;
  if (num_tokens > 1 && strcmp(tokens[1], "-"))
  {
    char *fileName = tokens[1];
    fin = open(fileName, O_RDONLY);
    if (fin == -1)
    {
      int err = errno;
      perror("cpcat");
      // fflush(stderr);
      status = err;
      return;
    }
  }

  if (num_tokens > 2)
  {
    char *fileName = tokens[2];
    fout = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fout == -1)
    {
      int err = errno;
      perror("cpcat");
      // fflush(stderr);
      status = err;
      return;
    }
  }
  char buf[BUFFER_SIZE];
  ssize_t bytes_read;
  while ((bytes_read = read(fin, buf, BUFFER_SIZE)) > 0)
  {
    if (write(fout, buf, bytes_read) != bytes_read)
    {
      int err = errno;
      perror("cpcat");

      if (fin != STDIN_FILENO)
      {
        close(fin);
      }
      if (fout != STDOUT_FILENO)
      {
        close(fout);
      }
      // fflush(stderr);
      status = err;
      return;
    }
    // fflush(stdout);
  }
  if (bytes_read < 0)
  {
    int err = errno;
    perror("cpcat");
    if (fin != STDIN_FILENO)
    {
      close(fin);
    }
    if (fout != STDOUT_FILENO)
    {
      close(fout);
    }
    // fflush(stderr);
    status = err;
  }
  if (fin != STDIN_FILENO)
  {
    close(fin);
  }
  if (fout != STDOUT_FILENO)
  {
    close(fout);
  }
}

void pid_f()
{
  pid_t pid = getpid();
  // printf("PID trenutnega procesa: %d\n", pid);
}

void ppid_f()
{
  pid_t ppid = getppid();

  // Izpis PID-a starševskega procesa
  // printf("PID starševskega procesa: %d\n", ppid);
}

void uid_f()
{
  uid_t uid = getuid();
  printf("%d\n", uid);
}

void euid_f()
{
  uid_t euid = geteuid();
  printf("%d\n", euid);
}

void gid_f()
{
  gid_t gid = getgid();
  printf("%d\n", gid);
}

void egid_f()
{
  gid_t egid = getegid();
  printf("%d\n", egid);
}

void sysinfo_f()
{
  struct utsname sys_info;

  // Pridobimo informacije o sistemu
  if (uname(&sys_info) != 0)
  {
    status = errno;
    perror("uname");
    return;
  }

  // Izpis informacij
  printf("Sysname: %s\n", sys_info.sysname);
  printf("Nodename: %s\n", sys_info.nodename);
  printf("Release: %s\n", sys_info.release);
  printf("Version: %s\n", sys_info.version);
  printf("Machine: %s\n", sys_info.machine);
}

void proc_f(char *tokens[], char *poti)
{
  if (num_tokens > 1)
  {
    if (access(tokens[1], F_OK | R_OK) != -1) // exists
      strcpy(pot, tokens[1]);
    else
      status = 1;
    return;
  }
  else
    printf("%s\n", pot);
  status = 0;
}

int compare_pid(const void *a, const void *b)
{
  return *((int *)a) - *((int *)b);
}

void pids_f(char *tokens[], char *poti)
{
  DIR *dir = opendir(poti);
  if (dir == NULL)
  {
    status = errno;
    perror("Napaka pri odpiranju mape /proc");
    return;
  }

  // Preberi vse datoteke v mapi /proc
  int *indeksi = calloc(1000, sizeof(int));
  int num_processes = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
  {
    // Preveri, ali je ime v mapi številka (PID)
    int pid = atoi(entry->d_name);
    if (pid != 0)
    {
      // Če je, izpiši PID
      // printf("%d\n", pid);
      indeksi[num_processes++] = pid;
    }
  }

  // Zapri mapo /proc
  closedir(dir);
  qsort(indeksi, num_processes, sizeof(int), compare_pid);
  for (int i = 0; i < num_processes; i++)
  {
    printf("%d\n", indeksi[i]);
  }

  // Počisti uporabljene vire
  free(indeksi);
}

typedef struct
{
  int pid;
  int ppid;
  char state;
  char name[MAX_LINE_LENGTH];
} ProcessInfo;

int compareByPID(const void *a, const void *b)
{
  ProcessInfo *processA = (ProcessInfo *)a;
  ProcessInfo *processB = (ProcessInfo *)b;
  return processA->pid - processB->pid;
}

void removeParenthesesAndSpaces(char *str)
{
  int len = strlen(str);
  int j = 0;
  for (int i = 0; i < len; i++)
  {
    if (str[i] != '(' && str[i] != ')' && !isspace(str[i]))
    {
      str[j++] = str[i];
    }
  }
  str[j] = '\0';
}

void pinfo_f(char *tokens[], char *poti)
{
  DIR *dir = opendir(poti);
  if (dir == NULL)
  {
    status = errno;
    perror("Napaka pri odpiranju mape /proc");
    return;
  }

  // Preberi vse datoteke v mapi /proc
  int num_processes = 0;
  ProcessInfo processes[MAX_PROCESSES];
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL && num_processes < MAX_PROCESSES)
  {
    // Preveri, ali je ime v mapi številka (PID)
    int pid = atoi(entry->d_name);
    if (pid != 0)
    {
      // Izberi samo aktivne procese, ker so mapice /proc tudi za druge sistemske entitete
      char path[256];
      sprintf(path, "%s/%d/stat", poti, pid);
      FILE *file = fopen(path, "r");
      if (file == NULL)
      {
        status = errno;
        perror("Napaka pri odpiranju datoteke");
        return;
      }
      // Preberi informacije o procesu iz datoteke stat
      int ppid;
      char name[100], state;
      fscanf(file, "%*d %s %c %d", name, &state, &ppid);
      fclose(file);
      // Dodaj informacije o procesu v seznam
      processes[num_processes].pid = pid;
      processes[num_processes].ppid = ppid;
      processes[num_processes].state = state;
      strcpy(processes[num_processes].name, name);
      num_processes++;
    }
  }

  closedir(dir);

  // Sortiranje procesov po PID
  qsort(processes, num_processes, sizeof(ProcessInfo), compareByPID);

  // Izpiši informacije o procesih
  printf("%5s %5s %6s %s\n", "PID", "PPID", "STANJE", "IME");
  for (int i = 0; i < num_processes; i++)
  {

    removeParenthesesAndSpaces(processes[i].name);
    printf("%5d %5d %6c %s\n", processes[i].pid, processes[i].ppid, processes[i].state, processes[i].name);
  }
}
/*
  void waitone_f(char* tokens[]) {
    int pid = -1;
    if(num_tokens == 2) {
      pid = atoi(tokens[1]);
      if(waitpid(pid, &status, 0) != -1) {
        status = 0;
      } else {
        status = errno;
        perror("wait");
      }
    } else {
      wait(&status);
    }
  }
*/
void waitone_f()
{
  int pid;
  if (num_tokens == 1)
  {
    // printf("za foro\n");
    pid = wait(&status);
    if (pid == -1)
    {
      status = 0;
      return;
    }
    status = WEXITSTATUS(status);
  }
  else
  {
    pid = atoi(tokens[1]);
    if (kill(pid, 0) == -1)
    {
      status = 0;
      return;
    }
    waitpid(pid, &status, 0);
    status = WEXITSTATUS(status);
  }
}

void waitall_f()
{
  int pid;
  while (1)
  {
    pid = wait(&status);
    if (pid == -1)
    {
      break;
    }
  }
  status = 0;
}

void head_f(char *tokens[], int num_lines) {
    FILE *file = fopen(tokens[1], "r");
    if (file == NULL) {
        status = errno;
        perror("fopen");
        return;
    }

    char buffer[1024];
    for (int i = 0; i < num_lines && fgets(buffer, sizeof(buffer), file); ++i) {
        fputs(buffer, stdout);
    }

    fclose(file);
}

void wc_f(char *tokens[]) {
    FILE *file = fopen(tokens[1], "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }

    int lines = 0, words = 0, bytes = 0;
    char ch;
    int in_word = 0;

    while ((ch = fgetc(file)) != EOF) {
        bytes++;
        if (ch == '\n') lines++;
        if (ch == ' ' || ch == '\n' || ch == '\t') {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            words++;
        }
    }

    fclose(file);
    printf("%d %d %d %s\n", lines, words, bytes, tokens[1]);
}

void touch_f(char *tokens[]) {
    // Open the file or create it if it doesn't exist
    int fd = open(tokens[1], O_CREAT | O_WRONLY, 0644);
    if (fd == -1) {
        status = errno;
        perror("open");
    }
    close(fd);

    // Update access and modification times to current time
    struct utimbuf times;
    times.actime = times.modtime = time(NULL);
    if (utime(tokens[1], &times) == -1) {
        status = errno;
        perror("utime");
    }
}

void ls_f(char *tokens[]) {
  pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        // Child process
        char *argv[] = {"ls", NULL};
        if (execvp("ls", argv) == -1) {
            status = errno;
            perror("execvp");
        }
        exit(EXIT_FAILURE);  // Exit if execvp fails
    } else {
        // Parent process
        if (waitpid(pid, NULL, 0) == -1) {
            status = errno;
            perror("waitpid");
        }
    }
}


void tail_f(char *tokens[], int lines) {
   FILE *file = fopen(tokens[1], "r");
    if (file == NULL) {
      status = errno;
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    char *line_buffer[lines];
    int line_count = 0;
    int current_line = 0;

    // Initialize line buffer
    for (int i = 0; i < lines; ++i) {
        line_buffer[i] = NULL;
    }

    // Read file line by line
    while (fgets(buffer, BUFFER_SIZE, file)) {
        if (line_buffer[current_line]) {
            free(line_buffer[current_line]);
        }
        line_buffer[current_line] = strdup(buffer);
        current_line = (current_line + 1) % lines;
        if (line_count < lines) {
            line_count++;
        }
    }

    fclose(file);

    // Print the last 'lines' lines
    for (int i = 0; i < line_count; ++i) {
        printf("%s", line_buffer[(current_line + i) % lines]);
        free(line_buffer[(current_line + i) % lines]);
    }
}


bool find_builtin(char *cmd)
{ // trazimo vgrajene (builtin) funckije

  if ((strcmp(cmd, "debug") == 0) || (strcmp(cmd, "exit") == 0) || (strcmp(cmd, "help") == 0) || (strcmp(cmd, "status") == 0) || (strcmp(cmd, "sum") == 0) || (strcmp(cmd, "len") == 0) || (strcmp(cmd, "echo") == 0) || (strcmp(cmd, "calc") == 0) || (strcmp(cmd, "basename") == 0) || (strcmp(cmd, "dirname") == 0) || (strcmp(cmd, "print") == 0) || (strcmp(cmd, "dirch") == 0) || (strcmp(cmd, "dirwd") == 0) || (strcmp(cmd, "dirmk") == 0) || (strcmp(cmd, "dirrm") == 0) || (strcmp(cmd, "dirls") == 0) || (strcmp(cmd, "rename") == 0) || (strcmp(cmd, "unlink") == 0) || (strcmp(cmd, "remove") == 0) || (strcmp(cmd, "linkhard") == 0) || (strcmp(cmd, "linksoft") == 0) || (strcmp(cmd, "linkread") == 0) || (strcmp(cmd, "linklist") == 0) || (strcmp(cmd, "cpcat") == 0) || (strcmp(cmd, "pid") == 0) || (strcmp(cmd, "ppid") == 0) || (strcmp(cmd, "uid") == 0) || (strcmp(cmd, "euid") == 0) || (strcmp(cmd, "gid") == 0) || (strcmp(cmd, "egid") == 0) || (strcmp(cmd, "pids") == 0) ||(strcmp(cmd, "pipes") == 0) || (strcmp(cmd, "sysinfo") == 0) || (strcmp(cmd, "pinfo") == 0) || (strcmp(cmd, "waitone") == 0) || (strcmp(cmd, "waitall") == 0) || (strcmp(cmd, "proc") == 0) ||(strcmp(cmd, "touch") == 0)||  (strcmp(cmd, "ls") == 0) ||  (strcmp(cmd, "head") == 0)|| (strcmp(cmd, "tail") == 0) || (strcmp(cmd, "wc") == 0) || (strcmp(cmd, "prompt") == 0))
  {
    return true;
  }
  return false;
}

void execute_builtin(char *tokens[])
{
  if (strcmp(tokens[0], "debug") == 0)
  {
    debug(tokens);
  }
  else if (strcmp(tokens[0], "help") == 0)
  {
    printf("\n");
    printf("debug   ----------> izpise trenutni level razhroscevanja\n");
    printf("prompt  ----------> izpisemo ali nastavimo pozivnika\n");
    printf("status  ----------> izpise izhodni status izhodnega ukaza\n");
    printf("exit    ----------> izhod iz programa\n");
    printf("help    ----------> izpise vse mozne ukaze\n");
    printf("\n");
  }
  else if (strcmp(tokens[0], "exit") == 0)
  {
    exit_f(tokens);
  }
  else if (strcmp(tokens[0], "prompt") == 0)
  {
    prompt_f(tokens);
  }
  else if (strcmp(tokens[0], "status") == 0)
  {
    status_f(tokens);
  }
  else if (strcmp(tokens[0], "print") == 0)
  {
    print_f(tokens);
  }
  else if (strcmp(tokens[0], "echo") == 0)
  {
    echo_f(tokens);
  }
  else if (strcmp(tokens[0], "len") == 0)
  {
    len_f(tokens);
  }
  else if (strcmp(tokens[0], "sum") == 0)
  {
    sum_f(tokens);
  }
  else if (strcmp(tokens[0], "calc") == 0)
  {
    calc_f(tokens);
  }
  else if (strcmp(tokens[0], "basename") == 0)
  {
    basename_f(tokens);
  }
  else if (strcmp(tokens[0], "dirname") == 0)
  {
    dirname_f(tokens);
  }
  else if (strcmp(tokens[0], "dirch") == 0)
  {
    dirch_f(tokens);
  }
  else if (strcmp(tokens[0], "dirwd") == 0)
  {
    dirwd_f(tokens);
  }
  else if (strcmp(tokens[0], "dirmk") == 0)
  {
    dirmk_f(tokens);
  }
  else if (strcmp(tokens[0], "dirrm") == 0)
  {
    dirrm_f(tokens);
  }
  else if (strcmp(tokens[0], "dirls") == 0)
  {
    dirls_f(tokens);
  }
  else if (strcmp(tokens[0], "rename") == 0)
  {
    rename_f(tokens);
  }
  else if (strcmp(tokens[0], "unlink") == 0)
  {
    unlink_f(tokens);
  }
  else if (strcmp(tokens[0], "remove") == 0)
  {
    remove_f(tokens);
  }
  else if (strcmp(tokens[0], "linkhard") == 0)
  {
    linkhard_f(tokens);
  }
  else if (strcmp(tokens[0], "linksoft") == 0)
  {
    linksoft_f(tokens);
  }
  else if (strcmp(tokens[0], "linkread") == 0)
  {
    linkread_f(tokens);
  }
  else if (strcmp(tokens[0], "linklist") == 0)
  {
    linklist_f(tokens);
  }
  else if (strcmp(tokens[0], "cpcat") == 0)
  {
    cpcat_f(num_tokens, tokens);
  }
  else if (strcmp(tokens[0], "pid") == 0)
  {
    pid_f();
  }
  else if (strcmp(tokens[0], "ppid") == 0)
  {
    ppid_f();
  }
  else if (strcmp(tokens[0], "uid") == 0)
  {
    uid_f();
  }
  else if (strcmp(tokens[0], "euid") == 0)
  {
    euid_f();
  }
  else if (strcmp(tokens[0], "gid") == 0)
  {
    gid_f();
  }
  else if (strcmp(tokens[0], "egid") == 0)
  {
    egid_f();
  }
  else if (strcmp(tokens[0], "sysinfo") == 0)
  {
    sysinfo_f();
  }
  else if (strcmp(tokens[0], "proc") == 0)
  {
    proc_f(tokens, pot);
  }
  else if (strcmp(tokens[0], "pids") == 0)
  {
    pids_f(tokens, pot);
  }
  else if (strcmp(tokens[0], "pinfo") == 0)
  {
    pinfo_f(tokens, pot);
  }
  else if (strcmp(tokens[0], "waitone") == 0)
  {
    waitone_f(tokens);
  }
  else if (strcmp(tokens[0], "waitall") == 0)
  {
    waitall_f(tokens);
  }
  else if (strcmp(tokens[0], "pipes") == 0)
  {
    pipes(tokens, background);
  }
  else if (strcmp(tokens[0], "head") == 0)
  {
    head_f(tokens, 5);
  }
  else if (strcmp(tokens[0], "wc") == 0)
  {
    wc_f(tokens);
  }
  else if (strcmp(tokens[0], "touch") == 0)
  {
    touch_f(tokens);
  }
  else if (strcmp(tokens[0], "ls") == 0)
  {
    ls_f(tokens);
  }
  else if (strcmp(tokens[0], "tail") == 0)
  {
    tail_f(tokens, 5);
  }


}

void execute_external(char *tokens[], int background, int in, char *input, int ot, char *output)
{ // izvodjenje spoljnih komandi
  //printf("Izvajam external funkcijo: %s\n", izpis);
  if (level > 0)
  {
    // printf("Input line: \'%s\'\n",izpis);
    //  for(int i = 0; i < num_tokens; i++) {
    //    printf("Token %d: \'%s\'\n", i, tokens[i]);
    //  }

    if (num_tokens > 2)
    {
      for (int i = num_tokens - 1; i >= num_tokens - 3; i--)
      {
        if (*(tokens[i]) == '&')
        {
          background = 1;
          continue;
        }
        if (tokens[i][0] == '<')
        {
          tokens[i]++;
          input = tokens[i];
          in = 1;
          continue;
        }
        if (tokens[i][0] == '>')
        {
          tokens[i]++;
          output = tokens[i];
          ot = 1;
          continue;
        }
      }
      if (in == 1)
      {
        printf("Input redirect: \'%s\'\n", input);
      }
      if (ot == 1)
      {
        printf("Output redirect: \'%s\'\n", output);
      }
      if (background == 1)
      {

        // printf("Background: %d\n", background);
      }
    }
  }
  char niz[50];
  int cnt = 0;
  for (int i = 0; i < strlen(izpis); i++)
  {
    if (what != true && level > 0 && (izpis[i] == '>' || (izpis[i] == '<') || (izpis[i] == '&')))
    {
      break;
    }
    niz[i] = izpis[i];
    cnt++;
  }
  if (niz[cnt - 1] == ' ')
  {
    niz[cnt - 1] = '\0';
    cnt--;
  }
  // TUKI SE MI ZDI DA JE NEKI NAROBE
  if (background)
  {
    tokens[num_tokens - 1] = NULL;
  }
  else
  {
    tokens[num_tokens] = NULL;
  }
  fflush(stdin);
  int pid = fork();
  if (pid > 0)
  {
    if (!background)
    {
      waitpid(pid, &status, 0);
      status = status >> 8;
    }
  }
  else
  {
    //printf("Izvajam external funkcijo: %s\n", tokens[0]);
    execvp(tokens[0], tokens);
    perror("exec");
    exit(127);
  }
}

// prepisano iz vaj
void handle_sigchld(int signum)
{
  int pid, status, serrno;
  serrno = errno;
  while (1)
  {
    pid = waitpid(WAIT_ANY, &status, WNOHANG);
    if (pid < 0)
    {
      break;
    }
    if (pid == 0)
    {
      break;
    }
  }
  errno = serrno;
}

void clearTokens(char *tokens[])
{
  int i = 0;
  while (tokens[i] != NULL)
  {
    tokens[i] = NULL;
    i++;
  }
}
void pipes(char *tokens[], int background)
{
  //printf("ENTERING PIPES\n");

    int fd1[2];
    pipe(fd1);
    fflush(stdin);
    if (!fork())
    {
      //printf("PARSING\n");
      char ukaz[MAX_LINE_LENGTH];
      strcpy(ukaz, tokens[1]);
      clearTokens(tokens);
      num_tokens = tokenize(ukaz);
      tokens[num_tokens] = NULL;
      //printf("|%s|\n", tokens[1]);

      fflush(stdout);
      dup2(fd1[1], 1);
      close(fd1[0]);
      close(fd1[1]);

      background = 0;
      parse(0,0,NULL,NULL);
      exit(42);
    }
    //return;
    int fd2[2];
    for (int i = 1; i < num_tokens - 2; i++)
    {
      fd2[0] = fd1[0];
      fd2[1] = fd1[1];
      pipe(fd1);
      fflush(stdin);

      if (!fork())
      {
        background = 0;
        dup2(fd2[0], 0);
        dup2(fd1[1], 1);
        close(fd1[0]);
        close(fd1[1]);
        close(fd2[0]);
        close(fd2[1]);
        char *ukaz = calloc(sizeof(char), MAX_LINE_LENGTH);
        strcpy(ukaz, tokens[i + 1]);
        clearTokens(tokens);
        num_tokens = tokenize(ukaz);
        tokens[num_tokens] = NULL;
        parse(0,0,NULL,NULL);
        free(ukaz);
        exit(42);
      }
      // brez spodnjega closea se cevovod ne bo nikoli prenehal izvajati
      close(fd2[0]);
      close(fd2[1]);
    }

    fd2[0] = fd1[0];
    fd2[1] = fd1[1];
    // tretji otrok naj deduje samo drugo cev
    fflush(stdin);

    if (!fork())
    {
      char ukaz[MAX_LINE_LENGTH];
      strcpy(ukaz, tokens[num_tokens-1]);
      clearTokens(tokens);
      num_tokens = tokenize(ukaz);
      tokens[num_tokens] =  NULL;
      //printf("FIRST TOKEN|%s|\n", tokens[1]);

      background = 0;
      dup2(fd2[0], 0);
      close(fd2[0]);
      close(fd2[1]);
      parse(0,0,NULL,NULL);
      exit(42);
    }
    close(fd2[0]);
    close(fd2[1]);
    waitall_f();
  }

int parse(int in, int ot, char *input, char *output)
{
  int original_out_fd;
  int original_in_fd;

  //printf("TOKEN 0: %s\n", tokens[0]);

  what = find_builtin(tokens[0]);
  //printf("What je %d \n", what);
  // what = false;
  if (what == true)
  {
    // INTERNAL COMMANDS
    if (background)
    {
      fflush(stdin);
      int pid = fork();
      if (pid > 0)
      {
      }
      else
      {
        if (input != NULL)
        {
          int inp = open(input, O_RDONLY, 0777);
          if (inp == -1)
          {
            status = errno;
            perror("open");
          }
          dup2(inp, STDIN_FILENO);
          close(inp);
        }
        if (output != NULL)
        {
          int out = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0777);
          if (out == -1)
          {
            status = errno;
            perror("open");
          }
          dup2(out, STDOUT_FILENO);
          close(out);
        }
        execute_builtin(tokens);
        exit(status);
      }
    }
    else
    {
      original_in_fd = dup(STDIN_FILENO);
      original_out_fd = dup(STDOUT_FILENO);
      fflush(stdout);
      if (input != NULL)
      {
        int inp = open(input, O_RDONLY, 0777);
        if (inp == -1)
        {
          status = errno;
          perror("open error v !background");
        }
        dup2(inp, STDIN_FILENO);
        close(inp);
      }
      if (output != NULL)
      {
        int out = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (out == -1)
        {
          status = errno;
          perror("open error v !background");
        }
        dup2(out, STDOUT_FILENO);
        close(out);
      }
      execute_builtin(tokens);
      fflush(stdout);
      if (input != NULL)
      {
        dup2(original_in_fd, STDIN_FILENO);
        close(original_in_fd);
      }
      if (output != NULL)
      {
        dup2(original_out_fd, STDOUT_FILENO);
        close(original_out_fd);
      }
    }
  }
  else
  {
    printf("What je false \n");
    // EXTERNAL COMMANDS
    if (num_tokens > 0)
    {
      original_in_fd = dup(STDIN_FILENO);
      original_out_fd = dup(STDOUT_FILENO);
      fflush(stdout);
      if (in == 1)
      {
        // printf("moj input: %s\n", input);
        int inp = open(input, O_RDONLY, 0777);
        if (inp == -1)
        {
          status = errno;
          perror("open");
        }
        dup2(inp, STDIN_FILENO);
        close(inp);
      }
      if (ot == 1)
      {
        // printf("MOOJ outpur: %s\n", output);
        int out = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (out == -1)
        {
          status = errno;
          perror("open");
        }
        dup2(out, STDOUT_FILENO);
        close(out);
      }
      execute_external(tokens, background, in, input, ot, output);
      fflush(stdout);
      if (input != NULL)
      {
        dup2(original_in_fd, STDIN_FILENO);
        close(original_in_fd);
      }
      if (output != NULL)
      {
        dup2(original_out_fd, STDOUT_FILENO);
        close(original_out_fd);
      }
    }
  }
  return 0;
}

int main()
{

  marker = isatty(STDIN_FILENO);
  char *output = NULL;
  char *input = NULL;
  int ot = 0; // output je nastavljen ili ne
  int in = 0; // input je nastavljen ili ne

  char command[MAX_NAME_SZ];
  signal(SIGCHLD, handle_sigchld);
  strcpy(prompt, "mysh");
  if (marker)
  {
    printf("%s> ", prompt);
  }
  while (fgets(command, sizeof(command), stdin) != NULL)
  { // cita sa ulaza komande linija po liniju
    fflush(stdout);
    fflush(stderr);

    if (strlen(command) == 0 || command[0] == '#' || (command[0] == '\n' && strlen(command) == 1))
    {
      continue;
    }
    in = 0;
    ot = 0;
    command[strlen(command) - 1] = '\0'; // stavi poslednji znak za konec vrstice
    strcpy(izpis, command);

    num_tokens = tokenize(command);

    for (int i = num_tokens - 1; i >= 0; i--)
    {
      if (tokens[i][0] == '<')
      {
        in = 1;
        input = tokens[i] + 1;
        num_tokens--;
        // strcpy(input, tokens[i]+1);
        // printf("MOJ INPUT %s\n", input);
      }
      else if (tokens[i][0] == '>')
      {
        ot = 1;
        num_tokens--;
        output = tokens[i] + 1;

        // strcpy(output, tokens[i]+1);
      }
    }

    // if(in == 1) printf("MOJ INPUT %s\n", input);
    //     if(ot == 1) printf("MOJ OUTPUT %s\n", output);
    if (level > 0)
    {
      printf("Input line: \'%s\'\n", izpis); // izpis je ono sto sam uneo kao komandu a krece sa 'debug'
      for (int i = 0; i < num_tokens; i++)
      {
        printf("Token %d: \'%s\'\n", i, tokens[i]); // izpisujem rec po rec kao tokene
      }
      printf("Executing builtin \'%s\' in foreground\n", tokens[0]);
    }

    if (strcmp(tokens[num_tokens - 1], "&") == 0)
    {
      background = 1;
      num_tokens--;
      debug(tokens);
    }

    parse(in, ot, input, output);

    if (marker)
    {
      printf("%s> ", prompt);
    }
    background = 0;
    in = 0;
    ot = 0;
    input = NULL;
    output = NULL;
  }

  return status;
}