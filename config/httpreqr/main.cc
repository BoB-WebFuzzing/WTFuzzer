
/*
 * sudo aptitude install libcurl4-openssl-dev
 * Compile and run the code
 * g++ main.cc -o httpreqr -lcurl

 */

#include <sys/stat.h>
#include <iostream>
#include <string>
#include <curl/curl.h>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/wait.h>
#include <regex>
#include <csignal>
#include <iomanip>
#include <sys/shm.h>
#include <csignal>

#include <sys/types.h>

#include <sys/shm.h>

#define FORKSRV_FD 198
#define TSL_FD (FORKSRV_FD - 1)

using namespace std;

struct test_process_info {
    int initialized=0;
    int afl_id = 0;
    int port = 0;
    int reqr_process_id;
    int process_id=0;
    char error_type[20]; /* SQL, Command */
    char error_msg[100];
    bool capture;
};
#define TEST_PROCESS_INFO_SHM_ID 0x411911
#define TEST_PROCESS_INFO_MAX_NBR 100
#define TEST_PROCESS_INFO_SMM_SIZE 0x4000
//test_process_info *test_process_info_ptr;

bool isparent = true;
int tbd_shm_id = 0;
static unsigned char *afl_area_ptr =0;
int fake_afl_shm_id =0;
bool use_shm = true;

string ToHex(const string& s, bool upper_case /* = true */)
{
  ostringstream ret;

  for (string::size_type i = 0; i < s.length(); ++i)
    ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << (int)s[i];

  return ret.str();
}
class RequestData {
    string url, cookies="", gets="", posts="", method, headers="";
    bool json = false;
public:
    RequestData(string urlIn){
      url = urlIn;
    }
    void loadVariableData(){
      int inputcount = 0;
      cout << "Loading variable data :: " << endl;
      for (string line; getline(std::cin, line, '\x00');) {
        cout << ToHex(line, true) << endl;
        if (inputcount == 0){
          cookies = line;
          //cookies = "";
        } else if (inputcount == 1){
          gets = line;
          //gets = "b=/++";
        } else if (inputcount == 2){
          posts = string(line);
          //posts = "";
        } else if (inputcount == 3){
          headers = string(line);
        }
        inputcount++;
      }
      if (getenv("LOGIN_COOKIE")){
          if (cookies.size() > 0){
              cookies += ",";
          }
          cookies.append(getenv("LOGIN_COOKIE"));
      }
      if (getenv("MANDATORY_COOKIE")){
          if (cookies.size() > 0){
              cookies += ",";
          }
          cookies.append(getenv("MANDATORY_COOKIE"));
      }
      cout << "Variable data loaded";
    }
    string getPort(){
      size_t first = url.find(":");
      size_t portpos = url.find(":", first+1);
      if (portpos == string::npos){
        return "80";
      }
      string port = regex_replace(url, regex("http://.*:([0-9]+).*"), string("$1"));
      if (port.length() == 0){
        return "";
      } else {
        return port;
      }
    }

    string getURL(){
      if (gets.size() == 0){
        return url;
      } else {
        if (url.find('?') == std::string::npos){
             return url + "?" +  gets;
        } else {
             return url + "&" +  gets;
        }

      }
    }
    bool hasCookies(){
      return cookies.size() > 0;
    }
    string getCookies(){
      return cookies;
    }

    string getGets(){
      return gets;
    }
    bool hasPosts(){
      return posts.size() > 0;
    }
    string getPosts(){
      if (json){
        if (posts.front() != '{'){
          cout << "PARAMS='" << posts << "'" << endl;
          format_to_json(posts.c_str());
          cout << "AFTERJSON='" << posts << "'" << endl;
        }
      }
      if (posts.size() == 0){
          return posts = "";
      }
      return posts;
    }

    bool hasHeaders(){
        return headers.size() > 0;
    }
    string getHeaders(){
        return headers;
    }
    void  format_to_json(const char *str){

      char tostr[posts.length()+1]{};
      memcpy(tostr, posts.c_str(), posts.length());
      tostr[posts.length()] = '\x00';

      posts = string("{");

      char * end_str;
      char * token = strtok_r(tostr, "&", &end_str);

      while( token != NULL ) {
        char jsonEleOut[strlen(token)+7];
        char *end_token;
        char *dup_token = strdup(token);

        char *first_part = strtok_r(dup_token, "=", &end_token);
        char *sec_part = strtok_r(NULL, "=", &end_token);
        if (sec_part) {
          sprintf(jsonEleOut,"\"%s\":\"%s\",", first_part, sec_part);
        } else {
          sprintf(jsonEleOut,"\"%s\":\"\",", first_part);
        }
        posts.append(jsonEleOut);
        token = strtok_r(NULL, "&", &end_str);
      }
      posts.pop_back();
      posts.append("}\x00");
      cout << "JSON before exit " << posts << endl;
      //return outstr;
    }

    void setMethod(string method_in){
      for (auto & c: method_in) c = toupper(c);

      method = method_in;
      if (method.length() == 0){
        method = "GET";
      }
    }
    string getMethod(){
    if (posts.length() > 0){
        method = "POST";
      }
      return method;
    }
    void setJSON(bool jsonIn){
      json = jsonIn;
    }

    string getContentType(){
      if (json){
        return "Content-Type: application/json";
      } else {
        return "Content-Type: application/x-www-form-urlencoded";
      }

    }
    string getRequest(){
        string r = method + " " + url + " HTTP/1.1\n";
        r += headers + "";
        r += "Cookie: " + cookies +"\n";
        r += getContentType() + "\n";
        r += "\n" + posts + "\n";

        return r;
    }

};

inline bool fileExists (const std::string& name) {
  struct stat buffer;
  return (stat (name.c_str(), &buffer) == 0);
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  ((std::string*)userp)->append((char*)contents, size * nmemb);
  return size * nmemb;
}

void writeOutAFLSHM(string PORT){

  ofstream myfile;
  
  char * afl_shm_loc = getenv("__AFL_SHM_ID");

  if (afl_shm_loc){
    struct stat info;
    if( stat( "/fs", &info ) == 0 ){
      myfile.open ("/fs/__AFL_SHM_ID"); //" +  PORT + ".afl");
      myfile << afl_shm_loc << endl;
      myfile.close();
    } else {
      myfile.open ("/__AFL_SHM_ID"); //" +  PORT + ".afl");
      myfile << afl_shm_loc << endl;
      myfile.close();
    }

    cout << "RECVD AFL_SHM_ID of " << hex << afl_shm_loc << endl;

  } else {
    cout << "NO AFL_SHM_MEM but wrote 0 to " << PORT << "" << endl;
  }

}


void checkForServerErrors(string port){
  string error;
  string serverErrorFile = "/tmp/" + port  + ".error";
  if (fileExists(serverErrorFile)){
    std::ifstream aflInfoFile (serverErrorFile);
    std::getline(aflInfoFile, error, '\n');
    ofstream errorFileOut;

    // clear file
    errorFileOut.open (serverErrorFile);
    errorFileOut << "" << endl;
    errorFileOut.close();

    if (error.compare("SQLERROR") == 0){

      raise(SIGSEGV);

    }
  }
  string fs_haccs_log = "/fs/HACCS.error";
  if (fileExists(fs_haccs_log)){
    string error;
    std::ifstream haccs_log_fn (fs_haccs_log);
    std::getline(haccs_log_fn, error, '\n');


    remove(fs_haccs_log.c_str());

    ofstream errorFileOut;
    string local_haccs_log = "/__haccs.log";
    errorFileOut.open (local_haccs_log, std::ios_base::app);
    errorFileOut << "HACCS.error found " << error << endl;
    errorFileOut.close();
    if (afl_area_ptr != NULL){
        afl_area_ptr[777]=1;
    }
    raise(SIGSEGV);

  }
}

void sendRequest(RequestData *reqD ){
  CURL *curl;
  CURLcode code(CURLE_FAILED_INIT);
  CURLcode res;
  long timeout = 3;
  if (getenv("DEBUG")){
      timeout = 600;
  }

  string readBuffer;
  cout << "SENDING REQUEST " << endl;
  curl = curl_easy_init();
  if(curl) {
    cout << "in da curl" << endl;
    reqD->loadVariableData();
    cout << "in da curl" << endl;

    cout << "Cookies = " << reqD->getCookies() << endl << "gets = " << reqD->getGets() << endl << "posts = '" << reqD->getPosts() << "'" << endl << "PORT=" << reqD->getPort() << endl;
    cout << "Headers = " << reqD->getHeaders() << endl;

    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    assert (CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout)));

    struct curl_slist *headers=NULL;

    printf("[main] sending '%s'\n", reqD->getPosts().c_str());
    char test[reqD->getPosts().length()+1];
    strcpy(test, reqD->getPosts().c_str());
    printf("original str = '%s'\n", test);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, reqD->getMethod().c_str());


    if (reqD->hasCookies()){
      assert (CURLE_OK == curl_easy_setopt(curl, CURLOPT_COOKIE, reqD->getCookies().c_str()));
    }
    if (reqD->hasPosts()){
      printf("[main] sending POST '%s'\n", reqD->getPosts().c_str());
      // POSTFIELDSIZE needs to be before COPYPOSTFIELDS
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) reqD->getPosts().size());
      curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS , reqD->getPosts().c_str());
      headers = curl_slist_append(headers, reqD->getContentType().c_str());

    }
    cout << "METHOD: " << reqD->getMethod() << endl;
    cout << "[main] URL=" << reqD->getURL() << endl;

    if (reqD->hasHeaders()){

      std::vector<std::string> lines;
      std::istringstream iss(reqD->getHeaders());
      std::string line;

      while (std::getline(iss, line)) {
          lines.push_back(line);
      }

      for (const auto& str : lines) {
        headers = curl_slist_append(headers, str.c_str());
    }

      
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    assert (CURLE_OK == curl_easy_setopt(curl, CURLOPT_URL, reqD->getURL().c_str()));

    code = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    curl_slist_free_all(headers);
    headers = NULL;
      cout << "----------------------- HTTP REQUEST --------------------------" << endl;
      cout << reqD->getRequest();
      cout << "--------------------- END HTTP REQUEST ------------------------" << endl;

    cout << "----------------------- HTTP RESPONSE --------------------------" << endl;
    cout << "Readbuffer = " << readBuffer << endl;
    cout << "--------------------- END HTTP RESPONSE ------------------------" << endl;


  }
}

string getArg(int argc, char *argv[], string param, bool getNext){
  for (int x=0; x < argc; x++){
    string pval = string((char*) argv[x]);

    if (pval.compare(param) == 0 ) {
      if (getNext) {
        if ((x + 1) < argc) {
          return string((char *) argv[x + 1]);
        } else {
          cout << "ERROR: the parameter" << param << " requires a value after it." << endl;
          exit(99);
        }

      } else {
        return "";
      }
    }
  }
  return "";

}


bool getArg(int argc, char *argv[], string param){
  for (int x=0; x < argc; x++) {
    string pval = string((char *) argv[x]);

    if (pval.compare(param) == 0) {
      return true;
    }
  }
  return false;


}

static void recvAFLRequests(RequestData *reqD) {

  static unsigned char tmp[4];
  static struct timespec start, finish;
  double elapsed;
  unsigned int afl_forksrv_pid = 0;
  static unsigned char afl_fork_child;
  static double totaltracetime;

  int parent_pid = getpid();
  //cgi_get_shm_mem();
  printf("[FORK]Starting up Forker %d __AFL_SHM_ID=%s\n", parent_pid, getenv("__AFL_SHM_ID"));
  bool infinite = true, firstpass_through = true;

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
    printf("[FORK]\tfork server not running.\n");
    infinite = false;
  } else {
    printf("\e[1;32m[FORK]\tWrote to FORKSRV_FD\e[0m\n");
  }

  afl_forksrv_pid = getpid();

  int claunch_cnt = 0;
  while (infinite || claunch_cnt < 1) {

    pid_t child_pid = -1;
    int status, t_fd[2];

    /* Whoops, parent dead? */
    if (claunch_cnt < 1){
      printf("[FORK]\t\tINITIAL awaiting orders %d\n", getpid());
    } else {
      printf("\n[FORK]\t\t\e[1;32mRESET and awaiting orders %d\e[0m\n", getpid());
    }

    if (infinite && read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    clock_gettime(CLOCK_MONOTONIC, &start);
    printf("[FORK]\t\tCreating communication channel to new child from %d\n", getpid());
    close(t_fd[1]);
    claunch_cnt ++;
    child_pid = fork();

    if (child_pid < 0) exit(4);

    if (child_pid==0) {  // child_pid == 0 when in the child

      /* Child process. Close descriptors and run free. */
      string id_str = getenv("__AFL_SHM_ID");
      int shm_id = atoi(id_str.c_str());

      afl_area_ptr = (unsigned char*)  shmat(shm_id, NULL, 0);
      afl_area_ptr[0] = 1;

      FILE *fptr;
      // opening file in writing mode
      fptr = fopen("/tmp/httpreqr.pid", "w");
      if (fptr){
          fprintf(fptr, "%d", getpid());
          fclose(fptr);
      }

      isparent=false;
      std::string cpid = std::to_string(getpid());

      setenv("AFL_CHILD_PID", cpid.c_str(),1);

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);

      sendRequest(reqD);

      checkForServerErrors(reqD->getPort());

      return;
    }

    /* Parent. */
    if (firstpass_through){

        firstpass_through = false;
    }
    close(TSL_FD);
    assert(parent_pid == getpid());

    if (infinite && write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      printf("\t\tExiting Parent %d with 5\n", child_pid);
      exit(5);
    }


    int waitedpid = waitpid(child_pid, &status, 0);
    if (waitedpid < 0) {
      printf("[PARENT-FORK]\t\tError with waitedpid (%d), Exiting Parent %d with 6\n", waitedpid, child_pid);
      exit(6);
    }
    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;

    cout << "[PARENT-FORK]\t\tChild exec of " << child_pid << " completed, completed in " << elapsed << " checking exit status, status=" << WEXITSTATUS(status) << " signal=" <<  WTERMSIG(status) << endl;

    int memcnt=0;
    if (afl_area_ptr == NULL){
        if (getenv("__AFL_SHM_ID")){
            int afl_id = atoi(getenv("__AFL_SHM_ID"));
            cout << "\033[36mAFL_ID = " << dec  << afl_id <<"\033[0m\n";
            afl_area_ptr = (unsigned char*) shmat(afl_id, NULL, 0);
            afl_area_ptr[0]=1;
        } else {
            cout << "\033[31m__AFL_SHM_ID environment variable is not set. "<< "\033[0m\n";
        }
    }

    if (afl_area_ptr == NULL){
        cout << "\033[31mFAILED to get afl_area_ptr " <<"\033[0m\n";
    } else {
      
        for (int x=0; x < 65536; x++){
            if (afl_area_ptr[x] != 0){
                memcnt++;
            }
        }
    }

    printf("\033[36mMEMCNT from run is %d\n\033[0m", memcnt);
    if (WIFEXITED(status)) {
      printf("\t\t\tRESULTS exited, status=%d signal=%d, total_val=%d\n", WEXITSTATUS(status), WTERMSIG(status), status);
    } else if (WIFSIGNALED(status)) {
      printf("\t\t\t\e[33mRESULTS killed by signal %d\e[0m\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
      printf("\t\t\t\e[33mRESULTS stopped by signal %d\e[0m\n", WSTOPSIG(status));
    } else if (WIFCONTINUED(status)) {
      printf("\t\t\tRESULTS continued\n");
    } else {
      printf("RESULTS ERROR: Child has not terminated correctly.\n");
    }
    //printf("\t\tStats from child (%d) is %d \n", child_pid, status);
    if (infinite && write(FORKSRV_FD + 1, &status, 4) != 4) {
      printf("\t\tExiting child %d with 7\n", child_pid);
      exit(7);
    }

    printf("[PARENT-FORK]\t\tEnd of Parent loop %d, finished with %d, claunch cnt = %d \n",getpid(), child_pid,  claunch_cnt);
    if (!infinite){
      printf("\t\tExiting first child...DONE\n");
      exit(0);
    }
  } // end of while infinite
}


void signal_handler(int signal){
    printf("[Witcher] caught signal, kill shm region up and exitting.\n");
    exit(33);
}


/**
 * This program requires --url
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

  string url = getArg(argc, argv, "--url", true);
  if (url.size() == 0 ){
    printf ("You must provide a url");
    exit(11);
  }

  string method = getArg(argc, argv, "--method", true);
  if (getenv("METHOD")){
      method = getenv("METHOD");
  }

  bool json = getArg(argc, argv, "--json");

  RequestData *reqD = new RequestData(url);

  reqD->setMethod(method);
  reqD->setJSON(json);
  cout << "TEST " << reqD->getURL() << " Using port:" << reqD->getPort() << endl;

  writeOutAFLSHM(reqD->getPort());

  if (getenv("__AFL_SHM_ID")){
    printf("RECEIVING AFL REQUEST\n");
    recvAFLRequests(reqD);
  } else {
    sendRequest(reqD);
  }

  delete reqD;

  return 0;
}


