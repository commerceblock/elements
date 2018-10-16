// From -> https://github.com/jlopp/statoshi

#ifndef STATSD_CLIENT_H
#define STATSD_CLIENT_H

#include <arpa/inet.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

namespace statsd {

using namespace std;

struct _StatsdClientData {
  int sock;
  struct sockaddr_in server;
  string ns;
  string host;
  string nodename;
  short port;
  bool init;
  char errmsg[1024];
};

class StatsdClient {
  public:
    StatsdClient(void);
    StatsdClient(const string& host, int port, const string& ns);
    ~StatsdClient();
    // you can config at anytime; client will use new address (useful for Singleton)
    void config(const string& host, int port, const string& ns = "");
    const char* errmsg();
    int inc(const string& key, float sample_rate = 1.0);
    int dec(const string& key, float sample_rate = 1.0);
    int count(const string& key, size_t value, float sample_rate = 1.0);
    int gauge(const string& key, size_t value, float sample_rate = 1.0);
    int timing(const string& key, size_t ms, float sample_rate = 1.0);
    /*
     * (Low Level Api) manually send a message
     * which might be composed of several lines.
     */
    int send(const string& message);
    /* (Low Level Api) manually send a message
     * type = "c", "g" or "ms"
     */
    int send(string key, size_t value, const string& type, float sample_rate);

  protected:
    int init();
    void cleanup(string& key);
    struct _StatsdClientData* d;
};
} // namespace statsd

#endif
