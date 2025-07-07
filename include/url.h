#pragma once

#include <assert.h>
#include <string>
#include <sys/socket.h>

class URL {
public:
  URL(std::string url, int redirects = 0);

  std::string scheme();

  std::string hostname();

  std::string path();

  std::string request();

private:
  std::string m_scheme{""};
  std::string m_hostname{""};
  std::string m_path{""};
  std::string m_port{""};
  std::string m_full_url{""};
  int m_redirects{0};

  std::string request_file();
  std::string request_http(int sockfd, std::string request);
  std::string request_https(int sockfd, std::string request);

  std::pair<std::string, std::string> split(std::string const str,
                                            std::string const splitter);

  void strip(std::string &s, const std::string &chars = " \t\r\n");
};
