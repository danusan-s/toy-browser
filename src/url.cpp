#include "url.h"
#include <cstdlib>
#include <fcntl.h>
#include <format>
#include <iostream>
#include <netdb.h> // for getaddrinfo
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sstream>
#include <sys/socket.h> // for socket
#include <unistd.h>
#include <unordered_map>

URL::URL(std::string url) {
  if (url.size() > 5 && url.substr(0, 5) == "data:") {
    this->m_scheme = "data";
    this->m_path = url.substr(5);
    return;
  }

  auto [scheme, remain] = split(url, "://");
  this->m_scheme = scheme;

  if (this->m_scheme == "file") {
    this->m_path = remain;
    return;
  }

  auto [host_port, path] = split(remain, "/");
  auto [host, port] = split(host_port, ":");

  assert(host != "");
  this->m_hostname = host;
  this->m_path = "/" + path;

  if (this->m_port == "") {
    if (scheme == "http") {
      this->m_port = "80";
    } else if (scheme == "https") {
      this->m_port = "443";
    }
  } else {
    this->m_port = port;
  }
}

std::string URL::request() {
  if (this->m_scheme == "data") {
    auto [type, data] = split(this->m_path, ",");
    return data;
  }

  if (this->m_scheme == "file") {
    return this->request_file();
  }

  if (this->m_scheme != "http" && this->m_scheme != "https") {
    std::cerr << "Unsupported scheme: " << this->m_scheme << '\n';
    exit(EXIT_FAILURE);
  }

  addrinfo hints{}, *res;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  // Resolve domain name to IP address
  int domain_status =
      getaddrinfo(this->m_hostname.c_str(), this->m_port.c_str(), &hints, &res);
  if (domain_status != 0) {
    std::cerr << "Failed to resolve domain" << '\n';
    exit(EXIT_FAILURE);
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd < 0) {
    std::cerr << "Failed to procure socket" << '\n';
    exit(EXIT_FAILURE);
  }

  if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
    std::cerr << "Failed to connect" << '\n';
    close(sockfd);
    freeaddrinfo(res);
    exit(EXIT_FAILURE);
  }

  freeaddrinfo(res);

  std::string request =
      std::format("GET {} HTTP/1.1\r\nHost: "
                  "{}\r\nConnection:close\r\nUser-Agent:toy-browser\r\n\r\n",
                  this->m_path, this->m_hostname);
  std::string response;

  if (this->m_scheme == "https") {
    response = request_https(sockfd, request);
  } else {
    response = request_http(sockfd, request);
  }

  std::istringstream iss(response);
  std::string line;
  std::getline(iss, line);

  auto [version, stat_exp] = split(line, " ");
  auto [status, explanation] = split(stat_exp, " ");

  std::cout << "HTTP Version: " << version << "\n";
  std::cout << "Status Code: " << status << "\n";
  std::cout << "Status Explanation: " << explanation << "\n";

  std::unordered_map<std::string, std::string> response_headers;

  while (std::getline(iss, line)) {
    auto [header, value] = split(line, ":");
    if (header.empty() || value.empty()) {
      break;
    }
    strip(value);
    response_headers[header] = value;
    std::cout << header << ": " << value << "\n";
  }

  assert(response_headers.find("transfer-encoding") == response_headers.end());
  assert(response_headers.find("content-encoding") == response_headers.end());

  return iss.str().substr(iss.tellg());
}

std::string URL::request_file() {
  int fd = open(this->m_path.c_str(), O_RDONLY);
  if (fd < 0) {
    std::cerr << "Failed to open file: " << this->m_path << '\n';
    exit(EXIT_FAILURE);
  }

  std::string response;
  const int bufsize = 4096;
  char buffer[bufsize];
  ssize_t n;
  while ((n = read(fd, buffer, bufsize)) > 0) {
    response.append(buffer, n);
  }

  close(fd);

  if (n < 0) {
    std::cerr << "Failed to read file: " << this->m_path << '\n';
    exit(EXIT_FAILURE);
  }

  return response;
}

std::string URL::request_http(int sockfd, std::string request) {
  ssize_t bytes_sent = send(sockfd, request.c_str(), request.size(), 0);

  std::string response;
  const int bufsize = 4096;
  char buffer[bufsize];
  ssize_t n;

  while ((n = read(sockfd, buffer, bufsize)) > 0) {
    response.append(buffer, n);
  }

  if (n < 0) {
    std::cerr << "Failed to read response" << '\n';
    exit(EXIT_FAILURE);
  }

  close(sockfd);

  return response;
}

std::string URL::request_https(int sockfd, std::string request) {
  SSL_library_init();
  SSL_load_error_strings();
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd); // bind socket to SSL

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  SSL_write(ssl, request.c_str(), request.size());

  std::string response;
  const int bufsize = 4096;
  char buffer[bufsize];
  ssize_t n;
  while ((n = SSL_read(ssl, buffer, bufsize)) > 0) {
    response.append(buffer, n);
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(sockfd);

  return response;
}

std::string URL::scheme() { return m_scheme; }

std::string URL::hostname() { return m_hostname; }

std::string URL::path() { return m_path; }

std::pair<std::string, std::string> URL::split(std::string const str,
                                               std::string const splitter) {
  int split_index = str.find(splitter);
  if (split_index == std::string::npos) {
    return {str, ""};
  }
  return {str.substr(0, split_index),
          str.substr(split_index + splitter.size())};
}

void URL::strip(std::string &s, const std::string &chars) {
  size_t start = s.find_first_not_of(chars);
  if (start == std::string::npos) {
    s.clear();
    return;
  }

  size_t end = s.find_last_not_of(chars);
  s = s.substr(start, end - start + 1);
}
