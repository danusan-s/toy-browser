#include "url.h"
#include <cstdlib>
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
  auto [scheme, remain] = split(url, "://");
  assert(scheme == "http");
  this->m_scheme = scheme;

  auto [host_port, path] = split(remain, "/");
  auto [host, port] = split(host_port, ":");
  assert(host != "");
  this->m_hostname = host;
  this->m_path = "/" + path;
  this->m_port = port;

  if (this->m_port == "") {
    if (scheme == "http") {
      this->m_port = "80";
    } else if (scheme == "https") {
      this->m_port = "443";
    }
  }
}

std::string URL::request() {
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

  std::string request = std::format("GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
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

std::string URL::request_http(int sockfd, std::string request) {
  ssize_t bytes_sent = send(sockfd, request.c_str(), request.size(), 0);

  std::string response;
  const int bufsize = 4096;
  char buffer[bufsize];
  ssize_t n;

  while ((n = read(sockfd, buffer, bufsize - 1)) > 0) {
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
  char buffer[4096];
  ssize_t n;
  while ((n = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
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
