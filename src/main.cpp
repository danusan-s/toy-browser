#include <iostream>
#include <url.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << " <url>" << std::endl;
    return 0;
  }
  URL test(argv[1]);
  std::cout << test.scheme() << " " << test.hostname() << " " << test.path()
            << std::endl;
  std::string response = test.request();
  std::cout << response << std::endl;
}
