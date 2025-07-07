#include "urlparser.h"
#include <iostream>

int main() {
  URL test("http://google.com/");
  std::cout << test.scheme() << " " << test.hostname() << " " << test.path()
            << std::endl;
  std::cout << test.request() << std::endl;
}
