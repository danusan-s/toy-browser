#include <string>
#include <unordered_map>

class Cache {
public:
  static std::string get(const std::string &url) {
    auto it = cache.find(url);
    if (it != cache.end()) {
      return it->second;
    }
    return "";
  }

  static void put(const std::string &url, const std::string &data) {
    cache[url] = data;
  }

private:
  inline static std::unordered_map<std::string, std::string> cache;
};
