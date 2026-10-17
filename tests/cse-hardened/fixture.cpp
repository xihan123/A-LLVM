#include <atomic>
#include <cstring>
#include <thread>

static const char* saved;
static std::atomic<unsigned> failure{0};
static const char* aggregate[] = {"NDKP_HARDENED_secret_19a7", "second entry"};
static const char16_t* wide = u"wide \u4e2d\u6587";
static const char* get() { return "NDKP_HARDENED_secret_19a7"; }
__attribute__((constructor(102))) static void early() { saved = get(); }
extern "C" __attribute__((visibility("default"))) const char* get_secret() { return saved; }
extern "C" __attribute__((visibility("default"))) const char16_t* get_wide() { return wide; }
extern "C" __attribute__((visibility("default"))) const char* get_lazy_secret() {
  return "NDKP_LAZY_SECRET_7731";
}
extern "C" __attribute__((visibility("default"))) const unsigned char* get_binary() {
  static const unsigned char bytes[] = {0xfe, 0xff, 1};
  return bytes;
}
extern "C" __attribute__((visibility("default"))) const char16_t* get_words() {
  static const char16_t words[] = {0x1234, 0xabcd};
  return words;
}
extern "C" const char* other_secret();
extern "C" __attribute__((visibility("default"))) int run() {
  // References and escaped pointers must retain static storage lifetime.
  std::thread workers[8];
  for (auto& worker : workers) worker = std::thread([] {
    for (unsigned i = 0; i < 64; ++i) {
      const char* text = get();
      if (text != saved) failure = 11;
      if (std::strlen(text) != 25) failure = 12;
      if (std::strcmp(text, aggregate[0])) failure = 13;
      if (std::strcmp(other_secret(), "other translation unit")) failure = 14;
    }
  });
  for (auto& worker : workers) worker.join();
  if (failure) return int(failure.load());
  if (saved != get()) return 15;
  return wide[5] == u'\u4e2d' && wide[6] == u'\u6587' && wide[7] == 0 ? 0 : 16;
}
