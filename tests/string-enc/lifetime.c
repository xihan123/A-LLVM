extern void save_string(const char *s);

#define BLOCK "abcdefghijklmnopqrstuvwxyz0123456789"
#define LONG4 BLOCK BLOCK BLOCK BLOCK
#define LONG16 LONG4 LONG4 LONG4 LONG4
#define LONG64 LONG16 LONG16 LONG16 LONG16

void publish_string(void) { save_string("saved after return"); }

const char *shared_string(void) { return LONG64 LONG64; }

const char *table_string(int index) {
  static const char *const entries[] = {"first entry", "second entry"};
  return entries[index & 1];
}

void publish_branch(int choice) {
  if (choice)
    save_string("first branch");
  else
    save_string("second branch");
}
