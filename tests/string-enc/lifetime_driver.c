#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define LOCAL __declspec(thread)
#else
#include <pthread.h>
#include <stdatomic.h>
#define LOCAL _Thread_local
#endif

void publish_string(void);
void publish_branch(int choice);
const char *shared_string(void);
const char *table_string(int index);

static LOCAL const char *saved;
void save_string(const char *s) { saved = s; }

enum { THREADS = 16 };
static int failures[THREADS];
static const char *results[THREADS];
#ifdef _WIN32
static HANDLE start_event;
static DWORD WINAPI worker(void *arg) {
  WaitForSingleObject(start_event, INFINITE);
#else
static atomic_int start_flag;
static void *worker(void *arg) {
  while (!atomic_load_explicit(&start_flag, memory_order_acquire)) {}
#endif
  int index = *(int *)arg;
  const char *s = shared_string();
  results[index] = s;
  const char *alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (int i = 0; i < 36 * 128; ++i)
    if (s[i] != alphabet[i % 36]) failures[index] = 1;
  if (s[36 * 128] != 0) failures[index] = 1;
  for (int i = 0; i < 100; ++i) {
    publish_string();
    if (strcmp(saved, "saved after return")) failures[index] = 1;
    publish_branch(i & 1);
    if (strcmp(saved, i & 1 ? "first branch" : "second branch"))
      failures[index] = 1;
    if (strcmp(table_string(i), i & 1 ? "second entry" : "first entry"))
      failures[index] = 1;
  }
  return 0;
}

int main(void) {
  int indices[THREADS];
#ifdef _WIN32
  HANDLE threads[THREADS];
  start_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (!start_event) return 2;
#else
  pthread_t threads[THREADS];
#endif
  for (int i = 0; i < THREADS; ++i) {
    indices[i] = i;
#ifdef _WIN32
    threads[i] = CreateThread(NULL, 0, worker, &indices[i], 0, NULL);
    if (!threads[i]) return 2;
#else
    if (pthread_create(&threads[i], NULL, worker, &indices[i])) return 2;
#endif
  }
#ifdef _WIN32
  SetEvent(start_event);
#else
  atomic_store_explicit(&start_flag, 1, memory_order_release);
#endif
  int failed = 0;
  for (int i = 0; i < THREADS; ++i) {
#ifdef _WIN32
    WaitForSingleObject(threads[i], INFINITE);
    CloseHandle(threads[i]);
#else
    pthread_join(threads[i], NULL);
#endif
    failed |= failures[i];
    if (results[i] != results[0]) failed = 1;
    // The borrowed pointer must remain usable even after its reader thread exits.
    if (strcmp(results[i], results[0])) failed = 1;
  }
#ifdef _WIN32
  CloseHandle(start_event);
#endif
  puts(failed ? "FAIL" : "OK");
  return failed;
}
