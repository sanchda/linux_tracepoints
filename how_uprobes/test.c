#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BAD_ADDR (-1UL)
#define HX PRIx64

typedef struct uprobe {
  const char *grp;
  const char *event;
  const char *path;
  uint64_t offset;
  const char *fetchargs;
} uprobe;

typedef struct region {
  uint64_t start_addr;
  uint64_t end_addr;
  uint64_t offset;
  char flags[4];
  char path[1024];
} region;

// Functions can be cast to other functions, but they can't be interpreted as
// pointers.  This is a workaround.
typedef union function_hack {
  uint64_t integer;
  void (*function);
} function_hack;

region* addr2reg(uint64_t addr) {
  static region ret = {0};
  static char proc_map[] = "/proc/self/maps";
  FILE *pmap = fopen(proc_map, "r");
  if (!pmap)
    return NULL;

  // Iterate until our desired address is located
  char *buf = malloc(4096);
  size_t sz_buf = 0;
  while (-1 != getline(&buf, &sz_buf, pmap)) {
    uint64_t addrl, addrr, off;
    char flags[4] = {0};
    char *path = malloc(1024);

    const char *fmt = "%lx-%lx %4c %lx %*x:%*x %*x %s";

    // Skip anon for this implementation
    if (sscanf(buf, fmt, &addrl, &addrr, (char *)&flags, &off, path) < 5)
      continue;

    // Bounds check
    if (addrl <= addr && addrr > addr) {
      ret.start_addr = addrl;
      ret.end_addr = addrr;
      ret.offset = off;
      memcpy(ret.flags, flags, sizeof(flags));
      strncpy(ret.path, path, sizeof(ret.path));
      free(buf);
      return &ret;
    }
  }

  // Didn't find anything...
  free(buf);
  return NULL;
}

bool uprobe_set(uprobe *up, bool enable) {
  if (!up)
    return false;

  // Enable the group
  {
    static char grouppath[1024] = {0};
    snprintf(grouppath, sizeof(grouppath), "/sys/kernel/tracing/events/%s/enable", up->grp);
    int fd = open(grouppath, O_WRONLY);
    write(fd, enable ? "1" : "0", 1);
    close(fd);
  }

  // Enable the event
  {
    static char eventpath[1024] = {0};
    snprintf(eventpath, sizeof(eventpath), "/sys/kernel/tracing/events/%s/%s/enable", up->grp, up->event);
    int fd = open(eventpath, O_WRONLY);
    write(fd, enable ? "1" : "0", 1);
    close(fd);
  }

  return true; // could do a lot more checks...
}


bool uprobe_remove_fd(uprobe *up, int fd) {
  if (-1 == fd)
    return false;

  // Before we remove the event, have to make sure it's disabled
  uprobe_set(up, false);

  static char probeline[1024] = {0};
  size_t sz = snprintf(probeline, sizeof(probeline), "-:%s/%s", up->grp, up->event);
  bool ret = 0 <= write(fd, probeline, sz);
  // ret/errno can be checked to figure out why removal failed
  // e.g., ENOENT after write() means the probe did not exist
  return ret;
}

bool uprobe_remove(uprobe *up) {
  int fd = open("/sys/kernel/tracing/uprobe_events", O_WRONLY);
  bool ret = uprobe_remove_fd(up, fd);
  close(fd);
  return ret;
}

bool uprobe_install(uprobe *up) {
  if (!up)
    return false;
  int fd = open("/sys/kernel/tracing/uprobe_events", O_WRONLY);
  if (-1 == fd)
    return false;

  // Try to remove the uprobe if one was installed.  Don't do anything on fail.
  uprobe_remove_fd(up, fd);

  static char probeline[1024] = {0};
  size_t sz = snprintf(probeline, sizeof(probeline),
                "p:%s/%s %s:0x%lx", up->grp, up->event, up->path, up->offset);
  bool ret = 0 <= write(fd, probeline, sz);
  close(fd);
  return ret;
}

void print_around_addr(uint64_t addr) {
  unsigned char *ptr = (unsigned char *)addr;
  for (int i = -8; i < 8; i++)
    printf("%02x ", ptr[i]);
  printf("\n");
  for (int i = -8; i < 8; i++)
    printf("%c  ", !i ? '^' : ' ');
  printf("\n");
}

int main() {
  uint64_t malloc_addr = (function_hack){.function = malloc}.integer;
  region *reg = addr2reg(malloc_addr);
  uint64_t uaddr = malloc_addr - reg->start_addr + reg->offset; // Compute offset in file
  uprobe umalloc = {.grp = "libc", .event = "malloc", .path = reg->path, .offset = uaddr};

  // Remove the uprobe if it exists.  There may be one with a different name,
  // but for test purposes let's just do it this way.
  uprobe_remove(&umalloc);

  // Print the contents around that address
  print_around_addr(malloc_addr);

  // Define a uprobe, then install it
  if (!uprobe_install(&umalloc)) {
    printf("Something went wrong installing %s/%s\n", umalloc.grp, umalloc.event);
    return -1;
  }
  uprobe_set(&umalloc, true);

  // Print the area again
  print_around_addr(malloc_addr);
  return 0;
}
