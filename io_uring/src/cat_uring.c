#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#define __USE_MISC // for syscall definition
#include <unistd.h>

/* If your compilation fails because the header file below is missing,
 * your kernel is probably too old to support io_uring.
 * */
#include <linux/io_uring.h>

#define QUEUE_DEPTH 1
#define BLOCK_SZ 1024

/* This is x86 specific */
#define read_barrier() __asm__ __volatile__("" ::: "memory")
#define write_barrier() __asm__ __volatile__("" ::: "memory")

struct app_io_sq_ring {
  unsigned *head;
  unsigned *tail;
  unsigned *ring_mask;
  unsigned *ring_entries;
  unsigned *flags;
  unsigned *array;
};

struct app_io_cq_ring {
  unsigned *head;
  unsigned *tail;
  unsigned *ring_mask;
  unsigned *ring_entries;
  struct io_uring_cqe *cqes;
};

struct submitter {
  int ring_fd;
  struct app_io_sq_ring sq_ring;
  struct io_uring_sqe *sqes;
  struct app_io_cq_ring cq_ring;
};

struct file_info {
  off_t file_sz;
  struct iovec iovecs[]; /* Referred by readv/writev */
};

/*
 * This code is written in the days when io_uring-related system calls are not
 * part of standard C libraries. So, we roll our own system call wrapper
 * functions.
 * */

static int io_uring_setup(unsigned entries, struct io_uring_params *params) {
  return (int)syscall(__NR_io_uring_setup, entries, params);
}

static int io_uring_enter(int ring_fd, unsigned int to_submit,
                          unsigned int min_complete, unsigned int flags) {
  return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete,
                      flags, NULL, 0);
}

/*
 * Returns the size of the file whose open file descriptor is passed in.
 * Properly handles regular file and block devices as well. Pretty.
 * */

static off_t get_file_size(int fd) {
  struct stat stat;

  if (fstat(fd, &stat) < 0) {
    perror("fstat");
    return -1;
  }

  if (S_ISBLK(stat.st_mode)) {
    auto bytes = 0;
    if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
      perror("ioctl");
      return -1;
    }
    return bytes;
  }

  if (S_ISREG(stat.st_mode)) {
    return stat.st_size;
  }

  return -1;
}

/*
 * io_uring requires a lot of setup which looks pretty hairy, but isn't all
 * that difficult to understand. Because of all this boilerplate code,
 * io_uring's author has created liburing, which is relatively easy to use.
 * However, you should take your time and understand this code. It is always
 * good to know how it all works underneath. Apart from bragging rights,
 * it does offer you a certain strange geeky peace.
 * */

static int app_setup_uring(struct submitter *sub) {
  struct io_uring_params params;
  /*
   * We need to pass in the io_uring_params structure to the io_uring_setup()
   * call zeroed out. We could set any flags if we need to, but for this
   * example, we don't.
   * */
  memset(&params, 0, sizeof(params));
  sub->ring_fd = io_uring_setup(QUEUE_DEPTH, &params);
  if (sub->ring_fd < 0) {
    perror("io_uring_setup");
    return 1;
  }

  /*
   * io_uring communication happens via 2 shared kernel-user space ring buffers,
   * which can be jointly mapped with a single mmap() call in recent kernels.
   * While the completion queue is directly manipulated, the submission queue
   * has an indirection array in between. We map that in as well.
   * */

  auto sring_sz = params.sq_off.array + (params.sq_entries * sizeof(unsigned));
  auto cring_sz =
      params.cq_off.cqes + (params.cq_entries * sizeof(struct io_uring_cqe));

  /* In kernel version 5.4 and above, it is possible to map the submission and
   * completion buffers with a single mmap() call. Rather than check for kernel
   * versions, the recommended way is to just check the features field of the
   * io_uring_params structure, which is a bit mask. If the
   * IORING_FEAT_SINGLE_MMAP is set, then we can do away with the second mmap()
   * call to map the completion ring.
   * */
  if (params.features & IORING_FEAT_SINGLE_MMAP) {
    if (cring_sz > sring_sz) {
      sring_sz = cring_sz;
    }
    cring_sz = sring_sz;
  }

  /* Map in the submission and completion queue ring buffers.
   * Older kernels only map in the submission queue, though.
   * */
  void *sq_ptr =
      mmap(nullptr, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           sub->ring_fd, IORING_OFF_SQ_RING);
  if (sq_ptr == MAP_FAILED) {
    perror("mmap");
    munmap(sq_ptr, sring_sz);
    return 1;
  }

  void *cq_ptr = nullptr;
  if (params.features & IORING_FEAT_SINGLE_MMAP) {
    cq_ptr = sq_ptr;
  } else {
    /* Map in the completion queue ring buffer in older kernels separately */
    cq_ptr = mmap(nullptr, cring_sz, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, sub->ring_fd, IORING_OFF_CQ_RING);
    if (cq_ptr == MAP_FAILED) {
      perror("mmap");
      munmap(sq_ptr, sring_sz);
      return 1;
    }
  }

  struct app_io_sq_ring *sring = &sub->sq_ring;
  struct app_io_cq_ring *cring = &sub->cq_ring;

  /* Save useful fields in a global app_io_sq_ring struct for later
   * easy reference */
  sring->head = sq_ptr + params.sq_off.head;
  sring->tail = sq_ptr + params.sq_off.tail;
  sring->ring_mask = sq_ptr + params.sq_off.ring_mask;
  sring->ring_entries = sq_ptr + params.sq_off.ring_entries;
  sring->flags = sq_ptr + params.sq_off.flags;
  sring->array = sq_ptr + params.sq_off.array;

  /* Map in the submission queue entries array */
  sub->sqes = mmap(nullptr, params.sq_entries * sizeof(struct io_uring_sqe),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   sub->ring_fd, IORING_OFF_SQES);
  if (sub->sqes == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  /* Save useful fields in a global app_io_cq_ring struct for later
   * easy reference */
  cring->head = cq_ptr + params.cq_off.head;
  cring->tail = cq_ptr + params.cq_off.tail;
  cring->ring_mask = cq_ptr + params.cq_off.ring_mask;
  cring->ring_entries = cq_ptr + params.cq_off.ring_entries;
  cring->cqes = cq_ptr + params.cq_off.cqes;

  return 0;
}

/*
 * Output a string of characters of len length to stdout.
 * We use buffered output here to be efficient,
 * since we need to output character-by-character.
 * */
static void output_to_console(char *buf, size_t len) {
  while (len--) {
    (void)fputc(*buf++, stdout);
  }
}

/*
 * Read from completion queue.
 * In this function, we read completion events from the completion queue, get
 * the data buffer that will have the file data and print it to the console.
 * */

static void read_from_cq(struct submitter *sub) {
  struct app_io_cq_ring *cring = &sub->cq_ring;

  unsigned head = *cring->head;

  do {
    read_barrier();
    /*
     * Remember, this is a ring buffer. If head == tail, it means that the
     * buffer is empty.
     * */
    if (head == *cring->tail) {
      break;
    }

    /* Get the entry */
    struct io_uring_cqe *cqe = &cring->cqes[head & *sub->cq_ring.ring_mask];

    auto file_info = (struct file_info *)cqe->user_data;
    if (cqe->res < 0) {
      (void)fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
    }

    int blocks = (int)file_info->file_sz / BLOCK_SZ;
    if (file_info->file_sz % BLOCK_SZ) {
      blocks++;
    }

    for (int index = 0; index < blocks; index++) {
      output_to_console(file_info->iovecs[index].iov_base,
                        file_info->iovecs[index].iov_len);
    }

    head++;
  } while (1);

  *cring->head = head;
  write_barrier();
}
/*
 * Submit to submission queue.
 * In this function, we submit requests to the submission queue. You can submit
 * many types of requests. Ours is going to be the readv() request, which we
 * specify via IORING_OP_READV.
 *
 * */
static int submit_to_sq(char *file_path, struct submitter *sub) {

  int file_fd = open(file_path, O_RDONLY | O_CLOEXEC);
  if (file_fd < 0) {
    perror("open");
    return 1;
  }

  off_t file_sz = get_file_size(file_fd);
  if (file_sz < 0) {
    return 1;
  }
  off_t bytes_remaining = file_sz;
  auto blocks = (size_t)file_sz / BLOCK_SZ;
  if (file_sz % BLOCK_SZ) {
    blocks++;
  }

  struct file_info *fileinfo =
      malloc(sizeof(struct file_info) + (sizeof(struct iovec) * blocks));
  if (!fileinfo) {
    (void)fprintf(stderr, "Unable to allocate memory\n");
    return 1;
  }
  fileinfo->file_sz = file_sz;

  /*
   * For each block of the file we need to read, we allocate an iovec struct
   * which is indexed into the iovecs array. This array is passed in as part
   * of the submission. If you don't understand this, then you need to look
   * up how the readv() and writev() system calls work.
   * */
  unsigned current_block = 0;
  while (bytes_remaining) {
    ssize_t bytes_to_read = bytes_remaining;
    if (bytes_to_read > BLOCK_SZ) {
      bytes_to_read = BLOCK_SZ;
    }

    void *buf = nullptr;
    if (posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ)) {
      perror("posix_memalign");
      free(fileinfo);
      return 1;
    }
    fileinfo->iovecs[current_block] =
        (struct iovec){.iov_base = buf, .iov_len = (size_t)bytes_to_read};

    current_block++;
    bytes_remaining -= bytes_to_read;
  }

  auto sring = &sub->sq_ring;
  /* Add our submission queue entry to the tail of the SQE ring buffer */
  auto tail = *sring->tail;
  auto next_tail = *sring->tail;
  next_tail++;
  read_barrier();
  auto index = tail & *sub->sq_ring.ring_mask;
  struct io_uring_sqe *sqe = &sub->sqes[index];
  sqe->fd = file_fd;
  sqe->flags = 0;
  sqe->opcode = IORING_OP_READV;
  sqe->addr = (uint64_t)fileinfo->iovecs;
  sqe->len = (uint32_t)blocks;
  sqe->off = 0;
  sqe->user_data = (uint64_t)fileinfo;
  sring->array[index] = index;
  tail = next_tail;

  /* Update the tail so the kernel can see it. */
  if (*sring->tail != tail) {
    *sring->tail = tail;
    write_barrier();
  }

  /*
   * Tell the kernel we have submitted events with the io_uring_enter() system
   * call. We also pass in the IOURING_ENTER_GETEVENTS flag which causes the
   * io_uring_enter() call to wait until min_complete events (the 3rd param)
   * complete.
   * */
  int ret = io_uring_enter(sub->ring_fd, 1, 1, IORING_ENTER_GETEVENTS);
  if (ret < 0) {
    perror("io_uring_enter");
    return 1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    (void)fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
    return 1;
  }

  struct submitter *sub = malloc(sizeof(struct submitter));
  if (!sub) {
    perror("malloc");
    return 1;
  }
  memset(sub, 0, sizeof(*sub));

  if (app_setup_uring(sub)) {
    (void)fprintf(stderr, "Unable to setup uring!\n");
    free(sub);
    return 1;
  }

  for (int i = 1; i < argc; i++) {
    if (submit_to_sq(argv[i], sub)) {
      (void)fprintf(stderr, "Error reading file\n");
      free(sub);
      return 1;
    }
    read_from_cq(sub);
  }

  free(sub);
  return 0;
}
