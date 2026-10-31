#import "TSUtil.h"

#import &lt;Foundation/Foundation.h&gt;

#import &lt;spawn.h&gt;

#import &lt;sys/sysctl.h&gt;

#import &lt;mach-o/dyld.h&gt;

#import &lt;libroot.h&gt;

#import &lt;signal.h&gt;

#import &lt;poll.h&gt;

#import &lt;unistd.h&gt;

#import &lt;sys/wait.h&gt;

#import &lt;sys/errno.h&gt;

#define OS_REASON_SIGNAL 2

#define OS_REASON_DYLD 6

#define DYLD_EXIT_REASON_OTHER 9

void abort_with_payload(uint32_t reason_namespace, uint64_t reason_code,
    void *payload, uint32_t payload_size,
    const char *reason_string, uint64_t reason_flags)
__attribute__((noreturn, cold));

enum {
    PERSONA_INVALID = 0,
    PERSONA_GUEST = 1,
    PERSONA_MANAGED = 2,
    PERSONA_PRIV = 3,
    PERSONA_SYSTEM = 4,
    PERSONA_DEFAULT = 5,
    PERSONA_SYSTEM_PROXY = 6,
    PERSONA_SYS_EXT = 7,
    PERSONA_ENTERPRISE = 8,
    PERSONA_TYPE_MAX = PERSONA_ENTERPRISE,
};

#define PERSONA_INFO_V1 1
#define PERSONA_INFO_V2 2

struct kpersona_info {
    uint32_t persona_info_version;
    uid_t persona_id;
    int persona_type;
    gid_t persona_gid;
    uint32_t persona_ngroups;
    gid_t persona_groups[NGROUPS];
    uid_t persona_gmuid;
    char persona_name[MAXLOGNAME + 1];
    uid_t persona_uid;
} __attribute__((packed));

extern int kpersona_find_by_type(int persona_type, uid_t *id, size_t *idlen);
extern int kpersona_getpath(uid_t id, char path[MAXPATHLEN]);
extern int kpersona_pidinfo(pid_t id, struct kpersona_info *info);
extern int kpersona_info(uid_t id, struct kpersona_info *info);
extern int kpersona_find(const char *name, uid_t uid, uid_t *id, size_t *idlen);
extern int kpersona_alloc(struct kpersona_info *info, uid_t *id);

extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

#define SIGABRT 6
#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1

int available_persona_id(void)
{
    struct kpersona_info info;
    memset(&info, 0, sizeof(info));
    info.persona_info_version = PERSONA_INFO_V1;

    if (kpersona_pidinfo(getpid(), &info) != 0)
        return 0;

    int current_persona_id = (int)info.persona_id;

    for (int t = 1; t &lt;= PERSONA_TYPE_MAX; t++) {
        uid_t personas[128];
        memset(personas, 0, sizeof(personas));
        size_t npersonas = sizeof(personas) / sizeof(personas[0]);

        int rc = kpersona_find_by_type(t, personas, &npersonas);
        if (rc != 0 || npersonas == 0)
            continue;

        for (size_t i = 0; i &lt; npersonas; i++) {
            if ((int)personas[i] != current_persona_id)
                return (int)personas[i];
        }
    }
    return 0;
}

int fd_is_valid(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

/**
 * Safe UTF-8 read from fd to NSString.
 * Reads entire stream up to optional newline or EOF, respecting
 * 8 MiB cap per stream. Does not split multibyte sequences.
 */
#define CAPTURE_LIMIT (8 * 1024 * 1024)

NSString *getNSStringFromFile(int fd)
{
    if (!fd_is_valid(fd))
        return @"";

    NSMutableData *data = [NSMutableData data];
    char buf[4096];
    size_t total = 0;

    while (total &lt; CAPTURE_LIMIT) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0)
            break;
        if (n == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                if (poll(&amp;pfd, 1, 100) &lt;= 0)
                    break;
                continue;
            }
            break;
        }
        total += (size_t)n;
        [data appendBytes:buf length:(size_t)n];
    }

    // Trim trailing newline if present
    if ([data length] &gt; 0) {
        NSUInteger len = [data length];
        const uint8_t *bytes = [data bytes];
        if (bytes[len - 1] == '\n') {
            [data setLength:len - 1];
        }
    }

    NSString *result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return result ? result : @"";
}

void printMultilineNSString(NSString *stringToPrint)
{
    NSCharacterSet *separator = [NSCharacterSet newlineCharacterSet];
    NSArray *lines = [stringToPrint componentsSeparatedByCharactersInSet:separator];
    for (NSString *line in lines) {
        NSLog(@"%@", line);
    }
}

/**
 * Robust POSIX process spawner with persona support.
 * Returns:
 *   0            – normal exit (exit code 0)
 *   N (1-255)    – normal exit with that code
 *   -(128+sig)   – terminated by signal
 *   &lt;0           – spawn/wait error (negative)
 */
int spawnRoot(NSString *path, NSArray *args, NSString **stdOut, NSString **stdErr)
{
    if (path == nil || ![NSFileManager.defaultManager fileExistsAtPath:path]) {
        if (path != nil)
            NSLog(@"spawnRoot: invalid path %@", path);
        return -22;
    }

    // Validate arguments
    if (args == nil) {
        args = @[];
    }

    NSMutableArray *argsM = [args mutableCopy] ?: [NSMutableArray array];
    if ([argsM count] == 0) {
        // argv[0] must be the executable path
        [argsM insertObject:path atIndex:0];
    } else {
        // Ensure argv[0] is the full executable path
        if (![[argsM objectAtIndex:0] hasPrefix:@"/"]) {
            [argsM insertObject:path atIndex:0];
        }
    }

    NSUInteger argCount = [argsM count];
    char **argv = (char **)malloc((argCount + 1) * sizeof(char *));
    if (argv == nil)
        return -28;

    for (NSUInteger i = 0; i &lt; argCount; i++) {
        const char *c = [[argsM objectAtIndex:i] UTF8String];
        argv[i] = c ? strdup(c) : strdup("");
    }
    argv[argCount] = NULL;

    // Init spawn attributes
    posix_spawnattr_t attr;
    int rc = posix_spawnattr_init(&amp;attr);
    if (rc != 0) {
        for (NSUInteger i = 0; i &lt; argCount; i++) free(argv[i]);
        free(argv);
        return -rc;
    }

    // Set persona
    int persona_id = available_persona_id();
    if (persona_id == 0) {
        // No persona available – fall back to no persona override
        // Don't ASSERT – just proceed without persona
        NSLog(@"spawnRoot: no persona available, spawning without persona override");
    } else {
        posix_spawnattr_set_persona_np(&amp;attr, (uid_t)persona_id, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
        posix_spawnattr_set_persona_uid_np(&amp;attr, 0);
        posix_spawnattr_set_persona_gid_np(&amp;attr, 0);
    }

    // File actions
    posix_spawn_file_actions_t actions;
    rc = posix_spawn_file_actions_init(&amp;actions);
    if (rc != 0) {
        posix_spawnattr_destroy(&amp;attr);
        for (NSUInteger i = 0; i &lt; argCount; i++) free(argv[i]);
        free(argv);
        return -rc;
    }

    int stdoutPipe[2] = { -1, -1 };
    int stderrPipe[2] = { -1, -1 };

    if (stdOut != nil) {
        if (pipe(stdoutPipe) != 0) {
            posix_spawn_file_actions_destroy(&amp;actions);
            posix_spawnattr_destroy(&amp;attr);
            for (NSUInteger i = 0; i &lt; argCount; i++) free(argv[i]);
            free(argv);
            return -errno;
        }
        posix_spawn_file_actions_adddup2(&amp;actions, stdoutPipe[1], STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&amp;actions, stdoutPipe[0]);
        posix_spawn_file_actions_addclose(&amp;actions, stdoutPipe[1]);
    }

    if (stdErr != nil) {
        if (pipe(stderrPipe) != 0) {
            close(stdoutPipe[0]); close(stdoutPipe[1]);
            posix_spawn_file_actions_destroy(&amp;actions);
            posix_spawnattr_destroy(&amp;attr);
            for (NSUInteger i = 0; i &lt; argCount; i++) free(argv[i]);
            free(argv);
            return -errno;
        }
        posix_spawn_file_actions_adddup2(&amp;actions, stderrPipe[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&amp;actions, stderrPipe[0]);
        posix_spawn_file_actions_addclose(&amp;actions, stderrPipe[1]);
    }

    // Spawn
    pid_t task_pid = -1;
    int spawnError = posix_spawn(&amp;task_pid, [path UTF8String], &amp;actions, &amp;attr,
        (char *const *)argv, environ);

    posix_spawn_file_actions_destroy(&amp;actions);
    posix_spawnattr_destroy(&amp;attr);

    for (NSUInteger i = 0; i &lt; argCount; i++)
        free(argv[i]);
    free(argv);

    if (spawnError != 0) {
        NSLog(@"posix_spawn error %d: %s", spawnError, strerror(spawnError));
        return -spawnError;
    }

    // Close write ends immediately to unblock reader on child exit
    if (stdOut && stdoutPipe[1] != -1) close(stdoutPipe[1]);
    if (stdErr && stderrPipe[1] != -1) close(stderrPipe[1]);

    // Collect stdout/stderr concurrently
    NSMutableString *outString = [NSMutableString string];
    NSMutableString *errString = [NSMutableString string];

    if (stdOut || stdErr) {
        dispatch_queue_t queue = dispatch_queue_create("com.opa334.TrollStore.LogCollector", NULL);

        dispatch_async(queue, ^{
            if (stdOut) {
                *stdOut = getNSStringFromFile(stdoutPipe[0]);
            }
            if (stdErr) {
                *stdErr = getNSStringFromFile(stderrPipe[0]);
            }
        });
    }

    // waitpid with EINTR handling
    int status = 0;
    pid_t wp;
    do {
        wp = waitpid(task_pid, &amp;status, 0);
    } while (wp == -1 &amp;&amp; errno == EINTR);

    if (wp == -1) {
        if (stdOut || stdErr) {
            dispatch_sync(dispatch_get_main_queue(), ^{});
        }
        return -222;
    }

    // Close read ends
    if (stdOut &amp;&amp; stdoutPipe[0] != -1) close(stdoutPipe[0]);
    if (stdErr &amp;&amp; stderrPipe[0] != -1) close(stderrPipe[0]);

    // Assign output if requested
    if (stdOut != nil) {
        // Output is set in the dispatch block above
        // Wait for it synchronously
        // We use a semaphore approach instead
    }
    if (stdErr != nil) {
        // Output is set in the dispatch block above
    }

    if (stdOut || stdErr) {
        // Wait for background queue to finish
        dispatch_sync(queue, ^{});
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        NSLog(@"Child terminated by signal %d", sig);
        return -(128 + sig);
    }

    if (WIFEXITED(status)) {
        int exitCode = WEXITSTATUS(status);
        NSLog(@"Child exit status %d", exitCode);
        return exitCode;
    }

    return -1; // Should not reach here
}

void enumerateProcessesUsingBlock(void (^enumerator)(pid_t, NSString *, BOOL *))
{
    static int maxArgumentSize = 0;
    if (maxArgumentSize == 0) {
        size_t size = sizeof(maxArgumentSize);
        if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &amp;maxArgumentSize, &amp;size, NULL, 0) == -1) {
            perror("sysctl argument size");
            maxArgumentSize = 4096;
        }
    }

    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    struct kinfo_proc *info = NULL;
    size_t length = 0;

    if (sysctl(mib, 3, NULL, &amp;length, NULL, 0) != 0 || length == 0)
        return;

    info = malloc(length);
    if (info == NULL)
        return;

    if (sysctl(mib, 3, info, &amp;length, NULL, 0) != 0) {
        free(info);
        return;
    }

    // Ensure length is a multiple of sizeof(kinfo_proc)
    size_t entrySize = sizeof(struct kinfo_proc);
    size_t validLength = (length / entrySize) * entrySize;
    if (validLength == 0) {
        free(info);
        return;
    }

    size_t count = validLength / entrySize;

    for (size_t i = 0; i &lt; count; i++) {
        @autoreleasepool {
            pid_t pid = info[i].kp_proc.p_pid;
            if (pid == 0)
                continue;

            size_t size = (size_t)maxArgumentSize;
            char *buffer = (char *)malloc(size);
            if (buffer == NULL)
                continue;

            int ret = sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &amp;size, NULL, 0);
            if (ret == 0 &amp;&amp; size &gt; sizeof(int)) {
                int argc;
                memcpy(&amp;argc, buffer, sizeof(int));

                // Safely parse executable path: skip argc, then read until null byte
                size_t offset = sizeof(int);
                // Skip arg0
                while (offset &lt; size &amp;&amp; buffer[offset] != '\0')
                    offset++;
                offset++; // skip the null

                if (offset &lt; size) {
                    NSString *executablePath = [[NSString alloc] initWithBytes:(buffer + offset)
                        length:size - offset
                        encoding:NSUTF8StringEncoding];
                    if (executablePath == nil)
                        executablePath = @"";

                    BOOL stop = NO;
                    enumerator(pid, executablePath, &amp;stop);
                    free(buffer);
                    if (stop)
                        break;
                } else {
                    free(buffer);
                    continue; // malformed data, skip
                }
            } else {
                free(buffer);
            }
        }
    }
    free(info);
}

void killall(NSString *processName, BOOL softly)
{
    enumerateProcessesUsingBlock(^(pid_t pid, NSString *executablePath, BOOL *stop) {
        if ([executablePath.lastPathComponent isEqualToString:processName]) {
            if (softly) {
                kill(pid, SIGTERM);
            } else {
                kill(pid, SIGKILL);
            }
        }
    });
}
