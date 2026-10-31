#include &lt;stdio.h&gt;
#import &lt;Foundation/Foundation.h&gt;
#import &lt;rootless.h&gt;
#import "TSUtil.h"

int main(int argc, char *argv[], char *envp[]) {
@autoreleasepool {
    if (getuid() == 501) {
        // mobile user path
        if (argc &gt; 1 &amp;&amp; strcmp(argv[1], "--child") == 0) {
            exit(1);
        }
        int ret = spawnRoot(ROOT_PATH_NS(@"/usr/local/bin/TDDaemonKiller"), @[ @"/usr/local/bin/TDDaemonKiller", @"--child" ], nil, nil);
        if (ret != 0) {
            fprintf(stderr, "spawnRoot failed with code %d\n", ret);
            exit(2);
        }
        exit(0);
    }
    // Root path - kill daemons
    int err = 0;
    if (killall(@@"appstored", NO) != 0)
        err |= 1;
    if (killall(@@"installd", YES) != 0)
        err |= 2;
    if (killall(@@"AppStore", YES) != 0)
        err |= 4;

    // killall returns -1 for ESRCH (no process found), which is ok
    // it returns 0 if process was found and killed
    // if non-zero and non-ESRCH, it's a real error
    if (err != 0) {
        fprintf(stderr, "Some daemon kill operations failed\n");
        exit(1);
    }
    exit(0);
}
}
