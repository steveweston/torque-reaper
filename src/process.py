import os, sys, re
from subprocess import Popen, PIPE

INIT = 1
KTHREADD = 2

# Return a dictionary mapping pid to process info dictionary.
# The "exempt" key in those dictionaries indicates if the
# process is exempt from being killed.
def nodeprocs():
    # Must provide extra space for "user", otherwise ps will display the
    # numeric uid instead of the username.  This is a problem with
    # usernames such as "vendortech" which are longer than 8 characters.
    pscmd = ['ps', '-e', '--no-headers',
             '--format=user:20,uid,pid,ppid,comm:20']
    p = Popen(pscmd, stdout=PIPE)
    procs = {}
    for s in p.stdout:
        user, uid, pid, ppid, comm = s.rstrip().split(None, 4)
        uid = int(uid)
        pid = int(pid)
        ppid = int(ppid)
        procs[pid] = {'user': user,
                      'uid': uid,
                      'pid': pid,
                      'ppid': ppid,
                      'comm': comm}
    p.stdout.close()
    p.wait()

    # Check for any process whose parent doesn't exist in
    # our snapshot of all of the processes.  I'm not sure if
    # this is necessary, but I'm not sure that ps guarantees
    # consistency either, so I'd like to be safe.
    for pid, proc in procs.items():
        ppid = proc['ppid']
        if ppid == 0:
            # Process 0 doesn't appear as a process in procs,
            # so don't check for it, but it should only be
            # the parent of init and kthreadd, so verify that.
            if pid not in (INIT, KTHREADD):
                raise ValueError('process %d has parent %d' % (pid, ppid))
        elif ppid not in procs:
            # The parent must have died while the ps command
            # was executing, so if this process still exists
            # (which it may not), then it must be an orphan,
            # so we'll change its parent to init.  This should
            # guarantee that the processes in procs are a single
            # tree, rooted at the hypothetical process 0, which
            # is the parent of init (process 1) and, in newer
            # Linux kernels, kthreadd (process 2).
            sys.stderr.write('parent of %d does not exist: %d\n' % \
                             (pid, ppid))
            proc['ppid'] = INIT

    return procs

# Create a dictionary mapping a pid to a list of child pids from a
# dictionary mapping a pid to process information dictionaries
def procchildren(procs):
    children = dict((pid, []) for pid in procs)
    for pid in procs:
        ppid = procs[pid]['ppid']
        if ppid > 0:
            children[ppid].append(pid)

    # Sort all child lists by pid
    for childpids in children.values():
        childpids.sort()

    return children

class ProcessList(object):
    def __init__(self):
        self._procs = nodeprocs()
        self._children = procchildren(self._procs)

    def __getitem__(self, i):
        return self._procs[i]

    def __iter__(self):
        return self._procs.iterkeys()

    def items(self):
        return self._procs.iteritems()

    def display(self, includekthreadd=False):
        # In newer versions of the Linux kernel, kthreadd is a sibling
        # of init.  In older versions, all processes are children of init.
        if includekthreadd and self._procs[KTHREADD]['ppid'] == 0:
            self._display(KTHREADD)
        self._display(INIT)

    def _display(self, pid, level=0):
        proc = self._procs[pid]
        sys.stdout.write('%5d %12s %s%s\n' % \
                         (pid, proc['user'], '. ' * level, proc['comm']))
        for c in self._children[pid]:
            self._display(c, level=level + 1)

    # Return a list of all descendants of a specified pid
    def descendants(self, pid):
        return set(self._descendants(pid, []))

    def _descendants(self, pid, d):
        for child in self._children[pid]:
            self._descendants(child, d)
        return d + self._children[pid]

    # Return the process ID of the oldest ancestor of process pid
    # which has the same user name as pid.  Processes can be
    # grouped by their "top process", which seems useful.
    def toppid(self, pid):
        proc = self._procs[pid]
        user = proc['user']
        if pid > 1:
            ppid = proc['ppid']
            pproc = self._procs[ppid]
            puser = pproc['user']
            while user == puser and ppid > 1:
                # "proc" isn't the top proc, so go up another level
                pid = ppid
                proc = pproc
                ppid = proc['ppid']
                pproc = self._procs[ppid]
                puser = pproc['user']
        return pid

    # Return a set of PID's containing a specified PID and
    # all its ancestors up to and including init (PID 1)
    def ancestors(self, pid):
        pids = [pid]
        pid = self._procs[pid]['ppid']
        while pid > 0:
            pids.append(pid)
            pid = self._procs[pid]['ppid']
        return set(pids)

if __name__ == '__main__':
    procs = ProcessList()
    procs.display(includekthreadd=True)
