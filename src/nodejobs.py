#!/usr/bin/env python
import os, sys, socket
from subprocess import Popen, PIPE

def nodejobs(nodename, pbsnodescmd='/usr/bin/pbsnodes'):
    if not os.access(pbsnodescmd, os.X_OK):
        raise ValueError('bad pbsnodes command path: %s' % pbsnodescmd)

    cmdv = [pbsnodescmd, nodename]
    p = Popen(cmdv, stdin=open(os.devnull, 'r'), stdout=PIPE,
              stderr=open(os.devnull, 'w'))
    jobs = set([])
    for s in p.stdout:
        v = [x.strip() for x in s.strip().split('=', 1)]
        if len(v) == 2 and v[0] == 'jobs':
            for proc in v[1].split(','):
                jobs.add(proc.strip().split('/')[-1].split('.')[0])
    p.stdout.close()
    p.wait()
    if p.returncode != 0 and not jobs:
        raise RuntimeError('error executing pbsnodes: %d' % p.returncode)
    return jobs

if __name__ == '__main__':
    if len(sys.argv) > 1:
        node = sys.argv[1]
    else:
        node = socket.gethostname().split('.')[0]

    try:
        for job in nodejobs(node):
            print job
    except RuntimeError, e:
        sys.stderr.write('%s\n' % e)
        sys.exit(1)

    sys.exit(0)
