#!/usr/bin/env python
import os, sys
from subprocess import Popen, PIPE

def jobinfo(jobid, qstatcmd='/usr/bin/qstat'):
    if not os.access(qstatcmd, os.X_OK):
        raise ValueError('bad qstat command path: %s' % qstatcmd)

    cmdv = [qstatcmd, '-f', '-1', jobid]
    p = Popen(cmdv, stdin=open(os.devnull, 'r'), stdout=PIPE,
              stderr=open(os.devnull, 'w'))
    info = {}
    for s in p.stdout:
        v = [x.strip() for x in s.split('=', 1)]
        if len(v) == 2:
            if v[0] == 'Job_Owner':
                info[v[0]] = v[1].split('@')[0]
            elif v[0] == 'exec_host':
                info[v[0]] = [x.split('/')[0] for x in v[1].split('+')]
            else:
                info[v[0]] = v[1]
    p.stdout.close()
    p.wait()
    info['returncode'] = p.returncode
    return info

if __name__ == '__main__':
    from pprint import pprint
    for k, v in jobinfo(sys.argv[1]).items():
        if k == 'exec_host':
            ex = {}
            for n in v:
                ex[n] = ex.get(n, 0) + 1
            print k, '='
            pprint(ex)
        else:
            print k, '=', v
