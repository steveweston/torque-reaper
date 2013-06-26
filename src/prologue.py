import os, sys, re, socket, time, signal
from process import ProcessList
from nodeusers import nodeusers

NODE = socket.gethostname().split('.')[0]
SYSTHRESHOLD = 500

# Return a dictionary containing the environment variables 
# of the specified pid
def getenviron(logger, pid):
    try:
        fname = '/proc/%d/environ' % pid
        fobj = open(fname, 'rb')
        try:
            d = fobj.read()
            if not d:
                # I've seen some processes with empty environ files
                env = {}
            elif d[-1] != '\0':
                raise ValueError('bad environ file: ' + fname)
            else:
                v = [x for x in d.rstrip('\0').split('\0')]
                bad = False
                for x in v:
                    if x and x.find('=') <= 0:
                        bad = True
                        logger.debug('bad environ string: %r' % x)
                if bad:
                    logger.debug('environ of PID %d: %r' % (pid, d))
                env = dict([x.split('=', 1) for x in v if x.find('=') > 0])
        finally:
            fobj.close()
    except Exception, e:
        # This can happen because the process just died
        logger.debug('unable to get environment of pid %d' % pid)
        env = {}

    return env

# Kill the rogue processes
def killprocs(logger, pids):
    def _killprocs(pids, signame):
        sig = getattr(signal, signame)
        npids = []
        for pid in pids:
            try:
                logger.debug('sending %s to pid %d' % (signame, pid))
                os.kill(pid, sig)
                npids.append(pid)
            except OSError, e:
                # May be "No such process", or
                # "Operation not permitted" if you're not root
                logger.debug('caught OSError: %s' % str(e))
            except Exception, e:
                logger.warning('caught unexpected exception: %s' % str(e))
        return npids

    pids = _killprocs(pids, 'SIGCONT')
    time.sleep(1)
    pids = _killprocs(pids, 'SIGTERM')
    time.sleep(5)
    _killprocs(pids, 'SIGKILL')

# This is called from the "prologue" and "prologue.parallel" scripts
# in order to detect rogue processes on the current node.
def main(logger, config, xjobids=[]):
    # If not enabled, return immediately
    if not config.enabled:
        logger.info('prologue is disabled: doing nothing')
        return 0

    pbs_home = config.pbs_home
    if not os.path.exists(pbs_home) or not os.path.isdir(pbs_home):
        raise ValueError('bad PBS_HOME directory: %s' % pbs_home)

    jobsdir = os.path.join(pbs_home, 'mom_priv', 'jobs')
    if not os.path.exists(jobsdir) or not os.path.isdir(jobsdir):
        raise ValueError('bad jobs directory: %s' % jobsdir)

    # Get process information before getting current job information
    procs = ProcessList()

    # Determine what users are currently running jobs on this node
    legalusers = nodeusers(logger, jobsdir, xjobids)

    # Combine safeusers with legalusers
    exemptusers = legalusers | config.safeusers

    # Set of additional processes not to kill
    apids = procs.ancestors(os.getpid())
    bpids = procs.descendants(os.getpid())
    exemptpids = apids | bpids

    # Create a dictionary that maps "top pids" to lists of process IDs
    # under that pid
    toplevel = {}
    for pid, pinfo in procs.items():
        if pinfo['user'] not in exemptusers and \
                pinfo['uid'] > SYSTHRESHOLD and \
                pid not in exemptpids:
            tpid = procs.toppid(pid)
            toplevel.setdefault(tpid, []).append(pid)

    # Only print this warning message once
    if len(toplevel) > 0:
        logger.warning('rogue processes detected on ' + NODE)

    # Log the top level commands associated with rogue processes
    for tpid, pids in toplevel.items():
        tproc = procs[tpid]
        pproc = procs[tproc['ppid']]
        pidstr = ' '.join([str(pid) for pid in pids])
        logger.warning('rogue user: %s' % tproc['user'])
        logger.warning('  pids: %s' % pidstr)
        logger.info('  comm: %s -> %s' % \
                    (pproc['comm'], tproc['comm']))

        # Display environment information for each process in the group
        for pid in pids:
            tenv = getenviron(logger, pid)
            tjobid = tenv.get('PBS_JOBID', '')
            ompi_size = tenv.get('OMPI_COMM_WORLD_SIZE', '')

            # Log more information from the environment if possible
            if tenv:
                logger.info('  %d: PBS_JOBID: %s; OMPI_COMM_WORLD_SIZE: %s' % \
                            (pid, tjobid, ompi_size))

        # Kill the rogue processes if requested
        if config.kill:
            killprocs(logger, pids)

    return 0
