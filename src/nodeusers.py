import os, sys, glob, re, socket
from nodejobs import nodejobs
from jobinfo import jobinfo

USERPAT = re.compile(r'PBS_O_LOGNAME=([^\n]+)\n')
NODE = socket.gethostname().split('.')[0]

# Return the user names of current jobs on this node, excluding
# the specified job IDs
def nodeusers(logger, jobsdir, xjobids):
    if os.geteuid() == 0:
        return set(nodeusers_root(logger, jobsdir, xjobids))
    else:
        return set(nodeusers_user(logger, xjobids))

# Return the value of the string following "PBS_O_LOGNAME=" in the
# specified JB file.  This is the owner of the corresponding job.
def jobowner(logger, jobfile):
    try:
        fobj = open(jobfile, 'rb')
        try:
            data = fobj.read()
            mat = USERPAT.search(data)
            if mat:
                user = mat.group(1)
                logger.debug('%s is owner of %s' % (user, jobfile))
            else:
                raise ValueError('unable to find PBS_O_LOGNAME')
        finally:
            fobj.close()
    except Exception, e:
        logger.debug('unable to determine owner of job file ' + jobfile)
        user = ''

    return user

def nodeusers_root(logger, jobsdir, xjobids):
    jobsglob = os.path.join(jobsdir, '*.JB')
    xjobfiles = [os.path.join(jobsdir, jobid + '.JB') for jobid in xjobids]

    # A JB file for the current job appears to always exist when
    # "prologue" is executed, and never exist when "prologue.parallel"
    # is executed.  We won't assume that, but will always ingore a JB
    # file for the current job since we don't want the current job
    # to prevent rogue processes owned by the same user from being
    # killed.  In addition, we already know the owner of the current job.
    return [jobowner(logger, jobfile)
            for jobfile in glob.glob(jobsglob) if jobfile not in xjobfiles]

def nodeusers_user(logger, xjobids):
    owners = []
    for jobid in nodejobs(NODE):
        if jobid not in xjobids:
            user = jobinfo(jobid)['Job_Owner']
            logger.debug('%s is owner of %s' % (user, jobid))
            owners.append(user)
    return owners
