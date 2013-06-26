import os, sys, re, socket, getopt, logging, logging.handlers, tempfile
from ConfigParser import RawConfigParser, NoSectionError

NODE = socket.gethostname().split('.')[0]
PBS_HOME = os.environ.get('PBS_HOME', '/var/spool/torque')
LOGFACILITIES = [
    'local0', 'local1', 'local2', 'local3', 'local4',
    'local5', 'local6', 'local7', 'user', 'daemon'
]
LOGLEVELS = [
    'CRITICAL', 'ERROR', 'WARNING', 'WARN', 'INFO', 'DEBUG'
]
SAFEUSERS = [
    'ag663', 'ch427', 'cw464', 'ra359',
    'dvasil', 'vendortech'
]

def tobool(v):
    if isinstance(v, basestring):
        return v.lower() in ('yes', 'true', 't', '1')
    else:
        return bool(v)

def tologlevel(v):
    if isinstance(v, basestring):
        if v.upper() in LOGLEVELS:
            v = v.upper()
        else:
            raise ValueError('illegal loglevel: %s' % v)
        return getattr(logging, v)
    else:
        return int(v)

def tosyslogfacility(v):
    if v.lower() in LOGFACILITIES:
        return v.lower()
    else:
        raise ValueError('illegal sysloglevel: %s' % v)

def metasection(s):
    suffix = '-classes'
    if s.endswith(suffix):
        return s[:-len(suffix)]
    else:
        return ''

def opsplit(s):
    s = s.strip()
    if s[0] in ('-', '+'):
        return s[0], s[1:]
    else:
        return '+', s

def touserset(s):
    return set([opsplit(u) for u in s.split(',') if u.strip()])

class Config(object):
    def __init__(self, ini, logfile=None, cluster='test', node=NODE,
                 stream=sys.stderr):
        if logfile:
            # Make sure we're able to write to the logfile if it exists
            if (os.path.exists(logfile) and \
                    not os.access(logfile, os.W_OK)) or \
               (not os.path.exists(logfile) and \
                    not os.access(os.path.dirname(logfile), os.W_OK)):
                logfile = tempfile.mktemp(suffix='.log', prefix='reaper-',
                                          dir='/tmp')
            self.logger = self.bootlogger(logfile)
        else:
            self.logger = None

        # Convert to canonical form
        # XXX doesn't work well for bulldogj/k/l
        nid = tuple(re.findall(r'\d+', node))
        if len(nid) == 0:
            node = '0-0'
        elif len(nid) == 1:
            node = '0-%s' % nid
        else:
            node = '%s-%s' % nid[:2]

        self.stream = stream

        self._params = {
            'enabled':        tobool,
            'kill':           tobool,
            'pbs_home':       str,
            'loglevel':       tologlevel,
            'logfmt':         str,
            'logname':        str,
            'sysloghost':     str,
            'syslogport':     int,
            'syslogsocket':   str,
            'syslogfacility': tosyslogfacility,
            'sysloglevel':    tologlevel,
            'safeusers':      touserset,
        }

        # Default configuration values
        self._defvals = {
            'enabled':        True,
            'kill':           False,
            'pbs_home':       PBS_HOME,
            'loglevel':       self._params['loglevel']('INFO'),
            'logfmt':         '%(name)s: %(message)s',
            'logname':        'prologue',
            'sysloghost':     None,
            'syslogport':     514,
            'syslogsocket':   '/dev/log',
            'syslogfacility': self._params['syslogfacility']('local7'),
            'sysloglevel':    self._params['sysloglevel']('DEBUG'),
            'safeusers':      set(SAFEUSERS),
        }

        try:
            # Create a dict of dict's from the ini file
            self._d = {}
            cluster = cluster.lower().strip()
            if not os.access(ini, os.R_OK):
                if self.logger is not None:
                    self.logger.warning('unable to read ini file: %s' % ini)
                else:
                    self.stream.write('unable to read ini file: %s\n' % ini)

                mapper = SectionMapper({}, ClusterConfig({}))
                self._k = mapper.sectiontuple('%s/%s' % (cluster, node))
            else:
                config = RawConfigParser()
                config.read(ini)

                cconfig = ClusterConfig({})
                nconfig = {}
                for sec in config.sections():
                    cl = metasection(sec)
                    if cl:
                        m = dict((k, [x.strip() for x in v.split(',')])
                                 for k, v in config.items(sec))
                        if cl == 'cluster':
                            cconfig = ClusterConfig(m)
                        else:
                            nconfig[cl] = NodeConfig(cl, m)

                mapper = SectionMapper(nconfig, cconfig)
                self._k = mapper.sectiontuple('%s/%s' % (cluster, node))

                for sec in config.sections():
                    if not metasection(sec):
                        dv = dict((k, self._params[k](v))
                                  for k, v in config.items(sec))
                        self._d.setdefault(mapper.sectiontuple(sec), {}).update(dv)
        except Exception, e:
            if self.logger is not None:
                self.logger.error('error: %s' % e)
            else:
                self.stream.write('error: %s\n' % e)
            raise

    def get(self, key):
        return self._get(self._k, key)

    def _get(self, tup, key):
        try:
            return self._d[tup][key]
        except KeyError:
            if tup:
                return self._get(tup[:-1], key)
            else:
                return self._defvals[key]

    def set(self, key, value):
        self._d.setdefault(self._k, {})[key] = self._params[key](value)

    def getstrset(self, key):
        # Make a copy of the default value since we will mutate it
        return self._getstrset(0, key, self._defvals[key].copy())

    def _getstrset(self, n, key, vals):
        if n > len(self._k):
            return vals
        else:
            try:
                val = self._d[self._k[:n]][key]
            except KeyError:
                pass
            else:
                if len([u for op, u in val if op == '-' and not u]) > 0:
                    vals -= vals
                else:
                    vals -= set([u for op, u in val if op == '-' and u])
                vals |= set([u for op, u in val if op == '+' and u])
            return self._getstrset(n + 1, key, vals)

    # Define the configuation parameter properties
    enabled =        property(
        lambda self, key='enabled':             self.get(key),
        lambda self, val, key='enabled':        self.set(key, val))
    kill =           property(
        lambda self, key='kill':                self.get(key),
        lambda self, val, key='kill':           self.set(key, val))
    pbs_home =       property(
        lambda self, key='pbs_home':            self.get(key),
        lambda self, val, key='pbs_home':       self.set(key, val))
    loglevel =       property(
        lambda self, key='loglevel':            self.get(key),
        lambda self, val, key='loglevel':       self.set(key, val))
    logfmt =         property(
        lambda self, key='logfmt':              self.get(key),
        lambda self, val, key='logfmt':         self.set(key, val))
    logname =        property(
        lambda self, key='logname':             self.get(key),
        lambda self, val, key='logname':        self.set(key, val))
    sysloghost =     property(
        lambda self, key='sysloghost':          self.get(key),
        lambda self, val, key='sysloghost':     self.set(key, val))
    syslogport =     property(
        lambda self, key='syslogport':          self.get(key),
        lambda self, val, key='syslogport':     self.set(key, val))
    syslogsocket =   property(
        lambda self, key='syslogsocket':        self.get(key),
        lambda self, val, key='syslogsocket':   self.set(key, val))
    syslogfacility = property(
        lambda self, key='syslogfacility':      self.get(key),
        lambda self, val, key='syslogfacility': self.set(key, val))
    sysloglevel =    property(
        lambda self, key='sysloglevel':         self.get(key),
        lambda self, val, key='sysloglevel':    self.set(key, val))
    safeusers =    property(
        lambda self, key='safeusers':           self.getstrset(key),
        lambda self, val, key='safeusers':      self.set(key, val))

    def usage(self, argv0):
        self.stream.write('''\
usage: %s [OPTION ...]

Check for rogue processes.

  -h              Display this message.
  --help          Synonym for the "-h" option.
  --info          Set verbosity to info level. 
  -k              Kill the rogue processes.
  --kill          Synonym for the "-k" option.
  --pbs <dir>     Path to the PBS_HOME directory.
  -q              Set verbosity to warning level.
  --quiet         Synonym for the "-q" option.
  -v              Set verbosity to debug level.
  --verbose       Synonym for the "-v" option.
''' % argv0)

    def cmdline(self, argv):
        argv0 = os.path.basename(argv[0])
        try:
            opts, args = getopt.getopt(argv[1:], 'hkqv',
                    ['help', 'info', 'kill', 'pbs=', 'quiet', 'verbose'])
        except getopt.GetoptError, e:
            self.stream.write('error: %s\n\n' % str(e))
            self.usage(argv0)
            return 1

        try:
            for opt, arg in opts:
                if opt in ('--help', '-h'):
                    self.usage(argv0)
                    return 0
                elif opt in ('--kill', '-k'):
                    self.kill = True
                elif opt in ('--pbs'):
                    self.pbs_home = arg
                elif opt in ('--info'):
                    self.loglevel = 'info'
                elif opt in ('--quiet', '-q'):
                    self.loglevel = 'warning'
                elif opt in ('--verbose', '-v'):
                    self.loglevel = 'debug'
                else:
                    self.stream.write('internal error: %s\n' % opt)
                    self.usage(argv0)
                    return 3
        except ValueError, e:
            self.stream.write('error: %s\n' % str(e))
            return 1

        if args:
            self.stream.write('error: illegal argument(s): %s\n\n' % \
                              ' '.join(args))
            self.usage(argv0)
            return 1

        return 0

    def syslogger(self):
        logger = logging.getLogger(self.logname)
        logger.setLevel(self.loglevel)
        if self.sysloghost:
            addr = (self.sysloghost, self.syslogport)
        else:
            addr = self.syslogsocket
        handler = logging.handlers.SysLogHandler(addr,
                facility=self.syslogfacility)
        handler.setLevel(self.sysloglevel)
        formatter = logging.Formatter(self.logfmt)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def bootlogger(self, logfile):
        logfmt = '%(asctime)s %(name)s: %(message)s'
        loglevel = 'DEBUG'
        logname = 'prologue.boot'
        logger = logging.getLogger(logname)
        logger.setLevel(loglevel)
        handler = logging.FileHandler(logfile)
        formatter = logging.Formatter(logfmt)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

def dinvert(children, legalparent):
    parent = {}
    for p in children:
        legalparent(p)  # raises exception if illegal
        for c in children[p]:
            if parent.has_key(c):
                if parent[c] != p:
                    raise ValueError('multiple parents specified for %s' % c)
            else:
                parent[c] = p
    return parent

class ClusterConfig(object):
    def __init__(self, children):
        self._clusterspecpat = re.compile(r'[a-z][a-z0-9]*$')
        self._children = children
        self._parent = dinvert(children, self._legalclusterclass)

    def _legalclusterclass(self, clusterspec):
        if not self._clusterspecpat.match(clusterspec):
            raise ValueError('illegal clusterclass: %s' % clusterspec)

    def parent(self, clusterspec):
        if clusterspec == 'default':
            return ''
        else:
            return self._parent.get(clusterspec, 'default')

    def path(self, clusterspec):
        if not clusterspec or clusterspec == 'default':
            return ()
        else:
            return self._path(self.parent(clusterspec), [clusterspec])

    def _path(self, clusterspec, p):
        if clusterspec == 'default':
            return p
        else:
            return self._path(self.parent(clusterspec), [clusterspec] + p)

    def clustertype(self, clusterspec):
        if not self._clusterspecpat.match(clusterspec):
            raise ValueError('illegal clusterspec: %s' % clusterspec)
        elif self._children.has_key(clusterspec) or clusterspec == 'default':
            return 'clusterclass'
        else:
            return 'clustername'

class NodeConfig(object):
    def __init__(self, cluster, children):
        self._cluster = cluster
        self._children = children

        # only omega and louise
        self._nodenamepat = re.compile(r'([a-z][a-z0-9]*-)?(?P<rack>\d+)-(\d+)$')
        self._rackpat = re.compile(r'(^\d+)$')
        self._nodeclasspat = re.compile(r'^[a-z][a-z0-9]*$')
        self._parent = dinvert(children, self._legalnodeclass)

    def _legalnodeclass(self, nodespec):
        if not self._nodeclasspat.match(nodespec):
            raise ValueError('illegal nodespec: %s' % nodespec)

    def _rack(self, nodename):
        m = self._nodenamepat.match(nodename)
        if not m:
            raise ValueError('illegal nodename: %s' % nodename)
        return m.group('rack')

    def parent(self, nodespec):
        if self.nodetype(nodespec) == 'nodename':
            try:
               return self._parent[nodespec]
            except KeyError:
               return self._rack(nodespec)
        else:
            return self._parent.get(nodespec, '')

    def path(self, nodespec):
        return self._path(self.parent(nodespec), [nodespec])

    def _path(self, nodespec, p):
        if not nodespec:
            return p
        else:
            return self._path(self.parent(nodespec), [nodespec] + p)

    def nodetype(self, nodespec):
        if self._nodenamepat.match(nodespec):
            t = 'nodename'
        elif self._rackpat.match(nodespec):
            t = 'rackname'
        elif nodespec in self._children:
            t = 'nodeclass'
        else:
            raise ValueError('illegal nodespec for cluster %s: %s' % \
                             (self._cluster, nodespec))
        return t

class SectionMapper(object):
    def __init__(self, nconfig, cconfig):
        self._nconfig = nconfig
        self._cconfig = cconfig

    def sectiontuple(self, s):
        sec = s.split('/', 1)
        if len(sec) == 2:
            if self._cconfig.clustertype(sec[0]) != 'clustername':
                raise ValueError('illegal section name: %s' % s)
            nodeconfig = self._nconfig.get(sec[0], NodeConfig(sec[0], {}))
            return tuple(self._cconfig.path(sec[0]) +
                         nodeconfig.path(sec[1]))
        else:
            return tuple(self._cconfig.path(sec[0]))
