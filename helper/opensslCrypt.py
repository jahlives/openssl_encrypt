try: 
  import sys
  import os
  import tempfile
  import hashlib
  import exceptions
  import getpass
  import base64
  import subprocess
  import argparse
  from scryptHelper import *
  from os.path import *
  import shutil
except ImportError, e:
  sys.stderr.write("FATAL: " + e.message + "\n")
  sys.exit(1)

class Object(object):
  pass

basedir = dirname(abspath(__file__))
confdir = dirname(abspath(__file__)) + os.sep + '..' + os.sep + 'conf' + os.sep
    

class opensslCrypt():
  """class used for encryption and decryption via *openssl*
  """
  def __init__(self, args=None, parent=None):
    """used to determine wheter run as cli script or as class called by a parent class
      
      :param list args: provide arguments via cli. Use something like app = opensslCrypt(sys.argv[1:])
      :param object parent: if called by parent class provide a reference to parent for opensslCrypt
      
    """
    self.parent = None
    self.cryptArgs = Object()
    self.cryptArgs.action = 'NotSet'
    self.cryptArgs.password = 'NotSet'
    self.cryptArgs.file = 'NotSet'
    self.cryptArgs.cipher = 'NotSet'
    self.cryptArgs.digest = 'NotSet'
    self.cryptArgs.rounds = 'NotSet'
    self.cryptArgs.scrypt = 0
    self.cryptArgs.keysize = 'NotSet'
    self.cryptArgs.salt = ''
    self.cryptArgs.interactive = False
    self.cryptArgs.tmpdir = tempfile.gettempdir()
    #: check if parent class is available
    #: and set the arguments from that parent class
    if parent is not None: 
      self.parent = parent
      self.cryptArgs.action = parent.buttonVariable.get()
      self.cryptArgs.password = parent.passwordVariable.get()
      self.cryptArgs.file = parent.filePathVariable.get()
      self.cryptArgs.cipher = parent.cipherVariable.get()
      self.cryptArgs.digest = parent.digestVariable.get()
      self.cryptArgs.rounds = parent.roundsVariable.get()
      self.cryptArgs.scrypt = parent.scryptVariable.get()
      self.cryptArgs.keysize = parent.keysizeVariable.get()
      self.cryptArgs.salt = ''
      self.cryptArgs.interactive = False
  #  self.readConfig()
    self.initialize()
    
  def readConfig(self, file=None):
    if file is None:
      file = confdir + 'opensslCrypt.cfg'
    if os.path.isdir(confdir) is True and os.path.isfile(file) is True:
      import ConfigParser
      Config = ConfigParser.ConfigParser()
      Config.read(file)
      for i in ('tmpdir', 'password', 'cipher', 'rounds', 'scrypt', 'keysize', 'digest', 'file', 'salt', 'interactive'):
        if Config.has_option('opensslCrypt', i):
          if i == 'interactive':
            try:
              self.cryptArgs.interactive = Config.getboolean('opensslCrypt', i)
            except Exception: 
              pass
          elif i == 'rounds':
            try:
              self.cryptArgs.rounds = Config.getint('opensslCrypt', i)
            except Exception:
              pass
          elif i == 'scrypt':
            try:
              self.cryptArgs.scrypt = Config.getint('opensslCrypt', i)
            except Exception:
              pass
          elif i == 'keysize':
            try:
              self.cryptArgs.keysize = Config.getint('opensslCrypt', i)
            except Exception:
              pass
          else:
            exec('self.cryptArgs.' + i + ' = \'' + Config.get('opensslCrypt', i) + '\'')
      try:
        os.mkdir(self.cryptArgs.tmpdir, 0700)
      except OSError:
        if not os.path.isdir(self.cryptArgs.tmpdir):
          sys.stdout.write('\rFATAL: could not create temp working dir ' + self.cryptArgs.tmpdir)
          sys.exit(255)
      return 0
    else:
      return 1
      

  def which(self, program, out=0, fpath=None):
    """checks if a given *program* exists. If path is ommitted the function checks PATH.
          
           :param str program: name of the program to look for
           :param int output: if set to 1 the method return the full path to the file if found
           :param str path: if provided the program will be searched in path only. If omitted PATH is searched instead
           :return: full path to program if found. Depending on *output* value
           :rtype: int or str
           :raises IOError: if file not found or not executable
    """
    if fpath == None:
      for path in os.environ["PATH"].split(os.pathsep):
        path = path.strip('"')
        path = os.path.join(path, program)
        if os.path.isfile(path) and os.access(path, os.X_OK):
          if out == 1:
            return path
          else:
            return 0
    raise IOError("1", 'FATAL: No file named ' + program + ' in PATH or ' + program + ' found but not executable')

  def initialize(self):
    """calls the member functions and catches the following errors
      
      :raises IOError: if openssl binary could not be found
      :raises SyntaxError: if given mandatory parameters not given
      :raises IndexError: argument value is out of allowed range
      :raises TypeError: if argument has not expected type
        
    """
    try:
			self.opensslBin = self.which('openssl', 1)
    except IOError, e:
			sys.stderr.write(e.strerror)
			sys.exit(1)
    try:
			self.assign_cliArgs()
    except SyntaxError, e:
			sys.stderr.write(e.message)
			sys.exit(1)
    try:
			self.check_cliArgs()
    except SyntaxError, e:
			sys.stderr.write(e.message)
			sys.exit(1)
    except IndexError, e:
			sys.stderr.write(e.message)
			sys.exit(1)
    except TypeError, e:
			sys.stderr.write(e.message)
			sys.exit(1)

  def assign_cliArgs(self):
    """reads user arguments from command line and assigns them to an object
        
       :raises: SyntaxError: if unknown cli argument provided
    """
    if self.parent is None:
      parser = argparse.ArgumentParser(
                                       description='encrypts and decrypts files via openssl', 
                                       prog='crypt.py', 
                                       usage='%(prog)s -f|--file [FILE] -p|--password [PASSWORD] [OPTIONS] ACTION'
                                       )
      
      parser.add_argument('-f', '--file', 
                          nargs='?', 
                          default='NotSet', 
                          help='file to perform action on', 
                          required=True
                          )
      
      parser.add_argument('-p', '--password', 
                          nargs='?', 
                          default='NotSet', 
                          help='password to perform enryption on', 
                          required=False
                          )
      
      parser.add_argument('-s', '--scrypt', 
                          nargs='?', 
                          const=0, 
                          default=0, 
                          help="number of rounds hashing the hash with scrypt. Set to 0 to disable usage of scrypt",
                          type=int, 
                          required=False
                          )
      
      parser.add_argument('action', 
                          nargs='?', 
                          default='NotSet', 
                          help='action to perform',
                          choices=('dec', 'dec-write', 'enc')
                          )
      
      parser.add_argument('-d', '--digest', 
                          nargs='?', 
                          const='sha256', 
                          default='NotSet', 
                          help='digest to use for password hashing',
                          required=False
                          )
      
      parser.add_argument('-r', '--rounds', 
                          nargs='?', 
                          const=10, 
                          default='NotSet', 
                          help='how many times the hash function should be applied',
                          required=False
                          )
      
      parser.add_argument('-k', '--keysize', 
                          nargs='?', 
                          const=128, 
                          default='NotSet', 
                          help='defines the size of the returned hash in bits', 
                          required=False
                          )
      
      parser.add_argument('-c', '--cipher', 
                          nargs='?', 
                          const='blowfish', 
                          default='NotSet', 
                          help='cipher to use for encryption/decryption', 
                          required=False
                          )
      
      parser.add_argument('--salt', nargs='?', 
                          const='NotSet', 
                          default='NotSet', 
                          help='salt to be used to scrypt the password', 
                          required=False
                          )
      
      parser.add_argument('-i', '--interactive',   
                          help='password will be provided interactive',
                          action='store_true',
                          required=False
                          )
      parser.add_argument('--np',
                          help='supress progress messages while generating the hash',
                          action='store_true',
                          required=False
                          )
      self.cryptArgs = parser.parse_args()

  def check_cliArgs(self):
    """checks the values of given arguments
        
       :raises SyntaxError: if file not found or empty values detected or if str values not contain supported values
       :raises TypeError: if values provided do not match expected types
       :raises IndexError: if int values are out of given boundary
    """
    if int(self.cryptArgs.scrypt) > 0:
      try:
        import scryptHelper
      except Exception:
        sys.stderr.write("FATAL: helper.scryptHelper module could not be loaded\n")
        sys.stderr.write("FATAL: cannot continue as you choose to enable scrypt\n")
        sys.stderr.write("FATAL: by setting self.cryptArgs.scrypt to " + str(self.cryptArgs.scrypt) + "\n")
        sys.stderr.flush()
        sys.exit(1)
    self.readConfig()
    if self.cryptArgs.action is 'NotSet':
      raise SyntaxError('FATAL: No action parameter specified')
    if self.cryptArgs.file is 'NotSet':
			raise SyntaxError('FATAL: No file specified')
    if self.cryptArgs.cipher is 'NotSet':
      self.cryptArgs.cipher = 'blowfish'
    if self.cryptArgs.digest is 'NotSet':
      self.cryptArgs.digest = 'sha256'
    if self.cryptArgs.rounds is 'NotSet':
      self.cryptArgs.rounds = str(512)
    if self.cryptArgs.keysize is 'NotSet':
      self.cryptArgs.keysize = str(448)
    if self.cryptArgs.action not in ('enc', 'dec', 'dec-write'):
		  raise SyntaxError('FATAL: First argument must be dec OR enc OR dec-write')
    elif os.path.isfile(self.cryptArgs.file) != True:
			raise SyntaxError('FATAL: File ' + self.cryptArgs.file + ' not found')
    elif self.cryptArgs.password == '':
			raise SyntaxError('FATAL: Empty password provided')
    elif os.path.isfile(self.cryptArgs.password):
      try:
        with open(self.cryptArgs.password) as fp:
          self.cryptArgs.password = fp.readline().strip()
      except Exception, e:
        pass
    elif self.cryptArgs.cipher not in ('blowfish', 'aes256', 'aes128', 'camelia128', 'camelia256', 'chacha20'):
      raise SyntaxError('FATAL: Cipher ' + str(self.cryptArgs.cipher) + ' not found')
    elif self.cryptArgs.digest not in ('md5', 'sha', 'sha1', 'ripemd160', 'sha224', 'sha256', 'sha384', 'sha512', 'whirlpool'):
      raise SyntaxError('FATAL: Digest ' + str(self.cryptArgs.digest) + 'not found')
    elif not str(self.cryptArgs.rounds).isdigit():
			raise TypeError('FATAL: Paramter rounds must be a integer value') 
    elif int(self.cryptArgs.rounds) < 1 or int(self.cryptArgs.rounds) > 1000000:
      raise IndexError('rounds value ' + str(self.crypArgs.rRounds) + ' out of allowed range 1-10000')
    elif not str(self.cryptArgs.scrypt).isdigit():
      raise TypeError('FATAL: Paramter scrypt must be a integer value')
    elif int(self.cryptArgs.scrypt) < 0 or int(self.cryptArgs.scrypt) > 1000:
      raise IndexError('FATAL: scrypt parameter value ' + str(self.cryptArgs.scrypt) + ' out of allowed range 0-1000')
    elif not str(self.cryptArgs.keysize).isdigit():
      raise TypeError('FATAL: Paramter keysize must be a integer value')
    elif int(self.cryptArgs.keysize) < 128 or int(self.cryptArgs.keysize) > 4096:
      raise IndexError('FATAL: keysize parameter value ' + str(self.cryptArgs.keysize) + ' out of allowed range 128-4096')
    elif self.cryptArgs.password is 'NotSet' or self.cryptArgs.interactive is True:
      if self.cryptArgs.interactive is True:
        try:
          t = getpass.getpass('Enter password: ')
          tt = getpass.getpass('Confirm password: ')
        except getpass.GetPassWarning, e:
          sys.stderr.write('FATAL: Cannot proceed as password might be echoed')
          sys.exit(1)
        if tt == t:
          self.cryptArgs.password = tt
        else:
          raise SyntaxError('FATAL: Given passwords not equal')
      else:
        raise SyntaxError('FATAL: No password specified')
    self.generateHash()

  def generateHash(self, password=None):
    """generates a hash value from provided password to be used as encryption key
    
      needs helper.scryptHelper to be loaded. Hashes the given password with the given hash digest
      and calls helper.scryptHelper if scrypt is requested. Digest methods found in :func:`hashlib.algorithms` will be called
      via their named member methods which are much faster than hashing via the new constructor as its necessary for ripemd160 and whirlpool
      
      :var str self.cryptArgs.digest: defines the digest to be used **(mandatory)**
      :var int self.cryptArgs.rounds: how many rounds of hashing will be performed **(mandatory)**
      :var int self.cryptArgs.scrypt: defines the number of rounds for hashing the hash with scrypt.hash() function **(not mandatory)**
      
    """
    if password is not None:
      t = password
    else:
      t = self.cryptArgs.password
    if self.cryptArgs.digest in hashlib.algorithms:
      bar_length = 20
      for i in xrange(0, int(self.cryptArgs.rounds) + 1):
        if i % 5000 is 0 and self.cryptArgs.np is False:
          #: show progress in loop
          percent = float(i) / int(self.cryptArgs.rounds)
          hashes = '#' * int(round(percent * bar_length))
          spaces = ' ' * (bar_length - len(hashes))
          if i > 0:
            sys.stdout.write("\rINFO: " + str(self.cryptArgs.digest) + " [{0}] {1}%".format(hashes + spaces, int(round(percent * 100))))
            sys.stdout.flush()
          else:
            sys.stdout.write("\nINFO: " + str(self.cryptArgs.digest) + " [{0}] {1}%".format(hashes + spaces, int(round(percent * 100))))
            sys.stdout.flush()
        t = 'hashlib.' + self.cryptArgs.digest + '(\'' + t + '\').hexdigest()'
        t = eval(t)
    elif self.cryptArgs.digest in ('ripemd160', 'whirlpool'):
      bar_length = 20
      for i in xrange(0, int(self.cryptArgs.rounds) + 1):
        if i % 5000 is 0 and self.cryptArgs.np is False:
          #: show progress in loop
          percent = float(i) / int(self.cryptArgs.rounds)
          hashes = '#' * int(round(percent * bar_length))
          spaces = ' ' * (bar_length - len(hashes))
          if i > 0:
            sys.stdout.write("\rINFO: " + str(self.cryptArgs.digest) + " [{0}] {1}%".format(hashes + spaces, int(round(percent * 100))))
            sys.stdout.flush()
          else:
            sys.stdout.write("\nINFO: " + str(self.cryptArgs.digest) + " [{0}] {1}%".format(hashes + spaces, int(round(percent * 100))))
            sys.stdout.flush()
        t = hashlib.new(self.cryptArgs.digest, t).hexdigest()
    if int(self.cryptArgs.scrypt) is 0 or password is not None:
      sys.stdout.write("\rOK: Performed " + str(self.cryptArgs.rounds) + " rounds of hashing with " + str(self.cryptArgs.digest) + "\n")
    elif int(self.cryptArgs.scrypt) > 0 and password is not None:
      sys.stdout.write("\rOK: Performed " + str(self.cryptArgs.rounds) + " rounds of hashing with " + str(self.cryptArgs.digest) + "\n")
    else:
      sys.stdout.write("\rOK: Performed " + str(self.cryptArgs.rounds) + " rounds of hashing with " + str(self.cryptArgs.digest))
    sys.stdout.flush()
    self.cryptArgs.password = t
    if password is not None:
      return self.cryptArgs.password
    
    hash = scryptHelper(self)
    fp = tempfile.mkstemp(suffix='', prefix='', dir=self.cryptArgs.tmpdir, text=True)
    if self.cryptArgs.action == 'enc': 
      t = hash.scryptOutput[0]
    os.write(fp[0], t)
    os.close(fp[0])
    self.callOpenssl(hash, fp)

  def createFilehash(self, file):
    """compute file content hash
    
        :param str file: path to *file* to compute the hash
        :return: hash of *file* content
        :rtype: str
    """
    BLOCKSIZE = 65536
    hasher = hashlib.sha512()
    with open(file, 'rb') as afile:
      buf = afile.read(BLOCKSIZE)
      while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(BLOCKSIZE)
    return self.generateHash(hasher.hexdigest())

  def readHashline(self):
    """reads the corresponding hash from */path/to/file.hash*
    """
    with open(self.cryptArgs.file + '.hash') as fp:
      return fp.readline()

  def readSaltline(self):
    """reads the corresponding salt from */path/to/file.hash*
    """
    with open(self.cryptArgs.file + '.hash') as fp:
      fp.seek(-2, 2)
      while fp.read(1) != "\n":
        fp.seek(-2 , 1)
      return fp.readline()

  def callOpenssl(self, child, pwfile):
    """calls *openssl* for action
    
        :param child: a object reference on *scryptHelper* class
        :param pwfile: file handler for password file. This file contains the generated encryption password which is passed via *-kfile* parameter to *openssl*
        :type child: object reference
        :type pwfile: tulple file handler
        :return: 0 if sucessful or 1 if error
        :rtype: int
    """
    salt = ''
    if self.cryptArgs.action in ('dec', 'dec-write'):
      action = 'd'
      if int(self.cryptArgs.scrypt) > 0: 
        try:
          self.cryptArgs.salt = self.readSaltline()
        except IOError, e:
          sys.stderr.write("\nFATAL: salt not found. Check /path/to/enc.file.hash")
          sys.stderr.write("\nFATAL: a common reason for this message is caused")
          sys.stderr.write("\nFATAL: because of enable scrypt for decryption") 
          sys.stderr.write("\nFATAL: on a file that was not encrypted using scrypt\n")
          sys.stderr.flush()
          return 1
      child.scryptRun()
      fp = open(pwfile[1], 'w')
      fp.write(child.scryptOutput[0])
      fp.close
    elif self.cryptArgs.action == 'enc':
      action = 'e'
      if self.cryptArgs.scrypt is None or self.cryptArgs.scrypt is 'NotSet' or self.cryptArgs.scrypt == 0:
        fcontent = self.createFilehash(self.cryptArgs.file)
      else:
        fcontent = self.createFilehash(self.cryptArgs.file) + "\n" + child.scryptOutput[1]
      with open(self.cryptArgs.file + '.hash', "w") as afile:
        afile.write(fcontent)
    else:
      raise SyntaxError('FATAL: ' + self.cryptArgs + ' is a non-supported action')
    tfile = child.scryptRandfilename(64)
    fp = tempfile.mkstemp(suffix='', prefix=tfile + "_", dir=self.cryptArgs.tmpdir, text=True)
    os.close(fp[0])
    cmd = self.which('openssl', 1) + ' enc -in \'' + self.cryptArgs.file + '\' -out \'' + fp[1] + '\' -' + action + ' -md ' + self.cryptArgs.digest + ' -' + self.cryptArgs.cipher + ' -kfile ' + pwfile[1]
 #   print cmd
    FNULL = open(os.devnull, 'w')
    ret = subprocess.call(cmd, shell=True, stdout=FNULL, stderr=FNULL)
#    sys.stdout.write(str(ret) + "\n" + self.cryptArgs.action + "\n")
#    sys.exit(1)
 #   print ret
    if int(ret) is 0 and self.cryptArgs.action in ('dec-write', 'enc'):
  #    sys.stdout.write(str(ret) + "\n" + self.cryptArgs.action + "\n")
      if self.cryptArgs.action == 'dec-write':
        chkHash = self.createFilehash(fp[1])
        if chkHash != self.readHashline().strip() and self.cryptArgs.np is False:
          sys.stdout.write('WARN: Sucessfully decrypted BUT hashes do not match\n')
          t = raw_input('Proceed anyway? Type [yes]: ')
          if t == 'yes':
            shutil.move(fp[1], self.cryptArgs.file)
            os.remove(pwfile[1])
#            os.rename(fp[1], self.cryptArgs.file)
            os.remove(pwfile[1])
          else:
            os.remove(fp[1])
            os.remove(pwfile[1])
          sys.exit(1)
        elif chkHash != self.readHashline().strip():
          sys.stdout.write("WARN: Sucessfully decrypted BUT hashes do not match")
          shutil.move(fp[1], self.cryptArgs.file)
          os.remove(pwfile[1])
#          os.rename(fp[1], self.cryptArgs.file)
          os.remove(pwfile[1])
          return 1
          
      if self.cryptArgs.action == 'dec-write':
        sys.stdout.write('OK: file ' + self.cryptArgs.file + ' sucessfully decrypted\n')
      else:
        sys.stdout.write('OK: file ' + self.cryptArgs.file + ' sucessfully encrypted\n')
#     os.rename(fp[1], self.cryptArgs.file)
      shutil.move(fp[1], self.cryptArgs.file)
      os.remove(pwfile[1])
      if self.parent is None:
        sys.exit(ret)
      else:
        return ret
    elif int(ret) is 0:
      if self.createFilehash(fp[1]) != self.readHashline().strip():
        sys.stdout.write("WARN: Hash Error\n")
        sys.stdout.write("WARN: Sucessfully decrypted BUT hashes do not match\n")
        t = raw_input('Proceed anyway? Type [yes]: ')
        if t == 'yes':
          sys.stderr.write(open(fp[1], 'r').read().strip() + "\n")
          os.remove(fp[1])
          os.remove(pwfile[1])
        else:
          os.remove(fp[1])
          os.remove(pwfile[1])
        if self.parent is None:
          sys.exit(1)
        else:
          return ret
      sys.stdout.write('OK: file ' + self.cryptArgs.file + ' sucessfully decrypted\n')
      sys.stderr.write(open(fp[1], 'r').read().strip() + "\n")
    else:
      sys.stdout.write('FATAL: An error occured while processing file ' + self.cryptArgs.file)
    os.remove(fp[1])
    os.remove(pwfile[1])
    if self.parent is None:
      sys.exit(ret)
    else:
      return ret

if __name__ == "__main__":
	app = opensslCrypt(sys.argv[1:])
