import sys
import random
import base64
import argparse
import scrypt
import string

class Object(object):
  pass

class scryptHelper():
  """helper class for interaction with *scrypt*
  
     :param parent: object reference to parent
     :type parent: object reference
  """
  def __init__(self, parent=None):
    self.parent = None
    self.scryptArgs = Object()
    self.scryptArgs.salt = 'NotSet'
    self.scryptArgs.random = 'NotSet'
    self.scryptArgs.keysize = 'NotSet'
    self.scryptArgs.action = 'NotSet'
    self.scryptArgs.count = 'NotSet'
    self.scryptArgs.file = 'NotSet'
    self.ScryptOutput = None
    if parent != None:
      self.scryptArgs.password = parent.cryptArgs.password
      self.scryptArgs.action = parent.cryptArgs.action
      self.scryptArgs.count = int(parent.cryptArgs.scrypt)
      self.scryptArgs.keysize = parent.cryptArgs.keysize
      self.scryptArgs.salt = parent.cryptArgs.salt
      self.parent = parent
    self.scryptInit()
  def scryptRandstr(self, length):
    """generates a random string
    
        :param int length: length of the generated string in Bytes
        :return: string generated
        :rtype: str
    """
    return ''.join(chr(random.randint(0, 255)) for i in range(length))
  def scryptRandfilename(self, length=32):
    """generates a random string to be used as part of filenames
        | similar to *scryptRandstr()* except only characters a-zA-Z0-9 are used
        
        :param int length: length of the string to be generated
        :return: string generated
        :rtype: str
    """
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(length))

  def scryptHash_pw(self, password, salt, count=50, hash_size=448):
    """actually generates the scrypt hash of the given password
    
        :param str password: password to use with scrypt. Mostly this is a hash of the cleartextpassword
        :param str salt: salt to use for hashing password with scrypt
        :param int count: how many times *scrypt.hash()* function should be applied
        :param int hash_size: desired length of the returned hash in Bits
        :return: hash generated
        :rtype: str
    """
#     if self.parent is not None:
#       for i in tqdm(range(count+1), desc='INFO: # of iterations with SCRYPT', total=count):
#         password = scrypt.hash(password, salt, 1 << 14, 8, 1, hash_size)
#     else:
    bar_length = 20
    for i in xrange(0, int(count)):
      if self.parent.cryptArgs.np is False:
        percent = float(i) / int(count)
        hashes = '#' * int(round(percent * bar_length))
        spaces = ' ' * (bar_length - len(hashes))
        if i > 0:
          sys.stdout.write("\rINFO: scrypt [{0}] {1}%".format(hashes + spaces, int(round(percent * 100))))
          sys.stdout.flush()
        else:
          sys.stdout.write("\nINFO: scrypt [{0}] {1}%".format(hashes + spaces, int(round(percent * 100))))
          sys.stdout.flush()
      password = scrypt.hash(password, salt, 1 << 14, 8, 1, hash_size)
    if self.parent.cryptArgs.np is False:
      sys.stdout.write("\rOK: Performed " + str(count) + " rounds with scrypt hashing function")
    else:
      sys.stdout.write("\nOK: Performed " + str(count) + " rounds with scrypt hashing function\n")
    sys.stdout.flush()
    return base64.b64encode(password)
  def scryptInit(self):
    """initialize the object. Reads arguments from cli or settings from parent object
    """
    if self.parent == None:
      parser = argparse.ArgumentParser(description='a scrypt interface by Tobi')
      parser.add_argument('-s', '--salt', 
                          nargs='?', 
                          help='either the salt to use for encryption or the hash of the password to verify', 
                          const='NotSet', 
                          default='NotSet', 
                          required=False
                          )
      
      parser.add_argument('-p', '--password', 
                          nargs='?', 
                          default='NotSet', 
                          help='password to perform enryption on'
                          )
      
      parser.add_argument('action', 
                          nargs='?', 
                          default='NotSet', 
                          help='action to perform. can be verify or encrypt'
                          )
      
      parser.add_argument('-r', '--random', 
                          nargs='?', 
                          const=32, 
                          default='NotSet', 
                          help='just generate a x-chars-length random string', 
                          required=False
                          )
      
      parser.add_argument('-f', '--file', 
                          nargs='?', 
                          default='NotSet', 
                          help='write salt into file', 
                          required=False
                          )
      
      parser.add_argument('-c', '--count', 
                          nargs='?', 
                          const=10, 
                          default='NotSet', 
                          help='how many times the scrypt hash function should be applied', 
                          required=False
                          )
      
      parser.add_argument('-k', '--keysize', 
                          nargs='?', 
                          const=128, 
                          default='NotSet', 
                          help='size of hash to use. Will be returned password length', 
                          required=False
                          )
      
      self.scryptArgs = parser.parse_args()
    if self.parent.cryptArgs.action not in ('dec', 'dec-write'):
      self.scryptRun()
  def scryptRun(self):
    """runs the generation of scrypt hash
    
        :return: tulple containing the generated password and the salt used
        :rtype: tulple
    """
    args = self.scryptArgs
#    print args.password + "\n" + args.action + "\n" + args.count + "\n" + args.keysize
#    sys.exit(0)
    if args.password is not 'NotSet' and args.password is not None and args.password != '' and args.count is 0:
      str = args.password + "\n"
      self.scryptOutput = str.splitlines()
      return
    if args.salt == 'NotSet' and args.random != 'NotSet' or args.salt == '' and args.random != 'NotSet':
      salt = self.scryptRandstr(int(args.random))
    elif args.salt == 'NotSet' and args.random == 'NotSet' or args.salt == '' and args.random == 'NotSet':
      salt = self.scryptRandstr(64)
    else:
      salt = base64.b64decode(args.salt)
    if args.keysize == 'NotSet':
	    args.keysize = 256
    if args.random != 'NotSet':
	    print("%s" % base64.b64encode(salt))
    elif args.action in ('enc', 'dec', 'dec-write'):
#      print self.parent.cryptArgs.salt
      if self.parent.cryptArgs.salt != 'NotSet' and self.parent.cryptArgs.salt is not None and self.parent.cryptArgs.salt != '': salt = base64.b64decode(self.parent.cryptArgs.salt)
#      print base64.b64encode(salt)
      if args.count != 'NotSet' and args.keysize != 'NotSet':
        str = self.scryptHash_pw(args.password, salt, int(args.count), int(args.keysize))
      elif args.count != 'NotSet':
        str = self.scryptHash_pw(args.password, salt, int(args.count))
      elif args.keysize != 'NotSet':
        str = self.scryptHash_pw(args.password, salt, None, int(args.keysize))
      elif args.count == 'NotSet' and args.keysize == 'NotSet':
        str = self.scryptHash_pw(args.password, salt)
      else:
        sys.exit(1)
      if args.file != 'NotSet':
        with open(args.file, "a") as myfile:
          myfile.write(base64.b64encode(salt))
      else:
        str = str + "\n" + base64.b64encode(salt)
      self.scryptOutput = str.splitlines()
if __name__ == "__main__":
  app = scryptHelper()
