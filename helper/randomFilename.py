def randFilename(length=32):
    """generates a random string to be used as part of filenames
        | similar to *scryptRandstr()* except only characters a-zA-Z0-9 are used
        
        :param int length: length of the string to be generated
        :return: string generated
        :rtype: str
    """
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(length))

if __name__ == "__main__":
  try:
    import random
    import string
    import sys
  except ImportError, e:
    sys.stderr.write(e.message)
    sys.exit(1)
  if len(sys.argv) > 1 and sys.argv[1].isdigit() and int(sys.argv[1]) > 1:
    sys.stdout.write(str(randFilename(int(sys.argv[1])) + "\n"))
    sys.stdout.flush()
    sys.exit(0)
  else:
    sys.stdout.write(str(randFilename(64)) + "\n")
    sys.stdout.flush()
    sys.exit(0)