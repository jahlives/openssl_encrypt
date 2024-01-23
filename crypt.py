try:
  import sys
except ImportError,e:
  print e.message
  exit(1)

if __name__ == "__main__":
  if len(sys.argv) > 1 and sys.argv[1] in ('-g', '--gui'):
    try:
      from helper.gui import *
    except ImportError, e:
      sys.stderr.write('FATAL: ' + e.message + '\n')
      sys.exit(1)
    app = cryptGui_tk(None)
    app.title('CryptGui')
    img = Tkinter.PhotoImage(file=baseDir + '/favicon.png')
    app.tk.call('wm', 'iconphoto', app._w, img)
    app.mainloop()
  elif len(sys.argv) > 1:
    try:
      from helper.opensslCrypt import *
    except ImportError, e:
      sys.stderr.write('FATAL: ' + e.message +'\n')
      sys.exit(1)
    app = opensslCrypt(sys.argv[1:])
  else:
    try:
      from helper.opensslCrypt import *
    except ImportError, e:
      sys.stderr.write('FATAL: ' + e.message + '\n')
      sys.exit(1)
    app = opensslCrypt('-h')
  