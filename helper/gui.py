#===============================================================================
#	try to import necessary modules
#===============================================================================
from os.path import abspath
from os.path import dirname
from opensslCrypt import *
try:
	import Tkinter
except ImportError:
	raise ImportError, "The tkPython module is required for this application"
try:
	import subprocess
except ImportError:
	raise ImportError, "The python subprocess module is required"
try:
	import shlex
except ImportError:
	raise ImportError, "The python module shlex is required"

class Object(object):
  pass
 
baseDir = dirname(abspath(__file__))
#===============================================================================
#	cryptGui_tk
#
#	gui for interacting with bash crypt script
#===============================================================================
class cryptGui_tk(Tkinter.Tk):
	"""class for the tk based gui
			
  .. moduleauthor:: Tobi <jahlives@gmx.ch>
		
	"""
	def __init__(self, parent):
		"""initialize the object
		"""
		Tkinter.Tk.__init__(self, parent)
		self.parent = parent
		self.guiArgs = Object()
		self.initialize()
	#===============================================================================
	#	initialize 
	#===============================================================================
	def initialize(self):
		"""sets variables for user input as Tkinter string variables
		
			| generate tk gui interface
			| set variables for user input (ex from dropbox or textfileds)
			| set available options for user input (ex dropbox)
			| set default values for user input (ex dropbox)
			| configure buttons and textfields
			
			:var str self.cipherVariable: cipher to use
			:var str self.digestVariable: digest to use
			:var str self.filePathVariable: path to file to perform action on
			:var str self.passwordVariable: password to use for encryption/decryption
			:var int self.roundsVariable: number of rounds using self.digestVariable for hashing the password
			:var int self.scryptVariable: number of rounds using scrypt to generate the final password. Set to 0 to disable the usage of scrypt
			:var int self.keysizeVariable: length of key returned by scrypt in bits 
			
		"""
		self.grid()
		#: set variables for gui widgets
		self.labelVariable = Tkinter.StringVar()
 		self.buttonVariable = Tkinter.StringVar()	
		self.cipherVariable = Tkinter.StringVar()		
		self.digestVariable = Tkinter.StringVar()
		self.filePathVariable = Tkinter.StringVar()
		self.passwordVariable = Tkinter.StringVar()
		self.roundsVariable = Tkinter.IntVar()
		self.scryptVariable = Tkinter.IntVar()
		self.keysizeVariable = Tkinter.IntVar()
		"""set available options for OptionMenu dropdowns
		"""
		cipherOptions = ('aes128', 'aes-128-cbc', 'aes192', 'aes-192-cbc', 'aes256', 'aes-256-cbc', 'blowfish', 'bf-cbc', 'camelia128', 'camelia-128-cbc', 'camelia192', 'camelia-192-cbc', 'camelia256', 'camelia-256-cbc')
		digestOptions = ('md5', 'sha', 'sha1', 'ripemd160', 'sha224', 'sha256', 'sha384', 'sha512', 'whirlpool')
		#roundsOptions = (1, 10, 20, 30, 40, 50, 100, 200, 300, 400, 500, 512, 600, 700, 800, 900, 1000, 1024, 2000, 2048, 3000, 4096, 5000, 10000, 20000, 40000, 80000, 160000, 320000, 640000, 1000000)
		scryptOptions = (0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)
		keysizeOptions = (128, 196, 256, 448, 512, 1024, 2048, 4096, 8192)
		"""set default values for OptionMenu dropdowns and input fields
		"""
		self.cipherVariable.set(cipherOptions[6])
		self.digestVariable.set(digestOptions[5])
		self.roundsVariable.set(512)
		self.scryptVariable.set(scryptOptions[0])
		self.keysizeVariable.set(keysizeOptions[3])
		self.filePathVariable.set('</path/to/file>')
		self.passwordVariable.set('<yourSecret>')		
		"""configure textfields and buttons
		"""
		self.filePath = Tkinter.Entry(self, textvariable=self.filePathVariable)
		self.password = Tkinter.Entry(self, textvariable=self.passwordVariable)
		button_enc = Tkinter.Radiobutton(self, variable=self.buttonVariable, text=u"Encrypt", val='enc', indicatoron=0, width=10, command=self.OnButtonClick)
#		button_dec = Tkinter.Radiobutton(self, variable=self.buttonVariable, text=u"Decrypt", val='dec', indicatoron=0, width=10, command=self.OnButtonClick)
		button_decWrite = Tkinter.Radiobutton(self, variable=self.buttonVariable, text=u"Decrypt", val='dec-write', indicatoron=0, width=10, command=self.OnButtonClick)
		self.output = Tkinter.Label(self, textvariable=self.labelVariable, anchor='w', fg="black", bg="grey")
		cipher_desc = Tkinter.Label(self, text='Cipher', anchor='w')
		digest_desc = Tkinter.Label(self, text='Digest', anchor='w')
		rounds_desc = Tkinter.Label(self, text='# of rounds', anchor='w')
		scrypt_desc = Tkinter.Label(self, text='# of scrypt', anchor='w')
		keysize_desc = Tkinter.Label(self, text='Keysize in Bits', anchor='w')
		"""configure MenuOption dropdowns
		"""
		dropdown_cipher = Tkinter.OptionMenu(self, self.cipherVariable, *cipherOptions)
		dropdown_digest = Tkinter.OptionMenu(self, self.digestVariable, *digestOptions)
#		dropdown_rounds = Tkinter.OptionMenu(self, self.roundsVariable, *roundsOptions)
		dropdown_rounds = Tkinter.Entry(self, textvariable=self.roundsVariable)
		#dropdown_scrypt = Tkinter.OptionMenu(self, self.scryptVariable, *scryptOptions)
		dropdown_scrypt = Tkinter.Entry(self, textvariable=self.scryptVariable)
		dropdown_keysize = Tkinter.OptionMenu(self, self.keysizeVariable, *keysizeOptions)		
		#------------------------------------------------------------------------------ 
		#	arrange gui widget elements via grid
		self.filePath.grid(column=0, row=0, sticky='EW')
		self.password.grid(column=1, row=0, sticky='EW')		
		button_enc.grid(column=2,row=0, sticky='W')
	#	button_dec.grid(column=3,row=0, sticky='W')
		button_decWrite.grid(column=3, row=0, sticky='W')
		cipher_desc.grid(column=0, row=2, sticky='W')
		digest_desc.grid(column=1, row=2, sticky='W')
		rounds_desc.grid(column=2, row=2, sticky='W')
		scrypt_desc.grid(column=3, row=2, sticky='W')
		keysize_desc.grid(column=4, row=2, sticky='W')
		dropdown_cipher.grid(column=0, row=3, sticky='W')
		dropdown_digest.grid(column=1, row=3, sticky='W')
		dropdown_rounds.grid(column=2, row=3, sticky='W')
		dropdown_scrypt.grid(column=3, row=3, sticky='W')
		dropdown_keysize.grid(column=4, row=3, sticky='W')
		self.output.grid(column=0, row=4, columnspan=6, sticky='EW')
		#------------------------------------------------------------------------------ 
		#	make gui resizable
		self.grid_columnconfigure(0, weight=1)
		self.resizable(True, True)
	#===========================================================================
	# 	event handler button click
	#===========================================================================
	def OnButtonClick(self):
		"""action function triggered by user selecting the preferences and button clicks
		"""
		self.output.config(bg='grey')
		self.labelVariable.set('')
		self.update_idletasks()
		if self.filePathVariable.get() == '</path/to/file>':
			self.labelVariable.set('No file provided')
			self.output.config(bg='red')
			return 1
		elif self.passwordVariable.get() == '<yourSecret>':
			self.labelVariable.set('No password provided')
			self.output.config(bg='red')
			return 1
		else: 
			self.guiArgs = Object()
			if self.buttonVariable.get() == 'enc':
				#self.cmd = baseDir + '/../crypt.py -f ' + self.filePathVariable.get() + ' -p ' + self.passwordVariable.get() + ' -c ' + self.cipherVariable.get() + ' -d ' + self.digestVariable.get() + ' -r ' + str(self.roundsVariable.get()) + ' -k ' + str(self.keysizeVariable.get()) + ' -s ' + str(self.scryptVariable.get()) + ' --verbose enc'
				#self.runCrypt()
				self.guiArgs.action = 'enc'
			elif self.buttonVariable.get() == 'dec':
				self.guiArgs.action = 'dec'
			elif self.buttonVariable.get() == 'dec-write':
				self.guiArgs.action = 'dec-write'
			else:
				self.labelVariable.set('Unknown action <' + self.buttonVariable + '> provided')
			#app = opensslCrypt(args=None, parent=self)
			#return 0
			self.cmd ='python ' + baseDir + '/../crypt.py' + ' -f ' + self.filePathVariable.get() + ' -p ' + self.passwordVariable.get() + ' -c ' + self.cipherVariable.get() + ' -d ' + self.digestVariable.get() + ' -r ' + str(self.roundsVariable.get()) + ' -k ' + str(self.keysizeVariable.get()) + ' -s ' + str(self.scryptVariable.get()) + ' --np ' + self.guiArgs.action
			#app = opensslCrypt(None, self)
			self.runCrypt()
# 			elif self.buttonVariable.get() == 'Decrypt':
# 				self.cmd = baseDir + '/../crypt.py -f ' + self.filePathVariable.get() + ' -p ' + self.passwordVariable.get() + ' -c ' + self.cipherVariable.get() + ' -d ' + self.digestVariable.get() + ' -r ' + str(self.roundsVariable.get()) + ' -k ' + str(self.keysizeVariable.get()) + ' -s ' + str(self.scryptVariable.get()) + ' --verbose dec'
# 				self.runCrypt()
# 			elif self.buttonVariable.get() == 'Write':
# 				self.cmd = baseDir + '/../crypt.py -f ' + self.filePathVariable.get() + ' -p ' + self.passwordVariable.get() + ' -c ' + self.cipherVariable.get() + ' -d ' + self.digestVariable.get() + ' -r ' + str(self.roundsVariable.get()) + ' -k ' + str(self.keysizeVariable.get()) + ' -s ' + str(self.scryptVariable.get()) + ' --verbose dec-write'				
# 				self.runCrypt()
	#===========================================================================
	# 	call crypt bash script via subprocess and read output in realtime
	#===========================================================================
	def runCrypt(self):
		"""read parameters and execute the encryption/decryption proccess
		
			interacts with crypt
			
			:todo: change code to call the python version of crypt as the current code **ONLY works with the bash version of crypt** (crypt.sh)
			
		"""
		content = ''
		scriptStdout = ''
		process = subprocess.Popen(shlex.split(self.cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		#process = subprocess.Popen(opensslCrypt(None, self), stdout=subprocess.PIPE)
		#: output line by line to stdout (cli) and label widget
		while process.poll() is None:
			
			line = process.stdout.readline()
 # 		print line.strip()
			scriptStdout = scriptStdout + line.strip() + "\n"
			self.labelVariable.set(scriptStdout.lstrip())
			sys.stdout.write(line.lstrip().strip() + "\n")
			sys.stdout.flush()
			#if self.buttonVariable.get() != 'Decrypt' or 'WARN' in line or 'INFO' in line or 'FATAL' in line:
				#------------------------------------------------------------------------------ 
				#	important to see updates on label in realtime
			self.update_idletasks()
		#------------------------------------------------------------------------------ 
		#	if we output the decrypted file conent strip last linebreak
#		self.labelVariable.set(scriptStdout.strip())
#		self.update_idletasks()
		#------------------------------------------------------------------------------ 
		#	color self.output label according to return of subprocess
		if 'FATAL' in line:
			self.output.config(bg='red')
			self.update_idletasks()
		elif 'WARN' in line:
			self.output.config(bg='orange')
			self.update_idletasks()
		else:
			self.output.config(bg='green')
			self.update_idletasks()
		return 0
#===============================================================================
# 	run the whole stuff
#===============================================================================
if __name__ == "__main__":
	app = cryptGui_tk(None)
	app.title('CryptGui')
	img = Tkinter.PhotoImage(file=baseDir + '/favicon.png')
	app.tk.call('wm', 'iconphoto', app._w, img)
	app.mainloop()