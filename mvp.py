import hmac
from hashlib import sha512
import os.path
import Crypto.Cipher.AES as AES

class Repo:
	def __init__(self, root, salt1, salt2):
		self.root = root
		dff = lambda salt: lambda: hmac.new(salt, digestmod=sha512)
		self.kdf = dff(salt1)
		self.ndf = dff(salt2)
	
	def cipher(self, key):
		secret, iv = key[:32], key[48:] #hmm, some wasted entropy
		return AES.new(secret, AES.MODE_CFB, iv) # let's make a change!!
		

	def encrypt(self, key, content):
		cipher = self.cipher(key)
		return cipher.encrypt(content)

	def decrypt(self, key, content):
		cipher = self.cipher(key)
		return cipher.decrypt(content)

	def _put(self, name, value):
		path = os.path.join(self.root, name)
		file(path, 'w').write(value)

	def _get(self, name):
		path = os.path.join(self.root, name)
		return file(path).read()

	def put(self, content):
		kd = self.kdf()
		kd.update(content)
		key = kd.digest()
		scrambled = self.encrypt(key, content)
		nd = self.ndf()
		nd.update(scrambled)
		name = nd.hexdigest()
		self._put(name, scrambled)
		return name, key.encode('hex')
		
	def get(self, name, key):
		scrambled = self._get(name)
		return self.decrypt(key, scrambled)
		

if __name__ == '__main__':
	from sys import argv, stdin, stdout, stderr, exit
	from os import environ
	try:
		dd_repo, dd_salt1, dd_salt2 = map(environ.__getitem__, 'DD_REPO DD_SALT1 DD_SALT2'.split())
	except KeyError, e:
		print >> stderr, 'must define DD_REPO DD_SALT1 DD_SALT2 in environment'
		exit(1)
	repo = Repo(dd_repo, dd_salt1, dd_salt2)
	if argv[1:] == [ 'put' ]:
		name, key = repo.put(stdin.read())
		print name, key
	else:
		get, name, key = argv[1:]
		if 'get' != get:
			print >> stderr, 'either "put" and content on stdin or "get <name> <key>" and content on stdout'
			exit(1)
		key = key.decode('hex')
		stdout.write(repo.get(name, key))
