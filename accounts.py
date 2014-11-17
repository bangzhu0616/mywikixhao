import re
import hashlib
import hmac
import random
import string

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EM_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

secret = ":m2#[Bc+Mb>Yw[|xhaowiki"

def verify_username(username):
	return USER_RE.match(username)

def verify_pwd(pwd):
	return PWD_RE.match(pwd)

def match_pwd(pwd, ver):
	if pwd==ver:
		return True
	else:
		return False

def verify_em(em):
	if em=='':
		return True
	return EM_RE.match(em)

def hash_pwd(s):
	return hmac.new(secret,s).hexdigest()

def make_salt():
	return ''.join([random.choice(string.letters) for i in range(5)])

def make_pw_salt(name, pw):
	salt = make_salt()
	return hashlib.sha256(name+pw+salt).hexdigest()+','+salt

def check_pwd(name, pw, ha):
	a = string.split(ha, ',')
	hnp = a[0]
	salt = a[1]
	if hashlib.sha256(name+pw+salt).hexdigest()==hnp:
		return True
	else:
		return False

def make_secure_val(s):
	return "%s|%s" % (s, hash_pwd(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def set_secure_cookie(self, name, val):
	cookie_val = make_secure_val(val)
	self.response.headers.add_header('Set-Cookie',
								'%s=%s; Path=/' % (str(name), str(cookie_val)))

def read_secure_cookie(self, name):
	cookie_val = self.request.cookies.get(name)
	return cookie_val and check_secure_val(cookie_val)
