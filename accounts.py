
#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import re
import hashlib
import hmac
import random
import string

"""
regular expression of username, password and email, used in followed 4 functions.
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EM_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

# the secret for hash passworkd
secret = ":m2#[Bc+Mb>Yw[|xhaowiki"

"""
The followed four functions are verify the fields of signup form are legal or not.
"""
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

"""
The followed four functions are for hashing the password and checking the password when login.
"""
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

"""
The followed four functions are for cookie.
"""
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
