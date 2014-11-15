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
import webapp2
import jinja2
import os

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
										autoescape = True)

from google.appengine.ext import db

from signup import *

class WikiHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template,**kw))

class Pages(db.Model):
	id = db.IntegerProperty(required = True)
	pagename = db.StringProperty()
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

class Signup(WikiHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username=username, email=email)

		if not verify_username(username):
			params['error_username'] = "That's not a valid username."
			haver_error = True

		if not verify_pwd(password):
			params['error_verify'] = "That's not a valid password."
			have_error = True
		elif not match_pwd(password, verify):
			params['error_verify'] = "Your password do not match."
			have_error = True

		if not verify_em(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup.html', **params)
		else:
			user = User.all().filter('username =', username).get()
			if user:
				self.render('signup.html', error_username="That user already exists.")
			else:
				newuser = User(username=username,
								password=make_pw_salt(username,password),
								email=email)
				newuser.put()
				set_secure_cookie(self, 'user_id', str(user.key().id()))
				self.redirect('/')

class Login(WikiHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		error = 'Invalid login!'
		user = User.all().filter('username =', username).get()
		if not user:
			self.render('login.html',error_login=error)
		else:
			user_hash = user.password
			if check_pwd(username, password, user_hash):
				set_secure_cookie(self, 'user_id', str(user.key().id()))
				self.redirect('/')
			else:
				self.render('login.html',error_login=error)

class Logout(WikiHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
		self.redirect('/')

class FrontPage(WikiHandler):
	def get(self):
		global loginflag
		fp = db.GqlQuery("select * from Pages where id = 1")
		user = self.request.cookies.get('user_id')
		if user:
			u_id = user.split('|')[0]
			u_name = User.get_by_id(int(u_id))
			if u_name and read_secure_cookie(self, 'user_id'):
				self.render('wikipage.html', login=1, 
									pagename='',
									username=u_name.username,
									pagecontent=fp)
		else:
			self.render('wikipage.html',login=0,
									pagename='',
									username='',
									pagecontent=fp)

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write('Hello world!')

app = webapp2.WSGIApplication([
    ('/', FrontPage),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout)
], debug=True)
