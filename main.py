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
import re

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
										autoescape = True)

from google.appengine.ext import db
from google.appengine.api import memcache

from accounts import *

class WikiHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template,**kw))

class Pages(db.Model):
	pagename = db.StringProperty()
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	version = db.IntegerProperty(required = True)

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

def get_data(pagename, update = False):
	key = pagename
	content = memcache.get(key)
	if content is None or update:
		fp = Pages.all().filter('pagename =', pagename).get()
		if fp:
			memcache.set(key, fp.content)
			content = fp.content
		else:
			memcache.set(key,'')
			content = ''
	return content

def set_data(pagename, content):
	key = pagename
	memcache.set(key, content)

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
				set_secure_cookie(self, 'user_id', str(newuser.key().id()))
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
		self.redirect(self.request.referer)

class WikiPage(WikiHandler):
	def get(self):
		path = self.request.path
		pagename = path[1:]
		para = self.request.query_string
		if para:
			version  = int(para[2:])
			fp = db.GqlQuery("select * from Pages where version=:1", version).get()
			content = fp.content
		else:
			content = get_data(pagename)
		# fp = Pages.all().filter('pagename =', pagename).get()
		user = self.request.cookies.get('user_id')
		if pagename=='':
			if user:
				u_id = user.split('|')[0]
				u_name = User.get_by_id(int(u_id))
				if u_name and read_secure_cookie(self, 'user_id'):
					self.render('wikipage.html', 
										pagename=pagename,
										username=u_name.username,
										pagecontent=content)
			else:
				self.render('wikipage.html',
										pagename=pagename,
										username='',
										pagecontent=content)
		elif content:
			if user:
				u_id = user.split('|')[0]
				u_name = User.get_by_id(int(u_id))
				if u_name and read_secure_cookie(self, 'user_id'):
					self.render('wikipage.html', 
										pagename=pagename,
										username=u_name.username,
										pagecontent=content)
			else:
				self.render('wikipage.html',
										pagename=pagename,
										username='',
										pagecontent=content)
		else:
			self.redirect('/_edit/'+pagename)

class EditPage(WikiHandler):
	def get(self):
		path = self.request.path
		pagename = path[7:]
		para = self.request.query_string
		if para:
			version  = int(para[2:])
			fp = db.GqlQuery("select * from Pages where version=:1", version).get()
		else:
			fp = Pages.all().filter('pagename =', pagename).order('-version').get()
		user = self.request.cookies.get('user_id')
		if user:
			u_id = user.split('|')[0]
			u_name = User.get_by_id(int(u_id))
			if u_name and read_secure_cookie(self, 'user_id'):
				self.render('editpage.html',
								pagename = pagename,
								username = u_name.username,
								pagecontent=fp)
		else:
			self.response.write('Please Login First!')

	def post(self):
		content = self.request.get('content')
		path = self.request.path
		pagename = path[7:]
		fp = Pages.all().filter('pagename =', pagename).get()
		if not fp:
			a = Pages(pagename=pagename, content=content, version=1)
			set_data(pagename, content)
			a.put()
		else:
			maxversions = Pages.all().filter('pagename =', pagename).order('-version').get()
			version = maxversions.version+1
			a = Pages(pagename=pagename, content=content, version=version)
			set_data(pagename, content)
			a.put()
		self.redirect('/%s' %pagename)

class HistPage(WikiHandler):
	def get(self):
		path = self.request.path
		pagename = path[10:]
		# hists = Pages.all().filter('pagename =', pagename).get()
		hists = db.GqlQuery("select * from Pages order by version desc")
		user = self.request.cookies.get('user_id')
		if user:
			u_id = user.split('|')[0]
			u_name = User.get_by_id(int(u_id))
			if u_name and read_secure_cookie(self, 'user_id'):
				self.render('history.html', 
										pagename=pagename,
										username=u_name.username,
										pagecontent=hists)


class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write('Hello world!')

app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/_edit'+'/(?:[a-zA-Z0-9_-]+/?)*', EditPage),
    ('/_history'+'/(?:[a-zA-Z0-9_-]+/?)*', HistPage),
    ('/(?:[a-zA-Z0-9_-]+/?)*', WikiPage)
], debug=True)
