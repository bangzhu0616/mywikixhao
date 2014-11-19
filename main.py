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

# import functions about account
from accounts import *

# Main handler
class WikiHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template,**kw))


class Pages(db.Model):
	"""
	The page database. 
	Pagename is the main ID of a page, which is the same as the end of the 
	url: http://wikiaddress/[pagename].
	Content is the the content of this page. autoescape is False.
	Created is the created time of this page.
	Last_modified not used in this application.
	Version is the version number of this page, which is the second ID of a 
	page. In the bonus problem, one pagename may have many versions.
	"""
	pagename = db.StringProperty()
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	version = db.IntegerProperty(required = True)

class User(db.Model):
	"""
	The user database.
	"""
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

def get_data(pagename, update = False):
	"""
	This function is for the memcache in front of the database, to get the content from
	the database. User will not communicate with databa directly.
	"""
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
	"""
	This function is for storing the content to database after a page was edited. Because the user 
	will not communicate with databa directly, the user only change the memcache, and this function
	stores the chagne to memcache. The memcache will store the chagne to database in EditPage handler.
	"""
	key = pagename
	memcache.set(key, content)

class Signup(WikiHandler):
	"""
	This class is the signup handler.
	"""
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		# get the fields submited from the signup form
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		# make the parameter dictionary
		params = dict(username=username, email=email)

		# Check all the four fields legal or not. These function are in accounts.py
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
				# set the cookie
				set_secure_cookie(self, 'user_id', str(newuser.key().id()))
				self.redirect('/')

class Login(WikiHandler):
	"""
	This class is for login
	"""
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		error = 'Invalid login!'
		user = User.all().filter('username =', username).get()
		if not user:
			# This user is not exists.
			self.render('login.html',error_login=error)
		else:
			user_hash = user.password
			if check_pwd(username, password, user_hash):
				# login success.
				set_secure_cookie(self, 'user_id', str(user.key().id()))
				self.redirect('/')
			else:
				# Password wrong!!!
				self.render('login.html',error_login=error)

class Logout(WikiHandler):
	"""
	This class is for logout. Only delete the cookie.
	"""
	def get(self):
		self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
		self.redirect(self.request.referer)

class WikiPage(WikiHandler):
	"""
	This class is for showing a wiki page. No post method.
	"""
	def get(self):
		path = self.request.path
		pagename = path[1:]
		# get the query string in url. In bonus problem this para is the version of the page. 
		para = self.request.query_string
		if para:
			# get the version number
			version  = int(para[2:])
			# get the content of certain version
			fp = db.GqlQuery("select * from Pages where version=:1", version).get()
			content = fp.content
		else:
			# get the data from memcache, not in bonus problem
			content = get_data(pagename)
		# get the cookie information to decide the head of this page
		user = self.request.cookies.get('user_id')
		if pagename=='':
			# front page
			if user:
				u_id = user.split('|')[0]
				u_name = User.get_by_id(int(u_id))
				if u_name and read_secure_cookie(self, 'user_id'):
					# already login
					self.render('wikipage.html', 
										pagename=pagename,
										username=u_name.username,
										pagecontent=content)
			else:
				# guest
				self.render('wikipage.html',
										pagename=pagename,
										username='',
										pagecontent=content)
		elif content:
			# not frontpage, but this page already exist.
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
			# not frontpage, this is a new page.
			self.redirect('/_edit/'+pagename)

class EditPage(WikiHandler):
	"""
	This class is for the edit page.
	"""
	def get(self):
		# get the path in the url so that get the pagename
		path = self.request.path
		pagename = path[7:]
		# get the version or no version
		para = self.request.query_string
		# get the row of this editing page.
		if para:
			version  = int(para[2:])
			fp = db.GqlQuery("select * from Pages where version=:1", version).get()
		else:
			fp = Pages.all().filter('pagename =', pagename).order('-version').get()
		# get the cookie
		user = self.request.cookies.get('user_id')
		if user:
			u_id = user.split('|')[0]
			u_name = User.get_by_id(int(u_id))
			if u_name and read_secure_cookie(self, 'user_id'):
				# show the edit page.
				self.render('editpage.html',
								pagename = pagename,
								username = u_name.username,
								pagecontent=fp)
		else:
			# if guest, show the login message.
			self.response.write('Please Login First!')

	def post(self):
		"""
		Save the new version of this page.
		"""
		# get the new content of this page
		content = self.request.get('content')
		# get the pagename
		path = self.request.path
		pagename = path[7:]
		# get all the version of this page
		fp = Pages.all().filter('pagename =', pagename).get()
		if not fp:
			# This is a new page. Store it to database and set the memcache. version is 1
			a = Pages(pagename=pagename, content=content, version=1)
			set_data(pagename, content)
			a.put()
		else:
			# get the max version number of this page.
			maxversions = Pages.all().filter('pagename =', pagename).order('-version').get()
			# set this version number
			version = maxversions.version+1
			# Store it to database and set the memcache. version is max+1
			a = Pages(pagename=pagename, content=content, version=version)
			set_data(pagename, content)
			a.put()
		# redirect to the new version of this page.
		self.redirect('/%s' %pagename)

class HistPage(WikiHandler):
	"""
	Handler for bonus question
	"""
	def get(self):
		# get the pagename
		path = self.request.path
		pagename = path[10:]
		# get all version of this page
		hists = db.GqlQuery("select * from Pages order by version desc")
		user = self.request.cookies.get('user_id')
		if user:
			u_id = user.split('|')[0]
			u_name = User.get_by_id(int(u_id))
			if u_name and read_secure_cookie(self, 'user_id'):
				# display all versions
				self.render('history.html', 
										pagename=pagename,
										username=u_name.username,
										pagecontent=hists)


class MainHandler(webapp2.RequestHandler):
	"""
	Not used.
	"""
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
