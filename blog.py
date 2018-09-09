import os
import re
import string
import hashlib
import hmac
import random
from google.appengine.ext import db

import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "dopedopedope"


def make_secure_val(uid):
    return "%s|%s" % (uid, hmac.new(secret, str(uid)).hexdigest())


def check_secure_val(uid, secure_val):
    return make_secure_val(uid) == secure_val


# Blog Stuff
class BlogHandler(webapp2.RequestHandler):
    """Handler for all web requests"""

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        self.write(self.render_str(template, **params))

    def set_cookie_val(self, name, val):
        self.response.headers.add_header(
            "Set-Cookie",
            "%s=%s; Path=/" % (name, val))

    def read_cookie_val(self, name):
        return self.request.cookies.get(name)

    def read_secure_val(self, name):
        secure_val = self.read_cookie_val(name)
        if not secure_val:
            return None
        val = secure_val.split("|")[0]
        if val and check_secure_val(val, secure_val):
            return val

    def login(self, uid):
        self.set_cookie_val("user_id", make_secure_val(uid))

    def logout(self):
        self.response.headers.add_header(
            "Set-Cookie",
            "user_id=; Path=/")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_val("user_id")
        self.user = uid and User.by_id(int(uid))


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Post(db.Model):
    """Database model for posts"""

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty(required=False)
    likes = db.IntegerProperty(default=0)

    def render(self, user, icon=True):
        self._render_text = self.content.replace("\n", "<br>")
        if not user or user.name != self.author:
            icon = False
        return render_str("single-post.html", p=self, user=user, icon=icon)

    @classmethod
    def by_id(cls, post_id):
        return cls.get_by_id(int(post_id))


class BlogFront(BlogHandler):
    """Handler for landing and front pages"""

    def get(self):
        msg = self.request.get("error_msg")
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
        self.render("front.html", posts=posts, user=self.user, msg=msg)


class NewPost(BlogHandler):
    """Handler for creating new posts"""

    def get(self):
        if not self.user:
            msg = "Login first, please."
            self.redirect("/blog?error_msg=%s" % msg)
            return
        self.render("newpost.html", user=self.user)

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        author = self.user.name

        if subject and content:
            p = Post(subject=subject,
                     content=content,
                     author=author)
            p.put()
            self.redirect("/blog/" + str(p.key().id()))
        else:
            msg = "You need to fill in both a subject and content"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=msg,
                        user=self.user)


class PostPage(BlogHandler):
    """Handler for the post page"""

    def get(self, post_id):
        msg = self.request.get("error_msg")
        post = Post.by_id(int(post_id))
        comments = db.GqlQuery("SELECT * FROM Comment " +
                               "WHERE post_id='%s'" % post_id)
        if not post:
            self.error(404)
        else:
            self.render("post.html",
                        post=post,
                        user=self.user,
                        msg=msg,
                        comments=comments)


class ModifyPost(BlogHandler):
    """Handler for modifying posts"""

    def get(self):
        post_id = self.request.get("id")
        if post_id and Post.by_id(post_id):
            post = Post.by_id(post_id)
            # Check permission
            if not self.user or self.user.name != post.author:
                msg = "Permission denied."
                self.redirect("/blog?error_msg=%s" % msg)
                return
            self.render("newpost.html",
                        subject=post.subject,
                        content=post.content,
                        user=self.user,
                        title="Modify")
        else:
            self.redirect("/blog")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        post_id = self.request.get("id")
        if post_id and Post.by_id(post_id):
            post = Post.by_id(post_id)
            if not self.user or self.user.name != post.author:
                msg = "Permission denied."
                self.redirect("/blog?error_msg=%s" % msg)
                return
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect("/blog/" + str(post.key().id()))
        else:
            msg = "You need to fill in both a subject and content"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=msg,
                        user=self.user,
                        title="Modify")


class DeletePost(BlogHandler):
    """Handler to delete posts"""

    def get(self):
        post_id = self.request.get("id")
        if post_id and Post.by_id(post_id):
            post = Post.by_id(post_id)
            if not self.user or self.user.name != post.author:
                msg = "Permission denied."
                self.redirect("/blog?error_msg=%s" % msg)
                return
            post.delete()
            self.redirect("/blog")
        else:
            self.redirect("/blog")


class LikePost(BlogHandler):
    """Handler to like and unlike posts"""

    def get(self):
        post_id = self.request.get("id")
        if post_id and Post.by_id(post_id):
            post = Post.by_id(post_id)
            if not self.user:
                msg = "Login first, please."
                self.redirect("/blog/%s?error_msg=%s" % (post_id, msg))
                return
            if self.user.name == post.author:
                msg = "You can not like your own post."
                self.redirect("/blog/%s?error_msg=%s" % (post_id, msg))
                return
            for liked_post in self.user.liked_posts:
                if liked_post == int(post_id):
                    post.likes -= 1
                    post.put()
                    self.user.liked_posts.remove(int(post_id))
                    self.user.put()
                    self.redirect("/blog/%s" % post_id)
                    return
            post.likes += 1
            post.put()
            self.user.liked_posts.append(int(post_id))
            self.user.put()
            self.redirect("/blog/%s" % post_id)
        else:
            self.redirect("/blog")
            return


# Comment Stuff
class Comment(db.Model):
    """Database model for comments"""

    name = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self, user):
        self._render_text = self.content.replace("\n", "<br>")
        return render_str("single-comment.html", comment=self, user=user)

    @classmethod
    def by_id(cls, comment_id):
        return cls.get_by_id(int(comment_id))


class NewComment(BlogHandler):
    """Handler for creating new comments"""

    def get(self, post_id):
        if not self.user:
            msg = "Login first, please."
            self.redirect("/blog/%s?error_msg=%s" % (post_id, msg))
            return
        self.render("newcomment.html", user=self.user)

    def post(self, post_id):
        if not self.user:
            msg = "Login first. please."
            self.redirect("/blog/%s?error_msg=%s" % (post_id, msg))
            return
        name = self.user.name
        content = self.request.get("content")
        if not content:
            msg = "Content can not be empty."
            self.render("newcomment.html", user=self.user, msg=msg)
            return
        comment = Comment(name=name,
                          content=content,
                          post_id=post_id)
        comment.put()
        self.redirect("/blog/%s" % post_id)


class ModifyComment(BlogHandler):
    """Handler to modify comments"""

    def get(self, post_id):
        if not Post.by_id(post_id):
            self.redirect("/blog")
            return
        comment_id = self.request.get("id")
        if not Comment.by_id(comment_id):
            self.redirect("/blog/%s" % post_id)
            return
        comment = Comment.by_id(comment_id)
        if not self.user or self.user.name != comment.name:
            self.redirct("/blog/%s?error_msg=%s" %
                         (post_id, "Permission denied."))
            return
        self.render("newcomment.html",
                    content=comment.content,
                    user=self.user)

    def post(self, post_id):
        if not Post.by_id(post_id):
            self.redirect("/blog")
            return
        comment_id = self.request.get("id")
        if not Comment.by_id(comment_id):
            self.redirect("/blog/%s" % post_id)
            return
        comment = Comment.by_id(comment_id)
        if not self.user or self.user.name != comment.name:
            self.redirct("/blog/%s?error_msg=%s" %
                         (post_id, "Permission denied."))
            return
        content = self.request.get("content")
        if not content:
            msg = "Content can not be empty."
            self.render("newcomment.html", user=self.user, msg=msg)
            return
        comment.content = content
        comment.put()
        self.redirect("/blog/%s" % post_id)


class DeleteComment(BlogHandler):
    """Handler to delete comments"""

    def get(self, post_id):
        if not Post.by_id(post_id):
            self.redirect("/blog")
            return
        comment_id = self.request.get("id")
        if not Comment.by_id(comment_id):
            self.redirect("/blog/%s" % post_id)
            return
        comment = Comment.by_id(comment_id)
        if not self.user or self.user.name != comment.name:
            self.redirct("/blog/%s?error_msg=%s" %
                         (post_id, "Permission denied."))
            return
        comment.delete()
        self.redirect("/blog/%s" % post_id)


# User Stuff
def make_salt(length=5):
    return "".join(random.choice(string.letters) for _ in range(length))


# Created a hashed password from name, password and salt
def make_pw_hash(name, password, salt=None):
    if salt is None:
        salt = make_salt()
    return hashlib.sha256(name + password + salt).hexdigest() + "|" + salt


def check_password(name, password, password_hash):
    salt = password_hash.split("|")[1]
    return make_pw_hash(name, password, salt) == password_hash


class User(db.Model):
    """Database model for users"""

    name = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    liked_posts = db.ListProperty(int)

    @classmethod
    def by_name(cls, name):
        u = db.GqlQuery("SELECT * FROM User WHERE name = '%s'" % name)
        return u.get()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(int(uid))

    @classmethod
    def register(cls, username, password, email):
        password_hash = make_pw_hash(username, password)
        return User(name=username,
                    password_hash=password_hash,
                    email=email)

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and check_password(username, password, u.password_hash):
            return u


USER_RE = re.compile(r"^[a-zA-Z0-9-_]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASS_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)


class SignUp(BlogHandler):
    """Handler for the sign up page"""

    def get(self):
        self.render("signup-form.html", user=self.user)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username=username, email=email)

        # Check whether inputs are valid
        have_error = False
        if not valid_username(username):
            have_error = True
            params["username_error"] = "Username is not valid."
        if not valid_password(password):
            have_error = True
            params["password_error"] = "Password is not valid."
        elif verify != password:
            have_error = True
            params["verify_error"] = "Did not match the password."
        if email and not valid_email(email):
            have_error = True
            params["email_error"] = "Email is not valid."
        if have_error:
            self.render("signup-form.html", user=self.user, **params)
        else:
            # Check whether username already exists
            u = User.by_name(username)
            if u:
                params["username_error"] = "Username already exists."
                self.render("signup-form.html", user=self.user, **params)
            else:
                new_user = User.register(username, password, email)
                new_user.put()
                self.login(new_user.key().id())
                self.redirect("/blog")


class Login(BlogHandler):
    """Handler for the login page"""

    def get(self):
        self.render("login-form.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        u = User.login(username, password)
        if u:
            self.login(u.key().id())
            self.redirect("/blog")
        else:
            msg = "Wrong username or password."
            self.render("login-form.html",
                        username=username,
                        error=msg,
                        user=self.user)


class Logout(BlogHandler):
    """Handler to logout"""

    def get(self):
        self.logout()
        self.redirect("/blog")


app = webapp2.WSGIApplication([("/blog/?", BlogFront),
                              ("/blog/newpost/?", NewPost),
                              ("/blog/([0-9]+)/?", PostPage),
                              ("/signup/?", SignUp),
                              ("/login/?", Login),
                              ("/logout/?", Logout),
                              ("/blog/modify/?", ModifyPost),
                              ("/blog/delete/?", DeletePost),
                              ("/blog/like/?", LikePost),
                              ("/blog/([0-9]+)/comment", NewComment),
                              ("/blog/([0-9]+)/comment/modify", ModifyComment),
                              ("/blog/([0-9]+)/comment/delete",
                              DeleteComment)],
                              debug=True)

