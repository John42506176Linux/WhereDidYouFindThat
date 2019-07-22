import webapp2
import jinja2
import os
# from google.cloud import datastore
from webapp2_extras import auth
from webapp2_extras import sessions
from google.appengine.ext.webapp import template
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

# the handler section
the_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    print("Reached check login")
    if not auth.get_user_by_session():
        print("Check login doesn't work")
        self.redirect(self.uri_for('login'), abort=True)
    else:
        print("Check login works")
        return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params={}):
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'templates', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)


class MainPage(BaseHandler):
    @user_required
    def get(self):
        params = {
          'first_name': self.user.first_name,
          'logged_in': True
        }
        self.render_template('index.html',params)


class UploadPhotoPage(BaseHandler,blobstore_handlers.BlobstoreUploadHandler):
    @user_required
    def get(self):
        params = {
          'first_name': self.user.first_name,
        }
        upload_url = blobstore.create_upload_url('/upload_photo')
        self.response.out.write(template.render("templates/ProfilePicture.html", params).format(upload_url))

    def post(self):
        upload = self.get_uploads()[0]
        self.user.user_photo = upload.key()
        self.user.put()
        self.redirect(self.uri_for('home'))



class LogOutPage(BaseHandler):
    @user_required
    def get(self): #for a get request
        self.user.logged_in = False
        self.auth.unset_session()
        self.redirect(self.uri_for('login'))



class LoginPage(BaseHandler):
    def error_login(self, error):
        params = {
          'bad_login': 'Yes',
          'bad_response': error
        }
        self.render_template('Login.html', params)

    def get(self):
        self.render_template('Login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        remember_var =  self.request.get('remember')
        print("Password is " + password)
        print("%s is the username " %(username))
        try:
          u = self.auth.get_user_by_password(username, password, remember=True)
          self.redirect(self.uri_for('home'))
        except (InvalidAuthIdError, InvalidPasswordError) as e:
          if "InvalidPasswordError" in str(type(e)):
            self.error_login("Wrong password")
          else:
            self.error_login("Wrong username")


class SignUpPage(BaseHandler):
    def get(self):
        self.render_template('Signup.html')

    def post(self):
        first_name_var = self.request.get('first_name')
        last_name_var = self.request.get('last_name')
        username_var = self.request.get('username')
        password_var = self.request.get('password')
        remember_var = self.request.get('remember')
        email_var = self.request.get('email')
        unique_properties = ['email','username','password']
        user_data = self.user_model.create_user(username_var,unique_properties,username=username_var,email=email_var,
                                                password_raw=password_var,logged_in=True,first_name = first_name_var,
                                                last_name=last_name_var
                                                )
        if not user_data[0]:
            error = {
                'bad_login' : 'Yes',
                'bad_response' : 'Duplicates for %s ' % (user_data[1])
            }
            return self.render_template('Signup.html',error)
        user = user_data[1]
        if remember_var == "on":
            print("Remember function says checkbox is on")
            self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
        else:
            print("Remember function says checkbox is off")
            self.auth.set_session(self.auth.store.user_to_dict(user), remember=False)
        self.redirect(self.uri_for('UploadPhoto'))


# the app configuration section
config = {
  'webapp2_extras.auth': {
    'user_model': 'Users.User',
    'user_attributes': ['username','password','email','first_name','last_name']
  },
  'webapp2_extras.sessions': {
    'secret_key': '\x0cWh\xd4|\xfd\xe6G\xba\x06\xf7)\xcf\xd32\x14\xc4\xbe\x8e\x10=\x87-r'
  }
}
app = webapp2.WSGIApplication([
    webapp2.Route('/', handler=MainPage, name='home'),
    webapp2.Route('/Logout', handler=LogOutPage, name='logout'),
    webapp2.Route('/Login', handler=LoginPage, name='login'),
    webapp2.Route('/sign_up', handler=SignUpPage, name='SignUp'),
    webapp2.Route('/upload_photo', handler=UploadPhotoPage, name='UploadPhoto'),
], debug=True,config=config)
