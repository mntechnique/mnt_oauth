import frappe
from frappe import database
from oauthlib.oauth2 import RequestValidator
from oauthlib.common import Request
from mnt_oauth.doctype.oauth_client.oauth_client import OAuthClient
import urllib

from urlparse import parse_qs, urlparse
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant, ImplicitGrant, ResourceOwnerPasswordCredentialsGrant, ClientCredentialsGrant,  RefreshTokenGrant

from oauthlib.oauth2.rfc6749.endpoints.authorization import AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.endpoints.resource import ResourceEndpoint
from oauthlib.oauth2.rfc6749.endpoints.revocation import RevocationEndpoint

def printstuff(stuff, times=20):
	for x in xrange(1,times):
		print stuff
	

#https://github.com/idan/oauthlib/blob/master/examples/skeleton_oauth2_web_application_server.py

#POSTAUTH REQUEST
#http://0.0.0.0:8000/api/method/mnt_oauth.api_oauth.mnt_providetoken?client_id=abc&client_secret=123456&grant_type=authorization_code&code=wbRjzg8BP0jtdU0JIkUjPvDpOWXKzz&redirect_uri=http://0.0.0.0:8000/redir.html

class WebApplicationServer(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint,
						   RevocationEndpoint):

	"""An all-in-one endpoint featuring Authorization code grant and Bearer tokens."""

	def __init__(self, request_validator, token_generator=None,
				 token_expires_in=None, refresh_token_generator=None, **kwargs):
		"""Construct a new web application server.

		:param request_validator: An implementation of
								  oauthlib.oauth2.RequestValidator.
		:param token_expires_in: An int or a function to generate a token
								 expiration offset (in seconds) given a
								 oauthlib.common.Request object.
		:param token_generator: A function to generate a token from a request.
		:param refresh_token_generator: A function to generate a token from a
										request for the refresh token.
		:param kwargs: Extra parameters to pass to authorization-,
					   token-, resource-, and revocation-endpoint constructors.
		"""
		auth_grant = AuthorizationCodeGrant(request_validator)
		refresh_grant = RefreshTokenGrant(request_validator)
		bearer = BearerToken(request_validator, token_generator,
							 token_expires_in, refresh_token_generator)
		AuthorizationEndpoint.__init__(self, default_response_type='code',
									   response_types={'code': auth_grant},
									   default_token_type=bearer)
		TokenEndpoint.__init__(self, default_grant_type='authorization_code',
							   grant_types={
								   'authorization_code': auth_grant,
								   'refresh_token': refresh_grant,
							   },
							   default_token_type=bearer)
		ResourceEndpoint.__init__(self, default_token='Bearer',
								  token_types={'Bearer': bearer})
		RevocationEndpoint.__init__(self, request_validator)


class MNTOAuthWebRequestValidator(RequestValidator):

	# def _load_application(self, client_id, request):
	# 	"""
	# 	If request.client was not set, load application instance for given client_id and store it
	# 	in request.client
	# 	"""

	# 	# we want to be sure that request has the client attribute!
	# 	assert hasattr(request, "client"), "'request' instance has no 'client' attribute"

	# 	oc = frappe.get_doc("OAuth Client", client_id)
		
	# 	try:
	# 		request.client = request.client or oc.as_dict() #Application.objects.get(client_id=client_id)
	# 		return request.client
	# 	except Exception, e:
	# 		print ("Failed body authentication: Application %s does not exist" % client_id)
	# 		return None

	# Ordered roughly in order of appearance in the authorization grant flow

	# Pre- and post-authorization.


	def validate_client_id(self, client_id, request, *args, **kwargs):
		# Simple validity check, does client exist? Not banned?
		cli_id = frappe.db.get_value("OAuth Client",{ "name":client_id })
		if cli_id:
		#  Client.objects.get(client_id=client_id)
			request.client = frappe.get_doc("OAuth Client", client_id).as_dict()
			return True
		else:
			return False

	def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
		# Is the client allowed to use the supplied redirect_uri? i.e. has
		# the client previously registered this EXACT redirect uri.
		#DISABLED FOR TESTING: 160904
		redirect_uris = frappe.db.get_value("OAuth Client", client_id, 'redirect_uris').split(';')
		
		# #Quote URIs to compare with redirect_uri param which will be x-url-form-encoded
		#quoted_uris = []
		
		#printstuff('Request.rediruri:' + redirect_uri)

		# for uri in redirect_uris:
		# 	quoted_uris.append(urllib.quote(uri))

		#printstuff(redirect_uris)

		if redirect_uri in redirect_uris: #quoted_uris:
			return True
		else:
			return False
		#return True
		
	def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
		# The redirect used if none has been supplied.
		# Prefer your clients to pre register a redirect uri rather than
		# supplying one on each authorization request.
		redirect_uri = frappe.db.get_value("OAuth Client", client_id, 'default_redirect_uri')
		return redirect_uri

	def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
		# Is the client allowed to access the requested scopes?
		client_scopes = frappe.db.get_value("OAuth Client", client_id, 'scopes').split(';')

		are_scopes_valid = True

		for scp in scopes:
			are_scopes_valid = are_scopes_valid and True if scp in client_scopes else False

		return are_scopes_valid
		
	def get_default_scopes(self, client_id, request, *args, **kwargs):
		# Scopes a client will authorize for if none are supplied in the
		# authorization request.
		scopes = frappe.db.get_value("OAuth Client", client_id, 'scopes').split(';')
		request.scopes = scopes #Apparently this is possible.
		return scopes

	def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
		# Clients should only be allowed to use one type of response type, the
		# one associated with their one allowed grant type.
		# In this case it must be "code".
		#resp_type_client = frappe.db.get_value("OAuth Client", client_id, 'response_type')
		#print resp_type_client
		#return (resp_type_client.lower() == response_type)


		

		#print client.response_type #Checking
		return (client.response_type.lower() == response_type)


	# Post-authorization

	def save_authorization_code(self, client_id, code, request, *args, **kwargs):

		cookie_dict = get_cookie_dict_from_headers(request)

		oac = frappe.new_doc('OAuth Authorization Code')
		oac.scopes = ';'.join(request.scopes)
		oac.redirect_uri_bound_to_authorization_code = request.redirect_uri
		oac.client = client_id
		oac.user = urllib.unquote(cookie_dict['user_id'])
		oac.authorization_code = code['code']
		oac.save(ignore_permissions=True)
		frappe.db.commit()

		#redirect_uri gets linked to OAC Auth Code via Client link field.

		# Remember to associate it with request.scopes, request.redirect_uri
		# request.client, request.state and request.user (the last is passed in
		# post_authorization credentials, i.e. { 'user': request.user}.
		#pass

	# Token request
	
	# Added later
	# def client_authentication_required(self, request, *args, **kwargs):
	# 	assert hasattr(request, "client"), "'request' instance has no 'client' attribute"

	# 	oc = frappe.get_doc("OAuth Client", request.client_id)
		
	# 	try:
	# 		request.client = request.client or oc.as_dict() #Application.objects.get(client_id=client_id)
	# 		return request.client
	# 	except Exception, e:
	# 		print ("Failed body authentication: Application %s does not exist" % client_id)
	# 		return None

	# 	return True

	

	def authenticate_client(self, request, *args, **kwargs):
		# Whichever authentication method suits you, HTTP Basic might work
		#return True #GRN: Authentication outside OAuth2. Disabled for MNT.
		#
		#return self.authenticate_cltient_id(kwargs['client_id'], request, args, kwargs)
	

		#Get URL from Cookie from Headers
		# cookie = request.headers.get('Cookie')
		# cookie = cookie.split("; ")
		# cookie_dict = {k:v for k,v in (x.split('=') for x in cookie)}

		cookie_dict = get_cookie_dict_from_headers(request)

		#Set Client in request.
		#oc = frappe.get_doc("OAuth Client", request.client_id)

		#Get ClientID in URL
		if request.client_id:
			oc = frappe.get_doc("OAuth Client", request.client_id) #request.client["name"])
		else:
			#Extract token, instantiate OAuth Bearer Token and use clientid from there.
			#querystring = parse_qs(urlparse(request["url"]).query)
			if frappe.form_dict.has_key("refresh_token"):
				oc = frappe.get_doc("OAuth Client", frappe.db.get_value("OAuth Bearer Token", {"refresh_token": frappe.form_dict["refresh_token"]}, 'client'))
			else:
				oc = frappe.get_doc("OAuth Client", frappe.db.get_value("OAuth Bearer Token", frappe.form_dict["token"], 'client'))	
		try:
			request.client = request.client or oc.as_dict()
		except Exception, e:
			print "Failed body authentication: Application %s does not exist".format(cid=request.client_id)
			#return None

		# for x in xrange(1,10):
		# 	print d
			#s.split("; ") #dict(token.split('=') for token in shlex.split(s))

			# cookie = Cookie.SimpleCookie()
			# cookie.load()
			# print cookie['user_id'].value
		# if cookie_dict != None:
		return frappe.session.user == urllib.unquote(cookie_dict.get('user_id', "Guest"))
		#else:
			#return frappe.session.user == "Guest"


		#TODO : Possible Additional validations
		#1. Check if client is valid. (Redundant?)
		#2. Check if session is active.
		
		# querystring = parse_qs(urlparse(request.url).query)
		# is_client_valid = not frappe.db.get_value("OAuth Client", querystring['client_id'], "name")

		#return is_user_valid and is_client_valid		

	def authenticate_client_id(self, client_id, request, *args, **kwargs):
		cli_id = frappe.db.get_value('OAuth Client', client_id, 'name')

		#printstuff(client_id + ': ' + cli_id)

		if not cli_id:
			# Don't allow public (non-authenticated) clients
			return False
		else:
			request["client"] = frappe.get_doc("OAuth Client", cli_id)
			return True

	def validate_code(self, client_id, code, client, request, *args, **kwargs):
		# Validate the code belongs to the client. Add associated scopes,
		# state and user to request.scopes and request.user.

		validcodes = frappe.get_all("OAuth Authorization Code", filters={"client": client_id, "validity": "Valid"})

		checkcodes = []
		for vcode in validcodes:
			checkcodes.append(vcode["name"])

		# printstuff(code)
		# printstuff(validcodes)
		# printstuff(checkcodes)

		if code in checkcodes:
			request.scopes = frappe.db.get_value("OAuth Authorization Code", code, 'scopes').split(';')
			request.user = frappe.db.get_value("OAuth Authorization Code", code, 'user')
			return True
		else:
			return False
		
		#validcodes = frappe.db.get_all("OAuth Authorization Code", filters={""})
	
	def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
		saved_redirect_uri = frappe.db.get_value('OAuth Client', client_id, 'default_redirect_uri')
		
		# for x in xrange(1,10):
		# 	print saved_redirect_uri
		# 	print redirect_uri

		return saved_redirect_uri == redirect_uri
		# You did save the redirect uri with the authorization code right?
		

	def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
		# Clients should only be allowed to use one type of grant.
		# In this case, it must be "authorization_code" or "refresh_token"
		return (grant_type in ["authorization_code", "refresh_token"])

	def save_bearer_token(self, token, request, *args, **kwargs):
		# Remember to associate it with request.scopes, request.user and
		# request.client. The two former will be set when you validate
		# the authorization code. Don't forget to save both the
		# access_token and the refresh_token and set expiration for the
		# access_token to now + expires_in seconds.
		#		printstuff(request)

		otoken = frappe.new_doc("OAuth Bearer To`ken")
		otoken.client = request.client['name']
		otoken.user = request.user
		otoken.scopes = ";".join(request.scopes)
		otoken.access_token = token['access_token']
		otoken.refresh_token = token['refresh_token']
		otoken.expires_in = token['expires_in']
		otoken.save(ignore_permissions=True)
		frappe.db.commit()

		default_redirect_uri = frappe.db.get_value("OAuth Client", request.client['name'], "default_redirect_uri")
		return default_redirect_uri

	def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
		# Authorization codes are use once, invalidate it when a Bearer token
		# has been acquired.

		frappe.db.set_value("OAuth Authorization Code", code, "validity", "Invalid")
		frappe.db.commit()

	# Protected resource request

	def validate_bearer_token(self, token, scopes, request):
		#printstuff(token)
		# Remember to check expiration and scope membership
		otoken = frappe.get_doc("OAuth Bearer Token", token) #{"access_token": str(token)})
		#dexp = otoken.creation + frappe.utils.datetime.timedelta(seconds=otoken.expires_in)
		is_token_valid = (frappe.utils.datetime.datetime.now() < otoken.expiration_time) \
			and otoken.status != "Revoked"
		#is_token_valid = is_token_valid and otoken.status == ""

		# printstuff(frappe.utils.datetime.datetime.now())
		# printstuff(otoken.expiration_time)

		client_scopes = frappe.db.get_value("OAuth Client", otoken.client, 'scopes').split(';')
		are_scopes_valid = True
		for scp in scopes:
			are_scopes_valid = are_scopes_valid and True if scp in client_scopes else False

		# for x in xrange(1,25):
		# 	print otoken.expiration_time
		# 	print frappe.utils.datetime.datetime.now()
		# 	print otoken.access_token + ": " + token
		# 	print "scopes: " + str(are_scopes_valid)
		# 	print "tokentimevalid: " + str(is_token_valid)

		# printstuff(is_token_valid)
		# printstuff(are_scopes_valid)

		return is_token_valid and are_scopes_valid


	# Token refresh request

	def get_original_scopes(self, refresh_token, request, *args, **kwargs):
		# Obtain the token associated with the given refresh_token and
		# return its scopes, these will be passed on to the refreshed
		# access token if the client did not specify a scope during the
		# request.
		obearer_token = frappe.get_doc("OAuth Bearer Token", {"refresh_token": refresh_token})
		return obearer_token.scopes
		


	#Additional

	# def is_within_original_scope(self, request_scopes, refresh_token, request, *args, **kwargs):
	# 	"""Check if requested scopes are within a scope of the refresh token.

	# 	When access tokens are refreshed the scope of the new token
	# 	needs to be within the scope of the original token. This is
	# 	ensured by checking that all requested scopes strings are on
	# 	the list returned by the get_original_scopes. If this check
	# 	fails, is_within_original_scope is called. The method can be
	# 	used in situations where returning all valid scopes from the
	# 	get_original_scopes is not practical.

	# 	:param request_scopes: A list of scopes that were requested by client
	# 	:param refresh_token: Unicode refresh_token
	# 	:param request: The HTTP Request (oauthlib.common.Request)
	# 	:rtype: True or False

	# 	Method is used by:
	# 		- Refresh token grant
	# 	"""
	# 	return False

	def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
		"""Revoke an access or refresh token.

		:param token: The token string.
		:param token_type_hint: access_token or refresh_token.
		:param request: The HTTP Request (oauthlib.common.Request)

		Method is used by:
			- Revocation Endpoint
		"""
		otoken = None

		if token_type_hint == "access_token":
			otoken = frappe.db.set_value("OAuth Bearer Token", token, 'status', 'Revoked')
		elif token_type_hint == "refresh_token":
			otoken = frappe.db.set_value("OAuth Bearer Token", {"refresh_token": token}, 'status', 'Revoked')
		else:
			otoken = frappe.db.set_value("OAuth Bearer Token", token, 'status', 'Revoked')

		frappe.db.commit()
		#raise NotImplementedError('Subclasses must implement this method.')

	# def rotate_refresh_token(self, request):
	# 	"""Determine whether to rotate the refresh token. Default, yes.

	# 	When access tokens are refreshed the old refresh token can be kept
	# 	or replaced with a new one (rotated). Return True to rotate and
	# 	and False for keeping original.

	# 	:param request: oauthlib.common.Request
	# 	:rtype: True or False

	# 	Method is used by:
	# 		- Refresh Token Grant
	# 	"""
	# 	return True

	def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
			# """Ensure the Bearer token is valid and authorized access to scopes.

			# OBS! The request.user attribute should be set to the resource owner
			# associated with this refresh token.

			# :param refresh_token: Unicode refresh token
			# :param client: Client object set by you, see authenticate_client.
			# :param request: The HTTP Request (oauthlib.common.Request)
			# :rtype: True or False

			# Method is used by:
			# 	- Authorization Code Grant (indirectly by issuing refresh tokens)
			# 	- Resource Owner Password Credentials Grant (also indirectly)
			# 	- Refresh Token Grant
			# """
			# raise NotImplementedError('Subclasses must implement this method.')
		# for x in xrange(1,20):
		# 	pass

		otoken = frappe.get_doc("OAuth Bearer Token", {"refresh_token": refresh_token, "status": "Active"})

		if not otoken:
			return False
		else:
			return True

		#TODO: Validate scopes.


	# def validate_user(self, username, password, client, request, *args, **kwargs):
	# 	"""Ensure the username and password is valid.

	# 	OBS! The validation should also set the user attribute of the request
	# 	to a valid resource owner, i.e. request.user = username or similar. If
	# 	not set you will be unable to associate a token with a user in the
	# 	persistance method used (commonly, save_bearer_token).

	# 	:param username: Unicode username
	# 	:param password: Unicode password
	# 	:param client: Client object set by you, see authenticate_client.
	# 	:param request: The HTTP Request (oauthlib.common.Request)
	# 	:rtype: True or False

	# 	Method is used by:
	# 		- Resource Owner Password Credentials Grant
	# 	"""
	# 	raise NotImplementedError('Subclasses must implement this method.')
def get_cookie_dict_from_headers(r):
	if r.headers.get('Cookie'):
		cookie = r.headers.get('Cookie')
		cookie = cookie.split("; ")
		cookie_dict = {k:v for k,v in (x.split('=') for x in cookie)}
		return cookie_dict
	else:
		return {}