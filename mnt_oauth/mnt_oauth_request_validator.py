import frappe
from frappe import database
from oauthlib.oauth2 import RequestValidator
from oauthlib.common import Request
from mnt_oauth.doctype.oauth_client.oauth_client import OAuthClient


#https://github.com/idan/oauthlib/blob/master/examples/skeleton_oauth2_web_application_server.py


class MNTOAuthWebRequestValidator(RequestValidator):

	# Ordered roughly in order of appearance in the authorization grant flow

	# Pre- and post-authorization.

	def validate_client_id(self, client_id, request, *args, **kwargs):
		# Simple validity check, does client exist? Not banned?
		cli_id = frappe.db.get_value("OAuth Client",{"name":client_id})
		if cli_id:
		#  Client.objects.get(client_id=client_id)
			return True
		else:
			return False
		#return True

	def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
		#if self.validate_client_id(client_id):

		r_uri = frappe.db.get_value("OAuth Client", client_id, 'redirect_uris')
		if redirect_uri == r_uri:
			return True
		else:
			return False

		# redirect_uris = [] 
		# redirect_uris.append()

		# if redirect_uri in redirect_uris:
		# 	return True
		# else:
		# 	return False
		# Is the client allowed to use the supplied redirect_uri? i.e. has
		# the client previously registered this EXACT redirect uri.
		#pass

	def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
		#No such field exists.
		#if self.validate_client_id(client_id):
		redirect_uri = frappe.db.get_value("OAuth Client", client_id, 'default_redirect_uri')

		# The redirect used if none has been supplied.
		# Prefer your clients to pre register a redirect uri rather than
		# supplying one on each authorization request.
		#pass

	def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
		# if validate_client_id(client_id):
		# 	client_scopes = []
		client_scopes = [frappe.db.get_value("OAuth Client", client_id, 'scopes')]

		for scp in client_scopes:
			if scp in scopes:
				return True
		# 	for scp in client_scopes :
		# 		if scp in scopes:

		# Is the client allowed to access the requested scopes?
		


	def get_default_scopes(self, client_id, request, *args, **kwargs):
		# Scopes a client will authorize for if none are supplied in the
		# authorization request.
		#pass
		return [frappe.db.get_value("OAuth Client", client_id, 'scopes')]

	def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
		# Clients should only be allowed to use one type of response type, the
		# one associated with their one allowed grant type.
		# In this case it must be "code".
		resp_type_client = frappe.db.get_value("OAuth Client", client_id, 'response_type')
		return (resp_type_client == response_type)
	# Post-authorization

	def save_authorization_code(self, client_id, code, request, *args, **kwargs):
		# oac = frappe.new_doc('OAuth Authorization Code')
		# oac.scopes = request.scopes
		# oac.client = client_id
		# oac.authorization_code = code
		# oac.insert()
		# frappe.db.commit()

		for x in xrange(0, 25):
			print '~~~Save Auth Code~~~'
		#print request

		# Remember to associate it with request.scopes, request.redirect_uri
		# request.client, request.state and request.user (the last is passed in
		# post_authorization credentials, i.e. { 'user': request.user}.
		#pass

	# Token request

	def authenticate_client(self, request, *args, **kwargs):
		# Whichever authentication method suits you, HTTP Basic might work
		#pass
		for x in xrange(0, 25):
			print '/// Authenticate CLient ///'

	def authenticate_client_id(self, client_id, request, *args, **kwargs):
		cli_id = frappe.db.get_value('OAuth Client', client_id, 'name')

		if not cli_id:
			# Don't allow public (non-authenticated) clients
			return False
		else:
			return True

	def validate_code(self, client_id, code, client, request, *args, **kwargs):
		# Validate the code belongs to the client. Add associated scopes,
		# state and user to request.scopes and request.user.
		pass

	def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
		saved_redirect_uri = frappe.db.get_value('OAuth Client', client_id, 'default_redirect_uri')
		return saved_redirect_uri == redirect_uri
		# You did save the redirect uri with the authorization code right?
		
	def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
		# Clients should only be allowed to use one type of grant.
		# In this case, it must be "authorization_code" or "refresh_token"
		for x in xrange(0, 25):
			print '/// Validate Grant Type ///'


	def save_bearer_token(self, token, request, *args, **kwargs):
		# Remember to associate it with request.scopes, request.user and
		# request.client. The two former will be set when you validate
		# the authorization code. Don't forget to save both the
		# access_token and the refresh_token and set expiration for the
		# access_token to now + expires_in seconds.
		#pass
		for x in xrange(0, 25):
			print '/// Save Bearer Token ///'

	def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
		# Authorization codes are use once, invalidate it when a Bearer token
		# has been acquired.
		#pass
		for x in xrange(0, 25):
			print '/// Invalidate Authorization Code ///'

	# Protected resource request

	def validate_bearer_token(self, token, scopes, request):
		# Remember to check expiration and scope membership
		#pass
		for x in xrange(0, 25):
			print '/// Validate Bearer Token ///'

	# Token refresh request

	def get_original_scopes(self, refresh_token, request, *args, **kwargs):
		# Obtain the token associated with the given refresh_token and
		# return its scopes, these will be passed on to the refreshed
		# access token if the client did not specify a scope during the
		# request.
		#pass
		for x in xrange(0, 25):
			print '/// Get Original Scopes ///'



# validator = MNTOAuthWebRequestValidator()
# server = WebApplicationServer(validator)