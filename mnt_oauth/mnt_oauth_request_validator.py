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
		cli_id = frappe.db.get_value("OAuth Client",{ "name":client_id })
		if cli_id:
		#  Client.objects.get(client_id=client_id)
			request.client = frappe.get_doc("OAuth Client", client_id)
			return True
		else:
			return False

	def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
		# Is the client allowed to use the supplied redirect_uri? i.e. has
		# the client previously registered this EXACT redirect uri.
		redirect_uris = frappe.db.get_value("OAuth Client", client_id, 'redirect_uris').split(';')
		if redirect_uri in redirect_uris:
			return True
		else:
			return False
		
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
		oac = frappe.new_doc('OAuth Authorization Code')
		oac.scopes = request.scopes
		oac.redirect_uri_bound_to_authorization_code = request.redirect_uri
		oac.client = client_id
		oac.authorization_code = code
		oac.insert()
		frappe.db.commit()

		#redirect_uri gets linked to OAC Auth Code via Client link field.

		# Remember to associate it with request.scopes, request.redirect_uri
		# request.client, request.state and request.user (the last is passed in
		# post_authorization credentials, i.e. { 'user': request.user}.
		#pass

	# Token request

	def authenticate_client(self, request, *args, **kwargs):
		# Whichever authentication method suits you, HTTP Basic might work
		return False #GRN: Authentication outside OAuth2. Disabled for MNT.

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
		return (client.authorization_code == code)
	
	def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
		saved_redirect_uri = frappe.db.get_value('OAuth Client', client_id, 'default_redirect_uri')
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
		otoken = frappe.new_doc("OAuth Bearer Token")
		otoken.client = request.client
		otoken.user = request.user
		otoken.scopes = request.scopes
		otoken.access_token = token
		otoken.refresh_token = frappe.generate_hash(token) #Aisehi.
		otoken.insert()
		frappe.db.commit()

		oclient = frappe.get_doc('OAuth Client', request.client)
		return oclient.default_redirect_uri

	def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
		# Authorization codes are use once, invalidate it when a Bearer token
		# has been acquired.
		if request.token:
			ocode = frappe.get_doc("OAuth Authorization Code", client_id) 
			ocode.expiration = frappe.utils.datetime.datetime.now()

		#Hopefully this should do it.

	# Protected resource request

	def validate_bearer_token(self, token, scopes, request):
		# Remember to check expiration and scope membership
		otoken = frappe.get_doc("OAuth Bearer Token", token)
		if frappe.utils.datetime.datetime.now() > otoken.expiration:
			return False
		
		are_scopes_valid = True
		for scp in scopes:
			are_scopes_valid = are_scopes_valid and True if scp in client_scopes else False

		return False


	# Token refresh request

	def get_original_scopes(self, refresh_token, request, *args, **kwargs):
		# Obtain the token associated with the given refresh_token and
		# return its scopes, these will be passed on to the refreshed
		# access token if the client did not specify a scope during the
		# request.
		obearer_token = frappe.get_doc("OAuth Bearer Token", {"refresh_token": refresh_token})
		return obearer_token.scopes 	


# validator = MNTOAuthWebRequestValidator()
# server = WebApplicationServer(validator)