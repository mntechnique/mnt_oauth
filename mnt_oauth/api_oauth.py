# Copyright (c) 2015, MN Technique
# License: GNU General Public License v3. See license.txt"
 
from __future__ import unicode_literals
import frappe
from mnt_oauth_request_validator import MNTOAuthWebRequestValidator
from oauthlib.oauth2 import WebApplicationServer, FatalClientError
import requests


#Variables required across requests.
oauth_validator = MNTOAuthWebRequestValidator()
oauth_server  = WebApplicationServer(oauth_validator)
credentials = None

#preauth.
@frappe.whitelist(allow_guest=True)
def mnt_authorize(*args, **kwargs):
	# for i in frappe.local.request:
	# 	print i
	#return frappe.get_request_header("")

	# for i in frappe.form_dict:
	# 	print i

	#r = requests.Request()
	r = frappe.request
	

	#return kwargs, frappe.form_dict	
	# #frappe.msgprint(frappe.form_dict['cmd'] + "," +  frappe.form_dict['data'])
	# uri = kwargs['cmd']
	# http_method = 'POST'
	# #headers = frappe.form_dict 

	try:
		uri = r.url
		http_method = r.method
		body = None
		headers = r.headers

		scopes, credentials = oauth_server.validate_authorization_request(uri, http_method, body, headers)
	
		# scopes will hold default scopes for client, i.e.
		#['https://example.com/userProfile', 'https://example.com/pictures']

		# credentials is a dictionary of
		# {
		# 	'client_id': 'foo',
		# 	'redirect_uri': 'https://foo.com/welcome_back',
		# 	'response_type': 'code',
		# 	'state': 'randomstring',
		# }
		# these credentials will be needed in the post authorization view and
		# should be persisted between. None of them are secret but take care
		# to ensure their integrity if embedding them in the form or cookies.
		# from your_datastore import persist_credentials
		# persist_credentials(credentials)
		#g_credentials = credentials

		# Present user with a nice form where client (id foo) request access to
		# his default scopes (omitted from request), after which you will
		# redirect to his default redirect uri (omitted from request).


	except FatalClientError as e:
		# this is your custom error page
		# from your_view_helpers import error_to_response
		# return error_to_response(e)
		return e
		
