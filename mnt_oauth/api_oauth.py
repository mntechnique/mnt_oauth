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
def mnt_pre_authorize(*args, **kwargs):
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

	response_html_params = {}
	resp_html = ""

	try:
		uri = r.url
		http_method = r.method
		body = r.get_data()
		headers = r.headers

		scopes, credentials = oauth_server.validate_authorization_request(uri, http_method, body, headers)

		success_url = "http://0.0.0.0:8000/redir.html?auth_code={auth_code}".format(auth_code=credentials['client_id']),
		
		#resp_html = "<div><h1>Allow {cli_id} &#63;</h1></div>".format(cli_id=kwargs['client_id'])
		response_html_params = frappe._dict({
			"client_id": kwargs['client_id'],
			"success_url": success_url,
			"details": ['User', 'Project'],
			"error": ""
		})

		resp_html = frappe.render_template("mnt_oauth/templates/includes/mnt_oauth_confirmation.html", response_html_params)

		frappe.respond_as_web_page("MNT OAuth Conf.", resp_html)

		# for x in xrange(0, 5):
		# 	print scopes, credentials
		
		# for d in xrange(0, 5):
		# 	print r.get_data() 
	
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
		# response_html_params['error'] = e.message
		# frappe.respond_as_web_page("MNT OAuth Conf Error", resp_html)
		# # this is your custom error page
		# # from your_view_helpers import error_to_response
		# # return error_to_response(e)
		# return False
		return e
		
@frappe.whitelist(allow_guest=True)
def mnt_post_authorize(*args, **kwargs):

	# # Fetch the credentials saved in the pre authorization phase
	# from your_datastore import fetch_credentials
	# credentials = fetch_credentials()
	global credentials

	# Fetch authorized scopes from the request
	#from your_framework import request
	scopes = request.POST.get('scopes')

	from oauthlib.oauth2 import OAuth2Error

	from your_framework import http_response
	http_response(body, status=status, headers=headers)
	
	try:
	    headers, body, status = server.create_authorization_response(
	        uri, http_method, body, headers, scopes, credentials)
	    # headers = {'Location': 'https://foo.com/welcome_back?code=somerandomstring&state=xyz'}, this might change to include suggested headers related
	    # to cache best practices etc.
	    # body = '', this might be set in future custom grant types
	    # status = 302, suggested HTTP status code

	    return http_response(body, status=status, headers=headers)

	except FatalClientError as e:
	    # this is your custom error page
	    from your_view_helpers import error_to_response
	    return error_to_response(e)

	except OAuth2Error as e:
	    # Less grave errors will be reported back to client
	    client_redirect_uri = credentials.get('redirect_uri')
	    redirect(e.in_uri(client_redirect_uri))
