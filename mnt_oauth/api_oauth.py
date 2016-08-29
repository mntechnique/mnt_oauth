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
		body = r.get_data()
		headers = r.headers

		scopes, credentials = oauth_server.validate_authorization_request(uri, http_method, body, headers)

		resp_html = "<div><h1>Allow {cli_id} &#63;</h1></div>".format(cli_id=kwargs['client_id'])

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
		# this is your custom error page
		# from your_view_helpers import error_to_response
		# return error_to_response(e)
		return e
		


# [u'0.0.0.0:8000/api/method'] 
# {u'state': None, u'redirect_uri': u'https://www.google.com', u'request': 
# <oauthlib.Request url="http://0.0.0.0:8000/api/method/mnt_oauth.api_oauth.mnt_authorize?client_id=abc&redirect_uri=https:%2F%2Fwww.google.com&response_type=code", 
# http_method="GET", 
# headers="{u'Content-Length': u'', u'Accept-Language': u'en-US,en;q=0.8', u'Accept-Encoding': u'gzip, deflate, sdch', u'Connection': u'keep-alive', u'Accept': u'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', u'User-Agent': u'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36', 
# u'Host': u'0.0.0.0:8000', u'Cookie': u'_ga=GA1.1.1971573397.1470386439; user_image=; user_id=Administrator; system_user=yes; full_name=Administrator; sid=7b99b8ce99bc027f6359bb8db4362c9b75418b03e29b49bbee384f23', u'Pragma': u'no-cache', u'Cache-Control': u'no-cache', u'Upgrade-Insecure-Requests': u'1', u'Content-Type': u''}", body="None">, u'response_type': u'code', u'client_id': u'abc'}
