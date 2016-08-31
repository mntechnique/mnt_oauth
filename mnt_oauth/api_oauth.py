# Copyright (c) 2015, MN Technique
# License: GNU General Public License v3. See license.txt"

###
### http://0.0.0.0:8000/api/method/mnt_oauth.api_oauth.mnt_preauth?client_id=abc&redirect_uri=http://0.0.0.0:8000/redir.html&response_type=code&scope=method
###

from __future__ import unicode_literals
import frappe
from mnt_oauth_request_validator import MNTOAuthWebRequestValidator
from oauthlib.oauth2 import WebApplicationServer, FatalClientError
from urllib import quote, urlencode


#Variables required across requests.
oauth_validator = MNTOAuthWebRequestValidator()
oauth_server  = WebApplicationServer(oauth_validator)
credentials = None


def get_urlparams_from_kwargs(param_kwargs):
	arguments = param_kwargs
	if arguments.get("data"):
		arguments.pop("data")
	if arguments.get("cmd"):
		arguments.pop("cmd")

	return urlencode(arguments)


#preauth.
@frappe.whitelist(allow_guest=True)
def mnt_preauth(*args, **kwargs):

 	#success_url = quote("api/method/mnt_oauth.api_oauth.mnt_postauth?client_id={cliid}&scope={scope}".format(cliid=kwargs['client_id'], scope=kwargs['scope']))
	# arguments =  [k,v for k, v in kwargs.items()]
 # 	for x in xrange(0, 10):
	# 	print arguments
	# 	# print kwargs #frappe.website.utils.abs_url(success_url)
		# print args
		
	params = get_urlparams_from_kwargs(kwargs)

	# for k, v in kwargs.iteritems():
	# 	preauth_url += ( "" if k in ["cmd", "data"] else (k + '=' + v))
		
	if frappe.session['user']=='Guest':
		#Force login, redirect to preauth again.
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = "/login?redirect-to=/api/method/mnt_oauth.api_oauth.mnt_preauth?" + quote(params) #quote("{endpoint}?client_id={cliid}&scope={scope}".format(endpoint=kwargs["cmd"], cliid=kwargs['client_id'], scope=kwargs['scope']))

	elif frappe.session['user']!='Guest':
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
			scopeless = kwargs
			scopeless.pop("scope")
			params = get_urlparams_from_kwargs(scopeless)
			success_url = "http://0.0.0.0:8000/api/method/mnt_oauth.api_oauth.mnt_postauth?" + params
			#success_url = "http://0.0.0.0:8000/api/method/mnt_oauth.api_oauth.mnt_postauth?client_id={cliid}&auth_code={authcode}&scope={scope}".format(cliid=credentials['client_id'], authcode=auth_code, scope=kwargs['scope'])
			#success_url = "http://0.0.0.0:8000/redir.html?auth_code=abc" #.format(auth_code=credentials['client_id']),
			
			response_html_params = frappe._dict({
				"client_id": kwargs['client_id'],
				"success_url": success_url,
				"details": ['User', 'Project'],
				"error": ""
			})

			resp_html = frappe.render_template("mnt_oauth/templates/includes/mnt_oauth_confirmation.html", response_html_params)

			frappe.respond_as_web_page("MNT OAuth Conf.", resp_html)

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
			#response_html_params['error'] = e.message
			# frappe.respond_as_web_page("MNT OAuth Conf Error", resp_html)
			# # this is your custom error page
			# # from your_view_helpers import error_to_response
			# # return error_to_response(e)
			# return False
			return e
		
@frappe.whitelist(allow_guest=True)
def mnt_postauth(*args, **kwargs):

	# # Fetch the credentials saved in the pre authorization phase
	# from your_datastore import fetch_credentials
	# credentials = fetch_credentials()
	#global credentials

	# Fetch authorized scopes from the request
	#from your_framework import request

	#{'scope': u'method', 'cmd': u'mnt_oauth.api_oauth.mnt_postauth', 'data': '', 'client_id': u'abc', 'auth_code': u'96d61a59cfee66745b438b467f4e43385c4634441117148e1de8191e'}
	# 	print kwargs

	scopes = frappe.db.get_value("OAuth Client", kwargs["client_id"], "scopes").split(";") #request.scopes #POST.get('scopes')
	arguments = get_urlparams_from_kwargs(kwargs)

	# for x in xrange(1,10):
	# 	print arguments

	# for s in scopes:
	# 	print s

	from oauthlib.oauth2 import OAuth2Error

	#from your_framework import http_response
	#http_response(body, status=status, headers=headers)
	r = frappe.request
	uri = r.url
	http_method = r.method
	body = r.get_data()
	headers = r.headers

	try:
	    headers, body, status = oauth_server.create_authorization_response(
	        uri, http_method, body, headers, scopes, credentials)
	    # headers = {'Location': 'https://foo.com/welcome_back?code=somerandomstring&state=xyz'}, this might change to include suggested headers related
	    # to cache best practices etc.
	    # body = '', this might be set in future custom grant types
	    # status = 302, suggested HTTP status code
	    return frappe._dict({
	    	"headers": headers,
	    	"body": body,
	    	"status": status
	    	})

	   
	except FatalClientError as e:
	    # this is your custom error page
	    return frappe.respond_as_web_page("Not Allowed", "Access Denied to " + kwargs["client_id"])

	except OAuth2Error as e:
	    # Less grave errors will be reported back to client
	    client_redirect_uri = credentials.get('redirect_uri')
	    redirect(e.in_uri(client_redirect_uri))
