# Copyright (c) 2015, MN Technique
# License: GNU General Public License v3. See license.txt"

from __future__ import unicode_literals
import frappe
from mnt_oauth_request_validator import MNTOAuthWebRequestValidator
from oauthlib.oauth2 import WebApplicationServer, FatalClientError, OAuth2Error
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

# def hasvalidtoken(client, scopes):
# 	tokens = frappe.get_all("OAuth Bearer Token", fields=["name", "scopes"], \
# 		filters=[['client', '=', client], ['status', '=', 'Active'], ['expiration_time', '>', frappe.utils.datetime.datetime.now()]])
# 		# check past authorizations regarded the same scopes as the current one
# 	token_names = []
# 	for token in tokens:
# 		if token["scopes"] in scopes:
# 			return True
# 	return False


@frappe.whitelist()
def mnt_approveauth(*args, **kwargs):
	r = frappe.request
	uri = r.url
	http_method = r.method
	body = r.get_data()
	headers = r.headers

	try:
		scopes, credentials = oauth_server.validate_authorization_request(uri, http_method, body, headers)	

		headers, body, status = oauth_server.create_authorization_response(uri=credentials['redirect_uri'], \
				body=body, headers=headers, scopes=scopes, credentials=credentials)
		uri = headers.get('Location', None)

		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = uri
	
	except FatalClientError as e:
		return e
	except OAuth2Error as e:
		return

@frappe.whitelist(allow_guest=True, xss_safe=True)
def mnt_authorize(*args, **kwargs):
	params = get_urlparams_from_kwargs(kwargs)

	if frappe.session['user']=='Guest':
		#Force login, redirect to preauth again.
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = "/login?redirect-to=/api/method/mnt_oauth.api_oauth.mnt_authorize?" + quote(params)
	
	elif frappe.session['user']!='Guest':
		try:
			r = frappe.request
			uri = r.url
			http_method = r.method
			body = r.get_data()
			headers = r.headers

			scopes, credentials = oauth_server.validate_authorization_request(uri, http_method, body, headers)	

			#skipauth = frappe.db.get_value("OAuth Client", credentials['client_id'], "skip_authorization")

			# if skipauth:
				
			# 	headers, body, status = oauth_server.create_authorization_response(uri=credentials['redirect_uri'], \
			# 		body=body, headers=headers, scopes=scopes, credentials=credentials)
			# 	uri = headers.get('Location', None)

			# 	frappe.local.response["type"] = "redirect"
			# 	frappe.local.response["location"] = uri

			# if hasvalidtoken(credentials['client_id'], scopes):
			# 	headers, body, status = oauth_server.create_authorization_response(uri, http_method, body, headers, scopes, credentials)
			# 	uri = headers.get('Location', None)

			# 	#return uri, headers, body, status
			# 	frappe.local.response["type"] = "redirect"
			# 	frappe.local.response["location"] = url
			# else:
			success_url = "http://0.0.0.0:8000/api/method/mnt_oauth.api_oauth.mnt_approveauth?" + params
			#SHOW ALLOW/DENY SCREEN.
			response_html_params = frappe._dict({
				"client_id": kwargs['client_id'],
				"success_url": success_url,
				"details": ['User', 'Project'],
				"error": ""
			})
			resp_html = frappe.render_template("mnt_oauth/templates/includes/mnt_oauth_confirmation.html", response_html_params)
			frappe.respond_as_web_page("MNT OAuth Conf.", resp_html)

		except FatalClientError as e:
			return e
		except OAuth2Error as e:
			return


@frappe.whitelist(allow_guest=True, xss_safe=True)
def mnt_gettoken(*args, **kwargs):
	r = frappe.request
	uri = r.url
	http_method = r.method
	body = r.get_data()
	headers = r.headers

	try:
		headers, body, status = oauth_server.create_token_response(uri, http_method, body, headers, credentials)
		return headers, body, status
	except FatalClientError as e:
		return e


@frappe.whitelist(allow_guest=True, xss_safe=True)
def mnt_revoketoken(*args, **kwargs):
	r = frappe.request
	uri = r.url
	http_method = r.method
	body = r.get_data()
	headers = r.headers

	headers, body, status = oauth_server.create_revocation_response(uri, headers=headers, body=body, http_method=http_method)

	return headers, body, status
