# Copyright (c) 2015, MN Technique
# License: GNU General Public License v3. See license.txt"

from __future__ import unicode_literals
import frappe, json
from mnt_oauth_request_validator import MNTOAuthWebRequestValidator, WebApplicationServer
from oauthlib.oauth2 import FatalClientError, OAuth2Error
from urllib import quote, urlencode
from mnt_oauth.doctype.oauth_provider_settings.oauth_provider_settings import get_oauth_settings
from mnt_oauth_provider_decorator import OAuth2ProviderDecorator 

#Variables required across requests
oauth_validator = MNTOAuthWebRequestValidator()
oauth_server  = WebApplicationServer(oauth_validator)
credentials = None
provider = OAuth2ProviderDecorator(oauth_server)

def get_urlparams_from_kwargs(param_kwargs):
	arguments = param_kwargs
	if arguments.get("data"):
		arguments.pop("data")
	if arguments.get("cmd"):
		arguments.pop("cmd")

	return urlencode(arguments)

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
		return e

@frappe.whitelist(allow_guest=True)
def mnt_authorize(*args, **kwargs):
	#Fetch provider URL from settings
	oauth_settings = get_oauth_settings()
	params = get_urlparams_from_kwargs(kwargs)
	success_url = oauth_settings["provider_url"] + "/api/method/mnt_oauth.api_oauth.mnt_approveauth?" + params
	failure_url = oauth_settings["provider_url"] + "/api/method/mnt_oauth.api_oauth.mnt_res_access_denied"

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

			skipauth = frappe.db.get_value("OAuth Client", credentials['client_id'], "skip_authorization")
			unrevoked_tokens = frappe.get_all("OAuth Bearer Token", filters={"status":"Active"})
			
			if skipauth or (oauth_settings["skip_authorization"] == "Auto" and len(unrevoked_tokens)):

				frappe.local.response["type"] = "redirect"
				frappe.local.response["location"] = success_url
			else:
				#Show Allow/Deny screen.
				response_html_params = frappe._dict({
					"client_id": frappe.db.get_value("OAuth Client", kwargs['client_id'], "app_name"),
					"success_url": success_url,
					"failure_url": failure_url,
					"details": scopes
				})
				resp_html = frappe.render_template("mnt_oauth/templates/includes/mnt_oauth_confirmation.html", response_html_params)
				frappe.respond_as_web_page("Confirm Access", resp_html)

		except FatalClientError as e:
			return e
		except OAuth2Error as e:
			return e

@frappe.whitelist(allow_guest=True)
def mnt_gettoken(*args, **kwargs):
	r = frappe.request	
	
	uri = r.url
	http_method = r.method
	body = r.get_data()
	headers = r.headers

	try:
		headers, body, status = oauth_server.create_token_response(uri, http_method, body, headers, credentials)
		out = json.loads(body)

		otoken_user = frappe.db.get_value("OAuth Bearer Token", out.get("access_token"), "user")
		#Add User ID to token response.
		out.update({"user_id": otoken_user})

		return out
	except FatalClientError as e:
		return e

@frappe.whitelist(allow_guest=True)
def mnt_revoketoken(*args, **kwargs):
	r = frappe.request
	uri = r.url
	http_method = r.method
	body = r.get_data()
	headers = r.headers

	headers, body, status = oauth_server.create_revocation_response(uri, headers=headers, body=body, http_method=http_method)

	return json.loads(body)

@frappe.whitelist(allow_guest=True, xss_safe=True)
def mnt_testresource(*args, **kwargs):
	r = frappe.request
	uri = r.url
	http_method = r.method
	body = r.get_data()
	headers = r.headers

	if not kwargs["access_token"]:
		return "Access Token Required"

	required_scopes = frappe.db.get_value("OAuth Bearer Token", kwargs["access_token"], "scopes").split(";")

	valid, oauthlib_request = oauth_server.verify_request(uri, http_method, body, headers, required_scopes)

	if valid:
	 	return "Access Granted"
	else:
		return "403: Forbidden"

@frappe.whitelist()
def mnt_res_access_denied(*args, **kwargs):
	resp_html = """
	<div class="well text-center">
		<p>Access to resource the app is trying to reach is denied.</p>
	</div>"""
	frappe.respond_as_web_page("Resource Access Denied", resp_html)