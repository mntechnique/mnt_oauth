# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# License: GNU General Public License v3. See license.txt"


from __future__ import unicode_literals
import frappe
from mnt_oauth_request_validator import RequestValidator
from oauthlib.oauth2 import WebApplicationServer 

def boot_session(bootinfo):
	"""boot session - send website info if guest"""
	import frappe

	if frappe.session['user']!='Guest': #Allow guests?
		oauth_validator =  RequestValidator()
		oauth_server = WebApplicationServer(oauth_validator)