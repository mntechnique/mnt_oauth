# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# License: GNU General Public License v3. See license.txt"


from __future__ import unicode_literals
import frappe
from mnt_oauth_request_validator import RequestValidator
from oauthlib.oauth2 import WebApplicationServer 


#oauth_server = None

def boot_session(bootinfo):
	"""boot session - send website info if guest"""
	 

	# if frappe.session['user']!='Guest': #Allow guests?
	# 	oauth_validator =  RequestValidator()
	# 	global oauth_server
	# 	oauth_server  = WebApplicationServer(oauth_validator)
