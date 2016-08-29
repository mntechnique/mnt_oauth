import frappe
from frappe import database
from oauthlib.oauth2 import RequestValidator
from my_models import Client

class MyRequestValidator(RequestValidator):

    def validate_client_id(self, client_id, request):
    	cli_id = frappe.db.get_value("OAuth Client",{"name":client_id})
     	if cli_id:
        	
          #  Client.objects.get(client_id=client_id)
            return True
        else
            return False
