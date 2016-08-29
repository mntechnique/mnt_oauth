import frappe


def get_context(context):
	clientid = frappe.form_dict['client_id']
	context.client_id = clientid