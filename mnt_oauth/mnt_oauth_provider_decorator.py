import frappe
import functools

class OAuth2ProviderDecorator(object):

    def __init__(self, resource_endpoint):
        self._resource_endpoint = resource_endpoint

    def protected_resource_view(self, scopes=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                
                #uri, http_method, body, headers = extract_params(request)
                request = frappe.request
                uri = request.url
                http_method = request.method
                body = request.get_data()
                headers = request.headers

                # Get the list of scopes
                try:
                    scopes_list = request.scopes
                except TypeError:
                    scopes_list = scopes

                valid, r = self._resource_endpoint.verify_request(
                        uri, http_method, body, headers, scopes_list)

                # For convenient parameter access in the view
                add_params(request, {
                    'client': r.client,
                    'user': r.user,
                    'scopes': scopes_list
                })

                if valid:
                    return f(request)
                else:
                    # Framework specific HTTP 403
                    return "403: Forbidden"
            return wrapper
        return decorator
