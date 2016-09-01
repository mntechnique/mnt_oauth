# -*- coding: utf-8 -*-
# Copyright (c) 2015, MN Technique and contributors
# For license information, please see license.txt

from __future__ import unicode_literals
import frappe
from frappe.model.document import Document

class OAuthBearerToken(Document):
	#pass
	def validate(self):
		# for x in xrange(1,100):
		# 	print self.creation
		# 	print type(self.creation)
		if not self.expiration_time:
	 		self.expiration_time = frappe.utils.datetime.datetime.strptime(self.creation, "%Y-%m-%d %H:%M:%S.%f") + frappe.utils.datetime.timedelta(seconds=self.expires_in)
