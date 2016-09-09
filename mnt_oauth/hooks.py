# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from . import __version__ as app_version

app_name = "mnt_oauth"
app_title = "MNT OAuth"
app_publisher = "MN Technique"
app_description = "Gives OAuth server abilities to Frappe apps."
app_icon = "octicon octicon-key"
app_color = "#46E846"
app_email = "support@mntechnique.com"
app_license = "MIT"

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/mnt_oauth/css/mnt_oauth.css"
# app_include_js = "/assets/mnt_oauth/js/mnt_oauth.js"

# include js, css files in header of web template
# web_include_css = "/assets/mnt_oauth/css/mnt_oauth.css"
# web_include_js = "/assets/mnt_oauth/js/mnt_oauth.js"

# boot_session = "mnt_oauth.mnt_oauth_boot.boot_session"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
#	"Role": "home_page"
# }

# Website user home page (by function)
# get_website_user_home_page = "mnt_oauth.utils.get_home_page"

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Installation
# ------------

# before_install = "mnt_oauth.install.before_install"
# after_install = "mnt_oauth.install.after_install"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "mnt_oauth.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
#	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
# 	"all": [
# 		"mnt_oauth.tasks.all"
# 	],
# 	"daily": [
# 		"mnt_oauth.tasks.daily"
# 	],
# 	"hourly": [
# 		"mnt_oauth.tasks.hourly"
# 	],
# 	"weekly": [
# 		"mnt_oauth.tasks.weekly"
# 	]
# 	"monthly": [
# 		"mnt_oauth.tasks.monthly"
# 	]
# }

# Testing
# -------

# before_tests = "mnt_oauth.install.before_tests"

# Overriding Whitelisted Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "mnt_oauth.event.get_events"
# }

