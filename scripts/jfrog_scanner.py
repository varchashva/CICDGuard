#!/usr/bin/python3

import json
import re
import requests
from neomodel import (config, StructuredNode, StringProperty, IntegerProperty, ArrayProperty, UniqueIdProperty, RelationshipTo, RelationshipFrom, Relationship)
import os
import time



# Global variables 

USER_QUERY = "/access/api/v2/users/$username"
GROUP_QUERY = "/access/api/v2/groups"
READINESS_QUERY = "/api/v1/system/readiness"

JFROG_URL = os.getenv("JFROG_URL")
JFROG_ACCESS_TOKEN = os.getenv("JFROG_ACCESS_TOKEN")

OUTPUT = []
config.DATABASE_URL = 'bolt://neo4j:Neo4j@localhost:7687'



class JFrog_Server(StructuredNode):
	uid = UniqueIdProperty()
	url = StringProperty()
	https_enabled = StringProperty()
	# version = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	

	group = Relationship("JFrog_Group","HAS")

	def __str__(self):
		return self.url

class JFrog_Group(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	description = StringProperty()
	admin_privileges = StringProperty()
	realm = StringProperty()

	user = Relationship("JFrog_User","PART_OF")

	def __str__(self):
		return self.name


class JFrog_User(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	email = StringProperty()
	is_admin = StringProperty()
	realm = StringProperty()
	status = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	
	def __str__(self):
		return self.name


def makeanode(nodetype,data):
	if "user" in nodetype:
		try:
			user_node = JFrog_User.nodes.get(name=data["name"])
		except JFrog_User.DoesNotExist as ex:
			user_node = JFrog_User(name=data["name"],email=data["email"],is_admin=data["is_admin"],realm=data["realm"],status=data["status"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			user_node.save()
		return user_node
	elif "group" in nodetype:
		try:
			group_node = JFrog_Group.nodes.get(name=data["name"])
		except JFrog_Group.DoesNotExist as ex:
			group_node = JFrog_Group(name=data["name"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"],description=data["description"],admin_privileges=data["admin_privileges"],realm=data["realm"])
			group_node.save()
		return group_node
	elif "jfrog" in nodetype:
		try:
			server_node = JFrog_Server.nodes.get(url=data["url"])
		except JFrog_Server.DoesNotExist as ex:
			server_node = JFrog_Server(url=data["url"],https_enabled=data["https_enabled"],vuln_artifacts=data["vuln_artifacts"],affected_vulns=data["affected_vulns"])
			server_node.save()
		return server_node


def warning_print(message):
	print("\033[93m {}\033[00m" .format(message))

def error_print(message):
	print("\033[91m {}\033[00m" .format(message))

def success_print(message):
	print("\033[32m {}\033[00m" .format(message))	

def update_vulnerability(node,vulnID,vuln_artifacts):
	node.affected_vulns = str(node.affected_vulns) + "$" + str(vulnID)
	node.vuln_artifacts = str(node.vuln_artifacts) + "$" + str(vuln_artifacts)
	node.save()
	success_print("[+] Node " + str(node) + " vulnerability details updated successfully: " + vulnID)
	return
	
if __name__ == "__main__":
	
	print("[*] Processing JFrog Server: " + JFROG_URL)
	
	headers = {
		"Authorization": "Bearer " + str(JFROG_ACCESS_TOKEN),
		"Accept": "application/json"
	}

	nodedata = {}
	nodedata["url"] = JFROG_URL
	nodedata["https_enabled"] = ("https" in JFROG_URL)
	nodedata["vuln_artifacts"] = ""
	nodedata["affected_vulns"] = ""
	server_node = makeanode("jfrog",nodedata)
	success_print("[+] Node " + str(server_node) + " created successfully")

	vuln_data = {}
	# JFA001
	if not nodedata["https_enabled"]:
		vuln_data["vuln_id"] = "JFA001"
		vuln_data["jfrog_server"] = JFROG_URL
		vuln_data["impacted_area"] = JFROG_URL
		OUTPUT.append(vuln_data)
		update_vulnerability(JFrog_Server.nodes.get(url=JFROG_URL),vuln_data["vuln_id"],vuln_data["impacted_area"])
	
	# JFA002
	anonymous_check = requests.get(str(JFROG_URL) + str(READINESS_QUERY))
	if "200" in str(anonymous_check.status_code):
		vuln_data["vuln_id"] = "JFA002"
		vuln_data["jfrog_server"] = JFROG_URL
		vuln_data["impacted_area"] = str(JFROG_URL) + "anonymous user allowed"
		OUTPUT.append(vuln_data)
		update_vulnerability(JFrog_Server.nodes.get(url=JFROG_URL),vuln_data["vuln_id"],vuln_data["impacted_area"])
	
	groups = requests.get(str(JFROG_URL) + str(GROUP_QUERY),headers=headers).json()

	for group in groups["groups"][0:5]:
		try:
			time.sleep(5)
			print("[*] Processing group: " + str(group["group_name"]))
			group_request = requests.get(str(JFROG_URL) + str(GROUP_QUERY) + "/" + str(group["group_name"]),headers=headers).json()

			nodedata = {}
			nodedata["name"] = group_request["name"]
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
			nodedata["description"] = group_request["description"]
			nodedata["admin_privileges"] = group_request["admin_privileges"]
			nodedata["realm"] = group_request["realm"]

			group_node = makeanode("group",nodedata)
			success_print("[+] Node " + str(group_node) + " created successfully")
			server_node.group.connect(group_node)

			for member in group_request["members"][0:3]:
				time.sleep(5)
				print("[*] Processing user: " + str(member))
				member_request = requests.get(str(JFROG_URL) + str(USER_QUERY).replace("$username",str(member)),headers=headers).json()

				nodedata = {}
				nodedata["name"] = member_request["username"]
				nodedata["affected_vulns"] = ""
				nodedata["vuln_artifacts"] = ""
				nodedata["email"] = member_request["email"]	
				nodedata["is_admin"] = member_request["admin"]
				nodedata["realm"] = member_request["realm"]
				nodedata["status"] = member_request["status"]
				
				user_node = makeanode("user",nodedata)
				success_print("[+] Node " + str(user_node) + " created successfully")

				group_node.user.connect(user_node)
		except Exception as ex:
			warning_print(str(ex))
