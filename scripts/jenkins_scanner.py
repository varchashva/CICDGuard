#!/usr/bin/python3

from github import Github # v1.55
import argparse
import os
import yaml
import urllib
import json
import re
import requests
from neomodel import (config, StructuredNode, StringProperty, IntegerProperty, ArrayProperty, UniqueIdProperty, RelationshipTo, RelationshipFrom, Relationship)
import jenkinsapi
from jenkinsapi.jenkins import Jenkins

# Global Variables
JENKINS_SERVER = os.getenv("JENKINS_SERVER") 
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN")
JENKINS_USERNAME = os.getenv("JENKINS_USERNAME")

USERS_QUERY = "/asynchPeople/api/json?depth=1"

OUTPUT_FORMAT = {
	"vuln_id": "vuln_id",
	"jenkins_server": "jenkins_server",
	"impacted_area": "impacted_area", # build#, node name, plugin name etc. 
	},{
	"vuln_id": "vuln_id",
	"jenkins_server": "jenkins_server",
	"impacted_area": "impacted_area", # build#, node name, plugin name etc. 
}

OUTPUT = []
config.DATABASE_URL = 'bolt://neo4j:Neo4j@localhost:7687'



class Github_Organization(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty(unique_index=True)
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	two_factor_enabled = StringProperty()

	repository = Relationship('Github_Repository',"PART_OF")
	# team = Relationship("Github_Team","HAS")

	def __str__(self):
		return self.name


class Github_Repository(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty(unique_index=True)
	visibility = StringProperty() # Private, Public, Internal
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	dependabot_enabled = StringProperty() # get_vulnerability_alert()
	secret_scanning_enabled = StringProperty() 
	code_scanning_enabled = StringProperty() 

	
	def __str__(self):
		return self.name

class Jenkins_Server(StructuredNode):
	uid = UniqueIdProperty()
	url = StringProperty()
	https_enabled = StringProperty()
	version = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	

	plugin = Relationship("Jenkins_Plugin","CONTAINS")
	user = Relationship("Jenkins_User","HAS")
	job = Relationship("Jenkins_Job","EXECUTES")

	def __str__(self):
		return self.url

class Jenkins_Node(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	is_online = StringProperty()
	description = StringProperty()
	url = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	

	job = Relationship("Jenkins_Job","RUNS")

	def __str__(self):
		return self.name

class Jenkins_Job(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	description = StringProperty()
	# last_build = StringProperty()
	is_running = StringProperty()
	is_enabled = StringProperty()
	full_name = StringProperty()
	url = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	

	build = Relationship("Jenkins_Build","BUILD")

	def __str__(self):
		return self.name

class Jenkins_Build(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	number = StringProperty()
	status = StringProperty()
	url = StringProperty()
	output = StringProperty()
	node = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()

	repo = Relationship("Github_Repository","REFERENCE")

	def __str__(self):
		return self.name

class Jenkins_User(StructuredNode):
	uid = UniqueIdProperty()
	username = StringProperty()
	user_url = StringProperty()
	project_name = StringProperty()
	project_url = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	

	def __str__(self):
		return self.username

class Jenkins_Plugin(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	installed_version = StringProperty()
	available_version = StringProperty()
	url = StringProperty()
	enabled = StringProperty()
	hasUpdate = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	

	def __str__(self):
		return self.name


def makeanode(nodetype,data):
	if "jenkins" in nodetype:
		try:
			server_node = Jenkins_Server.nodes.get(url=data["url"])
		except Jenkins_Server.DoesNotExist as ex:
			server_node = Jenkins_Server(url=data["url"],https_enabled=data["https_enabled"],version=data["version"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			server_node.save()
		return server_node
	elif "plugin" in nodetype:
		try:
			plugin_node = Jenkins_Plugin.nodes.get(name=data["name"])
		except Jenkins_Plugin.DoesNotExist as ex:
			plugin_node = Jenkins_Plugin(name=data["name"],installed_version=data["installed_version"],available_version=data["available_version"],url=data["url"],enabled=data["enabled"],hasUpdate=data["hasUpdate"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			plugin_node.save()
		return plugin_node
	elif "user" in nodetype:
		try:
			user_node = Jenkins_User.nodes.get(username=data["username"])
		except Jenkins_User.DoesNotExist as ex:
			user_node = Jenkins_User(username=data["username"],user_url=data["user_url"],project_name=data["project_name"],project_url=data["project_url"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			user_node.save()
		return user_node
	elif "job" in nodetype:
		try:
			job_node = Jenkins_Job.nodes.get(name=data["name"])
		except Jenkins_Job.DoesNotExist as ex:
			job_node = Jenkins_Job(name=data["name"],description=data["description"],is_running=data["is_running"],is_enabled=data["is_enabled"],full_name=data["full_name"],url=data["url"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			job_node.save()
		return job_node
	elif "build" in nodetype:
		try:
			build_node = Jenkins_Build.nodes.get(name=data["name"])
		except Jenkins_Build.DoesNotExist as ex:
			build_node = Jenkins_Build(name=data["name"],number=data["number"],status=data["status"],url=data["url"],output=data["output"],node=data["node"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			build_node.save()
		return build_node
	elif "node" in nodetype:
		try:
			node_node = Jenkins_Node.nodes.get(name=data["name"])
		except Jenkins_Node.DoesNotExist as ex:
			node_node = Jenkins_Node(name=data["name"],is_online=data["is_online"],description=data["description"],url=data["url"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			node_node.save()
		return node_node
	return


def warning_print(message):
	print("\033[93m {}\033[00m" .format(message))

def error_print(message):
	print("\033[91m {}\033[00m" .format(message))

def success_print(message):
	print("\033[32m {}\033[00m" .format(message))	

def clearall():
	for node in Jenkins_Plugin.nodes:
		print("[*] Deleting Jenkins Plugin Nodes")
		node.delete()
	for node in Jenkins_Server.nodes:
		print("[*] Deleting Jenkins Server Nodes")
		node.delete()
	for node in Jenkins_Job.nodes:
		print("[*] Deleting Jenkins Job Nodes")
		node.delete()
	for node in Jenkins_Node.nodes:
		print("[*] Deleting Jenkins Node Nodes")
		node.delete()
	for node in Jenkins_Build.nodes:
		print("[*] Deleting Jenkins Build Nodes")
		node.delete()
	for node in Jenkins_User.nodes:
		print("[*] Deleting Jenkins User Nodes")
		node.delete()
	return


def update_vulnerability(node,vulnID,vuln_artifacts):
	node.affected_vulns = str(node.affected_vulns) + "$" + str(vulnID)
	node.vuln_artifacts = str(node.vuln_artifacts) + "$" + str(vuln_artifacts)
	node.save()
	success_print("[+] Node " + str(node) + " vulnerability details updated successfully: " + vulnID)
	return

if __name__ == "__main__":
	print("[*] Processing Jenkins Server: " + JENKINS_SERVER)
	jenkins_object = Jenkins(JENKINS_SERVER, username=JENKINS_USERNAME, password=JENKINS_TOKEN)	
	success_print("[*] Jenkins API Connection established")
	
	jenkins_request_object = requests.get(JENKINS_SERVER + USERS_QUERY,auth=(JENKINS_USERNAME,JENKINS_TOKEN),headers={"Accept": "application/vnd.github.vixen-preview+json"})
	success_print("[*] Jenkins requests Connection established")
	
	nodedata = {}
	nodedata["url"] = JENKINS_SERVER
	# nodedata["https_enabled"] = not(jenkins_object.requester.cert == None and "None" in jenkins_object.requester.cert) # ("https" in JENKINS_SERVER)
	nodedata["https_enabled"] = "https" in JENKINS_SERVER

	nodedata["version"] = "1.1.1"
	
	nodedata["version"] = jenkins_request_object.headers["X-Jenkins"]
	# nodedata["version"] = jenkins_object.version # throwing exception
	
	nodedata["affected_vulns"] = ""
	nodedata["vuln_artifacts"] = ""
	server_node = makeanode("jenkins",nodedata)

	success_print("[+] Node " + str(server_node) + " created successfully")
	

	# JNK003
	vuln_data = {}
	if not nodedata["https_enabled"]:
		vuln_data["vuln_id"] = "JNK003"
		vuln_data["jenkins_server"] = JENKINS_SERVER
		vuln_data["impacted_area"] = JENKINS_SERVER
		OUTPUT.append(vuln_data)
		update_vulnerability(Jenkins_Server.nodes.get(url=JENKINS_SERVER),vuln_data["vuln_id"],vuln_data["impacted_area"])
	

	# JNK010
	vuln_data = {}
	try:
		nodedata["crumb_required"] = jenkins_object.requester._get_crumb_data()["Jenkins-Crumb"]
	except Exception as ex:
		warning_print("[*] " + str(ex))
		nodedata["crumb_required"] = str("False")
	
	if "False" in nodedata["crumb_required"]:
		vuln_data["vuln_id"] = "JNK010"
		vuln_data["jenkins_server"] = JENKINS_SERVER
		vuln_data["impacted_area"] = str(jenkins_server.requester)
		OUTPUT.append(vuln_data)
		update_vulnerability(Jenkins_Server.nodes.get(url=JENKINS_SERVER),vuln_data["vuln_id"],vuln_data["impacted_area"])
	
	# JNK007

	nodedata = {}
	for job_name, job_instance in jenkins_object.get_jobs():
		try:
			print("[*] Processing job: " +  str(job_name))
			nodedata["name"] = job_name
			nodedata["description"] = job_instance.get_description()
			nodedata["is_running"] = job_instance.is_running()
			nodedata["is_enabled"] = job_instance.is_enabled()
			nodedata["full_name"] = job_instance.get_full_name()
			nodedata["url"] = job_instance.baseurl
			
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
	
			job_node = makeanode("job",nodedata)
			server_node.job.connect(job_node)
			
			success_print("[+] Node " + str(job_node) + " created successfully")

			print("[*] Processing last build and last good build") # procesing last build and last good build - two only for now

			last_build_object = job_instance.get_last_build()
			nodedata = {}
			nodedata["name"] = last_build_object.name
			nodedata["number"] = last_build_object.get_number()
			nodedata["status"] = last_build_object.get_status()
			nodedata["url"] = last_build_object.get_build_url()
			nodedata["output"] = last_build_object.get_console()
			nodedata["node"] = last_build_object.get_slave()
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
	
			build_node = makeanode("build",nodedata)
			job_node.build.connect(build_node)
			success_print("[+] Node " + str(build_node) + " created successfully")

			node_object = jenkins_object.get_node(last_build_object.get_slave())
			nodedata = {}
			nodedata["name"] = node_object.name
			nodedata["is_online"] = node_object.is_online()
			nodedata["description"] = node_object._data["description"]
			nodedata["url"] = node_object.baseurl
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
	
			node_node = makeanode("node",nodedata)
			node_node.job.connect(job_node)
			success_print("[+] Node " + str(node_node) + " created successfully")

			last_good_build_object = job_instance.get_last_good_build()
			nodedata = {}
			nodedata["name"] = last_good_build_object.name
			nodedata["number"] = last_good_build_object.get_number()
			nodedata["status"] = last_good_build_object.get_status()
			nodedata["url"] = last_good_build_object.get_build_url()
			nodedata["output"] = last_good_build_object.get_console()
			nodedata["node"] = last_good_build_object.get_slave()
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
	
			build_node = makeanode("build",nodedata)
			job_node.build.connect(build_node)
			success_print("[+] Node " + str(build_node) + " created successfully")

			node_object = jenkins_object.get_node(last_good_build_object.get_slave())
			nodedata = {}
			nodedata["name"] = node_object.name
			nodedata["is_online"] = node_object.is_online()
			nodedata["description"] = node_object._data["description"]
			nodedata["url"] = node_object.baseurl
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
	
			node_node = makeanode("node",nodedata)
			node_node.job.connect(job_node)
			success_print("[+] Node " + str(node_node) + " created successfully")
		except Exception as ex:
			print(str(ex))


	# JNK001	

	users = jenkins_request_object.json()["users"]

	print("[*] Processing user list")

	nodedata = {}
	for user in users:
		nodedata["username"] = user["user"]["fullName"]
		nodedata["user_url"] = user["user"]["absoluteUrl"]
		nodedata["affected_vulns"] = ""
		nodedata["vuln_artifacts"] = ""
		
		if user["project"] == None or "None" in user["project"]:
			nodedata["project_name"] = "None"
			nodedata["project_url"] = "None"
		else:
			nodedata["project_name"] = user["project"]["name"]
			nodedata["project_url"] = user["project"]["url"]
		
		user_node = makeanode("user",nodedata)
		success_print("[+] Node " + str(user_node) + " created successfully")
		server_node.user.connect(user_node)


	# JNK002
	
	plugins_object = jenkins_object.get_plugins()
	plugins_list = plugins_object.values()
	update_center_dict = plugins_object.update_center_dict

	nodedata = {}
	print("[*] Processing Plugins list")
	for plugin in plugins_list[0:20]:
		nodedata["name"] = plugin.shortName
		nodedata["installed_version"] = plugin.version
		nodedata["available_version"] = plugin.get_download_link(update_center_dict)
		nodedata["url"] = plugin.url
		nodedata["enabled"] = plugin.enabled
		nodedata["hasUpdate"] = plugin.hasUpdate
		nodedata["affected_vulns"] = ""
		nodedata["vuln_artifacts"] = ""
	
		plugin_node = makeanode("plugin",nodedata)
		success_print("[+] Node " + str(plugin_node) + " created successfully")
		server_node.plugin.connect(plugin_node)

		# JNK002

		vuln_data = {}
		vuln_data["vuln_id"] = "JNK002"
		vuln_data["jenkins_server"] = JENKINS_SERVER
		vuln_data["impacted_area"] = "Installed: " + str(nodedata["installed_version"]) + " & Available: " + nodedata["available_version"] + " For: " + nodedata["url"]
		OUTPUT.append(vuln_data)
		update_vulnerability(Jenkins_Plugin.nodes.get(name=plugin.shortName),vuln_data["vuln_id"],vuln_data["impacted_area"])

	print(json.dumps(OUTPUT, indent = 2))
