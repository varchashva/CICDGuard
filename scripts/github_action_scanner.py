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

# Global Variables
ACTION_PERMISSIONS_QUERY = "/repos/$owner_name/$repo_name/actions/permissions"
WORKFLOW_PERMISSIONS_QUERY = "/repos/$owner_name/$repo_name/actions/permissions/workflow"
SECRET_SCANNING_ENABLED_QUERY = "/repos/$owner_name/$repo_name/secret-scanning/alerts" # 404 means disabled 
CODE_SCANNING_ENABLED_QUERY = "/repos/$owner_name/$repo_name/code-scanning/alerts" # 404 means disabled


OUTPUT = []
GIT = Github(os.getenv("GITHUB_ACCESS_TOKEN"))
config.DATABASE_URL = 'bolt://neo4j:Neo4j@localhost:7687'

OUTPUT_FORMAT = {
	"vuln_id": "vuln_id",
	"repository": "repository",
	"organization": "organization",
	"impacted_area": "impacted_area", # action, workflow etc.
	},{
	"vuln_id": "vuln_id",
	"repository": "repository",
	"organization": "organization",
	"impacted_area": "impacted_area", # action, workflow etc.
}



class Action_Workflow(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	trigger = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()

	repository = Relationship('Github_Repository',"CONTAINS")

	def __str__(self):
		return self.name

class Action_Job(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()

	workflow = Relationship("Action_Workflow","HAVE")

	def __str__(self):
		return self.name

class Action_Step(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	
	job = Relationship('Action_Job',"EXECUTES")

	def __str__(self):
		return self.uid

class Action_Command(StructuredNode):
	uid = UniqueIdProperty()
	command = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()

	step = Relationship("Action_Step","RUNS")

	def __str__(self):
		return self.command

class Github_Organization(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty(unique_index=True)
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	two_factor_enabled = StringProperty()

	repository = Relationship('Github_Repository',"PART_OF")
	team = Relationship("Github_Team","HAS")

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

class Github_Team(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()

	user = Relationship("Github_User","MEMBER")

	def __str__(self):
		return self.name


class Github_User(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()

	def __str__(self):
		return self.name


class Action_Runner(StructuredNode):
	uid = UniqueIdProperty()
	labels = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()

	job = Relationship('Action_Job',"RUNS_ON")

	def __str__(self):
		return self.labels

class Action_Action(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()

	step = Relationship('Action_Step',"USES")

	def __str__(self):
		return self.name



def warning_print(message):
	print("\033[93m {}\033[00m" .format(message))

def error_print(message):
	print("\033[91m {}\033[00m" .format(message))

def success_print(message):
	print("\033[32m {}\033[00m" .format(message))

def parse_workflow(workflow):
	download_url = repo.get_contents(urllib.parse.quote(workflow.path)).download_url
	with urllib.request.urlopen(download_url) as url_content:
		workflow_data = yaml.safe_load(url_content.read().decode())
	return workflow_data

def any_self_hosted(workflow_data):
	for job in workflow_data['jobs']:
		return "self-hosted" in workflow_data['jobs'][job]['runs-on']
	return False

def all_self_hosted(workflow_data):
	all_self_hosted = True
	for job in workflow_data['jobs']:
		if "self-hosted" not in workflow_data['jobs'][job]['runs-on']:
			all_self_hosted = False
			return all_self_hosted
	return all_self_hosted

def find_insecure_inputs(workflow_data):
	for job in workflow_data['jobs']:
		for step in workflow_data['jobs'][job]['steps']:
			if "run" in step:
				matches = re.findall('\${{[\w. ]*}}',step['run'])
				return matches
	return []

def find_actions(workflow_data):
	actions = []
	for job in workflow_data['jobs']:
		for step in workflow_data['jobs'][job]['steps']:
			if "uses" in step:
				actions.append(step['uses'])
	return actions


def makeanode(nodetype,data):
	if "organization" in nodetype:
		try:
			org_node = Github_Organization.nodes.get(name=data["name"])
		except Github_Organization.DoesNotExist as ex:
			org_node = Github_Organization(name=data["name"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"],two_factor_enabled=data["two_factor_enabled"])
			org_node.save()
		return org_node
	elif "repository" in nodetype:
		try:
			repo_node = Github_Repository.nodes.get(name=data["name"])
		except Github_Repository.DoesNotExist as ex:
			repo_node = Github_Repository(name=data["name"],visibility=data["visibility"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"],dependabot_enabled=data["dependabot_enabled"],code_scanning_enabled=data["code_scanning_enabled"],secret_scanning_enabled=data["secret_scanning_enabled"])
			repo_node.save()
		return repo_node
	elif "workflow" in nodetype:
		try:
			workflow_node = Action_Workflow.nodes.get(name=data["name"])
		except Action_Workflow.DoesNotExist as ex:
			workflow_node = Action_Workflow(name=data["name"],trigger=data["trigger"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			workflow_node.save()
		return workflow_node
	elif "job" in nodetype:
		try:
			job_node = Action_Job.nodes.get(name=data["name"])
		except Action_Job.DoesNotExist as ex:
			job_node = Action_Job(name=data["name"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			job_node.save()
		return job_node
	elif "runner" in nodetype:
		try:
			runner_node = Action_Runner.nodes.get(labels=data["labels"])
		except Action_Runner.DoesNotExist as ex:
			runner_node = Action_Runner(labels=data["labels"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			runner_node.save()
		return runner_node
	elif "step" in nodetype:
		try:
			step_node = Action_Step.nodes.get(name=data["name"])
		except Action_Step.DoesNotExist as ex:
			step_node = Action_Step(name=data["name"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			step_node.save()
		return step_node
	elif "action" in nodetype:
		try:
			action_node = Action_Action.nodes.get(name=data["name"])
		except Action_Action.DoesNotExist as ex:
			action_node = Action_Action(name=data["name"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			action_node.save()
		return action_node
	elif "command" in nodetype:
		try:
			command_node = Action_Command.nodes.get(command=data["command"])
		except Action_Command.DoesNotExist as ex:
			command_node = Action_Command(command=data["command"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			command_node.save()
		return command_node
	return


def update_vulnerability(node,vulnID,vuln_artifacts):
	node.affected_vulns = str(node.affected_vulns) + "$" + str(vulnID)
	node.vuln_artifacts = str(node.vuln_artifacts) + "$" + str(vuln_artifacts)
	node.save()
	success_print("[+] Node " + str("[node]") + " vulnerability details updated successfully: " + vulnID)
	return


def clearall():
	for node in Github_Repository.nodes:
		node.delete()
	for node in Github_Organization.nodes:
		node.delete()
	for node in Action_Workflow.nodes:
		node.delete()
	for node in Action_Job.nodes:
		node.delete()
	for node in Action_Runner.nodes:
		node.delete()
	for node in Action_Step.nodes:
		node.delete()
	for node in Action_Action.nodes:
		node.delete()
	for node in Action_Command.nodes:
		node.delete()


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-o","--organization", help="Github Organization Name")
	parser.add_argument("-r","--repo", help="Repository Name")
	args = parser.parse_args()
	if args.organization:
	    organization_name = args.organization
	else:
		parser.print_help()
		exit(0)
	if args.repo:
		repo_name = args.repo
	else:
		parser.print_help()
		exit(0)

	print("[*] Organization Name:  " + str("[organization_name]") + " & Repository Name: " + str("[repo_name]"))
	

	repo = GIT.get_repo(organization_name + "/" + repo_name)
	org = GIT.get_organization(organization_name)

	nodedata = {}

	nodedata["name"] = organization_name
	nodedata["affected_vulns"] = ""
	nodedata["vuln_artifacts"] = ""
	nodedata["two_factor_enabled"] = org.two_factor_requirement_enabled

	org_node = makeanode("organization",nodedata)
	success_print("[+] Node " + str(org_node) + " created successfully")
	
	nodedata["name"] = repo_name
	nodedata["visibility"] = repo._rawData["visibility"]
	nodedata["dependabot_enabled"] = repo.get_vulnerability_alert()

	nodedata["secret_scanning_enabled"] = "False"
	nodedata["code_scanning_enabled"] = "False"

	# secret_scanning_request = requests.get('https://api.github.com' + SECRET_SCANNING_ENABLED_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'})

	# if "404" in str(secret_scanning_request.status_code):
	# 	nodedata["secret_scanning_enabled"] = False
	# else:
	# 	nodedata["secret_scanning_enabled"] = True

	# code_scanning_request = requests.get('https://api.github.com' + CODE_SCANNING_ENABLED_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'})

	# if "404" in str(code_scanning_request.status_code):
	# 	nodedata["code_scanning_enabled"] = False
	# else:
	# 	nodedata["code_scanning_enabled"] = True

	nodedata["affected_vulns"] = ""
	nodedata["vuln_artifacts"] = ""

	repo_node = makeanode("repository",nodedata)
	success_print("[+] Node " + str(repo_node) + " created successfully")

	org_node.repository.connect(repo_node)

	workflows = repo.get_workflows()

	for workflow in workflows:
		workflow_data = parse_workflow(workflow)

		nodedata["name"] = workflow_data["name"]
		nodedata["trigger"] = workflow_data[True]
		nodedata["affected_vulns"] = ""
		nodedata["vuln_artifacts"] = ""
		workflow_node = makeanode("workflow",nodedata)
		workflow_node.repository.connect(repo_node)
		success_print("[+] Node " + str(workflow_node) + " created successfully")
		
		for job in workflow_data['jobs']:
			try: # in case job logs has expired
				nodedata["name"] = workflow_data['jobs'][job]['name']
			except Exception as ex:
				warning_print("[?] " + str(ex))
				nodedata["name"] = "Undefined"
				nodedata["affected_vulns"] = ""
				nodedata["vuln_artifacts"] = ""
		
				job_node = makeanode("job",nodedata)
				job_node.workflow.connect(workflow_node)
				success_print("[+] Node " + str(job_node) + " created successfully")
				
				nodedata["labels"] = str(workflow_data['jobs'][job]['runs-on'])
				nodedata["affected_vulns"] = ""
				nodedata["vuln_artifacts"] = ""
				runner_node = makeanode("runner",nodedata)
				runner_node.job.connect(job_node)
				success_print("[+] Node " + str(runner_node) + " created successfully")
				
				warning_print("[?] Exiting for current job")
				break
			
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
			job_node = makeanode("job",nodedata)
			job_node.workflow.connect(workflow_node)
			success_print("[+] Node " + str(job_node) + " created successfully")
			
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""	
			nodedata["labels"] = str(workflow_data['jobs'][job]['runs-on'])
			runner_node = makeanode("runner",nodedata)
			runner_node.job.connect(job_node)
			success_print("[+] Node " + str(runner_node) + " created successfully")
			
			for step in workflow_data['jobs'][job]['steps']:
				nodedata["affected_vulns"] = ""
				nodedata["vuln_artifacts"] = ""	
			
				nodedata["name"] = step["name"]
				step_node = makeanode("step",nodedata)
				step_node.job.connect(job_node)
				success_print("[+] Node " + str(step_node) + " created successfully")
					
				if "uses" in step:		
					nodedata["affected_vulns"] = ""
					nodedata["vuln_artifacts"] = ""	
			
					nodedata["name"] = step["uses"]
					action_node = makeanode("action",nodedata)
					action_node.step.connect(step_node)
					success_print("[+] Node " + str(action_node) + " created successfully")					
				else:
					nodedata["affected_vulns"] = ""
					nodedata["vuln_artifacts"] = ""	
			
					nodedata["command"] = step["run"]
					command_node = makeanode("command",nodedata)
					command_node.step.connect(step_node)
					success_print("[+] Node " + str(command_node) + " created successfully")	
				
	for workflow in workflows:
		vuln_data = {}
		vuln_data['repository'] = repo.name
		vuln_data['organization'] = organization_name

		workflow_data = parse_workflow(workflow)
		vuln_data["repo"] = repo.name
		vuln_data["workflow"] = workflow.name
		
		# SIA004		
		if ((not repo.private) and any_self_hosted(workflow_data)):
			vuln_data["vuln_id"] = "SIA004"	
			vuln_data["impacted_area"] = str(workflow.name) + " any self-hosted " + str(workflow_data['jobs'])			
			OUTPUT.append(vuln_data)	
			update_vulnerability(Action_Workflow.nodes.get(name=workflow.name),vuln_data["vuln_id"],vuln_data["impacted_area"])

		# SIA003	
		if (repo.private) and (not all_self_hosted(workflow_data)):
			vuln_data["vuln_id"] = "SIA003"
			vuln_data["impacted_area"] = str(workflow.name) + " all self-hosted " + str(workflow_data['jobs'])	
			OUTPUT.append(vuln_data)
			update_vulnerability(Action_Workflow.nodes.get(name=workflow.name),vuln_data["vuln_id"],vuln_data["impacted_area"])

		# SIA002
		matches = find_insecure_inputs(workflow_data)
		if len(matches) > 0:
			vuln_data["vuln_id"] = "SIA002"
			vuln_data["impacted_area"] = matches
			OUTPUT.append(vuln_data)
			update_vulnerability(Action_Workflow.nodes.get(name=workflow.name),vuln_data["vuln_id"],vuln_data["impacted_area"])

		# SIA005
		actions = find_actions(workflow_data)
		for action in actions:
			if len(action.split("@")) < 2:
				vuln_data["vuln_id"] = "SIA005"
				vuln_data["impacted_area"] = action
				OUTPUT.append(vuln_data)
				update_vulnerability(Action_Action.nodes.get(name=action),vuln_data["vuln_id"],vuln_data["impacted_area"])
			elif "master" in action.split("@")[1]:
				vuln_data["vuln_id"] = "SIA005"
				vuln_data["impacted_area"] = action
				OUTPUT.append(vuln_data)
				update_vulnerability(Action_Action.nodes.get(name=action),vuln_data["vuln_id"],vuln_data["impacted_area"])

		# SIA011
		# Note - it requires "administration" permission 
		# PyGithub library doesn't support it

		workflow_permission = requests.get('https://api.github.com' + WORKFLOW_PERMISSIONS_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'}).json()
		if "can_approve_pull_request_reviews" in workflow_permission:
			if workflow_permission["can_approve_pull_request_reviews"]:
				vuln_data["vuln_id"] = "SIA011"
				vuln_data["impacted_area"] = workflow_permission
				OUTPUT.append(vuln_data)
				update_vulnerability(Github_Organization.nodes.get(name=organization_name),vuln_data["vuln_id"],vuln_data["impacted_area"])

		# SIA016
		# Note - it requires "administration" permission 
		# PyGithub library doesn't support it

		if "write" in workflow_permission["default_workflow_permissions"]:
			vuln_data["vuln_id"] = "SIA016"
			vuln_data["impacted_area"] = workflow_permission
			OUTPUT.append(vuln_data)
			update_vulnerability(Github_Organization.nodes.get(name=organization_name),vuln_data["vuln_id"],vuln_data["impacted_area"])

		# SIA015
		# Note - it requires "administration" permission 
		# PyGithub library doesn't support it
		
		action_permission = requests.get('https://api.github.com' + ACTION_PERMISSIONS_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'}).json()
		if "all" in action_permission["allowed_actions"]:
			vuln_data["vuln_id"] = "SIA015"
			vuln_data["impacted_area"] = action_permission

			vuln_data["organization"]

			OUTPUT.append(vuln_data)
			update_vulnerability(Github_Organization.nodes.get(name=organization_name),vuln_data["vuln_id"],vuln_data["impacted_area"])
		elif "selected" in action_permission["allowed_actions"]:
			selected_actions = requests.get(action_permission["selected_actions_url"], headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'}).json()
			vuln_data["vuln_id"] = "SIA015"
			vuln_data["impacted_area"] = selected_actions
			OUTPUT.append(vuln_data)
			update_vulnerability(Github_Organization.nodes.get(name=organization_name),vuln_data["vuln_id"],vuln_data["impacted_area"])

	print(json.dumps(OUTPUT, indent = 2))