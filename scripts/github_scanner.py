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
CODE_SCANNING_ENABLED_QUERY "repos/$owner_name/$repo_name/code-scanning/alerts" # 404 means disabled

OUTPUT = []
GIT = Github(os.getenv("GITHUB_ACCESS_TOKEN"))
config.DATABASE_URL = 'bolt://neo4j:Neo4j@localhost:7687'


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
	description = StringProperty()
	permission = StringProperty()
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()

	user = Relationship("Github_User","MEMBER")
	repository = Relationship("Github_Repository","CONTRIBUTES")

	def __str__(self):
		return self.name


class Github_User(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty()
	email = StringProperty()
	usertype = StringProperty()
	is_site_admin = StringProperty()
	permissions = StringProperty()
	role = StringProperty()

	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()


	def __str__(self):
		return self.name

def warning_print(message):
	print("\033[93m {}\033[00m" .format(message))

def error_print(message):
	print("\033[91m {}\033[00m" .format(message))

def success_print(message):
	print("\033[32m {}\033[00m" .format(message))


def clearall():
	for node in Github_Organization.nodes:
		node.delete()
	for node in Github_Repository.nodes:
		node.delete()
	return

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

def makeanode(nodetype, data):
	if "team" in nodetype:
		try:
			team_node = Github_Team.nodes.get(name=data["name"])
		except Github_Team.DoesNotExist as ex:
			team_node = Github_Team(name=data["name"],description=data["description"],permission=data["permission"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"])
			team_node.save()
		return team_node
	elif "repository" in nodetype:
		try:
			repo_node = Github_Repository.nodes.get(name=data["name"])
		except Github_Repository.DoesNotExist as ex:
			repo_node = Github_Repository(name=data["name"],visibility=data["visibility"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"],dependabot_enabled=data["dependabot_enabled"],code_scanning_enabled=data["code_scanning_enabled"],secret_scanning_enabled=data["secret_scanning_enabled"])
			repo_node.save()
		return repo_node
	elif "organization" in nodetype:
		try:
			org_node = Github_Organization.nodes.get(name=data["name"])
		except Github_Organization.DoesNotExist as ex:
			org_node = Github_Organization(name=data["name"],affected_vulns=data["affected_vulns"],vuln_artifacts=data["vuln_artifacts"],two_factor_enabled=data["two_factor_enabled"])
			org_node.save()
		return org_node
	elif "user" in nodetype:
		try:
			user_node = Github_User.nodes.get(name=data["name"])
		except Github_User.DoesNotExist as ex:
			user_node = Github_User(name=data["name"],email=data["email"],usertype=data["usertype"],is_site_admin=data["is_site_admin"],permissions=data["permissions"],role=data["role"],vuln_artifacts=data["vuln_artifacts"],affected_vulns=data["affected_vulns"])
			user_node.save()
		return user_node
	return

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


	print("[*] Organization Name:  " + str(organization_name) + " & Repository Name: " + str(repo_name))

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
	nodedata["affected_vulns"] = ""
	nodedata["vuln_artifacts"] = ""
	secret_scanning_request = requests.get('https://api.github.com' + SECRET_SCANNING_ENABLED_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'})

	if "404" in str(secret_scanning_request.status_code):
		nodedata["secret_scanning_enabled"] = False
	else:
		nodedata["secret_scanning_enabled"] = True

	code_scanning_request = requests.get('https://api.github.com' + CODE_SCANNING_ENABLED_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'})

	if "404" in str(code_scanning_request.status_code):
		nodedata["code_scanning_enabled"] = False
	else:
		nodedata["code_scanning_enabled"] = True

	repo_node = makeanode("repository",nodedata)
	success_print("[+] Node " + str(repo_node) + " created successfully")

	org_node.repository.connect(repo_node)

	teams = org.get_teams()


	for team in teams:
		print("[*] Processing team: " + str(team.name))
		nodedata = {}
		nodedata["name"] = team.name
		nodedata["description"] = team.description
		nodedata["permission"] = team.permission
		nodedata["vuln_artifacts"] = ""
		nodedata["affected_vulns"] = ""

		team_node = makeanode("team",nodedata)
		success_print("[+] Node " + str(team_node) + " created successfully")
		org_node.team.connect(team_node)

		team_repos = team.get_repos()
		for repo in team_repos[0:5]:
			print("[*] Processing repository: " + str(repo.name))
			nodedata = {}
			nodedata["name"] = repo.name
			nodedata["visibility"] = repo._rawData["visibility"]
			nodedata["dependabot_enabled"] = repo.get_vulnerability_alert()
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
			repo_node = makeanode("repository",nodedata)
			success_print("[+] Node " + str(repo_node) + " created successfully")
			team_node.repository.connect(repo_node)



		team_members = team.get_members()
		for member in team_members[0:5]:
			print("[*] Processing member: " + str(member.name))
			nodedata = {}
			nodedata["name"] = member.name
			nodedata["email"] = member.email
			nodedata["usertype"] = member.type
			nodedata["is_site_admin"] = member.site_admin
			nodedata["permissions"] = member.permissions
			nodedata["role"] = member.role
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
			
			member_node = makeanode("user",nodedata)
			success_print("[+] Node " + str(repo_node) + " created successfully")
			team_node.user.connect(member_node)