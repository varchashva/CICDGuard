from django.shortcuts import render

from django.http import HttpResponse
from django.template import RequestContext

from .models import *
import re


def index(request):
	
	jenkins_filters = ["Node","Job","Server","Build","User","Plugin"]
	github_filters = ["Repository","Organization"]
	action_filters = ["Workflow","Job","Runner","Step","Action","Command"]
	jfrog_filters = ["User","Group"]
	context = {
		"jenkins_filters": jenkins_filters,
		"github_filters": github_filters,
		"action_filters": action_filters,
		"jfrog_filters": jfrog_filters

	}

	return render(request, 'main.html', context)

def makeanode(nodetype,data):
	if "repository" in nodetype:
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

def analyze(request):
	for build in Jenkins_Build.nodes:
		matches = re.findall('\${{[\w. ]*}}',str(build.output)) # need to modify regex to capture "git fetch --tags --progress git@github.com:netSkope/infrastructure.git"
		if len(matches) > 0:
			# need code to create repo and org node and connect to this 
			build_node = Jenkins_Build.nodes.get(name=build.name)
			repo_name = "" # will fetch from matches
			organization_name = "" # will fetch from matches

			nodedata = {}
			nodedata["name"] = repo_name
			nodedata["visibility"] = ""
			nodedata["dependabot_enabled"] = ""
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
			nodedata["secret_scanning_enabled"] = ""
			nodedata["code_scanning_enabled"] = ""
			repo_node = makeanode("repository",nodedata)
			success_print("[+] Node " + str(repo_node) + " created successfully")
			build_node.repo.connect(repo_node)

			nodedata = {}
			nodedata["name"] = organization_name
			nodedata["affected_vulns"] = ""
			nodedata["vuln_artifacts"] = ""
			nodedata["two_factor_enabled"] = ""
			org_node = makeanode("organization",nodedata)
			success_print("[+] Node " + str(org_node) + " created successfully")
			org_node.repository.connect(repo_node)

	jenkins_filters = ["Node","Job","Server","Build","User","Plugin"]
	github_filters = ["Repository","Organization"]
	action_filters = ["Workflow","Job","Runner","Step","Action","Command"]
	jfrog_filters = ["User","Group"]
	context = {
		"jenkins_filters": jenkins_filters,
		"github_filters": github_filters,
		"action_filters": action_filters,
		"jfrog_filters": jfrog_filters

	}

	return render(request, 'main.html', context)


def actionreview(request):
	context = {}
	return render(request,'main.html',context)


def  vulnerabilities(request):

	data = []
	headers = ["VulnID", "Description", "Technology", "Artifacts","Further Read"]

	for action in Action_Action.nodes:
		
		if action.affected_vulns != "":
			vulns = str(action.affected_vulns).split("$")
			artifacts = str(action.vuln_artifacts).split("$")

			for i in range(1,len(vulns)):
				row = []
				if vulns != "":
					row.append(vulns[i])
					row.append("")
					row.append("Github Action")
					row.append(artifacts[i] + " " + str(action.name))
					row.append("")
					data.append(row)

	for workflow in Action_Workflow.nodes:	
		if workflow.affected_vulns != "":
			vulns = str(workflow.affected_vulns).split("$")
			artifacts = str(workflow.vuln_artifacts).split("$")

			for i in range(1,len(vulns)):
				row = []
				if vulns != "":
					row.append(vulns[i])
					row.append("")
					row.append("Github Action Workflow")
					row.append(artifacts[i] + " " + str(workflow.name))
					row.append("")
					data.append(row)

	for organization in Github_Organization.nodes:	
		if organization.affected_vulns != "":
			vulns = str(organization.affected_vulns).split("$")
			artifacts = str(organization.vuln_artifacts).split("$")

			for i in range(1,len(vulns)):
				row = []
				if vulns != "":
					row.append(vulns[i])
					row.append("")
					row.append("Github Organization")
					row.append(artifacts[i] + " " + str(organization.name))
					row.append("")
					data.append(row)

	for repository in Github_Repository.nodes:	
		if repository.affected_vulns != "":
			vulns = str(repository.affected_vulns).split("$")
			artifacts = str(repository.vuln_artifacts).split("$")

			for i in range(1,len(vulns)):
				row = []
				if vulns != "":
					row.append(vulns[i])
					row.append("")
					row.append("Github Repository")
					row.append(artifacts[i] + " " + str(repository.name))
					row.append("")
					data.append(row)	

	for server in Jenkins_Server.nodes:	
		if server.affected_vulns != "":
			vulns = str(server.affected_vulns).split("$")
			artifacts = str(server.vuln_artifacts).split("$")

			for i in range(1,len(vulns)):
				row = []
				if vulns != "":
					row.append(vulns[i])
					row.append("")
					row.append("Jenkins Server")
					row.append(artifacts[i] + " " + str(server.url))
					row.append("")
					data.append(row)	
	



	#################################

	# for workflow in workflows:
	# 	result = {}
	# 	result['repo'] = repo.name
	# 	result['workflow'] = workflow.name
		
	# 	workflow_data = parse_workflow(workflow)
	# 	result["repo"] = repo.name
	# 	result["workflow"] = workflow.name
		
		
	# 	issues = []
	# 	issue = {}
		
	# 	# SIA004
	# 	issue["issue_id"] = "SIA004"
	# 	issue["status"] = "Not Applicable"
	# 	if ((not repo.private) and any_self_hosted(workflow_data)):
	# 		issue["status"] = "Vulnerable"
	# 	elif not repo.private:
	# 		issue["status"] = "Not Vulnerable"

	# 	issues.append(issue)
	# 	issue = {}

	# 	# SIA003	
	# 	issue["issue_id"] = "SIA003"
	# 	issue["status"] = "Not Applicable"
	# 	if (repo.private) and (not all_self_hosted(workflow_data)):
	# 		issue["status"] = "Vulnerable"
	# 	elif repo.private:
	# 		issue["status"] = "Not Vulnerable"
	# 	issues.append(issue)
		

	# 	# SIA002
	# 	issue["issue_id"] = "SIA002"
	# 	issue["status"] = "Not Applicable"

	# 	issue = {}
	# 	matches = find_insecure_inputs(workflow_data)
	# 	if len(matches) > 0:
	# 		issue["issue_id"] = "SIA002"
	# 		issue["status"] = "Vulnerable"
	# 		issue["config"] = matches 
	# 		issues.append(issue)

	# 	# SIA005

	# 	issue = {}
	# 	actions = find_actions(workflow_data)
	# 	for action in actions:
	# 		if len(action.split("@")) < 2:
	# 			issue["issue_id"] = "SIA005"
	# 			issue["status"] = "Vulnerable"
	# 			issue["config"] = action
	# 			issues.append(issue)
	# 		elif "master" in action.split("@")[1]:
	# 			issue["issue_id"] = "SIA005"
	# 			issue["status"] = "Vulnerable"
	# 			issue["config"] = action
	# 			issues.append(issue)

	# 	# SIA011
	# 	# Note - it requires "administration" permission 
	# 	# PyGithub library doesn't support it

	# 	issue = {}
	# 	workflow_permission = requests.get('https://api.github.com' + WORKFLOW_PERMISSIONS_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'}).json()
	# 	if "can_approve_pull_request_reviews" in workflow_permission:
	# 		if workflow_permission["can_approve_pull_request_reviews"]:
	# 			issue["issue_id"] = "SIA011"
	# 			issue["status"] = "Vulnerable"
	# 			issue["config"] = workflow_permission
	# 			issues.append(issue)

	# 	# SIA016
	# 	# Note - it requires "administration" permission 
	# 	# PyGithub library doesn't support it

	# 	issue = {}
	# 	if "write" in workflow_permission["default_workflow_permissions"]:
	# 		issue["issue_id"] = "SIA016"
	# 		issue["status"] = "Vulnerable"
	# 		issue["config"] = workflow_permission
	# 		issues.append(issue)

	# 	# SIA015
	# 	# Note - it requires "administration" permission 
	# 	# PyGithub library doesn't support it
		
	# 	issue = {}
	# 	action_permission = requests.get('https://api.github.com' + ACTION_PERMISSIONS_QUERY.replace("$owner_name",str(organization_name)).replace("$repo_name",str(repo.name)), headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'}).json()
	# 	if "all" in action_permission["allowed_actions"]:
	# 		issue["issue_id"] = "SIA015"
	# 		issue["status"] = "Vulnerable"
	# 		issue["config"] = action_permission
	# 		issues.append(issue)
	# 	elif "selected" in action_permission["allowed_actions"]:
	# 		selected_actions = requests.get(action_permission["selected_actions_url"], headers={'Authorization': 'bearer ' + str(os.getenv("GITHUB_ACCESS_TOKEN")) ,'Accept': 'application/vnd.github.vixen-preview+json'}).json()
	# 		issue["issue_id"] = "SIA015"
	# 		issue["status"] = "Review"
	# 		issue["config"] = selected_actions
	# 		issues.append(issue)

	# 	result["issues"] = issues
	# 	OUTPUT.append(result)





	#################################


	# data = []
	

	context = {
		"headers": headers,
		"data": data
	}
	return render(request,"vulnerabilities.html",context)