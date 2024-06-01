# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from neomodel import (config, StructuredNode, StringProperty, IntegerProperty, ArrayProperty,
    UniqueIdProperty, RelationshipTo, RelationshipFrom, Relationship)

config.DATABASE_URL = 'bolt://neo4j:Neo4j@localhost:7687'


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

	repository = Relationship('Github_Repository',"PART_OF")

	def __str__(self):
		return self.name

class Github_Repository(StructuredNode):
	uid = UniqueIdProperty()
	name = StringProperty(unique_index=True)
	visibility = StringProperty() # Private, Public, Internal
	affected_vulns = StringProperty()
	vuln_artifacts = StringProperty()
	
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

