from flask import Flask, render_template, request , send_file
from flask import jsonify
from flask_cors import CORS


import os
import time
import json
from flask_pymongo import PyMongo
import pymongo
import logging
from logging.handlers import RotatingFileHandler

import requests
import urllib.parse

import datetime
import base64
import hashlib
import redis
import random
import cerberus


logger =  logging.getLogger("Rotating Log websnap")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler("/home/ubuntu/web_server_log/web_server.log",maxBytes=5000000,backupCount=25)

formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
#logger.propagate = False # DISABLE LOG STDOUT
logger.info("Starting Webserver")

app = Flask(__name__,static_url_path='/static')
CORS(app)
app.config['MONGO_DBNAME'] = 'accounts'
app.config['MONGO_URI'] = 'mongodb://127.0.0.1:27017/accounts'

mongoc = PyMongo(app)
mdb = mongoc.db
mcollection = mdb['users']

red = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)


SOLR_CLOUD_BIN = "/home/ubuntu/solr-7.4.0/bin/"



@app.route('/')
def main():
	 return "API call only......."


@app.route('/search',methods = ['POST', 'GET'])
def search_query():
	if request.method == 'GET':
		try:
			get_req = request.args.to_dict()
			domain = get_req.get("domain")
			search_domain = get_req.get("search_domain")
			fl = get_req.get("fl")
			q = get_req.get("q")
			application = get_req.get("application")
			rows = get_req.get("rows")
			start = get_req.get("start")
			solr_url = "http://127.0.0.1:8983/solr/"+domain+"/select?"
			if domain != None:
				enc_url = {"fl":fl,"q":q,"rows":rows,"start":start}
				if search_domain != None and search_domain != "all":
					enc_url.update({"fq":"+id:/http?.:\/\/"+search_domain+".*/"})
				if application != None:
					enc_url.update({"q":"+f_type:"+application+" +"+q})
				
				enc_url = urllib.parse.urlencode(enc_url)

				solr_url = solr_url+enc_url
				logger.info(solr_url)
				solr_res = requests.get(solr_url)
				if solr_res.status_code == 200:
					if solr_res.headers['content-type'].split(";")[0] == "application/json":
						solr_res = solr_res.json()
						solr_res.update({"result":"success"})
						return jsonify(solr_res)

			return jsonify({"result":"error"})
		except Exception:
			logger.exception("search_query")
			return jsonify({"result":"failed error"})

@app.route('/suggest',methods = ['POST', 'GET'])
def suggest():
	if request.method == 'GET':
		try:
			get_req = request.args.to_dict()
			domain = get_req.get("domain")
			q = get_req.get("q")
			
			solr_url = "http://127.0.0.1:8983/solr/"
			if domain != None:
				enc_url = {"suggest":"true","suggest.build":"true","suggest.dictionary":"mySuggester","suggest.q":q}
				enc_url = urllib.parse.urlencode(enc_url)
				solr_url = solr_url + domain + "/suggest?" + enc_url
				solr_res = requests.get(solr_url)
				if solr_res.status_code == 200:
					if solr_res.headers['content-type'].split(";")[0] == "application/json":
						solr_res = solr_res.json()
						solr_res.update({"result":"success"})
						return jsonify(solr_res)

			return jsonify({"result":"failed"})
		except Exception:
			logger.exception("suggest")
			return jsonify({"result":"failed"})

@app.route('/spell',methods = ['POST', 'GET'])
def spell():
	if request.method == 'GET':
		try:
			get_req = request.args.to_dict()
			domain = get_req.get("domain")
			q = get_req.get("q")
			
			solr_url = "http://127.0.0.1:8983/solr/"
			if domain != None:
				enc_url = {"df":"text","spellcheck.q":q,"spellcheck":"true","spellcheck.collateParam.q.op":"AND"}
				enc_url = urllib.parse.urlencode(enc_url)
				solr_url = solr_url + domain + "/spell?"+enc_url
				solr_res = requests.get(solr_url)
				if solr_res.status_code == 200:
					if solr_res.headers['content-type'].split(";")[0] == "application/json":
						solr_res = solr_res.json()
						solr_res.update({"result":"success"})
						return jsonify(solr_res)

			return jsonify({"result":"failed"})
		except Exception:
			logger.exception("suggest")
			return jsonify({"result":"failed"})

##############################################################################################################

def check_user_session(session_id):
	# Validate user session with cookie
	try:
		user_id = red.hgetall(session_id)
		if not user_id:
			# If user_id is None or not containe dict value
			# No session found
			return None
		else:
			# Valid session
			# Update user TTL for this session
			red.expire(session_id,600)
			return user_id
	except Exception:
		logger.exception("check_user_session")

@app.route('/portal/logout',methods = ['POST', 'GET'])
def portal_logout():
	# Logout user by deleting session from redis DB
	try:
		if request.method == 'GET':
			# Get session ID from GET argument
			get_req = request.args.to_dict()
			session_id = get_req.get("session_id")
			
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session id
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"success","message":"Already Logged out"})
				else:
					# Remove user session from Redis DB
					delete_status = red.delete(session_id)
					if delete_status == 1:
						return jsonify({"result":"success","message":"Logout success"})
					else:
						return jsonify({"result":"success","message":"Already Logged out"})
			else:
				return jsonify({"result":"failed","message":"Session information missing"})
		else:
			return jsonify({"result":"failed","message":"Invalid API call"})
			
	except Exception:
		logger.exception("portal_logout")
		return jsonify({"result":"failed","message":"Clear Browser cookie or API Key"})

@app.route('/portal/login',methods = ['POST', 'GET'])
def portal_login():
	# Validate loging username and password
	# Creating Session when user login
	try:
		if request.method == 'POST':
			result = request.form
			
			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data != None:
					return jsonify({"result":"success","message":"Already logged In"})
			############## SESSION VALIDATION END #####################

			user_id = result.get("user_name")
			user_password = result.get("user_password")

			# Get User information from database
			pass_hash = hashlib.sha1(user_password.encode()).hexdigest()
			user_data = mcollection.find_one({"_id":user_id,"PasswordHash":pass_hash},{"_id":1,"AccountType":1})
			
			if user_data == None:
				# Provided user information in not available in database
				session_id = None
				return jsonify({"result":"failed","message":"Username or Password Not matched"})
			else:
				# Provided user information in available in database
				# Gendrating session id for user
				# Saving session and user information to Redis DB
				user_id = user_data.get("_id")
				account_type = user_data.get("AccountType")
				rand_number = str(random.randint(100,999999) + time.time())
				session_id = "user_"+user_id+"_"+hashlib.sha1(rand_number.encode()).hexdigest()
				
				# Setting session data to Redis DB
				user_session_data = {"_id":user_id,"AccountType":account_type}
				red.hmset(session_id,user_session_data)
				red.expire(session_id,600)
				
				resp = jsonify({"result":"success","message":"login success"})
				resp.set_cookie('session_id', session_id)
				return resp
		else:
			return jsonify({"result":"failed","message":"POST method required"})

	except Exception:
		logger.exception("portal_login")
		return jsonify({"result":"failed","message":"login failed"})

@app.route('/portal/create_domain',methods = ['POST', 'GET'])
def create_domain():
	try:
		if request.method == 'POST':
			result = request.form
			
			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################
			
			user_id = user_data.get("_id")
			form_schema = dict()
			form_schema.update({'domain_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'engine_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})

			form_validate = cerberus.Validator()
			form_valid = form_validate.validate(result, form_schema)
			if form_valid == False:
				# Form not valid
				error_status = {"results":"failed"}
				error_status.update(form_validate.errors)
				return jsonify(error_status)
			
			domain_name = result.get("domain_name")
			engine_name = result.get("engine_name")

			white_url = []
			black_url = []
			white_app = ["application/html"]
			black_app = ["application/exe"]
			crawl_schedule = {"week":["Su","Mo","Tu","We","Th","Fr","Sa"],"day":[],"time":"00 AM"}
			manual_url = []
			adv_settings = {"Allow Robot.txt":"yes","ParallelCrawler":5}
			weight = [{"field":"title","weight":1},{"field":"body","weight":2},{"field":"url","weight":3}]
			synonums = []
			custom_results = []

			new_domain = dict()
			new_domain.update({"DomainName":domain_name})
			new_domain.update({"Pages":0})
			new_domain.update({"LastCrawl":"no"})
			new_domain.update({"CreatedAt":datetime.datetime.utcnow()})
			new_domain.update({"UpdatedAt":datetime.datetime.utcnow()})
			new_domain.update({"CreatedBy":user_id})
			new_domain.update({"CurrentStatus":"created"})
			new_domain.update({"WhiteListUrls":white_url})
			new_domain.update({"BlackListUrls":black_url})
			new_domain.update({"WhiteListApp":white_app})
			new_domain.update({"BlackListApp":black_app})
			new_domain.update({"CrawlSchedule":crawl_schedule})
			new_domain.update({"ManualUrls":manual_url})
			new_domain.update({"ManualUrlsOnly":"no"})
			new_domain.update({"AdvancedSettings":adv_settings})
			new_domain.update({"Weight":weight})
			new_domain.update({"Synonums":synonums})
			new_domain.update({"CustomResults":custom_results})

			try:
				results = mcollection.update_one({"_id":user_id,"Engines.EngineName":engine_name,
					"Engines.Domains.DomainName":{"$ne":domain_name}},{"$push":{"Engines.$.Domains":new_domain}})
				if results.modified_count == 1:
					return jsonify({"result":"success","message":"Domain added"})
				else:
					return jsonify({"result":"failed","message":"Domain already exist"})
			except Exception:
				logger.exception("create_domain")
				return jsonify({"result":"failed","message":"Domain creation failed"})

	except Exception:
		logger.exception("create_domain")
		return jsonify({"result":"failed","message":"Domain creation failed"})

@app.route('/portal/create_engine',methods = ['POST', 'GET'])
def create_engine():
	try:
		if request.method == 'POST':
			result = request.form
			
			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################
			
			user_id = user_data.get("_id")
			form_schema = dict()
			form_schema.update({'engine_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})

			form_validate = cerberus.Validator()
			form_valid = form_validate.validate(result, form_schema)
			if form_valid == False:
				# Form not valid
				error_status = {"results":"failed"}
				error_status.update(form_validate.errors)
				return jsonify(error_status)
			
			engine_name = result.get("engine_name")
			
			new_engine = dict()
			new_engine.update({"EngineName":engine_name})
			new_engine.update({"Domains":[]})

			try:
				# Get MaximumEngine license
				user_details = mcollection.find_one({"_id":user_id},{"_id":1,"MaximumEngines":1,"LicenceEnd":1,"Engines":1})
				
				if user_details != None:
					max_engine = user_details.get("MaximumEngines")
					licence_end = user_details.get("LicenceEnd")
					current_engines = user_details.get("Engines")
				else:
					#logger.errot("BUG: MaximumEngines not found in DB for: "+user_id)
					return jsonify({"result":"failed","message":"No valid license found"})
				

				lic_count = len(current_engines)
				if int(max_engine) <= lic_count:
					return jsonify({"result":"failed","message":"Engine license limit reached,Allowed license count:"+str(lic_count)})

				if licence_end < datetime.datetime.utcnow():
					return jsonify({"result":"failed","message":"Account license expired"})

				collection_name = user_id+"_"+engine_name
				create_status = os.popen(SOLR_CLOUD_BIN+"solr create_core -c "+collection_name+" -d template_1").read()
				
				if create_status.find("Created new core") != -1:
					# Core Creation success
					results = mcollection.update_one({"_id":user_id,"Engines.EngineName":{"$ne":engine_name}},{"$push":{"Engines":new_engine}})
				else:
					return jsonify({"result":"failed","message":"Engine already exist","engine_name":engine_name})
				
				if results.modified_count == 1:
					# Create Solar collection with "name_engine_name" as collection name
					
					return jsonify({"result":"success","message":"Engine created","engine_name":engine_name})
				else:
					return jsonify({"result":"failed","message":"Engine already exist","engine_name":engine_name})
			except Exception:
				logger.exception("create_engine")
				return jsonify({"result":"failed","message":"Domain creation failed"})

	except Exception:
		logger.exception("create_engine")
		return jsonify({"result":"failed","message":"Domain creation failed"})


@app.route('/portal/domain_update',methods = ['PUT'])
def domain_update():
	try:
		if request.method == 'PUT':
			result = request.form

			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################

			user_id = user_data.get("_id")
			domain_name = result.get("domain_name")
			engine_name = result.get("engine_name")
			domain_update = result.get("domain_update")

			domain_update = json.loads(domain_update)
			form_schema = dict()
			form_schema.update({'domain_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'engine_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'domain_update': {'required': True,'type': 'string'}})
			
			form_validate = cerberus.Validator()
			form_valid = form_validate.validate(result, form_schema)
			if form_valid == False:
				# Form not valid
				error_status = {"results":"failed"}
				error_status.update(form_validate.errors)
				return jsonify(error_status)


			find_value = mcollection.find_one({"_id":user_id,"Engines":{"$elemMatch":{"Domains.DomainName":{"$eq":domain_name},
				"EngineName":engine_name}}},{"_id":0,"Engines.Domains.$":1})
			
			if find_value != None:
				find_value = find_value.get("Engines")[0]
				single_domain = find_value.get("Domains")[0]
				single_domain.update(domain_update)
				
				results = mcollection.update_one({"_id":user_id,"Engines":{"$elemMatch":{"Domains.DomainName":{"$eq":domain_name},
					"EngineName":engine_name}}},{"$set":{"Engines.$.Domains.0":single_domain}})
				
				if results.modified_count == 1:
					return jsonify({"result":"success","message":"Update Success"})
				else:
					return jsonify({"result":"failed","message":"Not Updated."})
			else:
				return jsonify({"result":"failed","message":"Domain not found"})
	except Exception:
		logger.exception("domain_update")
		return jsonify({"result":"failed","message":"Not Updated"})

@app.route('/portal/domain_delete',methods = ['DELETE'])
def domain_delete():
	try:
		# Delete provided domain for user
		if request.method == 'DELETE':
			result = request.form

			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################

			user_id = user_data.get("_id")
			domain_name = result.get("domain_name")
			engine_name = result.get("engine_name")
			print({"_id":user_id,"Engines.EngineName":engine_name})
			print({ "$pull": { 'Engines.$.Domains': { "DomainName" : domain_name } } })
			deleted_status = mcollection.update_one({"_id":user_id,"Engines.EngineName":engine_name},
				{ "$pull": { 'Engines.$.Domains': { "DomainName" : domain_name } } })
			if deleted_status.modified_count == 1:
				return jsonify({"result":"success","message":"domain deleted"})
			else:
				return jsonify({"result":"failed","message":"domain not deleted"})

	except Exception:
		logger.exception("domain_delete")
		return jsonify({"result":"failed","message":"unknown fail"})

@app.route('/portal/engine_delete',methods = ['DELETE'])
def engine_delete():
	try:
		# Delete provided engine for user
		if request.method == 'DELETE':
			result = request.form

			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################

			user_id = user_data.get("_id")
			engine_name = result.get("engine_name")

			deleted_status = mcollection.update_one({"_id":user_id},{ "$pull": { 'Engines': { "EngineName" : engine_name } } })
			
			if deleted_status.modified_count == 1:
				# Deleting core
				collection_name = user_id+"_"+engine_name
				create_status = os.popen(SOLR_CLOUD_BIN+"solr delete -c "+collection_name).read()
				
				return jsonify({"result":"success","message":"engine deleted"})
			else:
				return jsonify({"result":"failed","message":"engine not deleted"})

	except Exception:
		logger.exception("engine_delete")
		return jsonify({"result":"failed","message":"unknown fail"})

@app.route('/portal/get_domain_data',methods = ['GET'])
def get_domain_data():
	try:
		# Get domain data from DB
		# Get summary of all domains or full details for particular domain
		if request.method == 'GET':
			result = request.form
			result = request.args.to_dict()

			############## SESSION VALIDATION START ##################
			session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################
			user_id = user_data.get("_id")
			domain_name = result.get("domain_name")
			engine_name = result.get("engine_name")
			if domain_name == None:
				return jsonify({"result":"failed","message":"Please specify domain name or use 'all' to get summary"})
			else:
				
				required_fields = dict()
				required_fields.update({"_id":0})
				required_fields.update({"Engines.Domains.Pages":1})
				required_fields.update({"Engines.Domains.DomainName":1})
				required_fields.update({"Engines.Domains.LastCrawl":1})
				required_fields.update({"Engines.Domains.CurrentStatus":1})
				required_fields.update({"Engines.Domains.CreatedAt":1})
				required_fields.update({"Engines.Domains.CreatedBy":1})
				required_fields.update({"Engines.Domains.CrawlSchedule":1})
				
				if domain_name == "all":
					domain_info = mcollection.find({"_id":user_id},required_fields)
				else:
					domain_info = mcollection.find({"_id":user_id,"Engines":{"$elemMatch":{"Domains.DomainName":{"$eq":domain_name},
					"EngineName":engine_name}}},{"Engines.Domains":1})
				
				if domain_info.count() > 0:
					return jsonify({"result":"success","data":list(domain_info)[0]})
				else:
					return jsonify({"result":"success","data":{}})

	except Exception:
		logger.exception("get_domain_data")
		return jsonify({"result":"failed","message":"unknown fail"})

@app.route('/portal/get_user_info',methods = ['GET'])
def get_user_info():
	try:
		# Get user information from Database
		if request.method == 'GET':
			############## SESSION VALIDATION START ##################
			#session_id = result.get("session_id")
			session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################
			user_id = user_data.get("_id")
			required_fields = dict()
			required_fields.update({"FirstName":1})
			required_fields.update({"LastName":1})
			required_fields.update({"Email":1})
			required_fields.update({"LicenceEnd":1})
			required_fields.update({"LicenceStart":1})
			required_fields.update({"AccountCreatedDate":1})
			required_fields.update({"AccountStatus":1})
			required_fields.update({"MaximumDomains":1})
			required_fields.update({"MaximumEngines":1})
			required_fields.update({"MaximumDomainsInEngine":1})
			required_fields.update({"Engines":1})

			user_data = mcollection.find_one({"_id":user_id},required_fields)
			
			if user_data == None:
				return jsonify({"result":"failed","message":"User Information not found"})
			else:
				return jsonify({"result":"success","data":user_data})

	except Exception:
		logger.exception("get_user_info")
		return jsonify({"result":"failed","message":"unknown fail"})


@app.route('/portal/start_crawl',methods = ['POST'])
def start_crawler():
	try:
		# Get user information from Database
		if request.method == 'POST':
			############## SESSION VALIDATION START ##################
			#session_id = result.get("session_id")
			session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################
			
			user_id = user_data.get("_id")
			account_type = user_data.get("AccountType")
			result = request.form
			
			form_schema = dict()
			form_schema.update({'domain_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'engine_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'custom_settings': {'required': True,'type': 'string'}})

			form_validate = cerberus.Validator()
			form_valid = form_validate.validate(result, form_schema)
			
			if form_valid == False:
				# Form not valid
				error_status = {"results":"failed"}
				error_status.update(form_validate.errors)
				return jsonify(error_status)
			
			
			custom_settings = result.get("custom_settings")
			engine_name = result.get("engine_name")
			domain_name = result.get("domain_name")
			crawl_info = dict()
			crawl_info.update({"engine_name":engine_name,"domain_name":domain_name,"custom_settings":custom_settings})
			crawl_info.update({"status":"not started"})
			crawl_info.update({"triggered_by":user_id})
			crawl_info.update({"triggered_at":datetime.datetime.utcnow()})
			crawl_info.update({"user_id":user_id})
			
			if account_type =="admin":
				crawl_info.update({"triggered_by":user_id})
				# If account type is admin the use user_id
				user_id = result.get("user_id")
			# Check if user having valid Engine name and domain name
			result_data = mcollection.find_one({"_id":user_id,"Engines.EngineName":engine_name,"Engines.Domains.DomainName":domain_name})
			if result_data == None:
				return jsonify({"result":"failed","message":"Invalid Engine or domain name provided"})
			
			
			crawl_name = "crawl_task|"+engine_name+"|"+domain_name
			
			if red.exists(crawl_name) == 0:
				# Check if crawl is already running are intilized
				red.hmset(crawl_name,crawl_info)
				#red.expire(crawl_name,600)
				return jsonify({"result":"success","message":"starting crawler"})	
			else:
				return jsonify({"result":"failed","message":"crawler busy"})

	except Exception:
		logger.exception("start_crawler")
		return jsonify({"result":"failed","message":"unknown fail"})


@app.route('/portal/user_update',methods = ['PUT'])
def portal_user_info_update():
	# Update portal user informations ( ex:password,email)
	try:
		if request.method == 'PUT':
			result = request.form
			user_email = result.get("user_email")
			user_password = result.get("user_password")
			
			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################
			
			user_id = user_data.get("_id")
			if user_email == None:
				return jsonify({"result":"failed","message":"Please enter Valid Email ID"})
			

			if user_password != None:
				if len(user_password) > 8:
					pass_hash = hashlib.sha1(user_password.encode()).hexdigest()
					user_update = {"Email":user_email,"PasswordHash":pass_hash}
					results = mcollection.update_one({"_id":user_id},{"$set":user_update})
					if results.modified_count == 1:
						return jsonify({"result":"success","message":"Update success"})
					else:
						return jsonify({"result":"failed","message":"Update failed"})
			else:
				return jsonify({"result":"failed","message":"Password Must be grater than 8 charecter"})

	except Exception:
		logger.exception("portal_user_info_update")
		return jsonify({"result":"failed","message":"Update failed"})

@app.route('/portal/create_new_user',methods = ['POST', 'GET'])
def create_new_user():
	try:
		if request.method == 'POST':
			result = request.form

			############## SESSION VALIDATION START ##################
			session_id = result.get("session_id")
			if session_id == None:
				# Getting session_id from cookie
				session_id = request.cookies.get('session_id')
			if session_id != None:
				# Validate the user with session
				user_data = check_user_session(session_id)
				if user_data == None:
					return jsonify({"result":"failed","message":"Please login again"})
			else:
				return jsonify({"result":"failed","message":"Please login again"})

			############## SESSION VALIDATION END #####################
			
			account_type = user_data.get("AccountType")

			if account_type != 'admin':
				return jsonify({"result":"failed","message":"Admin privilage required to create new user"})

			first_name = result.get("first_name")
			last_name = result.get("last_name")
			user_id = result.get("user_id")
			user_email = result.get("user_email")
			user_password = result.get("user_password")
			maximum_domains = int(result.get("maximum_domains"))
			maximum_engines = int(result.get("maximum_engines"))
			maximum_domains_in_engine = int(result.get("maximum_domains_in_engine"))
			account_type = result.get("account_type")
			max_lic_days = int(result.get("max_lic_days"))
			user_ip = result.get("user_ip")

			form_schema = dict()
			form_schema.update({'first_name': {'required': True,'type': 'string','maxlength': 64,'minlength': 1}})
			form_schema.update({'last_name': {'required': True,'type': 'string','maxlength': 64,'minlength': 1}})
			form_schema.update({'user_id': {'required': True,'type': 'string','maxlength': 64,'minlength': 1}})
			form_schema.update({'user_email': {'required': True,'type': 'string','maxlength': 64,'minlength': 6}})
			form_schema.update({'user_password': {'required': True,'type': 'string','maxlength': 64,'minlength': 8}})
			form_schema.update({'maximum_domains': {'required': True}})
			form_schema.update({'maximum_engines': {'required': True}})
			form_schema.update({'maximum_domains_in_engine': {'required': True}})
			form_schema.update({'account_type': {'required': True,'type': 'string','maxlength': 60,'minlength': 1}})
			form_schema.update({'max_lic_days': {'required': True}})
			form_schema.update({'user_ip': {'required': True,'type': 'string','maxlength': 200,'minlength': 7}})



			form_validate = cerberus.Validator()
			form_valid = form_validate.validate(result, form_schema)
			if form_valid == False:
				# Form not valid
				error_status = {"results":"failed"}
				error_status.update(form_validate.errors)
				return jsonify(error_status)

			account_cdate = datetime.datetime.utcnow()
			current_date = account_cdate

			lic_end = account_cdate + datetime.timedelta(days=max_lic_days)
			pass_hash = hashlib.sha1(user_password.encode()).hexdigest()

			# Creating New user
			new_user = dict()
			new_user.update({"FirstName":first_name})
			new_user.update({"LastName":last_name})
			new_user.update({"_id":user_id})
			new_user.update({"Email":user_email})
			new_user.update({"PasswordHash":pass_hash})
			new_user.update({"AccountStatus":"Active"})
			new_user.update({"AccountCreatedDate":account_cdate})
			new_user.update({"AccountCreatedIP":user_ip})
			new_user.update({"MaximumDomains":maximum_domains})
			new_user.update({"MaximumEngines":1})
			new_user.update({"MaximumDomainsInEngine":1})
			new_user.update({"AccountType":account_type}) #user = paid users , demo = demo user
			new_user.update({"LicenceStart":current_date})
			new_user.update({"LicenceEnd":lic_end})
			new_user.update({"Engines":[]})

			try:
				result = mcollection.insert(new_user)
				if result == user_id:
					return jsonify({"result":"success","message":"User created"})
				else:
					jsonify({"result":"failed","message":"User already exist"})
			except pymongo.errors.DuplicateKeyError:
				return jsonify({"result":"failed","message":"User already exist"})

	except Exception:
		logger.exception("create_new_user")
		return jsonify({"result":"failed","message":"create_new_user failed"})

# if __name__ == '__main__':
# 	app.run()
if __name__ == '__main__':
	app.run(host="0.0.0.0", port=int("80"), debug=True)
