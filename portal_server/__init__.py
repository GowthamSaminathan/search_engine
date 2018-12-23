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
import binascii
import ast


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
#app.config['MONGO_DBNAME'] = 'accounts'
#app.config['MONGO_URI'] = 'mongodb://127.0.0.1:27017/'

mongoc = PyMongo(app,uri='mongodb://127.0.0.1:27017/accounts')
mdb = mongoc.db
mcollection = mdb['users']

mongoc2 = PyMongo(app,uri='mongodb://127.0.0.1:27017/Search_history')
mdb2 = mongoc2.db
#search_collection = mdb2['users']

red = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)


SOLR_ADMIN_URL = "http://127.0.0.1:8983/solr/admin/"


@app.route('/')
def main():
	 return "API call only......."

@app.route('/search',methods = ['POST', 'GET'])
def search_query():
	if request.method == 'GET':
		try:
			user_query_dic = request.args.to_dict()
			key = user_query_dic.get("key")
			query_str = user_query_dic.get("q")
			url_ip = user_query_dic.get("url_ip")


			if key == None:
				return jsonify({"result":"error","message":"key not specified"})

			settings = red.hgetall(key)
			if settings != None and settings != {}:
				engine_name = settings.get("engine_name")
				domain_name = settings.get("domain_name")
				user_id = settings.get("user_id")
				weight = ast.literal_eval(settings.get("weight"))
				synonums = ast.literal_eval(settings.get("synonums"))
				custom_results = ast.literal_eval(settings.get("custom_results"))
				c_name = user_id+"_"+engine_name
			else:
				return jsonify({"result":"error","message":"invalid user"})
			
			query_fields = []
			boost_field = []
			for w in weight:
				field = w.get("field")
				field_weight = w.get("weight")
				query_fields.append("qf="+field)
				boost_field.append(field+"^"+str(field_weight))
			
			qf = "&".join(query_fields)
			bf = ",".join(boost_field)
			bf = "bq="+bf



			# Insert the search query to DB
			try:
				search_col = mdb2[user_id]
				tim = datetime.datetime.utcnow()
				search_col.insert({"EngineName":engine_name,"DomainName":domain_name,"query":str(query_str),
					"url_ip":str(url_ip),"source_ip":request.remote_addr,"time":tim})
			except Exception:
				logger.exception("inserting search history to DB failed:")
				

			user_default_setting = "&fl=title,url,id"+"&"+qf+"&"+bf+"&defType=dismax"
			user_query = request.query_string.decode("utf-8")
			query = user_query + user_default_setting
			
			# Removeing user key in request
			query = query.replace("&key="+key,"")

			solr_url = "http://127.0.0.1:8983/solr/"+c_name+"/select?"+query
			solr_res = requests.get(solr_url)
			
			if solr_res.status_code == 200:
				solr_res = solr_res.json()
				# Removing response header
				solr_res.pop("responseHeader")
				solr_res.update({"result":"success"})
				return jsonify(solr_res)
			else:
				logger.exception("solr select error for request:"+solr_url)

			return jsonify({"results":"error","message":"query failed"})
		except Exception:
			logger.exception("search_query")
			return jsonify({"results":"error","message":"query failed"})

@app.route('/search_history',methods = ['POST', 'GET'])
def search_history():
	try:
		if request.method == 'GET':
			user_query_dic = request.args.to_dict()
			key = user_query_dic.get("key")
			from_time = user_query_dic.get("from_time")
			to_time = user_query_dic.get("to_time")
			qtype = user_query_dic.get("qtype")
			limit = user_query_dic.get("limit")
			query = dict()

			if key == None:
				return jsonify({"result":"error","message":"key not specified"})

			settings = red.hgetall(key)
			
			if settings != None:
				
				engine_name = settings.get("engine_name")
				domain_name = settings.get("domain_name")
				key_type = settings.get("type")
				user_id = settings.get("user_id")
				c_name = user_id+"_"+engine_name
				#query = {"time":{$gte:from_time,$lte:from_time}}
				
				if key_type == "engine_write":
					query.update({"EngineName":engine_name})
				elif key_type == "domain_write":
					query.update({"EngineName":engine_name,"DomainName":domain_name})
				else:
					return jsonify({"result":"error","message":"write key required"})
				
				search_col = mdb2[user_id]
				if qtype == "top_searches":
					if limit == None:
						limit = 10
					else:
						limit = int(limit)
					
					data = search_col.aggregate([{"$match":query},{"$group":{"_id":"$query",
						"count":{"$sum" :1}}},{"$sort":{"count":-1}},{"$limit":limit}])
					
					data = list(data)
					if len(data) > 0:
						return jsonify({"result":"success","data":data})
					else:
						return jsonify({"result":"success","data":[]})
				else:
					return jsonify({"result":"error","message":"not a valid option"})

			else:
				return jsonify({"result":"error","message":"invalid user"})
	except Exception as e:
			#print(e)
			return jsonify({"results":"error","message":"failed"})

@app.route('/search_old',methods = ['POST', 'GET'])
def search_query_old():
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

@app.route('/correct_me',methods = ['GET'])
def correct_me():
	if request.method == 'GET':
		try:
			user_query_dic = request.args.to_dict()
			key = user_query_dic.get("key")
			query_str = user_query_dic.get("q")
			#url_ip = user_query_dic.get("url_ip")

			query_type = user_query_dic.get("type")
			
			if key == None:
				return jsonify({"result":"error","message":"key not specified"})
			elif query_type == None:
				return jsonify({"result":"error","message":"type not specified"})
			
			settings = red.hgetall(key)
			if settings != None and settings != {}:
				engine_name = settings.get("engine_name")
				domain_name = settings.get("domain_name")
				user_id = settings.get("user_id")
				c_name = user_id+"_"+engine_name
			else:
				return jsonify({"result":"error","message":"invalid user"})
			
			# Removeing user key and type in request
			query = request.query_string.decode("utf-8")
			query = query.replace("&key="+key,"")
			query = query.replace("&type="+query_type,"")
			
			if query_type == "spell":
				#query = query.replace("correct_me?q=","spell?q=")
				solr_url = "http://127.0.0.1:8983/solr/"+c_name+"/spell?"+query
			elif query_type == "suggest":
				solr_url = "http://127.0.0.1:8983/solr/"+c_name+"/suggest?"+query

			else:
				jsonify({"result":"error","message":"type not specified"})
			
			
			solr_res = requests.get(solr_url)
			
			if solr_res.status_code == 200:
				solr_res = solr_res.json()
				# Removing response header
				solr_res.pop("responseHeader")
				solr_res.update({"result":"success"})
				return jsonify(solr_res)
			else:
				logger.exception("solr select error for request:"+solr_url)

			return jsonify({"results":"error","message":"query failed"})
		except Exception:
			logger.exception("correct_me")
			return jsonify({"results":"error","message":"query failed"})

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

@app.route('/portal/create_domain',methods = ['POST'])
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


			white_url = [urllib.parse.urljoin(domain_name,"/*")]
			black_url = []
			white_app = ["text/html"]
			black_app = ["application/exe"]
			crawl_schedule = {"week":["Su","Mo","Tu","We","Th","Fr","Sa"],"day":[],"time":"00 AM"}
			manual_url = []
			adv_settings = {"Allow Robot.txt":"yes","ParallelCrawler":10}
			adv_settings.update({"Use Sitemaps":"yes"})
			adv_settings.update({"Use Only Sitemaps":"no"})
			html_tags = ["p","h[1-6]","b","i","u","tt","strong","blockquote","small","tr","th","td","dd","title"]
			weight = [{"field":"title","weight":1},{"field":"body","weight":2},{"field":"url","weight":3}]
			synonums = []
			custom_results = []

			new_domain = dict()
			new_domain.update({"user_id":user_id})
			new_domain.update({"DomainName":domain_name})
			new_domain.update({"EngineName":engine_name})
			new_domain.update({"type":"domain"})
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
			new_domain.update({"HtmlTags":html_tags})
			new_domain.update({"creater_ip":str(request.remote_addr)})

			try:
				engine_collection = mdb['Engines']
				check_engine = engine_collection.find_one({"user_id":user_id,"EngineName":engine_name,"type":"engine"})
				
				if check_engine != None:

					results = engine_collection.update_one({"user_id":user_id,"EngineName":engine_name,"type":"domain",
						"DomainName":domain_name},{"$setOnInsert":new_domain},upsert=True)
					
					if results.upserted_id != None:
						return jsonify({"result":"success","message":"Domain added"})
					else:
						return jsonify({"result":"failed","message":"Domain already exist"})
				else:
					return jsonify({"result":"failed","message":"engine not found"})
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
				user_details = mcollection.find_one({"_id":user_id},{"_id":1,"MaximumEngines":1,"LicenceEnd":1})
				
				if user_details != None:
					max_engine = user_details.get("MaximumEngines")
					licence_end = user_details.get("LicenceEnd")
				else:
					#logger.errot("BUG: MaximumEngines not found in DB for: "+user_id)
					return jsonify({"result":"failed","message":"No valid license found"})
				
				engine_collection = mdb['Engines']
				current_engines = engine_collection.distinct("EngineName",{"user_id":user_id,"type":"engine"})
				current_engines = len(current_engines)

				if int(max_engine) <= current_engines:
					return jsonify({"result":"failed","message":"Engine license limit reached,Allowed license count:"+str(current_engines)})

				if licence_end < datetime.datetime.utcnow():
					return jsonify({"result":"failed","message":"Account license expired"})

				c_name = user_id+"_"+engine_name
				create_status = False
				url = SOLR_ADMIN_URL+"cores?action=CREATE&name="+c_name+"&instanceDir="+c_name+"&dataDir=data&configSet=template_ok"
				
				try:
					# Create core using admin API
					res = requests.get(url)
					if res.status_code == 200:
						data = res.json()
						if data.get("responseHeader").get("status") == 0:
							create_status = True
						else:
							return jsonify({"result":"failed","message":"Engine already exist","engine_name":engine_name})
					else:
						return jsonify({"result":"failed","message":"Engine already exist","engine_name":engine_name})
				except Exception:
					logger.exception("solr admin api failed")
					return jsonify({"result":"failed","message":"Creating engine failed","engine_name":engine_name})
				
				if create_status == True:
					# Core Creation success
					check_engine = engine_collection.find_one({"user_id":user_id,"EngineName":engine_name,"type":"engine"})
					
					if check_engine == None:
						# Engine not exist , creating new engine
						results = engine_collection.update_one({"user_id":user_id,"EngineName":engine_name,"type":"engine"},
							{"$setOnInsert":{"user_id":user_id,"EngineName":engine_name,"type":"engine",
							"CreatedAt":datetime.datetime.utcnow(),"creater_ip":str(request.remote_addr)}},upsert=True)
						
						if results.upserted_id != None:
							# Create Solar collection with "name_engine_name" as collection name
							return jsonify({"result":"success","message":"Engine created","engine_name":engine_name})
						else:
							return jsonify({"result":"failed","message":"Engine already exist","engine_name":engine_name})
					
					else:
						return jsonify({"result":"failed","message":"Engine already exist (in account)","engine_name":engine_name})
				

				else:
					return jsonify({"result":"failed","message":"Engine already exist (in index)","engine_name":engine_name})
				
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
			req_action = result.get("action")
			req_element = result.get("element")
			req_value = result.get("value")

			#domain_update = json.loads(domain_update)
			allowed_elements = ["AdvancedSettings"]
			allowed_elements.append("BlackListApp")
			allowed_elements.append("BlackListUrls")
			allowed_elements.append("CrawlSchedule")
			allowed_elements.append("CustomResults")
			allowed_elements.append("HtmlTags")
			allowed_elements.append("ManualUrls")
			allowed_elements.append("Synonums")
			allowed_elements.append("Weight")
			allowed_elements.append("WhiteListApp")
			allowed_elements.append("WhiteListUrls")


			form_schema = dict()
			form_schema.update({'domain_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'engine_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'action': {'required': True,'type': 'string','allowed':['add','delete','update']}})
			form_schema.update({'element': {'required': True,'type': 'string','allowed':allowed_elements}})
			form_schema.update({'value': {'required': True}})
			
			form_validate = cerberus.Validator()
			form_valid = form_validate.validate(result, form_schema)
			if form_valid == False:
				# Form not valid
				error_status = {"results":"failed"}
				error_status.update(form_validate.errors)
				return jsonify(error_status)

			req_validate = dict()
			
			query_sntx = None

			if req_element == "AdvancedSettings":
				req_validate.update({'ParallelCrawler': {'required': True,'type': 'number','anyof':[{'min': 1, 'max': 25}]}})
				req_validate.update({'Allow Robot.txt': {'required': True,'type': 'string','allowed':["yes","no"]}})
				req_validate.update({'Use Sitemaps': {'required': True,'type': 'string','allowed':["yes","no"]}})
				req_validate.update({'Use Only Sitemaps': {'required': True,'type': 'string','allowed':["yes","no"]}})

				req_data_validate = cerberus.Validator()
				form_valid = req_data_validate.validate(req_value, req_validate)
				if form_valid == False:
					# Form not valid
					error_status = {"results":"failed"}
					error_status.update(req_validate.errors)
					return jsonify(error_status)

				query_sntx = {"$set":{"AdvancedSettings": json.loads(req_value)}}

			elif req_element == "BlackListApp":
				query_sntx = {"$set":{"BlackListApp": json.loads(req_value)}}

			elif req_element == "BlackListUrls":
				query_sntx = {"$set":{"BlackListUrls": json.loads(req_value)}}

			elif req_element == "CrawlSchedule":
				query_sntx = {"$set":{"CrawlSchedule": json.loads(req_value)}}

			elif req_element == "CustomResults":
				query_sntx = {"$set":{"CustomResults": json.loads(req_value)}}

			elif req_element == "HtmlTags":
				query_sntx = {"$set":{"HtmlTags": json.loads(req_value)}}

			elif req_element == "ManualUrls":
				query_sntx = {"$set":{"ManualUrls": json.loads(req_value)}}

			elif req_element == "Synonums":
				query_sntx = {"$set":{"Synonums": json.loads(req_value)}}

			elif req_element == "Weight":
				query_sntx = {"$set":{"Weight": json.loads(req_value)}}

			elif req_element == "WhiteListApp":
				query_sntx = {"$set":{"WhiteListApp": json.loads(req_value)}}

			elif req_element == "WhiteListUrls":
				query_sntx = {"$set":{"WhiteListUrls": json.loads(req_value)}}


			# '''find_value = mcollection.find_one({"_id":user_id,"Engines":{"$elemMatch":{"Domains.DomainName":{"$eq":domain_name},
			# 	"EngineName":engine_name}}},{"_id":0,"Engines.Domains.$":1})
			
			# if find_value != None:
			# 	find_value = find_value.get("Engines")[0]
			# 	single_domain = find_value.get("Domains")[0]
			# 	single_domain.update(domain_update)'''
			
			# single_domain = mcollection.aggregate([{"$match":{"_id":user_id}},{"$unwind":"$Engines"},
			# 	{"$match":{"Engines.EngineName":engine_name}},
			# 	{"$replaceRoot":{"newRoot":"$Engines"}},
			# 	{"$unwind":"$Domains"},{"$match":{"Domains.DomainName":domain_name}},
			# 	{"$replaceRoot":{"newRoot":"$Domains"}},{"$addFields":domain_update}])
			
			if query_sntx != None:
				query_sntx.get("$set").update({"UpdatedAt":datetime.datetime.utcnow(),"last_updater_ip":str(request.remote_addr)})
				engine_collection = mdb['Engines']
				results = engine_collection.update_one({"user_id":user_id,"EngineName":engine_name,"DomainName":domain_name},query_sntx)
				if results.modified_count == 1:
					return jsonify({"result":"success","message":"Update Success"})
				else:
					return jsonify({"result":"failed","message":"Not Updated / Already updated one"})
			else:
				return jsonify({"result":"failed","message":"Not valid request"})
		else:
			return jsonify({"result":"failed","message":"request not allowed"})
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
			#print({"_id":user_id,"Engines.EngineName":engine_name})
			#print({ "$pull": { 'Engines.$.Domains': { "DomainName" : domain_name } } })
			deleted_status = mcollection.update_one({"_id":user_id,"Engines.EngineName":engine_name},
				{ "$pull": { 'Engines.$.Domains': { "DomainName" : domain_name } } })
			
			engine_collection = mdb['Engines']
			result = engine_collection.delete_many({"user_id":user_id,"EngineName":engine_name,"DomainName" : domain_name})

			if result.deleted_count > 0:
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

			try:
				# Delete core using admin API
				c_name = user_id+"_"+engine_name
				url = SOLR_ADMIN_URL+"cores?action=UNLOAD&core="+c_name+"&deleteIndex=true&deleteDataDir=true&deleteInstanceDir=true"
				res = requests.get(url)
				if res.status_code == 200:
					data = res.json()
					if data.get("responseHeader").get("status") == 0:
						pass;
					else:
						return jsonify({"result":"failed","message":"engine already deleted"})
				else:
					return jsonify({"result":"failed","message":"engine already deleted"})
			except Exception:
				logger.exception("solr admin api failed")
				return jsonify({"result":"failed","message":"engine not deleted"})

			engine_collection = mdb['Engines']
			result = engine_collection.delete_many({"user_id":user_id,"EngineName":engine_name})
			
			if result.deleted_count > 0:
				# Deleting core
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
			engine_collection = mdb['Engines']
			
			query = {"user_id":user_id,"type":"domain"}

			if engine_name != None:
				query.update({"EngineName":engine_name})
			
			if domain_name != None:
				query.update({"DomainName":domain_name})
			
			domain_info = engine_collection.find(query,{"_id":0})
			
			if domain_info.count() > 0:
				return jsonify({"result":"success","data":list(domain_info)})
			else:
				return jsonify({"result":"success","data":{}})

	except Exception:
		logger.exception("get_domain_data")
		return jsonify({"result":"failed","message":"unknown fail"})

@app.route('/portal/get_engine_data',methods = ['GET'])
def get_engine_data():
	try:
		# Get engine/domain data from DB
		if request.method == 'GET':
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
			engine_name = result.get("engine_name")
			engine_collection = mdb['Engines']
			
			query = {"user_id":user_id}

			if engine_name != None:
				query.update({"EngineName":engine_name})
			
			req_fld = {"DomainName":1}
			req_fld.update({"EngineName":1})
			req_fld.update({"type":1})
			req_fld.update({"user_id":1})
			req_fld.update({"CreatedAt":1})
			req_fld.update({"CreatedBy":1})
			req_fld.update({"CurrentStatus":1})
			req_fld.update({"creater_ip":1})
			req_fld.update({"last_updater_ip":1})
			req_fld.update({"UpdatedAt":1})
			req_fld.update({"_id":0})

			info = engine_collection.find(query,req_fld)
			
			if info.count() > 0:
				return jsonify({"result":"success","data":list(info)})
			else:
				return jsonify({"result":"failed","data":"Information not found , Please check provided input"})

	except Exception:
		logger.exception("get_engine_data")
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
			#required_fields.update({"Engines":1})

			user_data = mcollection.find_one({"_id":user_id},required_fields)
			
			if user_data == None:
				return jsonify({"result":"failed","message":"User Information not found"})
			else:
				return jsonify({"result":"success","data":user_data})

	except Exception:
		logger.exception("get_user_info")
		return jsonify({"result":"failed","message":"unknown fail"})


@app.route('/portal/get_crawl_info',methods = ['GET'])
def get_crawl_history():
	try:
		# Get crawl information from Database
		if request.method == 'GET':
			############## SESSION VALIDATION START ##################
			#session_id = result.get("session_id")
			result = request.args.to_dict()
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
			skip = result.get("skip")
			current_status = result.get("current_status")

			form_schema = dict()
			form_schema.update({'domain_name': {'required': False,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'engine_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
			form_schema.update({'skip': {'required': False}})
			form_schema.update({'current_status': {'required': False}})

			form_validate = cerberus.Validator()
			form_valid = form_validate.validate(result, form_schema)

			if form_valid == False:
				# Form not valid
				error_status = {"results":"failed"}
				error_status.update(form_validate.errors)
				return jsonify(error_status)

			search_field =dict()

			
			if domain_name != None:
				search_field.update({"domain_name":domain_name})

			if skip == None:
				skip = 0
			else:
				skip = int(skip)

			if current_status != None:
				search_field.update({"current_status":current_status})
			
			crawl_history = PyMongo(app,uri='mongodb://127.0.0.1:27017/Crawl_DB')
			crawl_history_db = crawl_history.db
			crawl_history_col = crawl_history_db[user_id+"_"+engine_name+"_history"]


			user_data = crawl_history_col.find(search_field,{"_id":0}).sort('version',pymongo.DESCENDING).limit(20).skip(skip)
			data = list(user_data)

			if(len(data)) == 0:
				return jsonify({"result":"failed","message":"History Information not found"})
			else:
				#print(list(user_data)[0])
				return jsonify({"result":"success","data":data})

	except Exception:
		logger.exception("get_crawl_info")
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
			engine_collection = mdb['Engines']
			result_data = engine_collection.find_one({"user_id":user_id,"EngineName":engine_name,"DomainName":domain_name})
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

def update_key_to_redis_server(user_id=None,engine_name=None,domain_name=None):
	try:
		if user_id == None:
			users = {}
		else:
			users = {"user_id":user_id}
			if domain_name != None:
				# Update paticular domain key (need engine_name also)
				users.append({"EngineName":engine_name,"DomainName":domain_name})
			elif engine_name != None:
				# Update all the key in particular engine
				users.append({"EngineName":engine_name})

		
		engine_collection = mdb['Engines']
		db_results = engine_collection.find(users,{"engine_write_key":1,"EngineName":1,
				"engine_read_key":1,"DomainName":1,"domain_read_key":1,"domain_write_key":1,"Weight":1,"Synonums":1,
				"CustomResults":1,"user_id":1,"user_id":1,"type":1})
		
		all_keys = []
		for data in db_results:
			try:
				user_id = data.get("user_id")
				# Delete all previous keys
				# Get match key based on user
				key_append = user_id.encode("utf-8").hex()
				old_keys = red.keys(key_append+"*")
				for old in old_keys:
					red.delete(old)
				
				if data.get("type") == "engine":
					engine_name = data.get("EngineName")
					engine_r_key = data.get("engine_read_key")
					engine_w_key = data.get("engine_write_key")
					if engine_r_key != None:
						all_keys.append({engine_r_key:{"engine_name":engine_name,"type":"engine_read","user_id":user_id}})
					if engine_w_key != None:
						all_keys.append({engine_w_key:{"engine_name":engine_name,"type":"engine_write","user_id":user_id}})
				
				elif data.get("type") == "domain":
					domain_name = data.get("DomainName")
					engine_name = data.get("EngineName")
					weight = data.get("Weight")
					synonums = data.get("Synonums")
					custom_results = data.get("CustomResults")
					domain_w_key = data.get("domain_write_key")
					domain_r_key = data.get("domain_read_key")
					if domain_r_key != None:
						all_keys.append({domain_r_key:{"engine_name":engine_name,"weight":weight,"synonums":synonums,
							"domain_name":domain_name,"type":"domain_read","user_id":user_id,"custom_results":custom_results}})
					if domain_w_key != None:
						all_keys.append({domain_w_key:{"engine_name":engine_name,"weight":weight,"synonums":synonums,
							"domain_name":domain_name,"type":"domain_read","user_id":user_id,"custom_results":custom_results}})
				else:
					logger.error("BUG Found> Type not found in 'Engine' collection> "+str(data))
				for key in all_keys:
					key_value = list(key.keys())[0]
					key_data = key.get(key_value)
					red.hmset(key_value,key_data)

			except Exception:
				logger.exception("update key to redis server failed:")

	except Exception:
		logger.exception("update_key_to_redis_server")
		return jsonify({"result":"failed","message":"error updating key to redis server"})

@app.route('/portal/manage_api_key',methods = ['POST', 'GET'])
def manage_api_key():
	try:
		if request.method == 'GET' or request.method == 'POST':
			if request.method == 'GET':
				result = request.args.to_dict()
			else:
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
			engine_name = result.get("engine_name")
			domain_name = result.get("domain_name")
			
			user_id = user_data.get("_id")
			form_schema = dict()
			if request.method == 'GET':
				query = {"user_id":user_id}
				if domain_name != None:
					query.update({"DomainName":domain_name})
				if engine_name != None:
					query.update({"EngineName":engine_name})
				else:
					jsonify({"result":"failed","message":"engine name required"})

				
				engine_collection = mdb['Engines']
				db_results = engine_collection.find(query,{"engine_write_key":1,
					"engine_read_key":1,"_id":0,"type":1,"EngineName":1,"DomainName":1,"domain_read_key":1,"domain_write_key":1})
				
				return jsonify({"result":"success","data":list(db_results)})

			else:
				form_schema.update({'refresh': {'required': True,'type': 'string','allowed':
					['domain_read_key','domain_write_key','engine_read_key','engine_write_key']}})
				
				form_schema.update({'engine_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
				
				if result.get('refresh') == 'domain_read_key' or result.get('refresh') == "domain_write_key":
					form_schema.update({'domain_name': {'required': True,'type': 'string','maxlength': 512,'minlength': 1}})
				else:
					form_schema.update({'domain_name': {'required': False}})
				
				form_validate = cerberus.Validator()
				form_valid = form_validate.validate(result, form_schema)
				if form_valid == False:
					# Form not valid
					error_status = {"results":"failed"}
					error_status.update(form_validate.errors)
					return jsonify(error_status)
				
				rand_number = str(random.randint(100,999999) + time.time())
				rand_number = rand_number + user_id
				api_key = hashlib.sha1(rand_number.encode()).hexdigest()

				hex_usr = user_id.encode("utf-8").hex()
				api_key = hex_usr+api_key

				engine_collection = mdb['Engines']
				if result.get("refresh") == "engine_read_key" or result.get("refresh") == "engine_write_key":
					if result.get("refresh") == "engine_read_key":
						key_type = {"engine_read_key":api_key}
					else:
						key_type = {"engine_write_key":api_key}
					
					db_results = engine_collection.update_one({"user_id":user_id,"EngineName":engine_name,"type":"engine"},
						{'$set':key_type})
					
				elif result.get("refresh") == "domain_read_key" or result.get("refresh") == "domain_write_key":
					if result.get("refresh") == "domain_read_key":
						key_type = {"domain_read_key":api_key}
					else:
						key_type = {"domain_write_key":api_key}
					
					db_results = engine_collection.update_one({"user_id":user_id,"EngineName":engine_name,
						'DomainName':domain_name},{'$set':key_type})

				else:
					return jsonify({"result":"failed","message":"key referesh failed"})

				if db_results.modified_count == 1:
					update_key_to_redis_server(user_id)
					return jsonify({"result":"success","message":"key refresh success"})
				else:
					return jsonify({"result":"failed","message":"unable to refresh specified engine or domain key"})
	except Exception:
		logger.exception("manage_api_key")
		return jsonify({"result":"failed","message":"Referesh API key failed"})



# if __name__ == '__main__':
# 	app.run()
if __name__ == '__main__':
	app.run(host="0.0.0.0", port=int("80"), debug=True)
