from flask import Flask, render_template, request , send_file
from flask import jsonify
from flask_cors import CORS

import os
import time
import json
from flask_pymongo import PyMongo
import logging
from logging.handlers import RotatingFileHandler

import requests
import urllib.parse

logger =  logging.getLogger("Rotating Log websnap")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.getcwd()+"/web_server.log",maxBytes=5000000,backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
#logger.propagate = False # DISABLE LOG STDOUT

logger.info("Starting Webserver")

app = Flask(__name__,static_url_path='/static')
CORS(app)
app.config['MONGO_DBNAME'] = 'LIVE'
app.config['MONGO_URI'] = 'mongodb://127.0.0.1:27017/LIVE'

@app.route('/')
def main():
	 return "API call only......."


@app.route('/search',methods = ['POST', 'GET'])
def search_query():
	if request.method == 'GET':
		try:
			get_req = request.args.to_dict()
			domain = get_req.get("domain")
			fl = get_req.get("fl")
			q = get_req.get("q")
			application = get_req.get("application")
			rows = get_req.get("rows")
			start = get_req.get("start")
			solr_url = "http://127.0.0.1:8983/solr/"+domain+"/select?"
			if domain != None:
				enc_url = {"fl":fl,"q":q,"rows":rows,"start":start}
				if application != None:
					enc_url.update({"q":"+f_type:"+application+" +"+q})
				enc_url = urllib.parse.urlencode(enc_url)
				solr_url = solr_url+enc_url
				solr_res = requests.get(solr_url)
				if solr_res.status_code == 200:
					if solr_res.headers['content-type'].split(";")[0] == "application/json":
						solr_res = solr_res.json()
						solr_res.update({"result":"success"})
						return jsonify(solr_res)

			return jsonify({"result":"failed"})
		except Exception:
			logger.exception("search_query")
			return jsonify({"result":"failed"})

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
				enc_url = urllib.parse.urlencode(solr_url)
				solr_url = solr_url + domain + "/spell?"+enc_url
				solr_res = requests.get(solr_url)
				print(solr_res.status_code)
				if solr_res.status_code == 200:
					print(solr_res.headers['content-type'])
					if solr_res.headers['content-type'].split(";")[0] == "application/json":
						solr_res = solr_res.json()
						solr_res.update({"result":"success"})
						return jsonify(solr_res)

			return jsonify({"result":"failed"})
		except Exception:
			logger.exception("suggest")
			return jsonify({"result":"failed"})



if __name__ == '__main__':
	app.run(host="0.0.0.0", port=int("80"), debug=True)