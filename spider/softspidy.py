import asyncio
import queue
import pymongo
import random
import aiohttp
from bs4 import BeautifulSoup
import urllib.parse
from urlmatch import urlmatch
import logging
from logging.handlers import RotatingFileHandler
import os
from mimetypes import guess_extension
import requests


logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(os.getcwd()+"/Engine.log", maxBytes=5000000, backupCount=25)
formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
#logger.propagate = False # DISABLE LOG STDOUT

logger.info("Starting MonitoringEngine")

URL_Q = queue.Queue()
WORKERS = 50
TASKS = 0
STARTING_URL = "https://gic.delaware.gov/"
DB_COLLECTION = None
UNIQ_ENGINE = "gic.delaware.gov"
FRESH = True
MATCHED_DOMAIN = ["*://gic.delaware.gov/*"]
SCRAP_PROGRESS = True


def startup_function():
	try:
		global FRESH
		global DB_COLLECTION
		mongoc = pymongo.MongoClient('/tmp/mongodb-27017.sock')
		mdb = mongoc['LIVE']
		
		if FRESH == True:
			# Drop the collections
			status = mdb.drop_collection(UNIQ_ENGINE)
			logger.info("Dropping collection"+str(UNIQ_ENGINE)+str(status))
			DB_COLLECTION = mdb[UNIQ_ENGINE]
			DB_COLLECTION.insert({"url":STARTING_URL,"status":"pending"})
			return DB_COLLECTION
		else:
			DB_COLLECTION = mdb[UNIQ_ENGINE]
			return DB_COLLECTION
	except Exception:
		logger.exception("startup_function")

async def data_clasifier(resp,old_url):
	# collect all the url from response and add it to db
	global DB_COLLECTION
	global UNIQ_ENGINE
	new_urls = []
	try:
		content_typ = resp.headers.get('content-type')
		application_type = guess_extension(content_typ.split(";")[0])
		if resp.status == 200:
			logger.info(str(resp.status)+">"+str(content_typ)+">"+str(old_url)+">"+str(application_type))
		else:
			logger.warning(str(resp.status)+">"+str(content_typ)+">"+str(old_url)+">"+str(application_type))
			return "completed"
		
		solr_payload = await  resp.content.read()
		try:
			file_type = content_typ.split(";")[0]
			if str(file_type).find("html") !=-1 or str(file_type).find("pdf") != -1:
				print(">>:"+str(file_type))
				resp.headers.get('content-type')
				custom_header = {'Content-type': resp.headers.get('content-type') }
				solr_url = 'http://192.168.130.1:8983'+str("/solr/"+UNIQ_ENGINE+"/update/extract?literal.id=")+old_url+"&literal.f_type="+file_type
				solr_response = requests.post(solr_url, data=solr_payload,headers=custom_header)

			else:
				print("unknow file:"+str(file_type))
		except Exception:
			logger.exception("errorcode:solar")
			return "errorcode:solar"

		# Extract URL if received file is html
		if application_type == ".htm":

			html_data = solr_payload
			beauty_data = BeautifulSoup(html_data,"html.parser")
			all_href = beauty_data.find_all('a',href=True)
			for href in all_href:
				href = href['href']
				#print (href)
				extraced_url = urllib.parse.urljoin(str(resp.url),href)
				for domain_patten in MATCHED_DOMAIN:
					if urlmatch(domain_patten,extraced_url) == True:
						new_urls.append(extraced_url)
						#logger.info(extraced_url)

		
		new_urls = list(set(new_urls))
		for url in new_urls:
			dup_url = DB_COLLECTION.find_one({"url":url})
			if dup_url == None:
				DB_COLLECTION.insert({"url":url,"status":"pending"})

	except Exception:
		logger.exception("errorcode:unknown")
		return "errorcode:unknown"

	return "completed"

async def url_scrap(url):
	global TASKS
	global DB_COLLECTION
	job_status = "errorcode:url_scrap"
	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(url) as resp:
				#logger.info(url+" >"+str(resp.status))
				job_status = await data_clasifier(resp,url)
	except Exception:
		job_status = "errorcode:scrap_timeout"
		logger.exception("url_scrap")
	finally:
		TASKS = TASKS - 1
	try:
		DB_COLLECTION.update({"url":str(url)},{"$set":{"status":job_status}})
	except Exception:
		logger.exception("url_scrap")

async def start_task(loop):
	while SCRAP_PROGRESS == True:
		await asyncio.sleep(0.01)
		try:
			try:
				url = URL_Q.get_nowait()
				#logger.info(url)
			except:
				url = None
			if url != None:
				loop.create_task(url_scrap(url))
		except Exception:
			logger.exception("start_task")


async def main_flow(loop):
	# Get url's from MongoDB
	global TASKS
	global WORKERS
	global STARTING_URL
	global DB_COLLECTION
	global SCRAP_PROGRESS
	print("==> Scrapping started")
	while SCRAP_PROGRESS == True:
		try:
			await asyncio.sleep(0.2)
			#print ("Main Loop...")
			free_worker = WORKERS - TASKS
			if free_worker > 0:
				# Add tasks to worker queue
				pending = DB_COLLECTION.find_and_modify({"status":"pending"},{"$set":{"status":"running"}})
				#logger.info("Free workers >"+str(free_worker))
				if pending != None:
					url = pending.get("url")
					if url == None:
						logger.error("Error: table not having url field")
					else:
						URL_Q.put_nowait(url)
						TASKS = TASKS + 1
				else:
					logger.info("No pending url")
					running_status = DB_COLLECTION.find_one({"status":"running"})
					if running_status == None:
						logger.info("============== Scrapped Success =============")
						print("==> Scrapped completed")
						SCRAP_PROGRESS = False
						
			else:
				pass;
				#logger.info("Free workers >"+str(free_worker))

		except Exception:
			logger.exception("main_flow")

startup_function()
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

tasks = [  
    asyncio.ensure_future(main_flow(loop)),
    asyncio.ensure_future(start_task(loop)),
]

loop.run_until_complete(asyncio.wait(tasks))
loop.close()