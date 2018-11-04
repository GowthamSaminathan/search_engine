import os
import time
import json
import pymongo
import logging
from logging.handlers import RotatingFileHandler
from logging.handlers import SysLogHandler

import requests
import urllib.parse

import datetime
import redis
import random
import asyncio
import multiprocessing
import random
import aiohttp
from mimetypes import guess_extension
from bs4 import BeautifulSoup
from urlmatch import urlmatch
from support import *


sysl = SysLogHandler(address='/dev/log')
sysl.setFormatter(logging.Formatter('pser-engine: %(levelname)s > %(asctime)s > %(message)s'))

logger =  logging.getLogger("pser-engine")
logger.addHandler(sysl)
logger.setLevel(logging.DEBUG)

logger.warning("Restarted>Engine_Head")

class run_crawler():
	
	def __init__(self):
		# Initialize new logger to sup-process
		self.crawl_version = datetime.datetime.utcnow()
		self.sysl = SysLogHandler(address='/dev/log')
		self.sysl.setFormatter(logging.Formatter('pser-engine: <V>'+str(self.crawl_version)+'>%(levelname)s>%(asctime)s>%(message)s'))

		self.logger =  logging.getLogger(str(self.crawl_version))
		self.logger.addHandler(self.sysl)
		self.logger.setLevel(logging.DEBUG)

		self.logger.info("Logger initialized for new process")

	async def http_req(self,url,retry,timeout):
		try:
			headers = {"User-Agent":"superman"}
			for x in range(retry):
				conn = aiohttp.TCPConnector()
				timeout = aiohttp.ClientTimeout(sock_connect=500)
				
				async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
					async with session.get(url,headers=headers) as resp:
						# Read as Text
						payload = await resp.text()
						return {"payload":payload,"status":resp.status}
		except Exception:
			self.logger.exception(http_req)

	def count_application_types(self,application_type):
		try:
			# Count the application types
			if application_type != None:
				if self.app_types.get(str(application_type)) == None:
					self.app_types.update({str(application_type):1})
				else:
					a = self.app_types.get(str(application_type))
					self.app_types.update({str(application_type):a+1})
		except Exception:
			self.logger.exception("count_application_types")


	def count_http_code(self,resp_status):
		try:
			# Count the responce code
			if(type(resp_status) == int):
				if self.http_status_code.get(str(resp_status)) == None:
					self.http_status_code.update({str(resp_status):1})
				else:
					a = self.http_status_code.get(str(resp_status))
					self.http_status_code.update({str(resp_status):a+1})
		except Exception:
			self.logger.exception("count_http_code")

	def init_crawl(self,task_details):
		# Getting basic task_details from main process
		# Getting user default settings for the domain from 'users' collection in 'accounts' DB.
		# Creating new crawl version in 'Crawl_DB' with 'user_id' and 'enginename' as colection name (Ex:'user1_engine1_history')
		# Set 'running' as current_status in'Crawl_DB'
		# Create two new tasks
		# Remove task_details from redis DB after task completed 
		try:
			self.craw_fin = None
			self.task_details = task_details
			self.tasks = []
			self.crawl_info = dict()
			self.crawl_settings = dict()
			self.crawl_message = "Good"
			self.page_info = dict()
			
			ename = self.task_details.get("engine_name")
			dname = self.task_details.get("domain_name")

			self.logger.info("Creating mongodb connection")
			self.mdb_client = pymongo.MongoClient('localhost', 27017)
			self.mdb_db = self.mdb_client["accounts"]
			self.mdb_collect = self.mdb_db["users"]

			self.logger.info("Mongodb connection created")

			self.user_default_settings = self.mdb_collect.find_one({"_id":self.task_details.get("user_id"),
				"Engines":{"$elemMatch":{"Domains.DomainName":{"$eq":self.task_details.get("domain_name")},
				"EngineName":self.task_details.get("engine_name")}}},{"_id":0,"Engines.Domains.$":1})			
			

			if self.user_default_settings != None:
				self.logger.info("User default setting found")
				self.user_default_settings = self.user_default_settings.get("Engines")[0].get("Domains")[0]
				self.logger.debug("User default setting >"+str(self.user_default_settings))
				#print(self.user_default_settings)
			else:
				# Filter Domain settings
				u = "User:"+str(self.task_details.get("user_id"))+" DomainName:"+str(dname)+" EngineName:"+str(ename)
				self.logger.error("User default setting not found in DB>"+u)
				# Need to retun hear
			
			self.logger.info("Creating new version history in Crawl_DB")
			self.mdb_db = self.mdb_client["Crawl_DB"]
			user_id = self.task_details.get("user_id")
			self.mdb_collect = self.mdb_db[user_id+"_"+ename+"_history"]

			# Insert the initial crawling starting status to DB
			self.mdb_collect.update_one({"version":self.crawl_version},{"$set":{"crawl_start":self.crawl_version,
				"crawl_end":0,"current_status":"running"}},upsert=True)
			
			self.logger.info("New version history created in DB with 'running' as current_status")
			self.mdb_collect = self.mdb_db[user_id+"_"+ename]

			self.loop = asyncio.new_event_loop()
			asyncio.set_event_loop(self.loop)

			self.tasks.append(asyncio.ensure_future(self.main_flow()))
			self.tasks.append(asyncio.ensure_future(self.page_crawl_init()))

			# Starting loop
			self.logger.info("Creating main_flow,page_crawl_init tasks")
			self.loop.run_until_complete(asyncio.wait(self.tasks))
			end_time = datetime.datetime.utcnow()
			crawling_time = end_time - self.crawl_version
			crawling_time = crawling_time.seconds

			self.logger.info("Crawl Completed > Status:"+self.crawl_message+"> Engine > "+ename+"> Domain > "
				+dname+" >Total Elapsed time >"+str(crawling_time)+" seconds")
			
			# Update the final crawling starting status to DB
			self.logger.info(str(self.page_info))
			self.logger.info("Updating completed status to DB")
			self.mdb_collect = self.mdb_db[user_id+"_"+ename+"_history"]
			self.mdb_collect.update_one({"version":self.crawl_version},{"$set":{"crawl_start":self.crawl_version,"crawling_sec":
				crawling_time,"domain":dname,"crawl_end":end_time,"current_status":"completed",
				"message":self.crawl_message,"page_info":self.page_info}})
			
			# Update completed status in Redius server
			red_ser = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)
			task_key = self.task_details.get("task_key")
			red_ser.delete(task_key)
			self.logger.info("Task details deleted> "+task_key+" from redis DB")
			
			self.logger.info("========== Task completed ==========")
			#Exit the process
			self.loop.close()
		except Exception:
			self.logger.exception("check_new_crawl_job")

	async def main_flow(self):
		try:
			self.logger.info("Main flow initialized")
			advanced_settings = self.user_default_settings.get("AdvancedSettings")
			#print(advanced_settings)
			self.allow_robot = advanced_settings.get("Allow Robot.txt")
			self.BlackListUrls = self.user_default_settings.get("BlackListUrls")
			self.WhiteListUrls = self.user_default_settings.get("WhiteListUrls")
			self.ManualUrlsOnly = self.user_default_settings.get("ManualUrlsOnly")
			self.BlackListApp = self.user_default_settings.get("BlackListApp")
			self.BlackListApp = self.user_default_settings.get("WhiteListApp")
			self.ManualUrls = self.user_default_settings.get("ManualUrls")
			self.DomainName = self.user_default_settings.get("DomainName")
			self.robot_disallowed = []
			self.robot_allowed = []
			self.site_map_files = []

			#print(self.user_default_settings)
			# Check Robot.txt is allowed
			if self.allow_robot == "yes":
				# Read robot.txt
				self.logger.info("Need to check Robots.txt")
				robot_url = urllib.parse.urljoin(self.DomainName,"robots.txt")
				self.logger.info("Requesting for robots.txt file >Domain >"+robot_url)
				res = await self.http_req(robot_url,retry=1,timeout=10)

				if res == None:
					self.logger.error("Domain reachability failed :"+self.DomainName)
				elif res.get("status") == 200:
					self.logger.info("Got robots.txt file")
					robo_status = robot_txt_reader(res.get("payload"),"spiderman",self.logger)
					if robo_status != None:
						self.site_map_files = robo_status.get("site_map")
						self.robot_disallowed = robo_status.get("disallowed")
						self.robot_allowed = robo_status.get("allowed")
					else:
						self.logger.error("Robots.txt error found")
				else:
					self.logger.warning("robots.txt failed > http.status="+str(res.status))

			# Add starting Point of the crawl
			starting_url = self.DomainName
			ename = self.task_details.get("engine_name")

			# Reset all status , To prevent If anything failed in previous crawl 
			self.logger.info("Resetting all status to 'init' in DB")
			self.mdb_collect.update_many({},{"$set":{"status":"init"}})
			
			# Set initial URL to scrole
			self.logger.info("Updating stating URL as pending in DB> "+starting_url)
			results = self.mdb_collect.update_one({"_id":starting_url},
				{"$set":{"status":"pending","version":self.crawl_version}},upsert=True)
			
			if results.modified_count != None:
				# Triger crawller to start check the pending crawl
				self.craw_fin = False
				self.logger.info("Trigger the crawller to start")
			else:
				# Failed to add starting point url
				self.logger.error("Failed to add stating point to crawl in DB")
				self.craw_fin = True

		except Exception:
			self.logger.exception("main_flow")

	async def page_crawl_init(self):
		try:
			self.logger.info("page crawller initialized...")
			self.visted_urls_count = 0
			self.http_status_code = dict()
			self.app_types = dict()
			advanced_settings = self.user_default_settings.get("AdvancedSettings")
			self.BlackListUrls = self.user_default_settings.get("BlackListUrls")
			self.WhiteListUrls = self.user_default_settings.get("WhiteListUrls")
			self.ManualUrlsOnly = self.user_default_settings.get("ManualUrlsOnly")
			self.BlackListApp = self.user_default_settings.get("BlackListApp")
			self.WhiteListApp = self.user_default_settings.get("WhiteListApp")
			self.ManualUrls = self.user_default_settings.get("ManualUrls")
			self.DomainName = self.user_default_settings.get("DomainName")
			self.free_workers = advanced_settings.get("ParallelCrawler")
			max_workers = self.free_workers
			self.logger.info("Maximum workers> "+str(max_workers))
			ename = self.task_details.get("engine_name")
			dname = self.task_details.get("domain_name")
			
			# Connect redis server to check any termination request is present
			self.logger.info("Creating redis DB connection to check terminate process status")
			red_ser = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)
			task_key = self.task_details.get("task_key")

			while self.craw_fin != True:
				#print("Free Workers:"+str(self.free_workers)+"/"+str(max_workers))
				# Check if terminate is ser to"force" in redis DB
				# If force then close the loop
				terminate =red_ser.hget(task_key,"terminate")
				if terminate == "force":
					self.logger.warning("Force termination found in redis,Setting craw_fin to True")
					self.crawl_message = "terminated"
					self.craw_fin = True
				
				if self.craw_fin == None:
					await asyncio.sleep(1)
					continue;
				else:
					#print("Free Workers:"+str(self.free_workers))
					if self.free_workers < 1:
						self.logger.debug("Free Workers>"+str(self.free_workers))
						await asyncio.sleep(0.5)
						continue;
					else:
						self.logger.debug("Free Workers>"+str(self.free_workers))
					
					# Pass the loop to crate task
					await asyncio.sleep(0.1) # If await not in this then it will not pass control to crate_task
					self.logger.info("Getting pending task from DB with limit of "+str(self.free_workers))
					url_info = self.mdb_collect.find({"status":"pending"}).limit(self.free_workers)
					url_info = list(url_info)
					self.logger.info("Pending task(s) in DB> "+str(len(url_info)))
					#print("Pending URL count:"+str(len(url_info)))
					if len(url_info) < 1:
						#Check if any running URL
						#print("No Pending URL found, Checking for running URL")
						self.logger.info("Checking if any running status in DB")
						run_status = self.mdb_collect.find_one({"status":"running"})
						#print("Current Running>"+str(len(url_info)))
						self.logger.info("Running status found in DB")
						if run_status == None:
							self.logger.info("No running or pending found in DB> Engine > "+ename+" Domain > "+dname)
							self.craw_fin = True
					else:
						# Pending URL found in DB
						# Convert mongodb cursor to list
						pending_id = []
						for url_data in url_info:
							pending_id.append(url_data.get("_id"))
							self.mdb_collect.update_many({"_id":{"$in":pending_id}},{"$set":{"status":"running","version":self.crawl_version}})
							self.free_workers = self.free_workers - 1
							self.logger.debug("Creating crawl for> "+str(url_data.get("_id")))
							self.loop.create_task(self.one_page_crawl(url_data.get("_id")))
			
			info = {"visted":self.visted_urls_count,"http_status":self.http_status_code,"application_count":self.app_types}
			self.page_info.update(info)
			self.logger.info("page crawller completed...")
		except Exception:
			self.crawl_message = "Error found"
			self.logger.exception("page_crawl_init")

	async def one_page_crawl(self,url):
		# Create a http connection to given url
		# Extract the URL from page content
		# Add extracted URL to DB for next crawl
		try:
			self.logger.debug("Trying to Crawl> "+url)
			new_urls = []
			conn = aiohttp.TCPConnector()
			timeout = aiohttp.ClientTimeout(sock_connect=500)
			headers = {"User-Agent":"superman"}
			async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
				async with session.get(url,headers=headers) as resp:
					# Count the responce code
					if resp != None:
						self.count_http_code(resp.status)
						self.visted_urls_count = self.visted_urls_count + 1
						content_typ = resp.headers.get('content-type')
						
						if resp.status == 200:
							self.logger.debug("Response code:"+str(resp.status)+"> URL> "+url)
							application_type = guess_extension(content_typ.split(";")[0])
							self.count_application_types(application_type)
							payload = await resp.content.read()
							
							# Check for user whitelist application
							if application_type in self.WhiteListApp:
								if application_type == ".html" or application_type == ".htm":
									html_data = payload
									beauty_data = BeautifulSoup(html_data,"html.parser")
									all_href = beauty_data.find_all('a',href=True)
									
									# Get all href in page
									for href in all_href:
										black_list = False
										robot_black_list = False
										href = href['href']
										extraced_url = urllib.parse.urljoin(str(resp.url),href)


										# Check if url is allowed or blocked in robots.txt
										for domain_patten in self.robot_disallowed:
											domain_patten = urllib.parse.urljoin(str(resp.url),domain_patten)
											if urlmatch(domain_patten,extraced_url) == True:
												self.logger.debug("Url Black listed by robots.txt>"+extraced_url+" >Patten >"+domain_patten)
												robot_black_list = True
												break
										if robot_black_list == True:
											continue

										# Check for user blacklist and whitelist url's
										if len(self.BlackListUrls) > 0:
											# Check if given url is blacklisted
											for domain_patten in self.BlackListUrls:
												if urlmatch(domain_patten,extraced_url) == True:
													self.logger.debug("Url Black listed by user>"+extraced_url+" >Patten >"+domain_patten)
													black_list = True
													break
										if black_list == True:
											continue
										for domain_patten in self.WhiteListUrls:
											if urlmatch(domain_patten,extraced_url) == True:
												#print("URL Matched:"+extraced_url+", Patten:"+domain_patten)
												new_urls.append(extraced_url)
												#logger.info(extraced_url)
											else:
												self.logger.debug("URL Not Matched with WhiteListUrls:"+extraced_url+
													", Patten:"+domain_patten)
								
								else:
									self.logger.debug("New application >"+str(application_type)+str(" >")+url)
							else:
								self.logger.debug("Application not white listed by user>"+str(application_type)+str(" >")+url)
						else:
							self.logger.debug("Response code:"+str(resp.status)+"> URL> "+url)

			ename = self.task_details.get("engine_name")
			dname = self.task_details.get("domain_name")

			# Make current URL as completed state
			#print("Completed> "+url)
			self.mdb_collect.update_one({"_id":url},
					{"$set":{"status":"completed"}})
			
			self.logger.info("Url:"+url+" >"+" Having > "+str(len(new_urls))+" Link(s)")
			for new_url in new_urls:
				# If "new_url" not in database then insert
				results = self.mdb_collect.update_one({"_id":new_url},{"$setOnInsert": {"status":"pending","version":
					self.crawl_version,"_id":new_url}},upsert=True)

				if results.modified_count != None:
					# If "new_url" in database and version not matched with current then update the current version and with pending as status
					self.mdb_collect.update_one({"_id":new_url,"version":{"$ne":self.crawl_version}},
						{"$set":{"status":"pending","version":self.crawl_version}})
		except Exception:
			self.crawl_message = "Error found"
			self.craw_fin = True
			self.logger.exception("one_page_crawl")
		
		finally:
			self.free_workers = self.free_workers + 1

	

class start_main():
	# This class will check for new task in redis DB frequently and start the subprocess for each new task
	def __init__(self):
		#logger.info("start_main started...")
		pass;
	async def check_new_crawl_job(self,loop):
		try:
			# Check if any new crawl job is added in DB
			# If added JOB is in 'not started' state then start the crawl
			while True:
				await asyncio.sleep(1)
				# Remove Zombie process (alternative for join)
				#logger.debug("Removeing Zombie process(if present)")
				multiprocessing.active_children()
				#logger.debug("Checking 'crawl_task*' in redis DB")

				# Read all keys starting with "crawl_task" to check the crawlling task status
				new_crawl_task = self.red.keys("crawl_task*")
				#logger.debug("crawl_task*>"+str(new_crawl_task))

				# Get status of crawl_task , 
				# If task in not started state then get the task details and create a sup-process for the task.
				# Subprocess will create ASYNCIO webcraweller
				for task in new_crawl_task:
					task_status = self.red.hget(task,"status")
					logger.debug(task+">"+str(task_status))
					if task_status == "not started":
						logger.info("New task found ,Setting task to 'started' state>"+str(task))
						self.red.hset(task,"status","started")
						task_details = self.red.hgetall(task)
						logger.info("New task details>"+str(task_details))
						# Add task_key to task details
						task_details.update({"task_key":task})
						logger.info("Starting New Process for task>"+str(task))
						crawler = run_crawler()
						p = multiprocessing.Process(target=crawler.init_crawl,args=(task_details,))
						p.start()

		except Exception:
			logger.exception("check_new_crawl_job")

	async def initial_tasks(self,loop):
		#logger.info("initial_tasks")
		try:
			logger.debug("initial_tasks")
			logger.info("Trying to connect redis server")
			self.red = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)
			logger.info("Redis connection create...")
			t1 = loop.create_task(self.check_new_crawl_job(loop))
			#t2 = loop.create_task(self.check(loop))
			
			await t1
		except Exception:
			logger.exception("initial_tasks")

if __name__ == '__main__':
	logger.debug("Creating new event loop")
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)

	#Adding required tasks
	tasks = []

	main_obj = start_main()
	tasks.append(asyncio.ensure_future(main_obj.initial_tasks(loop)))
	#tasks.append(asyncio.ensure_future(start_task(loop))

	# Starting loop
	loop.run_until_complete(asyncio.wait(tasks))
	loop.close()