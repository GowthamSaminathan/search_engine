import os
import time
import json
import pymongo
import logging
from logging.handlers import RotatingFileHandler

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

logger =  logging.getLogger("Rotating Log websnap")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler("/home/ubuntu/web_server_log/engine_log.log",maxBytes=5000000,backupCount=25)

formatter = logging.Formatter('%(asctime)s > %(levelname)s > %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
#logger.propagate = False # DISABLE LOG STDOUT
logger.info("Engine_Head")

class run_crawler():
	
	def __init__(self):
		pass;

	async def http_req(self,url,retry,timeout):
		try:
			for x in range(retry):
				print("Crawling>"+url)
				conn = aiohttp.TCPConnector()
				timeout = aiohttp.ClientTimeout(sock_connect=500)
				async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
					async with session.get(url) as resp:
						return resp
				print("Retry:"+str(x))
		except Exception as e:
			print(e)

	async def main_flow(self,loop):
		try:
			print("Main flow initialized...")
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
			self.robots_txt = None
			self.sitemap = None

			#print(self.user_default_settings)
			# Check Robot.txt is allowed
			if self.allow_robot == "yes":
				# Read robot.txt
				robot_url = urllib.parse.urljoin(self.DomainName,"robots.txt")
				logger.info("Allow Robot.txt : yes")
				res = await self.http_req(robot_url,retry=1,timeout=10)

				if res == None:
					print("Domain reachability failed :"+self.DomainName)
				if res.status == 200:
					print("Got robots.txt file")
				else:
					print("robots.txt failed > http.status="+str(res.status))

			# Add starting Point of the crawl
			starting_url = self.DomainName
			ename = self.task_details.get("engine_name")

			results = self.mdb_collect.update_one({"_id":starting_url},
				{"$set":{"status":"pending","version":self.crawl_version}},upsert=True)
			
			if results.modified_count != None:
				# Triger crawller to start check the pending crawl
				self.craw_fin = False
			else:
				# Failed to add starting point url
				print("Failed to add stating point to crawl")
				self.craw_fin = True

		except Exception:
			logger.exception("main_flow")

	async def page_crawl_init(self,loop):
		try:
			print("page crawller initialized...")
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
			ename = self.task_details.get("engine_name")
			dname = self.task_details.get("domain_name")
			while self.craw_fin != True:
				#print("Free Workers:"+str(self.free_workers)+"/"+str(max_workers))
				if self.craw_fin == None:
					await asyncio.sleep(0.5)
					continue;
				else:
					await asyncio.sleep(2)
					if self.free_workers < 1:
						continue;
					url_info = self.mdb_collect.find({"status":"pending"}).limit(self.free_workers)
					url_info = list(url_info)
					if len(url_info) < 1:
						#Check if any running URL
						await asyncio.sleep(2)
						#print("No Pending URL found, Checking for running URL")
						run_status = self.mdb_collect.find_one({"status":"running"})
						#print("Current Running>"+str(len(url_info)))
						if run_status == None:
							print("Crawl completed for > Engine > "+ename+" Domain > "+dname)
							self.craw_fin = True
					else:
						print("Pending>"+str(url_info[0].get("_id")))
						# Pending URL found in DB
						# Convert mongodb cursor to list
						url_info = list(url_info)
						pending_id = []
						for url_data in url_info:
							pending_id.append(url_data.get("_id"))
						self.mdb_collect.update_many({"_id":{"$in":pending_id}},{"$set":
							{"status":"running","version":self.crawl_version}})
						for url_data in url_info:
							#print("Creating Task....")
							self.free_workers = self.free_workers - 1
							loop.create_task(self.page_crawl(url_data.get("_id")))
			
			self.page_info.update({"visted":self.visted_urls_count,"http_status":self.http_status_code,
				"application_count":self.app_types})
			print("page crawller completed...")
		except Exception:
			self.crawl_message = "Error found"
			logger.exception("page_crawl_init")
	
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
			logger.exception("count_application_types")


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
			logger.exception("count_http_code")


	async def page_crawl(self,url):
		# Create a http connection to given url
		# Extract the URL from page content
		# Add extracted URL to DB for crawl
		try:
			print("Running> "+url)
			new_urls = []
			conn = aiohttp.TCPConnector()
			timeout = aiohttp.ClientTimeout(sock_connect=500)
			async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
				async with session.get(url) as resp:
					# Count the responce code
					if resp != None:
						self.count_http_code(resp.status)
						self.visted_urls_count = self.visted_urls_count + 1
						content_typ = resp.headers.get('content-type')
						if resp.status == 200:
							application_type = guess_extension(content_typ.split(";")[0])
							self.count_application_types(application_type)
							payload = await resp.content.read()
							if application_type == ".html" or application_type == ".htm":
								html_data = payload
								beauty_data = BeautifulSoup(html_data,"html.parser")
								all_href = beauty_data.find_all('a',href=True)
								for href in all_href:
									href = href['href']
									extraced_url = urllib.parse.urljoin(str(resp.url),href)
									for domain_patten in self.WhiteListUrls:
										if urlmatch(domain_patten,extraced_url) == True:
											#print("URL Matched:"+extraced_url+", Patten:"+domain_patten)
											new_urls.append(extraced_url)
											#logger.info(extraced_url)
										else:
											pass
											#print("URL Not Matched:"+extraced_url+", Patten:"+domain_patten)
							else:
								print("New application>"+str(application_type))
						else:
							print("Response code:"+str(resp.status))
			#print(new_urls)

			ename = self.task_details.get("engine_name")
			dname = self.task_details.get("domain_name")

			# Make current URL as completed state
			#print("Completed> "+url)
			self.mdb_collect.update_one({"_id":url},
					{"$set":{"status":"completed"}})
			
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
			logger.exception("page_crawl")
		
		finally:
			self.free_workers = self.free_workers + 1

	def init_crawl(self,task_details):
		try:
			self.craw_fin = None
			self.task_details = task_details
			self.red_db = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)
			self.mdb_client = pymongo.MongoClient('localhost', 27017)
			self.mdb_db = self.mdb_client["accounts"]
			self.mdb_collect = self.mdb_db["users"]
			self.tasks = []
			self.crawl_info = dict()
			self.crawl_settings = dict()
			self.crawl_version = datetime.datetime.utcnow()
			self.crawl_message = "Good"
			self.page_info = dict()
			
			#print(self.task_details)
			#self.red_db.hgetall()
			#self.crawl_info.update({"user_id":user_id,""})
			ename = self.task_details.get("engine_name")
			dname = self.task_details.get("domain_name")
			self.user_default_settings = self.mdb_collect.find_one({"_id":self.task_details.get("user_id"),
				"Engines":{"$elemMatch":{"Domains.DomainName":{"$eq":self.task_details.get("domain_name")},
				"EngineName":self.task_details.get("engine_name")}}},{"_id":0,"Engines.Domains.$":1})			
			

			if self.user_default_settings != None:
				self.user_default_settings = self.user_default_settings.get("Engines")[0].get("Domains")[0]
				#print(self.user_default_settings)
			else:
				# Filter Domain settings
				u = "User:"+str(self.task_details.get("user_id"))+" DomainName:"+str(dname)+" EngineName:"+str(ename)
				print("User Default setting not found:"+u)
				# Need to retun hear
			
			self.mdb_db = self.mdb_client["Crawl_DB"]
			user_id = self.task_details.get("user_id")
			self.mdb_collect = self.mdb_db[user_id+"_"+ename+"_history"]

			# Insert the initial crawling starting status to DB
			self.mdb_collect.update_one({"version":self.crawl_version},{"$set":{"crawl_start":self.crawl_version,
				"crawl_end":0,"current_status":"running"}},upsert=True)
			
			self.mdb_collect = self.mdb_db[user_id+"_"+ename]

			self.loop = asyncio.new_event_loop()
			asyncio.set_event_loop(self.loop)

			self.tasks.append(asyncio.ensure_future(self.main_flow(self.loop)))
			self.tasks.append(asyncio.ensure_future(self.page_crawl_init(self.loop)))
			#tasks.append(asyncio.ensure_future(start_task(loop))

			# Starting loop
			self.loop.run_until_complete(asyncio.wait(self.tasks))
			end_time = datetime.datetime.utcnow()
			crawling_time = end_time - self.crawl_version
			crawling_time = crawling_time.seconds
			print("Task Completed > Engine > "+ename+" Domain > "+dname)
			
			# Update the final crawling starting status to DB
			self.mdb_collect = self.mdb_db[user_id+"_"+ename+"_history"]
			self.mdb_collect.update_one({"version":self.crawl_version},{"$set":{"crawl_start":self.crawl_version,"crawling_sec":
				crawling_time,"domain":dname,"crawl_end":end_time,"current_status":"completed",
				"message":self.crawl_message,"page_info":self.page_info}})
			
			# Update completed status in Redius server
			red_ser = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)
			task_key = self.task_details.get("task_key")
			red_ser.delete(task_key)
			
			#Exit the process
			self.loop.close()
		except Exception:
			logger.exception("check_new_crawl_job")

class start_main():
	
	def __init__(self):
		#logger.info("start_main started...")
		pass;
	async def check_new_crawl_job(self,loop):
		try:
			# Check if any new crawl job is added in DB
			# If added JOB is in 'not started' state then start the crawl
			crawler = run_crawler()
			while True:
				await asyncio.sleep(1)				
				#Remove Zombie process (alternative for join)
				multiprocessing.active_children()
				
				new_crawl_task = self.red.keys("crawl_task*")
				for task in new_crawl_task:
					task_status = self.red.hget(task,"status")
					if task_status == "not started":
						self.red.hset(task,"status","started")
						task_details = self.red.hgetall(task)
						# Add task key name to task details 
						task_details.update({"task_key":task})
						print("New Task found>"+str(task_details))
						p = multiprocessing.Process(target=crawler.init_crawl,args=(task_details,))
						p.start()

		except Exception:
			logger.exception("check_new_crawl_job")

	async def initial_tasks(self,loop):
		#logger.info("initial_tasks")
		try:
			self.red = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)
			print("Redis connection create...")
			t1 = loop.create_task(self.check_new_crawl_job(loop))
			#t2 = loop.create_task(self.check(loop))
			
			await t1
		except Exception:
			logger.exception("initial_tasks")

if __name__ == '__main__':
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