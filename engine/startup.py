import os
import time
import pymongo
import redis
import logging
from logging.handlers import RotatingFileHandler
from logging.handlers import SysLogHandler
import click
import datetime
import binascii
import json

sysl = SysLogHandler(address='/dev/log')
sysl.setFormatter(logging.Formatter('pser-startup: %(levelname)s > %(asctime)s > %(message)s'))

logger =  logging.getLogger("pser-startup")
logger.addHandler(sysl)
logger.setLevel(logging.DEBUG)

logger.info("Starting>startup.py")


class startup_check():
	
	def __init__(self):
		pass;

	def create_db_connections(self):
		try:
			self.red = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)
			self.mdb_client = pymongo.MongoClient('localhost', 27017)
			return "success"
		except Exception:
			self.logger.exception(http_req)

	def update_key_to_redis_server(self,user_id=None,engine_name=None,domain_name=None):
		try:
			logger.info("Start updating key to redis server")
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

			self.mdb_db = self.mdb_client["accounts"]
			self.mcollection = self.mdb_db["Engines"]

			db_results = self.mcollection.find(users,{"engine_write_key":1,"EngineName":1,
					"engine_read_key":1,"DomainName":1,"domain_read_key":1,"domain_write_key":1,"Weight":1,"Synonums":1,
					"CustomResults":1,"user_id":1,"user_id":1,"type":1})
			
			all_keys = []
			for data in db_results:
				try:
					user_id = data.get("user_id")
					# Delete all previous keys
					# Get match key based on user
					key_append = user_id.encode("utf-8").hex()
					old_keys = self.red.keys(key_append+"*")
					for old in old_keys:
						self.red.delete(old)
					
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
							all_keys.append({domain_r_key:{"engine_name":engine_name,"weight":str(weight),
								"domain_name":domain_name,"type":"domain_read","user_id":user_id}})
						if domain_w_key != None:
							all_keys.append({domain_w_key:{"engine_name":engine_name,"weight":str(weight),
								"domain_name":domain_name,"type":"domain_read","user_id":user_id}})
					else:
						logger.error("BUG Found> Type not found in 'Engine' collection> "+str(data))
					for key in all_keys:
						key_value = list(key.keys())[0]
						key_data = key.get(key_value)
						print(key_value)
						print(key_data)
						self.red.hmset(key_value,key_data)
						logger.info("API Keys updated to redis")

				except Exception:
					logger.exception("update key to redis server failed:")

		except Exception:
			logger.exception("update_key_to_redis_server")
			return False


if __name__ == '__main__':
	
	@click.command()
	@click.option('--update_key',is_flag=True, help='Update API Key from DB to Redis cache')
	#@click.option('--restart_redis',is_flag=True, help='Restart redis server')
	
	def run(update_key):
		try:
			start = startup_check()
			if update_key == True:
				if start.create_db_connections() != "success":
					logger.error("DB connection create failed")
				else:
					if start.update_key_to_redis_server() == False:
						logger.error("update_key_to_redis_server failed")
			else:
				logger.error("No argument specified")
		except Exception:
			logger.exception("run")
	run()