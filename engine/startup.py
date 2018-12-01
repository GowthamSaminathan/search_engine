import os
import time
import pymongo
import redis
import logging
from logging.handlers import RotatingFileHandler
from logging.handlers import SysLogHandler
import click
import datetime

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

	def update_key_to_redis_server(self,user_id=None):
		try:
			logger.info("Start updating key to redis server")
			if user_id == None:
				users = {}
			else:
				users = {"_id":user_id}
			
			self.mdb_db = self.mdb_client["accounts"]
			self.mcollection = self.mdb_db["users"]

			db_results = self.mcollection.find(users,{"Engines.engine_write_key":1,"Engines.EngineName":1,
					"Engines.engine_read_key":1,"Engines.Domains.DomainName":1,"Engines.Domains.domain_read_key":1,
					"Engines.Domains.domain_write_key":1,"_id":1})
			
			all_keys = []
			for data in db_results:
				try:
					user_id = data.get("_id")
					# Delete all previous keys
					key_append = "key_"+user_id+"_"
					old_keys = self.red.keys(key_append+"*")
					for old in old_keys:
						self.red.delete(old)
					for engine in data.get("Engines"):
						engine_name = engine.get("EngineName")
						engine_r_key = engine.get("engine_read_key")
						engine_w_key = engine.get("engine_write_key")
						if engine_r_key != None:
							all_keys.append({key_append+engine_r_key:{"engine_name":engine_name,"type":"engine_read"}})
						if engine_w_key != None:
							all_keys.append({key_append+engine_w_key:{"engine_name":engine_name,"type":"engine_write"}})
						
						domains = engine.get("Domains")
						if domains != None:
							for domain in domains:
								domain_name = domain.get("DomainName")
								domain_w_key = domain.get("domain_write_key")
								domain_r_key = domain.get("domain_read_key")
								if domain_r_key != None:
									all_keys.append({key_append+domain_r_key:{"engine_name":engine_name,
										"domain_name":domain_name,"type":"domain_read"}})
								if domain_w_key != None:
									all_keys.append({key_append+domain_w_key:{"engine_name":engine_name,
										"domain_name":domain_name,"type":"domain_write"}})
					for key in all_keys:
						key_value = list(key.keys())[0]
						key_data = key.get(key_value)
						self.red.hmset(key_value,key_data)

				except Exception:
					logger.exception("update key to redis server failed:")

			logger.info("Key Update to redis completed....")
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