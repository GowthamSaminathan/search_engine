import asyncio
import aiohttp
import json

url = "http://127.0.0.1:8983/solr/admin/cores?action=STATUS&core=test"


async def show_core(loop,url,retry,timeout):
	try:
		url = "http://127.0.0.1:8983/solr/admin/cores?action=STATUS&core=test"
		for x in range(retry):
			conn = aiohttp.TCPConnector()
			timeout = aiohttp.ClientTimeout(sock_connect=5)
			async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
				async with session.get(url) as resp:
					print(resp.status)
					js = await resp.json()
					js = js.get("status")
					if js != {}:
						print(js.get("test"))
					else:
						print(js)
			print("Retry:"+str(x))
	except Exception as e:
		print(e)

async def create_core(loop,url,retry,timeout):
	try:
		url = "http://127.0.0.1:8983/solr/admin/cores?action=CREATE&name=core1"
		for x in range(retry):
			conn = aiohttp.TCPConnector()
			timeout = aiohttp.ClientTimeout(sock_connect=5)
			async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
				async with session.get(url) as resp:
					print(resp.status)
					js = await resp.json()
					print(js)
			print("Retry:"+str(x))
	except Exception as e:
		print(e)

async def add_data(loop,url,retry,timeout):
	try:
		url = "http://13.232.131.155:8983/solr/temp_core/update?commitWithin=1000"
		html_doc = {"title":"This is my first type of string","_text_":"gowtham is my data"}
		#solr_add = {"add": {"doc": html}}
		solr_add = {"add": {"doc": html_doc }}
		for x in range(retry):
			conn = aiohttp.TCPConnector()
			timeout = aiohttp.ClientTimeout(sock_connect=5)
			async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
				async with session.post(url,json=solr_add) as resp:
					print(resp.status)
					js = await resp.text()
					print(js)
			print("Retry:"+str(x))
	except Exception as e:
		print(e)


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

tasks = [  
    asyncio.ensure_future(add_data(loop,url,retry=1,timeout=10))
]

loop.run_until_complete(asyncio.wait(tasks))
loop.close()