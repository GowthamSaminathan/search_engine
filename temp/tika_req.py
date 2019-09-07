import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
import requests
import time
url = "http://13.232.131.155:9998/tika"
import tempfile


async def file_sender(file_name=None):
    async with aiofiles.open(file_name, 'rb') as f:
        chunk = await f.read(64*1024)
        while chunk:
            await chunk
            chunk = await f.read(64*1024)

async def test4(loop,url,retry,timeout):
	try:
		conn = aiohttp.TCPConnector()
		timeout = aiohttp.ClientTimeout(sock_connect=500)
		full_data = b""
		conn2 = aiohttp.TCPConnector()
		timeout2 = aiohttp.ClientTimeout(sock_connect=500)
		async with aiohttp.ClientSession() as session:
			async with session.put("http://127.0.0.1:9998/tika",data=f) as resp:
				print(await resp.text())
	except Exception as e:
		print(e)


async def test(loop,url,retry,timeout):
	try:
		conn = aiohttp.TCPConnector()
		timeout = aiohttp.ClientTimeout(sock_connect=500)
		full_data = b""
		conn2 = aiohttp.TCPConnector()
		timeout2 = aiohttp.ClientTimeout(sock_connect=500)
		temp_fp = tempfile.TemporaryFile()
		async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
			async with session.get("https://www.tutorialspoint.com/python3/python3_tutorial.pdf") as response:
				content_length = response.headers.get("Content-Length")
				print("Length >>>>"+str(content_length))
				if response.headers.get("Content-Type") == "text/html":
					max_download_size = 2000000
				else:
					
					max_download_size = 2000000

				chunk = None
				while chunk != b'':
					chunk = await response.content.read(max_download_size)
					#async for data in response.content.iter_chunked(max_download_size):
					max_download_size = max_download_size - chunk.__len__()

					if not chunk or max_download_size <= 0:
						break
					else:
						temp_fp.write(chunk)

		temp_fp.seek(0)
		async with aiohttp.ClientSession() as session:
			async with session.put("http://127.0.0.1:9998/tika",data=temp_fp) as resp:
				print(await resp.text())

		temp_fp.close()
	except Exception as e:
		print(e)

async def test2(loop,url,retry,timeout):
	data = await test(loop,url,retry,timeout)
	print(data)


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

tasks = [  
	asyncio.ensure_future(test2(loop,url,retry=1,timeout=10))
]

loop.run_until_complete(asyncio.wait(tasks))
loop.close()