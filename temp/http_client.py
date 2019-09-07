import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re


url = "https://stackoverflow.com/questions/1936466/beautifulsoup-grab-visible-webpage-text"


async def test(loop,url,retry,timeout):
	try:
		for x in range(retry):
			conn = aiohttp.TCPConnector()
			timeout = aiohttp.ClientTimeout(sock_connect=5)
			async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
				async with session.get(url) as resp:
					return await resp.text()
			print("Retry:"+str(x))
	except Exception as e:
		print(e)

async def test2(loop,url,retry,timeout):
	tag_names = ["p","h[1-6]","a","b","i","u","tt","strong","blockquote","small","tr","th","td","dd","title"]
	data = await test(loop,url,retry,timeout)
	soup = BeautifulSoup(data, 'html.parser')
	for tag in soup.find_all(True):
		for tag_patten in tag_names:
			if re.match(tag.name,tag_patten) != None:
				if tag.string != None:
					print(tag.string.strip())
					print("================")
				continue

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

tasks = [  
    asyncio.ensure_future(test2(loop,url,retry=1,timeout=10))
]

loop.run_until_complete(asyncio.wait(tasks))
loop.close()