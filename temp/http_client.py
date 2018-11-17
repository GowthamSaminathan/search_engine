import asyncio
import aiohttp
from bs4 import BeautifulSoup


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
	data = await test(loop,url,retry,timeout)
	soup = BeautifulSoup(data, 'html.parser')
	print(soup.get_text())

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

tasks = [  
    asyncio.ensure_future(test2(loop,url,retry=1,timeout=10))
]

loop.run_until_complete(asyncio.wait(tasks))
loop.close()