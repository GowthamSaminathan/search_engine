import asyncio
import aiohttp

url = "https://google.co.in"


async def test(loop,url,retry,timeout):
	try:
		for x in range(retry):
			conn = aiohttp.TCPConnector()
			timeout = aiohttp.ClientTimeout(sock_connect=5)
			async with aiohttp.ClientSession(connector=conn,timeout=timeout) as session:
				async with session.get(url) as resp:
					return resp
			print("Retry:"+str(x))
	except Exception as e:
		print(e)

async def test2(loop,url,retry,timeout):
	data = await test(loop,url,retry,timeout)
	print(data.status)

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

tasks = [  
    asyncio.ensure_future(test2(loop,url,retry=1,timeout=10))
]

loop.run_until_complete(asyncio.wait(tasks))
loop.close()