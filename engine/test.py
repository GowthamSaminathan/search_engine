import redis
import json

red = redis.Redis(host='localhost', port=6379, db=0,decode_responses=True)

a = red.hmset("Test",{"a":"a","b":"b","c":["aa","cc"]})

print(a)