def robot_txt_reader(data,bot,p_logger):
	try:
		data_list = []
		allowed_url = []
		disallowed_url = []
		site_maps = []
		crawl_delay = ""

		for line in data.split("\n"):
			line = line.replace("\r","")
			data_list.append(line)
		#print(data_list)
		# Get user agent
		bot_found = -1
		
		for inx , line in enumerate(data_list):
			if line.find("User-agent:") == 0:
				bot_name = line.split("User-agent:")
				if len(bot_name) > 1:
					bot_name = bot_name[1].strip()
					if bot_name == bot:
						bot_found = inx
		
		if bot_found != -1:
			agent_found = True
			for inx, line in enumerate(data_list[bot_found+1:]):
				if line == "":
					continue
				if line.find("User-agent") != -1:
					break;
				if line.find("Disallow:") != -1:
					url = line.split("Disallow:")
					if len(url) > 1:
						url = url[1].strip()
						if url != "":
							if url == "/":
								url = url + "*"
							disallowed_url.append(url)
				
				if line.find("Allowed:") != -1:
					url = line.split("Allowed:")
					if len(url) > 1:
						url = url[1].strip()
						if url != "":
							allowed_url.append(url)
		else:
			agent_found = False
		
		if line in data_list:
			if line.find("Sitemap:") == 0:
				sit_map = line.split("Sitemap:")
				if len(sit_map) > 1:
					sit_map = sit_map[1]
					sit_map = sit_map.strip()
					site_maps.append(sit_map)

		#print(disallowed_url)
		#print(allowed_url)
		#print(site_maps)
		return {"site_map":site_maps,"disallowed":disallowed_url,"allowed":allowed_url,"agent_found":agent_found}
	except Exception:
		p_logger.exception("check_new_crawl_job")