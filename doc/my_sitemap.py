
from scrapy.spiders import SitemapSpider
import requests



class MySpider(SitemapSpider):
    
    name = 'runrun'
    sitemap_urls = ['https://gic.delaware.gov/sitemap_index.xml']

    def parse(self, response):
        print "BOOTRESPONSE>> "+str(response.status)+" URL>"+str(response.url)

        custom_header = response.headers.get('Content-Type')
        custom_header = {'Content-type': custom_header }

        solr_payload = str(response.text.encode('utf-8'))
        url_id = response.url
        
        solr_url = 'http://127.0.0.1:8983'+str("/solr/gic-delaware/update/extract?literal.id=")+url_id+"&literal.url="+url_id
        solr_response = requests.post(solr_url, data=solr_payload,headers=custom_header)
        print "SOLAR_RESPONSE>> "+str(solr_response.text)

        #/solr/news-delaware/update/extract?commit=true