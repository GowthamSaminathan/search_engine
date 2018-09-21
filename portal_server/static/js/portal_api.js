function get_domain(engine_name,domain_name,onsuccess){

var settings = {
  "async": true,
  "crossDomain": true,
  "url": "/portal/get_domain_data?domain_name="+domain_name+"&engine_name="+engine_name,
  "method": "GET",
  "dataType": "json",
  "headers": {
    "Cache-Control": "no-cache",
  }
}

$.ajax(settings).done(function (response) {
  if(response.result == "success"){
  	// Extracting Domains from response
  	
  	domains = response.data.Engines[0].Domains
  	if (domains.constructor === Array){
  		// Valid domain data found
  		onsuccess(domains)

  	}}
  	
  	else if(response.result == "failed" && response.message == "Please login again")
  	{
  		// Session expired or not valid session
  		$(location).attr('href', 'index.html')
  	}
	
	else
	{
  	console.log("Domain Portal failed >")
  	console.log(response)
  	}

});
}