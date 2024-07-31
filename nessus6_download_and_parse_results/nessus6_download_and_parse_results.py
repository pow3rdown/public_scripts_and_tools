#!/usr/bin/env python
############################################################
# This tool intends to retrieve all scans from the nessus
# server and export them to the nessus output format.
############################################################
# it was initially based on:
# https://discussions.nessus.org/docs/DOC-1155
# https://<nessus>:8834/nessus6-api.html
# https://docs.python.org/2/library/xml.etree.elementtree.html
# https://docs.python.org/2/library/syslog.html
# http://sharadchhetri.com/2014/07/31/how-to-install-mysql-server-5-6-on-centos-7-rhel-7/
# https://github.com/nerdynick/PySQLPool/blob/master/doc/reference.rst
# http://stackoverflow.com/questions/1912813/truncate-all-tables-in-a-mysql-database-in-one-command
############################################################

#''' ----------------------------------------- '''
#'''                importing libs             '''
#''' ----------------------------------------- '''
import xml.etree.cElementTree as ET
from   datetime import datetime
from   decimal import *
import multiprocessing
import requests
import PySQLPool
import os.path
import MySQLdb
import syslog
import json
import time
import sys
import bz2
import re


#''' ----------------------------------------- '''
#''' nessus credentials and useful information '''
#''' ----------------------------------------- '''
username 		= 'nessus'
nessus_password_file 	= './.password_nessus.txt'

nessus_port 		= '8834'
nessus_servers_pool 	= [ 'localhost' ]
verify 			= False


#''' ----------------------------------------- '''
#'''  MySQL credentials and useful information '''
#''' ----------------------------------------- '''
db_server 		= '127.0.0.1'
db_name 		= 'scandb'

db_user 		= 'scandb'
db_password_file 	= './.password_db.txt'


#''' ----------------------------------------- '''
#'''         parameters regarding reports      '''
#''' ----------------------------------------- '''
scan_list_threshold = '20'
old_vuln_threshold = '3'
reports_dir = '/mnt/rm_reports/reports/'



#''' ----------------------------------------- '''
#'''         beggining of functions here       '''
#''' ----------------------------------------- '''

def get_password_from_file(filename):

	if os.path.isfile(filename):

		file_content = open(filename, 'r') 
		return file_content.read().decode('utf8').rstrip()
	else:

		print ' [ERROR]: Nessus or DB password file(s) not found!'
		print ' > NESSUS: \t[./.password_nessus.txt]'
		print ' > DB: \t\t[./.password_db.txt]'
		sys.exit(1)



def db_open_connection():

	try:
		global connection
		connection = PySQLPool.getNewConnection(username=db_user, password=db_password, host=db_server, db=db_name, use_unicode=True, charset='utf8')
		PySQLPool.getNewPool().maxActiveConnections = 10

	except Exception, e:
		message = '  [ERROR]: It was not possible to connect to the specified nessus server (%s)!!!' % (server)
		logging( 'err' , message )
		sys.exit(1)


def db_close_connection():

	PySQLPool.terminatePool()



def get_date(timestamp):

	year  = time.strftime("%Y",time.localtime(float(timestamp))) 
	month = time.strftime("%b",time.localtime(float(timestamp))) 
	day   = time.strftime("%-d",time.localtime(float(timestamp))) 

	now = str(year) + str(month) + str(day) 
	return now



def get_hour(timestamp):

	hour_and_min = time.strftime("%-H%-M",time.localtime(float(timestamp))) #timestamp in the following format: 09:25 -> 925, 01:03 -> 13

	now = str(hour_and_min)
	return now



def convert_date_to_epoch(date_to_be_converted):

	#''' '%c' looks something like that: 'Tue Feb 17 13:42:49 2015'
	date = datetime.strptime(date_to_be_converted, '%c')
	return date.strftime("%s")



def compress_data(raw_xml_data):

	return bz2.compress(raw_xml_data)
	


def logging(priority, message):

	if   priority == 'info': 	syslog.syslog( syslog.LOG_INFO ,    message)
	elif priority == 'warning': 	syslog.syslog( syslog.LOG_WARNING , message)
	elif priority == 'err': 	syslog.syslog( syslog.LOG_ERR ,     message)
	else:
		#''' we are assuming LOG_INFO as being the default facility '''
		syslog.syslog( syslog.LOG_INFO , message)
	
	print message



def build_url(resource):

	return 'https://{0}:{2}{1}'.format(server, resource, nessus_port)



def connect(method, resource, data=None):

	headers = {'X-Cookie': 'token={0}'.format(token), 'content-type': 'application/json'}
	data = json.dumps(data)

	if method == 'POST':
        
		r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
	elif method == 'PUT':
        
		r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
	elif method == 'DELETE':
        
		r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
	else:

		r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

	#''' Exit if there is an error. '''
	if r.status_code != 200:
        
		e = r.json()
		print e['error']
		sys.exit(1)

	#''' When downloading a scan we need the raw contents, not the JSON data. '''
	if 'download' in resource:
        
		return r.content
	else:
        
		#''' return json object only when it is not disconnecting from the console (delete session)
		if method != 'DELETE':
			return r.json()



def nessus_open_connection(usr, pwd):

	global token
	token = ''

	try:

		login = { 'username': usr, 'password': pwd }
		data = connect('POST', '/session', data=login)

		token = data['token']

	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to the specified nessus server (%s)!!!' % (server)
		logging( 'err' , message )
		sys.exit(1)



def nessus_close_connection():

	connect('DELETE', '/session')



def export_status(sid, fid):

	data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))
	return data['status'] == 'ready'



def export(sid, hid, nessus_format):

	data = { 'format': nessus_format }
	result = connect('POST', '/scans/{0}/export'.format(sid), data=data)

	fid = result['file']
	while export_status(sid, fid) != True:
		time.sleep(2)

	return fid



def download(sid, fid):

	data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
	return data



def db_list_all_data(table):

	#''' returns all existing data in a table
	try:

		sql = """SELECT * FROM %s;""" % (table)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)

	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to %s table - function (db_list_all_data) ' % (table)
		logging( 'err' , message )

	return query.record



def convert_severity(severity):

	if   severity == 'Low':      severity == '1';
	elif severity == 'Medium':   severity == '2';
	elif severity == 'High':     severity == '3';
	elif severity == 'Critical': severity == '4';
	elif severity == 'None' or not severity: severity == '0';
	
	return severity



def db_add_new_scanned_items(ip,lastseen,all_report_items,customer_name,elapsed_time):

	countcrit = counthigh = countmedium = countlow = 0

	for each_report_item in all_report_items:

		plugin_id = each_report_item[2]
		port = each_report_item[7]
		protocol = each_report_item[3]

		#''' check if item exists '''
		try:

			sql = """SELECT countseen,lastseen,firstseen FROM Vuln_Active WHERE ip=INET_ATON('%s') AND pluginid='%s' AND port='%s' AND protocol='%s';""" % (ip, plugin_id, port, protocol)
			query = PySQLPool.getNewQuery(connection)
			query.query(sql)
		
		except Exception, e:

			message = '  [ERROR]: It was not possible to connect to Vuln_Active table or query an IP scanned (%s) - function (db_add_new_scanned_items)' % (ip)
			logging( 'err' , message )


		severity = each_report_item[4]

		if   severity == '1': countlow    = countlow    + 1;
		elif severity == '2': countmedium = countmedium + 1;
		elif severity == '3': counthigh   = counthigh   + 1;
		elif severity == '4': countcrit   = countcrit   + 1;

		# removing any kind of blank spaces (returns, etc) from the begging of the 1st line
		temp = re.sub('^\s*','',each_report_item[14][0:1200]) #maximum size of plugin_ouput field in db
		plugin_output = re.sub('\'',' ', temp) 

		#''' add the new item '''
		if not query.record:

			countseen = 1
			firstseen = lastseen
			flagdel = 0

			try:

				sql = """INSERT INTO Vuln_Active (ip,pluginid,severity,port,protocol,pluginoutput,firstseen,lastseen,countseen,flagdel) \
				VALUES (INET_ATON('%s'), '%s', '%s', '%s', '%s', '%s', '%s', '%s', %s, %s); """  \
				% (ip,plugin_id,severity,port,protocol,plugin_output,firstseen,lastseen,countseen,flagdel) 
				query = PySQLPool.getNewQuery(connection)
				query.query(sql)

			except Exception, e:

				message = '  [ERROR]: It was not possible to connect to Vuln_Active table or add a new item scanned (%s, %s) - function (db_add_new_scanned_items)' % (ip, plugin_id)
				logging( 'err' , message )

		else:

			#''' update the item '''
			countseen = int(query.record[0]['countseen']) +1
			flagdel = 0

			try:

				sql = """UPDATE Vuln_Active SET pluginoutput='%s',lastseen='%s',countseen='%s',flagdel='%s' WHERE ip = INET_ATON('%s') AND pluginid = '%s' AND port = '%s' AND protocol = '%s'; """  \
				% (plugin_output,lastseen,countseen,flagdel,ip,plugin_id,port,protocol)
				query = PySQLPool.getNewQuery(connection)
				query.query(sql)

			except Exception, e:

				message = '  [ERROR]: It was not possible to connect to Vuln_Active table or update a new item scanned (%s, %s) - function (db_add_new_scanned_items)' % (ip, plugin_id)
				logging( 'err' , message )



			#''' looking for old vulnerabilies on a specific host '''
			#''' only for severity > 0 (non info) '''
			try:

				sql = """SELECT lastseen,flagdel,id,pluginid,protocol,port,severity,pluginoutput,firstseen,countseen FROM Vuln_Active WHERE severity > 0 AND ip=INET_ATON('%s') AND lastseen !='%s'; """  % (ip,lastseen)
				query = PySQLPool.getNewQuery(connection)
				query.query(sql)
	
			except Exception, e:

				message = '  [ERROR]: It was not possible to connect to Vuln_Active table or query for a old host (%s/%s) - function (db_add_new_scanned_items)' % (ip,customer_name)
				logging( 'err' , message )


			if not query.record:

				for line in query.record:

					flagdel = int(line['flagdel']) + 1
					if flagdel > old_vuln_threshold:

						#''' preparing for deletion and moving the info to the Vuln_History table
						try:

							sql = """INSERT INTO Vuln_History (ip,lastseen,flagdel,pluginid,protocol,port,severity,pluginoutput,firstseen,countseen) \
							VALUES (INET_ATON('%s'), '%s', '%s', '%s', '%s', '%s', '%s', '%s', %s, %s); """  \
							% (ip,lastseen,flagdel,plugin_id,protocol,port,severity,plugin_output,firstseen,countseen) 
							query = PySQLPool.getNewQuery(connection)
							query.query(sql)

						except Exception, e:

							message = '  [ERROR]: It was not possible to connect to Vuln_History table or add an old item scanned (%s, %s) - function (db_add_new_scanned_items)' % (ip, plugin_id)
							logging( 'err' , message )


						try:

							sql = """DELETE from Vuln_Active WHERE id='%s';""" % (line['id'])
							query = PySQLPool.getNewQuery(connection)
							query.query(sql)

						except Exception, e:

							message = '  [ERROR]: It was not possible to connect to Vuln_Active table or delete an old item scanned (%s, %s) - function (db_add_new_scanned_items)' % (ip, plugin_id)
							logging( 'err' , message )


	db_add_new_ip_scope(ip, customer_name)
	db_add_scanned_hosts_statistics(lastseen,elapsed_time,countcrit,counthigh,countmedium,countlow,ip,customer_name)




def db_add_new_plugin(lastseen,report):

	plugins_already_processed = []
	for each_report_item in report:

                plugin_id 		= each_report_item[2]
		plugin_type 		= each_report_item[9]
		cve 			= each_report_item[15]

		exploit_available 	= each_report_item[17]
		exploitability_ease 	= each_report_item[18]
		
		severity 		= convert_severity(each_report_item[4])
		severity_orig 		= severity

		cvss 			= 0.0
		if each_report_item[16]: cvss = Decimal(each_report_item[16])

		#''' replace (') to avoid problems when storing information into database
		temp 		= each_report_item[1]
		plugin_name 	= re.sub('\'',' ', temp)

		temp 		= each_report_item[13]
		synopsis 	= re.sub('\'',' ', temp)

		temp 		= each_report_item[8]
		description 	= re.sub('\'',' ', temp)

		temp 		= each_report_item[12]
		solution 	= re.sub('\'',' ', temp)

		temp 		= each_report_item[19]
		see_also 	= re.sub('\'',' ', temp)


		#''' check if plugin exists '''
		try:

			sql = """SELECT pluginid FROM Vuln_Description WHERE pluginid='%s';""" % (plugin_id)
			query = PySQLPool.getNewQuery(connection)
			query.query(sql)
		
		except Exception, e:

			message = '  [ERROR]: It was not possible to connect to Vuln_Description table or query a new plugin(%s) - function (db_add_new_plugin)' % (plugin_id)
			logging( 'err' , message )


		#''' add the new plugin '''
		if not query.record:

			firstseen = lastseen

			try:

				sql = """INSERT INTO Vuln_Description (pluginid,name,severity,severity_orig,firstseen,lastseen,cve,synopsis,description,solution,plugin_type,cvss,exploit_available,exploitability_ease,see_also) \
				VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, '%s', '%s', '%s'); """  \
				% (plugin_id,plugin_name,severity,severity_orig,firstseen,lastseen,cve,synopsis,description,solution,plugin_type,cvss,exploit_available,exploitability_ease,see_also)
				query = PySQLPool.getNewQuery(connection)
				query.query(sql)

			except Exception, e:

				message = '  [ERROR]: It was not possible to connect to Vuln_Description table or add a new pluginr(%s) - function (db_add_new_plugin)' % (plugin_id)
				logging( 'err' , message )

		else:

			#''' update the plugin '''
			try:

				sql = """UPDATE Vuln_Description SET name='%s',severity='%s',severity_orig='%s',lastseen='%s',cve='%s',synopsis='%s',description='%s',solution='%s',plugin_type='%s',\
				cvss=%d,exploit_available='%s',exploitability_ease='%s',see_also='%s' WHERE pluginid = '%s'; """  \
				% (plugin_name,severity,severity_orig,lastseen,cve,synopsis,description,solution,plugin_type,cvss,exploit_available,exploitability_ease,see_also,plugin_id)
				query = PySQLPool.getNewQuery(connection)
				query.query(sql)

			except Exception, e:

				message = '  [ERROR]: It was not possible to connect to Vuln_Description table or update a new pluginr(%s) - function (db_add_new_plugin)' % (plugin_id)
				logging( 'err' , message )




def db_add_scanned_hosts_statistics(scantime,scanelapsed,countcrit,counthigh,countmedium,countlow,ip,customer_name):

	#''' add a new scanned host for statistics '''
	try:

		sql = """INSERT INTO Vuln_Statistics (scantime,scanelapsed,countcrit,counthigh,countmedium,countlow,ip,customer) \
		VALUES ('%s', '%s', '%s', '%s', '%s', '%s', INET_ATON('%s'), '%s'); """  \
		% (scantime,scanelapsed,countcrit,counthigh,countmedium,countlow,ip,customer_name)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)
	
	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to Vuln_Description table or add a new host statistics(%s/%s) - function (db_add_scanned_hosts_statistics)' % (ip,customer_name)
		logging( 'err' , message )




def db_add_new_ip_scope(ip, customer_name):

	#''' check if ip exists '''
	try:

		sql = """SELECT name FROM IPs_scope WHERE name='%s' AND customer='%s';""" % (ip, customer_name)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)
		
	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to IPs_scope table or query a new IP(%s/%s) - function (db_add_new_ip_scope)' % (ip,customer_name)
		logging( 'err' , message )

	#''' add the new IP '''
	if not query.record:

		try:
			sql = """INSERT INTO IPs_scope (name,ip,customer) VALUES ('%s',INET_ATON('%s'),'%s'); """  % (ip,ip,customer_name)
			query = PySQLPool.getNewQuery(connection)
			query.query(sql)

		except Exception, e:

			message = '  [ERROR]: It was not possible to connect to IPs_scope table or add a new IP(%s/%s) - function (db_add_new_ip_scope)' % (ip,customer_name)
			logging( 'err' , message )




def db_add_new_customer(customer_name):

	#''' check if customer exists '''
	try:

		sql = """SELECT customer FROM Customers WHERE customer='%s';""" % (customer_name)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)
		
	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to Customer table or query a new customer(%s) - function (db_add_new_customer)' % (customer_name)
		logging( 'err' , message )
		print e


	#''' add the new customer '''
	if not query.record:

		try:
			sql = """INSERT INTO Customers (customer) VALUES ('%s'); """  % (customer_name)
			query = PySQLPool.getNewQuery(connection)
			query.query(sql)

		except Exception, e:

			message = '  [ERROR]: It was not possible to connect to Customer table or add a new customer(%s) - function (db_add_new_customer)' % (customer_name)
			logging( 'err' , message )




def db_add_new_report(report_name,creationtime,processedtime,customer_name):

	status = 'new' #''' new report or already stored (old)
	#''' check if report exists '''
	try:

		sql = """SELECT processedtime FROM Reports_Control WHERE name='%s';""" % (report_name)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)
		
	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to Reports_Control table or query a new report(%s) - function (db_add_new_report)' % (report_name)
		logging( 'err' , message )


	#''' add the new report ''' 
	if not query.record:

		try:
			sql = """INSERT INTO Reports_Control (name, creationtime, processedtime, customer) VALUES ('%s','%s','%s','%s'); """  % (report_name, creationtime, processedtime, customer_name)
			query = PySQLPool.getNewQuery(connection)
			query.query(sql)
			status = 'new'

		except Exception, e:

			message = '  [ERROR]: It was not possible to connect to Reports_Control table or add a new report(%s) - function (db_add_new_report)' % (report_name)
			logging( 'err' , message )
	else:
		status = 'old'

	return status



def db_add_new_report_host_statistics(scan_time, customer_name):


	#''' check if there are vulns for this customer '''
	try:

		sql = """SELECT severity,count(severity) FROM Vuln_Active v INNER JOIN IPs_scope s ON v.ip=s.ip WHERE customer='%s' AND severity > 0 GROUP BY severity;""" % (customer_name)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)
		
	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to Vuln_Active and IPs_scope tables or query for old vulns per hosts for statistics (%s) - function (db_add_new_report_host_statistics)' % (customer_name)
		logging( 'err' , message )


	#''' summarizing number of vulns where severity is not zero '''
	countlow = countmedium = counthigh = countcrit = '0'
	if query.record:
		for line in query.record:

			if   line['severity'] == 1: countlow 	= line['count(severity)'] 
			elif line['severity'] == 2: countmedium = line['count(severity)'] 
			elif line['severity'] == 3: counhigh 	= line['count(severity)'] 
			elif line['severity'] == 4: countcrit 	= line['count(severity)'] 


	#''' check if there are vuln IPs for this customer '''
	try:

		sql = """SELECT COUNT(DISTINCT(s.ip)) FROM Vuln_Active v INNER JOIN IPs_scope s ON v.ip=s.ip WHERE customer='%s' AND severity > 0;""" % (customer_name)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)
		
	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to Vuln_Active and IPs_scope tables or query for number of ips for statistics (%s) - function (db_add_new_report_host_statistics)' % (customer_name)
		logging( 'err' , message )


	#''' insert the statistics on customer x ips x vulns '''
	countips = query.record[0]['COUNT(DISTINCT(s.ip))']
	try:
		sql = """INSERT into Customer_Statistics (customer,scantime,countcrit,counthigh,countmedium,countlow,countipvuln)  VALUES ('%s','%s','%s','%s','%s','%s','%s'); """ %(customer_name,scan_time,countcrit,counthigh,countmedium,countlow,countips)
		query = PySQLPool.getNewQuery(connection)
		query.query(sql)

	except Exception, e:

		message = '  [ERROR]: It was not possible to connect to Customer_Statistics table or add info customer for statistics (%s) - function (db_add_new_report_host_statistics)' % (customer_name)
		logging( 'err' , message )




def save_file(raw_file_compressed, name, scan_creation_time, nessus_format):

	date 		= get_date(scan_creation_time)
	hour		= get_hour(scan_creation_time)

	filename 	= reports_dir + '{0}_{1}_{2}.{3}.bz2'.format(name, date, hour, nessus_format)

	temp_file 	= open(filename,"w")
	temp_file.write(raw_file_compressed)
	temp_file.close()

	message 	= '  [OK]: Results saved at: %s ' % (filename)
	logging( 'info' , message )



def fix_customer_name(scan_name):

	temp = re.sub('((\-|\_)(pontual|gr(upo|oup)[0-9]+|consolidado)$|\s+)', '', scan_name.lower()) #fixing the customer name (pontual, grupo/groupN etc will be considered as the customer itself)
	return temp



def list_scans():

	temp_list 	= []
	temp_full_list 	= []
	data 		= connect('GET', '/scans')
	counter 	= 1

	for line in data['scans']:

		#''' the main idea is to define a threshold in order to avoid listing scans already stored in databases	 '''
		#''' threshold means: list the N last scans 								'''
		if scan_list_threshold > counter:

			last_hist_scan_id	= line['uuid']
			id2 			= line['id']
			name 			= line['name']
			status 			= line['status']
			started_time 		= line['creation_date']
			finished_time 		= line['last_modification_date']

			temp_list.append(name)
			temp_list.append(id2)
			temp_list.append(status)
			temp_list.append(last_hist_scan_id)
			temp_list.append(started_time)
			temp_list.append(finished_time)

			temp_full_list.append(temp_list)
			temp_list 	= []

			counter 	= counter + 1
	
	return temp_full_list



def parse_xml(xml_content,scan_time):

	full_report = ET.fromstring(xml_content)

        '''
        -------------
         XML Scheme:
        -------------
         <Report>
                <ReportHost>
                        <HostProperties>
                                <values>
                        </HostProperties>
                        <ReportItem>
                                <values>
                        </ReportItem>
                </ReportHost>
         </Report>
        '''

	for report in full_report:

		items_per_host = []
		each_reportitem_per_host = []

		if report.tag == "Report":

			#''' customer's name '''
			scan_name = fix_customer_name(report.get('name'))

			for record in report.getchildren():

				if record.tag == "ReportHost":

					#''' each scanned host '''
					host = record.get('name')

					#''' each item / vulnerability '''
					for elem in record.getchildren():

						#''' parsing only data from <HostProperties> tag '''
						if elem.tag == "HostProperties":

							host_end = operating_system = host_ip = host_fqdn = host_start = ''

							for subelem in elem.getchildren():
								if   subelem.attrib.values() == ['HOST_END']:   host_end = subelem.text
								elif subelem.attrib.values() == ['host-ip']:    host_ip = subelem.text
								elif subelem.attrib.values() == ['HOST_START']: host_start = subelem.text


						#''' parsing only data from <ReportItem> tag '''
						elif elem.tag == "ReportItem":

							#''' forcing variables to be initialized '''
							plugin_name 	= plugin_id = protocol = severity = svc_name = plugin_family = port = description = \
							plugin_type 	= risk_factor = script_version = solution = synopsis = \
							plugin_output 	= cve = cvss_base_score = exploit_available = exploitability_ease = see_also = ''

							plugin_name 	= elem.get('pluginName')
							plugin_id 	= elem.get('pluginID')
							protocol 	= elem.get('protocol')
							severity 	= elem.get('severity')
							svc_name 	= elem.get('svc_name')
							plugin_family 	= elem.get('pluginFamily')
							port 		= elem.get('port')

							for subelem in elem.getchildren():

								if   subelem.tag == "description": 		description = subelem.text
								elif subelem.tag == "plugin_type": 		plugin_type = subelem.text
								elif subelem.tag == "risk_factor": 		risk_factor = subelem.text
								elif subelem.tag == "script_version": 		script_version = subelem.text
								elif subelem.tag == "solution": 		solution = subelem.text
								elif subelem.tag == "synopsis": 		synopsis = subelem.text
								elif subelem.tag == "plugin_output": 		plugin_output = subelem.text
								elif subelem.tag == "cve": 			cve = subelem.text
								elif subelem.tag == "cvss_base_score": 		cvss_base_score = subelem.text
								elif subelem.tag == "exploit_available": 	exploit_available = subelem.text
								elif subelem.tag == "exploitability_ease": 	exploitability_ease = subelem.text
								elif subelem.tag == "see_also": 		see_also = subelem.text

							#''' store each ReportItem into the vector '''
							each_reportitem_per_host.append(host)
							each_reportitem_per_host.append(plugin_name)
							each_reportitem_per_host.append(plugin_id)
							each_reportitem_per_host.append(protocol)
							each_reportitem_per_host.append(severity)
							each_reportitem_per_host.append(svc_name)
							each_reportitem_per_host.append(plugin_family)
							each_reportitem_per_host.append(port)
							each_reportitem_per_host.append(description)
							each_reportitem_per_host.append(plugin_type)
							each_reportitem_per_host.append(risk_factor)
							each_reportitem_per_host.append(script_version)
							each_reportitem_per_host.append(solution)
							each_reportitem_per_host.append(synopsis)
							each_reportitem_per_host.append(plugin_output)
							each_reportitem_per_host.append(cve)
							each_reportitem_per_host.append(cvss_base_score)
							each_reportitem_per_host.append(exploit_available)
							each_reportitem_per_host.append(exploitability_ease)
							each_reportitem_per_host.append(see_also)

							''' ----------------------------------------- '''
                                                        ''' each_reportitem_per_host list scheme:           '''
							''' ----------------------------------------- '''
                                                        '''   host, plugin_name, plugin_id, protocol, severity, svc_name, plugin_family, port, description, 
								 plugin_type, risk_factor, script_version, solution, synopsis, plugin_output, cve, 
								 cvss_base_score, exploit_available, exploitability_ease and see_also     '''
							''' ----------------------------------------- '''
							items_per_host.append(each_reportitem_per_host)
							each_reportitem_per_host = []


					scan_date_end_epoch 	= convert_date_to_epoch(host_end)
					scan_date_start_epoch 	= convert_date_to_epoch(host_start)
					elapsed_time 		= int(scan_date_end_epoch) - int(scan_date_start_epoch)

					if not host_ip: host_ip = host #''' just in case host-ip is empty (tag not found)

					db_add_new_scanned_items(host_ip,scan_time,items_per_host,scan_name,elapsed_time)
					db_add_new_plugin (scan_date_start_epoch,items_per_host)
					items_per_host = []



def do_the_magic(list_of_scans):

	#''' export, download and parse everything '''
	for each_scan in list_of_scans:

		#''' this information is got from nessus directly '''
		#''' and not from xml '''
		scan_name = fix_customer_name(each_scan[0]) # the customer name
		scan_id = each_scan[1] #internal scan id #normally the customer id in nessus
		scan_status = each_scan[2] #completed, running etc
		scan_last_report_id = each_scan[3] #uuid
		scan_creation_time = each_scan[4] #timestamp (epoch format)
		processed_time = datetime.now().strftime("%s") #now (epoch format)
   
		#''' only parse the already completed scans '''
    		if scan_status == 'completed' and scan_name != 'proteus': # do not parse/import proteus' results

			#''' start adding info into the DB
			db_add_new_customer(scan_name)
			status = db_add_new_report(scan_last_report_id,scan_creation_time,processed_time,scan_name)

			#''' do things only if it is new
			#''' otherwise, skip 
			if status == 'new':

				#''' export and download the report (nessus format)
				file_id = export(scan_id, scan_last_report_id, 'nessus')
    				xml_to_be_parsed = download(scan_id, file_id)

				#''' if xml_to_be_parsed was not generated properly and it is empty
				#''' in this case, do nothing
				if not xml_to_be_parsed: continue

				# start parsing the report
				parse_xml(xml_to_be_parsed,scan_creation_time)
				db_add_new_report_host_statistics(scan_creation_time, scan_name)

				#''' compress and save the nessus results (nessus format)'''
				xml_compressed = compress_data(xml_to_be_parsed)
				xml_to_be_parsed = ''
				save_file(xml_compressed, scan_name, scan_creation_time, 'nessus')
				xml_compressed = ''

				#''' export and download the report (csv format)
				file_id = export(scan_id, scan_last_report_id, 'csv')
    				csv_file_content = download(scan_id, file_id)

				#''' compress and save the nessus results (csv format)'''
				csv_compressed = compress_data(csv_file_content)
    				csv_file_content = ''
				save_file(csv_compressed, scan_name, scan_creation_time, 'csv')
				csv_compressed = ''



#''' ----------------------------------------- '''
#'''             it starts here                '''
#''' ----------------------------------------- '''
if __name__ == '__main__':


	#''' load the passwords for nessus and db
	db_password = get_password_from_file(db_password_file)
	password = get_password_from_file(nessus_password_file)

	#''' open connections from db '''
	db_open_connection()

	for server in nessus_servers_pool:

		#''' open connections from nessus '''
		nessus_open_connection(username, password)

		#''' list existing scans from nessus '''
		list_of_scans = list_scans()

		#''' download reports, parse everything, store information into DB, save files and compress them (bzip2)
		do_the_magic(list_of_scans)

		#''' close connections from nessus '''
		nessus_close_connection()

	#''' close connections from db '''
	db_close_connection()

