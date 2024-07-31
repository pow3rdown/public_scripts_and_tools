#!/usr/bin/env python
# -*- coding: utf-8 -*-


#''' ----------------------------------------- '''
#'''                importing libs             '''
#''' ----------------------------------------- '''
import xlsxwriter
import datetime
import os.path
import syslog
import xlrd
import time
import sys
import re


global _date_format_output_db
_date_format_output_db  = '%m/%d/%Y'

global _xlsx_filename
_xlsx_result_filename   = 'rm_diff.xlsx'


#''' ----------------------------------------- '''
#'''         beggining of functions here       '''
#''' ----------------------------------------- '''

def gen_xlsx(all_items):

        # creating the document and sheets
        workbook        = xlsxwriter.Workbook(_xlsx_result_filename)
        worksheet       = workbook.add_worksheet('data')
        row_number      = 0

        # formats
        center          = workbook.add_format({

            'align':            'center',
            'valign':           'vcenter',
            'text_wrap':        True
        })

        left          = workbook.add_format({

            'align':            'left',
            'valign':           'vcenter',
            'text_wrap':        True
        })

        date_format     = workbook.add_format({

            'align':            'center',
            'valign':           'vcenter',
            'num_format':       'mm/dd/yyyy',
            'text_wrap':        True
        })

        # creating the table and title, resizing etc.
        worksheet.set_zoom(100)
	number_of_items = str(len(all_items)+1)

	worksheet.add_table('A1:H' + number_of_items, 
			
			{
				'data': all_items, 
				'columns': [ 
						{ 'header': 'Status', 'format': center }, 
						{ 'header': 'Host', 'format': center }, 
						{ 'header': 'Risk', 'format': center }, 
						{ 'header': 'Protocol', 'format': center }, 
						{ 'header': 'Port', 'format': center }, 
						{ 'header': 'Name', 'format': left }, 
						{ 'header': 'Plugin_id', 'format': center },
						{ 'header': 'Site', 'format': center }
					] 
			})

        worksheet.set_column(0, 0, 13)
        worksheet.set_column(1, 1, 18)
        worksheet.set_column(2, 2, 12)
        worksheet.set_column(3, 3, 12)
        worksheet.set_column(4, 4, 12)
        worksheet.set_column(5, 5, 70)
        worksheet.set_column(6, 6, 16)
        worksheet.set_column(7, 7, 19)

        workbook.close()


def load_xlsx(filename):

	all_items 	= []
	item	  	= []

	workbook 	= xlrd.open_workbook(filename)
	worksheet 	= workbook.sheet_by_index(0)

	num_rows 	= worksheet.nrows - 1
	num_cells 	= worksheet.ncols - 1
	curr_row 	= -1

	while curr_row < num_rows:

        	curr_row 	+= 1
        	curr_cell 	= -1
        	row 		= worksheet.row(curr_row)

        	while curr_cell < num_cells:

                	curr_cell 	+= 1
                	cell_value 	= worksheet.cell_value(curr_row, curr_cell)

                	if   curr_cell == 0: host   	= str(cell_value)
                	elif curr_cell == 1: risk    	= str(cell_value)
                	elif curr_cell == 2: prot    	= str(cell_value)
                	elif curr_cell == 3: port  	= cell_value
                	elif curr_cell == 4: name  	= cell_value
                	elif curr_cell == 9: plugin_id 	= cell_value
                	elif curr_cell == 12: site 	= cell_value

		''' if the row processed is part of title, do nothing '''
		if re.match('\s*host\s*$', host.lower()) is not None:
			continue

		else:

			item.append(re.sub('\s+', '', host))
			item.append(risk)
			item.append(re.sub('\s+', '', prot))
			item.append(re.sub('\s+', '', str(int(port))))
			item.append(re.sub('\s+', '', str(int(plugin_id))))
			item.append(name)
			item.append(site)

			all_items.append(item)
			item = []

	return all_items


def compare_reports(old_report, new_report):

	found 		= 0
	all_diff	= []
	each_diff	= []

	# looking for fixed items
	for old_item in old_report:

		found 		= 0

		old_host 	= old_item[0] # host
		old_risk 	= old_item[1] # risk
		old_prot 	= old_item[2] # protocol
		old_port 	= old_item[3] # port
		old_plugin_id 	= old_item[4] # plugin_id
		old_name 	= old_item[5] # name
		old_site 	= old_item[6] # site

		for new_item in new_report:

			new_host 	= new_item[0] # host
			new_risk 	= new_item[1] # risk
			new_prot 	= new_item[2] # protocol
			new_port 	= new_item[3] # port
			new_plugin_id 	= new_item[4] # plugin_id
			new_name 	= new_item[5] # name
			new_site 	= new_item[6] # site

			if new_host == old_host and new_prot == old_prot and new_port == old_port and new_plugin_id == old_plugin_id:

				found = 1
				break

		if found == 0:

			each_diff.append('fixed')
			each_diff.append(old_host)
			each_diff.append(old_risk)
			each_diff.append(old_prot)
			each_diff.append(old_port)
			each_diff.append(old_name)
			each_diff.append(old_plugin_id)
			each_diff.append(old_site)

			all_diff.append(each_diff)
			each_diff = []

	# looking for new items
	for new_item in new_report:

		found 		= 0

		new_host 	= new_item[0] # host
		new_risk 	= new_item[1] # risk
		new_prot 	= new_item[2] # protocol
		new_port 	= new_item[3] # port
		new_plugin_id 	= new_item[4] # plugin_id
		new_name 	= new_item[5] # name
		new_site 	= new_item[6] # site

		for old_item in old_report:

			old_host 	= old_item[0] # host
			old_risk 	= old_item[1] # risk
			old_prot 	= old_item[2] # protocol
			old_port 	= old_item[3] # port
			old_plugin_id 	= old_item[4] # plugin_id
			old_name 	= old_item[5] # name
			old_site 	= old_item[6] # site

			if new_host == old_host and new_prot == old_prot and new_port == old_port and new_plugin_id == old_plugin_id:

				found = 1
				break

		if found == 0:

			each_diff.append('new')
			each_diff.append(new_host)
			each_diff.append(new_risk)
			each_diff.append(new_prot)
			each_diff.append(new_port)
			each_diff.append(new_name)
			each_diff.append(new_plugin_id)
			each_diff.append(new_site)

			all_diff.append(each_diff)
			each_diff = []


	return all_diff



#''' ----------------------------------------- '''
#'''             it starts here                '''
#''' ----------------------------------------- '''
if __name__ == '__main__':

	'''
	 ------------------
	 main
	 ------------------
	 this is the main function... everything starts here
	
	 <input>:   None
	 <output>:  None
	'''

	try:

		filename_old = str(sys.argv[1])
		filename_new = str(sys.argv[2])
	except:
		print '[ERROR] File(s) not found or invalid!'
		print 'USAGE: %s <old_report.xlsx> <new_report.xlsx>' % (sys.argv[0])
		print
		sys.exit(1)

	if not os.path.isfile(filename_old) or not os.path.isfile(filename_new):

		print '[ERROR] File(s) not found or invalid!'
		print
		sys.exit(1)

	old = load_xlsx(filename_old)
	new = load_xlsx(filename_new)

	all_diff = compare_reports(old, new)
	
	if len(all_diff) > 0:

		gen_xlsx(all_diff)
	else:
		print '[WARNING] There is no difference between the reports!'
		sys.exit(0)

