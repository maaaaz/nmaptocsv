#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of nmaptocsv.
#
# Copyright (C) 2012, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# nmaptocsv is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# nmaptocsv is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with nmaptocsv.  If not, see <http://www.gnu.org/licenses/>.

# Global imports
import sys, re, csv, struct, socket

# OptionParser imports
from optparse import OptionParser

# Options definition
option_0 = { 'name' : ('-i', '--input'), 'help' : 'Nmap scan output file in normal format (stdin if not specified)', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'), 'help' : 'csv output filename (stdout if not specified)', 'nargs' : 1 }

options = [option_0, option_1]

def dottedQuadToNum(ip):
    """
		Convert decimal dotted quad string IP to long integer
	"""
    return struct.unpack('!L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
    """
		Convert long int IP to dotted quad string
	"""
    return socket.inet_ntoa(struct.pack('!L',n))

def split_grepable_ports(raw_string) :
	"""
		Split the port raw list to a neat tuple list

		@param raw_string : string like '25/open/tcp//smtp///, 111/open/tcp//rpcbind///, 48175/open/tcp/////'
		
		@rtype : return a well-formed tuple list like '[('25', 'tcp', 'smtp', ''), ('111', 'tcp', 'rpcbind', ''), ('48175', 'tcp', 'unknown', '')]
	"""
	# Nmap Grepable output Port
	
	result_list = []
	
	all_ports = raw_string.split(', ')
	
	# keep only open ports
	open_ports_list = filter(lambda p: '/open/' in p, all_ports)
	
	for open_port in open_ports_list :
		
		splitted_fields = open_port.split('/')

		# extract each field
		number, state, protocol, dunno, service_name = splitted_fields[0:5]
		version = " ".join(splitted_fields[5:-1])
		eol = splitted_fields[-1]
		
		# group the tuple
		port_tuple = (number, protocol, service_name, version)
		result_list.append(port_tuple)
		
	
	return result_list


def parse(fd) :
	"""
		Parse the data according to several regexes

		@param fd : input file descriptor, could be a true file or stdin
		
		@rtype : return the results dictionary, example: {'127.0.0.1': [('25', 'tcp', 'smtp', ''), ('111', 'tcp', 'rpcbind', ''), ('48175', 'tcp', 'unknown', '')] }
	"""
	# IP regex
	p_ip_elementary = '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
	
	# Nmap normal output target
	p_ip_nmap5 = '(?:^Interesting.*on\s+(?:.*\()?(?P<ip_nmap5>%s)\)?\:?$)' % p_ip_elementary
	p_ip_nmap6 = '(?:^Nmap.*for\s+(?:.*\()?(?P<ip_nmap6>%s)\)?$)' % p_ip_elementary
	
	p_ip = re.compile('%s|%s' % (p_ip_nmap5, p_ip_nmap6))
	
	# Nmap normal output port finding
	p_port = re.compile('^([\d]+)\/(tcp|udp)\s*open\s*([\w\S]*)(?:\s*(.*))?$')
	
	# Nmap Grepable output 
	p_grepable = re.compile('^Host\:\s+(?P<ip>%s)\s+\(.*\)\s+Ports\:\s+(?P<ports>.*\/)' % p_ip_elementary)
	

	IPs = {}
	last_IP = ''
	
	lines = fd.readlines()
	for line in lines :
		
		# 1st case: Nmap normal output - 1st action:  grab the IP
		IP = p_ip.match(line)
		if IP :
			# IP can match from version 5 or 6
			last_IP = IP.group('ip_nmap5') if (IP.group('ip_nmap5') != None) else IP.group('ip_nmap6')
			
			# Conversion from dotted-quad IP -> long integer for sorting purposes
			last_IP = dottedQuadToNum(last_IP)
			
			IPs[last_IP] = []
			
			continue
		
		
		# 1st case: Nmap normal output - 2nd action: grab the port
		port = p_port.match(line)
		if port and last_IP != '':
			IPs[last_IP].append(port.groups())
		
		
		# 2nd case: Nmap grepable output - only 1 action : grab the IP and the port list
		grepable = p_grepable.match(line)
		if grepable :
			last_IP = grepable.group('ip')
			
			# Conversion from dotted-quad IP -> long integer for sorting purposes
			last_IP = dottedQuadToNum(last_IP)
			
			IPs[last_IP] = []
			
			port_list_splitted = split_grepable_ports(grepable.group('ports'))
			IPs[last_IP].extend(port_list_splitted)
			
			
	
	return IPs


def generate_csv(fd, results) :
	"""
		Generate a plain ';' separated csv file

		@param fd : output file descriptor, could be a true file or stdout
	"""	
	if results != {} :
		spamwriter = csv.writer(fd, delimiter=';')
		
		csv_header = ['IP', 'Port', 'Protocol', 'Service', 'Version']
		spamwriter.writerow(csv_header)
		
		for IP in sorted(results.iterkeys()) :
			port_list = results[IP]
			
			# Back Conversion from long integer -> dotted-quad IP
			IP = numToDottedQuad(IP)
			
			for index, port_tuple in enumerate(port_list) :
				port_number, port_protocol, port_service_name, port_service_version = port_tuple[0:4]
				
				line = [IP, port_number, port_protocol, port_service_name, port_service_version]
				
				spamwriter.writerow(line)
	return

def main(options, arguments) :

	if (options.input != None) :
		fd_input = open(options.input, 'r')
	else :
		# No input file specified, reading from stdin
		fd_input = sys.stdin
		
	results = parse(fd_input)
	fd_input.close()
	
	if (options.output != None) :
		fd_output = open(options.output, 'wb')
	else :
		# No output file specified, writing to stdout
		fd_output = sys.stdout
	
	generate_csv(fd_output, results)
	fd_output.close()

if __name__ == "__main__" :
	parser = OptionParser()
	for option in options :
		param = option['name']
		del option['name']
		parser.add_option(*param, **option)

	options, arguments = parser.parse_args()
	main(options, arguments)
