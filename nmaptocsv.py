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
import sys, re, csv, struct, socket, itertools

# OptionParser imports
from optparse import OptionParser

# Options definition
option_0 = { 'name' : ('-i', '--input'), 'help' : 'Nmap scan output file (stdin if not specified)', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'), 'help' : 'csv output filename (stdout if not specified)', 'nargs' : 1 }
option_2 = { 'name' : ('-f', '--format'), 'help' : 'csv column format { fqdn, hop_number, ip, mac_address, mac_vendor, port, protocol, os, service, version } (default : ip-fqdn-port-protocol-service-version)', 'nargs' : 1 }
option_3 = { 'name' : ('-n', '--newline'), 'help' : 'insert a newline between each host for better readability', 'action' : 'count' }
option_4 = { 'name' : ('-s', '--skip-header'), 'help' : 'do not print the csv header', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4]

# Format option
DEFAULT_FORMAT = 'ip-fqdn-port-protocol-service-version'
SUPPORTED_FORMAT_OBJECTS = [ 'fqdn', 'hop_number', 'ip', 'mac_address', 'mac_vendor', 'port', 'protocol', 'os', 'service', 'version' ]
INVALID_FORMAT = 10
VALID_FORMAT = 11

# Newline option
NO_NEWLINE = 20
YES_NEWLINE = 21

# Header option
NO_HEADER = 22
YES_HEADER = 23

# Handful patterns
#-- IP regex
p_ip_elementary = '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
p_mac_elementary = '[0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F]'

# Nmap Normal Output patterns
#-- Target
p_ip_nmap5 = 'Interesting.*on\s(?:(?P<fqdn_nmap5>.*) (?=\((?P<ip_nmap5>%s)\)))|Interesting.*on\s(?P<ip_only_nmap5>.*)\:' % p_ip_elementary
p_ip_nmap6 = 'Nmap.*for\s(?:(?P<fqdn_nmap6>.*) (?=\((?P<ip_nmap6>%s)\)))|Nmap.*for\s(?P<ip_only_nmap6>%s)$' % (p_ip_elementary, p_ip_elementary)

p_ip = re.compile('%s|%s' % (p_ip_nmap5, p_ip_nmap6))

#-- Port finding
p_port = re.compile('^(?P<number>[\d]+)\/(?P<protocol>tcp|udp)\s+(?:open|open\|filtered)\s+(?P<service>[\w\S]*)(?:\s*(?P<version>.*))?$')

#-- MAC address
p_mac = re.compile('MAC Address:\s(?P<mac_addr>(%s))\s\((?P<mac_vendor>.*)\)' % p_mac_elementary)

#-- OS detection (pattern order is important, the latter position the more precise and reliable the information is)
p_os = re.compile('(?:^Service Info: OS|^OS|^OS details|smb-os-discovery|\|\s+OS):\s(?P<os>[^;]+)')

#-- Network distance
p_network_dist = re.compile('Network Distance:\s(?P<hop_number>\d+)\shops?')

# Nmap Grepable output 
#-- Target, Ports
p_grepable = re.compile('(?P<whole_line>^Host:\s.*)')


# Handful functions
def dottedquad_to_num(ip):
	"""
		Convert decimal dotted quad string IP to long integer
	"""
	return struct.unpack('!L',socket.inet_aton(ip))[0]

def num_to_dottedquad(n):
	"""
		Convert long int IP to dotted quad string
	"""
	return socket.inet_ntoa(struct.pack('!L',n))

def unique_match_from_list(list):
	"""
		Check the list for a potential pattern match

		@param list : a list of potential matching groups
		
		@rtype : return the unique value that matched, or nothing if nothing matched
	"""
	result = ''
	for item in list:
		if item != None:
			result = str(item)
	
	return result

def extract_matching_pattern(regex, group_name, unfiltered_list):
	"""
		Return the desired group_name from a list of matching patterns

		@param regex : a regular expression with named groups
		@param group_name : the desired matching group name value
		@param unfiltered_list : a list of matches
		
		@rtype : the string value
	"""
	result = ''
	filtered_list = filter(regex.search, unfiltered_list)
	
	if len(filtered_list) == 1:
		filtered_string = ''.join(filtered_list)
		result = regex.search(filtered_string).group(group_name)
	
	return result

class Host:
	def __init__(self, ip, fqdn=''):
		self.ip_dottedquad = ip
		self.ip_num = dottedquad_to_num(ip)
		self.fqdn = fqdn
		self.ports = []
		self.os = ''
		self.mac_address = ''
		self.mac_address_vendor = ''
		self.network_distance = ''
		
	def add_port(self, port):
		self.ports.append(port)
	
	# Getters
	def get_ip_num_format(self):
		return str(self.ip_num)
	
	def get_ip_dotted_format(self):
		return str(self.ip_dottedquad)
	
	def get_fqdn(self):
		return str(self.fqdn)
	
	def get_port_list(self):
		return self.ports
	
	def get_port_number_list(self):
		if not(self.get_port_list()):
			return ['']
		else:
			result = []
			for port in self.get_port_list():
				result.append(port.get_number())
		return result
	
	def get_port_protocol_list(self):
		if not(self.get_port_list()):
			return ['']
		else:
			result = []
			for port in self.get_port_list():
				result.append(port.get_protocol())
		return result

	def get_port_service_list(self):
		if not(self.get_port_list()):
			return ['']
		else:
			result = []
			for port in self.get_port_list():
				result.append(port.get_service())
		return result

	def get_port_version_list(self):
		if not(self.get_port_list()):
			return ['']
		else:
			result = []
			for port in self.get_port_list():
				result.append(port.get_version())
		return result

	def get_os(self):
		return str(self.os)
	
	def get_mac_address(self):
		return str(self.mac_address)
	
	def get_mac_address_vendor(self):
		return str(self.mac_address_vendor)
	
	def get_network_distance(self):
		return str(self.network_distance)
		
	# Setters
	def set_fqdn(self, fqdn):
		self.fqdn = fqdn

	def set_os(self, os):
		self.os = os

	def set_mac(self, mac_address, mac_address_vendor = ''):
		self.mac_address = mac_address
		self.mac_address_vendor = mac_address_vendor

	def set_network_distance(self, network_distance):
		self.network_distance = network_distance

class Port:
	def __init__(self, number, protocol, service, version):
		self.number = number
		self.protocol = protocol
		self.service = service
		self.version = version
	
	def get_number(self):
		return self.number
		
	def get_protocol(self):
		return self.protocol
	
	def get_service(self):
		return self.service
	
	def get_version(self):
		return self.version

def split_grepable_match(raw_string) :
	"""
		Split the raw line to a neat Host object
		
		@param raw_string : the whole 'Host' line
		
		@rtype : return an Host object
	"""
	global p_ip_elementary
	
	splitted_fields = raw_string.split("\t")
	
	# Patterns
	p_host = re.compile('Host:\s(?P<ip>%s)\s+\((?P<fqdn>|.*)\)' % p_ip_elementary) 
	p_ports = re.compile('Ports:\s+(?P<ports>.*)')
	p_os = re.compile('OS:\s(?P<os>.*)')
	
	# Extracted named-group matches
	IP_str = extract_matching_pattern(p_host, 'ip', splitted_fields)
	FQDN_str = extract_matching_pattern(p_host, 'fqdn', splitted_fields)
	ports_str = extract_matching_pattern(p_ports, 'ports', splitted_fields)
	OS_str = extract_matching_pattern(p_os, 'os', splitted_fields)
	
	current_host = Host(IP_str, FQDN_str)
	current_host.set_os(OS_str)
	
	# Let's split the raw port list
	all_ports = ports_str.split(', ')
	
	# Keep only open ports
	open_ports_list = filter(lambda p: '/open/' in p, all_ports)
	
	for open_port in open_ports_list :
		splitted_fields = open_port.split('/',6)

		# Extract each field from the format:
		# [ port number / state / protocol / owner / service / rpc info / version info / ]
		#-- Thanks to http://www.unspecific.com/nmap-oG-output/
		number = splitted_fields[0]
		protocol = splitted_fields[2]
		service = splitted_fields[4]

		# the last field (version) has a trailing slash that we don't want
		version_with_trailing_slash = splitted_fields[6]
		version = version_with_trailing_slash[:-1]

		new_port = Port(number, protocol, service, version)

		current_host.add_port(new_port)

	return current_host

def parse(fd) :
	"""
		Parse the data according to several regexes
		
		@param fd : input file descriptor, could be a true file or stdin
		
		@rtype : return a list of <Host> objects indexed from their numerical IP representation
	"""
	global p_ip_elementary, p_ip, p_port, p_grepable
	
	IPs = {}
	last_host = None
	
	lines = [l.rstrip() for l in fd.readlines()]
	for line in lines:
		
		# 1st case: 	Nmap Normal Output
		#-- 1st action: Grab the IP
		IP = p_ip.search(line)
		if IP:
			# Check out what patterns matched
			IP_potential_match = [IP.group('ip_nmap5'), IP.group('ip_only_nmap5'), IP.group('ip_nmap6'), IP.group('ip_only_nmap6')]
			IP_str = unique_match_from_list(IP_potential_match)
			
			FQDN_potential_match = [IP.group('fqdn_nmap5'), IP.group('fqdn_nmap6')]
			FQDN_str = unique_match_from_list(FQDN_potential_match)
			
			new_host = Host(IP_str, FQDN_str)
			
			IPs[new_host.get_ip_num_format()] = new_host
			
			last_host = new_host
			
		
		# 1st case: 	Nmap Normal Output
		#-- 2nd action: Grab the port
		port = p_port.search(line)
		if port and last_host != None:
			number = str(port.group('number'))
			protocol = str(port.group('protocol'))
			service = str(port.group('service'))
			version = str(port.group('version'))
			
			new_port = Port(number, protocol, service, version )
			
			last_host.add_port(new_port)
		
		
		# 1st case: 	Nmap Normal Output
		#-- 3rd action:	Grab the MAC address
		mac = p_mac.search(line)
		if mac:
			last_host.set_mac(str(mac.group('mac_addr')), str(mac.group('mac_vendor')))
		
		
		# 1st case:		Nmap Normal Output	
		#-- 4th action:	Grab the OS detection
		os = p_os.search(line)
		if os:
			last_host.set_os(str(os.group('os')))
		
		
		# 1st case:		Nmap Normal Output
		#-- 5th action:	Grab the network distance
		network_distance = p_network_dist.search(line)
		if network_distance:
			last_host.set_network_distance(str(network_distance.group('hop_number')))
		
		
		# 2nd case: 		Nmap Grepable Output
		#-- 1 sole action:	Grab the whole line for further splitting
		grepable = p_grepable.search(line)
		if grepable :
			if grepable.group('whole_line') :
				new_host = split_grepable_match(grepable.group('whole_line'))
				
				# Update the occurence found with 'Status: Up'
				IPs[new_host.get_ip_num_format()] = new_host
				
				last_host = new_host
	
	return IPs

def check_supplied_format(fmt):
	"""
		Check for the supplied custom output format

		@param fmt : the supplied format
		
		@rtype : VALID_FORMAT or INVALID_FORMAT
	"""	
	global SUPPORTED_FORMAT_OBJECTS, INVALID_FORMAT, VALID_FORMAT
	result = INVALID_FORMAT
	
	splitted_fmt = fmt.split('-')
	
	for fmt_object in splitted_fmt :
		if not(fmt_object in SUPPORTED_FORMAT_OBJECTS):
			break
	else :
		result = VALID_FORMAT
	
	return result

def formatted_item(host, format_item):
	"""
		return the attribute value related to the host
		
		@param host : host object
		@param format_item : the attribute supplied in the custom format
		
		@rtype : the <list> attribute value
	"""
	if isinstance(host, Host) :
		option_map = {
					'fqdn' : 				[host.get_fqdn()],
					'hop_number': 			[host.get_network_distance()],
					'ip' : 					[host.get_ip_dotted_format()],
					'mac_address':			[host.get_mac_address()],
					'mac_vendor': 	    [host.get_mac_address_vendor()],
					'os' : 					[host.get_os()],
					'port':					host.get_port_number_list(),
					'protocol':				host.get_port_protocol_list(),
					'service':				host.get_port_service_list(),
					'version':				host.get_port_version_list()
					 }
		
		if format_item in option_map.keys():
			return option_map[format_item]
		else :
			return ''
	else :
		return []	

def repeat_attributes(attribute_list):
	"""
		repeat attribute lists to the maximum for the 
		
		@param attribute_list : raw list with different attribute list length
		
		@rtype : a list consisting of length equal attribute list
	"""
	max_number = len(max(attribute_list, key=len))
	attribute_list = map(lambda x: x * max_number, attribute_list)
	
	return attribute_list

def generate_csv(fd, results, output_format, header, newline) :
	"""
		Generate a plain ';' separated csv file with the desired or default attribute format

		@param fd : output file descriptor, could be a true file or stdout
	"""
	if results != {} :
		spamwriter = csv.writer(fd, delimiter=';')
		
		if header == YES_HEADER:
			csv_header = [format_item.upper() for format_item in output_format.split('-')]
			spamwriter.writerow(csv_header)
		
		for IP in sorted(results.iterkeys()) :
			formatted_attribute_list = []
			
			for index,format_item in enumerate(output_format.split('-')) :
				item = formatted_item(results[IP], format_item)
				formatted_attribute_list.insert(index, item)
			
			formatted_attribute_list = repeat_attributes(formatted_attribute_list)
			
			for line_to_write in itertools.izip(*formatted_attribute_list):
				spamwriter.writerow(list(line_to_write))
			
			# Print a newline if asked
			if newline == YES_NEWLINE:
				spamwriter.writerow('')

	return

def main(options, arguments):
	
	# Supplied format
	output_format = DEFAULT_FORMAT
	if options.format != None :
		if check_supplied_format(options.format) == VALID_FORMAT :
			output_format = options.format
		else:
			parser.error("Please specify a valid output format.\n\
			 Supported objects are { fqdn, ip, mac_address, mac_vendor, port, protocol, os, service, version }.")
	
	# Input descriptor
	if (options.input != None) :
		fd_input = open(options.input, 'rb')
	else :
		# No input file specified, reading from stdin
		fd_input = sys.stdin
	
	# Analysis	
	results = parse(fd_input)
	fd_input.close()
	
	# Output descriptor
	if (options.output != None) :
		fd_output = open(options.output, 'wb')
	else :
		# No output file specified, writing to stdout
		fd_output = sys.stdout
	
	# Newline
	newline = {True : YES_NEWLINE, False : NO_NEWLINE}[options.newline != None]
	
	# Header
	header = {True : NO_HEADER, False : YES_HEADER}[options.skip_header != None]  
	
	# CSV output
	generate_csv(fd_output, results, output_format, header, newline)
	fd_output.close()
	
	return

if __name__ == "__main__" :
	parser = OptionParser()
	for option in options :
		param = option['name']
		del option['name']
		parser.add_option(*param, **option)
	
	options, arguments = parser.parse_args()
	main(options, arguments)
