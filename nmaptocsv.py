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
import sys
import re
import csv
import struct
import socket
import itertools

# OptionParser imports
from optparse import OptionParser

# Options definition
OPTION_0 = {'name': ('-i', '--input'), 'help': 'Nmap scan output file (stdin if not specified)', 'nargs': 1}
OPTION_1 = {'name': ('-o', '--output'), 'help': 'csv output filename (stdout if not specified)', 'nargs': 1}
OPTION_2 = {'name': ('-f', '--format'), 'help': 'csv column format { fqdn, hop_number, ip, mac_address, mac_vendor, port, protocol, os, service, version, script } (default : ip-fqdn-port-protocol-service-version)', 'nargs': 1}
OPTION_3 = {'name': ('-n', '--newline'), 'help': 'insert a newline between each host for better readability', 'action': 'count'}
OPTION_4 = {'name': ('-s', '--skip-header'), 'help': 'do not print the csv header', 'action': 'count'}

ALL_OPTIONS = [OPTION_0, OPTION_1, OPTION_2, OPTION_3, OPTION_4]

# Format option
DEFAULT_FORMAT = 'ip-fqdn-port-protocol-service-version'
SUPPORTED_FORMAT_OBJECTS = ['fqdn', 'hop_number', 'ip', 'mac_address', 'mac_vendor', 'port', 'protocol', 'os',
                            'service', 'version', 'script']
INVALID_FORMAT = 10
VALID_FORMAT = 11

# Newline option
NO_NEWLINE = 20
YES_NEWLINE = 21

# Header option
NO_HEADER = 22
YES_HEADER = 23

# Handful patterns
# -- IP regex
P_IP_ELEMENTARY = '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
P_MAC_ELEMENTARY = '[0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F]'

# Nmap Normal Output patterns
# -- Target
P_IP_NMAP5 = 'Interesting.*on\s(?:(?P<fqdn_nmap5>.*) (?=\((?P<ip_nmap5>%s)\)))|Interesting.*on\s(?P<ip_only_nmap5>.*)\:' % P_IP_ELEMENTARY
P_IP_NMAP6 = 'Nmap.*for\s(?:(?P<fqdn_nmap6>.*) (?=\((?P<ip_nmap6>%s)\)))|Nmap.*for\s(?P<ip_only_nmap6>%s)$' % (
    P_IP_ELEMENTARY, P_IP_ELEMENTARY)

P_IP = re.compile('%s|%s' % (P_IP_NMAP5, P_IP_NMAP6))

# -- Port finding
P_PORT = re.compile(
    '^(?P<number>[\d]+)/(?P<protocol>tcp|udp)\s+(?:open|open\|filtered)\s+(?P<service>[\w\S]*)(?:\s*(?P<version>.*))?$')

# -- MAC address
P_MAC = re.compile('MAC Address:\s(?P<mac_addr>(%s))\s\((?P<mac_vendor>.*)\)' % P_MAC_ELEMENTARY)

# -- OS detection (pattern order is important, the latter position the more precise and reliable the information is)
P_OS = re.compile('(?:^Service Info: OS|^OS|^OS details|smb-os-discovery|\|\s+OS):\s(?P<os>[^;]+)')

# -- Network distance
P_NETWORK_DIST = re.compile('Network Distance:\s(?P<hop_number>\d+)\shops?')

# Nmap Grepable output
# -- Target, Ports
P_GREPABLE = re.compile('(?P<whole_line>^Host:\s.*)')

# Nmap Script Output
P_SCRIPT = re.compile('^(?P<identifier>\|_?)(?P<whole_line>.*)')


# Handful functions
def dottedquad_to_num(ip):
    """
        Convert decimal dotted quad string IP to long integer
    """
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def num_to_dottedquad(n):
    """
        Convert long int IP to dotted quad string
    """
    return socket.inet_ntoa(struct.pack('!L', n))


def unique_match_from_list(items):
    """
        Check the list for a potential pattern match

        @param items : a list of potential matching groups

        @rtype : return the unique value that matched, or nothing if nothing matched
    """
    for item in items:
        if item:
            return item
    return ''


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


class Host(object):
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

    def _get_port_info(self, func_name):
        if not self.ports:
            return ['']
        return [getattr(p, func_name) for p in self.ports]

    @property
    def port_numbers(self):
        return self._get_port_info('number')

    @property
    def port_protocols(self):
        return self._get_port_info('protocol')

    @property
    def port_services(self):
        return self._get_port_info('service')

    @property
    def port_versions(self):
        return self._get_port_info('version')

    @property
    def port_scripts(self):
        return self._get_port_info('script')


class Port(object):
    def __init__(self, number, protocol, service, version):
        self.number = number
        self.protocol = protocol
        self.service = service
        self.version = version
        self._script = []

    @property
    def script(self):
        return '\n'.join(self._script)

    @script.setter
    def script(self, value):
        self._script.append(value)


def split_grepable_match(raw_string):
    """
        Split the raw line to a neat Host object

        @param raw_string : the whole 'Host' line

        @rtype : return an Host object
    """
    splitted_fields = raw_string.split("\t")

    # Patterns
    p_host = re.compile('Host:\s(?P<ip>%s)\s+\((?P<fqdn>|.*)\)' % P_IP_ELEMENTARY)
    p_ports = re.compile('Ports:\s+(?P<ports>.*)')
    p_os = re.compile('OS:\s(?P<os>.*)')

    # Extracted named-group matches
    ip_str = extract_matching_pattern(p_host, 'ip', splitted_fields)
    fqdn_str = extract_matching_pattern(p_host, 'fqdn', splitted_fields)
    ports_str = extract_matching_pattern(p_ports, 'ports', splitted_fields)
    os_str = extract_matching_pattern(p_os, 'os', splitted_fields)

    current_host = Host(ip_str, fqdn_str)
    current_host.os = os_str

    # Let's split the raw port list
    all_ports = ports_str.split(', ')

    # Keep only open ports
    open_ports_list = filter(lambda p: '/open/' in p, all_ports)

    for open_port in open_ports_list:
        splitted_fields = open_port.split('/', 6)

        # Extract each field from the format [port number / state / protocol / owner / service / rpc info / version info]
        # -- Thanks to http://www.unspecific.com/nmap-oG-output/
        number, state, protocol, owner, service, version = splitted_fields[0:6]

        new_port = Port(number, protocol, service, version)

        current_host.add_port(new_port)

    return current_host


def parse(fd):
    """
        Parse the data according to several regexes

        @param fd : input file descriptor, could be a true file or stdin

        @rtype : return a list of <Host> objects indexed from their numerical IP representation
    """
    ip_addresses = {}
    last_host = None
    last_port = None

    lines = [l.rstrip() for l in fd.readlines()]
    for line in lines:

        # 1st case: 	Nmap Normal Output
        # -- 1st action: Grab the IP
        ip = P_IP.search(line)
        if ip:
            # Check out what patterns matched
            ip_potential_match = [ip.group('ip_nmap5'), ip.group('ip_only_nmap5'), ip.group('ip_nmap6'),
                                  ip.group('ip_only_nmap6')]
            ip_str = unique_match_from_list(ip_potential_match)

            fqdn_potential_match = [ip.group('fqdn_nmap5'), ip.group('fqdn_nmap6')]
            fqdn_str = unique_match_from_list(fqdn_potential_match)

            new_host = Host(ip_str, fqdn_str)

            ip_addresses[new_host.ip_num] = new_host

            last_host = new_host
            last_port = None

        # 1st case: 	Nmap Normal Output
        # -- 2nd action: Grab the port
        port = P_PORT.search(line)
        if port and last_host:
            number = port.group('number')
            protocol = port.group('protocol')
            service = port.group('service')
            version = port.group('version')

            new_port = Port(number, protocol, service, version)

            last_host.add_port(new_port)
            last_port = new_port

        # 1st case: 	Nmap Normal Output
        # -- 3rd action:	Grab the MAC address
        mac = P_MAC.search(line)
        if mac:
            last_host.mac_address = mac.group('mac_addr')
            last_host.mac_address_vendor = mac.group('mac_vendoer')

        # 1st case:		Nmap Normal Output
        # -- 4th action:	Grab the OS detection
        os = P_OS.search(line)
        if os:
            last_host.os = os.group('os')

        # 1st case:		Nmap Normal Output
        # -- 5th action:	Grab the network distance
        network_distance = P_NETWORK_DIST.search(line)
        if network_distance:
            last_host.network_distance = network_distance.group('hop_number')

        # 1st case:     Nmap Normal Output
        # -- 6th action:    Grab the Nmap Script Output
        script = P_SCRIPT.search(line)
        if script:
            value = script.group('whole_line')
            if len(script.group('identifier')) > 1:
                value = ' ' + value
            last_port.script = value

        # 2nd case: 		Nmap Grepable Output
        # -- 1 sole action:	Grab the whole line for further splitting
        grepable = P_GREPABLE.search(line)
        if grepable:
            if grepable.group('whole_line'):
                new_host = split_grepable_match(grepable.group('whole_line'))

                # Update the occurence found with 'Status: Up'
                ip_addresses[new_host.ip_num] = new_host

                last_host = new_host

    return ip_addresses


def check_supplied_format(fmt):
    """
        Check for the supplied custom output format

        @param fmt : the supplied format

        @rtype : VALID_FORMAT or INVALID_FORMAT
    """
    splitted_fmt = fmt.split('-')

    for fmt_object in splitted_fmt:
        if fmt_object not in SUPPORTED_FORMAT_OBJECTS:
            return INVALID_FORMAT

    return VALID_FORMAT


def formatted_item(host, format_item):
    """
        return the attribute value related to the host

        @param host : host object
        @param format_item : the attribute supplied in the custom format

        @rtype : the <list> attribute value
    """
    if not isinstance(host, Host):
        return []

    option_map = {
        'fqdn': [host.fqdn],
        'hop_number': [host.network_distance],
        'ip': [host.ip_dottedquad],
        'mac_address': [host.mac_address],
        'mac_vendor': [host.mac_address_vendor],
        'os': [host.os],
        'port': host.port_numbers,
        'protocol': host.port_protocols,
        'service': host.port_services,
        'version': host.port_versions,
        'script': host.port_scripts,
    }

    if format_item in option_map.keys():
        return option_map[format_item]
    else:
        return ''


def repeat_attributes(attribute_list):
    """
        repeat attribute lists to the maximum for the

        @param attribute_list : raw list with different attribute list length

        @rtype : a list consisting of length equal attribute list
    """
    max_number = len(max(attribute_list, key=len))
    attribute_list = map(lambda x: x * max_number, attribute_list)

    return attribute_list


def generate_csv(fd, results, output_format, header, newline):
    """
        Generate a plain ';' separated csv file with the desired or default attribute format

        @param fd : output file descriptor, could be a true file or stdout
        @param results: dictionary of the collected information
        @param output_format: string of fields to output and in what order
        @param header: should CSV have header line
        @param newline: should CSV have blank line between hosts for better readability
    """
    if not results:
        return

    csv_file = csv.writer(fd, delimiter=';')

    if header == YES_HEADER:
        csv_header = [format_item.upper() for format_item in output_format.split('-')]
        csv_file.writerow(csv_header)

    for ip in sorted(results.iterkeys()):
        formatted_attribute_list = []

        for index, format_item in enumerate(output_format.split('-')):
            item = formatted_item(results[ip], format_item)
            formatted_attribute_list.insert(index, item)

        formatted_attribute_list = repeat_attributes(formatted_attribute_list)

        for line_to_write in itertools.izip(*formatted_attribute_list):
            csv_file.writerow(list(line_to_write))

        # Print a newline on host change, if asked
        if newline == YES_NEWLINE:
            csv_file.writerow('')


def process_args():
    parser = OptionParser()
    for option in ALL_OPTIONS:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    opts, arguments = parser.parse_args()

    if opts.format and check_supplied_format(opts.format) != VALID_FORMAT:
        parser.error("Please specify a valid output format.\n\
        Supported objects are { fqdn, ip, mac_address, mac_vendor, port, protocol, os, service, version, script }.")

    return opts, arguments


def main():
    # arguments
    options, arguments = process_args()

    output_format = DEFAULT_FORMAT if not options.format else options.format
    fd_input = sys.stdin if not options.input else open(options.input, 'rb')

    results = parse(fd_input)
    fd_input.close()

    newline = YES_NEWLINE if options.newline else NO_NEWLINE
    header = NO_HEADER if options.skip_header else YES_HEADER
    fd_output = sys.stdout if not options.output else open(options.output, 'wb')

    generate_csv(fd_output, results, output_format, header, newline)
    fd_output.close()
    return

if __name__ == "__main__":
    sys.exit(main())
