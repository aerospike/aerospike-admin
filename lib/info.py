#!/usr/bin/python
####
#
# Copyright 2013-2017 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
####
# Aerospike python library
#
#

import sys					# please do not remove. used for stand alone build
import struct					# gives us a parser/encoder for binary data

from ctypes import create_string_buffer		 # gives us pre-allocated buffers
import types

try:
	import bcrypt
	hasbcrypt = True
except:
	# bcrypt not installed. This should only be fatal when authentication is required.
	hasbcrypt = False

#
# COMPATIBILITY COMPATIBILITY COMPATIBILITY
#
# So the 'struct' class went through lots of (good) improvements in 2.5, but we want to support
# old use as well as new. Write a few functions similar to the 2.5 ones, and either use builtin or
# pure based on what's available
#
#

def my_unpack_from(fmtStr, buf, offset  ):
	sz = struct.calcsize(fmtStr)
	return struct.unpack(fmtStr, buf[offset:offset+sz])

def my_pack_into(fmtStr, buf, offset, *args):
	tmp_array = struct.pack(fmtStr, *args)
	buf[offset:offset+len(tmp_array)] = tmp_array

# 2.5+ has this nice partition call
def partition_25(s, sep):
	return( s.partition(sep) )

# 2.4- doesn't
def partition_old(s, sep):
	idx = s.find(sep)
	if idx == -1:
		return(s, "", "")
	return( s[:idx], sep, s[idx+1:] )


g_proto_header = None
g_struct_header_in = None
g_struct_header_out = None
g_partition = None

# 2.5, this will succeed
try:
	g_proto_header = struct.Struct( '! Q' )
	g_struct_header_in = struct.Struct( '! Q B 4x B I 8x H H' )
	g_struct_header_out = struct.Struct( '! Q B B B B B B I I I H H' )
	g_struct_admin_header_in = struct.Struct( '! Q B B B B 12x' )
	g_struct_admin_header_out = struct.Struct( '! Q B B B B 12x' )
	g_partition = partition_25

# pre 2.5, if there's no Struct submember, so use my workaround pack/unpack
except:
	struct.unpack_from = my_unpack_from
	struct.pack_into = my_pack_into
	g_partition = partition_old

def receivedata(sock, sz):
	pos = 0
	while pos < sz:
		chunk = sock.recv(sz - pos)
		if pos == 0:
			data = chunk
		else:
			data += chunk
		pos += len(chunk)
	return data

def hashpassword(password):
	if hasbcrypt == False:
		print "Authentication failed: bcrypt not installed."
		sys.exit(1)

	if password == None:
		password = ""

	if len(password) != 60 or password.startswith("$2a$") == False:
		password = bcrypt.hashpw(password, "$2a$10$7EqJtq98hPqEX7fNZaFWoO")

	return password

def adminWriteHeader(sz, command, field_count):
	send_buf = create_string_buffer(sz);      # from ctypes
	# sz = (0 << 56) | (2 << 48) | (sz - 8)
	sz = (2 << 48) | (sz - 8)

	if g_struct_admin_header_out != None:
		g_struct_admin_header_out.pack_into(send_buf, 0, sz, 0, 0, command, field_count)
	else:
		struct.pack_into('! Q B B B B 12x', send_buf, 0, sz, 0, 0, command, field_count)

	return send_buf

def adminParseHeader(data):
	if g_struct_admin_header_in != None:
		rv = g_struct_admin_header_in.unpack(data)
	else:
		rv = struct.unpack('! Q B B B B 12x', data)

	return rv

def buffer_to_string(buf):
	buf_str = ""
	for s in buf:
		buf_str += s
	return buf_str

def authenticate(sock, user, password):
	sz = len(user) + len(password) + 34  # 2 * 5 + 24
	send_buf = adminWriteHeader(sz, 0, 2)
	fmtStr = "! I B %ds I B %ds" % (len(user), len(password))
	struct.pack_into(fmtStr, send_buf, 24, len(user)+1, 0, user, len(password)+1, 3, password)
	try:
		# OpenSSL wrapper doesn't support ctypes
		send_buf = buffer_to_string(send_buf)
		sock.sendall(send_buf)
		recv_buff = receivedata(sock, 24)
		rv = adminParseHeader(recv_buff)
		return rv[2]
	except Exception, msg:
		print "Authentication exception: ", msg
		return -1;

def _info_request(sock, buf):

	# request over TCP
	try:
		sock.send(buf)
		# get response
		rsp_hdr = sock.recv(8)
		q = struct.unpack_from("! Q",rsp_hdr, 0)
		sz = q[0] & 0xFFFFFFFFFFFF
		if sz > 0:
			rsp_data = receivedata(sock, sz)
	except Exception as ex:
		print "info request got exception ",type(ex)," ",ex
		return -1

	# parse out responses
	if sz == 0:
		return None

	return( rsp_data )

def info(sock, names=None):
	if not sock:
		return -1
	# Passed a set of names: created output buffer

	if names == None:
		q = (2 << 56) | (1 << 48)
		if g_proto_header != None:
			buf = g_proto_header.pack(q)
		else:
			buf = struct.pack('! Q',q)

	elif type(names) == types.StringType:
		q = (2 << 56) | (1 << 48) | (len(names) + 1)
		fmtStr = "! Q %ds B" % len(names)
		buf = struct.pack(fmtStr, q, names, 10 )

	else: # better be iterable of strings
		# annoyingly, join won't post-pend a seperator. So make a new list
		# with all the seps in
		names_l = []
		for name in names:
			names_l.append(name)
			names_l.append("\n")
		namestr = "".join(names_l)
		q = (2 << 56) | (1 << 48) | (len(namestr))
		fmtStr = "! Q %ds" % len(namestr)
		buf = struct.pack(fmtStr, q, namestr )

	rsp_data = _info_request(sock, buf)

	if rsp_data == -1 or rsp_data is None:
		return -1

	# if the original request was a single string, return a single string
	if type(names) == types.StringType:
		lines = rsp_data.split("\n")
		name, sep, value = g_partition(lines[0],"\t")

		if name != names:
			print " problem: requested name ",names," got name ",name
			return(-1)
		return value

	else:
		rdict = dict()
		for line in rsp_data.split("\n"):
			if len(line) < 1:
				# this accounts for the trailing '\n' - cheaper than chomp
				continue
			name, sep, value = g_partition(line,"\t")
			rdict[name] = value
		return rdict

