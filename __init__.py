#!/bin/python

import struct
import operator
import datetime
import time

UDP_DATA_PORT = 0x4746

class EGDTag():

	TYPE_MAP = {
		"REAL" :(4, "f"),
		"DINT" :(4, "l"),
		"INT"  :(2, "h"),
		"UDINT":(4, "L"),
		"UINT" :(2, "H"),
		"BOOL" :(1, 'B')
	}

	def __init__(self, id, name, type, exchangenumber, offsetbyte, offsetbit, description):
		self.id = id
		self.name = name
		self.type = type
		self.exchangenumber = exchangenumber
		self.offsetbyte = offsetbyte
		self.offsetbit = offsetbit
		self.description = description
		self.dataindex = None
		self.lastvalue = None

	@classmethod
	def fromAddress(cls, address, type):
		exchangenumber, offsetbyte, offsetbit = address.split(".")
		return cls('', '', type, exchangenumber, offsetbyte, offsetbit, '')

	def getExchangeNumber(self):
		return self.exchangenumber

	def getCodecChar(self):
		return EGDTag.TYPE_MAP[self.type][1]

	def getCodecSize(self):
		return EGDTag.TYPE_MAP[self.type][0]

	def evaluateValue(self, egdpayload):
		self.lastvalue = egdpayload.data[self.dataindex]
		if self.type is 'BOOL':
			self.lastvalue =  ((self.lastvalue >> self.offsetbit) & 1) == 1
		return self.lastvalue

	def dump(self):
		if self.lastvalue != None:
			return "[{}.{} = {}]".format(self.offsetbyte, self.offsetbit, self.lastvalue)
		else:
			return "[{}.{}]".format(self.offsetbyte, self.offsetbit)

class EGDExchange():

	MAX_PAYLOAD_SIZE = 1400

	def __init__(self, number, period):
		self.exchangenumber = number
		self.period = period
		self.tags = []
		self.lasttimestamp = None
		self.lastmessage = None

	def addTagFromAddressParts(self, tagtype, offsetbyte, offsetbit):
		tag = EGDTag('', '', tagtype, self.exchangenumber, offsetbyte, offsetbit, '')
		self.tags.append(tag)
		return tag
		
	def addTag(self, tag):
		self.tags.append(tag)
		return tag

	def sortedTags(self):
		return sorted(self.tags, key = operator.attrgetter('offsetbyte', 'offsetbit'))

	def buildCodec(self):
		self.tags = self.sortedTags()
		self.codec = "<"
		lastoffset = 0
		lasttag = None
		dataindex = 0
		for tag in self.tags:
		    tag.dataindex = dataindex
		    if lasttag is not None and lasttag.offsetbyte == tag.offsetbyte:
		        #skip tags that are packed into the same area
		        tag.dataindex -= 1
		        continue
		    else:
		        dataindex += 1
		        lasttag = tag

		    paddingbytes = int(tag.offsetbyte) - lastoffset
		    if paddingbytes > 0:
		        self.codec += str(paddingbytes) + "x"

		    self.codec += tag.getCodecChar()
		    lastoffset = int(tag.offsetbyte) + tag.getCodecSize()

		if EGDExchange.MAX_PAYLOAD_SIZE > lastoffset:
		    self.codec += str(EGDExchange.MAX_PAYLOAD_SIZE - lastoffset) + "x"

	def setLastMessage(self, egdmessage):
	    self.lastmessage = egdmessage
	    self.lasttimestamp = datetime.datetime.fromtimestamp(egdmessage.header.timestampsecs + (egdmessage.header.timestampnanosecs / 10e9))
	    self.lastnow = datetime.datetime.now()

	def dump(self):
		pre = "\t{} ({} ms) - {} - {}".format(self.exchangenumber, self.period, self.codec[:10]+"...", struct.calcsize(self.codec))
		tagstr = ",".join(list(map(lambda t: t.dump(), self.tags)))
		post = "-----------------------------------------------------------"
		return "\n".join([pre, tagstr, post])

class EGDProducer():

	def __init__(self, producerid, destination):
		self.producerid = producerid
		self.destination = destination
		self.exchanges = {}

	def addExchange(self, exchangenumber, period):
		exchange = EGDExchange(exchangenumber, period)
		self.exchanges[exchange.exchangenumber] = exchange
		return exchange

	def getExchange(self, exchangenumber):
		if exchangenumber in self.exchanges:
			return self.exchanges[exchangenumber]
		else: return None

	def dump(self):
		pre = "{}".format(self.producerid)
		exchstr = list(map(lambda e: e[1].dump(), self.exchanges.items()))
		return "\n".join([pre]+exchstr)

class EGDConfiguration():

	def __init__(self):
		self.producers = {}
		self.delimiter = ","
		self.skiplines = 2

	def getProducer(self, producerid):
		if producerid in self.producers:
			return self.producers[producerid]
		else: return None

	def addProducer(self, producerid, destination):
		producer = EGDProducer(producerid, destination)
		self.producers[producerid] = producer
		return producer

	def buildCodecs(self):
		for producerid in self.producers:
			for exchange in self.producers[producerid].exchanges:
				self.producers[producerid].exchanges[exchange].buildCodec()

	def dump(self):
		return "\n".join(list(map(lambda p: p[1].dump(), self.producers.items())))

class EGDHeader():

	codec = "<BBHLLLLHHHHL"
	HEADER_LEN = struct.calcsize(codec)

	def __init__(self, headerdata):
		self.header = headerdata
		headers = struct.unpack_from(EGDHeader.codec, headerdata)
		self.header = headerdata
		self.pdutype = headers[0]
		self.pduver = headers[1]
		self.requestid = headers[2]
		self.producerid = headers[3]
		self.exchangeid = headers[4]
		self.timestampsecs = headers[5]
		self.timestampnanosecs = headers[6]
		self.status = headers[8]
		self.configsig = headers[9]
		self.configsigextra = headers[10]
		self.reserved = headers[11]

	@classmethod
	def newHeaderFor(cls, producerid, exchangeid, count):
		tm = time.time()
		timestampsecs = long(tm)
		timestampnanosecs = (round((tm - timestampsecs) * 10e8))
		return cls(struct.pack(EGDHeader.codec, 1, 13, count % 65535, int(producerid), int(exchangeid), timestampsecs,
		                     timestampnanosecs, 0, 0, 0, 0, 0))

class EGDPayload(object):

    MAX_PAYLOAD_DATA_LEN = 1400

    def __init__(self, payloaddata, codec):
        #driverlen = struct.calcsize(egdexchange.codec)
        #print(codec)
        if EGDPayload.MAX_PAYLOAD_DATA_LEN > len(payloaddata):
            payloaddata += chr(0)*(EGDPayload.MAX_PAYLOAD_DATA_LEN - len(payloaddata))

        self.data = struct.unpack_from(codec, payloaddata)

class EGDMessage(object):
    def __init__(self, exchange):
        self.exchange = exchange
        self.header = None
        self.payload = None
        self.immediatetags = []

    @classmethod
    def fromDatagramData(cls, egdconfiguration, datagramdata):
        headerdata = datagramdata[:EGDHeader.HEADER_LEN]
        payloaddata = datagramdata[EGDHeader.HEADER_LEN:]
        egdheader = EGDHeader(headerdata)

        producer = egdconfiguration.getProducer(egdheader.producerid)
        if producer is None:
            #print("Unexpected producer id: " + str(egdheader.producerid))
            return None

        #print("Exchange " + str(exchangeid))

        exchange = producer.getExchange(egdheader.exchangeid)
        if exchange is None:
            print("Unexpected Exchange, skipping...")
            return None

        egdmessage = cls(exchange)
        egdmessage.header = egdheader
        egdmessage.payload = EGDPayload(payloaddata, exchange.codec)

        exchange.setLastMessage(egdmessage)
        for tag in exchange.tags:
            previousvalue = tag.lastvalue
            tag.evaluateValue(egdmessage.payload)
            
        return egdmessage

EGD_DATAGRAM_LEN = EGDHeader.HEADER_LEN + EGDPayload.MAX_PAYLOAD_DATA_LEN

