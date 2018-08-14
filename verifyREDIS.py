#######################################################
# vpavesi
# create delete check REDIS database
# august 10 2018
# version 0.1
#######################################################

##################################
import redis
import uuid
import sys
import platform
import logging
import optparse
import pprint
import inspect
import time
####import########################

##################################
def totheend():
	logging.info(printSepChar())
	logging.info('REDIS INFO')
	redisinfoend=redisInfoGet()
	pp.pprint(redisinfoend)
	logging.info(printSepChar())
	logging.info('')
	logging.info('verifyREDIS complete!')
	logging.info(printSepChar())
	sys.exit(0)
####totheend######################

##################################
def catchExceptionAppl(getErrorEx):
                #"Automatically log the current function details."
        # Get the previous frame in the stack, otherwise it would
        # be this function!!!
        func = inspect.currentframe().f_back.f_code

        # Dump the message + the name of this function to the log.
        logging.debug("%s: %s in %s:%i" % (
                getErrorEx,
                func.co_name,
                func.co_filename,
                func.co_firstlineno
        ))
###catchExceptionAppl#############

##################################
def redisInfoGet():
      return (r.info('all'))
####redisInfoGet##################

##################################
def printSepChar():
		nChar = str
		nChar = ('_' * 40 )
		return nChar	
####printSepChar##################

##################################
def defRedisCreateKey(nrkeys):
	try:
		while True:
			Keys=[]
			cnt = 0
			try:
				while cnt < nrkeys:
					cnt=cnt+1
					Keys.append ( str(uuid.uuid4()) )
			except KeyboardInterrupt:
				totheend()
			
			pipe = r.pipeline()	
			for key in Keys:
				try:
					pipe.set(keyname + '_' + key, key)
				except Exception as ex:
					catchExceptionAppl(ex)
			try:
				values=pipe.execute()
				if values:
					logging.info('REDIS SET')
			except Exception as ex:
				catchExceptionAppl(ex)

	except KeyboardInterrupt:
		totheend()
####defRedisCreateKey#############

##################################
def defRedisDeleteKey():
	try:
		for key in r.scan_iter(keyname + '_*'):
			r.delete(key)
		s = r.keys(pattern=keyname + '_*')
		logging.info(printSepChar())
		logging.info(s)
		logging.info('delete all keys')

		# VERIFY
		try:
				s = r.keys(pattern=keyname + '_*')
				if s:
					logging.info('DEL failed ' + str(len(s)))
					totheend()
				else:
					logging.info('DEL success')
				logging.info(printSepChar())

		except Exception as ex:
			   catchExceptionAppl(ex)


	except KeyboardInterrupt:
		totheend()
	except Exception as ex:
		catchExceptionAppl(ex)
###defRedisDeleteKey##############

##################################
def defRedisVerifyKey(nrkeys):
	try:
		while True:
			
			# SET
			Keys=[]
			cnt = 0
			try:
				while cnt < nrkeys:
					cnt=cnt+1
					Keys.append ( str(uuid.uuid4()) )
			except KeyboardInterrupt:
				totheend()

			pipe = r.pipeline()	
			for key in Keys:
				pipe.set(keyname + '_'+ key, key)
			try:
				values = pipe.execute()
				if values:
					pass
			except Exception as ex:
			   catchExceptionAppl(ex)
			
			time.sleep(3)

			# read keys
			s = r.keys(pattern=keyname + '_*')
			logging.info('SET number of keys:' + str(len(s)))

			# DEL
			try:
				for key in r.scan_iter(keyname + '_*'):
    					r.delete(key)
			except Exception as ex:
				catchExceptionAppl(ex)
			
			time.sleep(3)

			# VERIFY
			try:
				s = r.keys(pattern=keyname + '_*')
				if s:
						logging.critical('DEL failed ' + str(len(s)))
						logging.critical(r.keys(pattern=keyname + '_*'))
						totheend()
				else:
    					logging.info('DEL success')

			except Exception as ex:
			   catchExceptionAppl(ex)

	except KeyboardInterrupt:
		totheend()
####defRedisVerifyKey#############

##################################
# main
if __name__ == "__main__":
    	
	# define logging   	
	logging.basicConfig(format='%(asctime)s [%(levelname)s] [%(lineno)d]  %(message)s',level=0)
	logging.info('ctrl + c to stop')

	logging.info(printSepChar())
	logging.info(printSepChar())
	logging.info('')
	logging.info('verifyREDIS 0.1')
	logging.info(printSepChar())
	logging.info('')
	logging.info('OS info: ')
	logging.info('Endianness = %s',sys.byteorder)
	logging.info('OS = ' + platform.system() + '.' +  platform.release() + ' ' + sys.platform )
	logging.info('Machine = ' + platform.machine())
	logging.info('Node = ' + platform.node())
	logging.info('Processor = ' + platform.processor())
	logging.info('Python version = ' + platform.python_version())
	logging.info(printSepChar())
	logging.info('')
	logging.info('--create , create keys to redis')
	logging.info('--delete , delete keys from redis')
	logging.info('--verify , create-delete-verify')
	logging.info('--host , redis host')
	logging.info('--port  , redis tcp port')
	logging.info('--keyname , key name prefix')
	logging.info(printSepChar())
 
	# parser arguments
	usage = "usage: %prog [options] --create --delete --verify [--keyname] [--host] [--port] "
	parser = optparse.OptionParser(usage)
 
	parser.add_option("--create", action="store_true", default=False,
                      help='set keys')
	parser.add_option("--delete", action="store_true", default=False,
                      help='del keys')
	hlp = 'verify REDIS database SET DEL VERIFY'
	parser.add_option("--verify", action="store_true", default=False, help=hlp)
	parser.add_option("--keyname", type=str, default='mytestkey', help='key name prefix')
	parser.add_option("--host", type=str, default='localhost', help='REDIS ipaddr')
	parser.add_option("--port", type=int, default=6379, help='REDIS tcp port')
  

	(options, args) = parser.parse_args()


	# connect to redis
	try:
		r = redis.StrictRedis(host=options.host, port=options.port, db=0)

		logging.info('REDIS ping ' + str(r.ping()))
		logging.info('REDIS info:')
		pp = pprint.PrettyPrinter(indent=4)
		redisinfobegin = redisInfoGet()
		pp.pprint(redisinfobegin)

	except Exception as ex:
		catchExceptionAppl(ex)
		sys.exit(1)

	keyname=options.keyname

	if options.create:
		nrkeys=1000
		defRedisCreateKey(nrkeys)
	elif options.delete:
		defRedisDeleteKey()
	elif options.verify:
		nrkeys=400000
		defRedisVerifyKey(nrkeys)
	else:
		parser.print_help()
		sys.exit(1)
		
####main##########################
