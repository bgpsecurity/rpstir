# seeddb.py
# setup and tear-down script for
# swingpoint test case data
import MySQLdb
import sys

def dbup():
	print "HERE"	
	try:
		con = MySQLdb.connect(
			host='localhost', 
			user='rpstir', 
			passwd='bbn', 
			db='rpstir_test',
			cursorclass=MySQLdb.cursors.DictCursor
		)
		cur = con.cursor()

		# multiple certificates with same SKI and different valto(s) expiration
		# source: A.cer, target: B.cer
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('A.cer','1','2','2031-11-04 15:50:52',1001)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('B.cer','7','6','2031-11-04 15:50:52',1002)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('C.cer','2','3','2031-11-04 15:50:52',1003)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('CPRIME.cer','2','3','2030-11-04 15:50:52',1004)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('D.cer','6','3','2031-11-04 15:50:52',1005)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('DPRIME.cer','6','3','2030-11-04 15:50:52',1006)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('G.cer','3','4','2031-11-04 15:50:52',1007)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('GPRIME.cer','3','4','2030-11-04 15:50:52',1008)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('I.cer','4','5','2021-11-04 15:50:52',1009)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('J.cer','5',NULL,'2021-11-04 15:50:52',1010)")

		# 3 node swingpoint
		# source: M.cer, target: N.cer
		# vice-versa
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('M.cer','10','12','2031-11-04 15:50:52',1011)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('O.cer','12',NULL,'2031-11-04 15:50:52',1012)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('N.cer','11','12','2031-11-04 15:50:52',1013)")

		cur.execute("INSERT INTO rpki_dir(dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/EEcertificates/rpki.apnic.net/repository/B4A1BEA61D6611E2B2CD8B7C72FD1FF2', 1011)")
		cur.execute("INSERT INTO rpki_dir(dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/EEcertificates/rpki.apnic.net/repository/B4A1BEA61D6611E2B2CD8B7C72FD1FF2', 1012)")
		cur.execute("INSERT INTO rpki_dir(dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/EEcertificates/rpki.apnic.net/repository/B4A1BEA61D6611E2B2CD8B7C72FD1FF2', 1013)")	

		# 2 node swingpoint (direct ancestor)
		# source: K.cer, target: L.cer
		# vice-versa
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('K.cer','13','14','2031-11-04 15:50:52',1014)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('L.cer','14',NULL,'2031-11-04 15:50:52',1015)")
		
		con.commit()

	except MySQLdb.Error, e:
		if con: con.rollback()
		print "Error %d: %s" % (e.args[0],e.args[1])
		sys.exit(1)

	finally:
		if con: con.close()
	

def dbdown():

	try:
		
		con = MySQLdb.connect(
			host='localhost', 
			user='rpstir', 
			passwd='bbn', 
			db='rpstir_test', 
			cursorclass=MySQLdb.cursors.DictCursor
		)
		cur = con.cursor()
		cur.execute("TRUNCATE TABLE rpki_cert;")
		cur.execute("TRUNCATE TABLE rpki_dir;")
		#cur.execute("DELETE FROM rpki_cert WHERE local_id > 1000 AND local_id < 1020;")
	except MySQLdb.Error, e:
		if con: con.rollback()
		print "Error %d: %s" % (e.args[0],e.args[1])
		sys.exit(1)

	finally:
		if con: con.close()

