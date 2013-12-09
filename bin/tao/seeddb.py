###
# Program: seeddb.py
# Author(s): Brian Buchanan, John Slivka, Elijah Batkoski
# Description: Provides functions that upload the test database with test cases and clears the test 
# 	databasefor testing swingpoint.py.  
###
import MySQLdb
import sys

def dbup():
	print "HERE"	
	try:
		con = getCon()
		cur = con.cursor()

		# multiple certificates with same SKI and different valto(s) expiration
		# source: A.cer, target: B.cer
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('A.cer','1','2','2031-11-04 15:50:52',1101)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('B.cer','7','6','2031-11-04 15:50:52',1102)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('C.cer','2','3','2031-11-04 15:50:52',1103)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('CPRIME.cer','2','3','2030-11-04 15:50:52',1104)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('D.cer','6','3','2031-11-04 15:50:52',1105)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('DPRIME.cer','6','3','2030-11-04 15:50:52',1106)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('G.cer','3','4','2031-11-04 15:50:52',1107)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('GPRIME.cer','3','4','2030-11-04 15:50:52',1108)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('I.cer','4','5','2021-11-04 15:50:52',1109)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('J.cer','5',NULL,'2021-11-04 15:50:52',1110)")

		# 3 node swingpoint
		# source: M.cer, target: N.cer
		# vice-versa
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('M.cer','10','12','2031-11-04 15:50:52',1111)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('O.cer','12',NULL,'2031-11-04 15:50:52',1112)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('N.cer','11','12','2031-11-04 15:50:52',1113)")

		# 2 node swingpoint (direct ancestor)
		# source: K.cer, target: L.cer
		# vice-versa
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('K.cer','13','14','2031-11-04 15:50:52',1114)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('L.cer','14',NULL,'2031-11-04 15:50:52',1115)")

		# multiple certificates with same SKI and different valto(s) expiration
		# one parent has null AKI, other has valid AKI
		# source: A.cer, target: B.cer
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('AA.cer','111','222','2031-11-04 15:50:52',1201)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('BB.cer','777','66','2031-11-04 15:50:52',1202)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('CC.cer','222','NULL','2031-11-04 15:50:52',1203)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('CCPRIME.cer','222','333','2030-11-04 15:50:52',1204)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('DD.cer','66','333','2031-11-04 15:50:52',1205)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('DDPRIME.cer','66','NULL','2030-11-04 15:50:52',1206)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('GG.cer','333','444','2031-11-04 15:50:52',1207)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('GGPRIME.cer','333','444','2030-11-04 15:50:52',1208)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('II.cer','444','555','2021-11-04 15:50:52',1209)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('JJ.cer','555',NULL,'2021-11-04 15:50:52',1210)")

		# multiple certificates with same SKI and different valto(s) expiration
		# not actual hex values, ends with XX, letter, etc g, gg denotes a g prime
		# source: A.cer, target: B.cer
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0a.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:01','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:02','2031-11-04 15:50:52',1001)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0b.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:07','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:06','2031-11-04 15:50:52',1002)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0c.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:02','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:03','2031-11-04 15:50:52',1003)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8fcc.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:02','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:03','2030-11-04 15:50:52',1004)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0d.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:06','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:03','2031-11-04 15:50:52',1005)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8fdd.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:06','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:03','2030-11-04 15:50:52',1006)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0g.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:03','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:04','2031-11-04 15:50:52',1007)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8fgg.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:03','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:04','2030-11-04 15:50:52',1008)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0i.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:04','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:05','2021-11-04 15:50:52',1009)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0j.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:05',NULL,'2021-11-04 15:50:52',1010)")

		# 3 node swingpoint
		# source: M.cer, target: N.cer
		# vice-versa
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0m.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:10','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:12','2031-11-04 15:50:52',1011)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0o.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:12',NULL,'2031-11-04 15:50:52',1012)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0n.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:11','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:12','2031-11-04 15:50:52',1013)")

		# 2 node swingpoint (direct ancestor)
		# source: K.cer, target: L.cer
		# vice-versa
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0k.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:0C','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:0D','2031-11-04 15:50:52',1014)")
		cur.execute("INSERT INTO rpki_cert(filename,ski,aki,valto,local_id) VALUES('fd1f287669507cad7f87e6ac87af2e9fd54b8f0l.cer','FD:1F:28:76:69:50:7C:AD:7F:87:E6:AC:87:AF:2E:9F:D5:4B:8F:0D',NULL,'2031-11-04 15:50:52',1015)")
		
		# insert some directory data
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1001)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1002)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1003)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1004)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1005)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1006)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1007)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1008)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1009)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1010)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1011)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1012)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1013)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1014)")
		cur.execute("INSERT INTO rpki_dir (dirname, dir_id) VALUES ('/usr/local/var/cache/rpstir/repository.lacnic.net/rpki/lacnic',1015)")

		# metadata
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1001)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1002)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1003)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1004)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1005)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1006)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1007)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1008)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1009)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1010)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1011)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1012)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1013)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1014)")
		cur.execute("INSERT INTO rpki_metadata (rootdir, local_id) VALUES ('/usr/local/var/cache/rpstir',1015)")

		cur.execute("UPDATE rpki_cert SET subject = '/CN=52415bf6-482b' WHERE 1;")

		con.commit()

	except MySQLdb.Error, e:
		if con: con.rollback()
		print "Error %d: %s" % (e.args[0],e.args[1])
		sys.exit(1)

	finally:
		if con: con.close()
	

def dbdown():
	try:
		con = getCon()
		cur = con.cursor()
		cur.execute("TRUNCATE TABLE rpki_cert;")
		cur.execute("TRUNCATE TABLE rpki_dir;")
		cur.execute("TRUNCATE TABLE rpki_metadata;")

	except MySQLdb.Error, e:
		if con: con.rollback()
		print "Error %d: %s" % (e.args[0],e.args[1])
		sys.exit(1)

	finally:
		if con: con.close()

def getCon():
	return MySQLdb.connect(
			host='localhost', 
			user='rpstir', 
			passwd='bbn', 
			db='rpstir_test', 
			cursorclass=MySQLdb.cursors.DictCursor
		)
