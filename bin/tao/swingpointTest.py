import unittest
from swingpoint import swingpoint

class TestSwingpoint(unittest.TestCase):
	def setUp(self):
		pass
	## No Source File
	def test_InvalidSource(self):
		source = ""
		target = "B.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	## No Target File
	def test_InvalidTarget(self):
		source = "A.cer"
		target = ""
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	## Source Not Found
	def test_SourceNotFound(self):
		source = "Z.cer"
		target = "B.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	## Target Not Found
	def test_TargetNotFound(self):
		source = "A.cer"
		target = "Z.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	## Source does not have an AKI
	def test_SourceInvalidAKI(self):
		source = "X.cer"
		target = "Y.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	## Target does not have an AKI
	def test_TargetInvalidAKI(self):
		source = "X.cer"
		target = "Y.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
if __name__ == '__main__':
	unittest.main()
