import unittest
from swingpoint import swingpoint

class TestSwingpoint(unittest.TestCase):
	def setUp(self):
		pass
	def test_InvalidSource(self):
		source = ""
		target = "B.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	def test_InvalidTarget(self):
		source = "A.cer"
		target = ""
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	def test_SourceNotFound(self):
		source = "Z.cer"
		target = "B.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	def test_TargetNotFound(self):
		source = "A.cer"
		target = "Z.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	def test_SourceInvalidAKI(self):
		source = "X.cer"
		target = "Y.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
	def test_TargetInvalidAKI(self):
		source = "X.cer"
		target = "Y.cer"
		self.assertRaises(Exception, lambda: swingpoint(source, target))
if __name__ == '__main__':
	unittest.main()
