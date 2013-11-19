import unittest
from swingpoint import swingpoint
import seeddb as seed

class TestSwingpoint(unittest.TestCase):
	def setUp(self):
		#seed.dbdown
		pass
	## No Source File
	def test_InvalidSource(self):
		source = ""
		target = "B.cer"
		self.assertRaises(SystemExit, lambda: swingpoint(source, target))
	## No Target File
	def test_InvalidTarget(self):
		source = "A.cer"
		target = ""	
		self.assertRaises(SystemExit, lambda: swingpoint(source, target))
	## Source Not Found
	def test_SourceNotFound(self):
		source = "Z.cer"
		target = "B.cer"
		self.assertRaises(SystemExit, lambda: swingpoint(source, target))
	## Target Not Found
	def test_TargetNotFound(self):
		source = "A.cer"
		target = "Z.cer"
		self.assertRaises(SystemExit, lambda: swingpoint(source, target))
	## Source does not have an AKI
	def test_SourceTargetInvalidAKI(self):
		source = "J.cer"
		target = "J.cer"
		self.assertRaises(SystemExit, lambda: swingpoint(source, target))
	def test_MultipleParents(self):
		source = "A.cer"
		target = "B.cer"
		expected = "Swingpoints: ['G.cer', 'GPRIME.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)
	def test_SingleParent(self):
		source = "M.cer"
		target = "N.cer"
		expected = "Swingpoints: ['O.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)		
	def test_SwingpointIsTarget(self):
		source = "K.cer"
		target = "L.cer"
		expected = "Swingpoints: ['L.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)

if __name__ == '__main__':
	seed.dbdown()
	seed.dbup()
	unittest.main()
