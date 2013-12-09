import unittest
from swingpoint import swingpoint
import seeddb as seed

class TestSwingpoint(unittest.TestCase):
	def setUp(self):
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
	## Source and Target does not have an AKI
	def test_SourceTargetInvalidAKI(self):
		source = "J.cer"
		target = "J.cer"
		self.assertRaises(SystemExit, lambda: swingpoint(source, target))
	## Multiple Parents Swinpoint Test	
	def test_MultipleParents(self):
		source = "A.cer"
		target = "B.cer"
		expected = "Swingpoints: ['G.cer', 'GPRIME.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)
	## Singple Parent Swingpoint Test
	def test_SingleParent(self):
		source = "M.cer"
		target = "N.cer"
		expected = "Swingpoints: ['O.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)
	## Swingpoint is Target Test		
	def test_SwingpointIsTarget(self):
		source = "K.cer"
		target = "L.cer"
		expected = "Swingpoints: ['L.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)
	## No Swingpoint(Different Trust Anchors)	
	def test_DifferentTrustAnchor(self):
		source = "A.cer"
		target = "L.cer"
		expected = "Swingpoints: []"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)
	## A is farther from Swingpoint Than D	
	def test_UnbalancedGraph(self):
		source = "A.cer"
		target = "D.cer"
		expected = "Swingpoints: ['G.cer', 'GPRIME.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)
 	## Multiple Parents Swinpoint Test with Simulated Data    
        def test_MultipleParentsSimulatedData(self):
                source = "fd1f287669507cad7f87e6ac87af2e9fd54b8f0a.cer"
                target = "fd1f287669507cad7f87e6ac87af2e9fd54b8f0b.cer"
                expected = "Swingpoints: ['fd1f287669507cad7f87e6ac87af2e9fd54b8f0g.cer', 'fd1f287669507cad7f87e6ac87af2e9fd54b8fgg.cer']"
                result = swingpoint(source, target)
                self.assertEqual(expected, result)
	## Multiple Parents But One Parent has NULL AKI
	def test_MultipleParentsOneNull(self):
		source = "AA.cer"
		target = "BB.cer"
		expected = "Swingpoints: ['GG.cer', 'GGPRIME.cer']"
		result = swingpoint(source, target)
		self.assertEqual(expected, result)

if __name__ == '__main__':
	seed.dbdown()
	seed.dbup()	
	unittest.main()

