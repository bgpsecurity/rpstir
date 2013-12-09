import unittest
import swingpointUtility as util

class TestUtility(unittest.TestCase):
	def setUp(self):
		pass
	def test_Balanced(self):
		source = {1: {'aki': 'C', 'ski': 'A', 'depth': 0, 'filename': 'A.cer'}, 2: {'aki': 'E', 'ski': 'C', 'depth': 1, 'filename': 'C.cer'}, 3: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'F.cer'}, 4: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'E.cer'}}
		target = {1: {'aki': 'D', 'ski': 'B', 'depth': 0, 'filename': 'B.cer'}, 2: {'aki': 'E', 'ski': 'D', 'depth': 1, 'filename': 'D.cer'}, 3: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'F.cer'}, 4: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'E.cer'}}
		source,target = util.balance(source,target)
		self.assertEqual(source[1]['depth'],target[1]['depth'])
		self.assertIsNotNone(source)
		self.assertIsNotNone(target)
	def test_UnBalanced(self):
		visual = {}
		source = {1: {'aki': 'E', 'ski': 'A', 'depth': 0, 'filename': 'A.cer'}, 2: {'aki': None, 'ski': 'E', 'depth': 1, 'filename': 'F.cer'}, 3: {'aki': None, 'ski': 'E', 'depth': 1, 'filename': 'E.cer'}}
		target = {1: {'aki': 'D', 'ski': 'B', 'depth': 0, 'filename': 'B.cer'}, 2: {'aki': 'E', 'ski': 'D', 'depth': 1, 'filename': 'D.cer'}, 3: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'F.cer'}, 4: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'E.cer'}}
		source,target = util.balance(source,target)
		self.assertNotEqual(source[1]['depth'],target[1]['depth'])
		self.assertIsNotNone(source)
		self.assertIsNotNone(target)

	def test_Intersection(self):
		result = {}
		source = {1: {'aki': 'C', 'ski': 'A', 'depth': 0, 'filename': 'A.cer'}, 2: {'aki': 'E', 'ski': 'C', 'depth': 1, 'filename': 'C.cer'}, 3: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'F.cer'}, 4: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'E.cer'}}
		target = {1: {'aki': 'D', 'ski': 'B', 'depth': 0, 'filename': 'B.cer'}, 2: {'aki': 'E', 'ski': 'D', 'depth': 1, 'filename': 'D.cer'}, 3: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'F.cer'}, 4: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'E.cer'}}
		result = util.intersection(source,target)
		self.assertIsNotNone(result)
		self.assertEqual(result, {1: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'F.cer'}, 2: {'aki': None, 'ski': 'E', 'depth': 2, 'filename': 'E.cer'}})
		

if __name__ == '__main__':
	unittest.main()
