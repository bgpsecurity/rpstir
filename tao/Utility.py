def balance(source,target):
		visual = {}
		## Loads visualization for balanced graph
		if len(source) == len(target):
			for i in range(1, len(source)+1):
				if(not(source[i] in visual.itervalues())):
					visual[len(visual)+1] = source[i]
				if(not(target[i] in visual.itervalues())):
					visual[len(visual)+1] = target[i]
		## Loads visualization for unbalanced graph towards source and adjusts for the depth difference
		if len(source) > len(target):
			diff = source[len(source)]['depth'] - target[len(target)]['depth']
			for i in range(1, len(source)+1):
				if(not(source[i] in visual.itervalues())):
					visual[len(visual)+1] = source[i]
				if(not(i > len(target))) and (not(target[i] in visual.itervalues())):
					target[i]['depth'] += diff
					visual[len(visual)+1] = target[i]
		## Loads visualization for unbalanced graph towards target and adjusts for the depth difference
		if len(source) < len(target):
			diff = target[len(target)]['depth'] - source[len(source)]['depth']
			for i in range(1, len(target)+1):
				if(not(target[i] in visual.itervalues())):
					visual[len(visual)+1] = target[i]
				if(not(i > len(source))) and (not(source[i] in visual.itervalues())):
					source[i]['depth'] += diff
					visual[len(visual)+1] = source[i]
		return source,target,visual

def intersection(source,target):
	results = {}
	for i in range(1, len(source)+1):
		for x in range(1, len(target)+1):
			if source[i]  == target[x]:
					#depth = source[i]['depth'] + target[x]['depth']
					results[len(results)+1] = source[i]
	return results

