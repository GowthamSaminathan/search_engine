import shutil

def copyDirectory(src, dest):
	try:
		shutil.copytree(src, dest)
	# Directories are the same
	except Exception as e:
		print('Directory not copied. Error: %s' % e)
	# Any error saying that the directory doesn't exist