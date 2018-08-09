from distutils.core import setup
import py2exe, sys, os

sys.argv.append('py2exe')

setup(
    options = {'py2exe': {'includes':['Tkinter','tkFileDialog','shutil','os','xlrd','xlwt'],'bundle_files': 1, 'compressed': True}},
    windows = [{'script': "gui.py"}],
    zipfile = None,
)
