import lit
import os
import tempfile

config.name = "thorin"
config.test_format = lit.formats.ShTest(True)
config.excludes = ['inputs']
config.suffixes = ['.s', '.test']
config.test_source_root = os.path.dirname(__file__)
config.test_exec_root = tempfile.TemporaryDirectory().name
