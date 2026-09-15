from miasm.analysis.machine import Machine

from sibyl.learn.learn import TestCreator


class Generator:
    '''
    Abstract class used to represent a generator
    A generator is a class that create a test from a snapshot
    Here a test is a sibyl test init function and a sibyl test check function
    '''

    def __init__(self, testcreator: TestCreator):
        '''
        @testcreator: TestCreator instance with associated information
        '''
        self.trace = testcreator.trace
        self.prototype = testcreator.prototype
        self.learnexceptiontext = testcreator.learnexceptiontext
        self.types = testcreator.types
        self.printer = Printer()
        self.headerfile = testcreator.headerfile
        self.lifter_model_call = Machine(testcreator.machine).lifter_model_call(testcreator.loc_db)
        self.ptr_size = self.lifter_model_call.sizeof_pointer()//8
        self.logger = testcreator.logger

    def generate_test(self):
        '''Abstract method that should return the string corresponding to the code of the init test'''
        raise NotImplementedError("Abstract method")


class Printer:

    default_indentation_size = 4

    def __init__(self, indentation_size=default_indentation_size):
        self._indentation_size = indentation_size
        self._indentation_level = 0
        self._whitespace = ""
        self._print = ""

    def dump(self):
        return self._print

    def sub_lvl(self, n=1):
        self._indentation_level -= self._indentation_size * n

        if self._indentation_level < 0:
            raise RuntimeError("indentation level negative")

        self._whitespace = " "*self._indentation_level

    def add_lvl(self, n=1):
        self._indentation_level += self._indentation_size * n
        self._whitespace = " "*self._indentation_level

    def add_block(self, block):
        self._print += (self._whitespace + block).replace('\n', '\n'+self._whitespace).rstrip(' ')

    def add_empty_line(self):
        self._print += '\n'

    def add_lower_block(self, block, n=1):
        self.sub_lvl(n)
        self.add_block(block)
        self.add_lvl(n)

    def add_upper_block(self, block, n=1):
        self.add_lvl(n)
        self.add_block(block)
        self.sub_lvl(n)
