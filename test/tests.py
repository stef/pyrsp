from platform import machine
from unittest import main, TestCase
from subprocess import Popen

from os.path import split, join

test_dir = split(__file__)[0]
parent_dir = split(test_dir)[0]

# adjust PYTHONPATH to import pyrsp
from sys import path as PYTHONPATH
PYTHONPATH.insert(0, parent_dir)
from pyrsp.rsp import archmap
from pyrsp.utils import find_free_port, wait_for_tcp_port


def run(*args, **kw):
    return Popen([a for a in args if a], **kw).wait()


class TestUser(TestCase):
    "Test for userspace program debugging."

    DEFS = {}
    # SRC, EXE must be defined by child classes
    LIBS = []

    def setUp(self):
        try:
            rsp = archmap[machine()]
        except KeyError:
            self.skipTest("No RSP target for " + machine())
            return

        LDFLAGS = " ".join(("-l" + l) for l in self.LIBS)
        CFLAGS = " ".join("-D%s=%s" % (D, V) for D, V in self.DEFS.items())
        self.assertEqual(
            run("gcc", "-o", self.EXE, "-g", "-O0", CFLAGS, self.SRC, LDFLAGS),
            0
        )
        rsp_port = find_free_port()
        if rsp_port is None:
            raise RuntimeError("Cannot find free port!")
        self._port = port = str(rsp_port)
        self._gdb = gdb = Popen(["gdbserver", "localhost:" + port, self.EXE])

        # Wait for gdb to start listening.
        if not wait_for_tcp_port(rsp_port) or gdb.returncode is not None:
            raise RuntimeError("gdbserver malfunction")

        self._target = rsp(self._port, elffile = self.EXE, verbose = True)

    def tearDown(self):
        self._gdb.terminate()


class TestUserSimple(TestUser):
    SRC = join(test_dir, "test-simple.c")
    # ".exe" is not required by nix but for Windows it is.
    EXE = join(test_dir, "test-simple.exe")

    def test_simple(self):
        self._target.run("main")


if __name__ == "__main__":
    main()
