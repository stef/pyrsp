from platform import machine
from unittest import main, TestCase
from subprocess import Popen
from struct import pack

from os.path import split, join

test_dir = split(__file__)[0]
parent_dir = split(test_dir)[0]

# adjust PYTHONPATH to import pyrsp
from sys import path as PYTHONPATH
PYTHONPATH.insert(0, parent_dir)
from pyrsp.rsp import archmap, CortexM3
from pyrsp.utils import find_free_port, wait_for_tcp_port, QMP


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
        self._target.run(setpc=False)


class TestARM(TestCase):

    def setUp(self):
        self.example_dir = join(parent_dir, "example")
        self.elf_path = join(self.example_dir, "test.elf")

        self.assertEqual(run("make", cwd = self.example_dir), 0)
        rsp_port = find_free_port()
        qmp_port = find_free_port(rsp_port + 1)
        if (rsp_port or qmp_port) is None:
            raise RuntimeError("Cannot find free port!")
        self._port = str(rsp_port)
        qargs = [
            "qemu-system-arm",
            "-machine", "netduino2",
            "-kernel", self.elf_path,
            "-S", # guest is initially stopped
            "-gdb", "tcp:localhost:" + self._port,
            # QEMU monitor protocol for VM management
            "-qmp", "tcp:localhost:%u,server,nowait" % qmp_port,
            # do not create a window
            "-nographic"
        ]
        print(" ".join(qargs))
        self._qemu = qemu = Popen(qargs)

        if (not wait_for_tcp_port(qmp_port)
            or not wait_for_tcp_port(rsp_port)
            or qemu.returncode is not None
        ):
            raise RuntimeError("QEMU malfunction")

        self.qmp = QMP(qmp_port)

        self._target = CortexM3(self._port,
            elffile = self.elf_path,
            verbose = True
        )


    def test_example(self):
        target = self._target

        # Initialize reset vector to entry point address (with 0-th bit set)
        # and reset the board. It will switch the CPU to Thumb mode.
        target[4] = pack("<I", target.elf.entry)
        self.qmp("system_reset")

        target.set_br("rsp_finish", target.finish_cb)
        target.set_br("rsp_dump", target.dump_cb)
        target.run()

    def tearDown(self):
        self._qemu.terminate()

if __name__ == "__main__":
    main()
