from platform import machine
from unittest import main, TestCase
from subprocess import Popen
from struct import pack

from os.path import split, join, splitext

test_dir = split(__file__)[0]
parent_dir = split(test_dir)[0]

# adjust PYTHONPATH to import pyrsp
from sys import path as PYTHONPATH
PYTHONPATH.insert(0, parent_dir)
from pyrsp.rsp import archmap
from pyrsp.utils import find_free_port, wait_for_tcp_port, QMP


def run(*args, **kw):
    return Popen([a for a in args if a], **kw).wait()


class GCCBuilder(object):

    # SRC - path to source file, must be specified by child classes
    # EXE - path to executable file with debug info for both
    #       RSP server & client, defined by that helper
    DEFS = {}
    LIBS = []
    EXTRA_CFLAGS = ""
    GCC_PREFIX = ""

    def __build__(self):
        # ".exe" is not required by nix but for Windows it is.
        self.EXE = splitext(self.SRC)[0] + ".exe"
        LDFLAGS = " ".join(("-l" + l) for l in self.LIBS)
        CFLAGS = " ".join("-D%s=%s" % (D, V) for D, V in self.DEFS.items())
        self.assertEqual(
            run(self.GCC_PREFIX + "gcc", "-no-pie", "-o", self.EXE, "-g", "-O0",
                CFLAGS, self.EXTRA_CFLAGS, self.SRC, LDFLAGS),
            0
        )


class ExampleBuilder(object):

    def __build__(self):
        self.example_dir = join(parent_dir, "example")
        self.EXE = join(self.example_dir, "test.elf")

        self.assertEqual(run("make", cwd = self.example_dir), 0)


class TestRSP(TestCase):
    noack = False
    # CPU architecture of RSP target.
    arch = machine()

    def __build__(self):
        "Child class my build something before debugging start"

    def __start_gdb__(self, port):
        raise NotImplementedError("Child class must launch GDB server or"
            " any GDB RSP compatible server on given port %u" % port)

    # EXE must be defined by child classes. EXE is path to executable file
    # under debug, with debug info. It must be defined before __start_gdb__
    # returned.

    def setUp(self):
        try:
            rsp = archmap[self.arch]
        except KeyError:
            self.skipTest("No RSP target for " + machine())
            return

        rsp_port = find_free_port()
        if rsp_port is None:
            raise RuntimeError("Cannot find free port!")

        self.__build__()
        self.__start_gdb__(rsp_port)

        # Wait for server to start listening.
        if not wait_for_tcp_port(rsp_port) or self._gdb.returncode is not None:
            raise RuntimeError("server malfunction")

        self._target = rsp(str(rsp_port),
            elffile = self.EXE,
            verbose = True,
            noack = self.noack,
            noshell = True
        )

    def tearDown(self):
        self._gdb.terminate()


class TestUser(GCCBuilder, TestRSP):
    "Test for userspace program debugging."

    def __start_gdb__(self, port):
        self._gdb = Popen(["gdbserver", "localhost:%u" % port, self.EXE])


class TestUserSimple(TestUser):
    SRC = join(test_dir, "test-simple.c")

    def test_simple(self):
        self._target.run(setpc=False)

    def test_br(self):
        target = self._target

        def br():
            self._br = True
            target.step_over_br()

        target.set_br("main", br)

        self._br = False
        target.run(setpc=False)
        self.assertTrue(self._br, "breakpoint skipped")

    def test_overwrite_br(self):
        target = self._target
        target.set_br("main", None)
        # a `KeyError` expected there in buggy version
        target.set_br("main", None)

    def test_set_reg_int(self):
        target = self._target

        # Because target is not started yet, a register cannot be set.
        # So, do it during a breakpoint.
        def set_reg():
            reg_name = target.registers[4] # not a first register
            cur_val = int(getattr(target, reg_name), 16)

            bits = target.arch['bitsize']
            shift = bits - 5 # a bit within MSB
            new_val = (cur_val + (1 << shift) + 1) & ((1 << bits) - 1)

            target.set_reg(reg_name, new_val)

            target.dump_regs()
            self.assertEqual(int(getattr(target, reg_name), 16), new_val,
                             "the register was not set")
            target.step_over_br()

        target.set_br("main", set_reg)
        target.run(setpc=False)

    def test_read_0(self):
        "Test `dump` behavior on inaccessible target memory."
        target = self._target


        def br():
            # memory at 0 must not be readable for a user process
            with self.assertRaises(RuntimeError) as ctx:
                print("bytes at 0: %r" % target.dump(4, 0))

            print(ctx.exception)

            target.step_over_br()

        target.set_br("main", br)

        target.run(setpc=False)


class TestUserCalls(TestUser):
    DEFS = dict(NUM_CALLS = 10)
    SRC = join(test_dir, "test-calls.c")

    def test_br_trace(self):
        target = self._target

        def br():
            self._traces += 1
            target.step_over_br()

        target.set_br("trace", br)

        self._traces = 0
        target.run(setpc = False)
        self.assertEqual(self._traces, self.DEFS["NUM_CALLS"],
                         "incorrect breakpoint stops count")


class TestUserThreads(TestUser):
    DEFS = dict(NUM_THREADS = 20)
    SRC = join(test_dir, "test-threads.c")
    LIBS = ["pthread"]


    def test_br_trace(self):
        target = self._target

        def br():
            self._traces += 1
            target.step_over_br()

        target.set_br("trace", br)

        self._traces = 0
        target.run(setpc = False)
        self.assertEqual(self._traces, self.DEFS["NUM_THREADS"],
                         "incorrect breakpoint stops count")


class TestUserMemory(TestUser):
    DEFS = dict(NUB_KIBS = 10)
    SRC = join(test_dir, "test-memory.c")

    def test_dump(self):
        target = self._target

        expected = b'f' * (self.DEFS["NUB_KIBS"] << 10)

        def br():
            ptr = int(target.get_arg(1), 16)
            size = int(target.get_arg(2), 16)
            data = target[ptr:ptr + size]
            self.assertEqual(data, expected, "incorrect data")
            target.step_over_br()

        target.set_br("rsp_dump", br)

        target.run(setpc = False)

    def test_vfffff(self):
        target = self._target

        # In hexadecimal "vfffff" is 766666666666 ('7' + '6' * 11).
        # In run-length encoded packet it is $76*'#xx where xx is place of
        # checksum. "'" is before "#" because ord("'") - 29 == 10.
        # That means "repeat previous character 10 times yet".
        # I.e. '6' + '6' * 10, see run-length encoding of GDB RSP for details.
        expected = b"vfffff"

        def br():
            ptr = int(target.get_arg(1), 16)
            target[ptr] = expected
            data = target[ptr:ptr + len(expected)]
            self.assertEqual(data, expected, "incorrect data")
            target.step_over_br()

        target.set_br("rsp_dump", br)

        target.run(setpc = False)


class TestUserCallback(TestUser):
    SRC = join(test_dir, "test-callback.c")

    def test_br_at_addr(self):
        target = self._target

        def br_callback():
            self._br = True
            target.step_over_br()

        def br_caller():
            # get the callback address and set a breakpoint on it
            cb_addr_str = target.get_arg(1)
            target.set_br_a(cb_addr_str, br_callback)
            target.step_over_br()

        # assume that we known caller address only
        target.set_br("caller", br_caller)

        self._br = False
        target.run(setpc = False)
        self.assertTrue(self._br, "breakpoint skipped")


class QemuI386Launcher(GCCBuilder, TestRSP):
    arch = "i386"

    def __start_gdb__(self, port):
        qargs = [
            "qemu-i386",
            "-g", str(port),
            self.EXE
        ]

        self._gdb = Popen(qargs)


class QemuUserI386(QemuI386Launcher, GCCBuilder):
    EXTRA_CFLAGS = "-m32"
    CROSS_PREFIX = "x86_64-linux-gnu-"


class TestUserI386FastCall(QemuUserI386, TestRSP):
    SRC = join(test_dir, "test-fastcall.c")

    def test_br(self):
        target = self._target
        def br():
            self._br = True
            target.step_over_br()

        self._br = False
        target.set_br("foo", br)
        target.run(setpc = False)
        self.assertTrue(self._br, "breakpoint skipped")

    def test_fastcall(self):
        target = self._target
        def br():
            self.assertEqual(int(target.get_arg(1), 16), 0xDEADBEEF,
                "foo argument has unexpected value")
            target.step_over_br()

        target.set_br("foo", br)
        target.run(setpc = False)


class TestARM(ExampleBuilder, TestRSP):
    arch = "cortexm3"

    def __start_gdb__(self, rsp_port):
        qmp_port = find_free_port(rsp_port + 1)
        if qmp_port is None:
            raise RuntimeError("Cannot find free port for Qemu QMP!")

        qargs = [
            "qemu-system-arm",
            "-machine", "netduino2",
            "-kernel", self.EXE,
            "-S", # guest is initially stopped
            "-gdb", "tcp:localhost:%u" % rsp_port,
            # QEMU monitor protocol for VM management
            "-qmp", "tcp:localhost:%u,server,nowait" % qmp_port,
            # do not create a window
            "-nographic"
        ]
        print(" ".join(qargs))
        self._gdb = qemu = Popen(qargs)

        if not wait_for_tcp_port(qmp_port) or qemu.returncode is not None:
            raise RuntimeError("QEMU malfunction")

        self.qmp = QMP(qmp_port)

    def test_example(self):
        target = self._target

        # Initialize reset vector to entry point address (with 0-th bit set)
        # and reset the board. It will switch the CPU to Thumb mode.
        target[4] = pack("<I", target.elf.entry)
        self.qmp("system_reset")

        target.set_br("rsp_finish", target.finish_cb)
        target.set_br("rsp_dump", target.dump_cb)
        target.run()

    def test_set_reg_int(self):
        target = self._target
        new_val = (int(target.r1, 16) + (1 << 20) + 1) & ((1 << 32) - 1)
        target.set_reg("r1", new_val)
        target.dump_regs()
        self.assertEqual(int(target.r1, 16), new_val,
                         "the register was not set")

# Generate NoAck Variants of tests

def makeNoAckAttrs(base):
    """ Use a function factory to avoid the late binding problem.
See: https://stackoverflow.com/questions/3431676/creating-functions-in-a-loop
    """

    def setUp(self):
        base.setUp(self)
        if self._target.ack:
            self.tearDown()
            self.skipTest(
                "Used version of gdbserver does not support NoAck mode."
                " The mode has not been tested."
            )

    return dict(setUp = setUp, noack = True)

for test in (
    TestUserSimple,
    TestUserCalls,
    TestUserThreads,
    TestUserCallback,
    TestUserMemory
):
    NoAck = test.__name__ + "NoAck"
    globals()[NoAck] = type(NoAck, (test,), makeNoAckAttrs(test))

del test # else, this variable will be a yet another test

class TestARMNoAck(TestARM):
    noack = True

    def setUp(self):
        super(TestARMNoAck, self).setUp()
        if self._target.ack:
            self.tearDown()
            self.skipTest("Used version of QEMU does not support NoAck mode."
                " The mode has not been tested."
            )


if __name__ == "__main__":
    main()
