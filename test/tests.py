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


class TestRSP(TestCase):
    noack = False


class TestUser(TestRSP):
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

        # Passing function arguments through registers
        self._arg2reg = {
            "i386" : ("ecx", "edx") # fastcall calling convention is assumed
          , "x86_64" : ("rdi", "rsi")
          , "arm" : ("r0", "r1")
        }.get(machine(), None)

        LDFLAGS = " ".join(("-l" + l) for l in self.LIBS)
        CFLAGS = " ".join("-D%s=%s" % (D, V) for D, V in self.DEFS.items())
        self.assertEqual(
            run("gcc", "-no-pie", "-o", self.EXE, "-g", "-O0", CFLAGS, self.SRC, LDFLAGS),
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

        self._target = rsp(self._port,
            elffile = self.EXE,
            verbose = True,
            noack = self.noack,
            noshell = True
        )

    def tearDown(self):
        self._gdb.terminate()


class TestUserSimple(TestUser):
    SRC = join(test_dir, "test-simple.c")
    # ".exe" is not required by nix but for Windows it is.
    EXE = join(test_dir, "test-simple.exe")

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
    EXE = join(test_dir, "test-calls.exe")

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
    EXE = join(test_dir, "test-threads.exe")
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
    EXE = join(test_dir, "test-memory.exe")


    def test_dump(self):
        target = self._target

        expected = b'f' * (self.DEFS["NUB_KIBS"] << 10)

        def br():
            ptr = int(target.regs[self._arg2reg[0]], 16)
            size = int(target.regs[self._arg2reg[1]], 16)
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
            ptr = int(target.regs[self._arg2reg[0]], 16)
            target[ptr] = expected
            data = target[ptr:ptr + len(expected)]
            self.assertEqual(data, expected, "incorrect data")
            target.step_over_br()

        target.set_br("rsp_dump", br)

        target.run(setpc = False)


class TestUserCallback(TestUser):
    SRC = join(test_dir, "test-callback.c")
    EXE = join(test_dir, "test-callback.exe")

    def test_br_at_addr(self):
        target = self._target

        def br_callback():
            self._br = True
            target.step_over_br()

        def br_caller():
            # get the callback address and set a breakpoint on it
            cb_addr_str = target.regs[self._arg2reg[0]]
            target.set_br_a(cb_addr_str, br_callback)
            target.step_over_br()

        # assume that we known caller address only
        target.set_br("caller", br_caller)

        self._br = False
        target.run(setpc = False)
        self.assertTrue(self._br, "breakpoint skipped")


class TestARM(TestRSP):

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
            verbose = True,
            noack = self.noack
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

    def test_set_reg_int(self):
        target = self._target
        new_val = (int(target.r1, 16) + (1 << 20) + 1) & ((1 << 32) - 1)
        target.set_reg("r1", new_val)
        target.dump_regs()
        self.assertEqual(int(target.r1, 16), new_val,
                         "the register was not set")

    def tearDown(self):
        self._qemu.terminate()

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
