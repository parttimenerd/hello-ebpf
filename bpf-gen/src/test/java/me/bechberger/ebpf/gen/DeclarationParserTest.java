package me.bechberger.ebpf.gen;

import me.bechberger.ebpf.gen.Generator.Type.FuncType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class DeclarationParserTest {

    private Generator gen;

    @BeforeEach
    public void setUp() {
        gen = new Generator("");
    }

    @ParameterizedTest
    @CsvSource(value = {"static void (* const print)(void) = (void*) 0;|void print()", "static void (* const print)" +
            "(int i) = (void*) 0;|void print(int i)", "static void (* const print)(int i, int j) = (void*) 0;|void " +
            "print(int i, int j)",
            // more complex examples with pointers
            "static void (* const print)(int* i, int j) = (void*) 0;|void print(Ptr<java.lang.Integer> i, int j)",
            // and structs
            "static void (* const print)(struct A i, int j) = (void*) 0;|void print(A i, int j)",
            // and return values
            "static int (* const print)(int i) = (void*) 0;|int print(int i)",
            // and more complex return values
            "static int* (* const print)(int i) = (void*) 0;|Ptr<java.lang.Integer> print(int i)", "static const int*" +
            " (* const print)(int i) = (void*) 0;|Ptr<java.lang.Integer> print(int i)",
            // and var args
            "static void (* const print)(...) = (void*) 0;|void print(java.lang.Object... args)",
            // and real-world examples
            "static long (* const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;|long " +
                    "bpf_trace_printk(String fmt, @Unsigned int fmt_size, java.lang.Object... args)", "static long (*" +
            " const bpf_xdp_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 121;|long " +
            "bpf_xdp_output(Ptr<?> ctx, Ptr<?> map, @Unsigned long flags, Ptr<?> data, @Unsigned long size)", "static" +
            " long (* const bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;" +
            "|long bpf_probe_read_user_str(Ptr<?> dst, @Unsigned int size, Ptr<?> unsafe_ptr)", "static long (* const" +
            " bpf_msg_apply_bytes)(struct sk_msg_md *msg, __u32 bytes) = (void *) 61;|long bpf_msg_apply_bytes" +
            "(Ptr<sk_msg_md> msg, @Unsigned int bytes)", "static long (* const bpf_sysctl_get_current_value)(struct " +
            "bpf_sysctl *ctx, char *buf, unsigned long buf_len) = (void *) 102;" + "|long " +
            "bpf_sysctl_get_current_value(Ptr<bpf_sysctl> ctx, String buf, @Unsigned long buf_len)", "static long (* " +
            "const fn)(void (*func)())|long fn(Ptr<?> func)", "static long (* const fn)(void (*func)(), int a)|long " +
            "fn(Ptr<?> func, int a)", "static long (* const fn)(void (*func)(int a), int a)|long fn(Ptr<?> func, int " +
            "a)", "static long (* const fn)(void (*func)(int a, int b), int a)|long fn(Ptr<?> func, int a)", "static " +
            "long (* const fn)(void (*func)(int a, int (*b)()), int a)|long fn(Ptr<?> func, int a)"

    }, delimiter = '|')
    public void testParseFVarDeclaration(String c, String java) {
        assertParse(java, DeclarationParser.parseFunctionVariableDeclaration(c));
    }

    /**
     * Test parsing function declarations, with real-world ones from the syscall man pages
     */
    @ParameterizedTest
    @CsvSource(value = {
           /* "void* print(int i);|Ptr<?> print(int i)",
            "void *print(int i, int j);|Ptr<?> print(int i, int j)",
            "[[deprecated]] pid_t vfork(pid_t pid);|pid_t vfork(pid_t pid)",
            "void* vfork(unsigned long addr, unsigned long length, unsigned long prot, unsigned long flags);|Ptr<?>
            vfork(@Unsigned long addr, @Unsigned long length, @Unsigned long prot, @Unsigned long flags)",
            "pid_t vfork(void);|pid_t vfork()",
            "long vfork3(struct clone_args *cl_args, size_t size);|long vfork3(Ptr<clone_args> cl_args, @Unsigned
            long size)",
            "int getgroups(int size, gid_t list[]);|int getgroups(int size, Ptr<gid_t> list)",
            "ssize_t write(int fd, const void buf[.count], size_t count);|ssize_t write(int fd, Ptr<?> buf, @Unsigned
             long count)",
            "pid_t wait(int *_Nullable wstatus);|pid_t wait(Ptr<java.lang. @Nullable Integer> wstatus)",
            "int pipe(int pipefd[2]);|int pipe(int @Size(2) [] pipefd)",
            "int pkey_mprotect(void addr[.len], size_t len, int prot, int pkey);|int pkey_mprotect(Ptr<?> addr,
            @Unsigned long len, int prot, int pkey)",
            "int futimens(int fd, const struct timespec times[_Nullable 2]);|int futimens(int fd, timespec @Size(2)
            @Nullable [] times)",
            "int timer_create(clockid_t clockid, struct sigevent *_Nullable restrict sevp, timer_t *restrict timerid)
            ;|int timer_create(clockid_t clockid, Ptr<@Nullable sigevent> sevp, Ptr<timer_t> timerid)",
            "int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict
             statxbuf);|int statx(int dirfd, String pathname, int flags, @Unsigned int mask, Ptr<statx> statxbuf)",
            "long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);|long ptrace
            (__ptrace_request request, pid_t pid, Ptr<?> addr, Ptr<?> data)",
            "int clone(int (*fn)(void *_Nullable))|int clone(Ptr<?> fn)",
            "int clone(int (*fn)(void *_Nullable, int* i))|int clone(Ptr<?> fn)",
            "int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[]);|int execve
            (String pathname, Ptr<Ptr<java.lang. @Nullable String>> argv, Ptr<Ptr<java.lang. @Nullable String>> envp)
            ",*/
            "long get_mempolicy(int *mode, unsigned long nodemask[(.maxnode + ULONG_WIDTH ‐ 1) / ULONG_WIDTH]);|long " +
                    "get_mempolicy(Ptr<java.lang.Integer> mode, Ptr<java.lang. @Unsigned Long> nodemask)",},
            delimiter = '|')
    public void testParseFunctionDeclaration(String c, String java) {
        assertParse(java, DeclarationParser.parseFunctionDeclaration(c));
    }

    void assertParse(String javaDeclaration, FuncType actual) {
        assertEquals(javaDeclaration,
                actual.toMethodSpec(gen).toString().replace('\n', ' ').replaceAll(" +", " ").split("public static ")[1].split(" \\{")[0]);
    }

    @Test
    public void testStructIsPresentInFunctionTemplate() {
        var decl = "ssize_t writev(int fd, const struct iovec *iov, int iovcnt);";
        var func = DeclarationParser.parseFunctionDeclaration(decl);
        var expected = """
                @NotUsableInJava
                @BuiltinBPFFunction("writev($arg1, (const struct iovec*)$arg2, $arg3)")
                public static ssize_t writev(int fd, Ptr<iovec> iov, int iovcnt) {
                  throw new MethodIsBPFRelatedFunction();
                }
                """;
        assertEquals(expected, func.toMethodSpec(gen).toString());
    }

    @Test
    public void testVarargsHandlingInFunctionTemplate() {
        var decl = "int sigreturn(const int* i, ...);";
        var func = DeclarationParser.parseFunctionDeclaration(decl);
        var expected = """
                @NotUsableInJava
                @BuiltinBPFFunction("sigreturn((const int*)$arg1, $arg2_)")
                public static int sigreturn(Ptr<java.lang.Integer> i, java.lang.Object... args) {
                  throw new MethodIsBPFRelatedFunction();
                }
                """;
        assertEquals(expected, func.toMethodSpec(gen).toString());
    }

    @Test
    public void testFunctionWithoutAnyConversion() {
        var decl = "int sigreturn(int* i);";
        var func = DeclarationParser.parseFunctionDeclaration(decl);
        var expected = """
                @NotUsableInJava
                @BuiltinBPFFunction
                public static int sigreturn(Ptr<java.lang.Integer> i) {
                  throw new MethodIsBPFRelatedFunction();
                }
                """;
        assertEquals(expected, func.toMethodSpec(gen).toString());
    }

    @ParameterizedTest
    @CsvSource(value = {"void (*print)(int i, int j)|void;(*print);(int i, int j)", "void (*print)(int i)|void;" +
            "(*print);(int i)", "void (*print)()|void;(*print);()", "(a())()|(a());()", "(a(b))()|(a(b));()", "(a(b()" +
            ", c))()|(a(b(), c));()",}, delimiter = '|')
    public void testTopParenthesesSplit(String input, String expected) {
        assertArrayEquals(expected.split(";"), DeclarationParser.topParenthesesSplit(input));
    }

    @Test
    public void testTopParenthesesSplitWithEmptyInput() {
        assertArrayEquals(new String[]{}, DeclarationParser.topParenthesesSplit(""));
    }

    @ParameterizedTest
    @CsvSource(value = {"int (i), int j|int (i);int j", "int (i)|int (i)", "a,b|a;b", "a, b|a;b", "a, (,a,(a,a))|a;(," +
            "a,(a,a))",}, delimiter = '|')
    public void testTopCommaSplit(String input, String expected) {
        assertArrayEquals(expected.split(";"), DeclarationParser.topCommaSplit(input));
    }

    @Test
    public void testTopCommaSplitWithEmptyInput() {
        assertArrayEquals(new String[]{}, DeclarationParser.topCommaSplit(""));
    }
}