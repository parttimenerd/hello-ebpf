package me.bechberger.ebpf.gen;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SyscallUtilTest {

    @Test
    public void testSimpleManPage() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork - description
                
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       pid_t vfork(void);
                
                   More bla
                
                DESCRIPTION
                   Standard description
                       (From POSIX.1) Standard Description
                
                   Linux description
                       vfork(), blub
                
                       More description
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("vfork", syscall.name());
        assertEquals("pid_t vfork(void);", syscall.definition());
        assertEquals("__Man page for vfork(2) from Linux__\n" + manPageExcerpt.lines().map(l -> "  " + l).collect(Collectors.joining("\n")), syscall.description());
    }


    @Test
    public void testManPageWithMultipleSystemCalls() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork, vfork2 - description
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       pid_t vfork(void);
                       pid_t vfork_(void);
                       pid_t vfork2(int a);
                
                   More bla
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork", "vfork2"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("vfork", syscall.name());
        assertEquals("pid_t vfork(void);", syscall.definition());
        var syscall2 = syscalls.get("vfork2");
        assertEquals("vfork2", syscall2.name());
        assertEquals("pid_t vfork2(int a);", syscall2.definition());
    }

    @Test
    public void testManPageWithMultilineSystemCallDefinition() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork - description
                
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       pid_t vfork(
                           void
                       );
                
                   More bla
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("vfork", syscall.name());
        assertEquals("pid_t vfork(void);", syscall.definition());
    }

    @Test
    public void testManPageWithMultipleMultilineSystemCallDefinitions() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork,vfork2, vfork3 - description
                
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       pid_t vfork(
                           void
                       );
                       pid_t vfork2(
                           int a
                       );
                       pid_t vfork3(int a,
                           int b
                       );
                   More bla
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork", "vfork2", "vfork3"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("vfork", syscall.name());
        assertEquals("pid_t vfork(void);", syscall.definition());
        var syscall2 = syscalls.get("vfork2");
        assertEquals("pid_t vfork2(int a);", syscall2.definition());
        var syscall3 = syscalls.get("vfork3");
        assertEquals("pid_t vfork3(int a, int b);", syscall3.definition());
    }

    @Test
    public void testManPageWithSystemCallWithoutGLibcWrapper() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork - description
                
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       long syscall(SYS_vfork, struct clone_args *cl_args, size_t size);
                
                   More bla
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("long vfork(struct clone_args *cl_args, size_t size);", syscall.definition());
    }

    @Test
    public void testManPageWithSystemCallWithoutGLibcWrapper2() {
        String manPageExcerpt = """
                NAME
                       vfork3, vfork, clone3 - create a child process
                
                LIBRARY
                       Standard C library (libc, -lc)
                
                SYNOPSIS
                       /* Prototype for the glibc wrapper function */
                
                       #define _GNU_SOURCE
                       #include <sched.h>
                
                       int vfork(int (*fn)(void *_Nullable));
                
                       long syscall(SYS_vfork3, struct clone_args *cl_args, size_t size);
                
                       Text that contains vfork3().
                
                
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork3", "vfork"), syscalls.keySet());
        var syscall = syscalls.get("vfork3");
        assertEquals("long vfork3(struct clone_args *cl_args, size_t size);", syscall.definition());
    }

    @Test
    public void testManPageWhereReturnTypeIsOnAnotherLine() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork - description
                
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       pid_t
                       vfork(void);
                
                   More bla
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("pid_t vfork(void);", syscall.definition());
    }

    @Test
    public void testManPageWithSyscall() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork - description
                
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       void *syscall(SYS_vfork, unsigned long addr, unsigned long length,
                                     unsigned long prot, unsigned long flags);
                
                   More bla
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("void* vfork(unsigned long addr, unsigned long length, unsigned long prot, unsigned long flags);", syscall.definition());
    }

    @Test
    public void testManPageWithDeprecatedSyscall() {
        String manPageExcerpt = """
                vfork(2)                                                                                                                                                                                                                          System Calls Manual                                                                                                                                                                                                                          vfork(2)
                
                NAME
                       vfork - description
                
                LIBRARY
                       Bla
                
                SYNOPSIS
                       #include <unistd.h>
                
                       pid_t getpgrp(void);                            /* POSIX.1 version */
                       [[deprecated]] pid_t vfork(pid_t pid);        /* BSD version */
                
                   More bla
                """;
        var syscalls = SystemCallUtil.parseManPage("vfork", manPageExcerpt);
        assertEquals(Set.of("vfork"), syscalls.keySet());
        var syscall = syscalls.get("vfork");
        assertEquals("[[deprecated]] pid_t vfork(pid_t pid);", syscall.definition());
    }
}
