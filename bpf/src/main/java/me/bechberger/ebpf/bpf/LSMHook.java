package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Includes;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.LSM;
import me.bechberger.ebpf.runtime.KernelDefinitions;
import me.bechberger.ebpf.runtime.LinuxDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * Mix-in interface that provides a set of ready-to-use LSM (Linux Security Module) hooks.
 *
 * <p>Implement this interface in a {@code @BPF} program class, override the hooks you care about,
 * and call {@link #attachLSMHooks()} after loading:
 *
 * <pre>{@code
 * @BPF(license = "GPL")
 * public abstract class MyLSM extends BPFProgram implements LSMHook {
 *
 *     @Override
 *     public int onFileOpen(Ptr<runtime.file> file) {
 *         // inspect file, return -EACCES to deny
 *         return 0;
 *     }
 *
 *     public static void main(String[] args) {
 *         try (var prog = BPFProgram.load(MyLSM.class)) {
 *             prog.attachLSMHooks();
 *             prog.tracePrintLoop();
 *         }
 *     }
 * }
 * }</pre>
 *
 * <p>Alternatively, use {@code @LSM("hook_name")} directly on methods in your program class
 * without implementing this interface — that is the preferred pattern for new code since you
 * can name your methods freely and use {@code autoAttachPrograms()}.
 *
 * <p>Requires {@code CONFIG_BPF_LSM=y} and {@code lsm=...,bpf} in the kernel command line
 * (verify with {@code cat /sys/kernel/security/lsm | grep bpf}).
 *
 * @see <a href="https://docs.kernel.org/bpf/prog_lsm.html">BPF LSM documentation</a>
 */
@Includes({"linux/security.h"})
public interface LSMHook {

    /** POSIX error code: permission denied. */
    int EACCES = 13;
    /** POSIX error code: operation not permitted. */
    int EPERM = 1;

    // ── file hooks ──────────────────────────────────────────────────────────

    /**
     * Called when a file is opened. Return 0 to allow, {@code -EACCES} to deny.
     *
     * @param file the kernel {@code struct file *} being opened
     */
    @LSM("file_open")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/file_open",
            autoAttach = false
    )
    default int onFileOpen(Ptr<runtime.file> file) {
        return 0;
    }

    /**
     * Called when a file permission check is performed.
     * Return 0 to allow, negative errno to deny.
     *
     * @param file  the file being accessed
     * @param mask  the access mask (MAY_READ, MAY_WRITE, MAY_EXEC, MAY_APPEND)
     */
    @LSM("file_permission")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/file_permission",
            autoAttach = false
    )
    default int onFilePermission(Ptr<runtime.file> file, int mask) {
        return 0;
    }

    // ── inode hooks ──────────────────────────────────────────────────────────

    /**
     * Called when a file is created. Return 0 to allow, negative errno to deny.
     *
     * @param dir     parent directory inode
     * @param dentry  dentry for the new file
     * @param mode    creation mode bits
     */
    @LSM("inode_create")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/inode_create",
            autoAttach = false
    )
    default int onInodeCreate(Ptr<runtime.inode> dir, Ptr<runtime.dentry> dentry, int mode) {
        return 0;
    }

    /**
     * Called before a file is unlinked. Return 0 to allow, negative errno to deny.
     *
     * @param dir    parent directory inode
     * @param dentry dentry of the file to unlink
     */
    @LSM("inode_unlink")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/inode_unlink",
            autoAttach = false
    )
    default int onInodeUnlink(Ptr<runtime.inode> dir, Ptr<runtime.dentry> dentry) {
        return 0;
    }

    /**
     * Called before a directory is removed. Return 0 to allow, negative errno to deny.
     *
     * @param dir    parent directory inode
     * @param dentry dentry of the directory to remove
     */
    @LSM("inode_rmdir")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/inode_rmdir",
            autoAttach = false
    )
    default int onInodeRmdir(Ptr<runtime.inode> dir, Ptr<runtime.dentry> dentry) {
        return 0;
    }

    /**
     * Called before a file is renamed. Return 0 to allow, negative errno to deny.
     *
     * @param oldDir    source parent directory inode
     * @param oldDentry source dentry
     * @param newDir    destination parent directory inode
     * @param newDentry destination dentry
     */
    @LSM("inode_rename")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/inode_rename",
            autoAttach = false
    )
    default int onInodeRename(Ptr<runtime.inode> oldDir, Ptr<runtime.dentry> oldDentry,
                              Ptr<runtime.inode> newDir, Ptr<runtime.dentry> newDentry) {
        return 0;
    }

    /**
     * Called when inode attributes are changed. Return 0 to allow, negative errno to deny.
     *
     * @param dentry the dentry whose attributes are being set
     */
    @LSM("inode_setattr")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/inode_setattr",
            autoAttach = false
    )
    default int onInodeSetattr(Ptr<runtime.dentry> dentry) {
        return 0;
    }

    /**
     * Called when a permission check is performed on an inode.
     * Return 0 to allow, negative errno to deny.
     *
     * @param inode the inode being checked
     * @param mask  the access mask
     */
    @LSM("inode_permission")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/inode_permission",
            autoAttach = false
    )
    default int onInodePermission(Ptr<runtime.inode> inode, int mask) {
        return 0;
    }

    // ── BPF hooks ────────────────────────────────────────────────────────────

    /**
     * Called when a BPF syscall is invoked. Return 0 to allow, {@code -EPERM} to deny.
     *
     * @param cmd  the bpf command (e.g. {@code BPF_PROG_LOAD})
     * @param attr pointer to the bpf_attr union
     * @param size size of bpf_attr
     */
    @LSM("bpf")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/bpf",
            autoAttach = false
    )
    default int onBpf(int cmd, Ptr<?> attr, int size) {
        return 0;
    }

    // ── socket hooks ─────────────────────────────────────────────────────────

    /**
     * Called when a socket is created. Return 0 to allow, negative errno to deny.
     *
     * @param family   address family (AF_INET, AF_INET6, …)
     * @param type     socket type (SOCK_STREAM, SOCK_DGRAM, …)
     * @param protocol protocol (0 = default)
     * @param kern     1 if created by kernel, 0 if by user-space
     */
    @LSM("socket_create")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/socket_create",
            autoAttach = false
    )
    default int onSocketCreate(int family, int type, int protocol, int kern) {
        return 0;
    }

    /**
     * Called when a socket bind is attempted. Return 0 to allow, negative errno to deny.
     *
     * @param sock    the socket
     * @param addr    the address to bind to
     * @param addrLen length of the address structure
     */
    @LSM("socket_bind")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/socket_bind",
            autoAttach = false
    )
    default int onSocketBind(Ptr<runtime.socket> sock, Ptr<runtime.sockaddr> addr, int addrLen) {
        return 0;
    }

    /**
     * Called when a socket connect is attempted. Return 0 to allow, negative errno to deny.
     *
     * @param sock    the socket
     * @param addr    the destination address
     * @param addrLen length of the address structure
     */
    @LSM("socket_connect")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/socket_connect",
            autoAttach = false
    )
    default int onSocketConnect(Ptr<runtime.socket> sock, Ptr<runtime.sockaddr> addr, int addrLen) {
        return 0;
    }

    /**
     * Called when a socket listen is requested. Return 0 to allow, negative errno to deny.
     *
     * @param sock    the socket
     * @param backlog listen backlog
     */
    @LSM("socket_listen")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/socket_listen",
            autoAttach = false
    )
    default int onSocketListen(Ptr<runtime.socket> sock, int backlog) {
        return 0;
    }

    // ── task/process hooks ───────────────────────────────────────────────────

    /**
     * Called when setuid/setgid credentials are fixed up. Return 0 to allow, negative errno to deny.
     *
     * @param newCred   the new credentials
     * @param oldCred   the original credentials
     * @param which     which credentials are being set (LSM_SETID_ID, etc.)
     */
    @LSM("task_fix_setuid")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/task_fix_setuid",
            autoAttach = false
    )
    default int onTaskFixSetuid(Ptr<runtime.cred> newCred, Ptr<runtime.cred> oldCred, int which) {
        return 0;
    }

    /**
     * Called when a signal is sent to a task. Return 0 to allow, negative errno to deny.
     *
     * @param p      target task
     * @param info   signal info
     * @param sig    signal number
     * @param cred   sender's credentials
     */
    @LSM("task_kill")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/task_kill",
            autoAttach = false
    )
    default int onTaskKill(Ptr<TaskDefinitions.task_struct> p,
                           Ptr<KernelDefinitions.kernel_siginfo> info,
                           int sig, Ptr<runtime.cred> cred) {
        return 0;
    }

    /**
     * Called when a task's nice value is changed. Return 0 to allow, negative errno to deny.
     *
     * @param p    the task
     * @param nice the new nice value
     */
    @LSM("task_setnice")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/task_setnice",
            autoAttach = false
    )
    default int onTaskSetnice(Ptr<TaskDefinitions.task_struct> p, int nice) {
        return 0;
    }

    /**
     * Called when a task's scheduler is changed. Return 0 to allow, negative errno to deny.
     *
     * @param p the task
     */
    @LSM("task_setscheduler")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/task_setscheduler",
            autoAttach = false
    )
    default int onTaskSetscheduler(Ptr<TaskDefinitions.task_struct> p) {
        return 0;
    }

    /**
     * Called before executing a new program. Return 0 to allow, negative errno to deny.
     *
     * @param bprm the binary program structure
     */
    @LSM("bprm_check_security")
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            section = "lsm/bprm_check_security",
            autoAttach = false
    )
    default int onBprmCheckSecurity(Ptr<LinuxDefinitions.linux_binprm> bprm) {
        return 0;
    }

    // ── convenience ──────────────────────────────────────────────────────────

    /**
     * Attach all overridden LSM hooks.  Call this after
     * {@link BPFProgram#load(Class)}.
     */
    default void attachLSMHooks() {
        if (this instanceof BPFProgram program) {
            program.attachLSMHooks();
        } else {
            throw new IllegalStateException("LSMHook can only be used in a BPFProgram subclass");
        }
    }
}
