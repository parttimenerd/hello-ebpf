/*
 * Copyright 2015 Clevernet, SAP SE (Java translation)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package me.bechberger.ebpf.bcc;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static me.bechberger.ebpf.bcc.BPFType.BPFIntType.UINT64;

/**
 * Dissassembles eBPF bytecode
 * <p>
 * Based on {@see https://github.com/iovisor/bcc/blob/master/src/python/bcc/disassembler.py}
 */
public class Disassembler {

    final static BPFType<Short> OFFSET_TYPE = BPFType.BPFIntType.INT16;

    final static BPFType<Integer> IMM_TYPE = BPFType.BPFIntType.INT32;

    record BPFInstrFields(byte opcode, byte dst_and_src, short offset, int imm) {
        byte src() {
            return (byte) ((dst_and_src >> 4) & 0x0F);
        }

        byte dst() {
            return (byte) (dst_and_src & 0x0F);
        }
    }

    final static BPFType.BPFStructType<BPFInstrFields> BPF_INSTR_FIELDS_TYPE = new BPFType.BPFStructType<>(
            "bpf_instr_fields", List.of(new BPFType.BPFStructMember<>("opcode", BPFType.BPFIntType.UINT8, 0,
            BPFInstrFields::opcode), new BPFType.BPFStructMember<>("dst_and_src", BPFType.BPFIntType.UINT8, 1,
            BPFInstrFields::dst_and_src), new BPFType.BPFStructMember<>("offset", OFFSET_TYPE, 2,
            BPFInstrFields::offset), new BPFType.BPFStructMember<>("imm", IMM_TYPE, 4, BPFInstrFields::imm)),
            new BPFType.AnnotatedClass(BPFInstrFields.class, List.of()),
            objects -> new BPFInstrFields((byte) objects.get(0), (byte) objects.get(1), (short) objects.get(2),
                    (int) objects.get(3)));

    static final BPFType.BPFUnionType<Void> BPF_INSTR_TYPE = new BPFType.BPFUnionType<>("bpf_instr", null,
            List.of(new BPFType.BPFUnionTypeMember("s", BPF_INSTR_FIELDS_TYPE), new BPFType.BPFUnionTypeMember("instr"
                    , UINT64)));

    static class BPFDecoder {
        static final int BPF_PSEUDO_CALL = 1;

        static final String[] BPF_HELPERS = new String[]{"unspec", "map_lookup_elem", "map_update_elem",
                "map_delete_elem", "probe_read", "ktime_get_ns", "trace_printk", "get_prandom_u32",
                "get_smp_processor_id", "skb_store_bytes", "l3_csum_replace", "l4_csum_replace", "tail_call",
                "clone_redirect", "get_current_pid_tgid", "get_current_uid_gid", "get_current_comm",
                "get_cgroup_classid", "skb_vlan_push", "skb_vlan_pop", "skb_get_tunnel_key", "skb_set_tunnel_key",
                "perf_event_read", "redirect", "get_route_realm", "perf_event_output", "skb_load_bytes", "get_stackid"
                , "csum_diff", "skb_get_tunnel_opt", "skb_set_tunnel_opt", "skb_change_proto", "skb_change_type",
                "skb_under_cgroup", "get_hash_recalc", "get_current_task", "probe_write_user",
                "current_task_under_cgroup", "skb_change_tail", "skb_pull_data", "csum_update", "set_hash_invalid",
                "get_numa_node_id", "skb_change_head", "xdp_adjust_head", "probe_read_str", "get_socket_cookie",
                "get_socket_uid", "set_hash", "setsockopt", "skb_adjust_room", "redirect_map", "sk_redirect_map",
                "sock_map_update", "xdp_adjust_meta", "perf_event_read_value", "perf_prog_read_value", "getsockopt",
                "override_return", "sock_ops_cb_flags_set", "msg_redirect_map", "msg_apply_bytes", "msg_cork_bytes",
                "msg_pull_data", "bind", "xdp_adjust_tail", "skb_get_xfrm_state", "get_stack",
                "skb_load_bytes_relative", "fib_lookup", "sock_hash_update", "msg_redirect_hash", "sk_redirect_hash",
                "lwt_push_encap", "lwt_seg6_store_bytes", "lwt_seg6_adjust_srh", "lwt_seg6_action", "rc_repeat",
                "rc_keydown", "skb_cgroup_id", "get_current_cgroup_id", "get_local_storage", "sk_select_reuseport",
                "skb_ancestor_cgroup_id", "sk_lookup_tcp", "sk_lookup_udp", "sk_release", "map_push_elem",
                "map_pop_elem", "map_peek_elem", "msg_push_data", "msg_pop_data", "rc_pointer_rel"};

        record OpCode(String name, String op, String repr, int size) {
        }

        static final Map<Byte, OpCode> opcodes = new HashMap<>();

        static {
            opcodes.put((byte) 0x04, new OpCode("add32", "dstimm", "+=", 32));
            opcodes.put((byte) 0x05, new OpCode("ja", "joff", null, 64));
            opcodes.put((byte) 0x07, new OpCode("add", "dstimm", "+=", 64));
            opcodes.put((byte) 0x0c, new OpCode("add32", "dstsrc", "+=", 32));
            opcodes.put((byte) 0x0f, new OpCode("add", "dstsrc", "+=", 64));
            opcodes.put((byte) 0x14, new OpCode("sub32", "dstimm", "-=", 32));
            opcodes.put((byte) 0x15, new OpCode("jeq", "jdstimmoff", "==", 64));
            opcodes.put((byte) 0x17, new OpCode("sub", "dstimm", "-=", 64));
            opcodes.put((byte) 0x18, new OpCode("lddw", "lddw", null, 64));
            opcodes.put((byte) 0x1c, new OpCode("sub32", "dstsrc", "-=", 32));
            opcodes.put((byte) 0x1d, new OpCode("jeq", "jdstsrcoff", "==", 64));
            opcodes.put((byte) 0x1f, new OpCode("sub", "dstsrc", "-=", 64));
            opcodes.put((byte) 0x20, new OpCode("ldabsw", "ldabs", null, 32));
            opcodes.put((byte) 0x24, new OpCode("mul32", "dstimm", "*=", 32));
            opcodes.put((byte) 0x25, new OpCode("jgt", "jdstimmoff", ">", 64));
            opcodes.put((byte) 0x27, new OpCode("mul", "dstimm", "*=", 64));
            opcodes.put((byte) 0x28, new OpCode("ldabsh", "ldabs", null, 16));
            opcodes.put((byte) 0x2c, new OpCode("mul32", "dstsrc", "*=", 32));
            opcodes.put((byte) 0x2d, new OpCode("jgt", "jdstsrcoff", ">", 64));
            opcodes.put((byte) 0x2f, new OpCode("mul", "dstsrc", "*=", 64));
            opcodes.put((byte) 0x30, new OpCode("ldabsb", "ldabs", null, 8));
            opcodes.put((byte) 0x34, new OpCode("div32", "dstimm", "/=", 32));
            opcodes.put((byte) 0x35, new OpCode("jge", "jdstimmoff", ">=", 64));
            opcodes.put((byte) 0x37, new OpCode("div", "dstimm", "/=", 64));
            opcodes.put((byte) 0x38, new OpCode("ldabsdw", "ldabs", null, 64));
            opcodes.put((byte) 0x3c, new OpCode("div32", "dstsrc", "/=", 32));
            opcodes.put((byte) 0x3d, new OpCode("jge", "jdstsrcoff", ">=", 64));
            opcodes.put((byte) 0x3f, new OpCode("div", "dstsrc", "/=", 64));
            opcodes.put((byte) 0x40, new OpCode("ldindw", "ldind", null, 32));
            opcodes.put((byte) 0x44, new OpCode("or32", "dstimm_bw", "|=", 32));
            opcodes.put((byte) 0x45, new OpCode("jset", "jdstimmoff", "&", 64));
            opcodes.put((byte) 0x47, new OpCode("or", "dstimm_bw", "|=", 64));
            opcodes.put((byte) 0x48, new OpCode("ldindh", "ldind", null, 16));
            opcodes.put((byte) 0x4c, new OpCode("or32", "dstsrc", "|=", 32));
            opcodes.put((byte) 0x4d, new OpCode("jset", "jdstsrcoff", "&", 64));
            opcodes.put((byte) 0x4f, new OpCode("or", "dstsrc", "|=", 64));
            opcodes.put((byte) 0x50, new OpCode("ldindb", "ldind", null, 8));
            opcodes.put((byte) 0x54, new OpCode("and32", "dstimm_bw", "&=", 32));
            opcodes.put((byte) 0x55, new OpCode("jne", "jdstimmoff", "!=", 64));
            opcodes.put((byte) 0x57, new OpCode("and", "dstimm_bw", "&=", 64));
            opcodes.put((byte) 0x58, new OpCode("ldinddw", "ldind", null, 64));
            opcodes.put((byte) 0x5c, new OpCode("and32", "dstsrc", "&=", 32));
            opcodes.put((byte) 0x5d, new OpCode("jne", "jdstsrcoff", "!=", 64));
            opcodes.put((byte) 0x5f, new OpCode("and", "dstsrc", "&=", 64));
            opcodes.put((byte) 0x61, new OpCode("ldxw", "ldstsrcoff", null, 32));
            opcodes.put((byte) 0x62, new OpCode("stw", "sdstoffimm", null, 32));
            opcodes.put((byte) 0x63, new OpCode("stxw", "sdstoffsrc", null, 32));
            opcodes.put((byte) 0x64, new OpCode("lsh32", "dstimm", "<<=", 32));
            opcodes.put((byte) 0x65, new OpCode("jsgt", "jdstimmoff", "s>", 64));
            opcodes.put((byte) 0x67, new OpCode("lsh", "dstimm", "<<=", 64));
            opcodes.put((byte) 0x69, new OpCode("ldxh", "ldstsrcoff", null, 16));
            opcodes.put((byte) 0x6a, new OpCode("sth", "sdstoffimm", null, 16));
            opcodes.put((byte) 0x6b, new OpCode("stxh", "sdstoffsrc", null, 16));
            opcodes.put((byte) 0x6c, new OpCode("lsh32", "dstsrc", "<<=", 32));
            opcodes.put((byte) 0x6d, new OpCode("jsgt", "jdstsrcoff", "s>", 64));
            opcodes.put((byte) 0x6f, new OpCode("lsh", "dstsrc", "<<=", 64));
            opcodes.put((byte) 0x71, new OpCode("ldxb", "ldstsrcoff", null, 8));
            opcodes.put((byte) 0x72, new OpCode("stb", "sdstoffimm", null, 8));
            opcodes.put((byte) 0x73, new OpCode("stxb", "sdstoffsrc", null, 8));
            opcodes.put((byte) 0x74, new OpCode("rsh32", "dstimm", ">>=", 32));
            opcodes.put((byte) 0x75, new OpCode("jsge", "jdstimmoff", "s>=", 64));
            opcodes.put((byte) 0x77, new OpCode("rsh", "dstimm", ">>=", 64));
            opcodes.put((byte) 0x79, new OpCode("ldxdw", "ldstsrcoff", null, 64));
            opcodes.put((byte) 0x7a, new OpCode("stdw", "sdstoffimm", null, 64));
            opcodes.put((byte) 0x7b, new OpCode("stxdw", "sdstoffsrc", null, 64));
            opcodes.put((byte) 0x7c, new OpCode("rsh32", "dstsrc", ">>=", 32));
            opcodes.put((byte) 0x7d, new OpCode("jsge", "jdstsrcoff", "s>=", 64));
            opcodes.put((byte) 0x7f, new OpCode("rsh", "dstsrc", ">>=", 64));
            opcodes.put((byte) 0x84, new OpCode("neg32", "dst", "~", 32));
            opcodes.put((byte) 0x85, new OpCode("call", "call", null, 64));
            opcodes.put((byte) 0x87, new OpCode("neg", "dst", "~", 64));
            opcodes.put((byte) 0x94, new OpCode("mod32", "dstimm", "%=", 32));
            opcodes.put((byte) 0x95, new OpCode("exit", "exit", null, 64));
            opcodes.put((byte) 0x97, new OpCode("mod", "dstimm", "%=", 64));
            opcodes.put((byte) 0x9c, new OpCode("mod32", "dstsrc", "%=", 32));
            opcodes.put((byte) 0x9f, new OpCode("mod", "dstsrc", "%=", 64));
            opcodes.put((byte) 0xa4, new OpCode("xor32", "dstimm_bw", "^=", 32));
            opcodes.put((byte) 0xa5, new OpCode("jlt", "jdstimmoff", "<", 64));
            opcodes.put((byte) 0xa7, new OpCode("xor", "dstimm_bw", "^=", 64));
            opcodes.put((byte) 0xac, new OpCode("xor32", "dstsrc", "^=", 32));
            opcodes.put((byte) 0xad, new OpCode("jlt", "jdstsrcoff", "<", 64));
            opcodes.put((byte) 0xaf, new OpCode("xor", "dstsrc", "^=", 64));
            opcodes.put((byte) 0xb4, new OpCode("mov32", "dstimm", "=", 32));
            opcodes.put((byte) 0xb5, new OpCode("jle", "jdstimmoff", "<=", 64));
            opcodes.put((byte) 0xb7, new OpCode("mov", "dstimm", "=", 64));
            opcodes.put((byte) 0xbc, new OpCode("mov32", "dstsrc", "=", 32));
            opcodes.put((byte) 0xbd, new OpCode("jle", "jdstsrcoff", "<=", 64));
            opcodes.put((byte) 0xbf, new OpCode("mov", "dstsrc", "=", 64));
            opcodes.put((byte) 0xc4, new OpCode("arsh32", "dstimm", "s>>=", 32));
            opcodes.put((byte) 0xc5, new OpCode("jslt", "jdstimmoff", "s<", 64));
            opcodes.put((byte) 0xc7, new OpCode("arsh", "dstimm", "s>>=", 64));
            opcodes.put((byte) 0xcc, new OpCode("arsh32", "dstsrc", "s>>=", 32));
            opcodes.put((byte) 0xcd, new OpCode("jslt", "jdstsrcoff", "s<", 64));
            opcodes.put((byte) 0xcf, new OpCode("arsh", "dstsrc", "s>>=", 64));
            opcodes.put((byte) 0xd5, new OpCode("jsle", "jdstimmoff", "s<=", 64));
            opcodes.put((byte) 0xdc, new OpCode("endian32", "dstsrc", "endian", 32));
            opcodes.put((byte) 0xdd, new OpCode("jsle", "jdstimmoff", "s<=", 64));
        }

        public record InstrDecoded(String instr, int skip) {

            boolean valid() {
                return skip > -1;
            }

            static InstrDecoded invalid(int opcode) {
                return new InstrDecoded(String.format("0x%x", opcode), -1);
            }
        }

        static InstrDecoded decode(int i, BPFType.BPFUnion<Void> w, BPFType.BPFUnion<Void> w1) {
            var fields = w.<BPFInstrFields>get("s");
            var opcode = fields.opcode();
            var dst = fields.dst();
            var src = fields.src();
            var offset = fields.offset();
            var imm = fields.imm();
            var op = opcodes.getOrDefault(opcode, null);
            if (op == null) {
                return InstrDecoded.invalid(opcode);
            }
            var name = op.name();
            var opclass = op.op();
            var bits = op.size();
            switch (opclass) {
                case "dstimm" -> {
                    return new InstrDecoded(String.format("r%d %s %d", dst, op.repr(), imm), 0);
                }
                case "dstimm_bw" -> {
                    return new InstrDecoded(String.format("r%d %s 0x%x", dst, op.repr(), imm), 0);
                }
                case "joff" -> {
                    return new InstrDecoded(String.format("goto %s <%d>", String.format("%+d", offset),
                            i + offset + 1), 0);
                }
                case "dstsrc" -> {
                    return new InstrDecoded(String.format("r%d %s r%d", dst, op.repr(), src), 0);
                }
                case "jdstimmoff" -> {
                    return new InstrDecoded(String.format("if r%d %s %d goto pc%s <%d>", dst, op.repr(), imm,
                            String.format("%+d", offset), i + offset + 1), 0);
                }
                case "jdstsrcoff" -> {
                    return new InstrDecoded(String.format("if r%d %s r%d goto pc%s <%d>", dst, op.repr(), src,
                            String.format("%+d", offset), i + offset + 1), 0);
                }
                case "lddw" -> {
                    if (w1 == null) {
                        throw new RuntimeException("lddw requires two instructions to be disassembled");
                    }
                    var w1imm = w1.<BPFInstrFields>get("s").imm();
                    if (w1imm == 0) {
                        return new InstrDecoded(String.format("r%d = <map at fd #%d>", dst, imm), 1);
                    }
                    var imm64 = ((long) w1imm << 32) | imm;
                    return new InstrDecoded(String.format("r%d = 0x%x", dst, imm64), 1);
                }
                case "ldabs" -> {
                    return new InstrDecoded(String.format("r0 = *(u%s*)skb[%s]", bits, imm), 0);
                }
                case "ldind" -> {
                    return new InstrDecoded(String.format("r0 = *(u%d*)skb[r%d %s]", bits, src, String.format("%+d",
                            imm)), 0);
                }
                case "ldstsrcoff" -> {
                    return new InstrDecoded(String.format("r%d = *(u%d*)(r%d %s)", dst, bits, src, String.format("%+d"
                            , offset)), 0);
                }
                case "sdstoffimm" -> {
                    return new InstrDecoded(String.format("*(u%d*)(r%d %s) = %d", bits, dst, String.format("%+d",
                            offset), imm), 0);
                }
                case "sdstoffsrc" -> {
                    return new InstrDecoded(String.format("*(u%d*)(r%d %s) = r%d", bits, dst, String.format("%+d",
                            offset), src), 0);
                }
                case "dst" -> {
                    return new InstrDecoded(String.format("r%d = %s (u%s)r%d", dst, op.repr(), bits, dst), 0);
                }
                case "call" -> {
                    if (src != BPF_PSEUDO_CALL) {
                        try {
                            return new InstrDecoded(String.format("%s bpf_%s#%d", name, BPF_HELPERS[imm], imm), 0);
                        } catch (IndexOutOfBoundsException e) {
                            return new InstrDecoded(String.format("%s <unknown helper #%d>", op.repr(), imm), 0);
                        }
                    }
                    return new InstrDecoded(String.format("%s %s", name, String.format("%+d", imm)), 0);
                }
                case "exit" -> {
                    return new InstrDecoded(name, 0);
                }
                default -> throw new RuntimeException("unknown opcode class " + opclass);
            }
        }
    }

    static BPFDecoder.InstrDecoded disassembleInstruction(int i, BPFType.BPFUnion<Void> w0, BPFType.BPFUnion<Void> w1) {
        var decoded = BPFDecoder.decode(i, w0, w1);
        return new BPFDecoder.InstrDecoded(String.format("%4d: (%02x) %s", i, w0.<BPFInstrFields>get("s").opcode(),
                decoded.instr()), decoded.skip());
    }

    public static List<BPFDecoder.InstrDecoded> disassemble_str(MemorySegment bpfstr) {
        var numinstr = bpfstr.byteSize() / 8;
        var w0 = BPF_INSTR_TYPE.parseMemory(bpfstr);
        var skip = 0;
        var instr_list = new ArrayList<BPFDecoder.InstrDecoded>();
        for (var i = 1; i < numinstr; i++) {
            var w1 = BPF_INSTR_TYPE.parseMemory(bpfstr.asSlice(i * 8L, 8));
            if (skip > 0) {
                skip--;
                instr_list.add(new BPFDecoder.InstrDecoded(String.format("%4d:      (64-bit upper word)", i), 0));
            } else {
                var decoded = disassembleInstruction(i - 1, w0, w1);
                instr_list.add(decoded);
                skip = decoded.skip();
            }
            w0 = w1;
        }
        var decoded = disassembleInstruction((int) (numinstr - 1), w0, null);
        instr_list.add(decoded);
        return instr_list;
    }

    public static String disassemble_prog(String func_name, MemorySegment bpfstr) {
        var instr_list = new ArrayList<String>();
        instr_list.add(String.format("Disassemble of BPF program %s:", func_name));
        for (var instr : disassemble_str(bpfstr)) {
            instr_list.add(instr.instr());
        }
        return String.join(System.lineSeparator(), instr_list);
    }
}
