/** Auto-generated */
package me.bechberger.ebpf.runtime.interfaces;

import java.lang.SuppressWarnings;
import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

@java.lang.SuppressWarnings("unused")
@me.bechberger.ebpf.annotations.bpf.BPFInterface
public interface SystemCallHooks {
  /**
   * Enter the system call {@code accept}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* file, struct proto_accept_arg* arg, struct sockaddr* upeer_sockaddr, int* upeer_addrlen, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_accept",
      autoAttach = true
  )
  default void enterAccept(Ptr<file> file, Ptr<proto_accept_arg> arg, Ptr<sockaddr> upeer_sockaddr,
      Ptr<java.lang.Integer> upeer_addrlen, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code accept}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* file, struct proto_accept_arg* arg, struct sockaddr* upeer_sockaddr, int* upeer_addrlen, int flags, struct file* ret)",
      lastStatement = "return 0;",
      section = "fexit/do_accept",
      autoAttach = true
  )
  default void exitAccept(Ptr<file> file, Ptr<proto_accept_arg> arg, Ptr<sockaddr> upeer_sockaddr,
      Ptr<java.lang.Integer> upeer_addrlen, int flags, Ptr<file> ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code accept}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct file* file, struct proto_accept_arg* arg, struct sockaddr* upeer_sockaddr, int* upeer_addrlen, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_accept",
      autoAttach = true
  )
  default void kprobeEnterAccept(Ptr<file> file, Ptr<proto_accept_arg> arg,
      Ptr<sockaddr> upeer_sockaddr, Ptr<java.lang.Integer> upeer_addrlen, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code accept}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct file* file, struct proto_accept_arg* arg, struct sockaddr* upeer_sockaddr, int* upeer_addrlen, int flags, struct file* ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_accept",
      autoAttach = true
  )
  default void kprobeExitAccept(Ptr<file> file, Ptr<proto_accept_arg> arg,
      Ptr<sockaddr> upeer_sockaddr, Ptr<java.lang.Integer> upeer_addrlen, int flags,
      Ptr<file> ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code add_key}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* _type, const u8* _description, const void* _payload, long unsigned int plen, int ringid)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_add_key",
      autoAttach = true
  )
  default void enterAddKey(String _type, String _description, Ptr<?> _payload, @Unsigned long plen,
      @OriginalName("key_serial_t") int ringid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code add_key}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* _type, const u8* _description, const void* _payload, long unsigned int plen, int ringid, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_add_key",
      autoAttach = true
  )
  default void exitAddKey(String _type, String _description, Ptr<?> _payload, @Unsigned long plen,
      @OriginalName("key_serial_t") int ringid, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code add_key}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* _type, const u8* _description, const void* _payload, long unsigned int plen, int ringid)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_add_key",
      autoAttach = true
  )
  default void kprobeEnterAddKey(String _type, String _description, Ptr<?> _payload,
      @Unsigned long plen, @OriginalName("key_serial_t") int ringid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code add_key}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* _type, const u8* _description, const void* _payload, long unsigned int plen, int ringid, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_add_key",
      autoAttach = true
  )
  default void kprobeExitAddKey(String _type, String _description, Ptr<?> _payload,
      @Unsigned long plen, @OriginalName("key_serial_t") int ringid, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code adjtimex}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct __kernel_timex* txc)",
      lastStatement = "return 0;",
      section = "fentry/do_adjtimex",
      autoAttach = true
  )
  default void enterAdjtimex(Ptr<__kernel_timex> txc) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code adjtimex}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct __kernel_timex* txc, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_adjtimex",
      autoAttach = true
  )
  default void exitAdjtimex(Ptr<__kernel_timex> txc, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code adjtimex}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct __kernel_timex* txc)",
      lastStatement = "return 0;",
      section = "kprobe/do_adjtimex",
      autoAttach = true
  )
  default void kprobeEnterAdjtimex(Ptr<__kernel_timex> txc) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code adjtimex}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct __kernel_timex* txc, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_adjtimex",
      autoAttach = true
  )
  default void kprobeExitAdjtimex(Ptr<__kernel_timex> txc, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code brk}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int brk)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_brk",
      autoAttach = true
  )
  default void enterBrk(@Unsigned long brk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code brk}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int brk, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_brk",
      autoAttach = true
  )
  default void exitBrk(@Unsigned long brk, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code brk}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int brk)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_brk",
      autoAttach = true
  )
  default void kprobeEnterBrk(@Unsigned long brk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code brk}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int brk, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_brk",
      autoAttach = true
  )
  default void kprobeExitBrk(@Unsigned long brk, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code capget}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct __user_cap_header_struct* header, struct __user_cap_data_struct* dataptr)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_capget",
      autoAttach = true
  )
  default void enterCapget(@OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> dataptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code capget}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct __user_cap_header_struct* header, struct __user_cap_data_struct* dataptr, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_capget",
      autoAttach = true
  )
  default void exitCapget(@OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> dataptr, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code capget}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct __user_cap_header_struct* header, struct __user_cap_data_struct* dataptr)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_capget",
      autoAttach = true
  )
  default void kprobeEnterCapget(
      @OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> dataptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code capget}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct __user_cap_header_struct* header, struct __user_cap_data_struct* dataptr, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_capget",
      autoAttach = true
  )
  default void kprobeExitCapget(
      @OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> dataptr, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code capset}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct __user_cap_header_struct* header, const struct __user_cap_data_struct* data)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_capset",
      autoAttach = true
  )
  default void enterCapset(@OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code capset}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct __user_cap_header_struct* header, const struct __user_cap_data_struct* data, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_capset",
      autoAttach = true
  )
  default void exitCapset(@OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> data, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code capset}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct __user_cap_header_struct* header, const struct __user_cap_data_struct* data)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_capset",
      autoAttach = true
  )
  default void kprobeEnterCapset(
      @OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code capset}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct __user_cap_header_struct* header, const struct __user_cap_data_struct* data, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_capset",
      autoAttach = true
  )
  default void kprobeExitCapset(
      @OriginalName("cap_user_header_t") Ptr<__user_cap_header_struct> header,
      @OriginalName("cap_user_data_t") Ptr<__user_cap_data_struct> data, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code clock_adjtime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const int which_clock, struct __kernel_timex* ktx)",
      lastStatement = "return 0;",
      section = "fentry/do_clock_adjtime",
      autoAttach = true
  )
  default void enterClockAdjtime(@OriginalName("clockid_t") int which_clock,
      Ptr<__kernel_timex> ktx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code clock_adjtime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const int which_clock, struct __kernel_timex* ktx, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_clock_adjtime",
      autoAttach = true
  )
  default void exitClockAdjtime(@OriginalName("clockid_t") int which_clock, Ptr<__kernel_timex> ktx,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code clock_adjtime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const int which_clock, struct __kernel_timex* ktx)",
      lastStatement = "return 0;",
      section = "kprobe/do_clock_adjtime",
      autoAttach = true
  )
  default void kprobeEnterClockAdjtime(@OriginalName("clockid_t") int which_clock,
      Ptr<__kernel_timex> ktx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code clock_adjtime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const int which_clock, struct __kernel_timex* ktx, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_clock_adjtime",
      autoAttach = true
  )
  default void kprobeExitClockAdjtime(@OriginalName("clockid_t") int which_clock,
      Ptr<__kernel_timex> ktx, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code clone}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int clone_flags, long unsigned int newsp, int* parent_tidptr, int* child_tidptr, long unsigned int tls)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_clone",
      autoAttach = true
  )
  default void enterClone(@Unsigned long clone_flags, @Unsigned long newsp,
      Ptr<java.lang.Integer> parent_tidptr, Ptr<java.lang.Integer> child_tidptr,
      @Unsigned long tls) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code clone}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int clone_flags, long unsigned int newsp, int* parent_tidptr, int* child_tidptr, long unsigned int tls, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_clone",
      autoAttach = true
  )
  default void exitClone(@Unsigned long clone_flags, @Unsigned long newsp,
      Ptr<java.lang.Integer> parent_tidptr, Ptr<java.lang.Integer> child_tidptr, @Unsigned long tls,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code clone}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int clone_flags, long unsigned int newsp, int* parent_tidptr, int* child_tidptr, long unsigned int tls)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_clone",
      autoAttach = true
  )
  default void kprobeEnterClone(@Unsigned long clone_flags, @Unsigned long newsp,
      Ptr<java.lang.Integer> parent_tidptr, Ptr<java.lang.Integer> child_tidptr,
      @Unsigned long tls) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code clone}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int clone_flags, long unsigned int newsp, int* parent_tidptr, int* child_tidptr, long unsigned int tls, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_clone",
      autoAttach = true
  )
  default void kprobeExitClone(@Unsigned long clone_flags, @Unsigned long newsp,
      Ptr<java.lang.Integer> parent_tidptr, Ptr<java.lang.Integer> child_tidptr, @Unsigned long tls,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code clone3}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct clone_args* uargs, long unsigned int size)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_clone3",
      autoAttach = true
  )
  default void enterClone3(Ptr<clone_args> uargs, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code clone3}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct clone_args* uargs, long unsigned int size, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_clone3",
      autoAttach = true
  )
  default void exitClone3(Ptr<clone_args> uargs, @Unsigned long size, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code clone3}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct clone_args* uargs, long unsigned int size)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_clone3",
      autoAttach = true
  )
  default void kprobeEnterClone3(Ptr<clone_args> uargs, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code clone3}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct clone_args* uargs, long unsigned int size, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_clone3",
      autoAttach = true
  )
  default void kprobeExitClone3(Ptr<clone_args> uargs, @Unsigned long size, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code copy_file_range}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd_in, long long int* off_in, int fd_out, long long int* off_out, long unsigned int len, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_copy_file_range",
      autoAttach = true
  )
  default void enterCopyFileRange(int fd_in, Ptr<java.lang. @OriginalName("loff_t") Long> off_in,
      int fd_out, Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code copy_file_range}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd_in, long long int* off_in, int fd_out, long long int* off_out, long unsigned int len, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_copy_file_range",
      autoAttach = true
  )
  default void exitCopyFileRange(int fd_in, Ptr<java.lang. @OriginalName("loff_t") Long> off_in,
      int fd_out, Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code copy_file_range}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int fd_in, long long int* off_in, int fd_out, long long int* off_out, long unsigned int len, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_copy_file_range",
      autoAttach = true
  )
  default void kprobeEnterCopyFileRange(int fd_in,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_in, int fd_out,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code copy_file_range}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int fd_in, long long int* off_in, int fd_out, long long int* off_out, long unsigned int len, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_copy_file_range",
      autoAttach = true
  )
  default void kprobeExitCopyFileRange(int fd_in,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_in, int fd_out,
      Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len, @Unsigned int flags,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code delete_module}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* name_user, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_delete_module",
      autoAttach = true
  )
  default void enterDeleteModule(String name_user, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code delete_module}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* name_user, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_delete_module",
      autoAttach = true
  )
  default void exitDeleteModule(String name_user, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code delete_module}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* name_user, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_delete_module",
      autoAttach = true
  )
  default void kprobeEnterDeleteModule(String name_user, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code delete_module}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* name_user, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_delete_module",
      autoAttach = true
  )
  default void kprobeExitDeleteModule(String name_user, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code dup2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct files_struct* files, struct file* file, unsigned int fd, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_dup2",
      autoAttach = true
  )
  default void enterDup2(Ptr<files_struct> files, Ptr<file> file, @Unsigned int fd,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code dup2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct files_struct* files, struct file* file, unsigned int fd, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_dup2",
      autoAttach = true
  )
  default void exitDup2(Ptr<files_struct> files, Ptr<file> file, @Unsigned int fd,
      @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code dup2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct files_struct* files, struct file* file, unsigned int fd, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_dup2",
      autoAttach = true
  )
  default void kprobeEnterDup2(Ptr<files_struct> files, Ptr<file> file, @Unsigned int fd,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code dup2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct files_struct* files, struct file* file, unsigned int fd, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_dup2",
      autoAttach = true
  )
  default void kprobeExitDup2(Ptr<files_struct> files, Ptr<file> file, @Unsigned int fd,
      @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code epoll_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_epoll_create",
      autoAttach = true
  )
  default void enterEpollCreate(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code epoll_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_epoll_create",
      autoAttach = true
  )
  default void exitEpollCreate(int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code epoll_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_epoll_create",
      autoAttach = true
  )
  default void kprobeEnterEpollCreate(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code epoll_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_epoll_create",
      autoAttach = true
  )
  default void kprobeExitEpollCreate(int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code epoll_ctl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int epfd, int op, int fd, struct epoll_event* epds, _Bool nonblock)",
      lastStatement = "return 0;",
      section = "fentry/do_epoll_ctl",
      autoAttach = true
  )
  default void enterEpollCtl(int epfd, int op, int fd, Ptr<epoll_event> epds, boolean nonblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code epoll_ctl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int epfd, int op, int fd, struct epoll_event* epds, _Bool nonblock, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_epoll_ctl",
      autoAttach = true
  )
  default void exitEpollCtl(int epfd, int op, int fd, Ptr<epoll_event> epds, boolean nonblock,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code epoll_ctl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int epfd, int op, int fd, struct epoll_event* epds, _Bool nonblock)",
      lastStatement = "return 0;",
      section = "kprobe/do_epoll_ctl",
      autoAttach = true
  )
  default void kprobeEnterEpollCtl(int epfd, int op, int fd, Ptr<epoll_event> epds,
      boolean nonblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code epoll_ctl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int epfd, int op, int fd, struct epoll_event* epds, _Bool nonblock, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_epoll_ctl",
      autoAttach = true
  )
  default void kprobeExitEpollCtl(int epfd, int op, int fd, Ptr<epoll_event> epds, boolean nonblock,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code epoll_wait}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int epfd, struct epoll_event* events, int maxevents, struct timespec64* to)",
      lastStatement = "return 0;",
      section = "fentry/do_epoll_wait",
      autoAttach = true
  )
  default void enterEpollWait(int epfd, Ptr<epoll_event> events, int maxevents,
      Ptr<timespec64> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code epoll_wait}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int epfd, struct epoll_event* events, int maxevents, struct timespec64* to, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_epoll_wait",
      autoAttach = true
  )
  default void exitEpollWait(int epfd, Ptr<epoll_event> events, int maxevents, Ptr<timespec64> to,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code epoll_wait}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int epfd, struct epoll_event* events, int maxevents, struct timespec64* to)",
      lastStatement = "return 0;",
      section = "kprobe/do_epoll_wait",
      autoAttach = true
  )
  default void kprobeEnterEpollWait(int epfd, Ptr<epoll_event> events, int maxevents,
      Ptr<timespec64> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code epoll_wait}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int epfd, struct epoll_event* events, int maxevents, struct timespec64* to, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_epoll_wait",
      autoAttach = true
  )
  default void kprobeExitEpollWait(int epfd, Ptr<epoll_event> events, int maxevents,
      Ptr<timespec64> to, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code eventfd}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int count, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_eventfd",
      autoAttach = true
  )
  default void enterEventfd(@Unsigned int count, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code eventfd}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int count, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_eventfd",
      autoAttach = true
  )
  default void exitEventfd(@Unsigned int count, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code eventfd}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int count, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_eventfd",
      autoAttach = true
  )
  default void kprobeEnterEventfd(@Unsigned int count, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code eventfd}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int count, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_eventfd",
      autoAttach = true
  )
  default void kprobeExitEventfd(@Unsigned int count, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code faccessat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, int mode, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_faccessat",
      autoAttach = true
  )
  default void enterFaccessat(int dfd, String filename, int mode, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code faccessat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, int mode, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_faccessat",
      autoAttach = true
  )
  default void exitFaccessat(int dfd, String filename, int mode, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code faccessat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, const u8* filename, int mode, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_faccessat",
      autoAttach = true
  )
  default void kprobeEnterFaccessat(int dfd, String filename, int mode, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code faccessat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, const u8* filename, int mode, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_faccessat",
      autoAttach = true
  )
  default void kprobeExitFaccessat(int dfd, String filename, int mode, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fanotify_init}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int flags, unsigned int event_f_flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_fanotify_init",
      autoAttach = true
  )
  default void enterFanotifyInit(@Unsigned int flags, @Unsigned int event_f_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fanotify_init}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int flags, unsigned int event_f_flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_fanotify_init",
      autoAttach = true
  )
  default void exitFanotifyInit(@Unsigned int flags, @Unsigned int event_f_flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fanotify_init}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int flags, unsigned int event_f_flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_fanotify_init",
      autoAttach = true
  )
  default void kprobeEnterFanotifyInit(@Unsigned int flags, @Unsigned int event_f_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fanotify_init}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int flags, unsigned int event_f_flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_fanotify_init",
      autoAttach = true
  )
  default void kprobeExitFanotifyInit(@Unsigned int flags, @Unsigned int event_f_flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fanotify_mark}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fanotify_fd, unsigned int flags, long long unsigned int mask, int dfd, const u8* pathname)",
      lastStatement = "return 0;",
      section = "fentry/do_fanotify_mark",
      autoAttach = true
  )
  default void enterFanotifyMark(int fanotify_fd, @Unsigned int flags, @Unsigned long mask, int dfd,
      String pathname) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fanotify_mark}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fanotify_fd, unsigned int flags, long long unsigned int mask, int dfd, const u8* pathname, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_fanotify_mark",
      autoAttach = true
  )
  default void exitFanotifyMark(int fanotify_fd, @Unsigned int flags, @Unsigned long mask, int dfd,
      String pathname, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fanotify_mark}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int fanotify_fd, unsigned int flags, long long unsigned int mask, int dfd, const u8* pathname)",
      lastStatement = "return 0;",
      section = "kprobe/do_fanotify_mark",
      autoAttach = true
  )
  default void kprobeEnterFanotifyMark(int fanotify_fd, @Unsigned int flags, @Unsigned long mask,
      int dfd, String pathname) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fanotify_mark}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int fanotify_fd, unsigned int flags, long long unsigned int mask, int dfd, const u8* pathname, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_fanotify_mark",
      autoAttach = true
  )
  default void kprobeExitFanotifyMark(int fanotify_fd, @Unsigned int flags, @Unsigned long mask,
      int dfd, String pathname, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fchmodat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, short unsigned int mode, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_fchmodat",
      autoAttach = true
  )
  default void enterFchmodat(int dfd, String filename,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fchmodat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, short unsigned int mode, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_fchmodat",
      autoAttach = true
  )
  default void exitFchmodat(int dfd, String filename, @Unsigned @OriginalName("umode_t") short mode,
      @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fchmodat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, const u8* filename, short unsigned int mode, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_fchmodat",
      autoAttach = true
  )
  default void kprobeEnterFchmodat(int dfd, String filename,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fchmodat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, const u8* filename, short unsigned int mode, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_fchmodat",
      autoAttach = true
  )
  default void kprobeExitFchmodat(int dfd, String filename,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fchownat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, unsigned int user, unsigned int group, int flag)",
      lastStatement = "return 0;",
      section = "fentry/do_fchownat",
      autoAttach = true
  )
  default void enterFchownat(int dfd, String filename, @Unsigned @OriginalName("uid_t") int user,
      @Unsigned @OriginalName("gid_t") int group, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fchownat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, unsigned int user, unsigned int group, int flag, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_fchownat",
      autoAttach = true
  )
  default void exitFchownat(int dfd, String filename, @Unsigned @OriginalName("uid_t") int user,
      @Unsigned @OriginalName("gid_t") int group, int flag, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fchownat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, const u8* filename, unsigned int user, unsigned int group, int flag)",
      lastStatement = "return 0;",
      section = "kprobe/do_fchownat",
      autoAttach = true
  )
  default void kprobeEnterFchownat(int dfd, String filename,
      @Unsigned @OriginalName("uid_t") int user, @Unsigned @OriginalName("gid_t") int group,
      int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fchownat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, const u8* filename, unsigned int user, unsigned int group, int flag, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_fchownat",
      autoAttach = true
  )
  default void kprobeExitFchownat(int dfd, String filename,
      @Unsigned @OriginalName("uid_t") int user, @Unsigned @OriginalName("gid_t") int group,
      int flag, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fcntl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, unsigned int cmd, long unsigned int arg, struct file* filp)",
      lastStatement = "return 0;",
      section = "fentry/do_fcntl",
      autoAttach = true
  )
  default void enterFcntl(int fd, @Unsigned int cmd, @Unsigned long arg, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fcntl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, unsigned int cmd, long unsigned int arg, struct file* filp, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_fcntl",
      autoAttach = true
  )
  default void exitFcntl(int fd, @Unsigned int cmd, @Unsigned long arg, Ptr<file> filp, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fcntl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int fd, unsigned int cmd, long unsigned int arg, struct file* filp)",
      lastStatement = "return 0;",
      section = "kprobe/do_fcntl",
      autoAttach = true
  )
  default void kprobeEnterFcntl(int fd, @Unsigned int cmd, @Unsigned long arg, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fcntl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int fd, unsigned int cmd, long unsigned int arg, struct file* filp, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_fcntl",
      autoAttach = true
  )
  default void kprobeExitFcntl(int fd, @Unsigned int cmd, @Unsigned long arg, Ptr<file> filp,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code flock}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, unsigned int cmd)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_flock",
      autoAttach = true
  )
  default void enterFlock(@Unsigned int fd, @Unsigned int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code flock}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, unsigned int cmd, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_flock",
      autoAttach = true
  )
  default void exitFlock(@Unsigned int fd, @Unsigned int cmd, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code flock}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int fd, unsigned int cmd)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_flock",
      autoAttach = true
  )
  default void kprobeEnterFlock(@Unsigned int fd, @Unsigned int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code flock}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int fd, unsigned int cmd, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_flock",
      autoAttach = true
  )
  default void kprobeExitFlock(@Unsigned int fd, @Unsigned int cmd, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fork}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_fork",
      autoAttach = true
  )
  default void enterFork(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fork}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_fork",
      autoAttach = true
  )
  default void exitFork(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fork}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_fork",
      autoAttach = true
  )
  default void kprobeEnterFork(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fork}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_fork",
      autoAttach = true
  )
  default void kprobeExitFork(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fstat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, struct __old_kernel_stat* statbuf)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_fstat",
      autoAttach = true
  )
  default void enterFstat(@Unsigned int fd, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fstat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, struct __old_kernel_stat* statbuf, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_fstat",
      autoAttach = true
  )
  default void exitFstat(@Unsigned int fd, Ptr<__old_kernel_stat> statbuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fstat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int fd, struct __old_kernel_stat* statbuf)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_fstat",
      autoAttach = true
  )
  default void kprobeEnterFstat(@Unsigned int fd, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fstat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int fd, struct __old_kernel_stat* statbuf, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_fstat",
      autoAttach = true
  )
  default void kprobeExitFstat(@Unsigned int fd, Ptr<__old_kernel_stat> statbuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fstatfs}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, struct statfs* buf)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_fstatfs",
      autoAttach = true
  )
  default void enterFstatfs(@Unsigned int fd, Ptr<statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fstatfs}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, struct statfs* buf, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_fstatfs",
      autoAttach = true
  )
  default void exitFstatfs(@Unsigned int fd, Ptr<statfs> buf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fstatfs}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int fd, struct statfs* buf)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_fstatfs",
      autoAttach = true
  )
  default void kprobeEnterFstatfs(@Unsigned int fd, Ptr<statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fstatfs}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int fd, struct statfs* buf, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_fstatfs",
      autoAttach = true
  )
  default void kprobeExitFstatfs(@Unsigned int fd, Ptr<statfs> buf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fsync}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, int datasync)",
      lastStatement = "return 0;",
      section = "fentry/do_fsync",
      autoAttach = true
  )
  default void enterFsync(@Unsigned int fd, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fsync}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, int datasync, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_fsync",
      autoAttach = true
  )
  default void exitFsync(@Unsigned int fd, int datasync, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code fsync}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int fd, int datasync)",
      lastStatement = "return 0;",
      section = "kprobe/do_fsync",
      autoAttach = true
  )
  default void kprobeEnterFsync(@Unsigned int fd, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code fsync}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int fd, int datasync, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_fsync",
      autoAttach = true
  )
  default void kprobeExitFsync(@Unsigned int fd, int datasync, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ftruncate}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, long long int length, int small)",
      lastStatement = "return 0;",
      section = "fentry/do_sys_ftruncate",
      autoAttach = true
  )
  default void enterFtruncate(@Unsigned int fd, @OriginalName("loff_t") long length, int small) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ftruncate}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int fd, long long int length, int small, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sys_ftruncate",
      autoAttach = true
  )
  default void exitFtruncate(@Unsigned int fd, @OriginalName("loff_t") long length, int small,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ftruncate}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int fd, long long int length, int small)",
      lastStatement = "return 0;",
      section = "kprobe/do_sys_ftruncate",
      autoAttach = true
  )
  default void kprobeEnterFtruncate(@Unsigned int fd, @OriginalName("loff_t") long length,
      int small) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ftruncate}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int fd, long long int length, int small, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sys_ftruncate",
      autoAttach = true
  )
  default void kprobeExitFtruncate(@Unsigned int fd, @OriginalName("loff_t") long length, int small,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code futex}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int* uaddr, int op, unsigned int val, long long int* timeout, unsigned int* uaddr2, unsigned int val2, unsigned int val3)",
      lastStatement = "return 0;",
      section = "fentry/do_futex",
      autoAttach = true
  )
  default void enterFutex(Ptr<java.lang. @Unsigned Integer> uaddr, int op, @Unsigned int val,
      Ptr<java.lang. @OriginalName("ktime_t") Long> timeout,
      Ptr<java.lang. @Unsigned Integer> uaddr2, @Unsigned int val2, @Unsigned int val3) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code futex}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int* uaddr, int op, unsigned int val, long long int* timeout, unsigned int* uaddr2, unsigned int val2, unsigned int val3, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_futex",
      autoAttach = true
  )
  default void exitFutex(Ptr<java.lang. @Unsigned Integer> uaddr, int op, @Unsigned int val,
      Ptr<java.lang. @OriginalName("ktime_t") Long> timeout,
      Ptr<java.lang. @Unsigned Integer> uaddr2, @Unsigned int val2, @Unsigned int val3, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code futex}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int* uaddr, int op, unsigned int val, long long int* timeout, unsigned int* uaddr2, unsigned int val2, unsigned int val3)",
      lastStatement = "return 0;",
      section = "kprobe/do_futex",
      autoAttach = true
  )
  default void kprobeEnterFutex(Ptr<java.lang. @Unsigned Integer> uaddr, int op, @Unsigned int val,
      Ptr<java.lang. @OriginalName("ktime_t") Long> timeout,
      Ptr<java.lang. @Unsigned Integer> uaddr2, @Unsigned int val2, @Unsigned int val3) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code futex}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int* uaddr, int op, unsigned int val, long long int* timeout, unsigned int* uaddr2, unsigned int val2, unsigned int val3, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_futex",
      autoAttach = true
  )
  default void kprobeExitFutex(Ptr<java.lang. @Unsigned Integer> uaddr, int op, @Unsigned int val,
      Ptr<java.lang. @OriginalName("ktime_t") Long> timeout,
      Ptr<java.lang. @Unsigned Integer> uaddr2, @Unsigned int val2, @Unsigned int val3, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code get_mempolicy}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int* policy, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int addr, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_get_mempolicy",
      autoAttach = true
  )
  default void enterGetMempolicy(Ptr<java.lang.Integer> policy, Ptr<nodemask_t> nmask,
      @Unsigned long addr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code get_mempolicy}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int* policy, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int addr, long unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_get_mempolicy",
      autoAttach = true
  )
  default void exitGetMempolicy(Ptr<java.lang.Integer> policy, Ptr<nodemask_t> nmask,
      @Unsigned long addr, @Unsigned long flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code get_mempolicy}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int* policy, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int addr, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_get_mempolicy",
      autoAttach = true
  )
  default void kprobeEnterGetMempolicy(Ptr<java.lang.Integer> policy, Ptr<nodemask_t> nmask,
      @Unsigned long addr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code get_mempolicy}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int* policy, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int addr, long unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_get_mempolicy",
      autoAttach = true
  )
  default void kprobeExitGetMempolicy(Ptr<java.lang.Integer> policy, Ptr<nodemask_t> nmask,
      @Unsigned long addr, @Unsigned long flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code get_thread_area}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct task_struct* p, int idx, struct user_desc* u_info)",
      lastStatement = "return 0;",
      section = "fentry/do_get_thread_area",
      autoAttach = true
  )
  default void enterGetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code get_thread_area}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct task_struct* p, int idx, struct user_desc* u_info, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_get_thread_area",
      autoAttach = true
  )
  default void exitGetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code get_thread_area}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct task_struct* p, int idx, struct user_desc* u_info)",
      lastStatement = "return 0;",
      section = "kprobe/do_get_thread_area",
      autoAttach = true
  )
  default void kprobeEnterGetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code get_thread_area}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct task_struct* p, int idx, struct user_desc* u_info, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_get_thread_area",
      autoAttach = true
  )
  default void kprobeExitGetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getcwd}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, u8* buf, long unsigned int size)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getcwd",
      autoAttach = true
  )
  default void enterGetcwd(String buf, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getcwd}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, u8* buf, long unsigned int size, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getcwd",
      autoAttach = true
  )
  default void exitGetcwd(String buf, @Unsigned long size, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getcwd}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, u8* buf, long unsigned int size)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getcwd",
      autoAttach = true
  )
  default void kprobeEnterGetcwd(String buf, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getcwd}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, u8* buf, long unsigned int size, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getcwd",
      autoAttach = true
  )
  default void kprobeExitGetcwd(String buf, @Unsigned long size, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getegid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getegid",
      autoAttach = true
  )
  default void enterGetegid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getegid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getegid",
      autoAttach = true
  )
  default void exitGetegid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getegid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getegid",
      autoAttach = true
  )
  default void kprobeEnterGetegid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getegid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getegid",
      autoAttach = true
  )
  default void kprobeExitGetegid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code geteuid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_geteuid",
      autoAttach = true
  )
  default void enterGeteuid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code geteuid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_geteuid",
      autoAttach = true
  )
  default void exitGeteuid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code geteuid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_geteuid",
      autoAttach = true
  )
  default void kprobeEnterGeteuid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code geteuid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_geteuid",
      autoAttach = true
  )
  default void kprobeExitGeteuid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getgid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getgid",
      autoAttach = true
  )
  default void enterGetgid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getgid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getgid",
      autoAttach = true
  )
  default void exitGetgid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getgid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getgid",
      autoAttach = true
  )
  default void kprobeEnterGetgid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getgid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getgid",
      autoAttach = true
  )
  default void kprobeExitGetgid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code gethostname}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, u8* name, int len)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_gethostname",
      autoAttach = true
  )
  default void enterGethostname(String name, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code gethostname}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, u8* name, int len, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_gethostname",
      autoAttach = true
  )
  default void exitGethostname(String name, int len, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code gethostname}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, u8* name, int len)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_gethostname",
      autoAttach = true
  )
  default void kprobeEnterGethostname(String name, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code gethostname}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, u8* name, int len, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_gethostname",
      autoAttach = true
  )
  default void kprobeExitGethostname(String name, int len, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpgid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid)",
      lastStatement = "return 0;",
      section = "fentry/do_getpgid",
      autoAttach = true
  )
  default void enterGetpgid(@OriginalName("pid_t") int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpgid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_getpgid",
      autoAttach = true
  )
  default void exitGetpgid(@OriginalName("pid_t") int pid, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpgid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int pid)",
      lastStatement = "return 0;",
      section = "kprobe/do_getpgid",
      autoAttach = true
  )
  default void kprobeEnterGetpgid(@OriginalName("pid_t") int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpgid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int pid, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_getpgid",
      autoAttach = true
  )
  default void kprobeExitGetpgid(@OriginalName("pid_t") int pid, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpgrp}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getpgrp",
      autoAttach = true
  )
  default void enterGetpgrp(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpgrp}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getpgrp",
      autoAttach = true
  )
  default void exitGetpgrp(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpgrp}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getpgrp",
      autoAttach = true
  )
  default void kprobeEnterGetpgrp(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpgrp}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getpgrp",
      autoAttach = true
  )
  default void kprobeExitGetpgrp(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getpid",
      autoAttach = true
  )
  default void enterGetpid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getpid",
      autoAttach = true
  )
  default void exitGetpid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getpid",
      autoAttach = true
  )
  default void kprobeEnterGetpid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getpid",
      autoAttach = true
  )
  default void kprobeExitGetpid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getppid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getppid",
      autoAttach = true
  )
  default void enterGetppid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getppid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getppid",
      autoAttach = true
  )
  default void exitGetppid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getppid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getppid",
      autoAttach = true
  )
  default void kprobeEnterGetppid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getppid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getppid",
      autoAttach = true
  )
  default void kprobeExitGetppid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpriority}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getpriority",
      autoAttach = true
  )
  default void enterGetpriority(int which, int who) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpriority}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getpriority",
      autoAttach = true
  )
  default void exitGetpriority(int which, int who, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getpriority}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int which, int who)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getpriority",
      autoAttach = true
  )
  default void kprobeEnterGetpriority(int which, int who) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getpriority}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int which, int who, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getpriority",
      autoAttach = true
  )
  default void kprobeExitGetpriority(int which, int who, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getrusage}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int who, struct rusage* ru)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getrusage",
      autoAttach = true
  )
  default void enterGetrusage(int who, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getrusage}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int who, struct rusage* ru, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getrusage",
      autoAttach = true
  )
  default void exitGetrusage(int who, Ptr<rusage> ru, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getrusage}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int who, struct rusage* ru)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getrusage",
      autoAttach = true
  )
  default void kprobeEnterGetrusage(int who, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getrusage}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int who, struct rusage* ru, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getrusage",
      autoAttach = true
  )
  default void kprobeExitGetrusage(int who, Ptr<rusage> ru, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code gettid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_gettid",
      autoAttach = true
  )
  default void enterGettid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code gettid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_gettid",
      autoAttach = true
  )
  default void exitGettid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code gettid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_gettid",
      autoAttach = true
  )
  default void kprobeEnterGettid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code gettid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_gettid",
      autoAttach = true
  )
  default void kprobeExitGettid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getuid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_getuid",
      autoAttach = true
  )
  default void enterGetuid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getuid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_getuid",
      autoAttach = true
  )
  default void exitGetuid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code getuid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_getuid",
      autoAttach = true
  )
  default void kprobeEnterGetuid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code getuid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_getuid",
      autoAttach = true
  )
  default void kprobeExitGetuid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code init_module}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct module* mod)",
      lastStatement = "return 0;",
      section = "fentry/do_init_module",
      autoAttach = true
  )
  default void enterInitModule(Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code init_module}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct module* mod, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_init_module",
      autoAttach = true
  )
  default void exitInitModule(Ptr<module> mod, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code init_module}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct module* mod)",
      lastStatement = "return 0;",
      section = "kprobe/do_init_module",
      autoAttach = true
  )
  default void kprobeEnterInitModule(Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code init_module}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct module* mod, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_init_module",
      autoAttach = true
  )
  default void kprobeExitInitModule(Ptr<module> mod, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code inotify_init}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_inotify_init",
      autoAttach = true
  )
  default void enterInotifyInit(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code inotify_init}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_inotify_init",
      autoAttach = true
  )
  default void exitInotifyInit(int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code inotify_init}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_inotify_init",
      autoAttach = true
  )
  default void kprobeEnterInotifyInit(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code inotify_init}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_inotify_init",
      autoAttach = true
  )
  default void kprobeExitInotifyInit(int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code io_getevents}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int ctx_id, long int min_nr, long int nr, struct io_event* events, struct timespec64* ts)",
      lastStatement = "return 0;",
      section = "fentry/do_io_getevents",
      autoAttach = true
  )
  default void enterIoGetevents(@Unsigned @OriginalName("aio_context_t") long ctx_id, long min_nr,
      long nr, Ptr<io_event> events, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code io_getevents}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int ctx_id, long int min_nr, long int nr, struct io_event* events, struct timespec64* ts, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_io_getevents",
      autoAttach = true
  )
  default void exitIoGetevents(@Unsigned @OriginalName("aio_context_t") long ctx_id, long min_nr,
      long nr, Ptr<io_event> events, Ptr<timespec64> ts, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code io_getevents}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int ctx_id, long int min_nr, long int nr, struct io_event* events, struct timespec64* ts)",
      lastStatement = "return 0;",
      section = "kprobe/do_io_getevents",
      autoAttach = true
  )
  default void kprobeEnterIoGetevents(@Unsigned @OriginalName("aio_context_t") long ctx_id,
      long min_nr, long nr, Ptr<io_event> events, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code io_getevents}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int ctx_id, long int min_nr, long int nr, struct io_event* events, struct timespec64* ts, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_io_getevents",
      autoAttach = true
  )
  default void kprobeExitIoGetevents(@Unsigned @OriginalName("aio_context_t") long ctx_id,
      long min_nr, long nr, Ptr<io_event> events, Ptr<timespec64> ts, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ioprio_get}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_ioprio_get",
      autoAttach = true
  )
  default void enterIoprioGet(int which, int who) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ioprio_get}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_ioprio_get",
      autoAttach = true
  )
  default void exitIoprioGet(int which, int who, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ioprio_get}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int which, int who)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_ioprio_get",
      autoAttach = true
  )
  default void kprobeEnterIoprioGet(int which, int who) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ioprio_get}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int which, int who, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_ioprio_get",
      autoAttach = true
  )
  default void kprobeExitIoprioGet(int which, int who, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ioprio_set}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who, int ioprio)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_ioprio_set",
      autoAttach = true
  )
  default void enterIoprioSet(int which, int who, int ioprio) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ioprio_set}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who, int ioprio, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_ioprio_set",
      autoAttach = true
  )
  default void exitIoprioSet(int which, int who, int ioprio, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ioprio_set}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int which, int who, int ioprio)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_ioprio_set",
      autoAttach = true
  )
  default void kprobeEnterIoprioSet(int which, int who, int ioprio) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ioprio_set}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int which, int who, int ioprio, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_ioprio_set",
      autoAttach = true
  )
  default void kprobeExitIoprioSet(int which, int who, int ioprio, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code kcmp}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid1, int pid2, int type, long unsigned int idx1, long unsigned int idx2)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_kcmp",
      autoAttach = true
  )
  default void enterKcmp(@OriginalName("pid_t") int pid1, @OriginalName("pid_t") int pid2, int type,
      @Unsigned long idx1, @Unsigned long idx2) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code kcmp}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid1, int pid2, int type, long unsigned int idx1, long unsigned int idx2, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_kcmp",
      autoAttach = true
  )
  default void exitKcmp(@OriginalName("pid_t") int pid1, @OriginalName("pid_t") int pid2, int type,
      @Unsigned long idx1, @Unsigned long idx2, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code kcmp}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int pid1, int pid2, int type, long unsigned int idx1, long unsigned int idx2)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_kcmp",
      autoAttach = true
  )
  default void kprobeEnterKcmp(@OriginalName("pid_t") int pid1, @OriginalName("pid_t") int pid2,
      int type, @Unsigned long idx1, @Unsigned long idx2) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code kcmp}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int pid1, int pid2, int type, long unsigned int idx1, long unsigned int idx2, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_kcmp",
      autoAttach = true
  )
  default void kprobeExitKcmp(@OriginalName("pid_t") int pid1, @OriginalName("pid_t") int pid2,
      int type, @Unsigned long idx1, @Unsigned long idx2, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code kexec_file_load}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int kernel_fd, int initrd_fd, long unsigned int cmdline_len, const u8* cmdline_ptr, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_kexec_file_load",
      autoAttach = true
  )
  default void enterKexecFileLoad(int kernel_fd, int initrd_fd, @Unsigned long cmdline_len,
      String cmdline_ptr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code kexec_file_load}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int kernel_fd, int initrd_fd, long unsigned int cmdline_len, const u8* cmdline_ptr, long unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_kexec_file_load",
      autoAttach = true
  )
  default void exitKexecFileLoad(int kernel_fd, int initrd_fd, @Unsigned long cmdline_len,
      String cmdline_ptr, @Unsigned long flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code kexec_file_load}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int kernel_fd, int initrd_fd, long unsigned int cmdline_len, const u8* cmdline_ptr, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_kexec_file_load",
      autoAttach = true
  )
  default void kprobeEnterKexecFileLoad(int kernel_fd, int initrd_fd, @Unsigned long cmdline_len,
      String cmdline_ptr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code kexec_file_load}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int kernel_fd, int initrd_fd, long unsigned int cmdline_len, const u8* cmdline_ptr, long unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_kexec_file_load",
      autoAttach = true
  )
  default void kprobeExitKexecFileLoad(int kernel_fd, int initrd_fd, @Unsigned long cmdline_len,
      String cmdline_ptr, @Unsigned long flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code kexec_load}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int entry, long unsigned int nr_segments, struct kexec_segment* segments, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_kexec_load",
      autoAttach = true
  )
  default void enterKexecLoad(@Unsigned long entry, @Unsigned long nr_segments,
      Ptr<kexec_segment> segments, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code kexec_load}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int entry, long unsigned int nr_segments, struct kexec_segment* segments, long unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_kexec_load",
      autoAttach = true
  )
  default void exitKexecLoad(@Unsigned long entry, @Unsigned long nr_segments,
      Ptr<kexec_segment> segments, @Unsigned long flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code kexec_load}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int entry, long unsigned int nr_segments, struct kexec_segment* segments, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_kexec_load",
      autoAttach = true
  )
  default void kprobeEnterKexecLoad(@Unsigned long entry, @Unsigned long nr_segments,
      Ptr<kexec_segment> segments, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code kexec_load}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int entry, long unsigned int nr_segments, struct kexec_segment* segments, long unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_kexec_load",
      autoAttach = true
  )
  default void kprobeExitKexecLoad(@Unsigned long entry, @Unsigned long nr_segments,
      Ptr<kexec_segment> segments, @Unsigned long flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code keyctl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_keyctl",
      autoAttach = true
  )
  default void enterKeyctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code keyctl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_keyctl",
      autoAttach = true
  )
  default void exitKeyctl(int option, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code keyctl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_keyctl",
      autoAttach = true
  )
  default void kprobeEnterKeyctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code keyctl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_keyctl",
      autoAttach = true
  )
  default void kprobeExitKeyctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code landlock_create_ruleset}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const const struct landlock_ruleset_attr* attr, const long unsigned int size, const unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_landlock_create_ruleset",
      autoAttach = true
  )
  default void enterLandlockCreateRuleset(Ptr<landlock_ruleset_attr> attr, @Unsigned long size,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code landlock_create_ruleset}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const const struct landlock_ruleset_attr* attr, const long unsigned int size, const unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_landlock_create_ruleset",
      autoAttach = true
  )
  default void exitLandlockCreateRuleset(Ptr<landlock_ruleset_attr> attr, @Unsigned long size,
      @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code landlock_create_ruleset}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const const struct landlock_ruleset_attr* attr, const long unsigned int size, const unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_landlock_create_ruleset",
      autoAttach = true
  )
  default void kprobeEnterLandlockCreateRuleset(Ptr<landlock_ruleset_attr> attr,
      @Unsigned long size, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code landlock_create_ruleset}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const const struct landlock_ruleset_attr* attr, const long unsigned int size, const unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_landlock_create_ruleset",
      autoAttach = true
  )
  default void kprobeExitLandlockCreateRuleset(Ptr<landlock_ruleset_attr> attr, @Unsigned long size,
      @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code landlock_restrict_self}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const int ruleset_fd, const unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_landlock_restrict_self",
      autoAttach = true
  )
  default void enterLandlockRestrictSelf(int ruleset_fd, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code landlock_restrict_self}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const int ruleset_fd, const unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_landlock_restrict_self",
      autoAttach = true
  )
  default void exitLandlockRestrictSelf(int ruleset_fd, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code landlock_restrict_self}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const int ruleset_fd, const unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_landlock_restrict_self",
      autoAttach = true
  )
  default void kprobeEnterLandlockRestrictSelf(int ruleset_fd, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code landlock_restrict_self}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const int ruleset_fd, const unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_landlock_restrict_self",
      autoAttach = true
  )
  default void kprobeExitLandlockRestrictSelf(int ruleset_fd, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code linkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int olddfd, struct filename* old, int newdfd, struct filename* new, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_linkat",
      autoAttach = true
  )
  default void enterLinkat(int olddfd, Ptr<filename> old, int newdfd, Ptr<filename> _new,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code linkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int olddfd, struct filename* old, int newdfd, struct filename* new, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_linkat",
      autoAttach = true
  )
  default void exitLinkat(int olddfd, Ptr<filename> old, int newdfd, Ptr<filename> _new, int flags,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code linkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int olddfd, struct filename* old, int newdfd, struct filename* new, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_linkat",
      autoAttach = true
  )
  default void kprobeEnterLinkat(int olddfd, Ptr<filename> old, int newdfd, Ptr<filename> _new,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code linkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int olddfd, struct filename* old, int newdfd, struct filename* new, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_linkat",
      autoAttach = true
  )
  default void kprobeExitLinkat(int olddfd, Ptr<filename> old, int newdfd, Ptr<filename> _new,
      int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code lstat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* filename, struct __old_kernel_stat* statbuf)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_lstat",
      autoAttach = true
  )
  default void enterLstat(String filename, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code lstat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* filename, struct __old_kernel_stat* statbuf, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_lstat",
      autoAttach = true
  )
  default void exitLstat(String filename, Ptr<__old_kernel_stat> statbuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code lstat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* filename, struct __old_kernel_stat* statbuf)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_lstat",
      autoAttach = true
  )
  default void kprobeEnterLstat(String filename, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code lstat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* filename, struct __old_kernel_stat* statbuf, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_lstat",
      autoAttach = true
  )
  default void kprobeExitLstat(String filename, Ptr<__old_kernel_stat> statbuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code madvise}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mm_struct* mm, long unsigned int start, long unsigned int len_in, int behavior)",
      lastStatement = "return 0;",
      section = "fentry/do_madvise",
      autoAttach = true
  )
  default void enterMadvise(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len_in,
      int behavior) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code madvise}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mm_struct* mm, long unsigned int start, long unsigned int len_in, int behavior, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_madvise",
      autoAttach = true
  )
  default void exitMadvise(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len_in,
      int behavior, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code madvise}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct mm_struct* mm, long unsigned int start, long unsigned int len_in, int behavior)",
      lastStatement = "return 0;",
      section = "kprobe/do_madvise",
      autoAttach = true
  )
  default void kprobeEnterMadvise(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len_in,
      int behavior) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code madvise}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct mm_struct* mm, long unsigned int start, long unsigned int len_in, int behavior, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_madvise",
      autoAttach = true
  )
  default void kprobeExitMadvise(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len_in,
      int behavior, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mbind}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int start, long unsigned int len, short unsigned int mode, short unsigned int mode_flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_mbind",
      autoAttach = true
  )
  default void enterMbind(@Unsigned long start, @Unsigned long len, @Unsigned short mode,
      @Unsigned short mode_flags, Ptr<nodemask_t> nmask, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mbind}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int start, long unsigned int len, short unsigned int mode, short unsigned int mode_flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mbind",
      autoAttach = true
  )
  default void exitMbind(@Unsigned long start, @Unsigned long len, @Unsigned short mode,
      @Unsigned short mode_flags, Ptr<nodemask_t> nmask, @Unsigned long flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mbind}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int start, long unsigned int len, short unsigned int mode, short unsigned int mode_flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_mbind",
      autoAttach = true
  )
  default void kprobeEnterMbind(@Unsigned long start, @Unsigned long len, @Unsigned short mode,
      @Unsigned short mode_flags, Ptr<nodemask_t> nmask, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mbind}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int start, long unsigned int len, short unsigned int mode, short unsigned int mode_flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nmask, long unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mbind",
      autoAttach = true
  )
  default void kprobeExitMbind(@Unsigned long start, @Unsigned long len, @Unsigned short mode,
      @Unsigned short mode_flags, Ptr<nodemask_t> nmask, @Unsigned long flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code membarrier}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int cmd, unsigned int flags, int cpu_id)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_membarrier",
      autoAttach = true
  )
  default void enterMembarrier(int cmd, @Unsigned int flags, int cpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code membarrier}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int cmd, unsigned int flags, int cpu_id, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_membarrier",
      autoAttach = true
  )
  default void exitMembarrier(int cmd, @Unsigned int flags, int cpu_id, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code membarrier}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int cmd, unsigned int flags, int cpu_id)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_membarrier",
      autoAttach = true
  )
  default void kprobeEnterMembarrier(int cmd, @Unsigned int flags, int cpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code membarrier}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int cmd, unsigned int flags, int cpu_id, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_membarrier",
      autoAttach = true
  )
  default void kprobeExitMembarrier(int cmd, @Unsigned int flags, int cpu_id, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code memfd_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* uname, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_memfd_create",
      autoAttach = true
  )
  default void enterMemfdCreate(String uname, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code memfd_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* uname, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_memfd_create",
      autoAttach = true
  )
  default void exitMemfdCreate(String uname, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code memfd_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* uname, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_memfd_create",
      autoAttach = true
  )
  default void kprobeEnterMemfdCreate(String uname, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code memfd_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* uname, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_memfd_create",
      autoAttach = true
  )
  default void kprobeExitMemfdCreate(String uname, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code migrate_pages}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mm_struct* mm, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* from, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* to, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_migrate_pages",
      autoAttach = true
  )
  default void enterMigratePages(Ptr<mm_struct> mm, Ptr<nodemask_t> from, Ptr<nodemask_t> to,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code migrate_pages}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mm_struct* mm, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* from, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* to, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_migrate_pages",
      autoAttach = true
  )
  default void exitMigratePages(Ptr<mm_struct> mm, Ptr<nodemask_t> from, Ptr<nodemask_t> to,
      int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code migrate_pages}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct mm_struct* mm, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* from, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* to, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_migrate_pages",
      autoAttach = true
  )
  default void kprobeEnterMigratePages(Ptr<mm_struct> mm, Ptr<nodemask_t> from, Ptr<nodemask_t> to,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code migrate_pages}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct mm_struct* mm, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* from, const struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* to, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_migrate_pages",
      autoAttach = true
  )
  default void kprobeExitMigratePages(Ptr<mm_struct> mm, Ptr<nodemask_t> from, Ptr<nodemask_t> to,
      int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mincore}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int addr, long unsigned int pages, u8* vec)",
      lastStatement = "return 0;",
      section = "fentry/do_mincore",
      autoAttach = true
  )
  default void enterMincore(@Unsigned long addr, @Unsigned long pages, String vec) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mincore}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int addr, long unsigned int pages, u8* vec, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mincore",
      autoAttach = true
  )
  default void exitMincore(@Unsigned long addr, @Unsigned long pages, String vec, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mincore}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int addr, long unsigned int pages, u8* vec)",
      lastStatement = "return 0;",
      section = "kprobe/do_mincore",
      autoAttach = true
  )
  default void kprobeEnterMincore(@Unsigned long addr, @Unsigned long pages, String vec) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mincore}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int addr, long unsigned int pages, u8* vec, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mincore",
      autoAttach = true
  )
  default void kprobeExitMincore(@Unsigned long addr, @Unsigned long pages, String vec, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mkdirat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name, short unsigned int mode)",
      lastStatement = "return 0;",
      section = "fentry/do_mkdirat",
      autoAttach = true
  )
  default void enterMkdirat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mkdirat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name, short unsigned int mode, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mkdirat",
      autoAttach = true
  )
  default void exitMkdirat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mkdirat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, struct filename* name, short unsigned int mode)",
      lastStatement = "return 0;",
      section = "kprobe/do_mkdirat",
      autoAttach = true
  )
  default void kprobeEnterMkdirat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mkdirat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, struct filename* name, short unsigned int mode, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mkdirat",
      autoAttach = true
  )
  default void kprobeExitMkdirat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mknodat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name, short unsigned int mode, unsigned int dev)",
      lastStatement = "return 0;",
      section = "fentry/do_mknodat",
      autoAttach = true
  )
  default void enterMknodat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mknodat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name, short unsigned int mode, unsigned int dev, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mknodat",
      autoAttach = true
  )
  default void exitMknodat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mknodat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, struct filename* name, short unsigned int mode, unsigned int dev)",
      lastStatement = "return 0;",
      section = "kprobe/do_mknodat",
      autoAttach = true
  )
  default void kprobeEnterMknodat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mknodat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, struct filename* name, short unsigned int mode, unsigned int dev, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mknodat",
      autoAttach = true
  )
  default void kprobeExitMknodat(int dfd, Ptr<filename> name,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mlock}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int start, long unsigned int len, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_mlock",
      autoAttach = true
  )
  default void enterMlock(@Unsigned long start, @Unsigned long len,
      @Unsigned @OriginalName("vm_flags_t") long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mlock}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int start, long unsigned int len, long unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mlock",
      autoAttach = true
  )
  default void exitMlock(@Unsigned long start, @Unsigned long len,
      @Unsigned @OriginalName("vm_flags_t") long flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mlock}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int start, long unsigned int len, long unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_mlock",
      autoAttach = true
  )
  default void kprobeEnterMlock(@Unsigned long start, @Unsigned long len,
      @Unsigned @OriginalName("vm_flags_t") long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mlock}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int start, long unsigned int len, long unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mlock",
      autoAttach = true
  )
  default void kprobeExitMlock(@Unsigned long start, @Unsigned long len,
      @Unsigned @OriginalName("vm_flags_t") long flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mlockall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_mlockall",
      autoAttach = true
  )
  default void enterMlockall(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mlockall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_mlockall",
      autoAttach = true
  )
  default void exitMlockall(int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mlockall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_mlockall",
      autoAttach = true
  )
  default void kprobeEnterMlockall(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mlockall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_mlockall",
      autoAttach = true
  )
  default void kprobeExitMlockall(int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mmap}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* file, long unsigned int addr, long unsigned int len, long unsigned int prot, long unsigned int flags, long unsigned int vm_flags, long unsigned int pgoff, long unsigned int* populate, struct list_head* uf)",
      lastStatement = "return 0;",
      section = "fentry/do_mmap",
      autoAttach = true
  )
  default void enterMmap(Ptr<file> file, @Unsigned long addr, @Unsigned long len,
      @Unsigned long prot, @Unsigned long flags,
      @Unsigned @OriginalName("vm_flags_t") long vm_flags, @Unsigned long pgoff,
      Ptr<java.lang. @Unsigned Long> populate, Ptr<list_head> uf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mmap}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* file, long unsigned int addr, long unsigned int len, long unsigned int prot, long unsigned int flags, long unsigned int vm_flags, long unsigned int pgoff, long unsigned int* populate, struct list_head* uf, long unsigned int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mmap",
      autoAttach = true
  )
  default void exitMmap(Ptr<file> file, @Unsigned long addr, @Unsigned long len,
      @Unsigned long prot, @Unsigned long flags,
      @Unsigned @OriginalName("vm_flags_t") long vm_flags, @Unsigned long pgoff,
      Ptr<java.lang. @Unsigned Long> populate, Ptr<list_head> uf, @Unsigned long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mmap}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct file* file, long unsigned int addr, long unsigned int len, long unsigned int prot, long unsigned int flags, long unsigned int vm_flags, long unsigned int pgoff, long unsigned int* populate, struct list_head* uf)",
      lastStatement = "return 0;",
      section = "kprobe/do_mmap",
      autoAttach = true
  )
  default void kprobeEnterMmap(Ptr<file> file, @Unsigned long addr, @Unsigned long len,
      @Unsigned long prot, @Unsigned long flags,
      @Unsigned @OriginalName("vm_flags_t") long vm_flags, @Unsigned long pgoff,
      Ptr<java.lang. @Unsigned Long> populate, Ptr<list_head> uf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mmap}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct file* file, long unsigned int addr, long unsigned int len, long unsigned int prot, long unsigned int flags, long unsigned int vm_flags, long unsigned int pgoff, long unsigned int* populate, struct list_head* uf, long unsigned int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mmap",
      autoAttach = true
  )
  default void kprobeExitMmap(Ptr<file> file, @Unsigned long addr, @Unsigned long len,
      @Unsigned long prot, @Unsigned long flags,
      @Unsigned @OriginalName("vm_flags_t") long vm_flags, @Unsigned long pgoff,
      Ptr<java.lang. @Unsigned Long> populate, Ptr<list_head> uf, @Unsigned long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mount}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* dev_name, const u8* dir_name, const u8* type_page, long unsigned int flags, void* data_page)",
      lastStatement = "return 0;",
      section = "fentry/do_mount",
      autoAttach = true
  )
  default void enterMount(String dev_name, String dir_name, String type_page, @Unsigned long flags,
      Ptr<?> data_page) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mount}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* dev_name, const u8* dir_name, const u8* type_page, long unsigned int flags, void* data_page, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mount",
      autoAttach = true
  )
  default void exitMount(String dev_name, String dir_name, String type_page, @Unsigned long flags,
      Ptr<?> data_page, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mount}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* dev_name, const u8* dir_name, const u8* type_page, long unsigned int flags, void* data_page)",
      lastStatement = "return 0;",
      section = "kprobe/do_mount",
      autoAttach = true
  )
  default void kprobeEnterMount(String dev_name, String dir_name, String type_page,
      @Unsigned long flags, Ptr<?> data_page) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mount}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* dev_name, const u8* dir_name, const u8* type_page, long unsigned int flags, void* data_page, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mount",
      autoAttach = true
  )
  default void kprobeExitMount(String dev_name, String dir_name, String type_page,
      @Unsigned long flags, Ptr<?> data_page, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_getsetattr}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, struct mq_attr* new, struct mq_attr* old)",
      lastStatement = "return 0;",
      section = "fentry/do_mq_getsetattr",
      autoAttach = true
  )
  default void enterMqGetsetattr(int mqdes, Ptr<mq_attr> _new, Ptr<mq_attr> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_getsetattr}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, struct mq_attr* new, struct mq_attr* old, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mq_getsetattr",
      autoAttach = true
  )
  default void exitMqGetsetattr(int mqdes, Ptr<mq_attr> _new, Ptr<mq_attr> old, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_getsetattr}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int mqdes, struct mq_attr* new, struct mq_attr* old)",
      lastStatement = "return 0;",
      section = "kprobe/do_mq_getsetattr",
      autoAttach = true
  )
  default void kprobeEnterMqGetsetattr(int mqdes, Ptr<mq_attr> _new, Ptr<mq_attr> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_getsetattr}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int mqdes, struct mq_attr* new, struct mq_attr* old, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mq_getsetattr",
      autoAttach = true
  )
  default void kprobeExitMqGetsetattr(int mqdes, Ptr<mq_attr> _new, Ptr<mq_attr> old, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_notify}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, const struct sigevent* notification)",
      lastStatement = "return 0;",
      section = "fentry/do_mq_notify",
      autoAttach = true
  )
  default void enterMqNotify(@OriginalName("mqd_t") int mqdes, Ptr<sigevent> notification) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_notify}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, const struct sigevent* notification, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mq_notify",
      autoAttach = true
  )
  default void exitMqNotify(@OriginalName("mqd_t") int mqdes, Ptr<sigevent> notification, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_notify}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int mqdes, const struct sigevent* notification)",
      lastStatement = "return 0;",
      section = "kprobe/do_mq_notify",
      autoAttach = true
  )
  default void kprobeEnterMqNotify(@OriginalName("mqd_t") int mqdes, Ptr<sigevent> notification) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_notify}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int mqdes, const struct sigevent* notification, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mq_notify",
      autoAttach = true
  )
  default void kprobeExitMqNotify(@OriginalName("mqd_t") int mqdes, Ptr<sigevent> notification,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_open}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* u_name, int oflag, short unsigned int mode, struct mq_attr* attr)",
      lastStatement = "return 0;",
      section = "fentry/do_mq_open",
      autoAttach = true
  )
  default void enterMqOpen(String u_name, int oflag, @Unsigned @OriginalName("umode_t") short mode,
      Ptr<mq_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_open}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* u_name, int oflag, short unsigned int mode, struct mq_attr* attr, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mq_open",
      autoAttach = true
  )
  default void exitMqOpen(String u_name, int oflag, @Unsigned @OriginalName("umode_t") short mode,
      Ptr<mq_attr> attr, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_open}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* u_name, int oflag, short unsigned int mode, struct mq_attr* attr)",
      lastStatement = "return 0;",
      section = "kprobe/do_mq_open",
      autoAttach = true
  )
  default void kprobeEnterMqOpen(String u_name, int oflag,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<mq_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_open}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* u_name, int oflag, short unsigned int mode, struct mq_attr* attr, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mq_open",
      autoAttach = true
  )
  default void kprobeExitMqOpen(String u_name, int oflag,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<mq_attr> attr, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_timedreceive}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, u8* u_msg_ptr, long unsigned int msg_len, unsigned int* u_msg_prio, struct timespec64* ts)",
      lastStatement = "return 0;",
      section = "fentry/do_mq_timedreceive",
      autoAttach = true
  )
  default void enterMqTimedreceive(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, Ptr<java.lang. @Unsigned Integer> u_msg_prio, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_timedreceive}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, u8* u_msg_ptr, long unsigned int msg_len, unsigned int* u_msg_prio, struct timespec64* ts, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mq_timedreceive",
      autoAttach = true
  )
  default void exitMqTimedreceive(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, Ptr<java.lang. @Unsigned Integer> u_msg_prio, Ptr<timespec64> ts,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_timedreceive}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int mqdes, u8* u_msg_ptr, long unsigned int msg_len, unsigned int* u_msg_prio, struct timespec64* ts)",
      lastStatement = "return 0;",
      section = "kprobe/do_mq_timedreceive",
      autoAttach = true
  )
  default void kprobeEnterMqTimedreceive(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, Ptr<java.lang. @Unsigned Integer> u_msg_prio, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_timedreceive}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int mqdes, u8* u_msg_ptr, long unsigned int msg_len, unsigned int* u_msg_prio, struct timespec64* ts, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mq_timedreceive",
      autoAttach = true
  )
  default void kprobeExitMqTimedreceive(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, Ptr<java.lang. @Unsigned Integer> u_msg_prio, Ptr<timespec64> ts,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_timedsend}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, const u8* u_msg_ptr, long unsigned int msg_len, unsigned int msg_prio, struct timespec64* ts)",
      lastStatement = "return 0;",
      section = "fentry/do_mq_timedsend",
      autoAttach = true
  )
  default void enterMqTimedsend(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, @Unsigned int msg_prio, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_timedsend}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int mqdes, const u8* u_msg_ptr, long unsigned int msg_len, unsigned int msg_prio, struct timespec64* ts, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mq_timedsend",
      autoAttach = true
  )
  default void exitMqTimedsend(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, @Unsigned int msg_prio, Ptr<timespec64> ts, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_timedsend}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int mqdes, const u8* u_msg_ptr, long unsigned int msg_len, unsigned int msg_prio, struct timespec64* ts)",
      lastStatement = "return 0;",
      section = "kprobe/do_mq_timedsend",
      autoAttach = true
  )
  default void kprobeEnterMqTimedsend(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, @Unsigned int msg_prio, Ptr<timespec64> ts) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_timedsend}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int mqdes, const u8* u_msg_ptr, long unsigned int msg_len, unsigned int msg_prio, struct timespec64* ts, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mq_timedsend",
      autoAttach = true
  )
  default void kprobeExitMqTimedsend(@OriginalName("mqd_t") int mqdes, String u_msg_ptr,
      @Unsigned long msg_len, @Unsigned int msg_prio, Ptr<timespec64> ts, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_unlink}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* u_name)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_mq_unlink",
      autoAttach = true
  )
  default void enterMqUnlink(String u_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_unlink}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* u_name, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_mq_unlink",
      autoAttach = true
  )
  default void exitMqUnlink(String u_name, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mq_unlink}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* u_name)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_mq_unlink",
      autoAttach = true
  )
  default void kprobeEnterMqUnlink(String u_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mq_unlink}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* u_name, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_mq_unlink",
      autoAttach = true
  )
  default void kprobeExitMqUnlink(String u_name, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mremap}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct vma_remap_struct* vrm)",
      lastStatement = "return 0;",
      section = "fentry/do_mremap",
      autoAttach = true
  )
  default void enterMremap(Ptr<vma_remap_struct> vrm) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mremap}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct vma_remap_struct* vrm, long unsigned int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_mremap",
      autoAttach = true
  )
  default void exitMremap(Ptr<vma_remap_struct> vrm, @Unsigned long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code mremap}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct vma_remap_struct* vrm)",
      lastStatement = "return 0;",
      section = "kprobe/do_mremap",
      autoAttach = true
  )
  default void kprobeEnterMremap(Ptr<vma_remap_struct> vrm) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code mremap}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct vma_remap_struct* vrm, long unsigned int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_mremap",
      autoAttach = true
  )
  default void kprobeExitMremap(Ptr<vma_remap_struct> vrm, @Unsigned long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code msync}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int start, long unsigned int len, int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_msync",
      autoAttach = true
  )
  default void enterMsync(@Unsigned long start, @Unsigned long len, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code msync}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int start, long unsigned int len, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_msync",
      autoAttach = true
  )
  default void exitMsync(@Unsigned long start, @Unsigned long len, int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code msync}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int start, long unsigned int len, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_msync",
      autoAttach = true
  )
  default void kprobeEnterMsync(@Unsigned long start, @Unsigned long len, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code msync}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int start, long unsigned int len, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_msync",
      autoAttach = true
  )
  default void kprobeExitMsync(@Unsigned long start, @Unsigned long len, int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code munlockall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_munlockall",
      autoAttach = true
  )
  default void enterMunlockall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code munlockall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_munlockall",
      autoAttach = true
  )
  default void exitMunlockall(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code munlockall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_munlockall",
      autoAttach = true
  )
  default void kprobeEnterMunlockall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code munlockall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_munlockall",
      autoAttach = true
  )
  default void kprobeExitMunlockall(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code munmap}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mm_struct* mm, long unsigned int start, long unsigned int len, struct list_head* uf)",
      lastStatement = "return 0;",
      section = "fentry/do_munmap",
      autoAttach = true
  )
  default void enterMunmap(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len,
      Ptr<list_head> uf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code munmap}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mm_struct* mm, long unsigned int start, long unsigned int len, struct list_head* uf, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_munmap",
      autoAttach = true
  )
  default void exitMunmap(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len,
      Ptr<list_head> uf, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code munmap}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct mm_struct* mm, long unsigned int start, long unsigned int len, struct list_head* uf)",
      lastStatement = "return 0;",
      section = "kprobe/do_munmap",
      autoAttach = true
  )
  default void kprobeEnterMunmap(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len,
      Ptr<list_head> uf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code munmap}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct mm_struct* mm, long unsigned int start, long unsigned int len, struct list_head* uf, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_munmap",
      autoAttach = true
  )
  default void kprobeExitMunmap(Ptr<mm_struct> mm, @Unsigned long start, @Unsigned long len,
      Ptr<list_head> uf, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code nanosleep}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct hrtimer_sleeper* t, enum hrtimer_mode mode)",
      lastStatement = "return 0;",
      section = "fentry/do_nanosleep",
      autoAttach = true
  )
  default void enterNanosleep(Ptr<hrtimer_sleeper> t, hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code nanosleep}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct hrtimer_sleeper* t, enum hrtimer_mode mode, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_nanosleep",
      autoAttach = true
  )
  default void exitNanosleep(Ptr<hrtimer_sleeper> t, hrtimer_mode mode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code nanosleep}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct hrtimer_sleeper* t, enum hrtimer_mode mode)",
      lastStatement = "return 0;",
      section = "kprobe/do_nanosleep",
      autoAttach = true
  )
  default void kprobeEnterNanosleep(Ptr<hrtimer_sleeper> t, hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code nanosleep}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct hrtimer_sleeper* t, enum hrtimer_mode mode, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_nanosleep",
      autoAttach = true
  )
  default void kprobeExitNanosleep(Ptr<hrtimer_sleeper> t, hrtimer_mode mode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code openat2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, struct open_how* how)",
      lastStatement = "return 0;",
      section = "fentry/do_sys_openat2",
      autoAttach = true
  )
  default void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code openat2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* filename, struct open_how* how, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sys_openat2",
      autoAttach = true
  )
  default void exitOpenat2(int dfd, String filename, Ptr<open_how> how, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code openat2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, const u8* filename, struct open_how* how)",
      lastStatement = "return 0;",
      section = "kprobe/do_sys_openat2",
      autoAttach = true
  )
  default void kprobeEnterOpenat2(int dfd, String filename, Ptr<open_how> how) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code openat2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, const u8* filename, struct open_how* how, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sys_openat2",
      autoAttach = true
  )
  default void kprobeExitOpenat2(int dfd, String filename, Ptr<open_how> how, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pause}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_pause",
      autoAttach = true
  )
  default void enterPause(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pause}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_pause",
      autoAttach = true
  )
  default void exitPause(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pause}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_pause",
      autoAttach = true
  )
  default void kprobeEnterPause(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pause}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_pause",
      autoAttach = true
  )
  default void kprobeExitPause(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pidfd_send_signal}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct pid* pid, int sig, enum pid_type type, siginfo* info, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_pidfd_send_signal",
      autoAttach = true
  )
  default void enterPidfdSendSignal(Ptr<pid> pid, int sig, pid_type type,
      Ptr<@OriginalName("siginfo_t") siginfo> info, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pidfd_send_signal}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct pid* pid, int sig, enum pid_type type, siginfo* info, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_pidfd_send_signal",
      autoAttach = true
  )
  default void exitPidfdSendSignal(Ptr<pid> pid, int sig, pid_type type,
      Ptr<@OriginalName("siginfo_t") siginfo> info, @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pidfd_send_signal}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct pid* pid, int sig, enum pid_type type, siginfo* info, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_pidfd_send_signal",
      autoAttach = true
  )
  default void kprobeEnterPidfdSendSignal(Ptr<pid> pid, int sig, pid_type type,
      Ptr<@OriginalName("siginfo_t") siginfo> info, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pidfd_send_signal}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct pid* pid, int sig, enum pid_type type, siginfo* info, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_pidfd_send_signal",
      autoAttach = true
  )
  default void kprobeExitPidfdSendSignal(Ptr<pid> pid, int sig, pid_type type,
      Ptr<@OriginalName("siginfo_t") siginfo> info, @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pipe2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int* fildes, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_pipe2",
      autoAttach = true
  )
  default void enterPipe2(Ptr<java.lang.Integer> fildes, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pipe2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int* fildes, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_pipe2",
      autoAttach = true
  )
  default void exitPipe2(Ptr<java.lang.Integer> fildes, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pipe2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int* fildes, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_pipe2",
      autoAttach = true
  )
  default void kprobeEnterPipe2(Ptr<java.lang.Integer> fildes, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pipe2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int* fildes, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_pipe2",
      autoAttach = true
  )
  default void kprobeExitPipe2(Ptr<java.lang.Integer> fildes, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pivot_root}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* new_root, const u8* put_old)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_pivot_root",
      autoAttach = true
  )
  default void enterPivotRoot(String new_root, String put_old) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pivot_root}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* new_root, const u8* put_old, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_pivot_root",
      autoAttach = true
  )
  default void exitPivotRoot(String new_root, String put_old, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pivot_root}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* new_root, const u8* put_old)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_pivot_root",
      autoAttach = true
  )
  default void kprobeEnterPivotRoot(String new_root, String put_old) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pivot_root}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* new_root, const u8* put_old, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_pivot_root",
      autoAttach = true
  )
  default void kprobeExitPivotRoot(String new_root, String put_old, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pkey_alloc}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int flags, long unsigned int init_val)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_pkey_alloc",
      autoAttach = true
  )
  default void enterPkeyAlloc(@Unsigned long flags, @Unsigned long init_val) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pkey_alloc}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int flags, long unsigned int init_val, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_pkey_alloc",
      autoAttach = true
  )
  default void exitPkeyAlloc(@Unsigned long flags, @Unsigned long init_val, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pkey_alloc}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int flags, long unsigned int init_val)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_pkey_alloc",
      autoAttach = true
  )
  default void kprobeEnterPkeyAlloc(@Unsigned long flags, @Unsigned long init_val) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pkey_alloc}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int flags, long unsigned int init_val, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_pkey_alloc",
      autoAttach = true
  )
  default void kprobeExitPkeyAlloc(@Unsigned long flags, @Unsigned long init_val, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code prctl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_prctl",
      autoAttach = true
  )
  default void enterPrctl(int option, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code prctl}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_prctl",
      autoAttach = true
  )
  default void exitPrctl(int option, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code prctl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_prctl",
      autoAttach = true
  )
  default void kprobeEnterPrctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code prctl}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int option, long unsigned int arg2, long unsigned int arg3, long unsigned int arg4, long unsigned int arg5, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_prctl",
      autoAttach = true
  )
  default void kprobeExitPrctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code preadv}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_preadv",
      autoAttach = true
  )
  default void enterPreadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code preadv}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_preadv",
      autoAttach = true
  )
  default void exitPreadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code preadv}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_preadv",
      autoAttach = true
  )
  default void kprobeEnterPreadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code preadv}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_preadv",
      autoAttach = true
  )
  default void kprobeExitPreadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code process_madvise}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pidfd, const struct iovec* vec, long unsigned int vlen, int behavior, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_process_madvise",
      autoAttach = true
  )
  default void enterProcessMadvise(int pidfd, Ptr<iovec> vec, @Unsigned long vlen, int behavior,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code process_madvise}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pidfd, const struct iovec* vec, long unsigned int vlen, int behavior, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_process_madvise",
      autoAttach = true
  )
  default void exitProcessMadvise(int pidfd, Ptr<iovec> vec, @Unsigned long vlen, int behavior,
      @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code process_madvise}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int pidfd, const struct iovec* vec, long unsigned int vlen, int behavior, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_process_madvise",
      autoAttach = true
  )
  default void kprobeEnterProcessMadvise(int pidfd, Ptr<iovec> vec, @Unsigned long vlen,
      int behavior, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code process_madvise}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int pidfd, const struct iovec* vec, long unsigned int vlen, int behavior, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_process_madvise",
      autoAttach = true
  )
  default void kprobeExitProcessMadvise(int pidfd, Ptr<iovec> vec, @Unsigned long vlen,
      int behavior, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pwritev}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_pwritev",
      autoAttach = true
  )
  default void enterPwritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pwritev}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_pwritev",
      autoAttach = true
  )
  default void exitPwritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code pwritev}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_pwritev",
      autoAttach = true
  )
  default void kprobeEnterPwritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code pwritev}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, long long int pos, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_pwritev",
      autoAttach = true
  )
  default void kprobeExitPwritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("loff_t") long pos, @OriginalName("rwf_t") int flags,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code readahead}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, journal_s* journal, unsigned int start)",
      lastStatement = "return 0;",
      section = "fentry/do_readahead",
      autoAttach = true
  )
  default void enterReadahead(Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned int start) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code readahead}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, journal_s* journal, unsigned int start)",
      lastStatement = "return 0;",
      section = "fexit/do_readahead",
      autoAttach = true
  )
  default void exitReadahead(Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned int start) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code readahead}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, journal_s* journal, unsigned int start)",
      lastStatement = "return 0;",
      section = "kprobe/do_readahead",
      autoAttach = true
  )
  default void kprobeEnterReadahead(Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned int start) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code readahead}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, journal_s* journal, unsigned int start)",
      lastStatement = "return 0;",
      section = "kretprobe/do_readahead",
      autoAttach = true
  )
  default void kprobeExitReadahead(Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned int start) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code readlinkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* pathname, u8* buf, int bufsiz)",
      lastStatement = "return 0;",
      section = "fentry/do_readlinkat",
      autoAttach = true
  )
  default void enterReadlinkat(int dfd, String pathname, String buf, int bufsiz) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code readlinkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, const u8* pathname, u8* buf, int bufsiz, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_readlinkat",
      autoAttach = true
  )
  default void exitReadlinkat(int dfd, String pathname, String buf, int bufsiz, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code readlinkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, const u8* pathname, u8* buf, int bufsiz)",
      lastStatement = "return 0;",
      section = "kprobe/do_readlinkat",
      autoAttach = true
  )
  default void kprobeEnterReadlinkat(int dfd, String pathname, String buf, int bufsiz) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code readlinkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, const u8* pathname, u8* buf, int bufsiz, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_readlinkat",
      autoAttach = true
  )
  default void kprobeExitReadlinkat(int dfd, String pathname, String buf, int bufsiz, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code readv}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_readv",
      autoAttach = true
  )
  default void enterReadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code readv}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_readv",
      autoAttach = true
  )
  default void exitReadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code readv}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_readv",
      autoAttach = true
  )
  default void kprobeEnterReadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code readv}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_readv",
      autoAttach = true
  )
  default void kprobeExitReadv(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code reboot}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name)",
      lastStatement = "return 0;",
      section = "fentry/do_reboot",
      autoAttach = true
  )
  default void enterReboot() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code reboot}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name)",
      lastStatement = "return 0;",
      section = "fexit/do_reboot",
      autoAttach = true
  )
  default void exitReboot() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code reboot}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name)",
      lastStatement = "return 0;",
      section = "kprobe/do_reboot",
      autoAttach = true
  )
  default void kprobeEnterReboot() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code reboot}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name)",
      lastStatement = "return 0;",
      section = "kretprobe/do_reboot",
      autoAttach = true
  )
  default void kprobeExitReboot() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code recvmmsg}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, struct mmsghdr* mmsg, unsigned int vlen, unsigned int flags, struct timespec64* timeout)",
      lastStatement = "return 0;",
      section = "fentry/do_recvmmsg",
      autoAttach = true
  )
  default void enterRecvmmsg(int fd, Ptr<mmsghdr> mmsg, @Unsigned int vlen, @Unsigned int flags,
      Ptr<timespec64> timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code recvmmsg}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, struct mmsghdr* mmsg, unsigned int vlen, unsigned int flags, struct timespec64* timeout, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_recvmmsg",
      autoAttach = true
  )
  default void exitRecvmmsg(int fd, Ptr<mmsghdr> mmsg, @Unsigned int vlen, @Unsigned int flags,
      Ptr<timespec64> timeout, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code recvmmsg}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int fd, struct mmsghdr* mmsg, unsigned int vlen, unsigned int flags, struct timespec64* timeout)",
      lastStatement = "return 0;",
      section = "kprobe/do_recvmmsg",
      autoAttach = true
  )
  default void kprobeEnterRecvmmsg(int fd, Ptr<mmsghdr> mmsg, @Unsigned int vlen,
      @Unsigned int flags, Ptr<timespec64> timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code recvmmsg}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int fd, struct mmsghdr* mmsg, unsigned int vlen, unsigned int flags, struct timespec64* timeout, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_recvmmsg",
      autoAttach = true
  )
  default void kprobeExitRecvmmsg(int fd, Ptr<mmsghdr> mmsg, @Unsigned int vlen,
      @Unsigned int flags, Ptr<timespec64> timeout, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code renameat2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int olddfd, struct filename* from, int newdfd, struct filename* to, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_renameat2",
      autoAttach = true
  )
  default void enterRenameat2(int olddfd, Ptr<filename> from, int newdfd, Ptr<filename> to,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code renameat2}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int olddfd, struct filename* from, int newdfd, struct filename* to, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_renameat2",
      autoAttach = true
  )
  default void exitRenameat2(int olddfd, Ptr<filename> from, int newdfd, Ptr<filename> to,
      @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code renameat2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int olddfd, struct filename* from, int newdfd, struct filename* to, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_renameat2",
      autoAttach = true
  )
  default void kprobeEnterRenameat2(int olddfd, Ptr<filename> from, int newdfd, Ptr<filename> to,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code renameat2}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int olddfd, struct filename* from, int newdfd, struct filename* to, unsigned int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_renameat2",
      autoAttach = true
  )
  default void kprobeExitRenameat2(int olddfd, Ptr<filename> from, int newdfd, Ptr<filename> to,
      @Unsigned int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code request_key}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* _type, const u8* _description, const u8* _callout_info, int destringid)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_request_key",
      autoAttach = true
  )
  default void enterRequestKey(String _type, String _description, String _callout_info,
      @OriginalName("key_serial_t") int destringid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code request_key}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* _type, const u8* _description, const u8* _callout_info, int destringid, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_request_key",
      autoAttach = true
  )
  default void exitRequestKey(String _type, String _description, String _callout_info,
      @OriginalName("key_serial_t") int destringid, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code request_key}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* _type, const u8* _description, const u8* _callout_info, int destringid)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_request_key",
      autoAttach = true
  )
  default void kprobeEnterRequestKey(String _type, String _description, String _callout_info,
      @OriginalName("key_serial_t") int destringid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code request_key}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* _type, const u8* _description, const u8* _callout_info, int destringid, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_request_key",
      autoAttach = true
  )
  default void kprobeExitRequestKey(String _type, String _description, String _callout_info,
      @OriginalName("key_serial_t") int destringid, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code restart_syscall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_restart_syscall",
      autoAttach = true
  )
  default void enterRestartSyscall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code restart_syscall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_restart_syscall",
      autoAttach = true
  )
  default void exitRestartSyscall(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code restart_syscall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_restart_syscall",
      autoAttach = true
  )
  default void kprobeEnterRestartSyscall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code restart_syscall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_restart_syscall",
      autoAttach = true
  )
  default void kprobeExitRestartSyscall(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code rmdir}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name)",
      lastStatement = "return 0;",
      section = "fentry/do_rmdir",
      autoAttach = true
  )
  default void enterRmdir(int dfd, Ptr<filename> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code rmdir}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_rmdir",
      autoAttach = true
  )
  default void exitRmdir(int dfd, Ptr<filename> name, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code rmdir}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, struct filename* name)",
      lastStatement = "return 0;",
      section = "kprobe/do_rmdir",
      autoAttach = true
  )
  default void kprobeEnterRmdir(int dfd, Ptr<filename> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code rmdir}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, struct filename* name, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_rmdir",
      autoAttach = true
  )
  default void kprobeExitRmdir(int dfd, Ptr<filename> name, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code rt_sigqueueinfo}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, int sig, kernel_siginfo* info)",
      lastStatement = "return 0;",
      section = "fentry/do_rt_sigqueueinfo",
      autoAttach = true
  )
  default void enterRtSigqueueinfo(@OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code rt_sigqueueinfo}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, int sig, kernel_siginfo* info, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_rt_sigqueueinfo",
      autoAttach = true
  )
  default void exitRtSigqueueinfo(@OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code rt_sigqueueinfo}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int pid, int sig, kernel_siginfo* info)",
      lastStatement = "return 0;",
      section = "kprobe/do_rt_sigqueueinfo",
      autoAttach = true
  )
  default void kprobeEnterRtSigqueueinfo(@OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code rt_sigqueueinfo}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int pid, int sig, kernel_siginfo* info, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_rt_sigqueueinfo",
      autoAttach = true
  )
  default void kprobeExitRtSigqueueinfo(@OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code rt_tgsigqueueinfo}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int tgid, int pid, int sig, kernel_siginfo* info)",
      lastStatement = "return 0;",
      section = "fentry/do_rt_tgsigqueueinfo",
      autoAttach = true
  )
  default void enterRtTgsigqueueinfo(@OriginalName("pid_t") int tgid,
      @OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code rt_tgsigqueueinfo}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int tgid, int pid, int sig, kernel_siginfo* info, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_rt_tgsigqueueinfo",
      autoAttach = true
  )
  default void exitRtTgsigqueueinfo(@OriginalName("pid_t") int tgid, @OriginalName("pid_t") int pid,
      int sig, Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code rt_tgsigqueueinfo}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int tgid, int pid, int sig, kernel_siginfo* info)",
      lastStatement = "return 0;",
      section = "kprobe/do_rt_tgsigqueueinfo",
      autoAttach = true
  )
  default void kprobeEnterRtTgsigqueueinfo(@OriginalName("pid_t") int tgid,
      @OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code rt_tgsigqueueinfo}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int tgid, int pid, int sig, kernel_siginfo* info, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_rt_tgsigqueueinfo",
      autoAttach = true
  )
  default void kprobeExitRtTgsigqueueinfo(@OriginalName("pid_t") int tgid,
      @OriginalName("pid_t") int pid, int sig,
      Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> info, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sched_getattr}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, struct sched_attr* uattr, unsigned int usize, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_sched_getattr",
      autoAttach = true
  )
  default void enterSchedGetattr(@OriginalName("pid_t") int pid, Ptr<sched_attr> uattr,
      @Unsigned int usize, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sched_getattr}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, struct sched_attr* uattr, unsigned int usize, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_sched_getattr",
      autoAttach = true
  )
  default void exitSchedGetattr(@OriginalName("pid_t") int pid, Ptr<sched_attr> uattr,
      @Unsigned int usize, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sched_getattr}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int pid, struct sched_attr* uattr, unsigned int usize, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_sched_getattr",
      autoAttach = true
  )
  default void kprobeEnterSchedGetattr(@OriginalName("pid_t") int pid, Ptr<sched_attr> uattr,
      @Unsigned int usize, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sched_getattr}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int pid, struct sched_attr* uattr, unsigned int usize, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_sched_getattr",
      autoAttach = true
  )
  default void kprobeExitSchedGetattr(@OriginalName("pid_t") int pid, Ptr<sched_attr> uattr,
      @Unsigned int usize, @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sched_setscheduler}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, int policy, struct sched_param* param)",
      lastStatement = "return 0;",
      section = "fentry/do_sched_setscheduler",
      autoAttach = true
  )
  default void enterSchedSetscheduler(@OriginalName("pid_t") int pid, int policy,
      Ptr<sched_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sched_setscheduler}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, int policy, struct sched_param* param, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sched_setscheduler",
      autoAttach = true
  )
  default void exitSchedSetscheduler(@OriginalName("pid_t") int pid, int policy,
      Ptr<sched_param> param, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sched_setscheduler}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int pid, int policy, struct sched_param* param)",
      lastStatement = "return 0;",
      section = "kprobe/do_sched_setscheduler",
      autoAttach = true
  )
  default void kprobeEnterSchedSetscheduler(@OriginalName("pid_t") int pid, int policy,
      Ptr<sched_param> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sched_setscheduler}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int pid, int policy, struct sched_param* param, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sched_setscheduler",
      autoAttach = true
  )
  default void kprobeExitSchedSetscheduler(@OriginalName("pid_t") int pid, int policy,
      Ptr<sched_param> param, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sched_yield}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name)",
      lastStatement = "return 0;",
      section = "fentry/do_sched_yield",
      autoAttach = true
  )
  default void enterSchedYield() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sched_yield}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name)",
      lastStatement = "return 0;",
      section = "fexit/do_sched_yield",
      autoAttach = true
  )
  default void exitSchedYield() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sched_yield}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name)",
      lastStatement = "return 0;",
      section = "kprobe/do_sched_yield",
      autoAttach = true
  )
  default void kprobeEnterSchedYield() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sched_yield}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sched_yield",
      autoAttach = true
  )
  default void kprobeExitSchedYield() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code seccomp}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int op, unsigned int flags, void* uargs)",
      lastStatement = "return 0;",
      section = "fentry/do_seccomp",
      autoAttach = true
  )
  default void enterSeccomp(@Unsigned int op, @Unsigned int flags, Ptr<?> uargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code seccomp}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int op, unsigned int flags, void* uargs, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_seccomp",
      autoAttach = true
  )
  default void exitSeccomp(@Unsigned int op, @Unsigned int flags, Ptr<?> uargs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code seccomp}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int op, unsigned int flags, void* uargs)",
      lastStatement = "return 0;",
      section = "kprobe/do_seccomp",
      autoAttach = true
  )
  default void kprobeEnterSeccomp(@Unsigned int op, @Unsigned int flags, Ptr<?> uargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code seccomp}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int op, unsigned int flags, void* uargs, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_seccomp",
      autoAttach = true
  )
  default void kprobeExitSeccomp(@Unsigned int op, @Unsigned int flags, Ptr<?> uargs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sendfile}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int out_fd, int in_fd, long long int* ppos, long unsigned int count, long long int max)",
      lastStatement = "return 0;",
      section = "fentry/do_sendfile",
      autoAttach = true
  )
  default void enterSendfile(int out_fd, int in_fd,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long count,
      @OriginalName("loff_t") long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sendfile}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int out_fd, int in_fd, long long int* ppos, long unsigned int count, long long int max, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sendfile",
      autoAttach = true
  )
  default void exitSendfile(int out_fd, int in_fd,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long count,
      @OriginalName("loff_t") long max, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sendfile}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int out_fd, int in_fd, long long int* ppos, long unsigned int count, long long int max)",
      lastStatement = "return 0;",
      section = "kprobe/do_sendfile",
      autoAttach = true
  )
  default void kprobeEnterSendfile(int out_fd, int in_fd,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long count,
      @OriginalName("loff_t") long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sendfile}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int out_fd, int in_fd, long long int* ppos, long unsigned int count, long long int max, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sendfile",
      autoAttach = true
  )
  default void kprobeExitSendfile(int out_fd, int in_fd,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long count,
      @OriginalName("loff_t") long max, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code set_mempolicy}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, short unsigned int mode, short unsigned int flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nodes)",
      lastStatement = "return 0;",
      section = "fentry/do_set_mempolicy",
      autoAttach = true
  )
  default void enterSetMempolicy(@Unsigned short mode, @Unsigned short flags,
      Ptr<nodemask_t> nodes) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code set_mempolicy}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, short unsigned int mode, short unsigned int flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nodes, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_set_mempolicy",
      autoAttach = true
  )
  default void exitSetMempolicy(@Unsigned short mode, @Unsigned short flags, Ptr<nodemask_t> nodes,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code set_mempolicy}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, short unsigned int mode, short unsigned int flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nodes)",
      lastStatement = "return 0;",
      section = "kprobe/do_set_mempolicy",
      autoAttach = true
  )
  default void kprobeEnterSetMempolicy(@Unsigned short mode, @Unsigned short flags,
      Ptr<nodemask_t> nodes) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code set_mempolicy}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, short unsigned int mode, short unsigned int flags, struct {\n"
              + "  long unsigned int bits[16];\n"
              + "}* nodes, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_set_mempolicy",
      autoAttach = true
  )
  default void kprobeExitSetMempolicy(@Unsigned short mode, @Unsigned short flags,
      Ptr<nodemask_t> nodes, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code set_thread_area}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct task_struct* p, int idx, struct user_desc* u_info, int can_allocate)",
      lastStatement = "return 0;",
      section = "fentry/do_set_thread_area",
      autoAttach = true
  )
  default void enterSetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info,
      int can_allocate) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code set_thread_area}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct task_struct* p, int idx, struct user_desc* u_info, int can_allocate, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_set_thread_area",
      autoAttach = true
  )
  default void exitSetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info,
      int can_allocate, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code set_thread_area}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct task_struct* p, int idx, struct user_desc* u_info, int can_allocate)",
      lastStatement = "return 0;",
      section = "kprobe/do_set_thread_area",
      autoAttach = true
  )
  default void kprobeEnterSetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info,
      int can_allocate) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code set_thread_area}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct task_struct* p, int idx, struct user_desc* u_info, int can_allocate, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_set_thread_area",
      autoAttach = true
  )
  default void kprobeExitSetThreadArea(Ptr<task_struct> p, int idx, Ptr<user_desc> u_info,
      int can_allocate, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setgroups}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int gidsetsize, unsigned int* grouplist)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_setgroups",
      autoAttach = true
  )
  default void enterSetgroups(int gidsetsize,
      Ptr<java.lang. @Unsigned @OriginalName("gid_t") Integer> grouplist) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setgroups}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int gidsetsize, unsigned int* grouplist, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_setgroups",
      autoAttach = true
  )
  default void exitSetgroups(int gidsetsize,
      Ptr<java.lang. @Unsigned @OriginalName("gid_t") Integer> grouplist, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setgroups}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int gidsetsize, unsigned int* grouplist)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_setgroups",
      autoAttach = true
  )
  default void kprobeEnterSetgroups(int gidsetsize,
      Ptr<java.lang. @Unsigned @OriginalName("gid_t") Integer> grouplist) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setgroups}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int gidsetsize, unsigned int* grouplist, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_setgroups",
      autoAttach = true
  )
  default void kprobeExitSetgroups(int gidsetsize,
      Ptr<java.lang. @Unsigned @OriginalName("gid_t") Integer> grouplist, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setns}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_setns",
      autoAttach = true
  )
  default void enterSetns(int fd, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setns}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_setns",
      autoAttach = true
  )
  default void exitSetns(int fd, int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setns}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int fd, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_setns",
      autoAttach = true
  )
  default void kprobeEnterSetns(int fd, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setns}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int fd, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_setns",
      autoAttach = true
  )
  default void kprobeExitSetns(int fd, int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setpgid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, int pgid)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_setpgid",
      autoAttach = true
  )
  default void enterSetpgid(@OriginalName("pid_t") int pid, @OriginalName("pid_t") int pgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setpgid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int pid, int pgid, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_setpgid",
      autoAttach = true
  )
  default void exitSetpgid(@OriginalName("pid_t") int pid, @OriginalName("pid_t") int pgid,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setpgid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int pid, int pgid)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_setpgid",
      autoAttach = true
  )
  default void kprobeEnterSetpgid(@OriginalName("pid_t") int pid, @OriginalName("pid_t") int pgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setpgid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int pid, int pgid, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_setpgid",
      autoAttach = true
  )
  default void kprobeExitSetpgid(@OriginalName("pid_t") int pid, @OriginalName("pid_t") int pgid,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setpriority}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who, int niceval)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_setpriority",
      autoAttach = true
  )
  default void enterSetpriority(int which, int who, int niceval) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setpriority}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int who, int niceval, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_setpriority",
      autoAttach = true
  )
  default void exitSetpriority(int which, int who, int niceval, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setpriority}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int which, int who, int niceval)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_setpriority",
      autoAttach = true
  )
  default void kprobeEnterSetpriority(int which, int who, int niceval) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setpriority}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int which, int who, int niceval, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_setpriority",
      autoAttach = true
  )
  default void kprobeExitSetpriority(int which, int who, int niceval, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setsid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_setsid",
      autoAttach = true
  )
  default void enterSetsid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setsid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_setsid",
      autoAttach = true
  )
  default void exitSetsid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code setsid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_setsid",
      autoAttach = true
  )
  default void kprobeEnterSetsid(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code setsid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_setsid",
      autoAttach = true
  )
  default void kprobeExitSetsid(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sgetmask}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_sgetmask",
      autoAttach = true
  )
  default void enterSgetmask(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sgetmask}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_sgetmask",
      autoAttach = true
  )
  default void exitSgetmask(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sgetmask}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_sgetmask",
      autoAttach = true
  )
  default void kprobeEnterSgetmask(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sgetmask}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_sgetmask",
      autoAttach = true
  )
  default void kprobeExitSgetmask(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sigaction}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int sig, struct k_sigaction* act, struct k_sigaction* oact)",
      lastStatement = "return 0;",
      section = "fentry/do_sigaction",
      autoAttach = true
  )
  default void enterSigaction(int sig, Ptr<k_sigaction> act, Ptr<k_sigaction> oact) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sigaction}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int sig, struct k_sigaction* act, struct k_sigaction* oact, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sigaction",
      autoAttach = true
  )
  default void exitSigaction(int sig, Ptr<k_sigaction> act, Ptr<k_sigaction> oact, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sigaction}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int sig, struct k_sigaction* act, struct k_sigaction* oact)",
      lastStatement = "return 0;",
      section = "kprobe/do_sigaction",
      autoAttach = true
  )
  default void kprobeEnterSigaction(int sig, Ptr<k_sigaction> act, Ptr<k_sigaction> oact) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sigaction}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int sig, struct k_sigaction* act, struct k_sigaction* oact, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sigaction",
      autoAttach = true
  )
  default void kprobeExitSigaction(int sig, Ptr<k_sigaction> act, Ptr<k_sigaction> oact, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sigaltstack}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const sigaltstack* ss, sigaltstack* oss, long unsigned int sp, long unsigned int min_ss_size)",
      lastStatement = "return 0;",
      section = "fentry/do_sigaltstack",
      autoAttach = true
  )
  default void enterSigaltstack(Ptr<@OriginalName("stack_t") sigaltstack> ss,
      Ptr<@OriginalName("stack_t") sigaltstack> oss, @Unsigned long sp,
      @Unsigned long min_ss_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sigaltstack}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const sigaltstack* ss, sigaltstack* oss, long unsigned int sp, long unsigned int min_ss_size, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sigaltstack",
      autoAttach = true
  )
  default void exitSigaltstack(Ptr<@OriginalName("stack_t") sigaltstack> ss,
      Ptr<@OriginalName("stack_t") sigaltstack> oss, @Unsigned long sp, @Unsigned long min_ss_size,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sigaltstack}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const sigaltstack* ss, sigaltstack* oss, long unsigned int sp, long unsigned int min_ss_size)",
      lastStatement = "return 0;",
      section = "kprobe/do_sigaltstack",
      autoAttach = true
  )
  default void kprobeEnterSigaltstack(Ptr<@OriginalName("stack_t") sigaltstack> ss,
      Ptr<@OriginalName("stack_t") sigaltstack> oss, @Unsigned long sp,
      @Unsigned long min_ss_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sigaltstack}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const sigaltstack* ss, sigaltstack* oss, long unsigned int sp, long unsigned int min_ss_size, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sigaltstack",
      autoAttach = true
  )
  default void kprobeExitSigaltstack(Ptr<@OriginalName("stack_t") sigaltstack> ss,
      Ptr<@OriginalName("stack_t") sigaltstack> oss, @Unsigned long sp, @Unsigned long min_ss_size,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code socketcall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int call, long unsigned int* args)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_socketcall",
      autoAttach = true
  )
  default void enterSocketcall(int call, Ptr<java.lang. @Unsigned Long> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code socketcall}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int call, long unsigned int* args, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_socketcall",
      autoAttach = true
  )
  default void exitSocketcall(int call, Ptr<java.lang. @Unsigned Long> args, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code socketcall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int call, long unsigned int* args)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_socketcall",
      autoAttach = true
  )
  default void kprobeEnterSocketcall(int call, Ptr<java.lang. @Unsigned Long> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code socketcall}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int call, long unsigned int* args, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_socketcall",
      autoAttach = true
  )
  default void kprobeExitSocketcall(int call, Ptr<java.lang. @Unsigned Long> args, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code splice}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* in, long long int* off_in, struct file* out, long long int* off_out, long unsigned int len, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_splice",
      autoAttach = true
  )
  default void enterSplice(Ptr<file> in, Ptr<java.lang. @OriginalName("loff_t") Long> off_in,
      Ptr<file> out, Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code splice}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* in, long long int* off_in, struct file* out, long long int* off_out, long unsigned int len, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_splice",
      autoAttach = true
  )
  default void exitSplice(Ptr<file> in, Ptr<java.lang. @OriginalName("loff_t") Long> off_in,
      Ptr<file> out, Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code splice}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct file* in, long long int* off_in, struct file* out, long long int* off_out, long unsigned int len, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_splice",
      autoAttach = true
  )
  default void kprobeEnterSplice(Ptr<file> in, Ptr<java.lang. @OriginalName("loff_t") Long> off_in,
      Ptr<file> out, Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code splice}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct file* in, long long int* off_in, struct file* out, long long int* off_out, long unsigned int len, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_splice",
      autoAttach = true
  )
  default void kprobeExitSplice(Ptr<file> in, Ptr<java.lang. @OriginalName("loff_t") Long> off_in,
      Ptr<file> out, Ptr<java.lang. @OriginalName("loff_t") Long> off_out, @Unsigned long len,
      @Unsigned int flags, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code stat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* filename, struct __old_kernel_stat* statbuf)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_stat",
      autoAttach = true
  )
  default void enterStat(String filename, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code stat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* filename, struct __old_kernel_stat* statbuf, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_stat",
      autoAttach = true
  )
  default void exitStat(String filename, Ptr<__old_kernel_stat> statbuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code stat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* filename, struct __old_kernel_stat* statbuf)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_stat",
      autoAttach = true
  )
  default void kprobeEnterStat(String filename, Ptr<__old_kernel_stat> statbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code stat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* filename, struct __old_kernel_stat* statbuf, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_stat",
      autoAttach = true
  )
  default void kprobeExitStat(String filename, Ptr<__old_kernel_stat> statbuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code statfs}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* pathname, struct statfs* buf)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_statfs",
      autoAttach = true
  )
  default void enterStatfs(String pathname, Ptr<statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code statfs}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* pathname, struct statfs* buf, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_statfs",
      autoAttach = true
  )
  default void exitStatfs(String pathname, Ptr<statfs> buf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code statfs}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* pathname, struct statfs* buf)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_statfs",
      autoAttach = true
  )
  default void kprobeEnterStatfs(String pathname, Ptr<statfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code statfs}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* pathname, struct statfs* buf, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_statfs",
      autoAttach = true
  )
  default void kprobeExitStatfs(String pathname, Ptr<statfs> buf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code statx}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* filename, unsigned int flags, unsigned int mask, struct statx* buffer)",
      lastStatement = "return 0;",
      section = "fentry/do_statx",
      autoAttach = true
  )
  default void enterStatx(int dfd, Ptr<filename> filename, @Unsigned int flags, @Unsigned int mask,
      Ptr<statx> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code statx}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* filename, unsigned int flags, unsigned int mask, struct statx* buffer, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_statx",
      autoAttach = true
  )
  default void exitStatx(int dfd, Ptr<filename> filename, @Unsigned int flags, @Unsigned int mask,
      Ptr<statx> buffer, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code statx}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, struct filename* filename, unsigned int flags, unsigned int mask, struct statx* buffer)",
      lastStatement = "return 0;",
      section = "kprobe/do_statx",
      autoAttach = true
  )
  default void kprobeEnterStatx(int dfd, Ptr<filename> filename, @Unsigned int flags,
      @Unsigned int mask, Ptr<statx> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code statx}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, struct filename* filename, unsigned int flags, unsigned int mask, struct statx* buffer, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_statx",
      autoAttach = true
  )
  default void kprobeExitStatx(int dfd, Ptr<filename> filename, @Unsigned int flags,
      @Unsigned int mask, Ptr<statx> buffer, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code swapoff}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* specialfile)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_swapoff",
      autoAttach = true
  )
  default void enterSwapoff(String specialfile) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code swapoff}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* specialfile, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_swapoff",
      autoAttach = true
  )
  default void exitSwapoff(String specialfile, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code swapoff}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* specialfile)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_swapoff",
      autoAttach = true
  )
  default void kprobeEnterSwapoff(String specialfile) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code swapoff}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* specialfile, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_swapoff",
      autoAttach = true
  )
  default void kprobeExitSwapoff(String specialfile, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code swapon}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* specialfile, int swap_flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_swapon",
      autoAttach = true
  )
  default void enterSwapon(String specialfile, int swap_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code swapon}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* specialfile, int swap_flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_swapon",
      autoAttach = true
  )
  default void exitSwapon(String specialfile, int swap_flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code swapon}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* specialfile, int swap_flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_swapon",
      autoAttach = true
  )
  default void kprobeEnterSwapon(String specialfile, int swap_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code swapon}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* specialfile, int swap_flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_swapon",
      autoAttach = true
  )
  default void kprobeExitSwapon(String specialfile, int swap_flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code symlink}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name)",
      lastStatement = "return 0;",
      section = "fentry/do_symlink",
      autoAttach = true
  )
  default void enterSymlink() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code symlink}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_symlink",
      autoAttach = true
  )
  default void exitSymlink(int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code symlink}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name)",
      lastStatement = "return 0;",
      section = "kprobe/do_symlink",
      autoAttach = true
  )
  default void kprobeEnterSymlink() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code symlink}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_symlink",
      autoAttach = true
  )
  default void kprobeExitSymlink(int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code symlinkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct filename* from, int newdfd, struct filename* to)",
      lastStatement = "return 0;",
      section = "fentry/do_symlinkat",
      autoAttach = true
  )
  default void enterSymlinkat(Ptr<filename> from, int newdfd, Ptr<filename> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code symlinkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct filename* from, int newdfd, struct filename* to, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_symlinkat",
      autoAttach = true
  )
  default void exitSymlinkat(Ptr<filename> from, int newdfd, Ptr<filename> to, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code symlinkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct filename* from, int newdfd, struct filename* to)",
      lastStatement = "return 0;",
      section = "kprobe/do_symlinkat",
      autoAttach = true
  )
  default void kprobeEnterSymlinkat(Ptr<filename> from, int newdfd, Ptr<filename> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code symlinkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct filename* from, int newdfd, struct filename* to, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_symlinkat",
      autoAttach = true
  )
  default void kprobeExitSymlinkat(Ptr<filename> from, int newdfd, Ptr<filename> to, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sync}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_sync",
      autoAttach = true
  )
  default void enterSync(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sync}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_sync",
      autoAttach = true
  )
  default void exitSync(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sync}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_sync",
      autoAttach = true
  )
  default void kprobeEnterSync(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sync}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_sync",
      autoAttach = true
  )
  default void kprobeExitSync(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sysinfo}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct sysinfo* info)",
      lastStatement = "return 0;",
      section = "fentry/do_sysinfo",
      autoAttach = true
  )
  default void enterSysinfo(Ptr<sysinfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sysinfo}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct sysinfo* info, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sysinfo",
      autoAttach = true
  )
  default void exitSysinfo(Ptr<sysinfo> info, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code sysinfo}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct sysinfo* info)",
      lastStatement = "return 0;",
      section = "kprobe/do_sysinfo",
      autoAttach = true
  )
  default void kprobeEnterSysinfo(Ptr<sysinfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code sysinfo}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct sysinfo* info, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sysinfo",
      autoAttach = true
  )
  default void kprobeExitSysinfo(Ptr<sysinfo> info, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code syslog}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int type, u8* buf, int len, int source)",
      lastStatement = "return 0;",
      section = "fentry/do_syslog",
      autoAttach = true
  )
  default void enterSyslog(int type, String buf, int len, int source) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code syslog}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int type, u8* buf, int len, int source, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_syslog",
      autoAttach = true
  )
  default void exitSyslog(int type, String buf, int len, int source, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code syslog}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int type, u8* buf, int len, int source)",
      lastStatement = "return 0;",
      section = "kprobe/do_syslog",
      autoAttach = true
  )
  default void kprobeEnterSyslog(int type, String buf, int len, int source) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code syslog}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int type, u8* buf, int len, int source, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_syslog",
      autoAttach = true
  )
  default void kprobeExitSyslog(int type, String buf, int len, int source, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code tee}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* in, struct file* out, long unsigned int len, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_tee",
      autoAttach = true
  )
  default void enterTee(Ptr<file> in, Ptr<file> out, @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code tee}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct file* in, struct file* out, long unsigned int len, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_tee",
      autoAttach = true
  )
  default void exitTee(Ptr<file> in, Ptr<file> out, @Unsigned long len, @Unsigned int flags,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code tee}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct file* in, struct file* out, long unsigned int len, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_tee",
      autoAttach = true
  )
  default void kprobeEnterTee(Ptr<file> in, Ptr<file> out, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code tee}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct file* in, struct file* out, long unsigned int len, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_tee",
      autoAttach = true
  )
  default void kprobeExitTee(Ptr<file> in, Ptr<file> out, @Unsigned long len, @Unsigned int flags,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timer_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which_clock, struct sigevent* event, int* created_timer_id)",
      lastStatement = "return 0;",
      section = "fentry/do_timer_create",
      autoAttach = true
  )
  default void enterTimerCreate(@OriginalName("clockid_t") int which_clock, Ptr<sigevent> event,
      Ptr<java.lang. @OriginalName("timer_t") Integer> created_timer_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timer_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which_clock, struct sigevent* event, int* created_timer_id, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_timer_create",
      autoAttach = true
  )
  default void exitTimerCreate(@OriginalName("clockid_t") int which_clock, Ptr<sigevent> event,
      Ptr<java.lang. @OriginalName("timer_t") Integer> created_timer_id, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timer_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int which_clock, struct sigevent* event, int* created_timer_id)",
      lastStatement = "return 0;",
      section = "kprobe/do_timer_create",
      autoAttach = true
  )
  default void kprobeEnterTimerCreate(@OriginalName("clockid_t") int which_clock,
      Ptr<sigevent> event, Ptr<java.lang. @OriginalName("timer_t") Integer> created_timer_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timer_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int which_clock, struct sigevent* event, int* created_timer_id, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_timer_create",
      autoAttach = true
  )
  default void kprobeExitTimerCreate(@OriginalName("clockid_t") int which_clock,
      Ptr<sigevent> event, Ptr<java.lang. @OriginalName("timer_t") Integer> created_timer_id,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timer_gettime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int timer_id, struct itimerspec64* setting)",
      lastStatement = "return 0;",
      section = "fentry/do_timer_gettime",
      autoAttach = true
  )
  default void enterTimerGettime(@OriginalName("timer_t") int timer_id, Ptr<itimerspec64> setting) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timer_gettime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int timer_id, struct itimerspec64* setting, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_timer_gettime",
      autoAttach = true
  )
  default void exitTimerGettime(@OriginalName("timer_t") int timer_id, Ptr<itimerspec64> setting,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timer_gettime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int timer_id, struct itimerspec64* setting)",
      lastStatement = "return 0;",
      section = "kprobe/do_timer_gettime",
      autoAttach = true
  )
  default void kprobeEnterTimerGettime(@OriginalName("timer_t") int timer_id,
      Ptr<itimerspec64> setting) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timer_gettime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int timer_id, struct itimerspec64* setting, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_timer_gettime",
      autoAttach = true
  )
  default void kprobeExitTimerGettime(@OriginalName("timer_t") int timer_id,
      Ptr<itimerspec64> setting, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timer_settime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int timer_id, int tmr_flags, struct itimerspec64* new_spec64, struct itimerspec64* old_spec64)",
      lastStatement = "return 0;",
      section = "fentry/do_timer_settime",
      autoAttach = true
  )
  default void enterTimerSettime(@OriginalName("timer_t") int timer_id, int tmr_flags,
      Ptr<itimerspec64> new_spec64, Ptr<itimerspec64> old_spec64) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timer_settime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int timer_id, int tmr_flags, struct itimerspec64* new_spec64, struct itimerspec64* old_spec64, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_timer_settime",
      autoAttach = true
  )
  default void exitTimerSettime(@OriginalName("timer_t") int timer_id, int tmr_flags,
      Ptr<itimerspec64> new_spec64, Ptr<itimerspec64> old_spec64, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timer_settime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int timer_id, int tmr_flags, struct itimerspec64* new_spec64, struct itimerspec64* old_spec64)",
      lastStatement = "return 0;",
      section = "kprobe/do_timer_settime",
      autoAttach = true
  )
  default void kprobeEnterTimerSettime(@OriginalName("timer_t") int timer_id, int tmr_flags,
      Ptr<itimerspec64> new_spec64, Ptr<itimerspec64> old_spec64) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timer_settime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int timer_id, int tmr_flags, struct itimerspec64* new_spec64, struct itimerspec64* old_spec64, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_timer_settime",
      autoAttach = true
  )
  default void kprobeExitTimerSettime(@OriginalName("timer_t") int timer_id, int tmr_flags,
      Ptr<itimerspec64> new_spec64, Ptr<itimerspec64> old_spec64, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timerfd_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int clockid, int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_timerfd_create",
      autoAttach = true
  )
  default void enterTimerfdCreate(int clockid, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timerfd_create}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int clockid, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_timerfd_create",
      autoAttach = true
  )
  default void exitTimerfdCreate(int clockid, int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timerfd_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int clockid, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_timerfd_create",
      autoAttach = true
  )
  default void kprobeEnterTimerfdCreate(int clockid, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timerfd_create}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int clockid, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_timerfd_create",
      autoAttach = true
  )
  default void kprobeExitTimerfdCreate(int clockid, int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timerfd_gettime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int ufd, struct itimerspec64* t)",
      lastStatement = "return 0;",
      section = "fentry/do_timerfd_gettime",
      autoAttach = true
  )
  default void enterTimerfdGettime(int ufd, Ptr<itimerspec64> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timerfd_gettime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int ufd, struct itimerspec64* t, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_timerfd_gettime",
      autoAttach = true
  )
  default void exitTimerfdGettime(int ufd, Ptr<itimerspec64> t, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timerfd_gettime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int ufd, struct itimerspec64* t)",
      lastStatement = "return 0;",
      section = "kprobe/do_timerfd_gettime",
      autoAttach = true
  )
  default void kprobeEnterTimerfdGettime(int ufd, Ptr<itimerspec64> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timerfd_gettime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int ufd, struct itimerspec64* t, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_timerfd_gettime",
      autoAttach = true
  )
  default void kprobeExitTimerfdGettime(int ufd, Ptr<itimerspec64> t, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timerfd_settime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int ufd, int flags, const struct itimerspec64* new, struct itimerspec64* old)",
      lastStatement = "return 0;",
      section = "fentry/do_timerfd_settime",
      autoAttach = true
  )
  default void enterTimerfdSettime(int ufd, int flags, Ptr<itimerspec64> _new,
      Ptr<itimerspec64> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timerfd_settime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int ufd, int flags, const struct itimerspec64* new, struct itimerspec64* old, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_timerfd_settime",
      autoAttach = true
  )
  default void exitTimerfdSettime(int ufd, int flags, Ptr<itimerspec64> _new, Ptr<itimerspec64> old,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code timerfd_settime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int ufd, int flags, const struct itimerspec64* new, struct itimerspec64* old)",
      lastStatement = "return 0;",
      section = "kprobe/do_timerfd_settime",
      autoAttach = true
  )
  default void kprobeEnterTimerfdSettime(int ufd, int flags, Ptr<itimerspec64> _new,
      Ptr<itimerspec64> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code timerfd_settime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int ufd, int flags, const struct itimerspec64* new, struct itimerspec64* old, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_timerfd_settime",
      autoAttach = true
  )
  default void kprobeExitTimerfdSettime(int ufd, int flags, Ptr<itimerspec64> _new,
      Ptr<itimerspec64> old, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code times}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct tms* tms)",
      lastStatement = "return 0;",
      section = "fentry/do_sys_times",
      autoAttach = true
  )
  default void enterTimes(Ptr<tms> tms) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code times}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct tms* tms)",
      lastStatement = "return 0;",
      section = "fexit/do_sys_times",
      autoAttach = true
  )
  default void exitTimes(Ptr<tms> tms) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code times}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct tms* tms)",
      lastStatement = "return 0;",
      section = "kprobe/do_sys_times",
      autoAttach = true
  )
  default void kprobeEnterTimes(Ptr<tms> tms) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code times}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct tms* tms)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sys_times",
      autoAttach = true
  )
  default void kprobeExitTimes(Ptr<tms> tms) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code truncate}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* pathname, long long int length)",
      lastStatement = "return 0;",
      section = "fentry/do_sys_truncate",
      autoAttach = true
  )
  default void enterTruncate(String pathname, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code truncate}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const u8* pathname, long long int length, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_sys_truncate",
      autoAttach = true
  )
  default void exitTruncate(String pathname, @OriginalName("loff_t") long length, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code truncate}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const u8* pathname, long long int length)",
      lastStatement = "return 0;",
      section = "kprobe/do_sys_truncate",
      autoAttach = true
  )
  default void kprobeEnterTruncate(String pathname, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code truncate}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const u8* pathname, long long int length, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_sys_truncate",
      autoAttach = true
  )
  default void kprobeExitTruncate(String pathname, @OriginalName("loff_t") long length, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code umount}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mount* mnt, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_umount",
      autoAttach = true
  )
  default void enterUmount(Ptr<mount> mnt, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code umount}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, struct mount* mnt, int flags, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_umount",
      autoAttach = true
  )
  default void exitUmount(Ptr<mount> mnt, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code umount}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, struct mount* mnt, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_umount",
      autoAttach = true
  )
  default void kprobeEnterUmount(Ptr<mount> mnt, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code umount}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, struct mount* mnt, int flags, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_umount",
      autoAttach = true
  )
  default void kprobeExitUmount(Ptr<mount> mnt, int flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code unlinkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name)",
      lastStatement = "return 0;",
      section = "fentry/do_unlinkat",
      autoAttach = true
  )
  default void enterUnlinkat(int dfd, Ptr<filename> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code unlinkat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int dfd, struct filename* name, int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_unlinkat",
      autoAttach = true
  )
  default void exitUnlinkat(int dfd, Ptr<filename> name, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code unlinkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int dfd, struct filename* name)",
      lastStatement = "return 0;",
      section = "kprobe/do_unlinkat",
      autoAttach = true
  )
  default void kprobeEnterUnlinkat(int dfd, Ptr<filename> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code unlinkat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int dfd, struct filename* name, int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_unlinkat",
      autoAttach = true
  )
  default void kprobeExitUnlinkat(int dfd, Ptr<filename> name, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ustat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int dev, struct ustat* ubuf)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_ustat",
      autoAttach = true
  )
  default void enterUstat(@Unsigned int dev, Ptr<ustat> ubuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ustat}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, unsigned int dev, struct ustat* ubuf, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_ustat",
      autoAttach = true
  )
  default void exitUstat(@Unsigned int dev, Ptr<ustat> ubuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code ustat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, unsigned int dev, struct ustat* ubuf)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_ustat",
      autoAttach = true
  )
  default void kprobeEnterUstat(@Unsigned int dev, Ptr<ustat> ubuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code ustat}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, unsigned int dev, struct ustat* ubuf, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_ustat",
      autoAttach = true
  )
  default void kprobeExitUstat(@Unsigned int dev, Ptr<ustat> ubuf, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code utime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, u8* filename, long long int mtime)",
      lastStatement = "return 0;",
      section = "fentry/do_utime",
      autoAttach = true
  )
  default void enterUtime(String filename, @OriginalName("time64_t") long mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code utime}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, u8* filename, long long int mtime)",
      lastStatement = "return 0;",
      section = "fexit/do_utime",
      autoAttach = true
  )
  default void exitUtime(String filename, @OriginalName("time64_t") long mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code utime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, u8* filename, long long int mtime)",
      lastStatement = "return 0;",
      section = "kprobe/do_utime",
      autoAttach = true
  )
  default void kprobeEnterUtime(String filename, @OriginalName("time64_t") long mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code utime}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, u8* filename, long long int mtime)",
      lastStatement = "return 0;",
      section = "kretprobe/do_utime",
      autoAttach = true
  )
  default void kprobeExitUtime(String filename, @OriginalName("time64_t") long mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code vfork}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_vfork",
      autoAttach = true
  )
  default void enterVfork(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code vfork}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_vfork",
      autoAttach = true
  )
  default void exitVfork(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code vfork}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_vfork",
      autoAttach = true
  )
  default void kprobeEnterVfork(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code vfork}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_vfork",
      autoAttach = true
  )
  default void kprobeExitVfork(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code vhangup}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_vhangup",
      autoAttach = true
  )
  default void enterVhangup(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code vhangup}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_vhangup",
      autoAttach = true
  )
  default void exitVhangup(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code vhangup}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, const struct pt_regs* __unused)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_vhangup",
      autoAttach = true
  )
  default void kprobeEnterVhangup(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code vhangup}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, const struct pt_regs* __unused, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_vhangup",
      autoAttach = true
  )
  default void kprobeExitVhangup(Ptr<pt_regs> __unused, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code vmsplice}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, const struct iovec* uiov, long unsigned int nr_segs, unsigned int flags)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_vmsplice",
      autoAttach = true
  )
  default void enterVmsplice(int fd, Ptr<iovec> uiov, @Unsigned long nr_segs, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code vmsplice}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int fd, const struct iovec* uiov, long unsigned int nr_segs, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_vmsplice",
      autoAttach = true
  )
  default void exitVmsplice(int fd, Ptr<iovec> uiov, @Unsigned long nr_segs, @Unsigned int flags,
      long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code vmsplice}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int fd, const struct iovec* uiov, long unsigned int nr_segs, unsigned int flags)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_vmsplice",
      autoAttach = true
  )
  default void kprobeEnterVmsplice(int fd, Ptr<iovec> uiov, @Unsigned long nr_segs,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code vmsplice}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int fd, const struct iovec* uiov, long unsigned int nr_segs, unsigned int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_vmsplice",
      autoAttach = true
  )
  default void kprobeExitVmsplice(int fd, Ptr<iovec> uiov, @Unsigned long nr_segs,
      @Unsigned int flags, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code wait4}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int upid, int* stat_addr, int options, struct rusage* ru)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_wait4",
      autoAttach = true
  )
  default void enterWait4(@OriginalName("pid_t") int upid, Ptr<java.lang.Integer> stat_addr,
      int options, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code wait4}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int upid, int* stat_addr, int options, struct rusage* ru, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_wait4",
      autoAttach = true
  )
  default void exitWait4(@OriginalName("pid_t") int upid, Ptr<java.lang.Integer> stat_addr,
      int options, Ptr<rusage> ru, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code wait4}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int upid, int* stat_addr, int options, struct rusage* ru)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_wait4",
      autoAttach = true
  )
  default void kprobeEnterWait4(@OriginalName("pid_t") int upid, Ptr<java.lang.Integer> stat_addr,
      int options, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code wait4}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int upid, int* stat_addr, int options, struct rusage* ru, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_wait4",
      autoAttach = true
  )
  default void kprobeExitWait4(@OriginalName("pid_t") int upid, Ptr<java.lang.Integer> stat_addr,
      int options, Ptr<rusage> ru, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code waitid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int upid, struct siginfo* infop, int options, struct rusage* ru)",
      lastStatement = "return 0;",
      section = "fentry/__do_sys_waitid",
      autoAttach = true
  )
  default void enterWaitid(int which, @OriginalName("pid_t") int upid, Ptr<siginfo> infop,
      int options, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code waitid}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, int which, int upid, struct siginfo* infop, int options, struct rusage* ru, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/__do_sys_waitid",
      autoAttach = true
  )
  default void exitWaitid(int which, @OriginalName("pid_t") int upid, Ptr<siginfo> infop,
      int options, Ptr<rusage> ru, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code waitid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, int which, int upid, struct siginfo* infop, int options, struct rusage* ru)",
      lastStatement = "return 0;",
      section = "kprobe/__do_sys_waitid",
      autoAttach = true
  )
  default void kprobeEnterWaitid(int which, @OriginalName("pid_t") int upid, Ptr<siginfo> infop,
      int options, Ptr<rusage> ru) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code waitid}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, int which, int upid, struct siginfo* infop, int options, struct rusage* ru, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/__do_sys_waitid",
      autoAttach = true
  )
  default void kprobeExitWaitid(int which, @OriginalName("pid_t") int upid, Ptr<siginfo> infop,
      int options, Ptr<rusage> ru, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code writev}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags)",
      lastStatement = "return 0;",
      section = "fentry/do_writev",
      autoAttach = true
  )
  default void enterWritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code writev}  via fentry/fexit 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_PROG($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "fexit/do_writev",
      autoAttach = true
  )
  default void exitWritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Enter the system call {@code writev}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   */
  @BPFFunction(
      headerTemplate = "int BPF_KPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags)",
      lastStatement = "return 0;",
      section = "kprobe/do_writev",
      autoAttach = true
  )
  default void kprobeEnterWritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exit the system call {@code writev}  via kprobes 
   *
   * <p>Access the pointer/String argument of the system call arguments via
   * {@link BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)},
   * {@link BPFHelpers#bpf_probe_read_user(Ptr, int, Ptr)}, as well as
   * similar methods in BPFJ.
   * Passing the arguments directly to other {@link BPFHelpers} should mostly work.
   * @param ret return value of the system call
   */
  @BPFFunction(
      headerTemplate = "int BPF_KRETPROBE($name, long unsigned int fd, const struct iovec* vec, long unsigned int vlen, int flags, long int ret)",
      lastStatement = "return 0;",
      section = "kretprobe/do_writev",
      autoAttach = true
  )
  default void kprobeExitWritev(@Unsigned long fd, Ptr<iovec> vec, @Unsigned long vlen,
      @OriginalName("rwf_t") int flags, @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }
}
