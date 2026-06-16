/** Auto-generated */
package me.bechberger.ebpf.runtime.helpers;

import java.lang.SuppressWarnings;
import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
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

/**
 * BPF helper functions, based on <a href="https://ebpf-docs.dylanreimerink.nl/linux/helper-function/">ebpf-docs</a>
 */
@java.lang.SuppressWarnings("unused")
public final class BPFHelpers {
  /**
   * Bind the socket associated to <em>ctx</em> to the address pointed by
   * <em>addr</em>, of length <em>addr_len</em>. This allows for making outgoing
   * connection from the desired IP address, which can be useful for
   * example when all processes inside a cgroup should use one
   * single IP address on a host that has multiple IP configured.</p>
   * <p>This helper works for IPv4 and IPv6, TCP and UDP sockets. The
   * domain (<em>addr</em>\ <strong>-&gt;sa_family</strong>) must be <strong>AF_INET</strong> (or
   * <strong>AF_INET6</strong>). It's advised to pass zero port (<strong>sin_port</strong>
   * or <strong>sin6_port</strong>) which triggers IP_BIND_ADDRESS_NO_PORT-like
   * behavior and lets the kernel efficiently pick up an unused
   * port as long as 4-tuple is unique. Passing non-zero port might
   * lead to degraded performance.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_bind(Ptr<bpf_sock_addr> ctx, Ptr<sockaddr> addr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Set or clear certain options on <em>bprm</em>:</p>
   * <p><strong>BPF_F_BPRM_SECUREEXEC</strong> Set the secureexec bit
   * which sets the <strong>AT_SECURE</strong> auxv for glibc. The bit
   * is cleared if the flag is not specified.
   * @return <strong>-EINVAL</strong> if invalid <em>flags</em> are passed, zero otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_bprm_opts_set(Ptr<linux_binprm> bprm, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Find BTF type with given name and kind in vmlinux BTF or in module's BTFs.
   * @return Returns btf_id and btf_obj_fd in lower and upper 32 bits.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_btf_find_by_name_kind(String name, int name_sz, @Unsigned int kind,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Delete a bpf_local_storage from a <em>cgroup</em>.
   * @return 0 on success.</p>
   * <p><strong>-ENOENT</strong> if the bpf_local_storage cannot be found.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_cgrp_storage_delete(Ptr<?> map, Ptr<cgroup> cgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get a bpf_local_storage from the <em>cgroup</em>.</p>
   * <p>Logically, it could be thought of as getting the value from
   * a <em>map</em> with <em>cgroup</em> as the <strong>key</strong>.  From this
   * perspective,  the usage is not much different from
   * <strong>bpf_map_lookup_elem</strong>\ (<em>map</em>, <strong>&amp;</strong>\ <em>cgroup</em>) except this
   * helper enforces the key must be a cgroup struct and the map must also
   * be a <strong>BPF_MAP_TYPE_CGRP_STORAGE</strong>.</p>
   * <p>In reality, the local-storage value is embedded directly inside of the
   * <em>cgroup</em> object itself, rather than being located in the
   * <strong>BPF_MAP_TYPE_CGRP_STORAGE</strong> map. When the local-storage value is
   * queried for some <em>map</em> on a <em>cgroup</em> object, the kernel will perform an
   * O(n) iteration over all of the live local-storage values for that
   * <em>cgroup</em> object until the local-storage value for the <em>map</em> is found.</p>
   * <p>An optional <em>flags</em> (<strong>BPF_LOCAL_STORAGE_GET_F_CREATE</strong>) can be
   * used such that a new bpf_local_storage will be
   * created if one does not exist.  <em>value</em> can be used
   * together with <strong>BPF_LOCAL_STORAGE_GET_F_CREATE</strong> to specify
   * the initial value of a bpf_local_storage.  If <em>value</em> is
   * <strong>NULL</strong>, the new bpf_local_storage will be zero initialized.
   * @return A bpf_local_storage pointer is returned on success.</p>
   * <p><strong>NULL</strong> if not found or there was an error in adding
   * a new bpf_local_storage.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_cgrp_storage_get(Ptr<?> map, Ptr<cgroup> cgroup, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Check packet size against exceeding MTU of net device (based
   * on <em>ifindex</em>).  This helper will likely be used in combination
   * with helpers that adjust/change the packet size.</p>
   * <p>The argument <em>len_diff</em> can be used for querying with a planned
   * size change. This allows to check MTU prior to changing packet
   * ctx. Providing a <em>len_diff</em> adjustment that is larger than the
   * actual packet size (resulting in negative packet size) will in
   * principle not exceed the MTU, which is why it is not considered
   * a failure.  Other BPF helpers are needed for performing the
   * planned size change; therefore the responsibility for catching
   * a negative packet size belongs in those helpers.</p>
   * <p>Specifying <em>ifindex</em> zero means the MTU check is performed
   * against the current net device.  This is practical if this isn't
   * used prior to redirect.</p>
   * <p>On input <em>mtu_len</em> must be a valid pointer, else verifier will
   * reject BPF program.  If the value <em>mtu_len</em> is initialized to
   * zero then the ctx packet size is use.  When value <em>mtu_len</em> is
   * provided as input this specify the L3 length that the MTU check
   * is done against. Remember XDP and TC length operate at L2, but
   * this value is L3 as this correlate to MTU and IP-header tot_len
   * values which are L3 (similar behavior as bpf_fib_lookup).</p>
   * <p>The Linux kernel route table can configure MTUs on a more
   * specific per route level, which is not provided by this helper.
   * For route level MTU checks use the <strong>bpf_fib_lookup</strong>\ ()
   * helper.</p>
   * <p><em>ctx</em> is either <strong>struct xdp_md</strong> for XDP programs or
   * <strong>struct sk_buff</strong> for tc cls_act programs.</p>
   * <p>The <em>flags</em> argument can be a combination of one or more of the
   * following values:</p>
   * <p><strong>BPF_MTU_CHK_SEGS</strong>
   * This flag will only works for <em>ctx</em> <strong>struct sk_buff</strong>.
   * If packet context contains extra packet segment buffers
   * (often knows as GSO skb), then MTU check is harder to
   * check at this point, because in transmit path it is
   * possible for the skb packet to get re-segmented
   * (depending on net device features).  This could still be
   * a MTU violation, so this flag enables performing MTU
   * check against segments, with a different violation
   * return code to tell it apart. Check cannot use len_diff.</p>
   * <p>On return <em>mtu_len</em> pointer contains the MTU value of the net
   * device.  Remember the net device configured MTU is the L3 size,
   * which is returned here and XDP and TC length operate at L2.
   * Helper take this into account for you, but remember when using
   * MTU value in your BPF-code.
   * @return <ul>
   * <li>
   * <p>0 on success, and populate MTU value in <em>mtu_len</em> pointer.</p>
   * </li>
   * <li>
   * <p>&lt; 0 if any input argument is invalid (<em>mtu_len</em> not updated)</p>
   * </li>
   * </ul>
   * <p>MTU violations return positive values, but also populate MTU
   * value in <em>mtu_len</em> pointer, as this can be needed for
   * implementing PMTU handing:</p>
   * <ul>
   * <li><strong>BPF_MTU_CHK_RET_FRAG_NEEDED</strong></li>
   * <li><strong>BPF_MTU_CHK_RET_SEGS_TOOBIG</strong></li>
   * </ul>
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_check_mtu(Ptr<?> ctx, @Unsigned int ifindex,
      Ptr<java.lang. @Unsigned Integer> mtu_len, int len_diff, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Clone and redirect the packet associated to <em>skb</em> to another
   * net device of index <em>ifindex</em>. Both ingress and egress
   * interfaces can be used for redirection. The <strong>BPF_F_INGRESS</strong>
   * value in <em>flags</em> is used to make the distinction (ingress path
   * is selected if the flag is present, egress path otherwise).
   * This is the only flag supported for now.</p>
   * <p>In comparison with <strong>bpf_redirect</strong>\ () helper,
   * <strong>bpf_clone_redirect</strong>\ () has the associated cost of
   * duplicating the packet buffer, but this can be executed out of
   * the eBPF program. Conversely, <strong>bpf_redirect</strong>\ () is more
   * efficient, but it is handled through an action code where the
   * redirection happens only after the eBPF program has returned.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure. Positive
   * error indicates a potential drop or congestion in the target
   * device. The particular positive error codes are not defined.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_clone_redirect(Ptr<__sk_buff> skb, @Unsigned int ifindex,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Read <em>size</em> bytes from user space address <em>user_ptr</em> and store
   * the data in <em>dst</em>. This is a wrapper of <strong>copy_from_user</strong>\ ().
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user($arg1, $arg2, (const void*)$arg3)")
  public static long bpf_copy_from_user(Ptr<?> dst, @Unsigned int size, Ptr<?> user_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Read <em>size</em> bytes from user space address <em>user_ptr</em> in <em>tsk</em>'s
   * address space, and stores the data in <em>dst</em>. <em>flags</em> is not
   * used yet and is provided for future extensibility. This helper
   * can only be used by sleepable programs.
   * @return 0 on success, or a negative error in case of failure. On error
   * <em>dst</em> buffer is zeroed out.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user_task($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static long bpf_copy_from_user_task(Ptr<?> dst, @Unsigned int size, Ptr<?> user_ptr,
      Ptr<task_struct> tsk, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Compute a checksum difference, from the raw buffer pointed by
   * <em>from</em>, of length <em>from_size</em> (that must be a multiple of 4),
   * towards the raw buffer pointed by <em>to</em>, of size <em>to_size</em>
   * (same remark). An optional <em>seed</em> can be added to the value
   * (this can be cascaded, the seed may come from a previous call
   * to the helper).</p>
   * <p>This is flexible enough to be used in several ways:</p>
   * <ul>
   * <li>With <em>from_size</em> == 0, <em>to_size</em> &gt; 0 and <em>seed</em> set to
   * checksum, it can be used when pushing new data.</li>
   * <li>With <em>from_size</em> &gt; 0, <em>to_size</em> == 0 and <em>seed</em> set to
   * checksum, it can be used when removing data from a packet.</li>
   * <li>With <em>from_size</em> &gt; 0, <em>to_size</em> &gt; 0 and <em>seed</em> set to 0, it
   * can be used to compute a diff. Note that <em>from_size</em> and
   * <em>to_size</em> do not need to be equal.</li>
   * </ul>
   * <p>This helper can be used in combination with
   * <strong>bpf_l3_csum_replace</strong>\ () and <strong>bpf_l4_csum_replace</strong>\ (), to
   * which one can feed in the difference computed with
   * <strong>bpf_csum_diff</strong>\ ().
   * @return The checksum result, or a negative error code in case of
   * failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_csum_diff(Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> from,
      @Unsigned int from_size, Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> to,
      @Unsigned int to_size, @Unsigned @OriginalName("__wsum") int seed) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Change the skbs checksum level by one layer up or down, or
   * reset it entirely to none in order to have the stack perform
   * checksum validation. The level is applicable to the following
   * protocols: TCP, UDP, GRE, SCTP, FCOE. For example, a decap of
   * | ETH | IP | UDP | GUE | IP | TCP | into | ETH | IP | TCP |
   * through <strong>bpf_skb_adjust_room</strong>\ () helper with passing in
   * <strong>BPF_F_ADJ_ROOM_NO_CSUM_RESET</strong> flag would require one	call
   * to <strong>bpf_csum_level</strong>\ () with <strong>BPF_CSUM_LEVEL_DEC</strong> since
   * the UDP header is removed. Similarly, an encap of the latter
   * into the former could be accompanied by a helper call to
   * <strong>bpf_csum_level</strong>\ () with <strong>BPF_CSUM_LEVEL_INC</strong> if the
   * skb is still intended to be processed in higher layers of the
   * stack instead of just egressing at tc.</p>
   * <p>There are three supported level settings at this time:</p>
   * <ul>
   * <li><strong>BPF_CSUM_LEVEL_INC</strong>: Increases skb-&gt;csum_level for skbs
   * with CHECKSUM_UNNECESSARY.</li>
   * <li><strong>BPF_CSUM_LEVEL_DEC</strong>: Decreases skb-&gt;csum_level for skbs
   * with CHECKSUM_UNNECESSARY.</li>
   * <li><strong>BPF_CSUM_LEVEL_RESET</strong>: Resets skb-&gt;csum_level to 0 and
   * sets CHECKSUM_NONE to force checksum validation by the stack.</li>
   * <li><strong>BPF_CSUM_LEVEL_QUERY</strong>: No-op, returns the current
   * skb-&gt;csum_level.</li>
   * </ul>
   * @return 0 on success, or a negative error in case of failure. In the
   * case of <strong>BPF_CSUM_LEVEL_QUERY</strong>, the current skb-&gt;csum_level
   * is returned or the error code -EACCES in case the skb is not
   * subject to CHECKSUM_UNNECESSARY.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_csum_level(Ptr<__sk_buff> skb, @Unsigned long level) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Add the checksum <em>csum</em> into <em>skb</em>\ <strong>-&gt;csum</strong> in case the
   * driver has supplied a checksum for the entire packet into that
   * field. Return an error otherwise. This helper is intended to be
   * used in combination with <strong>bpf_csum_diff</strong>\ (), in particular
   * when the checksum needs to be updated after data has been
   * written into the packet through direct packet access.
   * @return The checksum on success, or a negative error code in case of
   * failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_csum_update(Ptr<__sk_buff> skb,
      @Unsigned @OriginalName("__wsum") int csum) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Check whether the probe is being run is the context of a given
   * subset of the cgroup2 hierarchy. The cgroup2 to test is held by
   * <em>map</em> of type <strong>BPF_MAP_TYPE_CGROUP_ARRAY</strong>, at <em>index</em>.
   * @return <p>The return value depends on the result of the test, and can be:</p>
   * <ul>
   * <li>1, if current task belongs to the cgroup2.</li>
   * <li>0, if current task does not belong to the cgroup2.</li>
   * <li>A negative error code, if an error occurred.</li>
   * </ul>
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_current_task_under_cgroup(Ptr<?> map, @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return full path for given <strong>struct path</strong> object, which
   * needs to be the kernel BTF <em>path</em> object. The path is
   * returned in the provided buffer <em>buf</em> of size <em>sz</em> and
   * is zero terminated.
   * @return On success, the strictly positive length of the string,
   * including the trailing NUL character. On error, a negative
   * value.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_d_path(Ptr<path> path, String buf, @Unsigned int sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get a pointer to the underlying dynptr data.</p>
   * <p><em>len</em> must be a statically known value. The returned data slice
   * is invalidated whenever the dynptr is invalidated.</p>
   * <p>skb and xdp type dynptrs may not use bpf_dynptr_data. They should
   * instead use bpf_dynptr_slice and bpf_dynptr_slice_rdwr.
   * @return Pointer to the underlying dynptr data, NULL if the dynptr is
   * read-only, if the dynptr is invalid, or if the offset and length
   * is out of bounds.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_data((const struct bpf_dynptr*)$arg1, $arg2, $arg3)")
  public static Ptr<?> bpf_dynptr_data(Ptr<bpf_dynptr> ptr, @Unsigned int offset,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get a dynptr to local memory <em>data</em>.</p>
   * <p><em>data</em> must be a ptr to a map value.
   * The maximum <em>size</em> supported is DYNPTR_MAX_SIZE.
   * <em>flags</em> is currently unused.
   * @return 0 on success, -E2BIG if the size exceeds DYNPTR_MAX_SIZE,
   * -EINVAL if flags is not 0.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_dynptr_from_mem(Ptr<?> data, @Unsigned int size, @Unsigned long flags,
      Ptr<bpf_dynptr> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Read <em>len</em> bytes from <em>src</em> into <em>dst</em>, starting from <em>offset</em>
   * into <em>src</em>.
   * <em>flags</em> is currently unused.
   * @return 0 on success, -E2BIG if <em>offset</em> + <em>len</em> exceeds the length
   * of <em>src</em>'s data, -EINVAL if <em>src</em> is an invalid dynptr or if
   * <em>flags</em> is not 0.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_read($arg1, $arg2, (const struct bpf_dynptr*)$arg3, $arg4, $arg5)")
  public static long bpf_dynptr_read(Ptr<?> dst, @Unsigned int len, Ptr<bpf_dynptr> src,
      @Unsigned int offset, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Write <em>len</em> bytes from <em>src</em> into <em>dst</em>, starting from <em>offset</em>
   * into <em>dst</em>.</p>
   * <p><em>flags</em> must be 0 except for skb-type dynptrs.</p>
   * <p>For skb-type dynptrs:
   * *  All data slices of the dynptr are automatically
   * invalidated after <strong>bpf_dynptr_write</strong>\ (). This is
   * because writing may pull the skb and change the
   * underlying packet buffer.</p>
   * <pre><code>*  For *flags*, please see the flags accepted by
   *    **bpf_skb_store_bytes**\ ().
   * </code></pre>
   * @return 0 on success, -E2BIG if <em>offset</em> + <em>len</em> exceeds the length
   * of <em>dst</em>'s data, -EINVAL if <em>dst</em> is an invalid dynptr or if <em>dst</em>
   * is a read-only dynptr or if <em>flags</em> is not correct. For skb-type dynptrs,
   * other errors correspond to errors returned by <strong>bpf_skb_store_bytes</strong>\ ().
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_write((const struct bpf_dynptr*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static long bpf_dynptr_write(Ptr<bpf_dynptr> dst, @Unsigned int offset, Ptr<?> src,
      @Unsigned int len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Do FIB lookup in kernel tables using parameters in <em>params</em>.
   * If lookup is successful and result shows packet is to be
   * forwarded, the neighbor tables are searched for the nexthop.
   * If successful (ie., FIB lookup shows forwarding and nexthop
   * is resolved), the nexthop address is returned in ipv4_dst
   * or ipv6_dst based on family, smac is set to mac address of
   * egress device, dmac is set to nexthop mac address, rt_metric
   * is set to metric from route (IPv4/IPv6 only), and ifindex
   * is set to the device index of the nexthop from the FIB lookup.</p>
   * <p><em>plen</em> argument is the size of the passed in struct.
   * <em>flags</em> argument can be a combination of one or more of the
   * following values:</p>
   * <p><strong>BPF_FIB_LOOKUP_DIRECT</strong>
   * Do a direct table lookup vs full lookup using FIB
   * rules.
   * <strong>BPF_FIB_LOOKUP_TBID</strong>
   * Used with BPF_FIB_LOOKUP_DIRECT.
   * Use the routing table ID present in <em>params</em>-&gt;tbid
   * for the fib lookup.
   * <strong>BPF_FIB_LOOKUP_OUTPUT</strong>
   * Perform lookup from an egress perspective (default is
   * ingress).
   * <strong>BPF_FIB_LOOKUP_SKIP_NEIGH</strong>
   * Skip the neighbour table lookup. <em>params</em>-&gt;dmac
   * and <em>params</em>-&gt;smac will not be set as output. A common
   * use case is to call <strong>bpf_redirect_neigh</strong>\ () after
   * doing <strong>bpf_fib_lookup</strong>\ ().
   * <strong>BPF_FIB_LOOKUP_SRC</strong>
   * Derive and set source IP addr in <em>params</em>-&gt;ipv{4,6}_src
   * for the nexthop. If the src addr cannot be derived,
   * <strong>BPF_FIB_LKUP_RET_NO_SRC_ADDR</strong> is returned. In this
   * case, <em>params</em>-&gt;dmac and <em>params</em>-&gt;smac are not set either.</p>
   * <p><em>ctx</em> is either <strong>struct xdp_md</strong> for XDP programs or
   * <strong>struct sk_buff</strong> tc cls_act programs.
   * @return <ul>
   * <li>&lt; 0 if any input argument is invalid</li>
   * <li>0 on success (packet is forwarded, nexthop neighbor exists)</li>
   * <li>
   * <blockquote>
   * <p>0 one of <strong>BPF_FIB_LKUP_RET_</strong> codes explaining why the
   * packet is not forwarded or needs assist from full stack</p>
   * </blockquote>
   * </li>
   * </ul>
   * <p>If lookup fails with BPF_FIB_LKUP_RET_FRAG_NEEDED, then the MTU
   * was exceeded and output params-&gt;mtu_result contains the MTU.</p>
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_fib_lookup(Ptr<?> ctx, Ptr<bpf_fib_lookup> params, int plen,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Find vma of <em>task</em> that contains <em>addr</em>, call <em>callback_fn</em>
   * function with <em>task</em>, <em>vma</em>, and <em>callback_ctx</em>.
   * The <em>callback_fn</em> should be a static function and
   * the <em>callback_ctx</em> should be a pointer to the stack.
   * The <em>flags</em> is used to control certain aspects of the helper.
   * Currently, the <em>flags</em> must be 0.</p>
   * <p>The expected callback signature is</p>
   * <p>long (*callback_fn)(struct task_struct *task, struct vm_area_struct *vma, void *callback_ctx);
   * @return 0 on success.
   * <strong>-ENOENT</strong> if <em>task-&gt;mm</em> is NULL, or no vma contains <em>addr</em>.
   * <strong>-EBUSY</strong> if failed to try lock mmap_lock.
   * <strong>-EINVAL</strong> for invalid <strong>flags</strong>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_find_vma(Ptr<task_struct> task, @Unsigned long addr, Ptr<?> callback_fn,
      Ptr<?> callback_ctx, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For each element in <strong>map</strong>, call <strong>callback_fn</strong> function with
   * <strong>map</strong>, <strong>callback_ctx</strong> and other map-specific parameters.
   * The <strong>callback_fn</strong> should be a static function and
   * the <strong>callback_ctx</strong> should be a pointer to the stack.
   * The <strong>flags</strong> is used to control certain aspects of the helper.
   * Currently, the <strong>flags</strong> must be 0.</p>
   * <p>The following are a list of supported map types and their
   * respective expected callback signatures:</p>
   * <p>BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_HASH,
   * BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH,
   * BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY</p>
   * <p>long (*callback_fn)(struct bpf_map *map, const void *key, void *value, void *ctx);</p>
   * <p>For per_cpu maps, the map_value is the value on the cpu where the
   * bpf_prog is running.</p>
   * <p>If <strong>callback_fn</strong> return 0, the helper will continue to the next
   * element. If return value is 1, the helper will skip the rest of
   * elements and return. Other return values are not used now.
   * @return The number of traversed map elements for success, <strong>-EINVAL</strong> for
   * invalid <strong>flags</strong>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_for_each_map_elem(Ptr<?> map, Ptr<?> callback_fn, Ptr<?> callback_ctx,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get bpf_cookie value provided (optionally) during the program
   * attachment. It might be different for each individual
   * attachment, even if BPF program itself is the same.
   * Expects BPF program context <em>ctx</em> as a first argument.</p>
   * <p>Supported for the following program types:
   * - kprobe/uprobe;
   * - tracepoint;
   * - perf_event.
   * @return Value specified by user at BPF link creation/attachment time
   * or 0, if it was not specified.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_attach_cookie(Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get branch trace from hardware engines like Intel LBR. The
   * hardware engine is stopped shortly after the helper is
   * called. Therefore, the user need to filter branch entries
   * based on the actual use case. To capture branch trace
   * before the trigger point of the BPF program, the helper
   * should be called at the beginning of the BPF program.</p>
   * <p>The data is stored as struct perf_branch_entry into output
   * buffer <em>entries</em>. <em>size</em> is the size of <em>entries</em> in bytes.
   * <em>flags</em> is reserved for now and must be zero.
   * @return On success, number of bytes written to <em>buf</em>. On error, a
   * negative value.</p>
   * <p><strong>-EINVAL</strong> if <em>flags</em> is not zero.</p>
   * <p><strong>-ENOENT</strong> if architecture does not support branch records.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_branch_snapshot(Ptr<?> entries, @Unsigned int size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Retrieve the classid for the current task, i.e. for the net_cls
   * cgroup to which <em>skb</em> belongs.</p>
   * <p>This helper can be used on TC egress path, but not on ingress.</p>
   * <p>The net_cls cgroup provides an interface to tag network packets
   * based on a user-provided identifier for all traffic coming from
   * the tasks belonging to the related cgroup. See also the related
   * kernel documentation, available from the Linux sources in file
   * <em>Documentation/admin-guide/cgroup-v1/net_cls.rst</em>.</p>
   * <p>The Linux kernel has two versions for cgroups: there are
   * cgroups v1 and cgroups v2. Both are available to users, who can
   * use a mixture of them, but note that the net_cls cgroup is for
   * cgroup v1 only. This makes it incompatible with BPF programs
   * run on cgroups, which is a cgroup-v2-only feature (a socket can
   * only hold data for one version of cgroups at a time).</p>
   * <p>This helper is only available is the kernel was compiled with
   * the <strong>CONFIG_CGROUP_NET_CLASSID</strong> configuration option set to
   * &quot;<strong>y</strong>&quot; or to &quot;<strong>m</strong>&quot;.
   * @return The classid, or 0 for the default unconfigured classid.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_get_cgroup_classid(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return id of cgroup v2 that is ancestor of the cgroup associated
   * with the current task at the <em>ancestor_level</em>. The root cgroup
   * is at <em>ancestor_level</em> zero and each step down the hierarchy
   * increments the level. If <em>ancestor_level</em> == level of cgroup
   * associated with the current task, then return value will be the
   * same as that of <strong>bpf_get_current_cgroup_id</strong>\ ().</p>
   * <p>The helper is useful to implement policies based on cgroups
   * that are upper in hierarchy than immediate cgroup associated
   * with the current task.</p>
   * <p>The format of returned id and helper limitations are same as in
   * <strong>bpf_get_current_cgroup_id</strong>\ ().
   * @return The id is returned or 0 in case the id could not be retrieved.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_ancestor_cgroup_id(int ancestor_level) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the current cgroup id based on the cgroup within which
   * the current task is running.
   * @return A 64-bit integer containing the current cgroup id based
   * on the cgroup within which the current task is running.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_cgroup_id() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Copy the <strong>comm</strong> attribute of the current task into <em>buf</em> of
   * <em>size_of_buf</em>. The <strong>comm</strong> attribute contains the name of
   * the executable (excluding the path) for the current task. The
   * <em>size_of_buf</em> must be strictly positive. On success, the
   * helper makes sure that the <em>buf</em> is NUL-terminated. On failure,
   * it is filled with zeroes.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_current_comm(Ptr<?> buf, @Unsigned int size_of_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the current pid and tgid.
   * @return A 64-bit integer containing the current tgid and pid, and
   * created as such:
   * <em>current_task</em>\ <strong>-&gt;tgid &lt;&lt; 32 |</strong>
   * <em>current_task</em>\ <strong>-&gt;pid</strong>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_pid_tgid() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the current task.
   * @return A pointer to the current task struct.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_task() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return a BTF pointer to the &quot;current&quot; task.
   * This pointer can also be used in helpers that accept an
   * <em>ARG_PTR_TO_BTF_ID</em> of type <em>task_struct</em>.
   * @return Pointer to the current task.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> bpf_get_current_task_btf() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the current uid and gid.
   * @return A 64-bit integer containing the current GID and UID, and
   * created as such: <em>current_gid</em> <strong>&lt;&lt; 32 |</strong> <em>current_uid</em>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_uid_gid() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get <strong>n</strong>-th argument register (zero based) of the traced function (for tracing programs)
   * returned in <strong>value</strong>.
   * @return 0 on success.
   * <strong>-EINVAL</strong> if n &gt;= argument register count of traced function.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_func_arg(Ptr<?> ctx, @Unsigned int n,
      Ptr<java.lang. @Unsigned Long> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get number of registers of the traced function (for tracing programs) where
   * function arguments are stored in these registers.
   * @return The number of argument registers of the traced function.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_func_arg_cnt(Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get address of the traced function (for tracing and kprobe programs).</p>
   * <p>When called for kprobe program attached as uprobe it returns
   * probe address for both entry and return uprobe.
   * @return Address of the traced function for kprobe.
   * 0 for kprobes placed within the function (not at the entry).
   * Address of the probe for uprobe and return uprobe.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_func_ip(Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get return value of the traced function (for tracing programs)
   * in <strong>value</strong>.
   * @return 0 on success.
   * <strong>-EOPNOTSUPP</strong> for tracing programs other than BPF_TRACE_FEXIT or BPF_MODIFY_RETURN.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_func_ret(Ptr<?> ctx, Ptr<java.lang. @Unsigned Long> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Retrieve the hash of the packet, <em>skb</em>\ <strong>-&gt;hash</strong>. If it is
   * not set, in particular if the hash was cleared due to mangling,
   * recompute this hash. Later accesses to the hash can be done
   * directly with <em>skb</em>\ <strong>-&gt;hash</strong>.</p>
   * <p>Calling <strong>bpf_set_hash_invalid</strong>\ (), changing a packet
   * prototype with <strong>bpf_skb_change_proto</strong>\ (), or calling
   * <strong>bpf_skb_store_bytes</strong>\ () with the
   * <strong>BPF_F_INVALIDATE_HASH</strong> are actions susceptible to clear
   * the hash and to trigger a new computation for the next call to
   * <strong>bpf_get_hash_recalc</strong>\ ().
   * @return The 32-bit hash.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_get_hash_recalc(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return a <strong>struct bpf_sock</strong> pointer in <strong>TCP_LISTEN</strong> state.
   * <strong>bpf_sk_release</strong>\ () is unnecessary and not allowed.
   * @return A <strong>struct bpf_sock</strong> pointer on success, or <strong>NULL</strong> in
   * case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_sock> bpf_get_listener_sock(Ptr<bpf_sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the pointer to the local storage area.
   * The type and the size of the local storage is defined
   * by the <em>map</em> argument.
   * The <em>flags</em> meaning is specific for each map type,
   * and has to be 0 for cgroup local storage.</p>
   * <p>Depending on the BPF program type, a local storage area
   * can be shared between multiple instances of the BPF program,
   * running simultaneously.</p>
   * <p>A user should care about the synchronization by himself.
   * For example, by using the <strong>BPF_ATOMIC</strong> instructions to alter
   * the shared data.
   * @return A pointer to the local storage area.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_get_local_storage(Ptr<?> map, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Retrieve the cookie (generated by the kernel) of the network
   * namespace the input <em>ctx</em> is associated with. The network
   * namespace cookie remains stable for its lifetime and provides
   * a global identifier that can be assumed unique. If <em>ctx</em> is
   * NULL, then the helper returns the cookie for the initial
   * network namespace. The cookie itself is very similar to that
   * of <strong>bpf_get_socket_cookie</strong>\ () helper, but for network
   * namespaces instead of sockets.
   * @return A 8-byte long opaque number.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_netns_cookie(Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Returns 0 on success, values for <em>pid</em> and <em>tgid</em> as seen from the current
   * <em>namespace</em> will be returned in <em>nsdata</em>.
   * @return 0 on success, or one of the following in case of failure:</p>
   * <p><strong>-EINVAL</strong> if dev and inum supplied don't match dev_t and inode number
   * with nsfs of current task, or if dev conversion to dev_t lost high bits.</p>
   * <p><strong>-ENOENT</strong> if pidns does not exists for the current task.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_ns_current_pid_tgid(@Unsigned long dev, @Unsigned long ino,
      Ptr<bpf_pidns_info> nsdata, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return the id of the current NUMA node. The primary use case
   * for this helper is the selection of sockets for the local NUMA
   * node, when the program is attached to sockets using the
   * <strong>SO_ATTACH_REUSEPORT_EBPF</strong> option (see also <strong>socket(7)</strong>),
   * but the helper is also available to other eBPF program types,
   * similarly to <strong>bpf_get_smp_processor_id</strong>\ ().
   * @return The id of current NUMA node.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_numa_node_id() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get a pseudo-random number.</p>
   * <p>From a security point of view, this helper uses its own
   * pseudo-random internal state, and cannot be used to infer the
   * seed of other random functions in the kernel. However, it is
   * essential to note that the generator used by the helper is not
   * cryptographically secure.
   * @return A random 32-bit unsigned value.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_get_prandom_u32() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the BPF program's return value that will be returned to the upper layers.</p>
   * <p>This helper is currently supported by cgroup programs and only by the hooks
   * where BPF program's return value is returned to the userspace via errno.
   * @return The BPF program's return value.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_get_retval() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Retrieve the realm or the route, that is to say the
   * <strong>tclassid</strong> field of the destination for the <em>skb</em>. The
   * identifier retrieved is a user-provided tag, similar to the
   * one used with the net_cls cgroup (see description for
   * <strong>bpf_get_cgroup_classid</strong>\ () helper), but here this tag is
   * held by a route (a destination entry), not by a task.</p>
   * <p>Retrieving this identifier works with the clsact TC egress hook
   * (see also <strong>tc-bpf(8)</strong>), or alternatively on conventional
   * classful egress qdiscs, but not on TC ingress path. In case of
   * clsact TC egress hook, this has the advantage that, internally,
   * the destination entry has not been dropped yet in the transmit
   * path. Therefore, the destination entry does not need to be
   * artificially held via <strong>netif_keep_dst</strong>\ () for a classful
   * qdisc until the <em>skb</em> is freed.</p>
   * <p>This helper is available only if the kernel was compiled with
   * <strong>CONFIG_IP_ROUTE_CLASSID</strong> configuration option.
   * @return The realm of the route for the packet associated to <em>skb</em>, or 0
   * if none was found.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_get_route_realm(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the SMP (symmetric multiprocessing) processor id. Note that
   * all programs run with migration disabled, which means that the
   * SMP processor id is stable during all the execution of the
   * program.
   * @return The SMP id of the processor running the program.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_get_smp_processor_id() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * If the <strong>struct sk_buff</strong> pointed by <em>skb</em> has a known socket,
   * retrieve the cookie (generated by the kernel) of this socket.
   * If no cookie has been set yet, generate a new cookie. Once
   * generated, the socket cookie remains stable for the life of the
   * socket. This helper can be useful for monitoring per socket
   * networking traffic statistics as it provides a global socket
   * identifier that can be assumed unique.
   * @return A 8-byte long unique number on success, or 0 if the socket
   * field is missing inside <em>skb</em>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_socket_cookie(Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the owner UID of the socked associated to <em>skb</em>.
   * @return The owner UID of the socket associated to <em>skb</em>. If the socket
   * is <strong>NULL</strong>, or if it is not a full socket (i.e. if it is a
   * time-wait or a request socket instead), <strong>overflowuid</strong> value
   * is returned (note that <strong>overflowuid</strong> might also be the actual
   * UID value for the socket).
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_get_socket_uid(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Return a user or a kernel stack in bpf program provided buffer.
   * To achieve this, the helper needs <em>ctx</em>, which is a pointer
   * to the context on which the tracing program is executed.
   * To store the stacktrace, the bpf program provides <em>buf</em> with
   * a nonnegative <em>size</em>.</p>
   * <p>The last argument, <em>flags</em>, holds the number of stack frames to
   * skip (from 0 to 255), masked with
   * <strong>BPF_F_SKIP_FIELD_MASK</strong>. The next bits can be used to set
   * the following flags:</p>
   * <p><strong>BPF_F_USER_STACK</strong>
   * Collect a user space stack instead of a kernel stack.
   * <strong>BPF_F_USER_BUILD_ID</strong>
   * Collect (build_id, file_offset) instead of ips for user
   * stack, only valid if <strong>BPF_F_USER_STACK</strong> is also
   * specified.</p>
   * <pre><code>*file_offset* is an offset relative to the beginning
   * of the executable or shared object file backing the vma
   * which the *ip* falls in. It is *not* an offset relative
   * to that object's base address. Accordingly, it must be
   * adjusted by adding (sh_addr - sh_offset), where
   * sh_{addr,offset} correspond to the executable section
   * containing *file_offset* in the object, for comparisons
   * to symbols' st_value to be valid.
   * </code></pre>
   * <p><strong>bpf_get_stack</strong>\ () can collect up to
   * <strong>PERF_MAX_STACK_DEPTH</strong> both kernel and user frames, subject
   * to sufficient large buffer size. Note that
   * this limit can be controlled with the <strong>sysctl</strong> program, and
   * that it should be manually increased in order to profile long
   * user stacks (such as stacks for Java programs). To do so, use:</p>
   * <p>::</p>
   * <pre><code># sysctl kernel.perf_event_max_stack=&lt;new value&gt;
   * </code></pre>
   * @return The non-negative copied <em>buf</em> length equal to or less than
   * <em>size</em> on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_stack(Ptr<?> ctx, Ptr<?> buf, @Unsigned int size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Walk a user or a kernel stack and return its id. To achieve
   * this, the helper needs <em>ctx</em>, which is a pointer to the context
   * on which the tracing program is executed, and a pointer to a
   * <em>map</em> of type <strong>BPF_MAP_TYPE_STACK_TRACE</strong>.</p>
   * <p>The last argument, <em>flags</em>, holds the number of stack frames to
   * skip (from 0 to 255), masked with
   * <strong>BPF_F_SKIP_FIELD_MASK</strong>. The next bits can be used to set
   * a combination of the following flags:</p>
   * <p><strong>BPF_F_USER_STACK</strong>
   * Collect a user space stack instead of a kernel stack.
   * <strong>BPF_F_FAST_STACK_CMP</strong>
   * Compare stacks by hash only.
   * <strong>BPF_F_REUSE_STACKID</strong>
   * If two different stacks hash into the same <em>stackid</em>,
   * discard the old one.</p>
   * <p>The stack id retrieved is a 32 bit long integer handle which
   * can be further combined with other data (including other stack
   * ids) and used as a key into maps. This can be useful for
   * generating a variety of graphs (such as flame graphs or off-cpu
   * graphs).</p>
   * <p>For walking a stack, this helper is an improvement over
   * <strong>bpf_probe_read</strong>\ (), which can be used with unrolled loops
   * but is not efficient and consumes a lot of eBPF instructions.
   * Instead, <strong>bpf_get_stackid</strong>\ () can collect up to
   * <strong>PERF_MAX_STACK_DEPTH</strong> both kernel and user frames. Note that
   * this limit can be controlled with the <strong>sysctl</strong> program, and
   * that it should be manually increased in order to profile long
   * user stacks (such as stacks for Java programs). To do so, use:</p>
   * <p>::</p>
   * <pre><code># sysctl kernel.perf_event_max_stack=&lt;new value&gt;
   * </code></pre>
   * @return The positive or null stack id on success, or a negative error
   * in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_stackid(Ptr<?> ctx, Ptr<?> map, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Return a user or a kernel stack in bpf program provided buffer.
   * Note: the user stack will only be populated if the <em>task</em> is
   * the current task; all other tasks will return -EOPNOTSUPP.
   * To achieve this, the helper needs <em>task</em>, which is a valid
   * pointer to <strong>struct task_struct</strong>. To store the stacktrace, the
   * bpf program provides <em>buf</em> with a nonnegative <em>size</em>.</p>
   * <p>The last argument, <em>flags</em>, holds the number of stack frames to
   * skip (from 0 to 255), masked with
   * <strong>BPF_F_SKIP_FIELD_MASK</strong>. The next bits can be used to set
   * the following flags:</p>
   * <p><strong>BPF_F_USER_STACK</strong>
   * Collect a user space stack instead of a kernel stack.
   * The <em>task</em> must be the current task.
   * <strong>BPF_F_USER_BUILD_ID</strong>
   * Collect buildid+offset instead of ips for user stack,
   * only valid if <strong>BPF_F_USER_STACK</strong> is also specified.</p>
   * <p><strong>bpf_get_task_stack</strong>\ () can collect up to
   * <strong>PERF_MAX_STACK_DEPTH</strong> both kernel and user frames, subject
   * to sufficient large buffer size. Note that
   * this limit can be controlled with the <strong>sysctl</strong> program, and
   * that it should be manually increased in order to profile long
   * user stacks (such as stacks for Java programs). To do so, use:</p>
   * <p>::</p>
   * <pre><code># sysctl kernel.perf_event_max_stack=&lt;new value&gt;
   * </code></pre>
   * @return The non-negative copied <em>buf</em> length equal to or less than
   * <em>size</em> on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_get_task_stack(Ptr<task_struct> task, Ptr<?> buf, @Unsigned int size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Emulate a call to <strong>getsockopt()</strong> on the socket associated to
   * <em>bpf_socket</em>, which must be a full socket. The <em>level</em> at
   * which the option resides and the name <em>optname</em> of the option
   * must be specified, see <strong>getsockopt(2)</strong> for more information.
   * The retrieved value is stored in the structure pointed by
   * <em>opval</em> and of length <em>optlen</em>.</p>
   * <p><em>bpf_socket</em> should be one of the following:</p>
   * <ul>
   * <li><strong>struct bpf_sock_ops</strong> for <strong>BPF_PROG_TYPE_SOCK_OPS</strong>.</li>
   * <li><strong>struct bpf_sock_addr</strong> for <strong>BPF_CGROUP_INET4_CONNECT</strong>,
   * <strong>BPF_CGROUP_INET6_CONNECT</strong> and <strong>BPF_CGROUP_UNIX_CONNECT</strong>.</li>
   * </ul>
   * <p>This helper actually implements a subset of <strong>getsockopt()</strong>.
   * It supports the same set of <em>optname</em>\ s that is supported by
   * the <strong>bpf_setsockopt</strong>\ () helper.  The exceptions are
   * <strong>TCP_BPF_</strong>* is <strong>bpf_setsockopt</strong>\ () only and
   * <strong>TCP_SAVED_SYN</strong> is <strong>bpf_getsockopt</strong>\ () only.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_getsockopt(Ptr<?> bpf_socket, int level, int optname, Ptr<?> optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Returns a calculated IMA hash of the <em>file</em>.
   * If the hash is larger than <em>size</em>, then only <em>size</em>
   * bytes will be copied to <em>dst</em>
   * @return The <strong>hash_algo</strong> is returned on success,
   * <strong>-EOPNOTSUP</strong> if the hash calculation failed or <strong>-EINVAL</strong> if
   * invalid arguments are passed.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_ima_file_hash(Ptr<file> file, Ptr<?> dst, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Returns the stored IMA hash of the <em>inode</em> (if it's available).
   * If the hash is larger than <em>size</em>, then only <em>size</em>
   * bytes will be copied to <em>dst</em>
   * @return The <strong>hash_algo</strong> is returned on success,
   * <strong>-EOPNOTSUP</strong> if IMA is disabled or <strong>-EINVAL</strong> if
   * invalid arguments are passed.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_ima_inode_hash(Ptr<inode> inode, Ptr<?> dst, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Delete a bpf_local_storage from an <em>inode</em>.
   * @return 0 on success.</p>
   * <p><strong>-ENOENT</strong> if the bpf_local_storage cannot be found.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_inode_storage_delete(Ptr<?> map, Ptr<?> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get a bpf_local_storage from an <em>inode</em>.</p>
   * <p>Logically, it could be thought of as getting the value from
   * a <em>map</em> with <em>inode</em> as the <strong>key</strong>.  From this
   * perspective,  the usage is not much different from
   * <strong>bpf_map_lookup_elem</strong>\ (<em>map</em>, <strong>&amp;</strong>\ <em>inode</em>) except this
   * helper enforces the key must be an inode and the map must also
   * be a <strong>BPF_MAP_TYPE_INODE_STORAGE</strong>.</p>
   * <p>Underneath, the value is stored locally at <em>inode</em> instead of
   * the <em>map</em>.  The <em>map</em> is used as the bpf-local-storage
   * &quot;type&quot;. The bpf-local-storage &quot;type&quot; (i.e. the <em>map</em>) is
   * searched against all bpf_local_storage residing at <em>inode</em>.</p>
   * <p>An optional <em>flags</em> (<strong>BPF_LOCAL_STORAGE_GET_F_CREATE</strong>) can be
   * used such that a new bpf_local_storage will be
   * created if one does not exist.  <em>value</em> can be used
   * together with <strong>BPF_LOCAL_STORAGE_GET_F_CREATE</strong> to specify
   * the initial value of a bpf_local_storage.  If <em>value</em> is
   * <strong>NULL</strong>, the new bpf_local_storage will be zero initialized.
   * @return A bpf_local_storage pointer is returned on success.</p>
   * <p><strong>NULL</strong> if not found or there was an error in adding
   * a new bpf_local_storage.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_inode_storage_get(Ptr<?> map, Ptr<?> inode, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Obtain the 64bit jiffies
   * @return The 64 bit jiffies
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_jiffies64() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the address of a kernel symbol, returned in <em>res</em>. <em>res</em> is
   * set to 0 if the symbol is not found.
   * @return On success, zero. On error, a negative value.</p>
   * <p><strong>-EINVAL</strong> if <em>flags</em> is not zero.</p>
   * <p><strong>-EINVAL</strong> if string <em>name</em> is not the same size as <em>name_sz</em>.</p>
   * <p><strong>-ENOENT</strong> if symbol is not found.</p>
   * <p><strong>-EPERM</strong> if caller does not have permission to obtain kernel address.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kallsyms_lookup_name((const u8 *)$arg1, $arg2, $arg3, $arg4)")
  public static long bpf_kallsyms_lookup_name(String name, int name_sz, int flags,
      Ptr<java.lang. @Unsigned Long> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Exchange kptr at pointer <em>map_value</em> with <em>ptr</em>, and return the
   * old value. <em>ptr</em> can be NULL, otherwise it must be a referenced
   * pointer which will be released when this helper is called.
   * @return The old value of kptr (which can be NULL). The returned pointer
   * if not NULL, is a reference which must be released using its
   * corresponding release function, or moved into a BPF map before
   * program exit.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_kptr_xchg(Ptr<?> map_value, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return the time elapsed since system boot, in nanoseconds.
   * Does include the time the system was suspended.
   * See: <strong>clock_gettime</strong>\ (<strong>CLOCK_BOOTTIME</strong>)
   * @return Current <em>ktime</em>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_boot_ns() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return a coarse-grained version of the time elapsed since
   * system boot, in nanoseconds. Does not include time the system
   * was suspended.</p>
   * <p>See: <strong>clock_gettime</strong>\ (<strong>CLOCK_MONOTONIC_COARSE</strong>)
   * @return Current <em>ktime</em>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_coarse_ns() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return the time elapsed since system boot, in nanoseconds.
   * Does not include time the system was suspended.
   * See: <strong>clock_gettime</strong>\ (<strong>CLOCK_MONOTONIC</strong>)
   * @return Current <em>ktime</em>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_ns() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * A nonsettable system-wide clock derived from wall-clock time but
   * ignoring leap seconds.  This clock does not experience
   * discontinuities and backwards jumps caused by NTP inserting leap
   * seconds as CLOCK_REALTIME does.</p>
   * <p>See: <strong>clock_gettime</strong>\ (<strong>CLOCK_TAI</strong>)
   * @return Current <em>ktime</em>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_tai_ns() {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Recompute the layer 3 (e.g. IP) checksum for the packet
   * associated to <em>skb</em>. Computation is incremental, so the helper
   * must know the former value of the header field that was
   * modified (<em>from</em>), the new value of this field (<em>to</em>), and the
   * number of bytes (2 or 4) for this field, stored in <em>size</em>.
   * Alternatively, it is possible to store the difference between
   * the previous and the new values of the header field in <em>to</em>, by
   * setting <em>from</em> and <em>size</em> to 0. For both methods, <em>offset</em>
   * indicates the location of the IP checksum within the packet.</p>
   * <p>This helper works in combination with <strong>bpf_csum_diff</strong>\ (),
   * which does not update the checksum in-place, but offers more
   * flexibility and can handle sizes larger than 2 or 4 for the
   * checksum to update.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_l3_csum_replace(Ptr<__sk_buff> skb, @Unsigned int offset,
      @Unsigned long from, @Unsigned long to, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Recompute the layer 4 (e.g. TCP, UDP or ICMP) checksum for the
   * packet associated to <em>skb</em>. Computation is incremental, so the
   * helper must know the former value of the header field that was
   * modified (<em>from</em>), the new value of this field (<em>to</em>), and the
   * number of bytes (2 or 4) for this field, stored on the lowest
   * four bits of <em>flags</em>. Alternatively, it is possible to store
   * the difference between the previous and the new values of the
   * header field in <em>to</em>, by setting <em>from</em> and the four lowest
   * bits of <em>flags</em> to 0. For both methods, <em>offset</em> indicates the
   * location of the IP checksum within the packet. In addition to
   * the size of the field, <em>flags</em> can be added (bitwise OR) actual
   * flags. With <strong>BPF_F_MARK_MANGLED_0</strong>, a null checksum is left
   * untouched (unless <strong>BPF_F_MARK_ENFORCE</strong> is added as well), and
   * for updates resulting in a null checksum the value is set to
   * <strong>CSUM_MANGLED_0</strong> instead. Flag <strong>BPF_F_PSEUDO_HDR</strong> indicates
   * the checksum is to be computed against a pseudo-header.</p>
   * <p>This helper works in combination with <strong>bpf_csum_diff</strong>\ (),
   * which does not update the checksum in-place, but offers more
   * flexibility and can handle sizes larger than 2 or 4 for the
   * checksum to update.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_l4_csum_replace(Ptr<__sk_buff> skb, @Unsigned int offset,
      @Unsigned long from, @Unsigned long to, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Load header option.  Support reading a particular TCP header
   * option for bpf program (<strong>BPF_PROG_TYPE_SOCK_OPS</strong>).</p>
   * <p>If <em>flags</em> is 0, it will search the option from the
   * <em>skops</em>\ <strong>-&gt;skb_data</strong>.  The comment in <strong>struct bpf_sock_ops</strong>
   * has details on what skb_data contains under different
   * <em>skops</em>\ <strong>-&gt;op</strong>.</p>
   * <p>The first byte of the <em>searchby_res</em> specifies the
   * kind that it wants to search.</p>
   * <p>If the searching kind is an experimental kind
   * (i.e. 253 or 254 according to RFC6994).  It also
   * needs to specify the &quot;magic&quot; which is either
   * 2 bytes or 4 bytes.  It then also needs to
   * specify the size of the magic by using
   * the 2nd byte which is &quot;kind-length&quot; of a TCP
   * header option and the &quot;kind-length&quot; also
   * includes the first 2 bytes &quot;kind&quot; and &quot;kind-length&quot;
   * itself as a normal TCP header option also does.</p>
   * <p>For example, to search experimental kind 254 with
   * 2 byte magic 0xeB9F, the searchby_res should be
   * [ 254, 4, 0xeB, 0x9F, 0, 0, .... 0 ].</p>
   * <p>To search for the standard window scale option (3),
   * the <em>searchby_res</em> should be [ 3, 0, 0, .... 0 ].
   * Note, kind-length must be 0 for regular option.</p>
   * <p>Searching for No-Op (0) and End-of-Option-List (1) are
   * not supported.</p>
   * <p><em>len</em> must be at least 2 bytes which is the minimal size
   * of a header option.</p>
   * <p>Supported flags:</p>
   * <ul>
   * <li><strong>BPF_LOAD_HDR_OPT_TCP_SYN</strong> to search from the
   * saved_syn packet or the just-received syn packet.</li>
   * </ul>
   * @return <blockquote>
   * <p>0 when found, the header option is copied to <em>searchby_res</em>.
   * The return value is the total length copied. On failure, a
   * negative error code is returned:</p>
   * </blockquote>
   * <p><strong>-EINVAL</strong> if a parameter is invalid.</p>
   * <p><strong>-ENOMSG</strong> if the option is not found.</p>
   * <p><strong>-ENOENT</strong> if no syn packet is available when
   * <strong>BPF_LOAD_HDR_OPT_TCP_SYN</strong> is used.</p>
   * <p><strong>-ENOSPC</strong> if there is not enough space.  Only <em>len</em> number of
   * bytes are copied.</p>
   * <p><strong>-EFAULT</strong> on failure to parse the header options in the
   * packet.</p>
   * <p><strong>-EPERM</strong> if the helper cannot be used under the current
   * <em>skops</em>\ <strong>-&gt;op</strong>.</p>
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_load_hdr_opt(Ptr<bpf_sock_ops> skops, Ptr<?> searchby_res,
      @Unsigned int len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For <strong>nr_loops</strong>, call <strong>callback_fn</strong> function
   * with <strong>callback_ctx</strong> as the context parameter.
   * The <strong>callback_fn</strong> should be a static function and
   * the <strong>callback_ctx</strong> should be a pointer to the stack.
   * The <strong>flags</strong> is used to control certain aspects of the helper.
   * Currently, the <strong>flags</strong> must be 0. Currently, nr_loops is
   * limited to 1 &lt;&lt; 23 (~8 million) loops.</p>
   * <p>long (*callback_fn)(u32 index, void *ctx);</p>
   * <p>where <strong>index</strong> is the current index in the loop. The index
   * is zero-indexed.</p>
   * <p>If <strong>callback_fn</strong> returns 0, the helper will continue to the next
   * loop. If return value is 1, the helper will skip the rest of
   * the loops and return. Other return values are not used now,
   * and will be rejected by the verifier.
   * @return The number of loops performed, <strong>-EINVAL</strong> for invalid <strong>flags</strong>,
   * <strong>-E2BIG</strong> if <strong>nr_loops</strong> exceeds the maximum number of loops.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_loop(@Unsigned int nr_loops, Ptr<?> callback_fn, Ptr<?> callback_ctx,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Encapsulate the packet associated to <em>skb</em> within a Layer 3
   * protocol header. This header is provided in the buffer at
   * address <em>hdr</em>, with <em>len</em> its size in bytes. <em>type</em> indicates
   * the protocol of the header and can be one of:</p>
   * <p><strong>BPF_LWT_ENCAP_SEG6</strong>
   * IPv6 encapsulation with Segment Routing Header
   * (<strong>struct ipv6_sr_hdr</strong>). <em>hdr</em> only contains the SRH,
   * the IPv6 header is computed by the kernel.
   * <strong>BPF_LWT_ENCAP_SEG6_INLINE</strong>
   * Only works if <em>skb</em> contains an IPv6 packet. Insert a
   * Segment Routing Header (<strong>struct ipv6_sr_hdr</strong>) inside
   * the IPv6 header.
   * <strong>BPF_LWT_ENCAP_IP</strong>
   * IP encapsulation (GRE/GUE/IPIP/etc). The outer header
   * must be IPv4 or IPv6, followed by zero or more
   * additional headers, up to <strong>LWT_BPF_MAX_HEADROOM</strong>
   * total bytes in all prepended headers. Please note that
   * if <strong>skb_is_gso</strong>\ (<em>skb</em>) is true, no more than two
   * headers can be prepended, and the inner header, if
   * present, should be either GRE or UDP/GUE.</p>
   * <p><strong>BPF_LWT_ENCAP_SEG6</strong>\ * types can be called by BPF programs
   * of type <strong>BPF_PROG_TYPE_LWT_IN</strong>; <strong>BPF_LWT_ENCAP_IP</strong> type can
   * be called by bpf programs of types <strong>BPF_PROG_TYPE_LWT_IN</strong> and
   * <strong>BPF_PROG_TYPE_LWT_XMIT</strong>.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_lwt_push_encap(Ptr<__sk_buff> skb, @Unsigned int type, Ptr<?> hdr,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Apply an IPv6 Segment Routing action of type <em>action</em> to the
   * packet associated to <em>skb</em>. Each action takes a parameter
   * contained at address <em>param</em>, and of length <em>param_len</em> bytes.
   * <em>action</em> can be one of:</p>
   * <p><strong>SEG6_LOCAL_ACTION_END_X</strong>
   * End.X action: Endpoint with Layer-3 cross-connect.
   * Type of <em>param</em>: <strong>struct in6_addr</strong>.
   * <strong>SEG6_LOCAL_ACTION_END_T</strong>
   * End.T action: Endpoint with specific IPv6 table lookup.
   * Type of <em>param</em>: <strong>int</strong>.
   * <strong>SEG6_LOCAL_ACTION_END_B6</strong>
   * End.B6 action: Endpoint bound to an SRv6 policy.
   * Type of <em>param</em>: <strong>struct ipv6_sr_hdr</strong>.
   * <strong>SEG6_LOCAL_ACTION_END_B6_ENCAP</strong>
   * End.B6.Encap action: Endpoint bound to an SRv6
   * encapsulation policy.
   * Type of <em>param</em>: <strong>struct ipv6_sr_hdr</strong>.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_lwt_seg6_action(Ptr<__sk_buff> skb, @Unsigned int action, Ptr<?> param,
      @Unsigned int param_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Adjust the size allocated to TLVs in the outermost IPv6
   * Segment Routing Header contained in the packet associated to
   * <em>skb</em>, at position <em>offset</em> by <em>delta</em> bytes. Only offsets
   * after the segments are accepted. <em>delta</em> can be as well
   * positive (growing) as negative (shrinking).</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_lwt_seg6_adjust_srh(Ptr<__sk_buff> skb, @Unsigned int offset, int delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Store <em>len</em> bytes from address <em>from</em> into the packet
   * associated to <em>skb</em>, at <em>offset</em>. Only the flags, tag and TLVs
   * inside the outermost IPv6 Segment Routing Header can be
   * modified through this helper.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lwt_seg6_store_bytes($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static long bpf_lwt_seg6_store_bytes(Ptr<__sk_buff> skb, @Unsigned int offset, Ptr<?> from,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Delete entry with <em>key</em> from <em>map</em>.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_delete_elem($arg1, (const void*)$arg2)")
  public static long bpf_map_delete_elem(Ptr<?> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Perform a lookup in <em>map</em> for an entry associated to <em>key</em>.
   * @return Map value associated to <em>key</em>, or <strong>NULL</strong> if no entry was
   * found.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_lookup_elem($arg1, (const void*)$arg2)")
  public static Ptr<?> bpf_map_lookup_elem(Ptr<?> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Perform a lookup in <em>percpu map</em> for an entry associated to
   * <em>key</em> on <em>cpu</em>.
   * @return Map value associated to <em>key</em> on <em>cpu</em>, or <strong>NULL</strong> if no entry
   * was found or <em>cpu</em> is invalid.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_lookup_percpu_elem($arg1, (const void*)$arg2, $arg3)")
  public static Ptr<?> bpf_map_lookup_percpu_elem(Ptr<?> map, Ptr<?> key, @Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get an element from <em>map</em> without removing it.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_map_peek_elem(Ptr<?> map, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Pop an element from <em>map</em>.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_map_pop_elem(Ptr<?> map, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Push an element <em>value</em> in <em>map</em>. <em>flags</em> is one of:</p>
   * <p><strong>BPF_EXIST</strong>
   * If the queue/stack is full, the oldest element is
   * removed to make room for this.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_push_elem($arg1, (const void*)$arg2, $arg3)")
  public static long bpf_map_push_elem(Ptr<?> map, Ptr<?> value, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Add or update the value of the entry associated to <em>key</em> in
   * <em>map</em> with <em>value</em>. <em>flags</em> is one of:</p>
   * <p><strong>BPF_NOEXIST</strong>
   * The entry for <em>key</em> must not exist in the map.
   * <strong>BPF_EXIST</strong>
   * The entry for <em>key</em> must already exist in the map.
   * <strong>BPF_ANY</strong>
   * No condition on the existence of the entry for <em>key</em>.</p>
   * <p>Flag value <strong>BPF_NOEXIST</strong> cannot be used for maps of types
   * <strong>BPF_MAP_TYPE_ARRAY</strong> or <strong>BPF_MAP_TYPE_PERCPU_ARRAY</strong>  (all
   * elements always exist), the helper would return an error.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_update_elem($arg1, (const void*)$arg2, (const void*)$arg3, $arg4)")
  public static long bpf_map_update_elem(Ptr<?> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For socket policies, apply the verdict of the eBPF program to
   * the next <em>bytes</em> (number of bytes) of message <em>msg</em>.</p>
   * <p>For example, this helper can be used in the following cases:</p>
   * <ul>
   * <li>A single <strong>sendmsg</strong>\ () or <strong>sendfile</strong>\ () system call
   * contains multiple logical messages that the eBPF program is
   * supposed to read and for which it should apply a verdict.</li>
   * <li>An eBPF program only cares to read the first <em>bytes</em> of a
   * <em>msg</em>. If the message has a large payload, then setting up
   * and calling the eBPF program repeatedly for all bytes, even
   * though the verdict is already known, would create unnecessary
   * overhead.</li>
   * </ul>
   * <p>When called from within an eBPF program, the helper sets a
   * counter internal to the BPF infrastructure, that is used to
   * apply the last verdict to the next <em>bytes</em>. If <em>bytes</em> is
   * smaller than the current data being processed from a
   * <strong>sendmsg</strong>\ () or <strong>sendfile</strong>\ () system call, the first
   * <em>bytes</em> will be sent and the eBPF program will be re-run with
   * the pointer for start of data pointing to byte number <em>bytes</em>
   * <strong>+ 1</strong>. If <em>bytes</em> is larger than the current data being
   * processed, then the eBPF verdict will be applied to multiple
   * <strong>sendmsg</strong>\ () or <strong>sendfile</strong>\ () calls until <em>bytes</em> are
   * consumed.</p>
   * <p>Note that if a socket closes with the internal counter holding
   * a non-zero value, this is not a problem because data is not
   * being buffered for <em>bytes</em> and is sent as it is received.
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_msg_apply_bytes(Ptr<sk_msg_md> msg, @Unsigned int bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For socket policies, prevent the execution of the verdict eBPF
   * program for message <em>msg</em> until <em>bytes</em> (byte number) have been
   * accumulated.</p>
   * <p>This can be used when one needs a specific number of bytes
   * before a verdict can be assigned, even if the data spans
   * multiple <strong>sendmsg</strong>\ () or <strong>sendfile</strong>\ () calls. The extreme
   * case would be a user calling <strong>sendmsg</strong>\ () repeatedly with
   * 1-byte long message segments. Obviously, this is bad for
   * performance, but it is still valid. If the eBPF program needs
   * <em>bytes</em> bytes to validate a header, this helper can be used to
   * prevent the eBPF program to be called again until <em>bytes</em> have
   * been accumulated.
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_msg_cork_bytes(Ptr<sk_msg_md> msg, @Unsigned int bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Will remove <em>len</em> bytes from a <em>msg</em> starting at byte <em>start</em>.
   * This may result in <strong>ENOMEM</strong> errors under certain situations if
   * an allocation and copy are required due to a full ring buffer.
   * However, the helper will try to avoid doing the allocation
   * if possible. Other errors can occur if input parameters are
   * invalid either due to <em>start</em> byte not being valid part of <em>msg</em>
   * payload and/or <em>pop</em> value being to large.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_msg_pop_data(Ptr<sk_msg_md> msg, @Unsigned int start, @Unsigned int len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For socket policies, pull in non-linear data from user space
   * for <em>msg</em> and set pointers <em>msg</em>\ <strong>-&gt;data</strong> and <em>msg</em><br />
   * <strong>-&gt;data_end</strong> to <em>start</em> and <em>end</em> bytes offsets into <em>msg</em>,
   * respectively.</p>
   * <p>If a program of type <strong>BPF_PROG_TYPE_SK_MSG</strong> is run on a
   * <em>msg</em> it can only parse data that the (<strong>data</strong>, <strong>data_end</strong>)
   * pointers have already consumed. For <strong>sendmsg</strong>\ () hooks this
   * is likely the first scatterlist element. But for calls relying
   * on the <strong>sendpage</strong> handler (e.g. <strong>sendfile</strong>\ ()) this will
   * be the range (<strong>0</strong>, <strong>0</strong>) because the data is shared with
   * user space and by default the objective is to avoid allowing
   * user space to modify data while (or after) eBPF verdict is
   * being decided. This helper can be used to pull in data and to
   * set the start and end pointer to given values. Data will be
   * copied if necessary (i.e. if data was not linear and if start
   * and end pointers do not point to the same chunk).</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.</p>
   * <p>All values for <em>flags</em> are reserved for future usage, and must
   * be left at zero.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_msg_pull_data(Ptr<sk_msg_md> msg, @Unsigned int start, @Unsigned int end,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For socket policies, insert <em>len</em> bytes into <em>msg</em> at offset
   * <em>start</em>.</p>
   * <p>If a program of type <strong>BPF_PROG_TYPE_SK_MSG</strong> is run on a
   * <em>msg</em> it may want to insert metadata or options into the <em>msg</em>.
   * This can later be read and used by any of the lower layer BPF
   * hooks.</p>
   * <p>This helper may fail if under memory pressure (a malloc
   * fails) in these cases BPF programs will get an appropriate
   * error and BPF programs will need to handle them.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_msg_push_data(Ptr<sk_msg_md> msg, @Unsigned int start, @Unsigned int len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is used in programs implementing policies at the
   * socket level. If the message <em>msg</em> is allowed to pass (i.e. if
   * the verdict eBPF program returns <strong>SK_PASS</strong>), redirect it to
   * the socket referenced by <em>map</em> (of type
   * <strong>BPF_MAP_TYPE_SOCKHASH</strong>) using hash <em>key</em>. Both ingress and
   * egress interfaces can be used for redirection. The
   * <strong>BPF_F_INGRESS</strong> value in <em>flags</em> is used to make the
   * distinction (ingress path is selected if the flag is present,
   * egress path otherwise). This is the only flag supported for now.
   * @return <strong>SK_PASS</strong> on success, or <strong>SK_DROP</strong> on error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_msg_redirect_hash(Ptr<sk_msg_md> msg, Ptr<?> map, Ptr<?> key,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is used in programs implementing policies at the
   * socket level. If the message <em>msg</em> is allowed to pass (i.e. if
   * the verdict eBPF program returns <strong>SK_PASS</strong>), redirect it to
   * the socket referenced by <em>map</em> (of type
   * <strong>BPF_MAP_TYPE_SOCKMAP</strong>) at index <em>key</em>. Both ingress and
   * egress interfaces can be used for redirection. The
   * <strong>BPF_F_INGRESS</strong> value in <em>flags</em> is used to make the
   * distinction (ingress path is selected if the flag is present,
   * egress path otherwise). This is the only flag supported for now.
   * @return <strong>SK_PASS</strong> on success, or <strong>SK_DROP</strong> on error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_msg_redirect_map(Ptr<sk_msg_md> msg, Ptr<?> map, @Unsigned int key,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Used for error injection, this helper uses kprobes to override
   * the return value of the probed function, and to set it to <em>rc</em>.
   * The first argument is the context <em>regs</em> on which the kprobe
   * works.</p>
   * <p>This helper works by setting the PC (program counter)
   * to an override function which is run in place of the original
   * probed function. This means the probed function is not run at
   * all. The replacement function just returns with the required
   * value.</p>
   * <p>This helper has security implications, and thus is subject to
   * restrictions. It is only available if the kernel was compiled
   * with the <strong>CONFIG_BPF_KPROBE_OVERRIDE</strong> configuration
   * option, and in this case it only works on functions tagged with
   * <strong>ALLOW_ERROR_INJECTION</strong> in the kernel code.</p>
   * <p>Also, the helper is only available for the architectures having
   * the CONFIG_FUNCTION_ERROR_INJECTION option. As of this writing,
   * x86 architecture is the only one to support this feature.
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_override_return(Ptr<pt_regs> regs, @Unsigned long rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Take a pointer to a percpu ksym, <em>percpu_ptr</em>, and return a
   * pointer to the percpu kernel variable on <em>cpu</em>. A ksym is an
   * extern variable decorated with '__ksym'. For ksym, there is a
   * global var (either static or global) defined of the same name
   * in the kernel. The ksym is percpu if the global var is percpu.
   * The returned pointer points to the global percpu var on <em>cpu</em>.</p>
   * <p>bpf_per_cpu_ptr() has the same semantic as per_cpu_ptr() in the
   * kernel, except that bpf_per_cpu_ptr() may return NULL. This
   * happens if <em>cpu</em> is larger than nr_cpu_ids. The caller of
   * bpf_per_cpu_ptr() must check the returned value.
   * @return A pointer pointing to the kernel percpu variable on <em>cpu</em>, or
   * NULL, if <em>cpu</em> is invalid.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_per_cpu_ptr((const void*)$arg1, $arg2)")
  public static Ptr<?> bpf_per_cpu_ptr(Ptr<?> percpu_ptr, @Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Write raw <em>data</em> blob into a special BPF perf event held by
   * <em>map</em> of type <strong>BPF_MAP_TYPE_PERF_EVENT_ARRAY</strong>. This perf
   * event must have the following attributes: <strong>PERF_SAMPLE_RAW</strong>
   * as <strong>sample_type</strong>, <strong>PERF_TYPE_SOFTWARE</strong> as <strong>type</strong>, and
   * <strong>PERF_COUNT_SW_BPF_OUTPUT</strong> as <strong>config</strong>.</p>
   * <p>The <em>flags</em> are used to indicate the index in <em>map</em> for which
   * the value must be put, masked with <strong>BPF_F_INDEX_MASK</strong>.
   * Alternatively, <em>flags</em> can be set to <strong>BPF_F_CURRENT_CPU</strong>
   * to indicate that the index of the current CPU core should be
   * used.</p>
   * <p>The value to write, of <em>size</em>, is passed through eBPF stack and
   * pointed by <em>data</em>.</p>
   * <p>The context of the program <em>ctx</em> needs also be passed to the
   * helper.</p>
   * <p>On user space, a program willing to read the values needs to
   * call <strong>perf_event_open</strong>\ () on the perf event (either for
   * one or for all CPUs) and to store the file descriptor into the
   * <em>map</em>. This must be done before the eBPF program can send data
   * into it. An example is available in file
   * <em>samples/bpf/trace_output_user.c</em> in the Linux kernel source
   * tree (the eBPF program counterpart is in
   * <em>samples/bpf/trace_output_kern.c</em>).</p>
   * <p><strong>bpf_perf_event_output</strong>\ () achieves better performance
   * than <strong>bpf_trace_printk</strong>\ () for sharing data with user
   * space, and is much better suitable for streaming data from eBPF
   * programs.</p>
   * <p>Note that this helper is not restricted to tracing use cases
   * and can be used with programs attached to TC or XDP as well,
   * where it allows for passing data to user space listeners. Data
   * can be:</p>
   * <ul>
   * <li>Only custom structs,</li>
   * <li>Only the packet payload, or</li>
   * <li>A combination of both.</li>
   * </ul>
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_perf_event_output(Ptr<?> ctx, Ptr<?> map, @Unsigned long flags,
      Ptr<?> data, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Read the value of a perf event counter. This helper relies on a
   * <em>map</em> of type <strong>BPF_MAP_TYPE_PERF_EVENT_ARRAY</strong>. The nature of
   * the perf event counter is selected when <em>map</em> is updated with
   * perf event file descriptors. The <em>map</em> is an array whose size
   * is the number of available CPUs, and each cell contains a value
   * relative to one CPU. The value to retrieve is indicated by
   * <em>flags</em>, that contains the index of the CPU to look up, masked
   * with <strong>BPF_F_INDEX_MASK</strong>. Alternatively, <em>flags</em> can be set to
   * <strong>BPF_F_CURRENT_CPU</strong> to indicate that the value for the
   * current CPU should be retrieved.</p>
   * <p>Note that before Linux 4.13, only hardware perf event can be
   * retrieved.</p>
   * <p>Also, be aware that the newer helper
   * <strong>bpf_perf_event_read_value</strong>\ () is recommended over
   * <strong>bpf_perf_event_read</strong>\ () in general. The latter has some ABI
   * quirks where error and counter value are used as a return code
   * (which is wrong to do since ranges may overlap). This issue is
   * fixed with <strong>bpf_perf_event_read_value</strong>\ (), which at the same
   * time provides more features over the <strong>bpf_perf_event_read</strong><br />
   * () interface. Please refer to the description of
   * <strong>bpf_perf_event_read_value</strong>\ () for details.
   * @return The value of the perf event counter read from the map, or a
   * negative error code in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_perf_event_read(Ptr<?> map, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Read the value of a perf event counter, and store it into <em>buf</em>
   * of size <em>buf_size</em>. This helper relies on a <em>map</em> of type
   * <strong>BPF_MAP_TYPE_PERF_EVENT_ARRAY</strong>. The nature of the perf event
   * counter is selected when <em>map</em> is updated with perf event file
   * descriptors. The <em>map</em> is an array whose size is the number of
   * available CPUs, and each cell contains a value relative to one
   * CPU. The value to retrieve is indicated by <em>flags</em>, that
   * contains the index of the CPU to look up, masked with
   * <strong>BPF_F_INDEX_MASK</strong>. Alternatively, <em>flags</em> can be set to
   * <strong>BPF_F_CURRENT_CPU</strong> to indicate that the value for the
   * current CPU should be retrieved.</p>
   * <p>This helper behaves in a way close to
   * <strong>bpf_perf_event_read</strong>\ () helper, save that instead of
   * just returning the value observed, it fills the <em>buf</em>
   * structure. This allows for additional data to be retrieved: in
   * particular, the enabled and running times (in <em>buf</em><br />
   * <strong>-&gt;enabled</strong> and <em>buf</em>\ <strong>-&gt;running</strong>, respectively) are
   * copied. In general, <strong>bpf_perf_event_read_value</strong>\ () is
   * recommended over <strong>bpf_perf_event_read</strong>\ (), which has some
   * ABI issues and provides fewer functionalities.</p>
   * <p>These values are interesting, because hardware PMU (Performance
   * Monitoring Unit) counters are limited resources. When there are
   * more PMU based perf events opened than available counters,
   * kernel will multiplex these events so each event gets certain
   * percentage (but not all) of the PMU time. In case that
   * multiplexing happens, the number of samples or counter value
   * will not reflect the case compared to when no multiplexing
   * occurs. This makes comparison between different runs difficult.
   * Typically, the counter value should be normalized before
   * comparing to other experiments. The usual normalization is done
   * as follows.</p>
   * <p>::</p>
   * <pre><code>normalized_counter = counter * t_enabled / t_running
   * </code></pre>
   * <p>Where t_enabled is the time enabled for event and t_running is
   * the time running for event since last normalization. The
   * enabled and running times are accumulated since the perf event
   * open. To achieve scaling factor between two invocations of an
   * eBPF program, users can use CPU id as the key (which is
   * typical for perf array usage model) to remember the previous
   * value and do the calculation inside the eBPF program.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_perf_event_read_value(Ptr<?> map, @Unsigned long flags,
      Ptr<bpf_perf_event_value> buf, @Unsigned int buf_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For an eBPF program attached to a perf event, retrieve the
   * value of the event counter associated to <em>ctx</em> and store it in
   * the structure pointed by <em>buf</em> and of size <em>buf_size</em>. Enabled
   * and running times are also stored in the structure (see
   * description of helper <strong>bpf_perf_event_read_value</strong>\ () for
   * more details).
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_perf_prog_read_value(Ptr<bpf_perf_event_data> ctx,
      Ptr<bpf_perf_event_value> buf, @Unsigned int buf_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For tracing programs, safely attempt to read <em>size</em> bytes from
   * kernel space address <em>unsafe_ptr</em> and store the data in <em>dst</em>.</p>
   * <p>Generally, use <strong>bpf_probe_read_user</strong>\ () or
   * <strong>bpf_probe_read_kernel</strong>\ () instead.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read($arg1, $arg2, (const void*)$arg3)")
  public static long bpf_probe_read(Ptr<?> dst, @Unsigned int size, Ptr<?> unsafe_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Safely attempt to read <em>size</em> bytes from kernel space address
   * <em>unsafe_ptr</em> and store the data in <em>dst</em>.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_kernel($arg1, $arg2, (const void*)$arg3)")
  public static long bpf_probe_read_kernel(Ptr<?> dst, @Unsigned int size, Ptr<?> unsafe_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Copy a NUL terminated string from an unsafe kernel address <em>unsafe_ptr</em>
   * to <em>dst</em>. Same semantics as with <strong>bpf_probe_read_user_str</strong>\ () apply.
   * @return On success, the strictly positive length of the string, including
   * the trailing NUL character. On error, a negative value.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, $arg2, (const void*)$arg3)")
  public static long bpf_probe_read_kernel_str(Ptr<?> dst, @Unsigned int size, Ptr<?> unsafe_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Copy a NUL terminated string from an unsafe kernel address
   * <em>unsafe_ptr</em> to <em>dst</em>. See <strong>bpf_probe_read_kernel_str</strong>\ () for
   * more details.</p>
   * <p>Generally, use <strong>bpf_probe_read_user_str</strong>\ () or
   * <strong>bpf_probe_read_kernel_str</strong>\ () instead.
   * @return On success, the strictly positive length of the string,
   * including the trailing NUL character. On error, a negative
   * value.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_str($arg1, $arg2, (const void*)$arg3)")
  public static long bpf_probe_read_str(Ptr<?> dst, @Unsigned int size, Ptr<?> unsafe_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Safely attempt to read <em>size</em> bytes from user space address
   * <em>unsafe_ptr</em> and store the data in <em>dst</em>.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_user($arg1, $arg2, (const void*)$arg3)")
  public static long bpf_probe_read_user(Ptr<?> dst, @Unsigned int size, Ptr<?> unsafe_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Copy a NUL terminated string from an unsafe user address
   * <em>unsafe_ptr</em> to <em>dst</em>. The <em>size</em> should include the
   * terminating NUL byte. In case the string length is smaller than
   * <em>size</em>, the target is not padded with further NUL bytes. If the
   * string length is larger than <em>size</em>, just <em>size</em>-1 bytes are
   * copied and the last byte is set to NUL.</p>
   * <p>On success, returns the number of bytes that were written,
   * including the terminal NUL. This makes this helper useful in
   * tracing programs for reading strings, and more importantly to
   * get its length at runtime. See the following snippet:</p>
   * <p>::</p>
   * <pre><code>SEC(&quot;kprobe/sys_open&quot;)
   * void bpf_sys_open(struct pt_regs *ctx)
   * {
   *         char buf[PATHLEN]; // PATHLEN is defined to 256
   *         int res = bpf_probe_read_user_str(buf, sizeof(buf),
   * 	                                  ctx-&gt;di);
   *
   * 	// Consume buf, for example push it to
   * 	// userspace via bpf_perf_event_output(); we
   * 	// can use res (the string length) as event
   * 	// size, after checking its boundaries.
   * }
   * </code></pre>
   * <p>In comparison, using <strong>bpf_probe_read_user</strong>\ () helper here
   * instead to read the string would require to estimate the length
   * at compile time, and would often result in copying more memory
   * than necessary.</p>
   * <p>Another useful use case is when parsing individual process
   * arguments or individual environment variables navigating
   * <em>current</em>\ <strong>-&gt;mm-&gt;arg_start</strong> and <em>current</em><br />
   * <strong>-&gt;mm-&gt;env_start</strong>: using this helper and the return value,
   * one can quickly iterate at the right offset of the memory area.
   * @return On success, the strictly positive length of the output string,
   * including the trailing NUL character. On error, a negative
   * value.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_user_str($arg1, $arg2, (const void*)$arg3)")
  public static long bpf_probe_read_user_str(Ptr<?> dst, @Unsigned int size, Ptr<?> unsafe_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Attempt in a safe way to write <em>len</em> bytes from the buffer
   * <em>src</em> to <em>dst</em> in memory. It only works for threads that are in
   * user context, and <em>dst</em> must be a valid user space address.</p>
   * <p>This helper should not be used to implement any kind of
   * security mechanism because of TOC-TOU attacks, but rather to
   * debug, divert, and manipulate execution of semi-cooperative
   * processes.</p>
   * <p>Keep in mind that this feature is meant for experiments, and it
   * has a risk of crashing the system and running programs.
   * Therefore, when an eBPF program using this helper is attached,
   * a warning including PID and process name is printed to kernel
   * logs.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_write_user($arg1, (const void*)$arg2, $arg3)")
  public static long bpf_probe_write_user(Ptr<?> dst, Ptr<?> src, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is used in programs implementing IR decoding, to
   * report a successfully decoded key press with <em>scancode</em>,
   * <em>toggle</em> value in the given <em>protocol</em>. The scancode will be
   * translated to a keycode using the rc keymap, and reported as
   * an input key down event. After a period a key up event is
   * generated. This period can be extended by calling either
   * <strong>bpf_rc_keydown</strong>\ () again with the same values, or calling
   * <strong>bpf_rc_repeat</strong>\ ().</p>
   * <p>Some protocols include a toggle bit, in case the button was
   * released and pressed again between consecutive scancodes.</p>
   * <p>The <em>ctx</em> should point to the lirc sample as passed into
   * the program.</p>
   * <p>The <em>protocol</em> is the decoded protocol number (see
   * <strong>enum rc_proto</strong> for some predefined values).</p>
   * <p>This helper is only available is the kernel was compiled with
   * the <strong>CONFIG_BPF_LIRC_MODE2</strong> configuration option set to
   * &quot;<strong>y</strong>&quot;.
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_rc_keydown(Ptr<?> ctx, @Unsigned int protocol, @Unsigned long scancode,
      @Unsigned int toggle) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is used in programs implementing IR decoding, to
   * report a successfully decoded pointer movement.</p>
   * <p>The <em>ctx</em> should point to the lirc sample as passed into
   * the program.</p>
   * <p>This helper is only available is the kernel was compiled with
   * the <strong>CONFIG_BPF_LIRC_MODE2</strong> configuration option set to
   * &quot;<strong>y</strong>&quot;.
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_rc_pointer_rel(Ptr<?> ctx, int rel_x, int rel_y) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is used in programs implementing IR decoding, to
   * report a successfully decoded repeat key message. This delays
   * the generation of a key up event for previously generated
   * key down event.</p>
   * <p>Some IR protocols like NEC have a special IR message for
   * repeating last button, for when a button is held down.</p>
   * <p>The <em>ctx</em> should point to the lirc sample as passed into
   * the program.</p>
   * <p>This helper is only available is the kernel was compiled with
   * the <strong>CONFIG_BPF_LIRC_MODE2</strong> configuration option set to
   * &quot;<strong>y</strong>&quot;.
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_rc_repeat(Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * For an eBPF program attached to a perf event, retrieve the
   * branch records (<strong>struct perf_branch_entry</strong>) associated to <em>ctx</em>
   * and store it in the buffer pointed by <em>buf</em> up to size
   * <em>size</em> bytes.
   * @return On success, number of bytes written to <em>buf</em>. On error, a
   * negative value.</p>
   * <p>The <em>flags</em> can be set to <strong>BPF_F_GET_BRANCH_RECORDS_SIZE</strong> to
   * instead return the number of bytes required to store all the
   * branch entries. If this flag is set, <em>buf</em> may be NULL.</p>
   * <p><strong>-EINVAL</strong> if arguments invalid or <strong>size</strong> not a multiple
   * of <strong>sizeof</strong>\ (<strong>struct perf_branch_entry</strong>\ ).</p>
   * <p><strong>-ENOENT</strong> if architecture does not support branch records.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_read_branch_records(Ptr<bpf_perf_event_data> ctx, Ptr<?> buf,
      @Unsigned int size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Redirect the packet to another net device of index <em>ifindex</em>.
   * This helper is somewhat similar to <strong>bpf_clone_redirect</strong><br />
   * (), except that the packet is not cloned, which provides
   * increased performance.</p>
   * <p>Except for XDP, both ingress and egress interfaces can be used
   * for redirection. The <strong>BPF_F_INGRESS</strong> value in <em>flags</em> is used
   * to make the distinction (ingress path is selected if the flag
   * is present, egress path otherwise). Currently, XDP only
   * supports redirection to the egress interface, and accepts no
   * flag at all.</p>
   * <p>The same effect can also be attained with the more generic
   * <strong>bpf_redirect_map</strong>\ (), which uses a BPF map to store the
   * redirect target instead of providing it directly to the helper.
   * @return For XDP, the helper returns <strong>XDP_REDIRECT</strong> on success or
   * <strong>XDP_ABORTED</strong> on error. For other program types, the values
   * are <strong>TC_ACT_REDIRECT</strong> on success or <strong>TC_ACT_SHOT</strong> on
   * error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_redirect(@Unsigned int ifindex, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Redirect the packet to the endpoint referenced by <em>map</em> at
   * index <em>key</em>. Depending on its type, this <em>map</em> can contain
   * references to net devices (for forwarding packets through other
   * ports), or to CPUs (for redirecting XDP frames to another CPU;
   * but this is only implemented for native XDP (with driver
   * support) as of this writing).</p>
   * <p>The lower two bits of <em>flags</em> are used as the return code if
   * the map lookup fails. This is so that the return value can be
   * one of the XDP program return codes up to <strong>XDP_TX</strong>, as chosen
   * by the caller. The higher bits of <em>flags</em> can be set to
   * BPF_F_BROADCAST or BPF_F_EXCLUDE_INGRESS as defined below.</p>
   * <p>With BPF_F_BROADCAST the packet will be broadcasted to all the
   * interfaces in the map, with BPF_F_EXCLUDE_INGRESS the ingress
   * interface will be excluded when do broadcasting.</p>
   * <p>See also <strong>bpf_redirect</strong>\ (), which only supports redirecting
   * to an ifindex, but doesn't require a map to do so.
   * @return <strong>XDP_REDIRECT</strong> on success, or the value of the two lower bits
   * of the <em>flags</em> argument on error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_redirect_map(Ptr<?> map, @Unsigned long key, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Redirect the packet to another net device of index <em>ifindex</em>
   * and fill in L2 addresses from neighboring subsystem. This helper
   * is somewhat similar to <strong>bpf_redirect</strong>\ (), except that it
   * populates L2 addresses as well, meaning, internally, the helper
   * relies on the neighbor lookup for the L2 address of the nexthop.</p>
   * <p>The helper will perform a FIB lookup based on the skb's
   * networking header to get the address of the next hop, unless
   * this is supplied by the caller in the <em>params</em> argument. The
   * <em>plen</em> argument indicates the len of <em>params</em> and should be set
   * to 0 if <em>params</em> is NULL.</p>
   * <p>The <em>flags</em> argument is reserved and must be 0. The helper is
   * currently only supported for tc BPF program types, and enabled
   * for IPv4 and IPv6 protocols.
   * @return The helper returns <strong>TC_ACT_REDIRECT</strong> on success or
   * <strong>TC_ACT_SHOT</strong> on error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_redirect_neigh(@Unsigned int ifindex, Ptr<bpf_redir_neigh> params,
      int plen, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Redirect the packet to another net device of index <em>ifindex</em>.
   * This helper is somewhat similar to <strong>bpf_redirect</strong>\ (), except
   * that the redirection happens to the <em>ifindex</em>' peer device and
   * the netns switch takes place from ingress to ingress without
   * going through the CPU's backlog queue.</p>
   * <p>The <em>flags</em> argument is reserved and must be 0. The helper is
   * currently only supported for tc BPF program types at the
   * ingress hook and for veth and netkit target device types. The
   * peer device must reside in a different network namespace.
   * @return The helper returns <strong>TC_ACT_REDIRECT</strong> on success or
   * <strong>TC_ACT_SHOT</strong> on error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_redirect_peer(@Unsigned int ifindex, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Reserve <em>len</em> bytes for the bpf header option.  The
   * space will be used by <strong>bpf_store_hdr_opt</strong>\ () later in
   * <strong>BPF_SOCK_OPS_WRITE_HDR_OPT_CB</strong>.</p>
   * <p>If <strong>bpf_reserve_hdr_opt</strong>\ () is called multiple times,
   * the total number of bytes will be reserved.</p>
   * <p>This helper can only be called during
   * <strong>BPF_SOCK_OPS_HDR_OPT_LEN_CB</strong>.
   * @return 0 on success, or negative error in case of failure:</p>
   * <p><strong>-EINVAL</strong> if a parameter is invalid.</p>
   * <p><strong>-ENOSPC</strong> if there is not enough space in the header.</p>
   * <p><strong>-EPERM</strong> if the helper cannot be used under the current
   * <em>skops</em>\ <strong>-&gt;op</strong>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_reserve_hdr_opt(Ptr<bpf_sock_ops> skops, @Unsigned int len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Discard reserved ring buffer sample, pointed to by <em>data</em>.
   * If <strong>BPF_RB_NO_WAKEUP</strong> is specified in <em>flags</em>, no notification
   * of new data availability is sent.
   * If <strong>BPF_RB_FORCE_WAKEUP</strong> is specified in <em>flags</em>, notification
   * of new data availability is sent unconditionally.
   * If <strong>0</strong> is specified in <em>flags</em>, an adaptive notification
   * of new data availability is sent.</p>
   * <p>See 'bpf_ringbuf_output()' for the definition of adaptive notification.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ringbuf_discard(Ptr<?> data, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Discard reserved ring buffer sample through the dynptr
   * interface. This is a no-op if the dynptr is invalid/null.</p>
   * <p>For more information on <em>flags</em>, please see
   * 'bpf_ringbuf_discard'.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ringbuf_discard_dynptr(Ptr<bpf_dynptr> ptr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Copy <em>size</em> bytes from <em>data</em> into a ring buffer <em>ringbuf</em>.
   * If <strong>BPF_RB_NO_WAKEUP</strong> is specified in <em>flags</em>, no notification
   * of new data availability is sent.
   * If <strong>BPF_RB_FORCE_WAKEUP</strong> is specified in <em>flags</em>, notification
   * of new data availability is sent unconditionally.
   * If <strong>0</strong> is specified in <em>flags</em>, an adaptive notification
   * of new data availability is sent.</p>
   * <p>An adaptive notification is a notification sent whenever the user-space
   * process has caught up and consumed all available payloads. In case the user-space
   * process is still processing a previous payload, then no notification is needed
   * as it will process the newly added payload automatically.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_ringbuf_output(Ptr<?> ringbuf, Ptr<?> data, @Unsigned long size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Query various characteristics of provided ring buffer. What
   * exactly is queries is determined by <em>flags</em>:</p>
   * <ul>
   * <li><strong>BPF_RB_AVAIL_DATA</strong>: Amount of data not yet consumed.</li>
   * <li><strong>BPF_RB_RING_SIZE</strong>: The size of ring buffer.</li>
   * <li><strong>BPF_RB_CONS_POS</strong>: Consumer position (can wrap around).</li>
   * <li><strong>BPF_RB_PROD_POS</strong>: Producer(s) position (can wrap around).</li>
   * </ul>
   * <p>Data returned is just a momentary snapshot of actual values
   * and could be inaccurate, so this facility should be used to
   * power heuristics and for reporting, not to make 100% correct
   * calculation.
   * @return Requested value, or 0, if <em>flags</em> are not recognized.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_query(Ptr<?> ringbuf, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Reserve <em>size</em> bytes of payload in a ring buffer <em>ringbuf</em>.
   * <em>flags</em> must be 0.
   * @return Valid pointer with <em>size</em> bytes of memory available; NULL,
   * otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_ringbuf_reserve(Ptr<?> ringbuf, @Unsigned long size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Reserve <em>size</em> bytes of payload in a ring buffer <em>ringbuf</em>
   * through the dynptr interface. <em>flags</em> must be 0.</p>
   * <p>Please note that a corresponding bpf_ringbuf_submit_dynptr or
   * bpf_ringbuf_discard_dynptr must be called on <em>ptr</em>, even if the
   * reservation fails. This is enforced by the verifier.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_ringbuf_reserve_dynptr(Ptr<?> ringbuf, @Unsigned int size,
      @Unsigned long flags, Ptr<bpf_dynptr> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Submit reserved ring buffer sample, pointed to by <em>data</em>.
   * If <strong>BPF_RB_NO_WAKEUP</strong> is specified in <em>flags</em>, no notification
   * of new data availability is sent.
   * If <strong>BPF_RB_FORCE_WAKEUP</strong> is specified in <em>flags</em>, notification
   * of new data availability is sent unconditionally.
   * If <strong>0</strong> is specified in <em>flags</em>, an adaptive notification
   * of new data availability is sent.</p>
   * <p>See 'bpf_ringbuf_output()' for the definition of adaptive notification.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ringbuf_submit(Ptr<?> data, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Submit reserved ring buffer sample, pointed to by <em>data</em>,
   * through the dynptr interface. This is a no-op if the dynptr is
   * invalid/null.</p>
   * <p>For more information on <em>flags</em>, please see
   * 'bpf_ringbuf_submit'.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ringbuf_submit_dynptr(Ptr<bpf_dynptr> ptr, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Send signal <em>sig</em> to the process of the current task.
   * The signal may be delivered to any of this process's threads.
   * @return 0 on success or successfully queued.</p>
   * <p><strong>-EBUSY</strong> if work queue under nmi is full.</p>
   * <p><strong>-EINVAL</strong> if <em>sig</em> is invalid.</p>
   * <p><strong>-EPERM</strong> if no permission to send the <em>sig</em>.</p>
   * <p><strong>-EAGAIN</strong> if bpf program can try again.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_send_signal(@Unsigned int sig) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Send signal <em>sig</em> to the thread corresponding to the current task.
   * @return 0 on success or successfully queued.</p>
   * <p><strong>-EBUSY</strong> if work queue under nmi is full.</p>
   * <p><strong>-EINVAL</strong> if <em>sig</em> is invalid.</p>
   * <p><strong>-EPERM</strong> if no permission to send the <em>sig</em>.</p>
   * <p><strong>-EAGAIN</strong> if bpf program can try again.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_send_signal_thread(@Unsigned int sig) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <strong>bpf_seq_printf</strong>\ () uses seq_file <strong>seq_printf</strong>\ () to print
   * out the format string.
   * The <em>m</em> represents the seq_file. The <em>fmt</em> and <em>fmt_size</em> are for
   * the format string itself. The <em>data</em> and <em>data_len</em> are format string
   * arguments. The <em>data</em> are a <strong>u64</strong> array and corresponding format string
   * values are stored in the array. For strings and pointers where pointees
   * are accessed, only the pointer values are stored in the <em>data</em> array.
   * The <em>data_len</em> is the size of <em>data</em> in bytes - must be a multiple of 8.</p>
   * <p>Formats <strong>%s</strong>, <strong>%p{i,I}{4,6}</strong> requires to read kernel memory.
   * Reading kernel memory may fail due to either invalid address or
   * valid address but requiring a major memory fault. If reading kernel memory
   * fails, the string for <strong>%s</strong> will be an empty string, and the ip
   * address for <strong>%p{i,I}{4,6}</strong> will be 0. Not returning error to
   * bpf program is consistent with what <strong>bpf_trace_printk</strong>\ () does for now.
   * @return 0 on success, or a negative error in case of failure:</p>
   * <p><strong>-EBUSY</strong> if per-CPU memory copy buffer is busy, can try again
   * by returning 1 from bpf program.</p>
   * <p><strong>-EINVAL</strong> if arguments are invalid, or if <em>fmt</em> is invalid/unsupported.</p>
   * <p><strong>-E2BIG</strong> if <em>fmt</em> contains too many format specifiers.</p>
   * <p><strong>-EOVERFLOW</strong> if an overflow happened: The same object will be tried again.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_seq_printf($arg1, (const u8 *)$arg2, $arg3, (const void *)$arg4, $arg5)")
  public static long bpf_seq_printf(Ptr<seq_file> m, String fmt, @Unsigned int fmt_size,
      Ptr<?> data, @Unsigned int data_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Use BTF to write to seq_write a string representation of
   * <em>ptr</em>-&gt;ptr, using <em>ptr</em>-&gt;type_id as per bpf_snprintf_btf().
   * <em>flags</em> are identical to those used for bpf_snprintf_btf.
   * @return 0 on success or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_seq_printf_btf(Ptr<seq_file> m, Ptr<btf_ptr> ptr, @Unsigned int ptr_size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <strong>bpf_seq_write</strong>\ () uses seq_file <strong>seq_write</strong>\ () to write the data.
   * The <em>m</em> represents the seq_file. The <em>data</em> and <em>len</em> represent the
   * data to write in bytes.
   * @return 0 on success, or a negative error in case of failure:</p>
   * <p><strong>-EOVERFLOW</strong> if an overflow happened: The same object will be tried again.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_seq_write($arg1, (const void*)$arg2, $arg3)")
  public static long bpf_seq_write(Ptr<seq_file> m, Ptr<?> data, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Set the full hash for <em>skb</em> (set the field <em>skb</em>\ <strong>-&gt;hash</strong>)
   * to value <em>hash</em>.
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_set_hash(Ptr<__sk_buff> skb, @Unsigned int hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Invalidate the current <em>skb</em>\ <strong>-&gt;hash</strong>. It can be used after
   * mangling on headers through direct packet access, in order to
   * indicate that the hash is outdated and to trigger a
   * recalculation the next time the kernel tries to access this
   * hash or when the <strong>bpf_get_hash_recalc</strong>\ () helper is called.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_set_hash_invalid(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Set the BPF program's return value that will be returned to the upper layers.</p>
   * <p>This helper is currently supported by cgroup programs and only by the hooks
   * where BPF program's return value is returned to the userspace via errno.</p>
   * <p>Note that there is the following corner case where the program exports an error
   * via bpf_set_retval but signals success via 'return 1':</p>
   * <pre><code>bpf_set_retval(-EPERM);
   * return 1;
   * </code></pre>
   * <p>In this case, the BPF program's return value will use helper's -EPERM. This
   * still holds true for cgroup/bind{4,6} which supports extra 'return 3' success case.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_set_retval(int retval) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Emulate a call to <strong>setsockopt()</strong> on the socket associated to
   * <em>bpf_socket</em>, which must be a full socket. The <em>level</em> at
   * which the option resides and the name <em>optname</em> of the option
   * must be specified, see <strong>setsockopt(2)</strong> for more information.
   * The option value of length <em>optlen</em> is pointed by <em>optval</em>.</p>
   * <p><em>bpf_socket</em> should be one of the following:</p>
   * <ul>
   * <li><strong>struct bpf_sock_ops</strong> for <strong>BPF_PROG_TYPE_SOCK_OPS</strong>.</li>
   * <li><strong>struct bpf_sock_addr</strong> for <strong>BPF_CGROUP_INET4_CONNECT</strong>,
   * <strong>BPF_CGROUP_INET6_CONNECT</strong> and <strong>BPF_CGROUP_UNIX_CONNECT</strong>.</li>
   * </ul>
   * <p>This helper actually implements a subset of <strong>setsockopt()</strong>.
   * It supports the following <em>level</em>\ s:</p>
   * <ul>
   * <li><strong>SOL_SOCKET</strong>, which supports the following <em>optname</em>\ s:
   * <strong>SO_RCVBUF</strong>, <strong>SO_SNDBUF</strong>, <strong>SO_MAX_PACING_RATE</strong>,
   * <strong>SO_PRIORITY</strong>, <strong>SO_RCVLOWAT</strong>, <strong>SO_MARK</strong>,
   * <strong>SO_BINDTODEVICE</strong>, <strong>SO_KEEPALIVE</strong>, <strong>SO_REUSEADDR</strong>,
   * <strong>SO_REUSEPORT</strong>, <strong>SO_BINDTOIFINDEX</strong>, <strong>SO_TXREHASH</strong>.</li>
   * <li><strong>IPPROTO_TCP</strong>, which supports the following <em>optname</em>\ s:
   * <strong>TCP_CONGESTION</strong>, <strong>TCP_BPF_IW</strong>,
   * <strong>TCP_BPF_SNDCWND_CLAMP</strong>, <strong>TCP_SAVE_SYN</strong>,
   * <strong>TCP_KEEPIDLE</strong>, <strong>TCP_KEEPINTVL</strong>, <strong>TCP_KEEPCNT</strong>,
   * <strong>TCP_SYNCNT</strong>, <strong>TCP_USER_TIMEOUT</strong>, <strong>TCP_NOTSENT_LOWAT</strong>,
   * <strong>TCP_NODELAY</strong>, <strong>TCP_MAXSEG</strong>, <strong>TCP_WINDOW_CLAMP</strong>,
   * <strong>TCP_THIN_LINEAR_TIMEOUTS</strong>, <strong>TCP_BPF_DELACK_MAX</strong>,
   * <strong>TCP_BPF_RTO_MIN</strong>.</li>
   * <li><strong>IPPROTO_IP</strong>, which supports <em>optname</em> <strong>IP_TOS</strong>.</li>
   * <li><strong>IPPROTO_IPV6</strong>, which supports the following <em>optname</em>\ s:
   * <strong>IPV6_TCLASS</strong>, <strong>IPV6_AUTOFLOWLABEL</strong>.</li>
   * </ul>
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_setsockopt(Ptr<?> bpf_socket, int level, int optname, Ptr<?> optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return id of cgroup v2 that is ancestor of cgroup associated
   * with the <em>sk</em> at the <em>ancestor_level</em>.  The root cgroup is at
   * <em>ancestor_level</em> zero and each step down the hierarchy
   * increments the level. If <em>ancestor_level</em> == level of cgroup
   * associated with <em>sk</em>, then return value will be same as that
   * of <strong>bpf_sk_cgroup_id</strong>\ ().</p>
   * <p>The helper is useful to implement policies based on cgroups
   * that are upper in hierarchy than immediate cgroup associated
   * with <em>sk</em>.</p>
   * <p>The format of returned id and helper limitations are same as in
   * <strong>bpf_sk_cgroup_id</strong>\ ().
   * @return The id is returned or 0 in case the id could not be retrieved.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_ancestor_cgroup_id(Ptr<?> sk, int ancestor_level) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Helper is overloaded depending on BPF program type. This
   * description applies to <strong>BPF_PROG_TYPE_SCHED_CLS</strong> and
   * <strong>BPF_PROG_TYPE_SCHED_ACT</strong> programs.</p>
   * <p>Assign the <em>sk</em> to the <em>skb</em>. When combined with appropriate
   * routing configuration to receive the packet towards the socket,
   * will cause <em>skb</em> to be delivered to the specified socket.
   * Subsequent redirection of <em>skb</em> via  <strong>bpf_redirect</strong>\ (),
   * <strong>bpf_clone_redirect</strong>\ () or other methods outside of BPF may
   * interfere with successful delivery to the socket.</p>
   * <p>This operation is only valid from TC ingress path.</p>
   * <p>The <em>flags</em> argument must be zero.
   * @return 0 on success, or a negative error in case of failure:</p>
   * <p><strong>-EINVAL</strong> if specified <em>flags</em> are not supported.</p>
   * <p><strong>-ENOENT</strong> if the socket is unavailable for assignment.</p>
   * <p><strong>-ENETUNREACH</strong> if the socket is unreachable (wrong netns).</p>
   * <p><strong>-EOPNOTSUPP</strong> if the operation is not supported, for example
   * a call from outside of TC ingress.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sk_assign(Ptr<?> ctx, Ptr<?> sk, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return the cgroup v2 id of the socket <em>sk</em>.</p>
   * <p><em>sk</em> must be a non-<strong>NULL</strong> pointer to a socket, e.g. one
   * returned from <strong>bpf_sk_lookup_xxx</strong>\ (),
   * <strong>bpf_sk_fullsock</strong>\ (), etc. The format of returned id is
   * same as in <strong>bpf_skb_cgroup_id</strong>\ ().</p>
   * <p>This helper is available only if the kernel was compiled with
   * the <strong>CONFIG_SOCK_CGROUP_DATA</strong> configuration option.
   * @return The id is returned or 0 in case the id could not be retrieved.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_cgroup_id(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper gets a <strong>struct bpf_sock</strong> pointer such
   * that all the fields in this <strong>bpf_sock</strong> can be accessed.
   * @return A <strong>struct bpf_sock</strong> pointer on success, or <strong>NULL</strong> in
   * case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_sock> bpf_sk_fullsock(Ptr<bpf_sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Look for TCP socket matching <em>tuple</em>, optionally in a child
   * network namespace <em>netns</em>. The return value must be checked,
   * and if non-<strong>NULL</strong>, released via <strong>bpf_sk_release</strong>\ ().</p>
   * <p>The <em>ctx</em> should point to the context of the program, such as
   * the skb or socket (depending on the hook in use). This is used
   * to determine the base network namespace for the lookup.</p>
   * <p><em>tuple_size</em> must be one of:</p>
   * <p><strong>sizeof</strong>\ (<em>tuple</em>\ <strong>-&gt;ipv4</strong>)
   * Look for an IPv4 socket.
   * <strong>sizeof</strong>\ (<em>tuple</em>\ <strong>-&gt;ipv6</strong>)
   * Look for an IPv6 socket.</p>
   * <p>If the <em>netns</em> is a negative signed 32-bit integer, then the
   * socket lookup table in the netns associated with the <em>ctx</em>
   * will be used. For the TC hooks, this is the netns of the device
   * in the skb. For socket hooks, this is the netns of the socket.
   * If <em>netns</em> is any other signed 32-bit value greater than or
   * equal to zero then it specifies the ID of the netns relative to
   * the netns associated with the <em>ctx</em>. <em>netns</em> values beyond the
   * range of 32-bit integers are reserved for future use.</p>
   * <p>All values for <em>flags</em> are reserved for future usage, and must
   * be left at zero.</p>
   * <p>This helper is available only if the kernel was compiled with
   * <strong>CONFIG_NET</strong> configuration option.
   * @return Pointer to <strong>struct bpf_sock</strong>, or <strong>NULL</strong> in case of failure.
   * For sockets with reuseport option, the <strong>struct bpf_sock</strong>
   * result is from <em>reuse</em>\ <strong>-&gt;socks</strong>\ [] using the hash of the
   * tuple.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_sock> bpf_sk_lookup_tcp(Ptr<?> ctx, Ptr<bpf_sock_tuple> tuple,
      @Unsigned int tuple_size, @Unsigned long netns, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Look for UDP socket matching <em>tuple</em>, optionally in a child
   * network namespace <em>netns</em>. The return value must be checked,
   * and if non-<strong>NULL</strong>, released via <strong>bpf_sk_release</strong>\ ().</p>
   * <p>The <em>ctx</em> should point to the context of the program, such as
   * the skb or socket (depending on the hook in use). This is used
   * to determine the base network namespace for the lookup.</p>
   * <p><em>tuple_size</em> must be one of:</p>
   * <p><strong>sizeof</strong>\ (<em>tuple</em>\ <strong>-&gt;ipv4</strong>)
   * Look for an IPv4 socket.
   * <strong>sizeof</strong>\ (<em>tuple</em>\ <strong>-&gt;ipv6</strong>)
   * Look for an IPv6 socket.</p>
   * <p>If the <em>netns</em> is a negative signed 32-bit integer, then the
   * socket lookup table in the netns associated with the <em>ctx</em>
   * will be used. For the TC hooks, this is the netns of the device
   * in the skb. For socket hooks, this is the netns of the socket.
   * If <em>netns</em> is any other signed 32-bit value greater than or
   * equal to zero then it specifies the ID of the netns relative to
   * the netns associated with the <em>ctx</em>. <em>netns</em> values beyond the
   * range of 32-bit integers are reserved for future use.</p>
   * <p>All values for <em>flags</em> are reserved for future usage, and must
   * be left at zero.</p>
   * <p>This helper is available only if the kernel was compiled with
   * <strong>CONFIG_NET</strong> configuration option.
   * @return Pointer to <strong>struct bpf_sock</strong>, or <strong>NULL</strong> in case of failure.
   * For sockets with reuseport option, the <strong>struct bpf_sock</strong>
   * result is from <em>reuse</em>\ <strong>-&gt;socks</strong>\ [] using the hash of the
   * tuple.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_sock> bpf_sk_lookup_udp(Ptr<?> ctx, Ptr<bpf_sock_tuple> tuple,
      @Unsigned int tuple_size, @Unsigned long netns, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is used in programs implementing policies at the
   * skb socket level. If the sk_buff <em>skb</em> is allowed to pass (i.e.
   * if the verdict eBPF program returns <strong>SK_PASS</strong>), redirect it
   * to the socket referenced by <em>map</em> (of type
   * <strong>BPF_MAP_TYPE_SOCKHASH</strong>) using hash <em>key</em>. Both ingress and
   * egress interfaces can be used for redirection. The
   * <strong>BPF_F_INGRESS</strong> value in <em>flags</em> is used to make the
   * distinction (ingress path is selected if the flag is present,
   * egress otherwise). This is the only flag supported for now.
   * @return <strong>SK_PASS</strong> on success, or <strong>SK_DROP</strong> on error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sk_redirect_hash(Ptr<__sk_buff> skb, Ptr<?> map, Ptr<?> key,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Redirect the packet to the socket referenced by <em>map</em> (of type
   * <strong>BPF_MAP_TYPE_SOCKMAP</strong>) at index <em>key</em>. Both ingress and
   * egress interfaces can be used for redirection. The
   * <strong>BPF_F_INGRESS</strong> value in <em>flags</em> is used to make the
   * distinction (ingress path is selected if the flag is present,
   * egress path otherwise). This is the only flag supported for now.
   * @return <strong>SK_PASS</strong> on success, or <strong>SK_DROP</strong> on error.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sk_redirect_map(Ptr<__sk_buff> skb, Ptr<?> map, @Unsigned int key,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Release the reference held by <em>sock</em>. <em>sock</em> must be a
   * non-<strong>NULL</strong> pointer that was returned from
   * <strong>bpf_sk_lookup_xxx</strong>\ ().
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sk_release(Ptr<?> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Select a <strong>SO_REUSEPORT</strong> socket from a
   * <strong>BPF_MAP_TYPE_REUSEPORT_SOCKARRAY</strong> <em>map</em>.
   * It checks the selected socket is matching the incoming
   * request in the socket buffer.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sk_select_reuseport(Ptr<sk_reuseport_md> reuse, Ptr<?> map, Ptr<?> key,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Delete a bpf-local-storage from a <em>sk</em>.
   * @return 0 on success.</p>
   * <p><strong>-ENOENT</strong> if the bpf-local-storage cannot be found.
   * <strong>-EINVAL</strong> if sk is not a fullsock (e.g. a request_sock).
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sk_storage_delete(Ptr<?> map, Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get a bpf-local-storage from a <em>sk</em>.</p>
   * <p>Logically, it could be thought of getting the value from
   * a <em>map</em> with <em>sk</em> as the <strong>key</strong>.  From this
   * perspective,  the usage is not much different from
   * <strong>bpf_map_lookup_elem</strong>\ (<em>map</em>, <strong>&amp;</strong>\ <em>sk</em>) except this
   * helper enforces the key must be a full socket and the map must
   * be a <strong>BPF_MAP_TYPE_SK_STORAGE</strong> also.</p>
   * <p>Underneath, the value is stored locally at <em>sk</em> instead of
   * the <em>map</em>.  The <em>map</em> is used as the bpf-local-storage
   * &quot;type&quot;. The bpf-local-storage &quot;type&quot; (i.e. the <em>map</em>) is
   * searched against all bpf-local-storages residing at <em>sk</em>.</p>
   * <p><em>sk</em> is a kernel <strong>struct sock</strong> pointer for LSM program.
   * <em>sk</em> is a <strong>struct bpf_sock</strong> pointer for other program types.</p>
   * <p>An optional <em>flags</em> (<strong>BPF_SK_STORAGE_GET_F_CREATE</strong>) can be
   * used such that a new bpf-local-storage will be
   * created if one does not exist.  <em>value</em> can be used
   * together with <strong>BPF_SK_STORAGE_GET_F_CREATE</strong> to specify
   * the initial value of a bpf-local-storage.  If <em>value</em> is
   * <strong>NULL</strong>, the new bpf-local-storage will be zero initialized.
   * @return A bpf-local-storage pointer is returned on success.</p>
   * <p><strong>NULL</strong> if not found or there was an error in adding
   * a new bpf-local-storage.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_sk_storage_get(Ptr<?> map, Ptr<?> sk, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Grow or shrink the room for data in the packet associated to
   * <em>skb</em> by <em>len_diff</em>, and according to the selected <em>mode</em>.</p>
   * <p>By default, the helper will reset any offloaded checksum
   * indicator of the skb to CHECKSUM_NONE. This can be avoided
   * by the following flag:</p>
   * <ul>
   * <li><strong>BPF_F_ADJ_ROOM_NO_CSUM_RESET</strong>: Do not reset offloaded
   * checksum data of the skb to CHECKSUM_NONE.</li>
   * </ul>
   * <p>There are two supported modes at this time:</p>
   * <ul>
   * <li>
   * <p><strong>BPF_ADJ_ROOM_MAC</strong>: Adjust room at the mac layer
   * (room space is added or removed between the layer 2 and
   * layer 3 headers).</p>
   * </li>
   * <li>
   * <p><strong>BPF_ADJ_ROOM_NET</strong>: Adjust room at the network layer
   * (room space is added or removed between the layer 3 and
   * layer 4 headers).</p>
   * </li>
   * </ul>
   * <p>The following flags are supported at this time:</p>
   * <ul>
   * <li>
   * <p><strong>BPF_F_ADJ_ROOM_FIXED_GSO</strong>: Do not adjust gso_size.
   * Adjusting mss in this way is not allowed for datagrams.</p>
   * </li>
   * <li>
   * <p><strong>BPF_F_ADJ_ROOM_ENCAP_L3_IPV4</strong>,
   * <strong>BPF_F_ADJ_ROOM_ENCAP_L3_IPV6</strong>:
   * Any new space is reserved to hold a tunnel header.
   * Configure skb offsets and other fields accordingly.</p>
   * </li>
   * <li>
   * <p><strong>BPF_F_ADJ_ROOM_ENCAP_L4_GRE</strong>,
   * <strong>BPF_F_ADJ_ROOM_ENCAP_L4_UDP</strong>:
   * Use with ENCAP_L3 flags to further specify the tunnel type.</p>
   * </li>
   * <li>
   * <p><strong>BPF_F_ADJ_ROOM_ENCAP_L2</strong>\ (<em>len</em>):
   * Use with ENCAP_L3/L4 flags to further specify the tunnel
   * type; <em>len</em> is the length of the inner MAC header.</p>
   * </li>
   * <li>
   * <p><strong>BPF_F_ADJ_ROOM_ENCAP_L2_ETH</strong>:
   * Use with BPF_F_ADJ_ROOM_ENCAP_L2 flag to further specify the
   * L2 type as Ethernet.</p>
   * </li>
   * <li>
   * <p><strong>BPF_F_ADJ_ROOM_DECAP_L3_IPV4</strong>,
   * <strong>BPF_F_ADJ_ROOM_DECAP_L3_IPV6</strong>:
   * Indicate the new IP header version after decapsulating the outer
   * IP header. Used when the inner and outer IP versions are different.</p>
   * </li>
   * </ul>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_adjust_room(Ptr<__sk_buff> skb, int len_diff, @Unsigned int mode,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return id of cgroup v2 that is ancestor of cgroup associated
   * with the <em>skb</em> at the <em>ancestor_level</em>.  The root cgroup is at
   * <em>ancestor_level</em> zero and each step down the hierarchy
   * increments the level. If <em>ancestor_level</em> == level of cgroup
   * associated with <em>skb</em>, then return value will be same as that
   * of <strong>bpf_skb_cgroup_id</strong>\ ().</p>
   * <p>The helper is useful to implement policies based on cgroups
   * that are upper in hierarchy than immediate cgroup associated
   * with <em>skb</em>.</p>
   * <p>The format of returned id and helper limitations are same as in
   * <strong>bpf_skb_cgroup_id</strong>\ ().
   * @return The id is returned or 0 in case the id could not be retrieved.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_ancestor_cgroup_id(Ptr<__sk_buff> skb, int ancestor_level) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * See <strong>bpf_get_cgroup_classid</strong>\ () for the main description.
   * This helper differs from <strong>bpf_get_cgroup_classid</strong>\ () in that
   * the cgroup v1 net_cls class is retrieved only from the <em>skb</em>'s
   * associated socket instead of the current process.
   * @return The id is returned or 0 in case the id could not be retrieved.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_cgroup_classid(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Return the cgroup v2 id of the socket associated with the <em>skb</em>.
   * This is roughly similar to the <strong>bpf_get_cgroup_classid</strong>\ ()
   * helper for cgroup v1 by providing a tag resp. identifier that
   * can be matched on or used for map lookups e.g. to implement
   * policy. The cgroup v2 id of a given path in the hierarchy is
   * exposed in user space through the f_handle API in order to get
   * to the same 64-bit id.</p>
   * <p>This helper can be used on TC egress path, but not on ingress,
   * and is available only if the kernel was compiled with the
   * <strong>CONFIG_SOCK_CGROUP_DATA</strong> configuration option.
   * @return The id is returned or 0 in case the id could not be retrieved.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_cgroup_id(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Grows headroom of packet associated to <em>skb</em> and adjusts the
   * offset of the MAC header accordingly, adding <em>len</em> bytes of
   * space. It automatically extends and reallocates memory as
   * required.</p>
   * <p>This helper can be used on a layer 3 <em>skb</em> to push a MAC header
   * for redirection into a layer 2 device.</p>
   * <p>All values for <em>flags</em> are reserved for future usage, and must
   * be left at zero.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_change_head(Ptr<__sk_buff> skb, @Unsigned int len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Change the protocol of the <em>skb</em> to <em>proto</em>. Currently
   * supported are transition from IPv4 to IPv6, and from IPv6 to
   * IPv4. The helper takes care of the groundwork for the
   * transition, including resizing the socket buffer. The eBPF
   * program is expected to fill the new headers, if any, via
   * <strong>skb_store_bytes</strong>\ () and to recompute the checksums with
   * <strong>bpf_l3_csum_replace</strong>\ () and <strong>bpf_l4_csum_replace</strong><br />
   * (). The main case for this helper is to perform NAT64
   * operations out of an eBPF program.</p>
   * <p>Internally, the GSO type is marked as dodgy so that headers are
   * checked and segments are recalculated by the GSO/GRO engine.
   * The size for GSO target is adapted as well.</p>
   * <p>All values for <em>flags</em> are reserved for future usage, and must
   * be left at zero.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_change_proto(Ptr<__sk_buff> skb,
      @Unsigned @OriginalName("__be16") short proto, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Resize (trim or grow) the packet associated to <em>skb</em> to the
   * new <em>len</em>. The <em>flags</em> are reserved for future usage, and must
   * be left at zero.</p>
   * <p>The basic idea is that the helper performs the needed work to
   * change the size of the packet, then the eBPF program rewrites
   * the rest via helpers like <strong>bpf_skb_store_bytes</strong>\ (),
   * <strong>bpf_l3_csum_replace</strong>\ (), <strong>bpf_l3_csum_replace</strong>\ ()
   * and others. This helper is a slow path utility intended for
   * replies with control messages. And because it is targeted for
   * slow path, the helper itself can afford to be slow: it
   * implicitly linearizes, unclones and drops offloads from the
   * <em>skb</em>.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_change_tail(Ptr<__sk_buff> skb, @Unsigned int len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Change the packet type for the packet associated to <em>skb</em>. This
   * comes down to setting <em>skb</em>\ <strong>-&gt;pkt_type</strong> to <em>type</em>, except
   * the eBPF program does not have a write access to <em>skb</em><br />
   * <strong>-&gt;pkt_type</strong> beside this helper. Using a helper here allows
   * for graceful handling of errors.</p>
   * <p>The major use case is to change incoming <em>skb</em>s to
   * <strong>PACKET_HOST</strong> in a programmatic way instead of having to
   * recirculate via <strong>redirect</strong>\ (..., <strong>BPF_F_INGRESS</strong>), for
   * example.</p>
   * <p>Note that <em>type</em> only allows certain values. At this time, they
   * are:</p>
   * <p><strong>PACKET_HOST</strong>
   * Packet is for us.
   * <strong>PACKET_BROADCAST</strong>
   * Send packet to all.
   * <strong>PACKET_MULTICAST</strong>
   * Send packet to group.
   * <strong>PACKET_OTHERHOST</strong>
   * Send packet to someone else.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_change_type(Ptr<__sk_buff> skb, @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Set ECN (Explicit Congestion Notification) field of IP header
   * to <strong>CE</strong> (Congestion Encountered) if current value is <strong>ECT</strong>
   * (ECN Capable Transport). Otherwise, do nothing. Works with IPv6
   * and IPv4.
   * @return 1 if the <strong>CE</strong> flag is set (either by the current helper call
   * or because it was already present), 0 if it is not set.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_ecn_set_ce(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get tunnel metadata. This helper takes a pointer <em>key</em> to an
   * empty <strong>struct bpf_tunnel_key</strong> of <strong>size</strong>, that will be
   * filled with tunnel metadata for the packet associated to <em>skb</em>.
   * The <em>flags</em> can be set to <strong>BPF_F_TUNINFO_IPV6</strong>, which
   * indicates that the tunnel is based on IPv6 protocol instead of
   * IPv4.</p>
   * <p>The <strong>struct bpf_tunnel_key</strong> is an object that generalizes the
   * principal parameters used by various tunneling protocols into a
   * single struct. This way, it can be used to easily make a
   * decision based on the contents of the encapsulation header,
   * &quot;summarized&quot; in this struct. In particular, it holds the IP
   * address of the remote end (IPv4 or IPv6, depending on the case)
   * in <em>key</em>\ <strong>-&gt;remote_ipv4</strong> or <em>key</em>\ <strong>-&gt;remote_ipv6</strong>. Also,
   * this struct exposes the <em>key</em>\ <strong>-&gt;tunnel_id</strong>, which is
   * generally mapped to a VNI (Virtual Network Identifier), making
   * it programmable together with the <strong>bpf_skb_set_tunnel_key</strong><br />
   * () helper.</p>
   * <p>Let's imagine that the following code is part of a program
   * attached to the TC ingress interface, on one end of a GRE
   * tunnel, and is supposed to filter out all messages coming from
   * remote ends with IPv4 address other than 10.0.0.1:</p>
   * <p>::</p>
   * <pre><code>int ret;
   * struct bpf_tunnel_key key = {};
   *
   * ret = bpf_skb_get_tunnel_key(skb, &amp;key, sizeof(key), 0);
   * if (ret &lt; 0)
   * 	return TC_ACT_SHOT;	// drop packet
   *
   * if (key.remote_ipv4 != 0x0a000001)
   * 	return TC_ACT_SHOT;	// drop packet
   *
   * return TC_ACT_OK;		// accept packet
   * </code></pre>
   * <p>This interface can also be used with all encapsulation devices
   * that can operate in &quot;collect metadata&quot; mode: instead of having
   * one network device per specific configuration, the &quot;collect
   * metadata&quot; mode only requires a single device where the
   * configuration can be extracted from this helper.</p>
   * <p>This can be used together with various tunnels such as VXLan,
   * Geneve, GRE or IP in IP (IPIP).
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_get_tunnel_key(Ptr<__sk_buff> skb, Ptr<bpf_tunnel_key> key,
      @Unsigned int size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Retrieve tunnel options metadata for the packet associated to
   * <em>skb</em>, and store the raw tunnel option data to the buffer <em>opt</em>
   * of <em>size</em>.</p>
   * <p>This helper can be used with encapsulation devices that can
   * operate in &quot;collect metadata&quot; mode (please refer to the related
   * note in the description of <strong>bpf_skb_get_tunnel_key</strong>\ () for
   * more details). A particular example where this can be used is
   * in combination with the Geneve encapsulation protocol, where it
   * allows for pushing (with <strong>bpf_skb_get_tunnel_opt</strong>\ () helper)
   * and retrieving arbitrary TLVs (Type-Length-Value headers) from
   * the eBPF program. This allows for full customization of these
   * headers.
   * @return The size of the option data retrieved.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_get_tunnel_opt(Ptr<__sk_buff> skb, Ptr<?> opt, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Retrieve the XFRM state (IP transform framework, see also
   * <strong>ip-xfrm(8)</strong>) at <em>index</em> in XFRM &quot;security path&quot; for <em>skb</em>.</p>
   * <p>The retrieved value is stored in the <strong>struct bpf_xfrm_state</strong>
   * pointed by <em>xfrm_state</em> and of length <em>size</em>.</p>
   * <p>All values for <em>flags</em> are reserved for future usage, and must
   * be left at zero.</p>
   * <p>This helper is available only if the kernel was compiled with
   * <strong>CONFIG_XFRM</strong> configuration option.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_get_xfrm_state(Ptr<__sk_buff> skb, @Unsigned int index,
      Ptr<bpf_xfrm_state> xfrm_state, @Unsigned int size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper was provided as an easy way to load data from a
   * packet. It can be used to load <em>len</em> bytes from <em>offset</em> from
   * the packet associated to <em>skb</em>, into the buffer pointed by
   * <em>to</em>.</p>
   * <p>Since Linux 4.7, usage of this helper has mostly been replaced
   * by &quot;direct packet access&quot;, enabling packet data to be
   * manipulated with <em>skb</em>\ <strong>-&gt;data</strong> and <em>skb</em>\ <strong>-&gt;data_end</strong>
   * pointing respectively to the first byte of packet data and to
   * the byte after the last byte of packet data. However, it
   * remains useful if one wishes to read large quantities of data
   * at once from a packet into the eBPF stack.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_skb_load_bytes((const void*)$arg1, $arg2, $arg3, $arg4)")
  public static long bpf_skb_load_bytes(Ptr<?> skb, @Unsigned int offset, Ptr<?> to,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is similar to <strong>bpf_skb_load_bytes</strong>\ () in that
   * it provides an easy way to load <em>len</em> bytes from <em>offset</em>
   * from the packet associated to <em>skb</em>, into the buffer pointed
   * by <em>to</em>. The difference to <strong>bpf_skb_load_bytes</strong>\ () is that
   * a fifth argument <em>start_header</em> exists in order to select a
   * base offset to start from. <em>start_header</em> can be one of:</p>
   * <p><strong>BPF_HDR_START_MAC</strong>
   * Base offset to load data from is <em>skb</em>'s mac header.
   * <strong>BPF_HDR_START_NET</strong>
   * Base offset to load data from is <em>skb</em>'s network header.</p>
   * <p>In general, &quot;direct packet access&quot; is the preferred method to
   * access packet data, however, this helper is in particular useful
   * in socket filters where <em>skb</em>\ <strong>-&gt;data</strong> does not always point
   * to the start of the mac header and where &quot;direct packet access&quot;
   * is not available.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_skb_load_bytes_relative((const void*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static long bpf_skb_load_bytes_relative(Ptr<?> skb, @Unsigned int offset, Ptr<?> to,
      @Unsigned int len, @Unsigned int start_header) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Write raw <em>data</em> blob into a special BPF perf event held by
   * <em>map</em> of type <strong>BPF_MAP_TYPE_PERF_EVENT_ARRAY</strong>. This perf
   * event must have the following attributes: <strong>PERF_SAMPLE_RAW</strong>
   * as <strong>sample_type</strong>, <strong>PERF_TYPE_SOFTWARE</strong> as <strong>type</strong>, and
   * <strong>PERF_COUNT_SW_BPF_OUTPUT</strong> as <strong>config</strong>.</p>
   * <p>The <em>flags</em> are used to indicate the index in <em>map</em> for which
   * the value must be put, masked with <strong>BPF_F_INDEX_MASK</strong>.
   * Alternatively, <em>flags</em> can be set to <strong>BPF_F_CURRENT_CPU</strong>
   * to indicate that the index of the current CPU core should be
   * used.</p>
   * <p>The value to write, of <em>size</em>, is passed through eBPF stack and
   * pointed by <em>data</em>.</p>
   * <p><em>ctx</em> is a pointer to in-kernel struct sk_buff.</p>
   * <p>This helper is similar to <strong>bpf_perf_event_output</strong>\ () but
   * restricted to raw_tracepoint bpf programs.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_output(Ptr<?> ctx, Ptr<?> map, @Unsigned long flags, Ptr<?> data,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Pull in non-linear data in case the <em>skb</em> is non-linear and not
   * all of <em>len</em> are part of the linear section. Make <em>len</em> bytes
   * from <em>skb</em> readable and writable. If a zero value is passed for
   * <em>len</em>, then all bytes in the linear part of <em>skb</em> will be made
   * readable and writable.</p>
   * <p>This helper is only needed for reading and writing with direct
   * packet access.</p>
   * <p>For direct packet access, testing that offsets to access
   * are within packet boundaries (test on <em>skb</em>\ <strong>-&gt;data_end</strong>) is
   * susceptible to fail if offsets are invalid, or if the requested
   * data is in non-linear parts of the <em>skb</em>. On failure the
   * program can just bail out, or in the case of a non-linear
   * buffer, use a helper to make the data available. The
   * <strong>bpf_skb_load_bytes</strong>\ () helper is a first solution to access
   * the data. Another one consists in using <strong>bpf_skb_pull_data</strong>
   * to pull in once the non-linear parts, then retesting and
   * eventually access the data.</p>
   * <p>At the same time, this also makes sure the <em>skb</em> is uncloned,
   * which is a necessary condition for direct write. As this needs
   * to be an invariant for the write part only, the verifier
   * detects writes and adds a prologue that is calling
   * <strong>bpf_skb_pull_data()</strong> to effectively unclone the <em>skb</em> from
   * the very beginning in case it is indeed cloned.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_pull_data(Ptr<__sk_buff> skb, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Change the __sk_buff-&gt;tstamp_type to <em>tstamp_type</em>
   * and set <em>tstamp</em> to the __sk_buff-&gt;tstamp together.</p>
   * <p>If there is no need to change the __sk_buff-&gt;tstamp_type,
   * the tstamp value can be directly written to __sk_buff-&gt;tstamp
   * instead.</p>
   * <p>BPF_SKB_TSTAMP_DELIVERY_MONO is the only tstamp that
   * will be kept during bpf_redirect_*().  A non zero
   * <em>tstamp</em> must be used with the BPF_SKB_TSTAMP_DELIVERY_MONO
   * <em>tstamp_type</em>.</p>
   * <p>A BPF_SKB_TSTAMP_UNSPEC <em>tstamp_type</em> can only be used
   * with a zero <em>tstamp</em>.</p>
   * <p>Only IPv4 and IPv6 skb-&gt;protocol are supported.</p>
   * <p>This function is most useful when it needs to set a
   * mono delivery time to _<em>sk_buff-&gt;tstamp and then
   * bpf_redirect</em><em>() to the egress of an iface.  For example,
   * changing the (rcv) timestamp in _<em>sk_buff-&gt;tstamp at
   * ingress to a mono delivery time and then bpf_redirect</em></em>()
   * to sch_fq@phy-dev.
   * @return 0 on success.
   * <strong>-EINVAL</strong> for invalid input
   * <strong>-EOPNOTSUPP</strong> for unsupported protocol
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_set_tstamp(Ptr<__sk_buff> skb, @Unsigned long tstamp,
      @Unsigned int tstamp_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Populate tunnel metadata for packet associated to <em>skb.</em> The
   * tunnel metadata is set to the contents of <em>key</em>, of <em>size</em>. The
   * <em>flags</em> can be set to a combination of the following values:</p>
   * <p><strong>BPF_F_TUNINFO_IPV6</strong>
   * Indicate that the tunnel is based on IPv6 protocol
   * instead of IPv4.
   * <strong>BPF_F_ZERO_CSUM_TX</strong>
   * For IPv4 packets, add a flag to tunnel metadata
   * indicating that checksum computation should be skipped
   * and checksum set to zeroes.
   * <strong>BPF_F_DONT_FRAGMENT</strong>
   * Add a flag to tunnel metadata indicating that the
   * packet should not be fragmented.
   * <strong>BPF_F_SEQ_NUMBER</strong>
   * Add a flag to tunnel metadata indicating that a
   * sequence number should be added to tunnel header before
   * sending the packet. This flag was added for GRE
   * encapsulation, but might be used with other protocols
   * as well in the future.
   * <strong>BPF_F_NO_TUNNEL_KEY</strong>
   * Add a flag to tunnel metadata indicating that no tunnel
   * key should be set in the resulting tunnel header.</p>
   * <p>Here is a typical usage on the transmit path:</p>
   * <p>::</p>
   * <pre><code>struct bpf_tunnel_key key;
   *      populate key ...
   * bpf_skb_set_tunnel_key(skb, &amp;key, sizeof(key), 0);
   * bpf_clone_redirect(skb, vxlan_dev_ifindex, 0);
   * </code></pre>
   * <p>See also the description of the <strong>bpf_skb_get_tunnel_key</strong>\ ()
   * helper for additional information.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_set_tunnel_key(Ptr<__sk_buff> skb, Ptr<bpf_tunnel_key> key,
      @Unsigned int size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Set tunnel options metadata for the packet associated to <em>skb</em>
   * to the option data contained in the raw buffer <em>opt</em> of <em>size</em>.</p>
   * <p>See also the description of the <strong>bpf_skb_get_tunnel_opt</strong>\ ()
   * helper for additional information.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_set_tunnel_opt(Ptr<__sk_buff> skb, Ptr<?> opt, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Store <em>len</em> bytes from address <em>from</em> into the packet
   * associated to <em>skb</em>, at <em>offset</em>. <em>flags</em> are a combination of
   * <strong>BPF_F_RECOMPUTE_CSUM</strong> (automatically recompute the
   * checksum for the packet after storing the bytes) and
   * <strong>BPF_F_INVALIDATE_HASH</strong> (set <em>skb</em>\ <strong>-&gt;hash</strong>, <em>skb</em><br />
   * <strong>-&gt;swhash</strong> and <em>skb</em>\ <strong>-&gt;l4hash</strong> to 0).</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_skb_store_bytes($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static long bpf_skb_store_bytes(Ptr<__sk_buff> skb, @Unsigned int offset, Ptr<?> from,
      @Unsigned int len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Check whether <em>skb</em> is a descendant of the cgroup2 held by
   * <em>map</em> of type <strong>BPF_MAP_TYPE_CGROUP_ARRAY</strong>, at <em>index</em>.
   * @return <p>The return value depends on the result of the test, and can be:</p>
   * <ul>
   * <li>0, if the <em>skb</em> failed the cgroup2 descendant test.</li>
   * <li>1, if the <em>skb</em> succeeded the cgroup2 descendant test.</li>
   * <li>A negative error code, if an error occurred.</li>
   * </ul>
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_under_cgroup(Ptr<__sk_buff> skb, Ptr<?> map, @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Pop a VLAN header from the packet associated to <em>skb</em>.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_vlan_pop(Ptr<__sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Push a <em>vlan_tci</em> (VLAN tag control information) of protocol
   * <em>vlan_proto</em> to the packet associated to <em>skb</em>, then update
   * the checksum. Note that if <em>vlan_proto</em> is different from
   * <strong>ETH_P_8021Q</strong> and <strong>ETH_P_8021AD</strong>, it is considered to
   * be <strong>ETH_P_8021Q</strong>.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_skb_vlan_push(Ptr<__sk_buff> skb,
      @Unsigned @OriginalName("__be16") short vlan_proto, @Unsigned short vlan_tci) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Look for TCP socket matching <em>tuple</em>, optionally in a child
   * network namespace <em>netns</em>. The return value must be checked,
   * and if non-<strong>NULL</strong>, released via <strong>bpf_sk_release</strong>\ ().</p>
   * <p>This function is identical to <strong>bpf_sk_lookup_tcp</strong>\ (), except
   * that it also returns timewait or request sockets. Use
   * <strong>bpf_sk_fullsock</strong>\ () or <strong>bpf_tcp_sock</strong>\ () to access the
   * full structure.</p>
   * <p>This helper is available only if the kernel was compiled with
   * <strong>CONFIG_NET</strong> configuration option.
   * @return Pointer to <strong>struct bpf_sock</strong>, or <strong>NULL</strong> in case of failure.
   * For sockets with reuseport option, the <strong>struct bpf_sock</strong>
   * result is from <em>reuse</em>\ <strong>-&gt;socks</strong>\ [] using the hash of the
   * tuple.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_sock> bpf_skc_lookup_tcp(Ptr<?> ctx, Ptr<bpf_sock_tuple> tuple,
      @Unsigned int tuple_size, @Unsigned long netns, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Dynamically cast a <em>sk</em> pointer to a <em>mptcp_sock</em> pointer.
   * @return <em>sk</em> if casting is valid, or <strong>NULL</strong> otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mptcp_sock> bpf_skc_to_mptcp_sock(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Dynamically cast a <em>sk</em> pointer to a <em>tcp6_sock</em> pointer.
   * @return <em>sk</em> if casting is valid, or <strong>NULL</strong> otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcp6_sock> bpf_skc_to_tcp6_sock(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Dynamically cast a <em>sk</em> pointer to a <em>tcp_request_sock</em> pointer.
   * @return <em>sk</em> if casting is valid, or <strong>NULL</strong> otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcp_request_sock> bpf_skc_to_tcp_request_sock(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Dynamically cast a <em>sk</em> pointer to a <em>tcp_sock</em> pointer.
   * @return <em>sk</em> if casting is valid, or <strong>NULL</strong> otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcp_sock> bpf_skc_to_tcp_sock(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Dynamically cast a <em>sk</em> pointer to a <em>tcp_timewait_sock</em> pointer.
   * @return <em>sk</em> if casting is valid, or <strong>NULL</strong> otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<tcp_timewait_sock> bpf_skc_to_tcp_timewait_sock(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Dynamically cast a <em>sk</em> pointer to a <em>udp6_sock</em> pointer.
   * @return <em>sk</em> if casting is valid, or <strong>NULL</strong> otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<udp6_sock> bpf_skc_to_udp6_sock(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Dynamically cast a <em>sk</em> pointer to a <em>unix_sock</em> pointer.
   * @return <em>sk</em> if casting is valid, or <strong>NULL</strong> otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<unix_sock> bpf_skc_to_unix_sock(Ptr<?> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Outputs a string into the <strong>str</strong> buffer of size <strong>str_size</strong>
   * based on a format string stored in a read-only map pointed by
   * <strong>fmt</strong>.</p>
   * <p>Each format specifier in <strong>fmt</strong> corresponds to one u64 element
   * in the <strong>data</strong> array. For strings and pointers where pointees
   * are accessed, only the pointer values are stored in the <em>data</em>
   * array. The <em>data_len</em> is the size of <em>data</em> in bytes - must be
   * a multiple of 8.</p>
   * <p>Formats <strong>%s</strong> and <strong>%p{i,I}{4,6}</strong> require to read kernel
   * memory. Reading kernel memory may fail due to either invalid
   * address or valid address but requiring a major memory fault. If
   * reading kernel memory fails, the string for <strong>%s</strong> will be an
   * empty string, and the ip address for <strong>%p{i,I}{4,6}</strong> will be 0.
   * Not returning error to bpf program is consistent with what
   * <strong>bpf_trace_printk</strong>\ () does for now.
   * @return The strictly positive length of the formatted string, including
   * the trailing zero character. If the return value is greater than
   * <strong>str_size</strong>, <strong>str</strong> contains a truncated string, guaranteed to
   * be zero-terminated except when <strong>str_size</strong> is 0.</p>
   * <p>Or <strong>-EBUSY</strong> if the per-CPU memory copy buffer is busy.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_snprintf($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static long bpf_snprintf(String str, @Unsigned int str_size, String fmt,
      Ptr<java.lang. @Unsigned Long> data, @Unsigned int data_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Use BTF to store a string representation of <em>ptr</em>-&gt;ptr in <em>str</em>,
   * using <em>ptr</em>-&gt;type_id.  This value should specify the type
   * that <em>ptr</em>-&gt;ptr points to. LLVM __builtin_btf_type_id(type, 1)
   * can be used to look up vmlinux BTF type ids. Traversing the
   * data structure using BTF, the type information and values are
   * stored in the first <em>str_size</em> - 1 bytes of <em>str</em>.  Safe copy of
   * the pointer data is carried out to avoid kernel crashes during
   * operation.  Smaller types can use string space on the stack;
   * larger programs can use map data to store the string
   * representation.</p>
   * <p>The string can be subsequently shared with userspace via
   * bpf_perf_event_output() or ring buffer interfaces.
   * bpf_trace_printk() is to be avoided as it places too small
   * a limit on string size to be useful.</p>
   * <p><em>flags</em> is a combination of</p>
   * <p><strong>BTF_F_COMPACT</strong>
   * no formatting around type information
   * <strong>BTF_F_NONAME</strong>
   * no struct/union member names/types
   * <strong>BTF_F_PTR_RAW</strong>
   * show raw (unobfuscated) pointer values;
   * equivalent to printk specifier %px.
   * <strong>BTF_F_ZERO</strong>
   * show zero-valued struct/union members; they
   * are not displayed by default
   * @return The number of bytes that were written (or would have been
   * written if output had to be truncated due to string size),
   * or a negative error in cases of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_snprintf_btf(String str, @Unsigned int str_size, Ptr<btf_ptr> ptr,
      @Unsigned int btf_ptr_size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * If the given file represents a socket, returns the associated
   * socket.
   * @return A pointer to a struct socket on success or NULL if the file is
   * not a socket.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<socket> bpf_sock_from_file(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Add an entry to, or update a sockhash <em>map</em> referencing sockets.
   * The <em>skops</em> is used as a new value for the entry associated to
   * <em>key</em>. <em>flags</em> is one of:</p>
   * <p><strong>BPF_NOEXIST</strong>
   * The entry for <em>key</em> must not exist in the map.
   * <strong>BPF_EXIST</strong>
   * The entry for <em>key</em> must already exist in the map.
   * <strong>BPF_ANY</strong>
   * No condition on the existence of the entry for <em>key</em>.</p>
   * <p>If the <em>map</em> has eBPF programs (parser and verdict), those will
   * be inherited by the socket being added. If the socket is
   * already attached to eBPF programs, this results in an error.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sock_hash_update(Ptr<bpf_sock_ops> skops, Ptr<?> map, Ptr<?> key,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Add an entry to, or update a <em>map</em> referencing sockets. The
   * <em>skops</em> is used as a new value for the entry associated to
   * <em>key</em>. <em>flags</em> is one of:</p>
   * <p><strong>BPF_NOEXIST</strong>
   * The entry for <em>key</em> must not exist in the map.
   * <strong>BPF_EXIST</strong>
   * The entry for <em>key</em> must already exist in the map.
   * <strong>BPF_ANY</strong>
   * No condition on the existence of the entry for <em>key</em>.</p>
   * <p>If the <em>map</em> has eBPF programs (parser and verdict), those will
   * be inherited by the socket being added. If the socket is
   * already attached to eBPF programs, this results in an error.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sock_map_update(Ptr<bpf_sock_ops> skops, Ptr<?> map, Ptr<?> key,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Attempt to set the value of the <strong>bpf_sock_ops_cb_flags</strong> field
   * for the full TCP socket associated to <em>bpf_sock_ops</em> to
   * <em>argval</em>.</p>
   * <p>The primary use of this field is to determine if there should
   * be calls to eBPF programs of type
   * <strong>BPF_PROG_TYPE_SOCK_OPS</strong> at various points in the TCP
   * code. A program of the same type can change its value, per
   * connection and as necessary, when the connection is
   * established. This field is directly accessible for reading, but
   * this helper must be used for updates in order to return an
   * error if an eBPF program tries to set a callback that is not
   * supported in the current kernel.</p>
   * <p><em>argval</em> is a flag array which can combine these flags:</p>
   * <ul>
   * <li><strong>BPF_SOCK_OPS_RTO_CB_FLAG</strong> (retransmission time out)</li>
   * <li><strong>BPF_SOCK_OPS_RETRANS_CB_FLAG</strong> (retransmission)</li>
   * <li><strong>BPF_SOCK_OPS_STATE_CB_FLAG</strong> (TCP state change)</li>
   * <li><strong>BPF_SOCK_OPS_RTT_CB_FLAG</strong> (every RTT)</li>
   * </ul>
   * <p>Therefore, this function can be used to clear a callback flag by
   * setting the appropriate bit to zero. e.g. to disable the RTO
   * callback:</p>
   * <p><strong>bpf_sock_ops_cb_flags_set(bpf_sock,</strong>
   * <strong>bpf_sock-&gt;bpf_sock_ops_cb_flags &amp; ~BPF_SOCK_OPS_RTO_CB_FLAG)</strong></p>
   * <p>Here are some examples of where one could call such eBPF
   * program:</p>
   * <ul>
   * <li>When RTO fires.</li>
   * <li>When a packet is retransmitted.</li>
   * <li>When the connection terminates.</li>
   * <li>When a packet is sent.</li>
   * <li>When a packet is received.</li>
   * </ul>
   * @return Code <strong>-EINVAL</strong> if the socket is not a full TCP socket;
   * otherwise, a positive number containing the bits that could not
   * be set is returned (which comes down to 0 if all bits were set
   * as required).
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sock_ops_cb_flags_set(Ptr<bpf_sock_ops> bpf_sock, int argval) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * <p>Acquire a spinlock represented by the pointer <em>lock</em>, which is
   * stored as part of a value of a map. Taking the lock allows to
   * safely update the rest of the fields in that value. The
   * spinlock can (and must) later be released with a call to
   * <strong>bpf_spin_unlock</strong>\ (\ <em>lock</em>\ ).</p>
   * <p>Spinlocks in BPF programs come with a number of restrictions
   * and constraints:</p>
   * <ul>
   * <li><strong>bpf_spin_lock</strong> objects are only allowed inside maps of
   * types <strong>BPF_MAP_TYPE_HASH</strong> and <strong>BPF_MAP_TYPE_ARRAY</strong> (this
   * list could be extended in the future).</li>
   * <li>BTF description of the map is mandatory.</li>
   * <li>The BPF program can take ONE lock at a time, since taking two
   * or more could cause dead locks.</li>
   * <li>Only one <strong>struct bpf_spin_lock</strong> is allowed per map element.</li>
   * <li>When the lock is taken, calls (either BPF to BPF or helpers)
   * are not allowed.</li>
   * <li>The <strong>BPF_LD_ABS</strong> and <strong>BPF_LD_IND</strong> instructions are not
   * allowed inside a spinlock-ed region.</li>
   * <li>The BPF program MUST call <strong>bpf_spin_unlock</strong>\ () to release
   * the lock, on all execution paths, before it returns.</li>
   * <li>The BPF program can access <strong>struct bpf_spin_lock</strong> only via
   * the <strong>bpf_spin_lock</strong>\ () and <strong>bpf_spin_unlock</strong>\ ()
   * helpers. Loading or storing data into the <strong>struct
   * bpf_spin_lock</strong> <em>lock</em>\ <strong>;</strong> field of a map is not allowed.</li>
   * <li>To use the <strong>bpf_spin_lock</strong>\ () helper, the BTF description
   * of the map value must be a struct and have <strong>struct
   * bpf_spin_lock</strong> <em>anyname</em>\ <strong>;</strong> field at the top level.
   * Nested lock inside another struct is not allowed.</li>
   * <li>The <strong>struct bpf_spin_lock</strong> <em>lock</em> field in a map value must
   * be aligned on a multiple of 4 bytes in that value.</li>
   * <li>Syscall with command <strong>BPF_MAP_LOOKUP_ELEM</strong> does not copy
   * the <strong>bpf_spin_lock</strong> field to user space.</li>
   * <li>Syscall with command <strong>BPF_MAP_UPDATE_ELEM</strong>, or update from
   * a BPF program, do not update the <strong>bpf_spin_lock</strong> field.</li>
   * <li><strong>bpf_spin_lock</strong> cannot be on the stack or inside a
   * networking packet (it can only be inside of a map values).</li>
   * <li><strong>bpf_spin_lock</strong> is available to root only.</li>
   * <li>Tracing programs and socket filter programs cannot use
   * <strong>bpf_spin_lock</strong>\ () due to insufficient preemption checks
   * (but this may change in the future).</li>
   * <li><strong>bpf_spin_lock</strong> is not allowed in inner maps of map-in-map.</li>
   * </ul>
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_spin_lock(Ptr<bpf_spin_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Release the <em>lock</em> previously locked by a call to
   * <strong>bpf_spin_lock</strong>\ (\ <em>lock</em>\ ).
   * @return 0
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_spin_unlock(Ptr<bpf_spin_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Store header option.  The data will be copied
   * from buffer <em>from</em> with length <em>len</em> to the TCP header.</p>
   * <p>The buffer <em>from</em> should have the whole option that
   * includes the kind, kind-length, and the actual
   * option data.  The <em>len</em> must be at least kind-length
   * long.  The kind-length does not have to be 4 byte
   * aligned.  The kernel will take care of the padding
   * and setting the 4 bytes aligned value to th-&gt;doff.</p>
   * <p>This helper will check for duplicated option
   * by searching the same option in the outgoing skb.</p>
   * <p>This helper can only be called during
   * <strong>BPF_SOCK_OPS_WRITE_HDR_OPT_CB</strong>.
   * @return 0 on success, or negative error in case of failure:</p>
   * <p><strong>-EINVAL</strong> If param is invalid.</p>
   * <p><strong>-ENOSPC</strong> if there is not enough space in the header.
   * Nothing has been written</p>
   * <p><strong>-EEXIST</strong> if the option already exists.</p>
   * <p><strong>-EFAULT</strong> on failure to parse the existing header options.</p>
   * <p><strong>-EPERM</strong> if the helper cannot be used under the current
   * <em>skops</em>\ <strong>-&gt;op</strong>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_store_hdr_opt($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static long bpf_store_hdr_opt(Ptr<bpf_sock_ops> skops, Ptr<?> from, @Unsigned int len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Do strncmp() between <strong>s1</strong> and <strong>s2</strong>. <strong>s1</strong> doesn't need
   * to be null-terminated and <strong>s1_sz</strong> is the maximum storage
   * size of <strong>s1</strong>. <strong>s2</strong> must be a read-only string.
   * @return An integer less than, equal to, or greater than zero
   * if the first <strong>s1_sz</strong> bytes of <strong>s1</strong> is found to be
   * less than, to match, or be greater than <strong>s2</strong>.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strncmp((const u8 *)$arg1, $arg2, (const u8 *)$arg3)")
  public static long bpf_strncmp(String s1, @Unsigned int s1_sz, String s2) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Convert the initial part of the string from buffer <em>buf</em> of
   * size <em>buf_len</em> to a long integer according to the given base
   * and save the result in <em>res</em>.</p>
   * <p>The string may begin with an arbitrary amount of white space
   * (as determined by <strong>isspace</strong>\ (3)) followed by a single
   * optional '<strong>-</strong>' sign.</p>
   * <p>Five least significant bits of <em>flags</em> encode base, other bits
   * are currently unused.</p>
   * <p>Base must be either 8, 10, 16 or 0 to detect it automatically
   * similar to user space <strong>strtol</strong>\ (3).
   * @return Number of characters consumed on success. Must be positive but
   * no more than <em>buf_len</em>.</p>
   * <p><strong>-EINVAL</strong> if no valid digits were found or unsupported base
   * was provided.</p>
   * <p><strong>-ERANGE</strong> if resulting value was out of range.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strtol((const u8 *)$arg1, $arg2, $arg3, $arg4)")
  public static long bpf_strtol(String buf, @Unsigned long buf_len, @Unsigned long flags,
      Ptr<java.lang.Long> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Convert the initial part of the string from buffer <em>buf</em> of
   * size <em>buf_len</em> to an unsigned long integer according to the
   * given base and save the result in <em>res</em>.</p>
   * <p>The string may begin with an arbitrary amount of white space
   * (as determined by <strong>isspace</strong>\ (3)).</p>
   * <p>Five least significant bits of <em>flags</em> encode base, other bits
   * are currently unused.</p>
   * <p>Base must be either 8, 10, 16 or 0 to detect it automatically
   * similar to user space <strong>strtoul</strong>\ (3).
   * @return Number of characters consumed on success. Must be positive but
   * no more than <em>buf_len</em>.</p>
   * <p><strong>-EINVAL</strong> if no valid digits were found or unsupported base
   * was provided.</p>
   * <p><strong>-ERANGE</strong> if resulting value was out of range.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strtoul((const u8 *)$arg1, $arg2, $arg3, $arg4)")
  public static long bpf_strtoul(String buf, @Unsigned long buf_len, @Unsigned long flags,
      Ptr<java.lang. @Unsigned Long> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Execute bpf syscall with given arguments.
   * @return A syscall result.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sys_bpf(@Unsigned int cmd, Ptr<?> attr, @Unsigned int attr_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Execute close syscall for given FD.
   * @return A syscall result.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sys_close(@Unsigned int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get current value of sysctl as it is presented in /proc/sys
   * (incl. newline, etc), and copy it as a string into provided
   * by program buffer <em>buf</em> of size <em>buf_len</em>.</p>
   * <p>The whole value is copied, no matter what file position user
   * space issued e.g. sys_read at.</p>
   * <p>The buffer is always NUL terminated, unless it's zero-sized.
   * @return Number of character copied (not including the trailing NUL).</p>
   * <p><strong>-E2BIG</strong> if the buffer wasn't big enough (<em>buf</em> will contain
   * truncated name in this case).</p>
   * <p><strong>-EINVAL</strong> if current value was unavailable, e.g. because
   * sysctl is uninitialized and read returns -EIO for it.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sysctl_get_current_value(Ptr<bpf_sysctl> ctx, String buf,
      @Unsigned long buf_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get name of sysctl in /proc/sys/ and copy it into provided by
   * program buffer <em>buf</em> of size <em>buf_len</em>.</p>
   * <p>The buffer is always NUL terminated, unless it's zero-sized.</p>
   * <p>If <em>flags</em> is zero, full name (e.g. &quot;net/ipv4/tcp_mem&quot;) is
   * copied. Use <strong>BPF_F_SYSCTL_BASE_NAME</strong> flag to copy base name
   * only (e.g. &quot;tcp_mem&quot;).
   * @return Number of character copied (not including the trailing NUL).</p>
   * <p><strong>-E2BIG</strong> if the buffer wasn't big enough (<em>buf</em> will contain
   * truncated name in this case).
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sysctl_get_name(Ptr<bpf_sysctl> ctx, String buf, @Unsigned long buf_len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get new value being written by user space to sysctl (before
   * the actual write happens) and copy it as a string into
   * provided by program buffer <em>buf</em> of size <em>buf_len</em>.</p>
   * <p>User space may write new value at file position &gt; 0.</p>
   * <p>The buffer is always NUL terminated, unless it's zero-sized.
   * @return Number of character copied (not including the trailing NUL).</p>
   * <p><strong>-E2BIG</strong> if the buffer wasn't big enough (<em>buf</em> will contain
   * truncated name in this case).</p>
   * <p><strong>-EINVAL</strong> if sysctl is being read.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_sysctl_get_new_value(Ptr<bpf_sysctl> ctx, String buf,
      @Unsigned long buf_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Override new value being written by user space to sysctl with
   * value provided by program in buffer <em>buf</em> of size <em>buf_len</em>.</p>
   * <p><em>buf</em> should contain a string in same form as provided by user
   * space on sysctl write.</p>
   * <p>User space may write new value at file position &gt; 0. To override
   * the whole sysctl value file position should be set to zero.
   * @return 0 on success.</p>
   * <p><strong>-E2BIG</strong> if the <em>buf_len</em> is too big.</p>
   * <p><strong>-EINVAL</strong> if sysctl is being read.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sysctl_set_new_value($arg1, (const u8 *)$arg2, $arg3)")
  public static long bpf_sysctl_set_new_value(Ptr<bpf_sysctl> ctx, String buf,
      @Unsigned long buf_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This special helper is used to trigger a &quot;tail call&quot;, or in
   * other words, to jump into another eBPF program. The same stack
   * frame is used (but values on stack and in registers for the
   * caller are not accessible to the callee). This mechanism allows
   * for program chaining, either for raising the maximum number of
   * available eBPF instructions, or to execute given programs in
   * conditional blocks. For security reasons, there is an upper
   * limit to the number of successive tail calls that can be
   * performed.</p>
   * <p>Upon call of this helper, the program attempts to jump into a
   * program referenced at index <em>index</em> in <em>prog_array_map</em>, a
   * special map of type <strong>BPF_MAP_TYPE_PROG_ARRAY</strong>, and passes
   * <em>ctx</em>, a pointer to the context.</p>
   * <p>If the call succeeds, the kernel immediately runs the first
   * instruction of the new program. This is not a function call,
   * and it never returns to the previous program. If the call
   * fails, then the helper has no effect, and the caller continues
   * to run its subsequent instructions. A call can fail if the
   * destination program for the jump does not exist (i.e. <em>index</em>
   * is superior to the number of entries in <em>prog_array_map</em>), or
   * if the maximum number of tail calls has been reached for this
   * chain of programs. This limit is defined in the kernel by the
   * macro <strong>MAX_TAIL_CALL_CNT</strong> (not accessible to user space),
   * which is currently set to 33.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tail_call(Ptr<?> ctx, Ptr<?> prog_array_map, @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the struct pt_regs associated with <strong>task</strong>.
   * @return A pointer to struct pt_regs.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_task_pt_regs(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Delete a bpf_local_storage from a <em>task</em>.
   * @return 0 on success.</p>
   * <p><strong>-ENOENT</strong> if the bpf_local_storage cannot be found.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_task_storage_delete(Ptr<?> map, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get a bpf_local_storage from the <em>task</em>.</p>
   * <p>Logically, it could be thought of as getting the value from
   * a <em>map</em> with <em>task</em> as the <strong>key</strong>.  From this
   * perspective,  the usage is not much different from
   * <strong>bpf_map_lookup_elem</strong>\ (<em>map</em>, <strong>&amp;</strong>\ <em>task</em>) except this
   * helper enforces the key must be a task_struct and the map must also
   * be a <strong>BPF_MAP_TYPE_TASK_STORAGE</strong>.</p>
   * <p>Underneath, the value is stored locally at <em>task</em> instead of
   * the <em>map</em>.  The <em>map</em> is used as the bpf-local-storage
   * &quot;type&quot;. The bpf-local-storage &quot;type&quot; (i.e. the <em>map</em>) is
   * searched against all bpf_local_storage residing at <em>task</em>.</p>
   * <p>An optional <em>flags</em> (<strong>BPF_LOCAL_STORAGE_GET_F_CREATE</strong>) can be
   * used such that a new bpf_local_storage will be
   * created if one does not exist.  <em>value</em> can be used
   * together with <strong>BPF_LOCAL_STORAGE_GET_F_CREATE</strong> to specify
   * the initial value of a bpf_local_storage.  If <em>value</em> is
   * <strong>NULL</strong>, the new bpf_local_storage will be zero initialized.
   * @return A bpf_local_storage pointer is returned on success.</p>
   * <p><strong>NULL</strong> if not found or there was an error in adding
   * a new bpf_local_storage.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_task_storage_get(Ptr<?> map, Ptr<task_struct> task, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Check whether <em>iph</em> and <em>th</em> contain a valid SYN cookie ACK for
   * the listening socket in <em>sk</em>.</p>
   * <p><em>iph</em> points to the start of the IPv4 or IPv6 header, while
   * <em>iph_len</em> contains <strong>sizeof</strong>\ (<strong>struct iphdr</strong>) or
   * <strong>sizeof</strong>\ (<strong>struct ipv6hdr</strong>).</p>
   * <p><em>th</em> points to the start of the TCP header, while <em>th_len</em>
   * contains the length of the TCP header (at least
   * <strong>sizeof</strong>\ (<strong>struct tcphdr</strong>)).
   * @return 0 if <em>iph</em> and <em>th</em> are a valid SYN cookie ACK, or a negative
   * error otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tcp_check_syncookie(Ptr<?> sk, Ptr<?> iph, @Unsigned int iph_len,
      Ptr<tcphdr> th, @Unsigned int th_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Try to issue a SYN cookie for the packet with corresponding
   * IP/TCP headers, <em>iph</em> and <em>th</em>, on the listening socket in <em>sk</em>.</p>
   * <p><em>iph</em> points to the start of the IPv4 or IPv6 header, while
   * <em>iph_len</em> contains <strong>sizeof</strong>\ (<strong>struct iphdr</strong>) or
   * <strong>sizeof</strong>\ (<strong>struct ipv6hdr</strong>).</p>
   * <p><em>th</em> points to the start of the TCP header, while <em>th_len</em>
   * contains the length of the TCP header with options (at least
   * <strong>sizeof</strong>\ (<strong>struct tcphdr</strong>)).
   * @return On success, lower 32 bits hold the generated SYN cookie in
   * followed by 16 bits which hold the MSS value for that cookie,
   * and the top 16 bits are unused.</p>
   * <p>On failure, the returned value is one of the following:</p>
   * <p><strong>-EINVAL</strong> SYN cookie cannot be issued due to error</p>
   * <p><strong>-ENOENT</strong> SYN cookie should not be issued (no SYN flood)</p>
   * <p><strong>-EOPNOTSUPP</strong> kernel configuration does not enable SYN cookies</p>
   * <p><strong>-EPROTONOSUPPORT</strong> IP packet version is not 4 or 6
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tcp_gen_syncookie(Ptr<?> sk, Ptr<?> iph, @Unsigned int iph_len,
      Ptr<tcphdr> th, @Unsigned int th_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Check whether <em>iph</em> and <em>th</em> contain a valid SYN cookie ACK
   * without depending on a listening socket.</p>
   * <p><em>iph</em> points to the IPv4 header.</p>
   * <p><em>th</em> points to the TCP header.
   * @return 0 if <em>iph</em> and <em>th</em> are a valid SYN cookie ACK.</p>
   * <p>On failure, the returned value is one of the following:</p>
   * <p><strong>-EACCES</strong> if the SYN cookie is not valid.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tcp_raw_check_syncookie_ipv4(Ptr<iphdr> iph, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Check whether <em>iph</em> and <em>th</em> contain a valid SYN cookie ACK
   * without depending on a listening socket.</p>
   * <p><em>iph</em> points to the IPv6 header.</p>
   * <p><em>th</em> points to the TCP header.
   * @return 0 if <em>iph</em> and <em>th</em> are a valid SYN cookie ACK.</p>
   * <p>On failure, the returned value is one of the following:</p>
   * <p><strong>-EACCES</strong> if the SYN cookie is not valid.</p>
   * <p><strong>-EPROTONOSUPPORT</strong> if CONFIG_IPV6 is not builtin.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tcp_raw_check_syncookie_ipv6(Ptr<ipv6hdr> iph, Ptr<tcphdr> th) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Try to issue a SYN cookie for the packet with corresponding
   * IPv4/TCP headers, <em>iph</em> and <em>th</em>, without depending on a
   * listening socket.</p>
   * <p><em>iph</em> points to the IPv4 header.</p>
   * <p><em>th</em> points to the start of the TCP header, while <em>th_len</em>
   * contains the length of the TCP header (at least
   * <strong>sizeof</strong>\ (<strong>struct tcphdr</strong>)).
   * @return On success, lower 32 bits hold the generated SYN cookie in
   * followed by 16 bits which hold the MSS value for that cookie,
   * and the top 16 bits are unused.</p>
   * <p>On failure, the returned value is one of the following:</p>
   * <p><strong>-EINVAL</strong> if <em>th_len</em> is invalid.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tcp_raw_gen_syncookie_ipv4(Ptr<iphdr> iph, Ptr<tcphdr> th,
      @Unsigned int th_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Try to issue a SYN cookie for the packet with corresponding
   * IPv6/TCP headers, <em>iph</em> and <em>th</em>, without depending on a
   * listening socket.</p>
   * <p><em>iph</em> points to the IPv6 header.</p>
   * <p><em>th</em> points to the start of the TCP header, while <em>th_len</em>
   * contains the length of the TCP header (at least
   * <strong>sizeof</strong>\ (<strong>struct tcphdr</strong>)).
   * @return On success, lower 32 bits hold the generated SYN cookie in
   * followed by 16 bits which hold the MSS value for that cookie,
   * and the top 16 bits are unused.</p>
   * <p>On failure, the returned value is one of the following:</p>
   * <p><strong>-EINVAL</strong> if <em>th_len</em> is invalid.</p>
   * <p><strong>-EPROTONOSUPPORT</strong> if CONFIG_IPV6 is not builtin.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tcp_raw_gen_syncookie_ipv6(Ptr<ipv6hdr> iph, Ptr<tcphdr> th,
      @Unsigned int th_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Send out a tcp-ack. <em>tp</em> is the in-kernel struct <strong>tcp_sock</strong>.
   * <em>rcv_nxt</em> is the ack_seq to be sent out.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_tcp_send_ack(Ptr<?> tp, @Unsigned int rcv_nxt) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper gets a <strong>struct bpf_tcp_sock</strong> pointer from a
   * <strong>struct bpf_sock</strong> pointer.
   * @return A <strong>struct bpf_tcp_sock</strong> pointer on success, or <strong>NULL</strong> in
   * case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_tcp_sock> bpf_tcp_sock(Ptr<bpf_sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Take a pointer to a percpu ksym, <em>percpu_ptr</em>, and return a
   * pointer to the percpu kernel variable on this cpu. See the
   * description of 'ksym' in <strong>bpf_per_cpu_ptr</strong>\ ().</p>
   * <p>bpf_this_cpu_ptr() has the same semantic as this_cpu_ptr() in
   * the kernel. Different from <strong>bpf_per_cpu_ptr</strong>\ (), it would
   * never return NULL.
   * @return A pointer pointing to the kernel percpu variable on this cpu.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_this_cpu_ptr((const void*)$arg1)")
  public static Ptr<?> bpf_this_cpu_ptr(Ptr<?> percpu_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Cancel the timer and wait for callback_fn to finish if it was running.
   * @return 0 if the timer was not active.
   * 1 if the timer was active.
   * <strong>-EINVAL</strong> if <em>timer</em> was not initialized with bpf_timer_init() earlier.
   * <strong>-EDEADLK</strong> if callback_fn tried to call bpf_timer_cancel() on its
   * own timer which would have led to a deadlock otherwise.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_timer_cancel(Ptr<bpf_timer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Initialize the timer.
   * First 4 bits of <em>flags</em> specify clockid.
   * Only CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_BOOTTIME are allowed.
   * All other bits of <em>flags</em> are reserved.
   * The verifier will reject the program if <em>timer</em> is not from
   * the same <em>map</em>.
   * @return 0 on success.
   * <strong>-EBUSY</strong> if <em>timer</em> is already initialized.
   * <strong>-EINVAL</strong> if invalid <em>flags</em> are passed.
   * <strong>-EPERM</strong> if <em>timer</em> is in a map that doesn't have any user references.
   * The user space should either hold a file descriptor to a map with timers
   * or pin such map in bpffs. When map is unpinned or file descriptor is
   * closed all timers in the map will be cancelled and freed.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_timer_init(Ptr<bpf_timer> timer, Ptr<?> map, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Configure the timer to call <em>callback_fn</em> static function.
   * @return 0 on success.
   * <strong>-EINVAL</strong> if <em>timer</em> was not initialized with bpf_timer_init() earlier.
   * <strong>-EPERM</strong> if <em>timer</em> is in a map that doesn't have any user references.
   * The user space should either hold a file descriptor to a map with timers
   * or pin such map in bpffs. When map is unpinned or file descriptor is
   * closed all timers in the map will be cancelled and freed.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_timer_set_callback(Ptr<bpf_timer> timer, Ptr<?> callback_fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Set timer expiration N nanoseconds from the current time. The
   * configured callback will be invoked in soft irq context on some cpu
   * and will not repeat unless another bpf_timer_start() is made.
   * In such case the next invocation can migrate to a different cpu.
   * Since struct bpf_timer is a field inside map element the map
   * owns the timer. The bpf_timer_set_callback() will increment refcnt
   * of BPF program to make sure that callback_fn code stays valid.
   * When user space reference to a map reaches zero all timers
   * in a map are cancelled and corresponding program's refcnts are
   * decremented. This is done to make sure that Ctrl-C of a user
   * process doesn't leave any timers running. If map is pinned in
   * bpffs the callback_fn can re-arm itself indefinitely.
   * bpf_map_update/delete_elem() helpers and user space sys_bpf commands
   * cancel and free the timer in the given map element.
   * The map can contain timers that invoke callback_fn-s from different
   * programs. The same callback_fn can serve different timers from
   * different maps if key/value layout matches across maps.
   * Every bpf_timer_set_callback() can have different callback_fn.</p>
   * <p><em>flags</em> can be one of:</p>
   * <p><strong>BPF_F_TIMER_ABS</strong>
   * Start the timer in absolute expire value instead of the
   * default relative one.
   * <strong>BPF_F_TIMER_CPU_PIN</strong>
   * Timer will be pinned to the CPU of the caller.
   * @return 0 on success.
   * <strong>-EINVAL</strong> if <em>timer</em> was not initialized with bpf_timer_init() earlier
   * or invalid <em>flags</em> are passed.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_timer_start(Ptr<bpf_timer> timer, @Unsigned long nsecs,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is a &quot;printk()-like&quot; facility for debugging. It
   * prints a message defined by format <em>fmt</em> (of size <em>fmt_size</em>)
   * to file <em>/sys/kernel/tracing/trace</em> from TraceFS, if
   * available. It can take up to three additional <strong>u64</strong>
   * arguments (as an eBPF helpers, the total number of arguments is
   * limited to five).</p>
   * <p>Each time the helper is called, it appends a line to the trace.
   * Lines are discarded while <em>/sys/kernel/tracing/trace</em> is
   * open, use <em>/sys/kernel/tracing/trace_pipe</em> to avoid this.
   * The format of the trace is customizable, and the exact output
   * one will get depends on the options set in
   * <em>/sys/kernel/tracing/trace_options</em> (see also the
   * <em>README</em> file under the same directory). However, it usually
   * defaults to something like:</p>
   * <p>::</p>
   * <pre><code>telnet-470   [001] .N.. 419421.045894: 0x00000001: &lt;formatted msg&gt;
   * </code></pre>
   * <p>In the above:</p>
   * <pre><code>* ``telnet`` is the name of the current task.
   * * ``470`` is the PID of the current task.
   * * ``001`` is the CPU number on which the task is
   *   running.
   * * In ``.N..``, each character refers to a set of
   *   options (whether irqs are enabled, scheduling
   *   options, whether hard/softirqs are running, level of
   *   preempt_disabled respectively). **N** means that
   *   **TIF_NEED_RESCHED** and **PREEMPT_NEED_RESCHED**
   *   are set.
   * * ``419421.045894`` is a timestamp.
   * * ``0x00000001`` is a fake value used by BPF for the
   *   instruction pointer register.
   * * ``&lt;formatted msg&gt;`` is the message formatted with
   *   *fmt*.
   * </code></pre>
   * <p>The conversion specifiers supported by <em>fmt</em> are similar, but
   * more limited than for printk(). They are <strong>%d</strong>, <strong>%i</strong>,
   * <strong>%u</strong>, <strong>%x</strong>, <strong>%ld</strong>, <strong>%li</strong>, <strong>%lu</strong>, <strong>%lx</strong>, <strong>%lld</strong>,
   * <strong>%lli</strong>, <strong>%llu</strong>, <strong>%llx</strong>, <strong>%p</strong>, <strong>%s</strong>. No modifier (size
   * of field, padding with zeroes, etc.) is available, and the
   * helper will return <strong>-EINVAL</strong> (but print nothing) if it
   * encounters an unknown specifier.</p>
   * <p>Also, note that <strong>bpf_trace_printk</strong>\ () is slow, and should
   * only be used for debugging purposes. For this reason, a notice
   * block (spanning several lines) is printed to kernel logs and
   * states that the helper should not be used &quot;for production use&quot;
   * the first time this helper is used (or more precisely, when
   * <strong>trace_printk</strong>\ () buffers are allocated). For passing values
   * to user space, perf events should be preferred.
   * @return The number of bytes written to the buffer, or a negative error
   * in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_trace_printk((const u8 *)$arg1, $arg2, $arg3_)")
  public static long bpf_trace_printk(String fmt, @Unsigned int fmt_size,
      java.lang.Object... args) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Behaves like <strong>bpf_trace_printk</strong>\ () helper, but takes an array of u64
   * to format and can handle more format args as a result.</p>
   * <p>Arguments are to be used as in <strong>bpf_seq_printf</strong>\ () helper.
   * @return The number of bytes written to the buffer, or a negative error
   * in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction("bpf_trace_vprintk((const u8 *)$arg1, $arg2, (const void *)$arg3, $arg4)")
  public static long bpf_trace_vprintk(String fmt, @Unsigned int fmt_size, Ptr<?> data,
      @Unsigned int data_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Drain samples from the specified user ring buffer, and invoke
   * the provided callback for each such sample:</p>
   * <p>long (*callback_fn)(const struct bpf_dynptr *dynptr, void *ctx);</p>
   * <p>If <strong>callback_fn</strong> returns 0, the helper will continue to try
   * and drain the next sample, up to a maximum of
   * BPF_MAX_USER_RINGBUF_SAMPLES samples. If the return value is 1,
   * the helper will skip the rest of the samples and return. Other
   * return values are not used now, and will be rejected by the
   * verifier.
   * @return The number of drained samples if no error was encountered while
   * draining samples, or 0 if no samples were present in the ring
   * buffer. If a user-space producer was epoll-waiting on this map,
   * and at least one sample was drained, they will receive an event
   * notification notifying them of available space in the ring
   * buffer. If the BPF_RB_NO_WAKEUP flag is passed to this
   * function, no wakeup notification will be sent. If the
   * BPF_RB_FORCE_WAKEUP flag is passed, a wakeup notification will
   * be sent even if no sample was drained.</p>
   * <p>On failure, the returned value is one of the following:</p>
   * <p><strong>-EBUSY</strong> if the ring buffer is contended, and another calling
   * context was concurrently draining the ring buffer.</p>
   * <p><strong>-EINVAL</strong> if user-space is not properly tracking the ring
   * buffer due to the producer position not being aligned to 8
   * bytes, a sample not being aligned to 8 bytes, or the producer
   * position not matching the advertised length of a sample.</p>
   * <p><strong>-E2BIG</strong> if user-space has tried to publish a sample which is
   * larger than the size of the ring buffer, or which cannot fit
   * within a struct bpf_dynptr.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_user_ringbuf_drain(Ptr<?> map, Ptr<?> callback_fn, Ptr<?> ctx,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Adjust (move) <em>xdp_md</em>\ <strong>-&gt;data</strong> by <em>delta</em> bytes. Note that
   * it is possible to use a negative value for <em>delta</em>. This helper
   * can be used to prepare the packet for pushing or popping
   * headers.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_xdp_adjust_head(Ptr<xdp_md> xdp_md, int delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Adjust the address pointed by <em>xdp_md</em>\ <strong>-&gt;data_meta</strong> by
   * <em>delta</em> (which can be positive or negative). Note that this
   * operation modifies the address stored in <em>xdp_md</em>\ <strong>-&gt;data</strong>,
   * so the latter must be loaded only after the helper has been
   * called.</p>
   * <p>The use of <em>xdp_md</em>\ <strong>-&gt;data_meta</strong> is optional and programs
   * are not required to use it. The rationale is that when the
   * packet is processed with XDP (e.g. as DoS filter), it is
   * possible to push further meta data along with it before passing
   * to the stack, and to give the guarantee that an ingress eBPF
   * program attached as a TC classifier on the same device can pick
   * this up for further post-processing. Since TC works with socket
   * buffers, it remains possible to set from XDP the <strong>mark</strong> or
   * <strong>priority</strong> pointers, or other pointers for the socket buffer.
   * Having this scratch space generic and programmable allows for
   * more flexibility as the user is free to store whatever meta
   * data they need.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_xdp_adjust_meta(Ptr<xdp_md> xdp_md, int delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Adjust (move) <em>xdp_md</em>\ <strong>-&gt;data_end</strong> by <em>delta</em> bytes. It is
   * possible to both shrink and grow the packet tail.
   * Shrink done via <em>delta</em> being a negative integer.</p>
   * <p>A call to this helper is susceptible to change the underlying
   * packet buffer. Therefore, at load time, all checks on pointers
   * previously done by the verifier are invalidated and must be
   * performed again, if the helper is used in combination with
   * direct packet access.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_xdp_adjust_tail(Ptr<xdp_md> xdp_md, int delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Get the total size of a given xdp buff (linear and paged area)
   * @return The total size of a given xdp buffer.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_get_buff_len(Ptr<xdp_md> xdp_md) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * This helper is provided as an easy way to load data from a
   * xdp buffer. It can be used to load <em>len</em> bytes from <em>offset</em> from
   * the frame associated to <em>xdp_md</em>, into the buffer pointed by
   * <em>buf</em>.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_xdp_load_bytes(Ptr<xdp_md> xdp_md, @Unsigned int offset, Ptr<?> buf,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Write raw <em>data</em> blob into a special BPF perf event held by
   * <em>map</em> of type <strong>BPF_MAP_TYPE_PERF_EVENT_ARRAY</strong>. This perf
   * event must have the following attributes: <strong>PERF_SAMPLE_RAW</strong>
   * as <strong>sample_type</strong>, <strong>PERF_TYPE_SOFTWARE</strong> as <strong>type</strong>, and
   * <strong>PERF_COUNT_SW_BPF_OUTPUT</strong> as <strong>config</strong>.</p>
   * <p>The <em>flags</em> are used to indicate the index in <em>map</em> for which
   * the value must be put, masked with <strong>BPF_F_INDEX_MASK</strong>.
   * Alternatively, <em>flags</em> can be set to <strong>BPF_F_CURRENT_CPU</strong>
   * to indicate that the index of the current CPU core should be
   * used.</p>
   * <p>The value to write, of <em>size</em>, is passed through eBPF stack and
   * pointed by <em>data</em>.</p>
   * <p><em>ctx</em> is a pointer to in-kernel struct xdp_buff.</p>
   * <p>This helper is similar to <strong>bpf_perf_eventoutput</strong>\ () but
   * restricted to raw_tracepoint bpf programs.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_xdp_output(Ptr<?> ctx, Ptr<?> map, @Unsigned long flags, Ptr<?> data,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * Store <em>len</em> bytes from buffer <em>buf</em> into the frame
   * associated to <em>xdp_md</em>, at <em>offset</em>.
   * @return 0 on success, or a negative error in case of failure.
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_xdp_store_bytes(Ptr<xdp_md> xdp_md, @Unsigned int offset, Ptr<?> buf,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }
}
