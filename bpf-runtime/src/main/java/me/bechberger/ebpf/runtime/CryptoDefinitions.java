/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
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
 * Generated class for BPF runtime types that start with crypto
 */
@java.lang.SuppressWarnings("unused")
public final class CryptoDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_alg_lookup((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_alg> __crypto_alg_lookup(String name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_tfm> __crypto_alloc_tfm(Ptr<crypto_alg> alg, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_tfm> __crypto_alloc_tfmgfp(Ptr<crypto_alg> alg, @Unsigned int type,
      @Unsigned int mask, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_dh_decode_key((const u8 *)$arg1, $arg2, $arg3)")
  public static int __crypto_dh_decode_key(String buf, @Unsigned int len, Ptr<dh> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_inst_setname($arg1, (const u8 *)$arg2, (const u8 *)$arg3, $arg4)")
  public static int __crypto_inst_setname(Ptr<crypto_instance> inst, String name, String driver,
      Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_lookup_template((const u8 *)$arg1)")
  public static Ptr<crypto_template> __crypto_lookup_template(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_memneq((const void *)$arg1, (const void *)$arg2, $arg3)")
  public static @Unsigned long __crypto_memneq(Ptr<?> a, Ptr<?> b, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_larval> __crypto_register_alg(Ptr<crypto_alg> alg,
      Ptr<list_head> algs_to_put) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha1_export((const struct sha1_ctx *)$arg1, $arg2)")
  public static int __crypto_sha1_export(Ptr<sha1_ctx> ctx0, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha1_export_core((const struct sha1_ctx *)$arg1, $arg2)")
  public static int __crypto_sha1_export_core(Ptr<sha1_ctx> ctx, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha1_import($arg1, (const void *)$arg2)")
  public static int __crypto_sha1_import(Ptr<sha1_ctx> ctx, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha1_import_core($arg1, (const void *)$arg2)")
  public static int __crypto_sha1_import_core(Ptr<sha1_ctx> ctx, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha256_export((const struct __sha256_ctx *)$arg1, $arg2)")
  public static int __crypto_sha256_export(Ptr<__sha256_ctx> ctx0, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha256_export_core((const struct __sha256_ctx *)$arg1, $arg2)")
  public static int __crypto_sha256_export_core(Ptr<__sha256_ctx> ctx, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha256_import($arg1, (const void *)$arg2)")
  public static int __crypto_sha256_import(Ptr<__sha256_ctx> ctx, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha256_import_core($arg1, (const void *)$arg2)")
  public static int __crypto_sha256_import_core(Ptr<__sha256_ctx> ctx, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha512_export((const struct __sha512_ctx *)$arg1, $arg2)")
  public static int __crypto_sha512_export(Ptr<__sha512_ctx> ctx0, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha512_export_core((const struct __sha512_ctx *)$arg1, $arg2)")
  public static int __crypto_sha512_export_core(Ptr<__sha512_ctx> ctx, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha512_import($arg1, (const void *)$arg2)")
  public static int __crypto_sha512_import(Ptr<__sha512_ctx> ctx, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_sha512_import_core($arg1, (const void *)$arg2)")
  public static int __crypto_sha512_import_core(Ptr<__sha512_ctx> ctx, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_shash_export($arg1, $arg2, (int (*)(struct shash_desc*, void*))$arg3)")
  public static int __crypto_shash_export(Ptr<shash_desc> desc, Ptr<?> out, Ptr<?> export) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_shash_import($arg1, (const void *)$arg2, (int (*)(struct shash_desc*, const void*))$arg3)")
  public static int __crypto_shash_import(Ptr<shash_desc> desc, Ptr<?> in, Ptr<?> _import) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__crypto_xor($arg1, (const u8 *)$arg2, (const u8 *)$arg3, $arg4)")
  public static void __crypto_xor(Ptr<java.lang.Character> dst, Ptr<java.lang.Character> src1,
      Ptr<java.lang.Character> src2, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_acomp_alloc_streams(Ptr<crypto_acomp_streams> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_acomp_compress(Ptr<acomp_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_acomp_decompress(Ptr<acomp_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_acomp_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int crypto_acomp_extsize(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_acomp_free_streams(Ptr<crypto_acomp_streams> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_acomp_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_acomp_stream> crypto_acomp_lock_stream_bh(Ptr<crypto_acomp_streams> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_acomp_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_acomp_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_aead_decrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_aead_encrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_aead_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_aead_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_aead_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_aead_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_aead_setauthsize(Ptr<crypto_aead> tfm, @Unsigned int authsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_aead_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_aead_setkey(Ptr<crypto_aead> tfm, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_aead_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_aes_decrypt($arg1, $arg2, (const u8 *)$arg3)")
  public static void crypto_aes_decrypt(Ptr<crypto_tfm> tfm, Ptr<java.lang.Character> out,
      Ptr<java.lang.Character> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_aes_encrypt($arg1, $arg2, (const u8 *)$arg3)")
  public static void crypto_aes_encrypt(Ptr<crypto_tfm> tfm, Ptr<java.lang.Character> out,
      Ptr<java.lang.Character> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_aes_set_key($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_aes_set_key(Ptr<crypto_tfm> tfm, Ptr<java.lang.Character> in_key,
      @Unsigned int key_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_digest(Ptr<ahash_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_ahash_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_export(Ptr<ahash_request> req, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_export_core(Ptr<ahash_request> req, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int crypto_ahash_extsize(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_finup(Ptr<ahash_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_ahash_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ahash_import($arg1, (const void *)$arg2)")
  public static int crypto_ahash_import(Ptr<ahash_request> req, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ahash_import_core($arg1, (const void *)$arg2)")
  public static int crypto_ahash_import_core(Ptr<ahash_request> req, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_init(Ptr<ahash_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ahash_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_ahash_setkey(Ptr<crypto_ahash> tfm, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_ahash_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ahash_update(Ptr<ahash_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_akcipher_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_akcipher_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_akcipher_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_akcipher_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_akcipher_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_akcipher_sync_decrypt($arg1, (const void *)$arg2, $arg3, $arg4, $arg5)")
  public static int crypto_akcipher_sync_decrypt(Ptr<crypto_akcipher> tfm, Ptr<?> src,
      @Unsigned int slen, Ptr<?> dst, @Unsigned int dlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_akcipher_sync_encrypt($arg1, (const void *)$arg2, $arg3, $arg4, $arg5)")
  public static int crypto_akcipher_sync_encrypt(Ptr<crypto_akcipher> tfm, Ptr<?> src,
      @Unsigned int slen, Ptr<?> dst, @Unsigned int dlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_akcipher_sync_post(Ptr<crypto_akcipher_sync_data> data, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_akcipher_sync_prep(Ptr<crypto_akcipher_sync_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int crypto_alg_extsize(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_alg_finish_registration(Ptr<crypto_alg> alg,
      Ptr<list_head> algs_to_put) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alg_lookup((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_alg> crypto_alg_lookup(String name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alg_mod_lookup((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_alg> crypto_alg_mod_lookup(String name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_alg_put(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alg_tested((const u8 *)$arg1, $arg2)")
  public static void crypto_alg_tested(String name, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_algapi_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_algapi_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_acomp((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_acomp> crypto_alloc_acomp(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_acomp_node((const u8 *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<crypto_acomp> crypto_alloc_acomp_node(String alg_name, @Unsigned int type,
      @Unsigned int mask, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_aead((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_aead> crypto_alloc_aead(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_ahash((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_ahash> crypto_alloc_ahash(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_akcipher((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_akcipher> crypto_alloc_akcipher(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_base((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_tfm> crypto_alloc_base(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_kpp((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_kpp> crypto_alloc_kpp(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_lskcipher((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_lskcipher> crypto_alloc_lskcipher(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_rng((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_rng> crypto_alloc_rng(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_shash((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_shash> crypto_alloc_shash(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_sig((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_sig> crypto_alloc_sig(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_skcipher((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_skcipher> crypto_alloc_skcipher(String alg_name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_sync_skcipher((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_sync_skcipher> crypto_alloc_sync_skcipher(String alg_name,
      @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_alloc_tfm_node((const u8 *)$arg1, (const struct crypto_type *)$arg2, $arg3, $arg4, $arg5)")
  public static Ptr<?> crypto_alloc_tfm_node(String alg_name, Ptr<crypto_type> frontend,
      @Unsigned int type, @Unsigned int mask, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)crypto_attr_alg_name($arg1))")
  public static String crypto_attr_alg_name(Ptr<rtattr> rta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cbc_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cbc_decrypt($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int crypto_cbc_decrypt(Ptr<crypto_lskcipher> tfm, Ptr<java.lang.Character> src,
      Ptr<java.lang.Character> dst, @Unsigned int len, Ptr<java.lang.Character> iv,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cbc_decrypt_inplace(Ptr<crypto_lskcipher> tfm,
      Ptr<java.lang.Character> src, @Unsigned int nbytes, Ptr<java.lang.Character> iv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cbc_decrypt_segment($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static int crypto_cbc_decrypt_segment(Ptr<crypto_lskcipher> tfm,
      Ptr<java.lang.Character> src, Ptr<java.lang.Character> dst, @Unsigned int nbytes,
      Ptr<java.lang.Character> oiv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cbc_encrypt($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int crypto_cbc_encrypt(Ptr<crypto_lskcipher> tfm, Ptr<java.lang.Character> src,
      Ptr<java.lang.Character> dst, @Unsigned int len, Ptr<java.lang.Character> iv,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cbc_encrypt_inplace(Ptr<crypto_lskcipher> tfm,
      Ptr<java.lang.Character> src, @Unsigned int nbytes, Ptr<java.lang.Character> oiv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cbc_encrypt_segment($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static int crypto_cbc_encrypt_segment(Ptr<crypto_lskcipher> tfm,
      Ptr<java.lang.Character> src, Ptr<java.lang.Character> dst, @Unsigned int nbytes,
      Ptr<java.lang.Character> iv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_cbc_module_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cbc_module_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_check_alg(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_check_attr_type(Ptr<Ptr<rtattr>> tb, @Unsigned int type,
      Ptr<java.lang. @Unsigned Integer> mask_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cipher_decrypt_one($arg1, $arg2, (const u8 *)$arg3)")
  public static void crypto_cipher_decrypt_one(Ptr<crypto_cipher> tfm, Ptr<java.lang.Character> dst,
      Ptr<java.lang.Character> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cipher_encrypt_one($arg1, $arg2, (const u8 *)$arg3)")
  public static void crypto_cipher_encrypt_one(Ptr<crypto_cipher> tfm, Ptr<java.lang.Character> dst,
      Ptr<java.lang.Character> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cipher_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_cipher_setkey(Ptr<crypto_cipher> tfm, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_ahash> crypto_clone_ahash(Ptr<crypto_ahash> hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_cipher> crypto_clone_cipher(Ptr<crypto_cipher> cipher) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_shash> crypto_clone_shash(Ptr<crypto_shash> hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_clone_tfm((const struct crypto_type *)$arg1, $arg2)")
  public static Ptr<?> crypto_clone_tfm(Ptr<crypto_type> frontend, Ptr<crypto_tfm> otfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_create_tfm_node($arg1, (const struct crypto_type *)$arg2, $arg3)")
  public static Ptr<?> crypto_create_tfm_node(Ptr<crypto_alg> alg, Ptr<crypto_type> frontend,
      int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ctr_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ctr_crypt(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_ctr_module_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ctr_module_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cts_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cts_decrypt(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_cts_decrypt_done(Ptr<?> data, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cts_encrypt(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_cts_encrypt_done(Ptr<?> data, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_cts_exit_tfm(Ptr<crypto_skcipher> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_cts_free(Ptr<skcipher_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cts_init_tfm(Ptr<crypto_skcipher> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_cts_module_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_cts_module_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_cts_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_cts_setkey(Ptr<crypto_skcipher> parent, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_del_default_rng() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_async_request> crypto_dequeue_request(Ptr<crypto_queue> queue) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_destroy_alg(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_destroy_instance(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_destroy_instance_workfn(Ptr<work_struct> w) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_destroy_tfm(Ptr<?> mem, Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_dh_decode_key((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_dh_decode_key(String buf, @Unsigned int len, Ptr<dh> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_dh_encode_key($arg1, $arg2, (const struct dh *)$arg3)")
  public static int crypto_dh_encode_key(String buf, @Unsigned int len, Ptr<dh> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_dh_key_len((const struct dh *)$arg1)")
  public static @Unsigned int crypto_dh_key_len(Ptr<dh> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_drop_spawn(Ptr<crypto_spawn> spawn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ecb_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ecb_decrypt2($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int crypto_ecb_decrypt2(Ptr<crypto_lskcipher> tfm, Ptr<java.lang.Character> src,
      Ptr<java.lang.Character> dst, @Unsigned int len, Ptr<java.lang.Character> iv,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ecb_encrypt2($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int crypto_ecb_encrypt2(Ptr<crypto_lskcipher> tfm, Ptr<java.lang.Character> src,
      Ptr<java.lang.Character> dst, @Unsigned int len, Ptr<java.lang.Character> iv,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_ecb_module_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_ecb_module_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ecdh_decode_key((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_ecdh_decode_key(String buf, @Unsigned int len, Ptr<ecdh> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ecdh_encode_key($arg1, $arg2, (const struct ecdh *)$arg3)")
  public static int crypto_ecdh_encode_key(String buf, @Unsigned int len, Ptr<ecdh> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ecdh_key_len((const struct ecdh *)$arg1)")
  public static @Unsigned int crypto_ecdh_key_len(Ptr<ecdh> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_ecdh_shared_secret($arg1, $arg2, (const long long unsigned int *)$arg3, (const long long unsigned int *)$arg4, $arg5)")
  public static int crypto_ecdh_shared_secret(@Unsigned int curve_id, @Unsigned int ndigits,
      Ptr<java.lang. @Unsigned Long> private_key, Ptr<java.lang. @Unsigned Long> public_key,
      Ptr<java.lang. @Unsigned Long> secret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_enqueue_request(Ptr<crypto_queue> queue,
      Ptr<crypto_async_request> request) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_enqueue_request_head(Ptr<crypto_queue> queue,
      Ptr<crypto_async_request> request) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_exit_ahash_using_shash(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_exit_proc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_exit_scomp_ops_async(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_find_alg((const u8 *)$arg1, (const struct crypto_type *)$arg2, $arg3, $arg4)")
  public static Ptr<crypto_alg> crypto_find_alg(String alg_name, Ptr<crypto_type> frontend,
      @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_free_alg(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_free_cb(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_base_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_gcm_create_common($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static int crypto_gcm_create_common(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb,
      String ctr_name, String ghash_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_decrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_encrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_gcm_exit_tfm(Ptr<crypto_aead> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_gcm_free(Ptr<aead_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_gcm_init_common(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_init_tfm(Ptr<crypto_aead> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_gcm_module_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_module_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_setauthsize(Ptr<crypto_aead> tfm, @Unsigned int authsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_gcm_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_gcm_setkey(Ptr<crypto_aead> aead, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_gcm_verify(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_attr_type> crypto_get_attr_type(Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_get_default_rng() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_aead($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_aead(Ptr<crypto_aead_spawn> spawn, Ptr<crypto_instance> inst,
      String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_ahash($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_ahash(Ptr<crypto_ahash_spawn> spawn, Ptr<crypto_instance> inst,
      String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_akcipher($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_akcipher(Ptr<crypto_akcipher_spawn> spawn,
      Ptr<crypto_instance> inst, String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_kpp($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_kpp(Ptr<crypto_kpp_spawn> spawn, Ptr<crypto_instance> inst,
      String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_lskcipher($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_lskcipher(Ptr<crypto_lskcipher_spawn> spawn,
      Ptr<crypto_instance> inst, String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_shash($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_shash(Ptr<crypto_shash_spawn> spawn, Ptr<crypto_instance> inst,
      String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_sig($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_sig(Ptr<crypto_sig_spawn> spawn, Ptr<crypto_instance> inst,
      String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_skcipher($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_skcipher(Ptr<crypto_skcipher_spawn> spawn,
      Ptr<crypto_instance> inst, String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_grab_spawn($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int crypto_grab_spawn(Ptr<crypto_spawn> spawn, Ptr<crypto_instance> inst,
      String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_has_aead((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_has_aead(String alg_name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_has_ahash((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_has_ahash(String alg_name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_has_alg((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_has_alg(String name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_has_kpp((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_has_kpp(String alg_name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_has_shash((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_has_shash(String alg_name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_has_skcipher((const u8 *)$arg1, $arg2, $arg3)")
  public static int crypto_has_skcipher(String alg_name, @Unsigned int type, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean crypto_hash_alg_has_setkey(Ptr<hash_alg_common> halg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hash_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_hash_digest(Ptr<crypto_ahash> tfm, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hash_walk_done(Ptr<crypto_hash_walk> walk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hash_walk_first(Ptr<ahash_request> req, Ptr<crypto_hash_walk> walk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_hkdf_module_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hkdf_module_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha1_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_hmac_sha1_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha1_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha1_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha1_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha1_import($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha1_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha1_import_core($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha1_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha1_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha1_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha1_setkey(Ptr<crypto_shash> tfm, Ptr<java.lang.Character> raw_key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha1_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha1_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha224_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_hmac_sha224_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha224_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha224_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha224_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha224_import($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha224_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha224_import_core($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha224_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha224_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha224_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha224_setkey(Ptr<crypto_shash> tfm,
      Ptr<java.lang.Character> raw_key, @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha224_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha224_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha256_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_hmac_sha256_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha256_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha256_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha256_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha256_import($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha256_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha256_import_core($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha256_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha256_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha256_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha256_setkey(Ptr<crypto_shash> tfm,
      Ptr<java.lang.Character> raw_key, @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha256_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha256_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha384_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_hmac_sha384_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha384_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha384_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha384_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha384_import($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha384_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha384_import_core($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha384_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha384_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha384_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha384_setkey(Ptr<crypto_shash> tfm,
      Ptr<java.lang.Character> raw_key, @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha384_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha384_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha512_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_hmac_sha512_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha512_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha512_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha512_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha512_import($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha512_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha512_import_core($arg1, (const void *)$arg2)")
  public static int crypto_hmac_sha512_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_hmac_sha512_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha512_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha512_setkey(Ptr<crypto_shash> tfm,
      Ptr<java.lang.Character> raw_key, @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_hmac_sha512_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_hmac_sha512_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_inc(Ptr<java.lang.Character> a, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_init_lskcipher_ops_sg(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_init_proc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_init_queue(Ptr<crypto_queue> queue, @Unsigned int max_qlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_init_scomp_ops_async(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_kdf108_ctr_generate($arg1, (const struct kvec *)$arg2, $arg3, $arg4, $arg5)")
  public static int crypto_kdf108_ctr_generate(Ptr<crypto_shash> kmd, Ptr<kvec> info,
      @Unsigned int info_nvec, Ptr<java.lang.Character> dst, @Unsigned int dlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_kdf108_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_kdf108_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_kdf108_setkey($arg1, (const u8 *)$arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static int crypto_kdf108_setkey(Ptr<crypto_shash> kmd, Ptr<java.lang.Character> key,
      @Unsigned long keylen, Ptr<java.lang.Character> ikm, @Unsigned long ikmlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_kfunc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_kpp_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_kpp_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_kpp_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_kpp_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_kpp_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_larval_alloc((const u8 *)$arg1, $arg2, $arg3)")
  public static Ptr<crypto_larval> crypto_larval_alloc(String name, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_larval_destroy(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_larval_kill(Ptr<crypto_larval> larval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_alg> crypto_larval_wait(Ptr<crypto_alg> alg, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_lookup_template((const u8 *)$arg1)")
  public static Ptr<crypto_template> crypto_lookup_template(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_lskcipher_crypt_sg($arg1, (int (*)(struct crypto_lskcipher*, const u8*, u8*, unsigned int, u8*, unsigned int))$arg2)")
  public static int crypto_lskcipher_crypt_sg(Ptr<skcipher_request> req, Ptr<?> crypt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_lskcipher_crypt_unaligned($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5, (int (*)(struct crypto_lskcipher*, const u8*, u8*, unsigned int, u8*, unsigned int))$arg6)")
  public static int crypto_lskcipher_crypt_unaligned(Ptr<crypto_lskcipher> tfm,
      Ptr<java.lang.Character> src, Ptr<java.lang.Character> dst, @Unsigned int len,
      Ptr<java.lang.Character> iv, Ptr<?> crypt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_lskcipher_decrypt($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static int crypto_lskcipher_decrypt(Ptr<crypto_lskcipher> tfm,
      Ptr<java.lang.Character> src, Ptr<java.lang.Character> dst, @Unsigned int len,
      Ptr<java.lang.Character> iv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_lskcipher_decrypt_sg(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_lskcipher_encrypt($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static int crypto_lskcipher_encrypt(Ptr<crypto_lskcipher> tfm,
      Ptr<java.lang.Character> src, Ptr<java.lang.Character> dst, @Unsigned int len,
      Ptr<java.lang.Character> iv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_lskcipher_encrypt_sg(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_lskcipher_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_lskcipher_exit_tfm_sg(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_lskcipher_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_lskcipher_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_lskcipher_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_lskcipher_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_lskcipher_setkey(Ptr<crypto_lskcipher> tfm, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_lskcipher_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_alg> crypto_mod_get(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_mod_put(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_null_mod_fini() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_null_mod_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_probing_notify(@Unsigned long val, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_put_default_rng() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_acomp(Ptr<acomp_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_acomps(Ptr<acomp_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_aead(Ptr<aead_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_aeads(Ptr<aead_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_ahash(Ptr<ahash_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_ahashes(Ptr<ahash_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_akcipher(Ptr<akcipher_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_alg(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_algs(Ptr<crypto_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_instance(Ptr<crypto_template> tmpl, Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_kpp(Ptr<kpp_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_lskcipher(Ptr<lskcipher_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_lskciphers(Ptr<lskcipher_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_notifier(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_rng(Ptr<rng_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_rngs(Ptr<rng_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_scomp(Ptr<scomp_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_scomps(Ptr<scomp_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_shash(Ptr<shash_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_shashes(Ptr<shash_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_sig(Ptr<sig_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_skcipher(Ptr<skcipher_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_skciphers(Ptr<skcipher_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_template(Ptr<crypto_template> tmpl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_register_templates(Ptr<crypto_template> tmpls, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_remove_final(Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_remove_instance(Ptr<crypto_instance> inst, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_remove_spawns(Ptr<crypto_alg> alg, Ptr<list_head> list,
      Ptr<crypto_alg> nalg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_req_done(Ptr<?> data, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_async_request> crypto_request_clone(Ptr<crypto_async_request> req,
      @Unsigned long total, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc3686_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc3686_crypt(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_rfc3686_exit_tfm(Ptr<crypto_skcipher> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_rfc3686_free(Ptr<skcipher_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc3686_init_tfm(Ptr<crypto_skcipher> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_rfc3686_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_rfc3686_setkey(Ptr<crypto_skcipher> parent, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4106_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<aead_request> crypto_rfc4106_crypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4106_decrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4106_encrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_rfc4106_exit_tfm(Ptr<crypto_aead> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_rfc4106_free(Ptr<aead_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4106_init_tfm(Ptr<crypto_aead> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4106_setauthsize(Ptr<crypto_aead> parent, @Unsigned int authsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_rfc4106_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_rfc4106_setkey(Ptr<crypto_aead> parent, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4543_create(Ptr<crypto_template> tmpl, Ptr<Ptr<rtattr>> tb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4543_crypt(Ptr<aead_request> req, boolean enc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4543_decrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4543_encrypt(Ptr<aead_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_rfc4543_exit_tfm(Ptr<crypto_aead> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_rfc4543_free(Ptr<aead_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4543_init_tfm(Ptr<crypto_aead> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rfc4543_setauthsize(Ptr<crypto_aead> parent, @Unsigned int authsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_rfc4543_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_rfc4543_setkey(Ptr<crypto_aead> parent, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rng_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_rng_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_rng_reset($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_rng_reset(Ptr<crypto_rng> tfm, Ptr<java.lang.Character> seed,
      @Unsigned int slen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_rng_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_schedule_test(Ptr<crypto_larval> larval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_scomp_destroy(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_scomp_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_scomp_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_scomp_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha1_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_sha1_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha1_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha1_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha1_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha1_import($arg1, (const void *)$arg2)")
  public static int crypto_sha1_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha1_import_core($arg1, (const void *)$arg2)")
  public static int crypto_sha1_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha1_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_sha1_mod_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha1_mod_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha1_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_sha1_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha224_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_sha224_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha224_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha224_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha224_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha224_import($arg1, (const void *)$arg2)")
  public static int crypto_sha224_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha224_import_core($arg1, (const void *)$arg2)")
  public static int crypto_sha224_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha224_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha224_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_sha224_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha256_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_sha256_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha256_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha256_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha256_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha256_import($arg1, (const void *)$arg2)")
  public static int crypto_sha256_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha256_import_core($arg1, (const void *)$arg2)")
  public static int crypto_sha256_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha256_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_sha256_mod_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha256_mod_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha256_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_sha256_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha384_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_sha384_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha384_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha384_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha384_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha384_import($arg1, (const void *)$arg2)")
  public static int crypto_sha384_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha384_import_core($arg1, (const void *)$arg2)")
  public static int crypto_sha384_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha384_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha384_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_sha384_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha3_finup($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_sha3_finup(Ptr<shash_desc> desc, Ptr<java.lang.Character> src,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha3_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha3_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_sha3_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha512_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_sha512_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha512_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha512_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha512_final(Ptr<shash_desc> desc, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha512_import($arg1, (const void *)$arg2)")
  public static int crypto_sha512_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha512_import_core($arg1, (const void *)$arg2)")
  public static int crypto_sha512_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha512_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_sha512_mod_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sha512_mod_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_sha512_update($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_sha512_update(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_shash_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_shash_digest(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_shash_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_shash_export(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_shash_export_core(Ptr<shash_desc> desc, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_shash_finup((restrict struct shash_desc*)$arg1, (const u8 *)$arg2, $arg3, (restrict u8*)$arg4)")
  public static int crypto_shash_finup(Ptr<shash_desc> desc, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_shash_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_shash_import($arg1, (const void *)$arg2)")
  public static int crypto_shash_import(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_shash_import_core($arg1, (const void *)$arg2)")
  public static int crypto_shash_import_core(Ptr<shash_desc> desc, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_shash_init(Ptr<shash_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_shash_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_shash_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_shash_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_shash_setkey(Ptr<crypto_shash> tfm, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_shash_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_shash_tfm_digest($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int crypto_shash_tfm_digest(Ptr<crypto_shash> tfm, Ptr<java.lang.Character> data,
      @Unsigned int len, Ptr<java.lang.Character> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_shoot_alg(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_sig_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_sig_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sig_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_sig_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_sig_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_skcipher_decrypt(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_skcipher_encrypt(Ptr<skcipher_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_skcipher_exit_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_skcipher_export(Ptr<skcipher_request> req, Ptr<?> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int crypto_skcipher_extsize(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_skcipher_free_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_skcipher_import($arg1, (const void *)$arg2)")
  public static int crypto_skcipher_import(Ptr<skcipher_request> req, Ptr<?> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_skcipher_init_tfm(Ptr<crypto_tfm> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_skcipher_report(Ptr<sk_buff> skb, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_skcipher_setkey($arg1, (const u8 *)$arg2, $arg3)")
  public static int crypto_skcipher_setkey(Ptr<crypto_skcipher> tfm, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_skcipher_show(Ptr<seq_file> m, Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_alg> crypto_spawn_alg(Ptr<crypto_spawn> spawn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<crypto_tfm> crypto_spawn_tfm(Ptr<crypto_spawn> spawn, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> crypto_spawn_tfm2(Ptr<crypto_spawn> spawn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("crypto_type_has_alg((const u8 *)$arg1, (const struct crypto_type *)$arg2, $arg3, $arg4)")
  public static int crypto_type_has_alg(String name, Ptr<crypto_type> frontend, @Unsigned int type,
      @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_acomp(Ptr<acomp_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_acomps(Ptr<acomp_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_aead(Ptr<aead_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_aeads(Ptr<aead_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_ahash(Ptr<ahash_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_ahashes(Ptr<ahash_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_akcipher(Ptr<akcipher_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_alg(Ptr<crypto_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_algs(Ptr<crypto_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_instance(Ptr<crypto_instance> inst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_kpp(Ptr<kpp_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_lskcipher(Ptr<lskcipher_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_lskciphers(Ptr<lskcipher_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int crypto_unregister_notifier(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_rng(Ptr<rng_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_rngs(Ptr<rng_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_scomp(Ptr<scomp_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_scomps(Ptr<scomp_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_shash(Ptr<shash_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_shashes(Ptr<shash_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_sig(Ptr<sig_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_skcipher(Ptr<skcipher_alg> alg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_skciphers(Ptr<skcipher_alg> algs, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_template(Ptr<crypto_template> tmpl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void crypto_unregister_templates(Ptr<crypto_template> tmpls, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_aes_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_aes_ctx extends Struct {
    public @Unsigned int @Size(60) [] key_enc;

    public @Unsigned int @Size(60) [] key_dec;

    public @Unsigned int key_length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_async_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_async_request extends Struct {
    public list_head list;

    public @OriginalName("crypto_completion_t") Ptr<?> complete;

    public Ptr<?> data;

    public Ptr<crypto_tfm> tfm;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_tfm"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_tfm extends Struct {
    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned int crt_flags;

    public int node;

    public Ptr<crypto_tfm> fb;

    public Ptr<?> exit;

    public Ptr<crypto_alg> __crt_alg;

    public Ptr<?> @Size(0) [] __crt_ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_alg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_alg extends Struct {
    public list_head cra_list;

    public list_head cra_users;

    public @Unsigned int cra_flags;

    public @Unsigned int cra_blocksize;

    public @Unsigned int cra_ctxsize;

    public @Unsigned int cra_alignmask;

    public @Unsigned int cra_reqsize;

    public int cra_priority;

    public @OriginalName("refcount_t") refcount_struct cra_refcnt;

    public char @Size(128) [] cra_name;

    public char @Size(128) [] cra_driver_name;

    public Ptr<crypto_type> cra_type;

    public cra_u_of_crypto_alg cra_u;

    public Ptr<?> cra_init;

    public Ptr<?> cra_exit;

    public Ptr<?> cra_destroy;

    public Ptr<module> cra_module;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_type extends Struct {
    public Ptr<?> ctxsize;

    public Ptr<?> extsize;

    public Ptr<?> init_tfm;

    public Ptr<?> show;

    public Ptr<?> report;

    public Ptr<?> free;

    public Ptr<?> destroy;

    public @Unsigned int type;

    public @Unsigned int maskclear;

    public @Unsigned int maskset;

    public @Unsigned int tfmsize;

    public @Unsigned int algsize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_acomp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_acomp extends Struct {
    public Ptr<?> compress;

    public Ptr<?> decompress;

    public @Unsigned int reqsize;

    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_wait"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_wait extends Struct {
    public completion completion;

    public int err;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_acomp_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_acomp_ctx extends Struct {
    public Ptr<crypto_acomp> acomp;

    public Ptr<acomp_req> req;

    public crypto_wait wait;

    public Ptr<java.lang.Character> buffer;

    public mutex mutex;

    public boolean is_sleepable;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_skcipher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_skcipher extends Struct {
    public @Unsigned int reqsize;

    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_sync_skcipher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_sync_skcipher extends Struct {
    public crypto_skcipher base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_shash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_shash extends Struct {
    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_kpp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_kpp extends Struct {
    public @Unsigned int reqsize;

    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_ahash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_ahash extends Struct {
    public boolean using_shash;

    public @Unsigned int statesize;

    public @Unsigned int reqsize;

    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_spawn extends Struct {
    public list_head list;

    public Ptr<crypto_alg> alg;

    @InlineUnion(29257)
    public Ptr<crypto_instance> inst;

    @InlineUnion(29257)
    public Ptr<crypto_spawn> next;

    public Ptr<crypto_type> frontend;

    public @Unsigned int mask;

    public boolean dead;

    public boolean registered;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_instance"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_instance extends Struct {
    public crypto_alg alg;

    public Ptr<crypto_template> tmpl;

    @InlineUnion(29247)
    public hlist_node list;

    @InlineUnion(29247)
    public Ptr<crypto_spawn> spawns;

    public Ptr<?> @Size(0) [] __ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_template"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_template extends Struct {
    public list_head list;

    public hlist_head instances;

    public hlist_head dead;

    public Ptr<module> module;

    public work_struct free_work;

    public Ptr<?> create;

    public char @Size(128) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_larval"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_larval extends Struct {
    public crypto_alg alg;

    public Ptr<crypto_alg> adult;

    public completion completion;

    public @Unsigned int mask;

    public boolean test_started;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_cipher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_cipher extends Struct {
    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_queue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_queue extends Struct {
    public list_head list;

    public Ptr<list_head> backlog;

    public @Unsigned int qlen;

    public @Unsigned int max_qlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_attr_alg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_attr_alg extends Struct {
    public char @Size(128) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_attr_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_attr_type extends Struct {
    public @Unsigned int type;

    public @Unsigned int mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_aead"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_aead extends Struct {
    public @Unsigned int authsize;

    public @Unsigned int reqsize;

    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_aead_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_aead_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum crypto_attr_type_t"
  )
  public enum crypto_attr_type_t implements Enum<crypto_attr_type_t>, TypedEnum<crypto_attr_type_t, java.lang. @Unsigned Integer> {
    /**
     * {@code CRYPTOCFGA_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "CRYPTOCFGA_UNSPEC"
    )
    CRYPTOCFGA_UNSPEC,

    /**
     * {@code CRYPTOCFGA_PRIORITY_VAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "CRYPTOCFGA_PRIORITY_VAL"
    )
    CRYPTOCFGA_PRIORITY_VAL,

    /**
     * {@code CRYPTOCFGA_REPORT_LARVAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "CRYPTOCFGA_REPORT_LARVAL"
    )
    CRYPTOCFGA_REPORT_LARVAL,

    /**
     * {@code CRYPTOCFGA_REPORT_HASH = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CRYPTOCFGA_REPORT_HASH"
    )
    CRYPTOCFGA_REPORT_HASH,

    /**
     * {@code CRYPTOCFGA_REPORT_BLKCIPHER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "CRYPTOCFGA_REPORT_BLKCIPHER"
    )
    CRYPTOCFGA_REPORT_BLKCIPHER,

    /**
     * {@code CRYPTOCFGA_REPORT_AEAD = 5}
     */
    @EnumMember(
        value = 5L,
        name = "CRYPTOCFGA_REPORT_AEAD"
    )
    CRYPTOCFGA_REPORT_AEAD,

    /**
     * {@code CRYPTOCFGA_REPORT_COMPRESS = 6}
     */
    @EnumMember(
        value = 6L,
        name = "CRYPTOCFGA_REPORT_COMPRESS"
    )
    CRYPTOCFGA_REPORT_COMPRESS,

    /**
     * {@code CRYPTOCFGA_REPORT_RNG = 7}
     */
    @EnumMember(
        value = 7L,
        name = "CRYPTOCFGA_REPORT_RNG"
    )
    CRYPTOCFGA_REPORT_RNG,

    /**
     * {@code CRYPTOCFGA_REPORT_CIPHER = 8}
     */
    @EnumMember(
        value = 8L,
        name = "CRYPTOCFGA_REPORT_CIPHER"
    )
    CRYPTOCFGA_REPORT_CIPHER,

    /**
     * {@code CRYPTOCFGA_REPORT_AKCIPHER = 9}
     */
    @EnumMember(
        value = 9L,
        name = "CRYPTOCFGA_REPORT_AKCIPHER"
    )
    CRYPTOCFGA_REPORT_AKCIPHER,

    /**
     * {@code CRYPTOCFGA_REPORT_KPP = 10}
     */
    @EnumMember(
        value = 10L,
        name = "CRYPTOCFGA_REPORT_KPP"
    )
    CRYPTOCFGA_REPORT_KPP,

    /**
     * {@code CRYPTOCFGA_REPORT_ACOMP = 11}
     */
    @EnumMember(
        value = 11L,
        name = "CRYPTOCFGA_REPORT_ACOMP"
    )
    CRYPTOCFGA_REPORT_ACOMP,

    /**
     * {@code CRYPTOCFGA_STAT_LARVAL = 12}
     */
    @EnumMember(
        value = 12L,
        name = "CRYPTOCFGA_STAT_LARVAL"
    )
    CRYPTOCFGA_STAT_LARVAL,

    /**
     * {@code CRYPTOCFGA_STAT_HASH = 13}
     */
    @EnumMember(
        value = 13L,
        name = "CRYPTOCFGA_STAT_HASH"
    )
    CRYPTOCFGA_STAT_HASH,

    /**
     * {@code CRYPTOCFGA_STAT_BLKCIPHER = 14}
     */
    @EnumMember(
        value = 14L,
        name = "CRYPTOCFGA_STAT_BLKCIPHER"
    )
    CRYPTOCFGA_STAT_BLKCIPHER,

    /**
     * {@code CRYPTOCFGA_STAT_AEAD = 15}
     */
    @EnumMember(
        value = 15L,
        name = "CRYPTOCFGA_STAT_AEAD"
    )
    CRYPTOCFGA_STAT_AEAD,

    /**
     * {@code CRYPTOCFGA_STAT_COMPRESS = 16}
     */
    @EnumMember(
        value = 16L,
        name = "CRYPTOCFGA_STAT_COMPRESS"
    )
    CRYPTOCFGA_STAT_COMPRESS,

    /**
     * {@code CRYPTOCFGA_STAT_RNG = 17}
     */
    @EnumMember(
        value = 17L,
        name = "CRYPTOCFGA_STAT_RNG"
    )
    CRYPTOCFGA_STAT_RNG,

    /**
     * {@code CRYPTOCFGA_STAT_CIPHER = 18}
     */
    @EnumMember(
        value = 18L,
        name = "CRYPTOCFGA_STAT_CIPHER"
    )
    CRYPTOCFGA_STAT_CIPHER,

    /**
     * {@code CRYPTOCFGA_STAT_AKCIPHER = 19}
     */
    @EnumMember(
        value = 19L,
        name = "CRYPTOCFGA_STAT_AKCIPHER"
    )
    CRYPTOCFGA_STAT_AKCIPHER,

    /**
     * {@code CRYPTOCFGA_STAT_KPP = 20}
     */
    @EnumMember(
        value = 20L,
        name = "CRYPTOCFGA_STAT_KPP"
    )
    CRYPTOCFGA_STAT_KPP,

    /**
     * {@code CRYPTOCFGA_STAT_ACOMP = 21}
     */
    @EnumMember(
        value = 21L,
        name = "CRYPTOCFGA_STAT_ACOMP"
    )
    CRYPTOCFGA_STAT_ACOMP,

    /**
     * {@code CRYPTOCFGA_REPORT_SIG = 22}
     */
    @EnumMember(
        value = 22L,
        name = "CRYPTOCFGA_REPORT_SIG"
    )
    CRYPTOCFGA_REPORT_SIG,

    /**
     * {@code __CRYPTOCFGA_MAX = 23}
     */
    @EnumMember(
        value = 23L,
        name = "__CRYPTOCFGA_MAX"
    )
    __CRYPTOCFGA_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_aead"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_aead extends Struct {
    public char @Size(64) [] type;

    public char @Size(64) [] geniv;

    public @Unsigned int blocksize;

    public @Unsigned int maxauthsize;

    public @Unsigned int ivsize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rng"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rng extends Struct {
    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_blkcipher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_blkcipher extends Struct {
    public char @Size(64) [] type;

    public char @Size(64) [] geniv;

    public @Unsigned int blocksize;

    public @Unsigned int min_keysize;

    public @Unsigned int max_keysize;

    public @Unsigned int ivsize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_lskcipher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_lskcipher extends Struct {
    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_lskcipher_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_lskcipher_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_cipher_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_cipher_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_skcipher_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_skcipher_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_hash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_hash extends Struct {
    public char @Size(64) [] type;

    public @Unsigned int blocksize;

    public @Unsigned int digestsize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_hash_walk"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_hash_walk extends Struct {
    public String data;

    public @Unsigned int offset;

    public @Unsigned int flags;

    public Ptr<page> pg;

    public @Unsigned int entrylen;

    public @Unsigned int total;

    public Ptr<scatterlist> sg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_ahash_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_ahash_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_shash_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_shash_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_akcipher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_akcipher extends Struct {
    public @Unsigned int reqsize;

    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_akcipher_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_akcipher_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_akcipher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_akcipher extends Struct {
    public char @Size(64) [] type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_akcipher_sync_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_akcipher_sync_data extends Struct {
    public Ptr<crypto_akcipher> tfm;

    public Ptr<?> src;

    public Ptr<?> dst;

    public @Unsigned int slen;

    public @Unsigned int dlen;

    public Ptr<akcipher_request> req;

    public crypto_wait cwait;

    public scatterlist sg;

    public Ptr<java.lang.Character> buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_sig"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_sig extends Struct {
    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_sig_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_sig_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_sig"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_sig extends Struct {
    public char @Size(64) [] type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_kpp_spawn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_kpp_spawn extends Struct {
    public crypto_spawn base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_kpp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_kpp extends Struct {
    public char @Size(64) [] type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_acomp_stream"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_acomp_stream extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<?> ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_acomp_streams"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_acomp_streams extends Struct {
    public Ptr<?> alloc_ctx;

    public Ptr<?> free_ctx;

    public Ptr<crypto_acomp_stream> streams;

    public work_struct stream_work;

    public @OriginalName("cpumask_t") cpumask stream_want;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_acomp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_acomp extends Struct {
    public char @Size(64) [] type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_scomp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_scomp extends Struct {
    public crypto_tfm base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_comp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_comp extends Struct {
    public char @Size(64) [] type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_test_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_test_param extends Struct {
    public char @Size(128) [] driver;

    public char @Size(128) [] alg;

    public @Unsigned int type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_cts_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_cts_ctx extends Struct {
    public Ptr<crypto_skcipher> child;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_cts_reqctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_cts_reqctx extends Struct {
    public scatterlist @Size(2) [] sg;

    public @Unsigned int offset;

    public skcipher_request subreq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rfc3686_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rfc3686_ctx extends Struct {
    public Ptr<crypto_skcipher> child;

    public char @Size(4) [] nonce;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rfc3686_req_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rfc3686_req_ctx extends Struct {
    public char @Size(16) [] iv;

    public skcipher_request subreq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_gcm_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_gcm_ctx extends Struct {
    public Ptr<crypto_skcipher> ctr;

    public Ptr<crypto_ahash> ghash;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rfc4106_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rfc4106_ctx extends Struct {
    public Ptr<crypto_aead> child;

    public char @Size(4) [] nonce;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rfc4106_req_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rfc4106_req_ctx extends Struct {
    public scatterlist @Size(3) [] src;

    public scatterlist @Size(3) [] dst;

    public aead_request subreq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rfc4543_instance_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rfc4543_instance_ctx extends Struct {
    public crypto_aead_spawn aead;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rfc4543_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rfc4543_ctx extends Struct {
    public Ptr<crypto_aead> child;

    public char @Size(4) [] nonce;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_rfc4543_req_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_rfc4543_req_ctx extends Struct {
    public aead_request subreq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_gcm_ghash_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_gcm_ghash_ctx extends Struct {
    public @Unsigned int cryptlen;

    public Ptr<scatterlist> src;

    public Ptr<?> complete;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_gcm_req_priv_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_gcm_req_priv_ctx extends Struct {
    public char @Size(16) [] iv;

    public char @Size(16) [] auth_tag;

    public char @Size(16) [] iauth_tag;

    public scatterlist @Size(3) [] src;

    public scatterlist @Size(3) [] dst;

    public scatterlist sg;

    public crypto_gcm_ghash_ctx ghash_ctx;

    public u_of_crypto_gcm_req_priv_ctx u;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct crypto_report_rng"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class crypto_report_rng extends Struct {
    public char @Size(64) [] type;

    public @Unsigned int seedsize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dh"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dh extends Struct {
    public Ptr<?> key;

    public Ptr<?> p;

    public Ptr<?> g;

    public @Unsigned int key_size;

    public @Unsigned int p_size;

    public @Unsigned int g_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ecdh"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ecdh extends Struct {
    public String key;

    public @Unsigned short key_size;
  }
}
