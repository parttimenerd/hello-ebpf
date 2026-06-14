/** Auto-generated */
package me.bechberger.ebpf.runtime;

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
 * Generated class for BPF runtime types that start with dpll
 */
@java.lang.SuppressWarnings("unused")
public final class DpllDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __dpll_pin_change_ntf(Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__dpll_pin_register($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4, $arg5)")
  public static int __dpll_pin_register(Ptr<dpll_device> dpll, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv, Ptr<?> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__dpll_pin_unregister($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4, $arg5)")
  public static void __dpll_pin_unregister(Ptr<dpll_device> dpll, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv, Ptr<?> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_cmd_pin_get_one(Ptr<sk_buff> msg, Ptr<dpll_pin> pin,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_device_change_ntf(Ptr<dpll_device> dpll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_device_create_ntf(Ptr<dpll_device> dpll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_device_delete_ntf(Ptr<dpll_device> dpll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_device_event_send(dpll_cmd event, Ptr<dpll_device> dpll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dpll_device> dpll_device_find_from_nlattr(Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dpll_device> dpll_device_get(@Unsigned long clock_id, @Unsigned int device_idx,
      Ptr<module> module) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dpll_device> dpll_device_get_by_id(int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_device_get_one(Ptr<dpll_device> dpll, Ptr<sk_buff> msg,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dpll_device_put(Ptr<dpll_device> dpll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_device_register($arg1, $arg2, (const struct dpll_device_ops*)$arg3, $arg4)")
  public static int dpll_device_register(Ptr<dpll_device> dpll, dpll_type type,
      Ptr<dpll_device_ops> ops, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_device_unregister($arg1, (const struct dpll_device_ops*)$arg2, $arg3)")
  public static void dpll_device_unregister(Ptr<dpll_device> dpll, Ptr<dpll_device_ops> ops,
      Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dpll_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_lock_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int dpll_lock_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_msg_add_pin_dplls(Ptr<sk_buff> msg, Ptr<dpll_pin> pin,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_msg_add_pin_esync(Ptr<sk_buff> msg, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ref> ref, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_msg_add_pin_freq(Ptr<sk_buff> msg, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ref> ref, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_msg_add_pin_parents(Ptr<sk_buff> msg, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ref> dpll_ref, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_msg_add_pin_ref_sync(Ptr<sk_buff> msg, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ref> ref, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_netdev_add_pin_handle($arg1, (const struct net_device*)$arg2)")
  public static int dpll_netdev_add_pin_handle(Ptr<sk_buff> msg, Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dpll_netdev_pin_clear(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_netdev_pin_handle_size((const struct net_device*)$arg1)")
  public static @Unsigned long dpll_netdev_pin_handle_size(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dpll_netdev_pin_set(Ptr<net_device> dev, Ptr<dpll_pin> dpll_pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_device_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_device_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_device_id_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_device_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_pin_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_pin_get_dumpit(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_pin_id_get_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_nl_pin_set_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dpll_pin_available(Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_change_ntf(Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_create_ntf(Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_delete_ntf(Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_esync_set(Ptr<dpll_pin> pin, Ptr<nlattr> a,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_event_send(dpll_cmd event, Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dpll_pin> dpll_pin_find(@Unsigned long clock_id, Ptr<nlattr> mod_name_attr,
      dpll_pin_type type, Ptr<nlattr> board_label, Ptr<nlattr> panel_label,
      Ptr<nlattr> package_label, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dpll_pin> dpll_pin_find_from_nlattr(Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_freq_set(Ptr<dpll_pin> pin, Ptr<nlattr> a,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_get($arg1, $arg2, $arg3, (const struct dpll_pin_properties*)$arg4)")
  public static Ptr<dpll_pin> dpll_pin_get(@Unsigned long clock_id, @Unsigned int pin_idx,
      Ptr<module> module, Ptr<dpll_pin_properties> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dpll_pin_on_dpll_priv(Ptr<dpll_device> dpll, Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dpll_pin_on_pin_priv(Ptr<dpll_pin> parent, Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_on_pin_register($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4)")
  public static int dpll_pin_on_pin_register(Ptr<dpll_pin> parent, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_on_pin_unregister($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4)")
  public static void dpll_pin_on_pin_unregister(Ptr<dpll_pin> parent, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_parent_device_set(Ptr<dpll_pin> pin, Ptr<nlattr> parent_nest,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_parent_pin_set(Ptr<dpll_pin> pin, Ptr<nlattr> parent_nest,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_phase_adj_set(Ptr<dpll_pin> pin, Ptr<nlattr> phase_adj_attr,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_post_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void dpll_pin_post_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_pre_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int dpll_pin_pre_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_prop_dup((const struct dpll_pin_properties*)$arg1, $arg2)")
  public static int dpll_pin_prop_dup(Ptr<dpll_pin_properties> src, Ptr<dpll_pin_properties> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dpll_pin_put(Ptr<dpll_pin> pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_ref_sync_pair_add(Ptr<dpll_pin> pin, Ptr<dpll_pin> ref_sync_pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_ref_sync_set(Ptr<dpll_pin> pin, Ptr<nlattr> nest,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_ref_sync_state_set($arg1, $arg2, (const enum dpll_pin_state)$arg3, $arg4)")
  public static int dpll_pin_ref_sync_state_set(Ptr<dpll_pin> pin, @Unsigned long ref_sync_pin_idx,
      dpll_pin_state state, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_register($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4)")
  public static int dpll_pin_register(Ptr<dpll_device> dpll, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dpll_pin_set_from_nlattr(Ptr<dpll_pin> pin, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pin_unregister($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4)")
  public static void dpll_pin_unregister(Ptr<dpll_device> dpll, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_post_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void dpll_post_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_pre_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static int dpll_pre_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dpll_priv(Ptr<dpll_device> dpll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_unlock_doit((const struct genl_split_ops*)$arg1, $arg2, $arg3)")
  public static void dpll_unlock_doit(Ptr<genl_split_ops> ops, Ptr<sk_buff> skb,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_xa_ref_dpll_add($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4, $arg5)")
  public static int dpll_xa_ref_dpll_add(Ptr<xarray> xa_dplls, Ptr<dpll_device> dpll,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv, Ptr<?> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dpll_pin_ref> dpll_xa_ref_dpll_first(Ptr<xarray> xa_refs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_xa_ref_pin_add($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4, $arg5)")
  public static int dpll_xa_ref_pin_add(Ptr<xarray> xa_pins, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv, Ptr<?> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dpll_xa_ref_pin_del($arg1, $arg2, (const struct dpll_pin_ops*)$arg3, $arg4, $arg5)")
  public static int dpll_xa_ref_pin_del(Ptr<xarray> xa_pins, Ptr<dpll_pin> pin,
      Ptr<dpll_pin_ops> ops, Ptr<?> priv, Ptr<?> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_mode"
  )
  public enum dpll_mode implements Enum<dpll_mode>, TypedEnum<dpll_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_MODE_MANUAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_MODE_MANUAL"
    )
    DPLL_MODE_MANUAL,

    /**
     * {@code DPLL_MODE_AUTOMATIC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_MODE_AUTOMATIC"
    )
    DPLL_MODE_AUTOMATIC,

    /**
     * {@code __DPLL_MODE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__DPLL_MODE_MAX"
    )
    __DPLL_MODE_MAX,

    /**
     * {@code DPLL_MODE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_MODE_MAX"
    )
    DPLL_MODE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_lock_status"
  )
  public enum dpll_lock_status implements Enum<dpll_lock_status>, TypedEnum<dpll_lock_status, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_LOCK_STATUS_UNLOCKED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_LOCK_STATUS_UNLOCKED"
    )
    DPLL_LOCK_STATUS_UNLOCKED,

    /**
     * {@code DPLL_LOCK_STATUS_LOCKED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_LOCK_STATUS_LOCKED"
    )
    DPLL_LOCK_STATUS_LOCKED,

    /**
     * {@code DPLL_LOCK_STATUS_LOCKED_HO_ACQ = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_LOCK_STATUS_LOCKED_HO_ACQ"
    )
    DPLL_LOCK_STATUS_LOCKED_HO_ACQ,

    /**
     * {@code DPLL_LOCK_STATUS_HOLDOVER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_LOCK_STATUS_HOLDOVER"
    )
    DPLL_LOCK_STATUS_HOLDOVER,

    /**
     * {@code __DPLL_LOCK_STATUS_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "__DPLL_LOCK_STATUS_MAX"
    )
    __DPLL_LOCK_STATUS_MAX,

    /**
     * {@code DPLL_LOCK_STATUS_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_LOCK_STATUS_MAX"
    )
    DPLL_LOCK_STATUS_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_lock_status_error"
  )
  public enum dpll_lock_status_error implements Enum<dpll_lock_status_error>, TypedEnum<dpll_lock_status_error, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_LOCK_STATUS_ERROR_NONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_LOCK_STATUS_ERROR_NONE"
    )
    DPLL_LOCK_STATUS_ERROR_NONE,

    /**
     * {@code DPLL_LOCK_STATUS_ERROR_UNDEFINED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_LOCK_STATUS_ERROR_UNDEFINED"
    )
    DPLL_LOCK_STATUS_ERROR_UNDEFINED,

    /**
     * {@code DPLL_LOCK_STATUS_ERROR_MEDIA_DOWN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_LOCK_STATUS_ERROR_MEDIA_DOWN"
    )
    DPLL_LOCK_STATUS_ERROR_MEDIA_DOWN,

    /**
     * {@code DPLL_LOCK_STATUS_ERROR_FRACTIONAL_FREQUENCY_OFFSET_TOO_HIGH = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_LOCK_STATUS_ERROR_FRACTIONAL_FREQUENCY_OFFSET_TOO_HIGH"
    )
    DPLL_LOCK_STATUS_ERROR_FRACTIONAL_FREQUENCY_OFFSET_TOO_HIGH,

    /**
     * {@code __DPLL_LOCK_STATUS_ERROR_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "__DPLL_LOCK_STATUS_ERROR_MAX"
    )
    __DPLL_LOCK_STATUS_ERROR_MAX,

    /**
     * {@code DPLL_LOCK_STATUS_ERROR_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_LOCK_STATUS_ERROR_MAX"
    )
    DPLL_LOCK_STATUS_ERROR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_type"
  )
  public enum dpll_type implements Enum<dpll_type>, TypedEnum<dpll_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_TYPE_PPS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_TYPE_PPS"
    )
    DPLL_TYPE_PPS,

    /**
     * {@code DPLL_TYPE_EEC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_TYPE_EEC"
    )
    DPLL_TYPE_EEC,

    /**
     * {@code __DPLL_TYPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__DPLL_TYPE_MAX"
    )
    __DPLL_TYPE_MAX,

    /**
     * {@code DPLL_TYPE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_TYPE_MAX"
    )
    DPLL_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_pin_type"
  )
  public enum dpll_pin_type implements Enum<dpll_pin_type>, TypedEnum<dpll_pin_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_PIN_TYPE_MUX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_PIN_TYPE_MUX"
    )
    DPLL_PIN_TYPE_MUX,

    /**
     * {@code DPLL_PIN_TYPE_EXT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_PIN_TYPE_EXT"
    )
    DPLL_PIN_TYPE_EXT,

    /**
     * {@code DPLL_PIN_TYPE_SYNCE_ETH_PORT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_PIN_TYPE_SYNCE_ETH_PORT"
    )
    DPLL_PIN_TYPE_SYNCE_ETH_PORT,

    /**
     * {@code DPLL_PIN_TYPE_INT_OSCILLATOR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_PIN_TYPE_INT_OSCILLATOR"
    )
    DPLL_PIN_TYPE_INT_OSCILLATOR,

    /**
     * {@code DPLL_PIN_TYPE_GNSS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DPLL_PIN_TYPE_GNSS"
    )
    DPLL_PIN_TYPE_GNSS,

    /**
     * {@code __DPLL_PIN_TYPE_MAX = 6}
     */
    @EnumMember(
        value = 6L,
        name = "__DPLL_PIN_TYPE_MAX"
    )
    __DPLL_PIN_TYPE_MAX,

    /**
     * {@code DPLL_PIN_TYPE_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DPLL_PIN_TYPE_MAX"
    )
    DPLL_PIN_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_pin_direction"
  )
  public enum dpll_pin_direction implements Enum<dpll_pin_direction>, TypedEnum<dpll_pin_direction, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_PIN_DIRECTION_INPUT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_PIN_DIRECTION_INPUT"
    )
    DPLL_PIN_DIRECTION_INPUT,

    /**
     * {@code DPLL_PIN_DIRECTION_OUTPUT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_PIN_DIRECTION_OUTPUT"
    )
    DPLL_PIN_DIRECTION_OUTPUT,

    /**
     * {@code __DPLL_PIN_DIRECTION_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__DPLL_PIN_DIRECTION_MAX"
    )
    __DPLL_PIN_DIRECTION_MAX,

    /**
     * {@code DPLL_PIN_DIRECTION_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_PIN_DIRECTION_MAX"
    )
    DPLL_PIN_DIRECTION_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_pin_state"
  )
  public enum dpll_pin_state implements Enum<dpll_pin_state>, TypedEnum<dpll_pin_state, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_PIN_STATE_CONNECTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_PIN_STATE_CONNECTED"
    )
    DPLL_PIN_STATE_CONNECTED,

    /**
     * {@code DPLL_PIN_STATE_DISCONNECTED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_PIN_STATE_DISCONNECTED"
    )
    DPLL_PIN_STATE_DISCONNECTED,

    /**
     * {@code DPLL_PIN_STATE_SELECTABLE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_PIN_STATE_SELECTABLE"
    )
    DPLL_PIN_STATE_SELECTABLE,

    /**
     * {@code __DPLL_PIN_STATE_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "__DPLL_PIN_STATE_MAX"
    )
    __DPLL_PIN_STATE_MAX,

    /**
     * {@code DPLL_PIN_STATE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_PIN_STATE_MAX"
    )
    DPLL_PIN_STATE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_feature_state"
  )
  public enum dpll_feature_state implements Enum<dpll_feature_state>, TypedEnum<dpll_feature_state, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_FEATURE_STATE_DISABLE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DPLL_FEATURE_STATE_DISABLE"
    )
    DPLL_FEATURE_STATE_DISABLE,

    /**
     * {@code DPLL_FEATURE_STATE_ENABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_FEATURE_STATE_ENABLE"
    )
    DPLL_FEATURE_STATE_ENABLE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_a_pin"
  )
  public enum dpll_a_pin implements Enum<dpll_a_pin>, TypedEnum<dpll_a_pin, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_A_PIN_ID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_A_PIN_ID"
    )
    DPLL_A_PIN_ID,

    /**
     * {@code DPLL_A_PIN_PARENT_ID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_A_PIN_PARENT_ID"
    )
    DPLL_A_PIN_PARENT_ID,

    /**
     * {@code DPLL_A_PIN_MODULE_NAME = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_A_PIN_MODULE_NAME"
    )
    DPLL_A_PIN_MODULE_NAME,

    /**
     * {@code DPLL_A_PIN_PAD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_A_PIN_PAD"
    )
    DPLL_A_PIN_PAD,

    /**
     * {@code DPLL_A_PIN_CLOCK_ID = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DPLL_A_PIN_CLOCK_ID"
    )
    DPLL_A_PIN_CLOCK_ID,

    /**
     * {@code DPLL_A_PIN_BOARD_LABEL = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DPLL_A_PIN_BOARD_LABEL"
    )
    DPLL_A_PIN_BOARD_LABEL,

    /**
     * {@code DPLL_A_PIN_PANEL_LABEL = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DPLL_A_PIN_PANEL_LABEL"
    )
    DPLL_A_PIN_PANEL_LABEL,

    /**
     * {@code DPLL_A_PIN_PACKAGE_LABEL = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DPLL_A_PIN_PACKAGE_LABEL"
    )
    DPLL_A_PIN_PACKAGE_LABEL,

    /**
     * {@code DPLL_A_PIN_TYPE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DPLL_A_PIN_TYPE"
    )
    DPLL_A_PIN_TYPE,

    /**
     * {@code DPLL_A_PIN_DIRECTION = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DPLL_A_PIN_DIRECTION"
    )
    DPLL_A_PIN_DIRECTION,

    /**
     * {@code DPLL_A_PIN_FREQUENCY = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DPLL_A_PIN_FREQUENCY"
    )
    DPLL_A_PIN_FREQUENCY,

    /**
     * {@code DPLL_A_PIN_FREQUENCY_SUPPORTED = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DPLL_A_PIN_FREQUENCY_SUPPORTED"
    )
    DPLL_A_PIN_FREQUENCY_SUPPORTED,

    /**
     * {@code DPLL_A_PIN_FREQUENCY_MIN = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DPLL_A_PIN_FREQUENCY_MIN"
    )
    DPLL_A_PIN_FREQUENCY_MIN,

    /**
     * {@code DPLL_A_PIN_FREQUENCY_MAX = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DPLL_A_PIN_FREQUENCY_MAX"
    )
    DPLL_A_PIN_FREQUENCY_MAX,

    /**
     * {@code DPLL_A_PIN_PRIO = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DPLL_A_PIN_PRIO"
    )
    DPLL_A_PIN_PRIO,

    /**
     * {@code DPLL_A_PIN_STATE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DPLL_A_PIN_STATE"
    )
    DPLL_A_PIN_STATE,

    /**
     * {@code DPLL_A_PIN_CAPABILITIES = 17}
     */
    @EnumMember(
        value = 17L,
        name = "DPLL_A_PIN_CAPABILITIES"
    )
    DPLL_A_PIN_CAPABILITIES,

    /**
     * {@code DPLL_A_PIN_PARENT_DEVICE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DPLL_A_PIN_PARENT_DEVICE"
    )
    DPLL_A_PIN_PARENT_DEVICE,

    /**
     * {@code DPLL_A_PIN_PARENT_PIN = 19}
     */
    @EnumMember(
        value = 19L,
        name = "DPLL_A_PIN_PARENT_PIN"
    )
    DPLL_A_PIN_PARENT_PIN,

    /**
     * {@code DPLL_A_PIN_PHASE_ADJUST_MIN = 20}
     */
    @EnumMember(
        value = 20L,
        name = "DPLL_A_PIN_PHASE_ADJUST_MIN"
    )
    DPLL_A_PIN_PHASE_ADJUST_MIN,

    /**
     * {@code DPLL_A_PIN_PHASE_ADJUST_MAX = 21}
     */
    @EnumMember(
        value = 21L,
        name = "DPLL_A_PIN_PHASE_ADJUST_MAX"
    )
    DPLL_A_PIN_PHASE_ADJUST_MAX,

    /**
     * {@code DPLL_A_PIN_PHASE_ADJUST = 22}
     */
    @EnumMember(
        value = 22L,
        name = "DPLL_A_PIN_PHASE_ADJUST"
    )
    DPLL_A_PIN_PHASE_ADJUST,

    /**
     * {@code DPLL_A_PIN_PHASE_OFFSET = 23}
     */
    @EnumMember(
        value = 23L,
        name = "DPLL_A_PIN_PHASE_OFFSET"
    )
    DPLL_A_PIN_PHASE_OFFSET,

    /**
     * {@code DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET = 24}
     */
    @EnumMember(
        value = 24L,
        name = "DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET"
    )
    DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET,

    /**
     * {@code DPLL_A_PIN_ESYNC_FREQUENCY = 25}
     */
    @EnumMember(
        value = 25L,
        name = "DPLL_A_PIN_ESYNC_FREQUENCY"
    )
    DPLL_A_PIN_ESYNC_FREQUENCY,

    /**
     * {@code DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED = 26}
     */
    @EnumMember(
        value = 26L,
        name = "DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED"
    )
    DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED,

    /**
     * {@code DPLL_A_PIN_ESYNC_PULSE = 27}
     */
    @EnumMember(
        value = 27L,
        name = "DPLL_A_PIN_ESYNC_PULSE"
    )
    DPLL_A_PIN_ESYNC_PULSE,

    /**
     * {@code DPLL_A_PIN_REFERENCE_SYNC = 28}
     */
    @EnumMember(
        value = 28L,
        name = "DPLL_A_PIN_REFERENCE_SYNC"
    )
    DPLL_A_PIN_REFERENCE_SYNC,

    /**
     * {@code __DPLL_A_PIN_MAX = 29}
     */
    @EnumMember(
        value = 29L,
        name = "__DPLL_A_PIN_MAX"
    )
    __DPLL_A_PIN_MAX,

    /**
     * {@code DPLL_A_PIN_MAX = 28}
     */
    @EnumMember(
        value = 28L,
        name = "DPLL_A_PIN_MAX"
    )
    DPLL_A_PIN_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin extends Struct {
    public @Unsigned int id;

    public @Unsigned int pin_idx;

    public @Unsigned long clock_id;

    public Ptr<module> module;

    public xarray dpll_refs;

    public xarray parent_refs;

    public xarray ref_sync_pins;

    public dpll_pin_properties prop;

    public @OriginalName("refcount_t") refcount_struct refcount;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_device_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_device_ops extends Struct {
    public Ptr<?> mode_get;

    public Ptr<?> lock_status_get;

    public Ptr<?> temp_get;

    public Ptr<?> clock_quality_level_get;

    public Ptr<?> phase_offset_monitor_set;

    public Ptr<?> phase_offset_monitor_get;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_device extends Struct {
    public @Unsigned int id;

    public @Unsigned int device_idx;

    public @Unsigned long clock_id;

    public Ptr<module> module;

    public dpll_type type;

    public xarray pin_refs;

    public @OriginalName("refcount_t") refcount_struct refcount;

    public list_head registration_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin_ops extends Struct {
    public Ptr<?> frequency_set;

    public Ptr<?> frequency_get;

    public Ptr<?> direction_set;

    public Ptr<?> direction_get;

    public Ptr<?> state_on_pin_get;

    public Ptr<?> state_on_dpll_get;

    public Ptr<?> state_on_pin_set;

    public Ptr<?> state_on_dpll_set;

    public Ptr<?> prio_get;

    public Ptr<?> prio_set;

    public Ptr<?> phase_offset_get;

    public Ptr<?> phase_adjust_get;

    public Ptr<?> phase_adjust_set;

    public Ptr<?> ffo_get;

    public Ptr<?> esync_set;

    public Ptr<?> esync_get;

    public Ptr<?> ref_sync_set;

    public Ptr<?> ref_sync_get;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin_esync"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin_esync extends Struct {
    public @Unsigned long freq;

    public Ptr<dpll_pin_frequency> range;

    public char range_num;

    public char pulse;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin_frequency"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin_frequency extends Struct {
    public @Unsigned long min;

    public @Unsigned long max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin_phase_adjust_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin_phase_adjust_range extends Struct {
    public int min;

    public int max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin_properties"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin_properties extends Struct {
    public String board_label;

    public String panel_label;

    public String package_label;

    public dpll_pin_type type;

    public @Unsigned long capabilities;

    public @Unsigned int freq_supported_num;

    public Ptr<dpll_pin_frequency> freq_supported;

    public dpll_pin_phase_adjust_range phase_range;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin_ref"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin_ref extends Struct {
    @InlineUnion(56656)
    public Ptr<dpll_device> dpll;

    @InlineUnion(56656)
    public Ptr<dpll_pin> pin;

    public list_head registration_list;

    public @OriginalName("refcount_t") refcount_struct refcount;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_device_registration"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_device_registration extends Struct {
    public list_head list;

    public Ptr<dpll_device_ops> ops;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_pin_registration"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_pin_registration extends Struct {
    public list_head list;

    public Ptr<dpll_pin_ops> ops;

    public Ptr<?> priv;

    public Ptr<?> cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_clock_quality_level"
  )
  public enum dpll_clock_quality_level implements Enum<dpll_clock_quality_level>, TypedEnum<dpll_clock_quality_level, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRC"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRC,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_A = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_A"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_A,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_B = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_B"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_SSU_B,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEC1 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEC1"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEC1,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRTC = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRTC"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_PRTC,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRTC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRTC"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRTC,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEEC = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEEC"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EEEC,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRC = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRC"
    )
    DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT1_EPRC,

    /**
     * {@code __DPLL_CLOCK_QUALITY_LEVEL_MAX = 9}
     */
    @EnumMember(
        value = 9L,
        name = "__DPLL_CLOCK_QUALITY_LEVEL_MAX"
    )
    __DPLL_CLOCK_QUALITY_LEVEL_MAX,

    /**
     * {@code DPLL_CLOCK_QUALITY_LEVEL_MAX = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DPLL_CLOCK_QUALITY_LEVEL_MAX"
    )
    DPLL_CLOCK_QUALITY_LEVEL_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_pin_capabilities"
  )
  public enum dpll_pin_capabilities implements Enum<dpll_pin_capabilities>, TypedEnum<dpll_pin_capabilities, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE"
    )
    DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE,

    /**
     * {@code DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE"
    )
    DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE,

    /**
     * {@code DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE"
    )
    DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_a"
  )
  public enum dpll_a implements Enum<dpll_a>, TypedEnum<dpll_a, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_A_ID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_A_ID"
    )
    DPLL_A_ID,

    /**
     * {@code DPLL_A_MODULE_NAME = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_A_MODULE_NAME"
    )
    DPLL_A_MODULE_NAME,

    /**
     * {@code DPLL_A_PAD = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_A_PAD"
    )
    DPLL_A_PAD,

    /**
     * {@code DPLL_A_CLOCK_ID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_A_CLOCK_ID"
    )
    DPLL_A_CLOCK_ID,

    /**
     * {@code DPLL_A_MODE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DPLL_A_MODE"
    )
    DPLL_A_MODE,

    /**
     * {@code DPLL_A_MODE_SUPPORTED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DPLL_A_MODE_SUPPORTED"
    )
    DPLL_A_MODE_SUPPORTED,

    /**
     * {@code DPLL_A_LOCK_STATUS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DPLL_A_LOCK_STATUS"
    )
    DPLL_A_LOCK_STATUS,

    /**
     * {@code DPLL_A_TEMP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DPLL_A_TEMP"
    )
    DPLL_A_TEMP,

    /**
     * {@code DPLL_A_TYPE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DPLL_A_TYPE"
    )
    DPLL_A_TYPE,

    /**
     * {@code DPLL_A_LOCK_STATUS_ERROR = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DPLL_A_LOCK_STATUS_ERROR"
    )
    DPLL_A_LOCK_STATUS_ERROR,

    /**
     * {@code DPLL_A_CLOCK_QUALITY_LEVEL = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DPLL_A_CLOCK_QUALITY_LEVEL"
    )
    DPLL_A_CLOCK_QUALITY_LEVEL,

    /**
     * {@code DPLL_A_PHASE_OFFSET_MONITOR = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DPLL_A_PHASE_OFFSET_MONITOR"
    )
    DPLL_A_PHASE_OFFSET_MONITOR,

    /**
     * {@code __DPLL_A_MAX = 13}
     */
    @EnumMember(
        value = 13L,
        name = "__DPLL_A_MAX"
    )
    __DPLL_A_MAX,

    /**
     * {@code DPLL_A_MAX = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DPLL_A_MAX"
    )
    DPLL_A_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dpll_cmd"
  )
  public enum dpll_cmd implements Enum<dpll_cmd>, TypedEnum<dpll_cmd, java.lang. @Unsigned Integer> {
    /**
     * {@code DPLL_CMD_DEVICE_ID_GET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DPLL_CMD_DEVICE_ID_GET"
    )
    DPLL_CMD_DEVICE_ID_GET,

    /**
     * {@code DPLL_CMD_DEVICE_GET = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DPLL_CMD_DEVICE_GET"
    )
    DPLL_CMD_DEVICE_GET,

    /**
     * {@code DPLL_CMD_DEVICE_SET = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DPLL_CMD_DEVICE_SET"
    )
    DPLL_CMD_DEVICE_SET,

    /**
     * {@code DPLL_CMD_DEVICE_CREATE_NTF = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DPLL_CMD_DEVICE_CREATE_NTF"
    )
    DPLL_CMD_DEVICE_CREATE_NTF,

    /**
     * {@code DPLL_CMD_DEVICE_DELETE_NTF = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DPLL_CMD_DEVICE_DELETE_NTF"
    )
    DPLL_CMD_DEVICE_DELETE_NTF,

    /**
     * {@code DPLL_CMD_DEVICE_CHANGE_NTF = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DPLL_CMD_DEVICE_CHANGE_NTF"
    )
    DPLL_CMD_DEVICE_CHANGE_NTF,

    /**
     * {@code DPLL_CMD_PIN_ID_GET = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DPLL_CMD_PIN_ID_GET"
    )
    DPLL_CMD_PIN_ID_GET,

    /**
     * {@code DPLL_CMD_PIN_GET = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DPLL_CMD_PIN_GET"
    )
    DPLL_CMD_PIN_GET,

    /**
     * {@code DPLL_CMD_PIN_SET = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DPLL_CMD_PIN_SET"
    )
    DPLL_CMD_PIN_SET,

    /**
     * {@code DPLL_CMD_PIN_CREATE_NTF = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DPLL_CMD_PIN_CREATE_NTF"
    )
    DPLL_CMD_PIN_CREATE_NTF,

    /**
     * {@code DPLL_CMD_PIN_DELETE_NTF = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DPLL_CMD_PIN_DELETE_NTF"
    )
    DPLL_CMD_PIN_DELETE_NTF,

    /**
     * {@code DPLL_CMD_PIN_CHANGE_NTF = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DPLL_CMD_PIN_CHANGE_NTF"
    )
    DPLL_CMD_PIN_CHANGE_NTF,

    /**
     * {@code __DPLL_CMD_MAX = 13}
     */
    @EnumMember(
        value = 13L,
        name = "__DPLL_CMD_MAX"
    )
    __DPLL_CMD_MAX,

    /**
     * {@code DPLL_CMD_MAX = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DPLL_CMD_MAX"
    )
    DPLL_CMD_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dpll_dump_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dpll_dump_ctx extends Struct {
    public @Unsigned long idx;
  }
}
