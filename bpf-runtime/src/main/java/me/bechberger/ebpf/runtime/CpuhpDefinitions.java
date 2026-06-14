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
 * Generated class for BPF runtime types that start with cpuhp
 */
@java.lang.SuppressWarnings("unused")
public final class CpuhpDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __cpuhp_invoke_callback_range(boolean bringup, @Unsigned int cpu,
      Ptr<cpuhp_cpu_state> st, cpuhp_state target, boolean nofail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __cpuhp_kick_ap(Ptr<cpuhp_cpu_state> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __cpuhp_remove_state(cpuhp_state state, boolean invoke) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __cpuhp_remove_state_cpuslocked(cpuhp_state state, boolean invoke) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__cpuhp_setup_state($arg1, (const u8*)$arg2, $arg3, (int (*)(unsigned int))$arg4, (int (*)(unsigned int))$arg5, $arg6)")
  public static int __cpuhp_setup_state(cpuhp_state state, String name, boolean invoke,
      Ptr<?> startup, Ptr<?> teardown, boolean multi_instance) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__cpuhp_setup_state_cpuslocked($arg1, (const u8*)$arg2, $arg3, (int (*)(unsigned int))$arg4, (int (*)(unsigned int))$arg5, $arg6)")
  public static int __cpuhp_setup_state_cpuslocked(cpuhp_state state, String name, boolean invoke,
      Ptr<?> startup, Ptr<?> teardown, boolean multi_instance) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __cpuhp_state_add_instance(cpuhp_state state, Ptr<hlist_node> node,
      boolean invoke) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __cpuhp_state_add_instance_cpuslocked(cpuhp_state state, Ptr<hlist_node> node,
      boolean invoke) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __cpuhp_state_remove_instance(cpuhp_state state, Ptr<hlist_node> node,
      boolean invoke) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_ap_report_dead() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_ap_sync_alive() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_bringup_ap(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean cpuhp_bringup_cpus_parallel(@Unsigned int ncpus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("cpuhp_bringup_mask((const struct cpumask*)$arg1, $arg2, $arg3)")
  public static void cpuhp_bringup_mask(Ptr<cpumask> mask, @Unsigned int ncpus,
      cpuhp_state target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_complete_idle_dead(Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_cpufreq_offline(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_cpufreq_online(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_invoke_callback(@Unsigned int cpu, cpuhp_state state, boolean bringup,
      Ptr<hlist_node> node, Ptr<Ptr<hlist_node>> lastp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_issue_call(int cpu, cpuhp_state state, boolean bringup,
      Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_kick_ap_alive(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_kick_ap_work(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_online_idle(cpuhp_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_report_idle_dead() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_rollback_install(int failedcpu, cpuhp_state state,
      Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_should_run(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_smt_disable(cpuhp_smt_control ctrlval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_smt_enable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int cpuhp_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_thread_fun(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void cpuhp_threads_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean cpuhp_wait_for_sync_state(@Unsigned int cpu, cpuhp_sync_state state,
      cpuhp_sync_state next_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum cpuhp_state"
  )
  public enum cpuhp_state implements Enum<cpuhp_state>, TypedEnum<cpuhp_state, java.lang.Integer> {
    /**
     * {@code CPUHP_INVALID = -1}
     */
    @EnumMember(
        value = -1L,
        name = "CPUHP_INVALID"
    )
    CPUHP_INVALID,

    /**
     * {@code CPUHP_OFFLINE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "CPUHP_OFFLINE"
    )
    CPUHP_OFFLINE,

    /**
     * {@code CPUHP_CREATE_THREADS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "CPUHP_CREATE_THREADS"
    )
    CPUHP_CREATE_THREADS,

    /**
     * {@code CPUHP_PERF_X86_PREPARE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "CPUHP_PERF_X86_PREPARE"
    )
    CPUHP_PERF_X86_PREPARE,

    /**
     * {@code CPUHP_PERF_X86_AMD_UNCORE_PREP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CPUHP_PERF_X86_AMD_UNCORE_PREP"
    )
    CPUHP_PERF_X86_AMD_UNCORE_PREP,

    /**
     * {@code CPUHP_PERF_POWER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "CPUHP_PERF_POWER"
    )
    CPUHP_PERF_POWER,

    /**
     * {@code CPUHP_PERF_SUPERH = 5}
     */
    @EnumMember(
        value = 5L,
        name = "CPUHP_PERF_SUPERH"
    )
    CPUHP_PERF_SUPERH,

    /**
     * {@code CPUHP_X86_HPET_DEAD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "CPUHP_X86_HPET_DEAD"
    )
    CPUHP_X86_HPET_DEAD,

    /**
     * {@code CPUHP_X86_MCE_DEAD = 7}
     */
    @EnumMember(
        value = 7L,
        name = "CPUHP_X86_MCE_DEAD"
    )
    CPUHP_X86_MCE_DEAD,

    /**
     * {@code CPUHP_VIRT_NET_DEAD = 8}
     */
    @EnumMember(
        value = 8L,
        name = "CPUHP_VIRT_NET_DEAD"
    )
    CPUHP_VIRT_NET_DEAD,

    /**
     * {@code CPUHP_IBMVNIC_DEAD = 9}
     */
    @EnumMember(
        value = 9L,
        name = "CPUHP_IBMVNIC_DEAD"
    )
    CPUHP_IBMVNIC_DEAD,

    /**
     * {@code CPUHP_SLUB_DEAD = 10}
     */
    @EnumMember(
        value = 10L,
        name = "CPUHP_SLUB_DEAD"
    )
    CPUHP_SLUB_DEAD,

    /**
     * {@code CPUHP_DEBUG_OBJ_DEAD = 11}
     */
    @EnumMember(
        value = 11L,
        name = "CPUHP_DEBUG_OBJ_DEAD"
    )
    CPUHP_DEBUG_OBJ_DEAD,

    /**
     * {@code CPUHP_MM_WRITEBACK_DEAD = 12}
     */
    @EnumMember(
        value = 12L,
        name = "CPUHP_MM_WRITEBACK_DEAD"
    )
    CPUHP_MM_WRITEBACK_DEAD,

    /**
     * {@code CPUHP_MM_VMSTAT_DEAD = 13}
     */
    @EnumMember(
        value = 13L,
        name = "CPUHP_MM_VMSTAT_DEAD"
    )
    CPUHP_MM_VMSTAT_DEAD,

    /**
     * {@code CPUHP_SOFTIRQ_DEAD = 14}
     */
    @EnumMember(
        value = 14L,
        name = "CPUHP_SOFTIRQ_DEAD"
    )
    CPUHP_SOFTIRQ_DEAD,

    /**
     * {@code CPUHP_NET_MVNETA_DEAD = 15}
     */
    @EnumMember(
        value = 15L,
        name = "CPUHP_NET_MVNETA_DEAD"
    )
    CPUHP_NET_MVNETA_DEAD,

    /**
     * {@code CPUHP_CPUIDLE_DEAD = 16}
     */
    @EnumMember(
        value = 16L,
        name = "CPUHP_CPUIDLE_DEAD"
    )
    CPUHP_CPUIDLE_DEAD,

    /**
     * {@code CPUHP_ARM64_FPSIMD_DEAD = 17}
     */
    @EnumMember(
        value = 17L,
        name = "CPUHP_ARM64_FPSIMD_DEAD"
    )
    CPUHP_ARM64_FPSIMD_DEAD,

    /**
     * {@code CPUHP_ARM_OMAP_WAKE_DEAD = 18}
     */
    @EnumMember(
        value = 18L,
        name = "CPUHP_ARM_OMAP_WAKE_DEAD"
    )
    CPUHP_ARM_OMAP_WAKE_DEAD,

    /**
     * {@code CPUHP_IRQ_POLL_DEAD = 19}
     */
    @EnumMember(
        value = 19L,
        name = "CPUHP_IRQ_POLL_DEAD"
    )
    CPUHP_IRQ_POLL_DEAD,

    /**
     * {@code CPUHP_BLOCK_SOFTIRQ_DEAD = 20}
     */
    @EnumMember(
        value = 20L,
        name = "CPUHP_BLOCK_SOFTIRQ_DEAD"
    )
    CPUHP_BLOCK_SOFTIRQ_DEAD,

    /**
     * {@code CPUHP_BIO_DEAD = 21}
     */
    @EnumMember(
        value = 21L,
        name = "CPUHP_BIO_DEAD"
    )
    CPUHP_BIO_DEAD,

    /**
     * {@code CPUHP_ACPI_CPUDRV_DEAD = 22}
     */
    @EnumMember(
        value = 22L,
        name = "CPUHP_ACPI_CPUDRV_DEAD"
    )
    CPUHP_ACPI_CPUDRV_DEAD,

    /**
     * {@code CPUHP_S390_PFAULT_DEAD = 23}
     */
    @EnumMember(
        value = 23L,
        name = "CPUHP_S390_PFAULT_DEAD"
    )
    CPUHP_S390_PFAULT_DEAD,

    /**
     * {@code CPUHP_BLK_MQ_DEAD = 24}
     */
    @EnumMember(
        value = 24L,
        name = "CPUHP_BLK_MQ_DEAD"
    )
    CPUHP_BLK_MQ_DEAD,

    /**
     * {@code CPUHP_FS_BUFF_DEAD = 25}
     */
    @EnumMember(
        value = 25L,
        name = "CPUHP_FS_BUFF_DEAD"
    )
    CPUHP_FS_BUFF_DEAD,

    /**
     * {@code CPUHP_PRINTK_DEAD = 26}
     */
    @EnumMember(
        value = 26L,
        name = "CPUHP_PRINTK_DEAD"
    )
    CPUHP_PRINTK_DEAD,

    /**
     * {@code CPUHP_MM_MEMCQ_DEAD = 27}
     */
    @EnumMember(
        value = 27L,
        name = "CPUHP_MM_MEMCQ_DEAD"
    )
    CPUHP_MM_MEMCQ_DEAD,

    /**
     * {@code CPUHP_PERCPU_CNT_DEAD = 28}
     */
    @EnumMember(
        value = 28L,
        name = "CPUHP_PERCPU_CNT_DEAD"
    )
    CPUHP_PERCPU_CNT_DEAD,

    /**
     * {@code CPUHP_RADIX_DEAD = 29}
     */
    @EnumMember(
        value = 29L,
        name = "CPUHP_RADIX_DEAD"
    )
    CPUHP_RADIX_DEAD,

    /**
     * {@code CPUHP_PAGE_ALLOC = 30}
     */
    @EnumMember(
        value = 30L,
        name = "CPUHP_PAGE_ALLOC"
    )
    CPUHP_PAGE_ALLOC,

    /**
     * {@code CPUHP_NET_DEV_DEAD = 31}
     */
    @EnumMember(
        value = 31L,
        name = "CPUHP_NET_DEV_DEAD"
    )
    CPUHP_NET_DEV_DEAD,

    /**
     * {@code CPUHP_IOMMU_IOVA_DEAD = 32}
     */
    @EnumMember(
        value = 32L,
        name = "CPUHP_IOMMU_IOVA_DEAD"
    )
    CPUHP_IOMMU_IOVA_DEAD,

    /**
     * {@code CPUHP_AP_ARM_CACHE_B15_RAC_DEAD = 33}
     */
    @EnumMember(
        value = 33L,
        name = "CPUHP_AP_ARM_CACHE_B15_RAC_DEAD"
    )
    CPUHP_AP_ARM_CACHE_B15_RAC_DEAD,

    /**
     * {@code CPUHP_PADATA_DEAD = 34}
     */
    @EnumMember(
        value = 34L,
        name = "CPUHP_PADATA_DEAD"
    )
    CPUHP_PADATA_DEAD,

    /**
     * {@code CPUHP_AP_DTPM_CPU_DEAD = 35}
     */
    @EnumMember(
        value = 35L,
        name = "CPUHP_AP_DTPM_CPU_DEAD"
    )
    CPUHP_AP_DTPM_CPU_DEAD,

    /**
     * {@code CPUHP_RANDOM_PREPARE = 36}
     */
    @EnumMember(
        value = 36L,
        name = "CPUHP_RANDOM_PREPARE"
    )
    CPUHP_RANDOM_PREPARE,

    /**
     * {@code CPUHP_WORKQUEUE_PREP = 37}
     */
    @EnumMember(
        value = 37L,
        name = "CPUHP_WORKQUEUE_PREP"
    )
    CPUHP_WORKQUEUE_PREP,

    /**
     * {@code CPUHP_POWER_NUMA_PREPARE = 38}
     */
    @EnumMember(
        value = 38L,
        name = "CPUHP_POWER_NUMA_PREPARE"
    )
    CPUHP_POWER_NUMA_PREPARE,

    /**
     * {@code CPUHP_HRTIMERS_PREPARE = 39}
     */
    @EnumMember(
        value = 39L,
        name = "CPUHP_HRTIMERS_PREPARE"
    )
    CPUHP_HRTIMERS_PREPARE,

    /**
     * {@code CPUHP_X2APIC_PREPARE = 40}
     */
    @EnumMember(
        value = 40L,
        name = "CPUHP_X2APIC_PREPARE"
    )
    CPUHP_X2APIC_PREPARE,

    /**
     * {@code CPUHP_SMPCFD_PREPARE = 41}
     */
    @EnumMember(
        value = 41L,
        name = "CPUHP_SMPCFD_PREPARE"
    )
    CPUHP_SMPCFD_PREPARE,

    /**
     * {@code CPUHP_RELAY_PREPARE = 42}
     */
    @EnumMember(
        value = 42L,
        name = "CPUHP_RELAY_PREPARE"
    )
    CPUHP_RELAY_PREPARE,

    /**
     * {@code CPUHP_MD_RAID5_PREPARE = 43}
     */
    @EnumMember(
        value = 43L,
        name = "CPUHP_MD_RAID5_PREPARE"
    )
    CPUHP_MD_RAID5_PREPARE,

    /**
     * {@code CPUHP_RCUTREE_PREP = 44}
     */
    @EnumMember(
        value = 44L,
        name = "CPUHP_RCUTREE_PREP"
    )
    CPUHP_RCUTREE_PREP,

    /**
     * {@code CPUHP_CPUIDLE_COUPLED_PREPARE = 45}
     */
    @EnumMember(
        value = 45L,
        name = "CPUHP_CPUIDLE_COUPLED_PREPARE"
    )
    CPUHP_CPUIDLE_COUPLED_PREPARE,

    /**
     * {@code CPUHP_POWERPC_PMAC_PREPARE = 46}
     */
    @EnumMember(
        value = 46L,
        name = "CPUHP_POWERPC_PMAC_PREPARE"
    )
    CPUHP_POWERPC_PMAC_PREPARE,

    /**
     * {@code CPUHP_POWERPC_MMU_CTX_PREPARE = 47}
     */
    @EnumMember(
        value = 47L,
        name = "CPUHP_POWERPC_MMU_CTX_PREPARE"
    )
    CPUHP_POWERPC_MMU_CTX_PREPARE,

    /**
     * {@code CPUHP_XEN_PREPARE = 48}
     */
    @EnumMember(
        value = 48L,
        name = "CPUHP_XEN_PREPARE"
    )
    CPUHP_XEN_PREPARE,

    /**
     * {@code CPUHP_XEN_EVTCHN_PREPARE = 49}
     */
    @EnumMember(
        value = 49L,
        name = "CPUHP_XEN_EVTCHN_PREPARE"
    )
    CPUHP_XEN_EVTCHN_PREPARE,

    /**
     * {@code CPUHP_ARM_SHMOBILE_SCU_PREPARE = 50}
     */
    @EnumMember(
        value = 50L,
        name = "CPUHP_ARM_SHMOBILE_SCU_PREPARE"
    )
    CPUHP_ARM_SHMOBILE_SCU_PREPARE,

    /**
     * {@code CPUHP_SH_SH3X_PREPARE = 51}
     */
    @EnumMember(
        value = 51L,
        name = "CPUHP_SH_SH3X_PREPARE"
    )
    CPUHP_SH_SH3X_PREPARE,

    /**
     * {@code CPUHP_TOPOLOGY_PREPARE = 52}
     */
    @EnumMember(
        value = 52L,
        name = "CPUHP_TOPOLOGY_PREPARE"
    )
    CPUHP_TOPOLOGY_PREPARE,

    /**
     * {@code CPUHP_NET_IUCV_PREPARE = 53}
     */
    @EnumMember(
        value = 53L,
        name = "CPUHP_NET_IUCV_PREPARE"
    )
    CPUHP_NET_IUCV_PREPARE,

    /**
     * {@code CPUHP_ARM_BL_PREPARE = 54}
     */
    @EnumMember(
        value = 54L,
        name = "CPUHP_ARM_BL_PREPARE"
    )
    CPUHP_ARM_BL_PREPARE,

    /**
     * {@code CPUHP_TRACE_RB_PREPARE = 55}
     */
    @EnumMember(
        value = 55L,
        name = "CPUHP_TRACE_RB_PREPARE"
    )
    CPUHP_TRACE_RB_PREPARE,

    /**
     * {@code CPUHP_MM_ZSWP_POOL_PREPARE = 56}
     */
    @EnumMember(
        value = 56L,
        name = "CPUHP_MM_ZSWP_POOL_PREPARE"
    )
    CPUHP_MM_ZSWP_POOL_PREPARE,

    /**
     * {@code CPUHP_KVM_PPC_BOOK3S_PREPARE = 57}
     */
    @EnumMember(
        value = 57L,
        name = "CPUHP_KVM_PPC_BOOK3S_PREPARE"
    )
    CPUHP_KVM_PPC_BOOK3S_PREPARE,

    /**
     * {@code CPUHP_ZCOMP_PREPARE = 58}
     */
    @EnumMember(
        value = 58L,
        name = "CPUHP_ZCOMP_PREPARE"
    )
    CPUHP_ZCOMP_PREPARE,

    /**
     * {@code CPUHP_TIMERS_PREPARE = 59}
     */
    @EnumMember(
        value = 59L,
        name = "CPUHP_TIMERS_PREPARE"
    )
    CPUHP_TIMERS_PREPARE,

    /**
     * {@code CPUHP_TMIGR_PREPARE = 60}
     */
    @EnumMember(
        value = 60L,
        name = "CPUHP_TMIGR_PREPARE"
    )
    CPUHP_TMIGR_PREPARE,

    /**
     * {@code CPUHP_MIPS_SOC_PREPARE = 61}
     */
    @EnumMember(
        value = 61L,
        name = "CPUHP_MIPS_SOC_PREPARE"
    )
    CPUHP_MIPS_SOC_PREPARE,

    /**
     * {@code CPUHP_BP_PREPARE_DYN = 62}
     */
    @EnumMember(
        value = 62L,
        name = "CPUHP_BP_PREPARE_DYN"
    )
    CPUHP_BP_PREPARE_DYN,

    /**
     * {@code CPUHP_BP_PREPARE_DYN_END = 82}
     */
    @EnumMember(
        value = 82L,
        name = "CPUHP_BP_PREPARE_DYN_END"
    )
    CPUHP_BP_PREPARE_DYN_END,

    /**
     * {@code CPUHP_BP_KICK_AP = 83}
     */
    @EnumMember(
        value = 83L,
        name = "CPUHP_BP_KICK_AP"
    )
    CPUHP_BP_KICK_AP,

    /**
     * {@code CPUHP_BRINGUP_CPU = 84}
     */
    @EnumMember(
        value = 84L,
        name = "CPUHP_BRINGUP_CPU"
    )
    CPUHP_BRINGUP_CPU,

    /**
     * {@code CPUHP_AP_IDLE_DEAD = 85}
     */
    @EnumMember(
        value = 85L,
        name = "CPUHP_AP_IDLE_DEAD"
    )
    CPUHP_AP_IDLE_DEAD,

    /**
     * {@code CPUHP_AP_OFFLINE = 86}
     */
    @EnumMember(
        value = 86L,
        name = "CPUHP_AP_OFFLINE"
    )
    CPUHP_AP_OFFLINE,

    /**
     * {@code CPUHP_AP_CACHECTRL_STARTING = 87}
     */
    @EnumMember(
        value = 87L,
        name = "CPUHP_AP_CACHECTRL_STARTING"
    )
    CPUHP_AP_CACHECTRL_STARTING,

    /**
     * {@code CPUHP_AP_SCHED_STARTING = 88}
     */
    @EnumMember(
        value = 88L,
        name = "CPUHP_AP_SCHED_STARTING"
    )
    CPUHP_AP_SCHED_STARTING,

    /**
     * {@code CPUHP_AP_RCUTREE_DYING = 89}
     */
    @EnumMember(
        value = 89L,
        name = "CPUHP_AP_RCUTREE_DYING"
    )
    CPUHP_AP_RCUTREE_DYING,

    /**
     * {@code CPUHP_AP_CPU_PM_STARTING = 90}
     */
    @EnumMember(
        value = 90L,
        name = "CPUHP_AP_CPU_PM_STARTING"
    )
    CPUHP_AP_CPU_PM_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_GIC_STARTING = 91}
     */
    @EnumMember(
        value = 91L,
        name = "CPUHP_AP_IRQ_GIC_STARTING"
    )
    CPUHP_AP_IRQ_GIC_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_HIP04_STARTING = 92}
     */
    @EnumMember(
        value = 92L,
        name = "CPUHP_AP_IRQ_HIP04_STARTING"
    )
    CPUHP_AP_IRQ_HIP04_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_APPLE_AIC_STARTING = 93}
     */
    @EnumMember(
        value = 93L,
        name = "CPUHP_AP_IRQ_APPLE_AIC_STARTING"
    )
    CPUHP_AP_IRQ_APPLE_AIC_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_ARMADA_XP_STARTING = 94}
     */
    @EnumMember(
        value = 94L,
        name = "CPUHP_AP_IRQ_ARMADA_XP_STARTING"
    )
    CPUHP_AP_IRQ_ARMADA_XP_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_BCM2836_STARTING = 95}
     */
    @EnumMember(
        value = 95L,
        name = "CPUHP_AP_IRQ_BCM2836_STARTING"
    )
    CPUHP_AP_IRQ_BCM2836_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_MIPS_GIC_STARTING = 96}
     */
    @EnumMember(
        value = 96L,
        name = "CPUHP_AP_IRQ_MIPS_GIC_STARTING"
    )
    CPUHP_AP_IRQ_MIPS_GIC_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_EIOINTC_STARTING = 97}
     */
    @EnumMember(
        value = 97L,
        name = "CPUHP_AP_IRQ_EIOINTC_STARTING"
    )
    CPUHP_AP_IRQ_EIOINTC_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_AVECINTC_STARTING = 98}
     */
    @EnumMember(
        value = 98L,
        name = "CPUHP_AP_IRQ_AVECINTC_STARTING"
    )
    CPUHP_AP_IRQ_AVECINTC_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING = 99}
     */
    @EnumMember(
        value = 99L,
        name = "CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING"
    )
    CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_ACLINT_SSWI_STARTING = 100}
     */
    @EnumMember(
        value = 100L,
        name = "CPUHP_AP_IRQ_ACLINT_SSWI_STARTING"
    )
    CPUHP_AP_IRQ_ACLINT_SSWI_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_RISCV_IMSIC_STARTING = 101}
     */
    @EnumMember(
        value = 101L,
        name = "CPUHP_AP_IRQ_RISCV_IMSIC_STARTING"
    )
    CPUHP_AP_IRQ_RISCV_IMSIC_STARTING,

    /**
     * {@code CPUHP_AP_IRQ_RISCV_SBI_IPI_STARTING = 102}
     */
    @EnumMember(
        value = 102L,
        name = "CPUHP_AP_IRQ_RISCV_SBI_IPI_STARTING"
    )
    CPUHP_AP_IRQ_RISCV_SBI_IPI_STARTING,

    /**
     * {@code CPUHP_AP_ARM_MVEBU_COHERENCY = 103}
     */
    @EnumMember(
        value = 103L,
        name = "CPUHP_AP_ARM_MVEBU_COHERENCY"
    )
    CPUHP_AP_ARM_MVEBU_COHERENCY,

    /**
     * {@code CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING = 104}
     */
    @EnumMember(
        value = 104L,
        name = "CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING"
    )
    CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING,

    /**
     * {@code CPUHP_AP_PERF_X86_STARTING = 105}
     */
    @EnumMember(
        value = 105L,
        name = "CPUHP_AP_PERF_X86_STARTING"
    )
    CPUHP_AP_PERF_X86_STARTING,

    /**
     * {@code CPUHP_AP_PERF_X86_AMD_IBS_STARTING = 106}
     */
    @EnumMember(
        value = 106L,
        name = "CPUHP_AP_PERF_X86_AMD_IBS_STARTING"
    )
    CPUHP_AP_PERF_X86_AMD_IBS_STARTING,

    /**
     * {@code CPUHP_AP_PERF_XTENSA_STARTING = 107}
     */
    @EnumMember(
        value = 107L,
        name = "CPUHP_AP_PERF_XTENSA_STARTING"
    )
    CPUHP_AP_PERF_XTENSA_STARTING,

    /**
     * {@code CPUHP_AP_ARM_VFP_STARTING = 108}
     */
    @EnumMember(
        value = 108L,
        name = "CPUHP_AP_ARM_VFP_STARTING"
    )
    CPUHP_AP_ARM_VFP_STARTING,

    /**
     * {@code CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING = 109}
     */
    @EnumMember(
        value = 109L,
        name = "CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING"
    )
    CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING,

    /**
     * {@code CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING = 110}
     */
    @EnumMember(
        value = 110L,
        name = "CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING"
    )
    CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING,

    /**
     * {@code CPUHP_AP_PERF_ARM_ACPI_STARTING = 111}
     */
    @EnumMember(
        value = 111L,
        name = "CPUHP_AP_PERF_ARM_ACPI_STARTING"
    )
    CPUHP_AP_PERF_ARM_ACPI_STARTING,

    /**
     * {@code CPUHP_AP_PERF_ARM_STARTING = 112}
     */
    @EnumMember(
        value = 112L,
        name = "CPUHP_AP_PERF_ARM_STARTING"
    )
    CPUHP_AP_PERF_ARM_STARTING,

    /**
     * {@code CPUHP_AP_PERF_RISCV_STARTING = 113}
     */
    @EnumMember(
        value = 113L,
        name = "CPUHP_AP_PERF_RISCV_STARTING"
    )
    CPUHP_AP_PERF_RISCV_STARTING,

    /**
     * {@code CPUHP_AP_ARM_L2X0_STARTING = 114}
     */
    @EnumMember(
        value = 114L,
        name = "CPUHP_AP_ARM_L2X0_STARTING"
    )
    CPUHP_AP_ARM_L2X0_STARTING,

    /**
     * {@code CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING = 115}
     */
    @EnumMember(
        value = 115L,
        name = "CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING"
    )
    CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_ARM_ARCH_TIMER_STARTING = 116}
     */
    @EnumMember(
        value = 116L,
        name = "CPUHP_AP_ARM_ARCH_TIMER_STARTING"
    )
    CPUHP_AP_ARM_ARCH_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_ARM_ARCH_TIMER_EVTSTRM_STARTING = 117}
     */
    @EnumMember(
        value = 117L,
        name = "CPUHP_AP_ARM_ARCH_TIMER_EVTSTRM_STARTING"
    )
    CPUHP_AP_ARM_ARCH_TIMER_EVTSTRM_STARTING,

    /**
     * {@code CPUHP_AP_ARM_GLOBAL_TIMER_STARTING = 118}
     */
    @EnumMember(
        value = 118L,
        name = "CPUHP_AP_ARM_GLOBAL_TIMER_STARTING"
    )
    CPUHP_AP_ARM_GLOBAL_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_JCORE_TIMER_STARTING = 119}
     */
    @EnumMember(
        value = 119L,
        name = "CPUHP_AP_JCORE_TIMER_STARTING"
    )
    CPUHP_AP_JCORE_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_ARM_TWD_STARTING = 120}
     */
    @EnumMember(
        value = 120L,
        name = "CPUHP_AP_ARM_TWD_STARTING"
    )
    CPUHP_AP_ARM_TWD_STARTING,

    /**
     * {@code CPUHP_AP_QCOM_TIMER_STARTING = 121}
     */
    @EnumMember(
        value = 121L,
        name = "CPUHP_AP_QCOM_TIMER_STARTING"
    )
    CPUHP_AP_QCOM_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_TEGRA_TIMER_STARTING = 122}
     */
    @EnumMember(
        value = 122L,
        name = "CPUHP_AP_TEGRA_TIMER_STARTING"
    )
    CPUHP_AP_TEGRA_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_ARMADA_TIMER_STARTING = 123}
     */
    @EnumMember(
        value = 123L,
        name = "CPUHP_AP_ARMADA_TIMER_STARTING"
    )
    CPUHP_AP_ARMADA_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_LOONGARCH_ARCH_TIMER_STARTING = 124}
     */
    @EnumMember(
        value = 124L,
        name = "CPUHP_AP_LOONGARCH_ARCH_TIMER_STARTING"
    )
    CPUHP_AP_LOONGARCH_ARCH_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_MIPS_GIC_TIMER_STARTING = 125}
     */
    @EnumMember(
        value = 125L,
        name = "CPUHP_AP_MIPS_GIC_TIMER_STARTING"
    )
    CPUHP_AP_MIPS_GIC_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_ARC_TIMER_STARTING = 126}
     */
    @EnumMember(
        value = 126L,
        name = "CPUHP_AP_ARC_TIMER_STARTING"
    )
    CPUHP_AP_ARC_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_REALTEK_TIMER_STARTING = 127}
     */
    @EnumMember(
        value = 127L,
        name = "CPUHP_AP_REALTEK_TIMER_STARTING"
    )
    CPUHP_AP_REALTEK_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_RISCV_TIMER_STARTING = 128}
     */
    @EnumMember(
        value = 128L,
        name = "CPUHP_AP_RISCV_TIMER_STARTING"
    )
    CPUHP_AP_RISCV_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_CLINT_TIMER_STARTING = 129}
     */
    @EnumMember(
        value = 129L,
        name = "CPUHP_AP_CLINT_TIMER_STARTING"
    )
    CPUHP_AP_CLINT_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_CSKY_TIMER_STARTING = 130}
     */
    @EnumMember(
        value = 130L,
        name = "CPUHP_AP_CSKY_TIMER_STARTING"
    )
    CPUHP_AP_CSKY_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_TI_GP_TIMER_STARTING = 131}
     */
    @EnumMember(
        value = 131L,
        name = "CPUHP_AP_TI_GP_TIMER_STARTING"
    )
    CPUHP_AP_TI_GP_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_HYPERV_TIMER_STARTING = 132}
     */
    @EnumMember(
        value = 132L,
        name = "CPUHP_AP_HYPERV_TIMER_STARTING"
    )
    CPUHP_AP_HYPERV_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_DUMMY_TIMER_STARTING = 133}
     */
    @EnumMember(
        value = 133L,
        name = "CPUHP_AP_DUMMY_TIMER_STARTING"
    )
    CPUHP_AP_DUMMY_TIMER_STARTING,

    /**
     * {@code CPUHP_AP_ARM_XEN_STARTING = 134}
     */
    @EnumMember(
        value = 134L,
        name = "CPUHP_AP_ARM_XEN_STARTING"
    )
    CPUHP_AP_ARM_XEN_STARTING,

    /**
     * {@code CPUHP_AP_ARM_XEN_RUNSTATE_STARTING = 135}
     */
    @EnumMember(
        value = 135L,
        name = "CPUHP_AP_ARM_XEN_RUNSTATE_STARTING"
    )
    CPUHP_AP_ARM_XEN_RUNSTATE_STARTING,

    /**
     * {@code CPUHP_AP_ARM_CORESIGHT_STARTING = 136}
     */
    @EnumMember(
        value = 136L,
        name = "CPUHP_AP_ARM_CORESIGHT_STARTING"
    )
    CPUHP_AP_ARM_CORESIGHT_STARTING,

    /**
     * {@code CPUHP_AP_ARM_CORESIGHT_CTI_STARTING = 137}
     */
    @EnumMember(
        value = 137L,
        name = "CPUHP_AP_ARM_CORESIGHT_CTI_STARTING"
    )
    CPUHP_AP_ARM_CORESIGHT_CTI_STARTING,

    /**
     * {@code CPUHP_AP_ARM64_ISNDEP_STARTING = 138}
     */
    @EnumMember(
        value = 138L,
        name = "CPUHP_AP_ARM64_ISNDEP_STARTING"
    )
    CPUHP_AP_ARM64_ISNDEP_STARTING,

    /**
     * {@code CPUHP_AP_SMPCFD_DYING = 139}
     */
    @EnumMember(
        value = 139L,
        name = "CPUHP_AP_SMPCFD_DYING"
    )
    CPUHP_AP_SMPCFD_DYING,

    /**
     * {@code CPUHP_AP_HRTIMERS_DYING = 140}
     */
    @EnumMember(
        value = 140L,
        name = "CPUHP_AP_HRTIMERS_DYING"
    )
    CPUHP_AP_HRTIMERS_DYING,

    /**
     * {@code CPUHP_AP_TICK_DYING = 141}
     */
    @EnumMember(
        value = 141L,
        name = "CPUHP_AP_TICK_DYING"
    )
    CPUHP_AP_TICK_DYING,

    /**
     * {@code CPUHP_AP_X86_TBOOT_DYING = 142}
     */
    @EnumMember(
        value = 142L,
        name = "CPUHP_AP_X86_TBOOT_DYING"
    )
    CPUHP_AP_X86_TBOOT_DYING,

    /**
     * {@code CPUHP_AP_ARM_CACHE_B15_RAC_DYING = 143}
     */
    @EnumMember(
        value = 143L,
        name = "CPUHP_AP_ARM_CACHE_B15_RAC_DYING"
    )
    CPUHP_AP_ARM_CACHE_B15_RAC_DYING,

    /**
     * {@code CPUHP_AP_ONLINE = 144}
     */
    @EnumMember(
        value = 144L,
        name = "CPUHP_AP_ONLINE"
    )
    CPUHP_AP_ONLINE,

    /**
     * {@code CPUHP_TEARDOWN_CPU = 145}
     */
    @EnumMember(
        value = 145L,
        name = "CPUHP_TEARDOWN_CPU"
    )
    CPUHP_TEARDOWN_CPU,

    /**
     * {@code CPUHP_AP_ONLINE_IDLE = 146}
     */
    @EnumMember(
        value = 146L,
        name = "CPUHP_AP_ONLINE_IDLE"
    )
    CPUHP_AP_ONLINE_IDLE,

    /**
     * {@code CPUHP_AP_HYPERV_ONLINE = 147}
     */
    @EnumMember(
        value = 147L,
        name = "CPUHP_AP_HYPERV_ONLINE"
    )
    CPUHP_AP_HYPERV_ONLINE,

    /**
     * {@code CPUHP_AP_KVM_ONLINE = 148}
     */
    @EnumMember(
        value = 148L,
        name = "CPUHP_AP_KVM_ONLINE"
    )
    CPUHP_AP_KVM_ONLINE,

    /**
     * {@code CPUHP_AP_SCHED_WAIT_EMPTY = 149}
     */
    @EnumMember(
        value = 149L,
        name = "CPUHP_AP_SCHED_WAIT_EMPTY"
    )
    CPUHP_AP_SCHED_WAIT_EMPTY,

    /**
     * {@code CPUHP_AP_SMPBOOT_THREADS = 150}
     */
    @EnumMember(
        value = 150L,
        name = "CPUHP_AP_SMPBOOT_THREADS"
    )
    CPUHP_AP_SMPBOOT_THREADS,

    /**
     * {@code CPUHP_AP_IRQ_AFFINITY_ONLINE = 151}
     */
    @EnumMember(
        value = 151L,
        name = "CPUHP_AP_IRQ_AFFINITY_ONLINE"
    )
    CPUHP_AP_IRQ_AFFINITY_ONLINE,

    /**
     * {@code CPUHP_AP_BLK_MQ_ONLINE = 152}
     */
    @EnumMember(
        value = 152L,
        name = "CPUHP_AP_BLK_MQ_ONLINE"
    )
    CPUHP_AP_BLK_MQ_ONLINE,

    /**
     * {@code CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS = 153}
     */
    @EnumMember(
        value = 153L,
        name = "CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS"
    )
    CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS,

    /**
     * {@code CPUHP_AP_X86_INTEL_EPB_ONLINE = 154}
     */
    @EnumMember(
        value = 154L,
        name = "CPUHP_AP_X86_INTEL_EPB_ONLINE"
    )
    CPUHP_AP_X86_INTEL_EPB_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ONLINE = 155}
     */
    @EnumMember(
        value = 155L,
        name = "CPUHP_AP_PERF_ONLINE"
    )
    CPUHP_AP_PERF_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_X86_ONLINE = 156}
     */
    @EnumMember(
        value = 156L,
        name = "CPUHP_AP_PERF_X86_ONLINE"
    )
    CPUHP_AP_PERF_X86_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_X86_UNCORE_ONLINE = 157}
     */
    @EnumMember(
        value = 157L,
        name = "CPUHP_AP_PERF_X86_UNCORE_ONLINE"
    )
    CPUHP_AP_PERF_X86_UNCORE_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE = 158}
     */
    @EnumMember(
        value = 158L,
        name = "CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE"
    )
    CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_X86_AMD_POWER_ONLINE = 159}
     */
    @EnumMember(
        value = 159L,
        name = "CPUHP_AP_PERF_X86_AMD_POWER_ONLINE"
    )
    CPUHP_AP_PERF_X86_AMD_POWER_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_S390_CF_ONLINE = 160}
     */
    @EnumMember(
        value = 160L,
        name = "CPUHP_AP_PERF_S390_CF_ONLINE"
    )
    CPUHP_AP_PERF_S390_CF_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_S390_SF_ONLINE = 161}
     */
    @EnumMember(
        value = 161L,
        name = "CPUHP_AP_PERF_S390_SF_ONLINE"
    )
    CPUHP_AP_PERF_S390_SF_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_CCI_ONLINE = 162}
     */
    @EnumMember(
        value = 162L,
        name = "CPUHP_AP_PERF_ARM_CCI_ONLINE"
    )
    CPUHP_AP_PERF_ARM_CCI_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_CCN_ONLINE = 163}
     */
    @EnumMember(
        value = 163L,
        name = "CPUHP_AP_PERF_ARM_CCN_ONLINE"
    )
    CPUHP_AP_PERF_ARM_CCN_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HISI_CPA_ONLINE = 164}
     */
    @EnumMember(
        value = 164L,
        name = "CPUHP_AP_PERF_ARM_HISI_CPA_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HISI_CPA_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE = 165}
     */
    @EnumMember(
        value = 165L,
        name = "CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE = 166}
     */
    @EnumMember(
        value = 166L,
        name = "CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HISI_L3_ONLINE = 167}
     */
    @EnumMember(
        value = 167L,
        name = "CPUHP_AP_PERF_ARM_HISI_L3_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HISI_L3_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HISI_PA_ONLINE = 168}
     */
    @EnumMember(
        value = 168L,
        name = "CPUHP_AP_PERF_ARM_HISI_PA_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HISI_PA_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE = 169}
     */
    @EnumMember(
        value = 169L,
        name = "CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE = 170}
     */
    @EnumMember(
        value = 170L,
        name = "CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_HNS3_PMU_ONLINE = 171}
     */
    @EnumMember(
        value = 171L,
        name = "CPUHP_AP_PERF_ARM_HNS3_PMU_ONLINE"
    )
    CPUHP_AP_PERF_ARM_HNS3_PMU_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_L2X0_ONLINE = 172}
     */
    @EnumMember(
        value = 172L,
        name = "CPUHP_AP_PERF_ARM_L2X0_ONLINE"
    )
    CPUHP_AP_PERF_ARM_L2X0_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE = 173}
     */
    @EnumMember(
        value = 173L,
        name = "CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE"
    )
    CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE = 174}
     */
    @EnumMember(
        value = 174L,
        name = "CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE"
    )
    CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE = 175}
     */
    @EnumMember(
        value = 175L,
        name = "CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE"
    )
    CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE = 176}
     */
    @EnumMember(
        value = 176L,
        name = "CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE"
    )
    CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE = 177}
     */
    @EnumMember(
        value = 177L,
        name = "CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE"
    )
    CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_ARM_MRVL_PEM_ONLINE = 178}
     */
    @EnumMember(
        value = 178L,
        name = "CPUHP_AP_PERF_ARM_MRVL_PEM_ONLINE"
    )
    CPUHP_AP_PERF_ARM_MRVL_PEM_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE = 179}
     */
    @EnumMember(
        value = 179L,
        name = "CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE"
    )
    CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE = 180}
     */
    @EnumMember(
        value = 180L,
        name = "CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE"
    )
    CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE = 181}
     */
    @EnumMember(
        value = 181L,
        name = "CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE"
    )
    CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE = 182}
     */
    @EnumMember(
        value = 182L,
        name = "CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE"
    )
    CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE = 183}
     */
    @EnumMember(
        value = 183L,
        name = "CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE"
    )
    CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE = 184}
     */
    @EnumMember(
        value = 184L,
        name = "CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE"
    )
    CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE,

    /**
     * {@code CPUHP_AP_PERF_CSKY_ONLINE = 185}
     */
    @EnumMember(
        value = 185L,
        name = "CPUHP_AP_PERF_CSKY_ONLINE"
    )
    CPUHP_AP_PERF_CSKY_ONLINE,

    /**
     * {@code CPUHP_AP_TMIGR_ONLINE = 186}
     */
    @EnumMember(
        value = 186L,
        name = "CPUHP_AP_TMIGR_ONLINE"
    )
    CPUHP_AP_TMIGR_ONLINE,

    /**
     * {@code CPUHP_AP_WATCHDOG_ONLINE = 187}
     */
    @EnumMember(
        value = 187L,
        name = "CPUHP_AP_WATCHDOG_ONLINE"
    )
    CPUHP_AP_WATCHDOG_ONLINE,

    /**
     * {@code CPUHP_AP_WORKQUEUE_ONLINE = 188}
     */
    @EnumMember(
        value = 188L,
        name = "CPUHP_AP_WORKQUEUE_ONLINE"
    )
    CPUHP_AP_WORKQUEUE_ONLINE,

    /**
     * {@code CPUHP_AP_RANDOM_ONLINE = 189}
     */
    @EnumMember(
        value = 189L,
        name = "CPUHP_AP_RANDOM_ONLINE"
    )
    CPUHP_AP_RANDOM_ONLINE,

    /**
     * {@code CPUHP_AP_RCUTREE_ONLINE = 190}
     */
    @EnumMember(
        value = 190L,
        name = "CPUHP_AP_RCUTREE_ONLINE"
    )
    CPUHP_AP_RCUTREE_ONLINE,

    /**
     * {@code CPUHP_AP_KTHREADS_ONLINE = 191}
     */
    @EnumMember(
        value = 191L,
        name = "CPUHP_AP_KTHREADS_ONLINE"
    )
    CPUHP_AP_KTHREADS_ONLINE,

    /**
     * {@code CPUHP_AP_BASE_CACHEINFO_ONLINE = 192}
     */
    @EnumMember(
        value = 192L,
        name = "CPUHP_AP_BASE_CACHEINFO_ONLINE"
    )
    CPUHP_AP_BASE_CACHEINFO_ONLINE,

    /**
     * {@code CPUHP_AP_ONLINE_DYN = 193}
     */
    @EnumMember(
        value = 193L,
        name = "CPUHP_AP_ONLINE_DYN"
    )
    CPUHP_AP_ONLINE_DYN,

    /**
     * {@code CPUHP_AP_ONLINE_DYN_END = 233}
     */
    @EnumMember(
        value = 233L,
        name = "CPUHP_AP_ONLINE_DYN_END"
    )
    CPUHP_AP_ONLINE_DYN_END,

    /**
     * {@code CPUHP_AP_X86_HPET_ONLINE = 234}
     */
    @EnumMember(
        value = 234L,
        name = "CPUHP_AP_X86_HPET_ONLINE"
    )
    CPUHP_AP_X86_HPET_ONLINE,

    /**
     * {@code CPUHP_AP_X86_KVM_CLK_ONLINE = 235}
     */
    @EnumMember(
        value = 235L,
        name = "CPUHP_AP_X86_KVM_CLK_ONLINE"
    )
    CPUHP_AP_X86_KVM_CLK_ONLINE,

    /**
     * {@code CPUHP_AP_ACTIVE = 236}
     */
    @EnumMember(
        value = 236L,
        name = "CPUHP_AP_ACTIVE"
    )
    CPUHP_AP_ACTIVE,

    /**
     * {@code CPUHP_ONLINE = 237}
     */
    @EnumMember(
        value = 237L,
        name = "CPUHP_ONLINE"
    )
    CPUHP_ONLINE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum cpuhp_smt_control"
  )
  public enum cpuhp_smt_control implements Enum<cpuhp_smt_control>, TypedEnum<cpuhp_smt_control, java.lang. @Unsigned Integer> {
    /**
     * {@code CPU_SMT_ENABLED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "CPU_SMT_ENABLED"
    )
    CPU_SMT_ENABLED,

    /**
     * {@code CPU_SMT_DISABLED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "CPU_SMT_DISABLED"
    )
    CPU_SMT_DISABLED,

    /**
     * {@code CPU_SMT_FORCE_DISABLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "CPU_SMT_FORCE_DISABLED"
    )
    CPU_SMT_FORCE_DISABLED,

    /**
     * {@code CPU_SMT_NOT_SUPPORTED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CPU_SMT_NOT_SUPPORTED"
    )
    CPU_SMT_NOT_SUPPORTED,

    /**
     * {@code CPU_SMT_NOT_IMPLEMENTED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "CPU_SMT_NOT_IMPLEMENTED"
    )
    CPU_SMT_NOT_IMPLEMENTED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct cpuhp_cpu_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class cpuhp_cpu_state extends Struct {
    public cpuhp_state state;

    public cpuhp_state target;

    public cpuhp_state fail;

    public Ptr<task_struct> thread;

    public boolean should_run;

    public boolean rollback;

    public boolean single;

    public boolean bringup;

    public Ptr<hlist_node> node;

    public Ptr<hlist_node> last;

    public cpuhp_state cb_state;

    public int result;

    public atomic_t ap_sync_state;

    public completion done_up;

    public completion done_down;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct cpuhp_step"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class cpuhp_step extends Struct {
    public String name;

    public startup_of_cpuhp_step_and_teardown_of_cpuhp_step startup;

    public startup_of_cpuhp_step_and_teardown_of_cpuhp_step teardown;

    public hlist_head list;

    public boolean cant_stop;

    public boolean multi_instance;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum cpuhp_sync_state"
  )
  public enum cpuhp_sync_state implements Enum<cpuhp_sync_state>, TypedEnum<cpuhp_sync_state, java.lang. @Unsigned Integer> {
    /**
     * {@code SYNC_STATE_DEAD = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SYNC_STATE_DEAD"
    )
    SYNC_STATE_DEAD,

    /**
     * {@code SYNC_STATE_KICKED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SYNC_STATE_KICKED"
    )
    SYNC_STATE_KICKED,

    /**
     * {@code SYNC_STATE_SHOULD_DIE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SYNC_STATE_SHOULD_DIE"
    )
    SYNC_STATE_SHOULD_DIE,

    /**
     * {@code SYNC_STATE_ALIVE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SYNC_STATE_ALIVE"
    )
    SYNC_STATE_ALIVE,

    /**
     * {@code SYNC_STATE_SHOULD_ONLINE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SYNC_STATE_SHOULD_ONLINE"
    )
    SYNC_STATE_SHOULD_ONLINE,

    /**
     * {@code SYNC_STATE_ONLINE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SYNC_STATE_ONLINE"
    )
    SYNC_STATE_ONLINE
  }
}
