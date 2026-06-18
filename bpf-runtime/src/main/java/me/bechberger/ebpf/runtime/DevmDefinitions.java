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
 * Generated class for BPF runtime types that start with devm
 */
@java.lang.SuppressWarnings("unused")
public final class DevmDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__devm_add_action($arg1, (void (*)(void*))$arg2, $arg3, (const u8*)$arg4)")
  public static int __devm_add_action(Ptr<device> dev, Ptr<?> action, Ptr<?> data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> __devm_alloc_percpu(Ptr<device> dev, @Unsigned long size,
      @Unsigned long align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_auxiliary_device_create($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static Ptr<auxiliary_device> __devm_auxiliary_device_create(Ptr<device> dev,
      String modname, String devname, Ptr<?> platform_data, int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devm_clk_bulk_get(Ptr<device> dev, int num_clks, Ptr<clk_bulk_data> clks,
      boolean optional) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_clk_get($arg1, (const u8*)$arg2, (struct clk* (*)(struct device*, const u8*))$arg3, (int (*)(struct clk*))$arg4, (void (*)(struct clk*))$arg5)")
  public static Ptr<clk> __devm_clk_get(Ptr<device> dev, String id, Ptr<?> get, Ptr<?> init,
      Ptr<?> exit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_clk_hw_register_divider($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4, (const struct clk_hw*)$arg5, (const struct clk_parent_data*)$arg6, $arg7, $arg8, $arg9, $arg10, $arg11, (const struct clk_div_table*)$arg12, $arg13)")
  public static Ptr<clk_hw> __devm_clk_hw_register_divider(Ptr<device> dev, Ptr<device_node> np,
      String name, String parent_name, Ptr<clk_hw> parent_hw, Ptr<clk_parent_data> parent_data,
      @Unsigned long flags, Ptr<?> reg, char shift, char width, @Unsigned long clk_divider_flags,
      Ptr<clk_div_table> table, Ptr<@OriginalName("spinlock_t") spinlock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_clk_hw_register_gate($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4, (const struct clk_hw*)$arg5, (const struct clk_parent_data*)$arg6, $arg7, $arg8, $arg9, $arg10, $arg11)")
  public static Ptr<clk_hw> __devm_clk_hw_register_gate(Ptr<device> dev, Ptr<device_node> np,
      String name, String parent_name, Ptr<clk_hw> parent_hw, Ptr<clk_parent_data> parent_data,
      @Unsigned long flags, Ptr<?> reg, char bit_idx, char clk_gate_flags,
      Ptr<@OriginalName("spinlock_t") spinlock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_clk_hw_register_mux($arg1, $arg2, (const u8*)$arg3, $arg4, (const u8**)$arg5, (const struct clk_hw**)$arg6, (const struct clk_parent_data*)$arg7, $arg8, $arg9, $arg10, $arg11, $arg12, (const unsigned int*)$arg13, $arg14)")
  public static Ptr<clk_hw> __devm_clk_hw_register_mux(Ptr<device> dev, Ptr<device_node> np,
      String name, char num_parents, Ptr<String> parent_names, Ptr<Ptr<clk_hw>> parent_hws,
      Ptr<clk_parent_data> parent_data, @Unsigned long flags, Ptr<?> reg, char shift,
      @Unsigned int mask, char clk_mux_flags, Ptr<java.lang. @Unsigned Integer> table,
      Ptr<@OriginalName("spinlock_t") spinlock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dev_dax> __devm_create_dev_dax(Ptr<dev_dax_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_drm_bridge_alloc($arg1, $arg2, $arg3, (const struct drm_bridge_funcs*)$arg4)")
  public static Ptr<?> __devm_drm_bridge_alloc(Ptr<device> dev, @Unsigned long size,
      @Unsigned long offset, Ptr<drm_bridge_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_drm_dev_alloc($arg1, (const struct drm_driver*)$arg2, $arg3, $arg4)")
  public static Ptr<?> __devm_drm_dev_alloc(Ptr<device> parent, Ptr<drm_driver> driver,
      @Unsigned long size, @Unsigned long offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_drm_panel_alloc($arg1, $arg2, $arg3, (const struct drm_panel_funcs*)$arg4, $arg5)")
  public static Ptr<?> __devm_drm_panel_alloc(Ptr<device> dev, @Unsigned long size,
      @Unsigned long offset, Ptr<drm_panel_funcs> funcs, int connector_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devm_hte_release_ts(Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_intel_scu_ipc_register($arg1, (const struct intel_scu_ipc_data*)$arg2, $arg3)")
  public static Ptr<intel_scu_ipc_dev> __devm_intel_scu_ipc_register(Ptr<device> parent,
      Ptr<intel_scu_ipc_data> scu_data, Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> __devm_ioremap(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long offset,
      @Unsigned @OriginalName("resource_size_t") long size, devm_ioremap_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_ioremap_resource($arg1, (const struct resource*)$arg2, $arg3)")
  public static Ptr<?> __devm_ioremap_resource(Ptr<device> dev, Ptr<resource> res,
      devm_ioremap_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_irq_alloc_descs($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, (const struct irq_affinity_desc*)$arg7)")
  public static int __devm_irq_alloc_descs(Ptr<device> dev, int irq, @Unsigned int from,
      @Unsigned int cnt, int node, Ptr<module> owner, Ptr<irq_affinity_desc> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devm_mbox_controller_unregister(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devm_mdiobus_register(Ptr<device> dev, Ptr<mii_bus> bus, Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_of_phy_provider_register($arg1, $arg2, $arg3, (struct phy* (*)(struct device*, const struct of_phandle_args*))$arg4)")
  public static Ptr<phy_provider> __devm_of_phy_provider_register(Ptr<device> dev,
      Ptr<device_node> children, Ptr<module> owner, Ptr<?> of_xlate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_pci_epc_create($arg1, (const struct pci_epc_ops*)$arg2, $arg3)")
  public static Ptr<pci_epc> __devm_pci_epc_create(Ptr<device> dev, Ptr<pci_epc_ops> ops,
      Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devm_pwmchip_add(Ptr<device> dev, Ptr<pwm_chip> chip, Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_regmap_init($arg1, (const struct regmap_bus*)$arg2, $arg3, (const struct regmap_config*)$arg4, $arg5, (const u8*)$arg6)")
  public static Ptr<regmap> __devm_regmap_init(Ptr<device> dev, Ptr<regmap_bus> bus,
      Ptr<?> bus_context, Ptr<regmap_config> config, Ptr<lock_class_key> lock_key,
      String lock_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_regmap_init_i2c($arg1, (const struct regmap_config*)$arg2, $arg3, (const u8*)$arg4)")
  public static Ptr<regmap> __devm_regmap_init_i2c(Ptr<i2c_client> i2c, Ptr<regmap_config> config,
      Ptr<lock_class_key> lock_key, String lock_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_regmap_init_mmio_clk($arg1, (const u8*)$arg2, $arg3, (const struct regmap_config*)$arg4, $arg5, (const u8*)$arg6)")
  public static Ptr<regmap> __devm_regmap_init_mmio_clk(Ptr<device> dev, String clk_id, Ptr<?> regs,
      Ptr<regmap_config> config, Ptr<lock_class_key> lock_key, String lock_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_regmap_init_spi($arg1, (const struct regmap_config*)$arg2, $arg3, (const u8*)$arg4)")
  public static Ptr<regmap> __devm_regmap_init_spi(Ptr<spi_device> spi, Ptr<regmap_config> config,
      Ptr<lock_class_key> lock_key, String lock_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __devm_release_region(Ptr<device> dev, Ptr<resource> parent,
      @Unsigned @OriginalName("resource_size_t") long start,
      @Unsigned @OriginalName("resource_size_t") long n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_request_region($arg1, $arg2, $arg3, $arg4, (const u8*)$arg5)")
  public static Ptr<resource> __devm_request_region(Ptr<device> dev, Ptr<resource> parent,
      @Unsigned @OriginalName("resource_size_t") long start,
      @Unsigned @OriginalName("resource_size_t") long n, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devm_reset_control_bulk_get(Ptr<device> dev, int num_rstcs,
      Ptr<reset_control_bulk_data> rstcs, reset_control_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__devm_reset_control_get($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static Ptr<reset_control> __devm_reset_control_get(Ptr<device> dev, String id, int index,
      reset_control_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __devm_rtc_register_device(Ptr<module> owner, Ptr<rtc_device> rtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<spi_controller> __devm_spi_alloc_controller(Ptr<device> dev, @Unsigned int size,
      boolean target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int _devm_regulator_bulk_get(Ptr<device> dev, int num_consumers,
      Ptr<regulator_bulk_data> consumers, regulator_get_type get_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("_devm_regulator_get($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<regulator> _devm_regulator_get(Ptr<device> dev, String id, int get_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("_devm_regulator_get_enable($arg1, (const u8*)$arg2, $arg3)")
  public static int _devm_regulator_get_enable(Ptr<device> dev, String id, int get_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_acpi_dev_add_driver_gpios($arg1, (const struct acpi_gpio_mapping*)$arg2)")
  public static int devm_acpi_dev_add_driver_gpios(Ptr<device> dev, Ptr<acpi_gpio_mapping> gpios) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_acpi_dma_controller_register($arg1, (struct dma_chan* (*)(struct acpi_dma_spec*, struct acpi_dma*))$arg2, $arg3)")
  public static int devm_acpi_dma_controller_register(Ptr<device> dev, Ptr<?> acpi_dma_xlate,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_acpi_dma_free(Ptr<?> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_acpi_fan_create_hwmon(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_action_match(Ptr<device> dev, Ptr<?> res, Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_action_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> devm_alloc_etherdev_mqs(Ptr<device> dev, int sizeof_priv,
      @Unsigned int txqs, @Unsigned int rxqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_aperture_acquire_for_platform_device(Ptr<platform_device> pdev,
      @Unsigned @OriginalName("resource_size_t") long base,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_aperture_acquire_release(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_arch_io_free_memtype_wc_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_arch_io_reserve_memtype_wc(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long start,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_arch_phys_ac_add_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_arch_phys_wc_add(Ptr<device> dev, @Unsigned long base,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_attr_group_remove(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_backlight_device_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_backlight_device_register($arg1, (const u8*)$arg2, $arg3, $arg4, (const struct backlight_ops*)$arg5, (const struct backlight_properties*)$arg6)")
  public static Ptr<backlight_device> devm_backlight_device_register(Ptr<device> dev, String name,
      Ptr<device> parent, Ptr<?> devdata, Ptr<backlight_ops> ops, Ptr<backlight_properties> props) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_backlight_device_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_backlight_device_unregister(Ptr<device> dev, Ptr<backlight_device> bd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_battery_hook_register(Ptr<device> dev, Ptr<acpi_battery_hook> hook) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_battery_hook_unregister(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang. @Unsigned Long> devm_bitmap_alloc(Ptr<device> dev,
      @Unsigned int nbits, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_bitmap_free(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang. @Unsigned Long> devm_bitmap_zalloc(Ptr<device> dev,
      @Unsigned int nbits, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_blk_crypto_profile_init(Ptr<device> dev, Ptr<blk_crypto_profile> profile,
      @Unsigned int num_slots) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_bulk_get(Ptr<device> dev, int num_clks, Ptr<clk_bulk_data> clks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_bulk_get_all(Ptr<device> dev, Ptr<Ptr<clk_bulk_data>> clks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_bulk_get_all_enabled(Ptr<device> dev, Ptr<Ptr<clk_bulk_data>> clks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_bulk_get_optional(Ptr<device> dev, int num_clks,
      Ptr<clk_bulk_data> clks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_bulk_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_bulk_release_all(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_bulk_release_all_enable(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_get($arg1, (const u8*)$arg2)")
  public static Ptr<clk> devm_clk_get(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_get_enabled($arg1, (const u8*)$arg2)")
  public static Ptr<clk> devm_clk_get_enabled(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_get_optional($arg1, (const u8*)$arg2)")
  public static Ptr<clk> devm_clk_get_optional(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_get_optional_enabled($arg1, (const u8*)$arg2)")
  public static Ptr<clk> devm_clk_get_optional_enabled(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_get_optional_enabled_with_rate($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<clk> devm_clk_get_optional_enabled_with_rate(Ptr<device> dev, String id,
      @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_get_optional_prepared($arg1, (const u8*)$arg2)")
  public static Ptr<clk> devm_clk_get_optional_prepared(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_get_prepared($arg1, (const u8*)$arg2)")
  public static Ptr<clk> devm_clk_get_prepared(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_get_clk($arg1, $arg2, (const u8*)$arg3)")
  public static Ptr<clk> devm_clk_hw_get_clk(Ptr<device> dev, Ptr<clk_hw> hw, String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_hw_register(Ptr<device> dev, Ptr<clk_hw> hw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_register_clkdev($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static int devm_clk_hw_register_clkdev(Ptr<device> dev, Ptr<clk_hw> hw, String con_id,
      String dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_register_composite_pdata($arg1, (const u8*)$arg2, (const struct clk_parent_data*)$arg3, $arg4, $arg5, (const struct clk_ops*)$arg6, $arg7, (const struct clk_ops*)$arg8, $arg9, (const struct clk_ops*)$arg10, $arg11)")
  public static Ptr<clk_hw> devm_clk_hw_register_composite_pdata(Ptr<device> dev, String name,
      Ptr<clk_parent_data> parent_data, int num_parents, Ptr<clk_hw> mux_hw, Ptr<clk_ops> mux_ops,
      Ptr<clk_hw> rate_hw, Ptr<clk_ops> rate_ops, Ptr<clk_hw> gate_hw, Ptr<clk_ops> gate_ops,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_register_fixed_factor($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4, $arg5, $arg6)")
  public static Ptr<clk_hw> devm_clk_hw_register_fixed_factor(Ptr<device> dev, String name,
      String parent_name, @Unsigned long flags, @Unsigned int mult, @Unsigned int div) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_register_fixed_factor_fwname($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4, $arg5, $arg6, $arg7)")
  public static Ptr<clk_hw> devm_clk_hw_register_fixed_factor_fwname(Ptr<device> dev,
      Ptr<device_node> np, String name, String fw_name, @Unsigned long flags, @Unsigned int mult,
      @Unsigned int div) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_register_fixed_factor_index($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<clk_hw> devm_clk_hw_register_fixed_factor_index(Ptr<device> dev, String name,
      @Unsigned int index, @Unsigned long flags, @Unsigned int mult, @Unsigned int div) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_register_fixed_factor_parent_hw($arg1, (const u8*)$arg2, (const struct clk_hw*)$arg3, $arg4, $arg5, $arg6)")
  public static Ptr<clk_hw> devm_clk_hw_register_fixed_factor_parent_hw(Ptr<device> dev,
      String name, Ptr<clk_hw> parent_hw, @Unsigned long flags, @Unsigned int mult,
      @Unsigned int div) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_hw_register_fixed_factor_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_clk_hw_register_fixed_factor_with_accuracy_fwname($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static Ptr<clk_hw> devm_clk_hw_register_fixed_factor_with_accuracy_fwname(Ptr<device> dev,
      Ptr<device_node> np, String name, String fw_name, @Unsigned long flags, @Unsigned int mult,
      @Unsigned int div, @Unsigned long acc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_hw_register_fixed_rate_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_hw_release_composite(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_hw_release_divider(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_hw_release_gate(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_hw_release_mux(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_hw_unregister_cb(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_notifier_register(Ptr<device> dev, Ptr<clk> clk,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_notifier_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_put(Ptr<device> dev, Ptr<clk> clk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_clk_rate_exclusive_get(Ptr<device> dev, Ptr<clk> clk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_rate_exclusive_put(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<clk> devm_clk_register(Ptr<device> dev, Ptr<clk_hw> hw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clk_unregister_cb(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_clkdev_release(Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_component_match_release(Ptr<device> parent, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dev_dax> devm_create_dev_dax(Ptr<dev_dax_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_devfreq_add_device($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static Ptr<devfreq> devm_devfreq_add_device(Ptr<device> dev,
      Ptr<devfreq_dev_profile> profile, String governor_name, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_devfreq_add_governor(Ptr<device> dev, Ptr<devfreq_governor> governor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_devfreq_dev_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_dev_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<devfreq_event_dev> devm_devfreq_event_add_edev(Ptr<device> dev,
      Ptr<devfreq_event_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_devfreq_event_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_event_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_event_remove_edev(Ptr<device> dev, Ptr<devfreq_event_dev> edev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_notifier_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_opp_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_devfreq_register_notifier(Ptr<device> dev, Ptr<devfreq> devfreq,
      Ptr<notifier_block> nb, @Unsigned int list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_devfreq_register_opp_notifier(Ptr<device> dev, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_remove_device(Ptr<device> dev, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_remove_governor(Ptr<?> governor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_unregister_notifier(Ptr<device> dev, Ptr<devfreq> devfreq,
      Ptr<notifier_block> nb, @Unsigned int list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_devfreq_unregister_opp_notifier(Ptr<device> dev, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_device_add_group($arg1, (const struct attribute_group*)$arg2)")
  public static int devm_device_add_group(Ptr<device> dev, Ptr<attribute_group> grp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_dma_request_chan($arg1, (const u8*)$arg2)")
  public static Ptr<dma_chan> devm_dma_request_chan(Ptr<device> dev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_drm_bridge_add(Ptr<device> dev, Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_drm_dev_init_release(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_drm_panel_add_follower(Ptr<device> follower_dev,
      Ptr<drm_panel_follower> follower) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge> devm_drm_panel_bridge_add(Ptr<device> dev, Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge> devm_drm_panel_bridge_add_typed(Ptr<device> dev,
      Ptr<drm_panel> panel, @Unsigned int connector_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_drm_panel_bridge_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_drm_put_bridge(Ptr<device> dev, Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_extcon_dev_allocate($arg1, (const unsigned int*)$arg2)")
  public static Ptr<extcon_dev> devm_extcon_dev_allocate(Ptr<device> dev,
      Ptr<java.lang. @Unsigned Integer> supported_cable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_dev_free(Ptr<device> dev, Ptr<extcon_dev> edev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_extcon_dev_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_dev_notifier_all_unreg(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_dev_notifier_unreg(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_extcon_dev_register(Ptr<device> dev, Ptr<extcon_dev> edev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_dev_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_dev_unreg(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_dev_unregister(Ptr<device> dev, Ptr<extcon_dev> edev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_extcon_register_notifier(Ptr<device> dev, Ptr<extcon_dev> edev,
      @Unsigned int id, Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_extcon_register_notifier_all(Ptr<device> dev, Ptr<extcon_dev> edev,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_unregister_notifier(Ptr<device> dev, Ptr<extcon_dev> edev,
      @Unsigned int id, Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_extcon_unregister_notifier_all(Ptr<device> dev, Ptr<extcon_dev> edev,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_free_irq(Ptr<device> dev, @Unsigned int irq, Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_free_netdev(Ptr<device> dev, Ptr<?> _this) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_free_pages(Ptr<device> dev, @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_free_percpu(Ptr<device> dev, Ptr<?> pdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_fwnode_gpiod_get_index($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, (const u8*)$arg6)")
  public static Ptr<gpio_desc> devm_fwnode_gpiod_get_index(Ptr<device> dev,
      Ptr<fwnode_handle> fwnode, String con_id, int index, gpiod_flags flags, String label) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_fwnode_pwm_get($arg1, $arg2, (const u8*)$arg3)")
  public static Ptr<pwm_device> devm_fwnode_pwm_get(Ptr<device> dev, Ptr<fwnode_handle> fwnode,
      String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gen_pool_create($arg1, $arg2, $arg3, (const u8*)$arg4)")
  public static Ptr<gen_pool> devm_gen_pool_create(Ptr<device> dev, int min_alloc_order, int nid,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_gen_pool_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gen_pool_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_get_clk_from_child($arg1, $arg2, (const u8*)$arg3)")
  public static Ptr<clk> devm_get_clk_from_child(Ptr<device> dev, Ptr<device_node> np,
      String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long devm_get_free_pages(Ptr<device> dev,
      @Unsigned @OriginalName("gfp_t") int gfp_mask, @Unsigned int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gpio_chip_release(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gpio_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gpio_request_one($arg1, $arg2, $arg3, (const u8*)$arg4)")
  public static int devm_gpio_request_one(Ptr<device> dev, @Unsigned int gpio, @Unsigned long flags,
      String label) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_gpiochip_add_data_with_key(Ptr<device> dev, Ptr<gpio_chip> gc, Ptr<?> data,
      Ptr<lock_class_key> lock_key, Ptr<lock_class_key> request_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gpiod_get($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<gpio_desc> devm_gpiod_get(Ptr<device> dev, String con_id, gpiod_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gpiod_get_array($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<gpio_descs> devm_gpiod_get_array(Ptr<device> dev, String con_id,
      gpiod_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gpiod_get_array_optional($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<gpio_descs> devm_gpiod_get_array_optional(Ptr<device> dev, String con_id,
      gpiod_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gpiod_get_index($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static Ptr<gpio_desc> devm_gpiod_get_index(Ptr<device> dev, String con_id,
      @Unsigned int idx, gpiod_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gpiod_get_index_optional($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static Ptr<gpio_desc> devm_gpiod_get_index_optional(Ptr<device> dev, String con_id,
      @Unsigned int index, gpiod_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_gpiod_get_optional($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<gpio_desc> devm_gpiod_get_optional(Ptr<device> dev, String con_id,
      gpiod_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gpiod_put(Ptr<device> dev, Ptr<gpio_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gpiod_put_array(Ptr<device> dev, Ptr<gpio_descs> descs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gpiod_release(Ptr<?> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gpiod_release_array(Ptr<?> descs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_gpiod_unhinge(Ptr<device> dev, Ptr<gpio_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hte_register_chip(Ptr<hte_chip> chip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hte_request_ts_ns(Ptr<device> dev, Ptr<hte_ts_desc> desc,
      @OriginalName("hte_ts_cb_t") Ptr<?> cb, @OriginalName("hte_ts_sec_cb_t") Ptr<?> tcb,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_hwmon_device_register_with_groups($arg1, (const u8*)$arg2, $arg3, (const struct attribute_group**)$arg4)")
  public static Ptr<device> devm_hwmon_device_register_with_groups(Ptr<device> dev, String name,
      Ptr<?> drvdata, Ptr<Ptr<attribute_group>> groups) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_hwmon_device_register_with_info($arg1, (const u8*)$arg2, $arg3, (const struct hwmon_chip_info*)$arg4, (const struct attribute_group**)$arg5)")
  public static Ptr<device> devm_hwmon_device_register_with_info(Ptr<device> dev, String name,
      Ptr<?> drvdata, Ptr<hwmon_chip_info> chip, Ptr<Ptr<attribute_group>> extra_groups) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_hwmon_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_hwmon_sanitize_name($arg1, (const u8*)$arg2)")
  public static String devm_hwmon_sanitize_name(Ptr<device> dev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hwrng_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hwrng_register(Ptr<device> dev, Ptr<hwrng> rng) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_hwrng_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_hwrng_unregister(Ptr<device> dev, Ptr<hwrng> rng) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hwspin_lock_device_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hwspin_lock_free(Ptr<device> dev, Ptr<hwspinlock> hwlock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hwspin_lock_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_hwspin_lock_register($arg1, $arg2, (const struct hwspinlock_ops*)$arg3, $arg4, $arg5)")
  public static int devm_hwspin_lock_register(Ptr<device> dev, Ptr<hwspinlock_device> bank,
      Ptr<hwspinlock_ops> ops, int base_id, int num_locks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_hwspin_lock_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<hwspinlock> devm_hwspin_lock_request_specific(Ptr<device> dev,
      @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_hwspin_lock_unreg(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_hwspin_lock_unregister(Ptr<device> dev, Ptr<hwspinlock_device> bank) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_i2c_add_adapter(Ptr<device> dev, Ptr<i2c_adapter> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_i2c_del_adapter(Ptr<?> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<i2c_client> devm_i2c_new_dummy_device(Ptr<device> dev, Ptr<i2c_adapter> adapter,
      @Unsigned short address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_i2c_release_dummy(Ptr<?> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_icc_bulk_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_icc_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_init_badblocks(Ptr<device> dev, Ptr<badblocks> bb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<input_dev> devm_input_allocate_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_input_device_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_input_device_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_input_device_unregister(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<intel_scu_ipc_dev> devm_intel_scu_ipc_dev_get(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_intel_scu_ipc_dev_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_intel_scu_ipc_unregister(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_ioport_map(Ptr<device> dev, @Unsigned long port, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_ioport_map_match(Ptr<device> dev, Ptr<?> res, Ptr<?> match_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_ioport_map_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_ioport_unmap(Ptr<device> dev, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_ioremap(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long offset,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_ioremap_match(Ptr<device> dev, Ptr<?> res, Ptr<?> match_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_ioremap_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_ioremap_resource($arg1, (const struct resource*)$arg2)")
  public static Ptr<?> devm_ioremap_resource(Ptr<device> dev, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_ioremap_resource_wc($arg1, (const struct resource*)$arg2)")
  public static Ptr<?> devm_ioremap_resource_wc(Ptr<device> dev, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_ioremap_uc(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long offset,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_ioremap_wc(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long offset,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_iounmap(Ptr<device> dev, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_irq_alloc_generic_chip($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<irq_chip_generic> devm_irq_alloc_generic_chip(Ptr<device> dev, String name,
      int num_ct, @Unsigned int irq_base, Ptr<?> reg_base,
      @OriginalName("irq_flow_handler_t") Ptr<?> handler) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_irq_desc_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_domain> devm_irq_domain_create_sim(Ptr<device> dev,
      Ptr<fwnode_handle> fwnode, @Unsigned int num_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_irq_domain_create_sim_full($arg1, $arg2, $arg3, (const struct irq_sim_ops*)$arg4, $arg5)")
  public static Ptr<irq_domain> devm_irq_domain_create_sim_full(Ptr<device> dev,
      Ptr<fwnode_handle> fwnode, @Unsigned int num_irqs, Ptr<irq_sim_ops> ops, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_irq_domain_instantiate($arg1, (const struct irq_domain_info*)$arg2)")
  public static Ptr<irq_domain> devm_irq_domain_instantiate(Ptr<device> dev,
      Ptr<irq_domain_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_irq_domain_remove(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_irq_domain_remove_sim(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_irq_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_irq_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_irq_remove_generic_chip(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_irq_setup_generic_chip(Ptr<device> dev, Ptr<irq_chip_generic> gc,
      @Unsigned int msk, irq_gc_flags flags, @Unsigned int clr, @Unsigned int set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_is_action_added($arg1, (void (*)(void*))$arg2, $arg3)")
  public static boolean devm_is_action_added(Ptr<device> dev, Ptr<?> action, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_kasprintf($arg1, $arg2, (const u8*)$arg3, $arg4_)")
  public static String devm_kasprintf(Ptr<device> dev, @Unsigned @OriginalName("gfp_t") int gfp,
      String fmt, java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_kasprintf_strarray($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<String> devm_kasprintf_strarray(Ptr<device> dev, String prefix,
      @Unsigned long n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_kfree($arg1, (const void*)$arg2)")
  public static void devm_kfree(Ptr<device> dev, Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_kfree_strarray(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_kmalloc(Ptr<device> dev, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_kmalloc_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_kmalloc_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_kmemdup($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static Ptr<?> devm_kmemdup(Ptr<device> dev, Ptr<?> src, @Unsigned long len,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_krealloc(Ptr<device> dev, Ptr<?> ptr, @Unsigned long new_size,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_kstrdup($arg1, (const u8*)$arg2, $arg3)")
  public static String devm_kstrdup(Ptr<device> dev, String s,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)devm_kstrdup_const($arg1, (const u8*)$arg2, $arg3))")
  public static String devm_kstrdup_const(Ptr<device> dev, String s,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_kvasprintf($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static String devm_kvasprintf(Ptr<device> dev, @Unsigned @OriginalName("gfp_t") int gfp,
      String fmt, Ptr<__va_list_tag> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_led_classdev_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_led_classdev_register_ext(Ptr<device> parent, Ptr<led_classdev> led_cdev,
      Ptr<led_init_data> init_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_led_classdev_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_led_classdev_unregister(Ptr<device> dev, Ptr<led_classdev> led_cdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<led_classdev> devm_led_get(Ptr<device> dev, String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_led_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_led_trigger_register(Ptr<device> dev, Ptr<led_trigger> trig) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_led_trigger_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_mbox_controller_register(Ptr<device> dev, Ptr<mbox_controller> mbox) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mii_bus> devm_mdiobus_alloc_size(Ptr<device> dev, int sizeof_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_mdiobus_free(Ptr<device> dev, Ptr<?> _this) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_mdiobus_unregister(Ptr<device> dev, Ptr<?> _this) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_memremap(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long offset, @Unsigned long size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_memremap_match(Ptr<device> dev, Ptr<?> res, Ptr<?> match_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_memremap_pages(Ptr<device> dev, Ptr<dev_pagemap> pgmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_memremap_pages_release(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_memremap_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_memunmap(Ptr<device> dev, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_memunmap_pages(Ptr<device> dev, Ptr<dev_pagemap> pgmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_mfd_add_devices($arg1, $arg2, (const struct mfd_cell*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int devm_mfd_add_devices(Ptr<device> dev, int id, Ptr<mfd_cell> cells, int n_devs,
      Ptr<resource> mem_base, int irq_base, Ptr<irq_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_mfd_dev_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_mipi_dsi_attach(Ptr<device> dev, Ptr<mipi_dsi_device> dsi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_mipi_dsi_detach(Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_mipi_dsi_device_register_full($arg1, $arg2, (const struct mipi_dsi_device_info*)$arg3)")
  public static Ptr<mipi_dsi_device> devm_mipi_dsi_device_register_full(Ptr<device> dev,
      Ptr<mipi_dsi_host> host, Ptr<mipi_dsi_device_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_mipi_dsi_device_unregister(Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mmc_host> devm_mmc_alloc_host(Ptr<device> dev, int extra) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_mmc_host_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_name_match(Ptr<device> dev, Ptr<?> res, Ptr<?> match_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_namespace_disable(Ptr<device> dev, Ptr<nd_namespace_common> ndns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_namespace_enable(Ptr<device> dev, Ptr<nd_namespace_common> ndns,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_nsio_disable(Ptr<device> dev, Ptr<nd_namespace_io> nsio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_nsio_enable(Ptr<device> dev, Ptr<nd_namespace_io> nsio,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_nvdimm_memremap(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long offset, @Unsigned long size,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_nvmem_cell_get($arg1, (const u8*)$arg2)")
  public static Ptr<nvmem_cell> devm_nvmem_cell_get(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_nvmem_cell_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_nvmem_cell_put(Ptr<device> dev, Ptr<nvmem_cell> cell) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_nvmem_cell_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_nvmem_device_get($arg1, (const u8*)$arg2)")
  public static Ptr<nvmem_device> devm_nvmem_device_get(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_nvmem_device_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_nvmem_device_put(Ptr<device> dev, Ptr<nvmem_device> nvmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_nvmem_device_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_nvmem_register($arg1, (const struct nvmem_config*)$arg2)")
  public static Ptr<nvmem_device> devm_nvmem_register(Ptr<device> dev, Ptr<nvmem_config> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_nvmem_unregister(Ptr<?> nvmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<backlight_device> devm_of_find_backlight(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_of_icc_bulk_get(Ptr<device> dev, int num_paths, Ptr<icc_bulk_data> paths) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_of_icc_get($arg1, (const u8*)$arg2)")
  public static Ptr<icc_path> devm_of_icc_get(Ptr<device> dev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_of_iomap(Ptr<device> dev, Ptr<device_node> node, int index,
      Ptr<java.lang. @Unsigned @OriginalName("resource_size_t") Long> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<led_classdev> devm_of_led_get(Ptr<device> dev, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<led_classdev> devm_of_led_get_optional(Ptr<device> dev, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_of_phy_get($arg1, $arg2, (const u8*)$arg3)")
  public static Ptr<phy> devm_of_phy_get(Ptr<device> dev, Ptr<device_node> np, String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<phy> devm_of_phy_get_by_index(Ptr<device> dev, Ptr<device_node> np, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_of_phy_optional_get($arg1, $arg2, (const u8*)$arg3)")
  public static Ptr<phy> devm_of_phy_optional_get(Ptr<device> dev, Ptr<device_node> np,
      String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_of_phy_provider_unregister(Ptr<device> dev,
      Ptr<phy_provider> phy_provider) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pages_match(Ptr<device> dev, Ptr<?> res, Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pages_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_host_bridge> devm_pci_alloc_host_bridge(Ptr<device> dev,
      @Unsigned long priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pci_alloc_host_bridge_release(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pci_epc_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_pci_remap_cfg_resource(Ptr<device> dev, Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_pci_remap_cfgspace(Ptr<device> dev,
      @Unsigned @OriginalName("resource_size_t") long offset,
      @Unsigned @OriginalName("resource_size_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pci_remap_iospace($arg1, (const struct resource*)$arg2, $arg3)")
  public static int devm_pci_remap_iospace(Ptr<device> dev, Ptr<resource> res,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pci_unmap_iospace(Ptr<device> dev, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_percpu_match(Ptr<device> dev, Ptr<?> data, Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_percpu_release(Ptr<device> dev, Ptr<?> pdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_phy_consume(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_phy_create($arg1, $arg2, (const struct phy_ops*)$arg3)")
  public static Ptr<phy> devm_phy_create(Ptr<device> dev, Ptr<device_node> node, Ptr<phy_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_phy_destroy(Ptr<device> dev, Ptr<phy> phy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_phy_get($arg1, (const u8*)$arg2)")
  public static Ptr<phy> devm_phy_get(Ptr<device> dev, String string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_phy_match(Ptr<device> dev, Ptr<?> res, Ptr<?> match_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_phy_optional_get($arg1, (const u8*)$arg2)")
  public static Ptr<phy> devm_phy_optional_get(Ptr<device> dev, String string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_phy_provider_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_phy_put(Ptr<device> dev, Ptr<phy> phy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_phy_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pinctrl_dev_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pinctrl_dev_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pinctrl> devm_pinctrl_get(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pinctrl_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pinctrl_put(Ptr<pinctrl> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pinctrl_register($arg1, (const struct pinctrl_desc*)$arg2, $arg3)")
  public static Ptr<pinctrl_dev> devm_pinctrl_register(Ptr<device> dev, Ptr<pinctrl_desc> pctldesc,
      Ptr<?> driver_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pinctrl_register_and_init($arg1, (const struct pinctrl_desc*)$arg2, $arg3, $arg4)")
  public static int devm_pinctrl_register_and_init(Ptr<device> dev, Ptr<pinctrl_desc> pctldesc,
      Ptr<?> driver_data, Ptr<Ptr<pinctrl_dev>> pctldev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pinctrl_register_mappings($arg1, (const struct pinctrl_map*)$arg2, $arg3)")
  public static int devm_pinctrl_register_mappings(Ptr<device> dev, Ptr<pinctrl_map> maps,
      @Unsigned int num_maps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pinctrl_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pinctrl_unregister(Ptr<device> dev, Ptr<pinctrl_dev> pctldev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pinctrl_unregister_mappings(Ptr<?> maps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_platform_get_and_ioremap_resource(Ptr<platform_device> pdev,
      @Unsigned int index, Ptr<Ptr<resource>> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_platform_get_irqs_affinity(Ptr<platform_device> dev,
      Ptr<irq_affinity> affd, @Unsigned int minvec, @Unsigned int maxvec,
      Ptr<Ptr<java.lang.Integer>> irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_platform_get_irqs_affinity_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> devm_platform_ioremap_resource(Ptr<platform_device> pdev,
      @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_platform_ioremap_resource_byname($arg1, (const u8*)$arg2)")
  public static Ptr<?> devm_platform_ioremap_resource_byname(Ptr<platform_device> pdev,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pm_clear_wake_irq(Ptr<?> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pm_clk_create(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pm_domain_attach_list($arg1, (const struct dev_pm_domain_attach_data*)$arg2, $arg3)")
  public static int devm_pm_domain_attach_list(Ptr<device> dev, Ptr<dev_pm_domain_attach_data> data,
      Ptr<Ptr<dev_pm_domain_list>> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pm_domain_detach_list(Ptr<?> _list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pm_opp_config_release(Ptr<?> token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pm_opp_set_config(Ptr<device> dev, Ptr<dev_pm_opp_config> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pm_runtime_enable(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pm_runtime_get_noresume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pm_runtime_set_active_enabled(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pm_set_wake_irq(Ptr<device> dev, int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_power_supply_get_by_reference($arg1, (const u8*)$arg2)")
  public static Ptr<power_supply> devm_power_supply_get_by_reference(Ptr<device> dev,
      String property) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_power_supply_put(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_power_supply_register($arg1, (const struct power_supply_desc*)$arg2, (const struct power_supply_config*)$arg3)")
  public static Ptr<power_supply> devm_power_supply_register(Ptr<device> parent,
      Ptr<power_supply_desc> desc, Ptr<power_supply_config> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_power_supply_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_pse_controller_register(Ptr<device> dev, Ptr<pse_controller_dev> pcdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pse_controller_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pse_irq_helper($arg1, $arg2, $arg3, (const struct pse_irq_desc*)$arg4)")
  public static int devm_pse_irq_helper(Ptr<pse_controller_dev> pcdev, int irq, int irq_flags,
      Ptr<pse_irq_desc> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pwm_get($arg1, (const u8*)$arg2)")
  public static Ptr<pwm_device> devm_pwm_get(Ptr<device> dev, String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_pwm_lpss_probe($arg1, $arg2, (const struct pwm_lpss_boardinfo*)$arg3)")
  public static Ptr<pwm_chip> devm_pwm_lpss_probe(Ptr<device> dev, Ptr<?> base,
      Ptr<pwm_lpss_boardinfo> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pwm_release(Ptr<?> pwm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pwm_chip> devm_pwmchip_alloc(Ptr<device> parent, @Unsigned int npwm,
      @Unsigned long sizeof_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pwmchip_put(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_pwmchip_remove(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_rdev_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_region_match(Ptr<device> dev, Ptr<?> res, Ptr<?> match_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_region_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_register_dax_mapping(Ptr<dev_dax> dev_dax, int range_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_register_framebuffer(Ptr<device> dev, Ptr<fb_info> fb_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_register_netdev(Ptr<device> dev, Ptr<net_device> ndev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_register_power_off_handler($arg1, (int (*)(struct sys_off_data*))$arg2, $arg3)")
  public static int devm_register_power_off_handler(Ptr<device> dev, Ptr<?> callback,
      Ptr<?> cb_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_register_reboot_notifier(Ptr<device> dev, Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_register_restart_handler($arg1, (int (*)(struct sys_off_data*))$arg2, $arg3)")
  public static int devm_register_restart_handler(Ptr<device> dev, Ptr<?> callback,
      Ptr<?> cb_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_register_sys_off_handler($arg1, $arg2, $arg3, (int (*)(struct sys_off_data*))$arg4, $arg5)")
  public static int devm_register_sys_off_handler(Ptr<device> dev, sys_off_mode mode, int priority,
      Ptr<?> callback, Ptr<?> cb_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regmap_add_irq_chip($arg1, $arg2, $arg3, $arg4, $arg5, (const struct regmap_irq_chip*)$arg6, $arg7)")
  public static int devm_regmap_add_irq_chip(Ptr<device> dev, Ptr<regmap> map, int irq,
      int irq_flags, int irq_base, Ptr<regmap_irq_chip> chip, Ptr<Ptr<regmap_irq_chip_data>> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regmap_add_irq_chip_fwnode($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, (const struct regmap_irq_chip*)$arg7, $arg8)")
  public static int devm_regmap_add_irq_chip_fwnode(Ptr<device> dev, Ptr<fwnode_handle> fwnode,
      Ptr<regmap> map, int irq, int irq_flags, int irq_base, Ptr<regmap_irq_chip> chip,
      Ptr<Ptr<regmap_irq_chip_data>> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regmap_del_irq_chip(Ptr<device> dev, int irq,
      Ptr<regmap_irq_chip_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<regmap_field> devm_regmap_field_alloc(Ptr<device> dev, Ptr<regmap> regmap,
      reg_field reg_field) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regmap_field_bulk_alloc($arg1, $arg2, $arg3, (const struct reg_field*)$arg4, $arg5)")
  public static int devm_regmap_field_bulk_alloc(Ptr<device> dev, Ptr<regmap> regmap,
      Ptr<Ptr<regmap_field>> rm_field, Ptr<reg_field> reg_field, int num_fields) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regmap_field_bulk_free(Ptr<device> dev, Ptr<regmap_field> field) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regmap_field_free(Ptr<device> dev, Ptr<regmap_field> field) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regmap_irq_chip_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regmap_irq_chip_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regmap_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_bulk_disable(Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regulator_bulk_get(Ptr<device> dev, int num_consumers,
      Ptr<regulator_bulk_data> consumers) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_bulk_get_const($arg1, $arg2, (const struct regulator_bulk_data*)$arg3, $arg4)")
  public static int devm_regulator_bulk_get_const(Ptr<device> dev, int num_consumers,
      Ptr<regulator_bulk_data> in_consumers, Ptr<Ptr<regulator_bulk_data>> out_consumers) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_bulk_get_enable($arg1, $arg2, (const u8**)$arg3)")
  public static int devm_regulator_bulk_get_enable(Ptr<device> dev, int num_consumers,
      Ptr<String> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regulator_bulk_get_exclusive(Ptr<device> dev, int num_consumers,
      Ptr<regulator_bulk_data> consumers) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regulator_bulk_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_bulk_put(Ptr<regulator_bulk_data> consumers) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_bulk_register_supply_alias($arg1, (const u8**)$arg2, $arg3, (const u8**)$arg4, $arg5)")
  public static int devm_regulator_bulk_register_supply_alias(Ptr<device> dev, Ptr<String> id,
      Ptr<device> alias_dev, Ptr<String> alias_id, int num_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_bulk_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_destroy_notifier(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_destroy_supply_alias(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_get($arg1, (const u8*)$arg2)")
  public static Ptr<regulator> devm_regulator_get(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_get_enable($arg1, (const u8*)$arg2)")
  public static int devm_regulator_get_enable(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_get_enable_optional($arg1, (const u8*)$arg2)")
  public static int devm_regulator_get_enable_optional(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_get_enable_read_voltage($arg1, (const u8*)$arg2)")
  public static int devm_regulator_get_enable_read_voltage(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_get_exclusive($arg1, (const u8*)$arg2)")
  public static Ptr<regulator> devm_regulator_get_exclusive(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_get_optional($arg1, (const u8*)$arg2)")
  public static Ptr<regulator> devm_regulator_get_optional(Ptr<device> dev, String id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_irq_helper($arg1, (const struct regulator_irq_desc*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static Ptr<?> devm_regulator_irq_helper(Ptr<device> dev, Ptr<regulator_irq_desc> d,
      int irq, int irq_flags, int common_errs, Ptr<java.lang.Integer> per_rdev_errs,
      Ptr<Ptr<regulator_dev>> rdev, int rdev_amount) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regulator_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regulator_match_notifier(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regulator_match_supply_alias(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_put(Ptr<regulator> regulator) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_register($arg1, (const struct regulator_desc*)$arg2, (const struct regulator_config*)$arg3)")
  public static Ptr<regulator_dev> devm_regulator_register(Ptr<device> dev,
      Ptr<regulator_desc> regulator_desc, Ptr<regulator_config> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_regulator_register_notifier(Ptr<regulator> regulator,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_regulator_register_supply_alias($arg1, (const u8*)$arg2, $arg3, (const u8*)$arg4)")
  public static int devm_regulator_register_supply_alias(Ptr<device> dev, String id,
      Ptr<device> alias_dev, String alias_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_regulator_unregister_notifier(Ptr<regulator> regulator,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_release_action($arg1, (void (*)(void*))$arg2, $arg3)")
  public static void devm_release_action(Ptr<device> dev, Ptr<?> action, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_release_resource(Ptr<device> dev, Ptr<resource> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_remove_action_nowarn($arg1, (void (*)(void*))$arg2, $arg3)")
  public static int devm_remove_action_nowarn(Ptr<device> dev, Ptr<?> action, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_request_any_context_irq($arg1, $arg2, $arg3, $arg4, (const u8*)$arg5, $arg6)")
  public static int devm_request_any_context_irq(Ptr<device> dev, @Unsigned int irq,
      @OriginalName("irq_handler_t") Ptr<?> handler, @Unsigned long irqflags, String devname,
      Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<resource> devm_request_free_mem_region(Ptr<device> dev, Ptr<resource> base,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_request_pci_bus_resources(Ptr<device> dev, Ptr<list_head> resources) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_request_resource(Ptr<device> dev, Ptr<resource> root, Ptr<resource> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_request_threaded_irq($arg1, $arg2, $arg3, $arg4, $arg5, (const u8*)$arg6, $arg7)")
  public static int devm_request_threaded_irq(Ptr<device> dev, @Unsigned int irq,
      @OriginalName("irq_handler_t") Ptr<?> handler,
      @OriginalName("irq_handler_t") Ptr<?> thread_fn, @Unsigned long irqflags, String devname,
      Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<reset_control> devm_reset_control_array_get(Ptr<device> dev,
      reset_control_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_reset_control_bulk_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_reset_control_bulk_release_deasserted(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_reset_control_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_reset_control_release_deasserted(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_reset_controller_register(Ptr<device> dev,
      Ptr<reset_controller_dev> rcdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_reset_controller_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_resource_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_resource_release(Ptr<device> dev, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_rproc_add(Ptr<device> dev, Ptr<rproc> rproc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_rproc_alloc($arg1, (const u8*)$arg2, (const struct rproc_ops*)$arg3, (const u8*)$arg4, $arg5)")
  public static Ptr<rproc> devm_rproc_alloc(Ptr<device> dev, String name, Ptr<rproc_ops> ops,
      String firmware, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_rproc_free(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_rproc_remove(Ptr<?> rproc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<rtc_device> devm_rtc_allocate_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_rtc_device_register($arg1, (const u8*)$arg2, (const struct rtc_class_ops*)$arg3, $arg4)")
  public static Ptr<rtc_device> devm_rtc_device_register(Ptr<device> dev, String name,
      Ptr<rtc_class_ops> ops, Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_rtc_nvmem_register(Ptr<rtc_device> rtc, Ptr<nvmem_config> nvmem_config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_rtc_release_device(Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_rtc_unregister_device(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_serdev_device_close(Ptr<?> serdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_serdev_device_open(Ptr<device> dev, Ptr<serdev_device> serdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_spi_mem_dirmap_create($arg1, $arg2, (const struct spi_mem_dirmap_info*)$arg3)")
  public static Ptr<spi_mem_dirmap_desc> devm_spi_mem_dirmap_create(Ptr<device> dev,
      Ptr<spi_mem> mem, Ptr<spi_mem_dirmap_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_spi_mem_dirmap_destroy(Ptr<device> dev, Ptr<spi_mem_dirmap_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_spi_mem_dirmap_match(Ptr<device> dev, Ptr<?> res, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_spi_mem_dirmap_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<spi_offload> devm_spi_offload_alloc(Ptr<device> dev, @Unsigned long priv_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_spi_offload_get($arg1, $arg2, (const struct spi_offload_config*)$arg3)")
  public static Ptr<spi_offload> devm_spi_offload_get(Ptr<device> dev, Ptr<spi_device> spi,
      Ptr<spi_offload_config> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_chan> devm_spi_offload_rx_stream_request_dma_chan(Ptr<device> dev,
      Ptr<spi_offload> offload) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<spi_offload_trigger> devm_spi_offload_trigger_get(Ptr<device> dev,
      Ptr<spi_offload> offload, spi_offload_trigger_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_spi_offload_trigger_register(Ptr<device> dev,
      Ptr<spi_offload_trigger_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_chan> devm_spi_offload_tx_stream_request_dma_chan(Ptr<device> dev,
      Ptr<spi_offload> offload) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_spi_optimize_message(Ptr<device> dev, Ptr<spi_device> spi,
      Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_spi_register_controller(Ptr<device> dev, Ptr<spi_controller> ctlr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_spi_release_controller(Ptr<device> dev, Ptr<?> ctlr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_spi_unoptimize_message(Ptr<?> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_spi_unregister(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_thermal_add_hwmon_sysfs(Ptr<device> dev, Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_thermal_hwmon_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_thermal_of_cooling_device_register($arg1, $arg2, (const u8*)$arg3, $arg4, (const struct thermal_cooling_device_ops*)$arg5)")
  public static Ptr<thermal_cooling_device> devm_thermal_of_cooling_device_register(Ptr<device> dev,
      Ptr<device_node> np, String type, Ptr<?> devdata, Ptr<thermal_cooling_device_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_unregister_framebuffer(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_unregister_netdev(Ptr<device> dev, Ptr<?> _this) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_unregister_reboot_notifier(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_unregister_sys_off_handler(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_phy> devm_usb_get_phy(Ptr<device> dev, usb_phy_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<usb_phy> devm_usb_get_phy_by_node(Ptr<device> dev, Ptr<device_node> node,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("devm_usb_get_phy_by_phandle($arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<usb_phy> devm_usb_get_phy_by_phandle(Ptr<device> dev, String phandle,
      char index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_usb_phy_release(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_usb_phy_release2(Ptr<device> dev, Ptr<?> _res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int devm_watchdog_register_device(Ptr<device> dev, Ptr<watchdog_device> wdd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void devm_watchdog_unregister_device(Ptr<device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum devm_ioremap_type"
  )
  public enum devm_ioremap_type implements Enum<devm_ioremap_type>, TypedEnum<devm_ioremap_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DEVM_IOREMAP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DEVM_IOREMAP"
    )
    DEVM_IOREMAP,

    /**
     * {@code DEVM_IOREMAP_UC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DEVM_IOREMAP_UC"
    )
    DEVM_IOREMAP_UC,

    /**
     * {@code DEVM_IOREMAP_WC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DEVM_IOREMAP_WC"
    )
    DEVM_IOREMAP_WC,

    /**
     * {@code DEVM_IOREMAP_NP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DEVM_IOREMAP_NP"
    )
    DEVM_IOREMAP_NP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct devm_clk_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class devm_clk_state extends Struct {
    public Ptr<clk> clk;

    public Ptr<?> exit;
  }
}
