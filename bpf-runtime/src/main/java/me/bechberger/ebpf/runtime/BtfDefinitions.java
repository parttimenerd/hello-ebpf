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
 * Generated class for BPF runtime types that start with btf
 */
@java.lang.SuppressWarnings("unused")
public final class BtfDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__btf_array_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void __btf_array_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id,
      Ptr<?> data, char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__btf_kfunc_id_set_contains((const struct btf*)$arg1, $arg2, $arg3, (const struct bpf_prog*)$arg4)")
  public static Ptr<java.lang. @Unsigned Integer> __btf_kfunc_id_set_contains(Ptr<btf> btf,
      btf_kfunc_hook hook, @Unsigned int kfunc_btf_id, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)__btf_name_by_offset((const struct btf*)$arg1, $arg2))")
  public static String __btf_name_by_offset(Ptr<btf> btf, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)__btf_resolve_size((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, (const struct btf_type**)$arg4, $arg5, $arg6, $arg7))")
  public static Ptr<btf_type> __btf_resolve_size(Ptr<btf> btf, Ptr<btf_type> type,
      Ptr<java.lang. @Unsigned Integer> type_size, Ptr<Ptr<btf_type>> elem_type,
      Ptr<java.lang. @Unsigned Integer> elem_id, Ptr<java.lang. @Unsigned Integer> total_nelems,
      Ptr<java.lang. @Unsigned Integer> type_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__btf_type_is_scalar_struct($arg1, (const struct btf*)$arg2, (const struct btf_type*)$arg3, $arg4)")
  public static boolean __btf_type_is_scalar_struct(Ptr<bpf_verifier_env> env, Ptr<btf> btf,
      Ptr<btf_type> t, int rec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__btf_verifier_log($arg1, (const u8*)$arg2, $arg3_)")
  public static void __btf_verifier_log(Ptr<bpf_verifier_log> log, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__btf_verifier_log_type($arg1, (const struct btf_type*)$arg2, $arg3, (const u8*)$arg4, $arg5_)")
  public static void __btf_verifier_log_type(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      boolean log_details, String fmt, java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_add_type(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_alloc_id(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_array_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_array_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_array_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_array_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_array_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_array_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_array_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_array_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_array_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_array_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id,
      Ptr<?> data, char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_base_btf((const struct btf*)$arg1)")
  public static Ptr<btf> btf_base_btf(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void btf_bitfield_show(Ptr<?> data, char bits_offset, char nr_bits,
      Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_check_all_metas(Ptr<btf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_check_all_types(Ptr<btf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_check_and_fixup_fields((const struct btf*)$arg1, $arg2)")
  public static int btf_check_and_fixup_fields(Ptr<btf> btf, Ptr<btf_record> rec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_check_func_type_match($arg1, $arg2, (const struct btf_type*)$arg3, $arg4, (const struct btf_type*)$arg5)")
  public static int btf_check_func_type_match(Ptr<bpf_verifier_log> log, Ptr<btf> btf1,
      Ptr<btf_type> t1, Ptr<btf> btf2, Ptr<btf_type> t2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_check_iter_arg($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_check_iter_arg(Ptr<btf> btf, Ptr<btf_type> func, int arg_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_check_iter_kfuncs($arg1, (const u8*)$arg2, (const struct btf_type*)$arg3, $arg4)")
  public static int btf_check_iter_kfuncs(Ptr<btf> btf, String func_name, Ptr<btf_type> func,
      @Unsigned int func_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_check_subprog_call(Ptr<bpf_verifier_env> env, int subprog,
      Ptr<bpf_reg_state> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_check_type_match($arg1, (const struct bpf_prog*)$arg2, $arg3, (const struct btf_type*)$arg4)")
  public static int btf_check_type_match(Ptr<bpf_verifier_log> log, Ptr<bpf_prog> prog,
      Ptr<btf> btf2, Ptr<btf_type> t2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_check_type_tags(Ptr<btf_verifier_env> env, Ptr<btf> btf, int start_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ctx_access($arg1, $arg2, $arg3, (const struct bpf_prog*)$arg4, $arg5)")
  public static boolean btf_ctx_access(int off, int size, bpf_access_type type, Ptr<bpf_prog> prog,
      Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ctx_arg_idx($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static @Unsigned int btf_ctx_arg_idx(Ptr<btf> btf, Ptr<btf_type> func_proto, int off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ctx_arg_offset((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_ctx_arg_offset(Ptr<btf> btf, Ptr<btf_type> func_proto,
      @Unsigned int arg_no) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_datasec_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_datasec_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_datasec_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_datasec_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_datasec_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_datasec_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_datasec_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_datasec_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id,
      Ptr<?> data, char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_decl_tag_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_decl_tag_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_decl_tag_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_decl_tag_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_decl_tag_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_decl_tag_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_df_check_kflag_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_df_check_kflag_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_df_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_df_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_df_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_df_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_df_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_df_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id, Ptr<?> data,
      char bits_offsets, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_distill_func_proto($arg1, $arg2, (const struct btf_type*)$arg3, (const u8*)$arg4, $arg5)")
  public static int btf_distill_func_proto(Ptr<bpf_verifier_log> log, Ptr<btf> btf,
      Ptr<btf_type> func, String tname, Ptr<btf_func_model> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_enum64_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_enum64_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_enum64_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_enum64_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id,
      Ptr<?> data, char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_enum_check_kflag_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_enum_check_kflag_member(Ptr<btf_verifier_env> env,
      Ptr<btf_type> struct_type, Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_enum_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_enum_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_enum_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_enum_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_enum_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_enum_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_enum_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_enum_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id,
      Ptr<?> data, char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_field_iter_init(Ptr<btf_field_iter> it, Ptr<btf_type> t,
      btf_field_iter_kind iter_kind) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang. @Unsigned Integer> btf_field_iter_next(Ptr<btf_field_iter> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_find_by_name_kind((const struct btf*)$arg1, (const u8*)$arg2, $arg3)")
  public static int btf_find_by_name_kind(Ptr<btf> btf, String name, char kind) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)btf_find_decl_tag_value((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, (const u8*)$arg4))")
  public static String btf_find_decl_tag_value(Ptr<btf> btf, Ptr<btf_type> pt, int comp_idx,
      String tag_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_find_dtor_kfunc(Ptr<btf> btf, @Unsigned int btf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_find_field_one((const struct btf*)$arg1, (const struct btf_type*)$arg2, (const struct btf_type*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9, $arg10, $arg11)")
  public static int btf_find_field_one(Ptr<btf> btf, Ptr<btf_type> var, Ptr<btf_type> var_type,
      int var_idx, @Unsigned int off, @Unsigned int expected_size, @Unsigned int field_mask,
      Ptr<java.lang. @Unsigned Integer> seen_mask, Ptr<btf_field_info> info, int info_cnt,
      @Unsigned int level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_find_func_proto((const u8*)$arg1, $arg2))")
  public static Ptr<btf_type> btf_find_func_proto(String func_name, Ptr<Ptr<btf>> btf_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_find_next_decl_tag((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static int btf_find_next_decl_tag(Ptr<btf> btf, Ptr<btf_type> pt, int comp_idx,
      String tag_key, int last_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_find_struct_field((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int btf_find_struct_field(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int field_mask,
      Ptr<btf_field_info> info, int info_cnt, @Unsigned int level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_member*)btf_find_struct_member($arg1, (const struct btf_type*)$arg2, (const u8*)$arg3, $arg4))")
  public static Ptr<btf_member> btf_find_struct_member(Ptr<btf> btf, Ptr<btf_type> type,
      String member_name, Ptr<java.lang. @Unsigned Integer> anon_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_find_struct_meta((const struct btf*)$arg1, $arg2)")
  public static Ptr<btf_struct_meta> btf_find_struct_meta(Ptr<btf> btf, @Unsigned int btf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_float_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_float_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_float_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_float_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_float_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_float_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void btf_free(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void btf_free_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_func_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_func_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_func_proto_check($arg1, (const struct btf_type*)$arg2)")
  public static int btf_func_proto_check(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_func_proto_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_func_proto_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_func_proto_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_func_proto_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_func_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_func_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_fwd_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_fwd_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_fwd_type_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_fwd_type_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_generic_check_kflag_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_generic_check_kflag_member(Ptr<btf_verifier_env> env,
      Ptr<btf_type> struct_type, Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void btf_get(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<btf> btf_get_by_fd(int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_get_fd_by_id(@Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_get_field_type((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int btf_get_field_type(Ptr<btf> btf, Ptr<btf_type> var_type,
      @Unsigned int field_mask, Ptr<java.lang. @Unsigned Integer> seen_mask,
      Ptr<java.lang.Integer> align, Ptr<java.lang.Integer> sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_param*)btf_get_func_param((const struct btf_type*)$arg1, $arg2))")
  public static Ptr<btf_param> btf_get_func_param(Ptr<btf_type> func_proto,
      Ptr<java.lang.Integer> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_get_info_by_fd((const struct btf*)$arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int btf_get_info_by_fd(Ptr<btf> btf, Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_get_module_btf((const struct module*)$arg1)")
  public static Ptr<btf> btf_get_module_btf(Ptr<module> module) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)btf_get_name((const struct btf*)$arg1))")
  public static String btf_get_name(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_get_ptr_to_btf_id($arg1, $arg2, (const struct btf*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_get_ptr_to_btf_id(Ptr<bpf_verifier_log> log, int arg_idx, Ptr<btf> btf,
      Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_id_cmp_func((const void*)$arg1, (const void*)$arg2)")
  public static int btf_id_cmp_func(Ptr<?> a, Ptr<?> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void btf_int128_print(Ptr<btf_show> show, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_int_check_kflag_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_int_check_kflag_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_int_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_int_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_int_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_int_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_int_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_int_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_int_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_int_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id, Ptr<?> data,
      char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_is_kernel((const struct btf*)$arg1)")
  public static boolean btf_is_kernel(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_is_module((const struct btf*)$arg1)")
  public static boolean btf_is_module(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_is_prog_ctx_type($arg1, (const struct btf*)$arg2, (const struct btf_type*)$arg3, $arg4, $arg5)")
  public static boolean btf_is_prog_ctx_type(Ptr<bpf_verifier_log> log, Ptr<btf> btf,
      Ptr<btf_type> t, bpf_prog_type prog_type, int arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_is_projection_of((const u8*)$arg1, (const u8*)$arg2)")
  public static boolean btf_is_projection_of(String pname, String tname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_is_vmlinux((const struct btf*)$arg1)")
  public static boolean btf_is_vmlinux(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_kfunc_id_set_contains((const struct btf*)$arg1, $arg2, (const struct bpf_prog*)$arg3)")
  public static Ptr<java.lang. @Unsigned Integer> btf_kfunc_id_set_contains(Ptr<btf> btf,
      @Unsigned int kfunc_btf_id, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_kfunc_is_modify_return((const struct btf*)$arg1, $arg2, (const struct bpf_prog*)$arg3)")
  public static Ptr<java.lang. @Unsigned Integer> btf_kfunc_is_modify_return(Ptr<btf> btf,
      @Unsigned int kfunc_btf_id, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_member_is_reg_int((const struct btf*)$arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, $arg4, $arg5)")
  public static boolean btf_member_is_reg_int(Ptr<btf> btf, Ptr<btf_type> s, Ptr<btf_member> m,
      @Unsigned int expected_offset, @Unsigned int expected_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_modifier_check_kflag_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_modifier_check_kflag_member(Ptr<btf_verifier_env> env,
      Ptr<btf_type> struct_type, Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_modifier_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_modifier_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_modifier_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_modifier_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_modifier_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_modifier_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id,
      Ptr<?> data, char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_module_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_module_notify(Ptr<notifier_block> nb, @Unsigned long op, Ptr<?> module) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)btf_name_by_offset((const struct btf*)$arg1, $arg2))")
  public static String btf_name_by_offset(Ptr<btf> btf, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_name_valid_identifier((const struct btf*)$arg1, $arg2)")
  public static boolean btf_name_valid_identifier(Ptr<btf> btf, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_nested_type_is_trusted($arg1, (const struct bpf_reg_state*)$arg2, (const u8*)$arg3, $arg4, (const u8*)$arg5)")
  public static boolean btf_nested_type_is_trusted(Ptr<bpf_verifier_log> log,
      Ptr<bpf_reg_state> reg, String field_name, @Unsigned int btf_id, String suffix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_new_fd((const union bpf_attr*)$arg1, $arg2, $arg3)")
  public static int btf_new_fd(Ptr<bpf_attr> attr, @OriginalName("bpfptr_t") sockptr_t uattr,
      @Unsigned int uattr_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_nr_types((const struct btf*)$arg1)")
  public static @Unsigned int btf_nr_types(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_obj_id((const struct btf*)$arg1)")
  public static @Unsigned int btf_obj_id(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_param_match_suffix((const struct btf*)$arg1, (const struct btf_param*)$arg2, (const u8*)$arg3)")
  public static boolean btf_param_match_suffix(Ptr<btf> btf, Ptr<btf_param> arg, String suffix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_parse((const union bpf_attr*)$arg1, $arg2, $arg3)")
  public static Ptr<btf> btf_parse(Ptr<bpf_attr> attr, @OriginalName("bpfptr_t") sockptr_t uattr,
      @Unsigned int uattr_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_parse_base($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static Ptr<btf> btf_parse_base(Ptr<btf_verifier_env> env, String name, Ptr<?> data,
      @Unsigned int data_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_parse_fields((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4)")
  public static Ptr<btf_record> btf_parse_fields(Ptr<btf> btf, Ptr<btf_type> t,
      @Unsigned int field_mask, @Unsigned int value_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_parse_graph_root((const struct btf*)$arg1, $arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static int btf_parse_graph_root(Ptr<btf> btf, Ptr<btf_field> field,
      Ptr<btf_field_info> info, String node_type_name, @Unsigned long node_type_align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_parse_hdr(Ptr<btf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_parse_kptr((const struct btf*)$arg1, $arg2, $arg3)")
  public static int btf_parse_kptr(Ptr<btf> btf, Ptr<btf_field> field, Ptr<btf_field_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_parse_module((const u8*)$arg1, (const void*)$arg2, $arg3, $arg4, $arg5)")
  public static Ptr<btf> btf_parse_module(String module_name, Ptr<?> data, @Unsigned int data_size,
      Ptr<?> base_data, @Unsigned int base_data_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_parse_str_sec(Ptr<btf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<btf> btf_parse_vmlinux() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_populate_kfunc_set($arg1, $arg2, (const struct btf_kfunc_id_set*)$arg3)")
  public static int btf_populate_kfunc_set(Ptr<btf> btf, btf_kfunc_hook hook,
      Ptr<btf_kfunc_id_set> kset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_prepare_func_args(Ptr<bpf_verifier_env> env, int subprog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ptr_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_ptr_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ptr_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_ptr_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ptr_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_ptr_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id, Ptr<?> data,
      char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void btf_put(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_record_dup((const struct btf_record*)$arg1)")
  public static Ptr<btf_record> btf_record_dup(Ptr<btf_record> rec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_record_equal((const struct btf_record*)$arg1, (const struct btf_record*)$arg2)")
  public static boolean btf_record_equal(Ptr<btf_record> rec_a, Ptr<btf_record> rec_b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_record_find((const struct btf_record*)$arg1, $arg2, $arg3)")
  public static Ptr<btf_field> btf_record_find(Ptr<btf_record> rec, @Unsigned int offset,
      @Unsigned int field_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void btf_record_free(Ptr<btf_record> rec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ref_type_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_ref_type_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_ref_type_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_ref_type_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_release(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_relocate_map_distilled_base(Ptr<btf_relocate> r) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_relocate_rewrite_strs(Ptr<btf_relocate> r, @Unsigned int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_relocate_rewrite_type_id(Ptr<btf_relocate> r, @Unsigned int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_repeat_fields(Ptr<btf_field_info> info, int info_cnt,
      @Unsigned int field_cnt, @Unsigned int repeat_cnt, @Unsigned int elem_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_resolve($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_resolve(Ptr<btf_verifier_env> env, Ptr<btf_type> t, @Unsigned int type_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_resolve_size((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3))")
  public static Ptr<btf_type> btf_resolve_size(Ptr<btf> btf, Ptr<btf_type> type,
      Ptr<java.lang. @Unsigned Integer> type_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_resolve_valid($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static boolean btf_resolve_valid(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int type_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_sec_info_cmp((const void*)$arg1, (const void*)$arg2)")
  public static int btf_sec_info_cmp(Ptr<?> a, Ptr<?> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_seq_show($arg1, (const u8*)$arg2, $arg3)")
  public static void btf_seq_show(Ptr<btf_show> show, String fmt, Ptr<__va_list_tag> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_set_base_btf($arg1, (const struct btf*)$arg2)")
  public static void btf_set_base_btf(Ptr<btf> btf, Ptr<btf> base_btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_show_end_aggr_type($arg1, (const u8*)$arg2)")
  public static void btf_show_end_aggr_type(Ptr<btf_show> show, String suffix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)btf_show_name($arg1))")
  public static String btf_show_name(Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_show_obj_safe($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static Ptr<?> btf_show_obj_safe(Ptr<btf_show> show, Ptr<btf_type> t, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_show_start_aggr_type($arg1, (const struct btf_type*)$arg2, $arg3, $arg4)")
  public static Ptr<?> btf_show_start_aggr_type(Ptr<btf_show> show, Ptr<btf_type> t,
      @Unsigned int type_id, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_snprintf_show($arg1, (const u8*)$arg2, $arg3)")
  public static void btf_snprintf_show(Ptr<btf_show> show, String fmt, Ptr<__va_list_tag> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)btf_str_by_offset((const struct btf*)$arg1, $arg2))")
  public static String btf_str_by_offset(Ptr<btf> btf, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_access($arg1, (const struct bpf_reg_state*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const u8**)$arg8)")
  public static int btf_struct_access(Ptr<bpf_verifier_log> log, Ptr<bpf_reg_state> reg, int off,
      int size, bpf_access_type atype, Ptr<java.lang. @Unsigned Integer> next_btf_id,
      Ptr<bpf_type_flag> flag, Ptr<String> field_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_check_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const struct btf_type*)$arg4)")
  public static int btf_struct_check_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, Ptr<btf_type> member_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_struct_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_ids_match($arg1, (const struct btf*)$arg2, $arg3, $arg4, (const struct btf*)$arg5, $arg6, $arg7)")
  public static boolean btf_struct_ids_match(Ptr<bpf_verifier_log> log, Ptr<btf> btf,
      @Unsigned int id, int off, Ptr<btf> need_btf, @Unsigned int need_type_id, boolean strict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_struct_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_struct_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_struct_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id,
      Ptr<?> data, char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_struct_walk($arg1, (const struct btf*)$arg2, (const struct btf_type*)$arg3, $arg4, $arg5, $arg6, $arg7, (const u8**)$arg8)")
  public static int btf_struct_walk(Ptr<bpf_verifier_log> log, Ptr<btf> btf, Ptr<btf_type> t,
      int off, int size, Ptr<java.lang. @Unsigned Integer> next_btf_id, Ptr<bpf_type_flag> flag,
      Ptr<String> field_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_sysfs_vmlinux_mmap($arg1, $arg2, (const struct bin_attribute*)$arg3, $arg4)")
  public static int btf_sysfs_vmlinux_mmap(Ptr<file> filp, Ptr<kobject> kobj,
      Ptr<bin_attribute> attr, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_try_get_module((const struct btf*)$arg1)")
  public static Ptr<module> btf_try_get_module(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_type_by_id((const struct btf*)$arg1, $arg2))")
  public static Ptr<btf_type> btf_type_by_id(Ptr<btf> btf, @Unsigned int type_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_type_id_resolve((const struct btf*)$arg1, $arg2))")
  public static Ptr<btf_type> btf_type_id_resolve(Ptr<btf> btf,
      Ptr<java.lang. @Unsigned Integer> type_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_type_id_size((const struct btf*)$arg1, $arg2, $arg3))")
  public static Ptr<btf_type> btf_type_id_size(Ptr<btf> btf,
      Ptr<java.lang. @Unsigned Integer> type_id, Ptr<java.lang. @Unsigned Integer> ret_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_ids_nocast_alias($arg1, (const struct btf*)$arg2, $arg3, (const struct btf*)$arg4, $arg5)")
  public static boolean btf_type_ids_nocast_alias(Ptr<bpf_verifier_log> log, Ptr<btf> reg_btf,
      @Unsigned int reg_id, Ptr<btf> arg_btf, @Unsigned int arg_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_is_i32((const struct btf_type*)$arg1)")
  public static boolean btf_type_is_i32(Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_is_i64((const struct btf_type*)$arg1)")
  public static boolean btf_type_is_i64(Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_is_primitive((const struct btf_type*)$arg1)")
  public static boolean btf_type_is_primitive(Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_is_void((const struct btf_type*)$arg1)")
  public static boolean btf_type_is_void(Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)btf_type_name((const struct btf*)$arg1, $arg2))")
  public static String btf_type_name(Ptr<btf> btf, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_needs_resolve((const struct btf_type*)$arg1)")
  public static boolean btf_type_needs_resolve(Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_type_resolve_func_ptr((const struct btf*)$arg1, $arg2, $arg3))")
  public static Ptr<btf_type> btf_type_resolve_func_ptr(Ptr<btf> btf, @Unsigned int id,
      Ptr<java.lang. @Unsigned Integer> res_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_type_resolve_ptr((const struct btf*)$arg1, $arg2, $arg3))")
  public static Ptr<btf_type> btf_type_resolve_ptr(Ptr<btf> btf, @Unsigned int id,
      Ptr<java.lang. @Unsigned Integer> res_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_seq_show((const struct btf*)$arg1, $arg2, $arg3, $arg4)")
  public static void btf_type_seq_show(Ptr<btf> btf, @Unsigned int type_id, Ptr<?> obj,
      Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_seq_show_flags((const struct btf*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int btf_type_seq_show_flags(Ptr<btf> btf, @Unsigned int type_id, Ptr<?> obj,
      Ptr<seq_file> m, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_show((const struct btf*)$arg1, $arg2, $arg3, $arg4)")
  public static void btf_type_show(Ptr<btf> btf, @Unsigned int type_id, Ptr<?> obj,
      Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_type*)btf_type_skip_modifiers((const struct btf*)$arg1, $arg2, $arg3))")
  public static Ptr<btf_type> btf_type_skip_modifiers(Ptr<btf> btf, @Unsigned int id,
      Ptr<java.lang. @Unsigned Integer> res_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_type_snprintf_show((const struct btf*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int btf_type_snprintf_show(Ptr<btf> btf, @Unsigned int type_id, Ptr<?> obj,
      String buf, int len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)btf_type_str((const struct btf_type*)$arg1))")
  public static String btf_type_str(Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_types_are_same((const struct btf*)$arg1, $arg2, (const struct btf*)$arg3, $arg4)")
  public static boolean btf_types_are_same(Ptr<btf> btf1, @Unsigned int id1, Ptr<btf> btf2,
      @Unsigned int id2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_validate_prog_ctx_type($arg1, (const struct btf*)$arg2, (const struct btf_type*)$arg3, $arg4, $arg5, $arg6)")
  public static int btf_validate_prog_ctx_type(Ptr<bpf_verifier_log> log, Ptr<btf> btf,
      Ptr<btf_type> t, int arg, bpf_prog_type prog_type, bpf_attach_type attach_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_var_check_meta($arg1, (const struct btf_type*)$arg2, $arg3)")
  public static int btf_var_check_meta(Ptr<btf_verifier_env> env, Ptr<btf_type> t,
      @Unsigned int meta_left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_var_log($arg1, (const struct btf_type*)$arg2)")
  public static void btf_var_log(Ptr<btf_verifier_env> env, Ptr<btf_type> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_var_resolve($arg1, (const struct resolve_vertex*)$arg2)")
  public static int btf_var_resolve(Ptr<btf_verifier_env> env, Ptr<resolve_vertex> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_var_show((const struct btf*)$arg1, (const struct btf_type*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void btf_var_show(Ptr<btf> btf, Ptr<btf_type> t, @Unsigned int type_id, Ptr<?> data,
      char bits_offset, Ptr<btf_show> show) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_verifier_log($arg1, (const u8*)$arg2, $arg3_)")
  public static void btf_verifier_log(Ptr<btf_verifier_env> env, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_verifier_log_member($arg1, (const struct btf_type*)$arg2, (const struct btf_member*)$arg3, (const u8*)$arg4, $arg5_)")
  public static void btf_verifier_log_member(Ptr<btf_verifier_env> env, Ptr<btf_type> struct_type,
      Ptr<btf_member> member, String fmt, java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("btf_verifier_log_vsi($arg1, (const struct btf_type*)$arg2, (const struct btf_var_secinfo*)$arg3, (const u8*)$arg4, $arg5_)")
  public static void btf_verifier_log_vsi(Ptr<btf_verifier_env> env, Ptr<btf_type> datasec_type,
      Ptr<btf_var_secinfo> vsi, String fmt, java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int btf_vmlinux_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_type extends Struct {
    public @Unsigned int name_off;

    public @Unsigned int info;

    @InlineUnion(2025)
    public @Unsigned int size;

    @InlineUnion(2025)
    public @Unsigned int type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_member"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_member extends Struct {
    public @Unsigned int name_off;

    public @Unsigned int type;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_record"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_record extends Struct {
    public @Unsigned int cnt;

    public @Unsigned int field_mask;

    public int spin_lock_off;

    public int res_spin_lock_off;

    public int timer_off;

    public int wq_off;

    public int refcount_off;

    public btf_field @Size(0) [] fields;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum btf_field_type"
  )
  public enum btf_field_type implements Enum<btf_field_type>, TypedEnum<btf_field_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_SPIN_LOCK = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_SPIN_LOCK"
    )
    BPF_SPIN_LOCK,

    /**
     * {@code BPF_TIMER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_TIMER"
    )
    BPF_TIMER,

    /**
     * {@code BPF_KPTR_UNREF = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_KPTR_UNREF"
    )
    BPF_KPTR_UNREF,

    /**
     * {@code BPF_KPTR_REF = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_KPTR_REF"
    )
    BPF_KPTR_REF,

    /**
     * {@code BPF_KPTR_PERCPU = 16}
     */
    @EnumMember(
        value = 16L,
        name = "BPF_KPTR_PERCPU"
    )
    BPF_KPTR_PERCPU,

    /**
     * {@code BPF_KPTR = 28}
     */
    @EnumMember(
        value = 28L,
        name = "BPF_KPTR"
    )
    BPF_KPTR,

    /**
     * {@code BPF_LIST_HEAD = 32}
     */
    @EnumMember(
        value = 32L,
        name = "BPF_LIST_HEAD"
    )
    BPF_LIST_HEAD,

    /**
     * {@code BPF_LIST_NODE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "BPF_LIST_NODE"
    )
    BPF_LIST_NODE,

    /**
     * {@code BPF_RB_ROOT = 128}
     */
    @EnumMember(
        value = 128L,
        name = "BPF_RB_ROOT"
    )
    BPF_RB_ROOT,

    /**
     * {@code BPF_RB_NODE = 256}
     */
    @EnumMember(
        value = 256L,
        name = "BPF_RB_NODE"
    )
    BPF_RB_NODE,

    /**
     * {@code BPF_GRAPH_NODE = 320}
     */
    @EnumMember(
        value = 320L,
        name = "BPF_GRAPH_NODE"
    )
    BPF_GRAPH_NODE,

    /**
     * {@code BPF_GRAPH_ROOT = 160}
     */
    @EnumMember(
        value = 160L,
        name = "BPF_GRAPH_ROOT"
    )
    BPF_GRAPH_ROOT,

    /**
     * {@code BPF_REFCOUNT = 512}
     */
    @EnumMember(
        value = 512L,
        name = "BPF_REFCOUNT"
    )
    BPF_REFCOUNT,

    /**
     * {@code BPF_WORKQUEUE = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "BPF_WORKQUEUE"
    )
    BPF_WORKQUEUE,

    /**
     * {@code BPF_UPTR = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "BPF_UPTR"
    )
    BPF_UPTR,

    /**
     * {@code BPF_RES_SPIN_LOCK = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "BPF_RES_SPIN_LOCK"
    )
    BPF_RES_SPIN_LOCK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_field_kptr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_field_kptr extends Struct {
    public Ptr<btf> btf;

    public Ptr<module> module;

    public @OriginalName("btf_dtor_kfunc_t") Ptr<?> dtor;

    public @Unsigned int btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_field_graph_root"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_field_graph_root extends Struct {
    public Ptr<btf> btf;

    public @Unsigned int value_btf_id;

    public @Unsigned int node_offset;

    public Ptr<btf_record> value_rec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_field"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_field extends Struct {
    public @Unsigned int offset;

    public @Unsigned int size;

    public btf_field_type type;

    @InlineUnion(2200)
    public btf_field_kptr kptr;

    @InlineUnion(2200)
    public btf_field_graph_root graph_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_func_model"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_func_model extends Struct {
    public char ret_size;

    public char ret_flags;

    public char nr_args;

    public char @Size(12) [] arg_size;

    public char @Size(12) [] arg_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_mod_pair"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_mod_pair extends Struct {
    public Ptr<btf> btf;

    public Ptr<module> module;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_id_set8"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_id_set8 extends Struct {
    public @Unsigned int cnt;

    public @Unsigned int flags;

    public AnonymousType1247127272C51 @Size(0) [] pairs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_kfunc_id_set"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_kfunc_id_set extends Struct {
    public Ptr<module> owner;

    public Ptr<btf_id_set8> set;

    public @OriginalName("btf_kfunc_filter_t") Ptr<?> filter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_struct_meta"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_struct_meta extends Struct {
    public @Unsigned int btf_id;

    public Ptr<btf_record> record;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { enum bpf_reg_type reg_type; union { struct { struct btf *btf; unsigned int btf_id; }; unsigned int mem_size; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_var_of_anon_member_of_bpf_insn_aux_data extends Struct {
    public bpf_reg_type reg_type;

    @InlineUnion(11848)
    public anon_member_of_anon_member_of_bpf_reg_state_and_anon_member_of_anon_member_of_btf_var_of_anon_member_of_bpf_insn_aux_data anon1$0;

    @InlineUnion(11848)
    public @Unsigned int mem_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_param extends Struct {
    public @Unsigned int name_off;

    public @Unsigned int type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_ptr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_ptr extends Struct {
    public Ptr<?> ptr;

    public @Unsigned int type_id;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_id_set"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_id_set extends Struct {
    public @Unsigned int cnt;

    public @Unsigned int @Size(0) [] ids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_array extends Struct {
    public @Unsigned int type;

    public @Unsigned int index_type;

    public @Unsigned int nelems;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_anon_stack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_anon_stack extends Struct {
    public @Unsigned int tid;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum btf_func_linkage"
  )
  public enum btf_func_linkage implements Enum<btf_func_linkage>, TypedEnum<btf_func_linkage, java.lang. @Unsigned Integer> {
    /**
     * {@code BTF_FUNC_STATIC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BTF_FUNC_STATIC"
    )
    BTF_FUNC_STATIC,

    /**
     * {@code BTF_FUNC_GLOBAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BTF_FUNC_GLOBAL"
    )
    BTF_FUNC_GLOBAL,

    /**
     * {@code BTF_FUNC_EXTERN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BTF_FUNC_EXTERN"
    )
    BTF_FUNC_EXTERN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_var_secinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_var_secinfo extends Struct {
    public @Unsigned int type;

    public @Unsigned int offset;

    public @Unsigned int size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_enum"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_enum extends Struct {
    public @Unsigned int name_off;

    public int val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_id_dtor_kfunc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_id_dtor_kfunc extends Struct {
    public @Unsigned int btf_id;

    public @Unsigned int kfunc_btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_header extends Struct {
    public @Unsigned short magic;

    public char version;

    public char flags;

    public @Unsigned int hdr_len;

    public @Unsigned int type_off;

    public @Unsigned int type_len;

    public @Unsigned int str_off;

    public @Unsigned int str_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_var"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_var extends Struct {
    public @Unsigned int linkage;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_decl_tag"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_decl_tag extends Struct {
    public int component_idx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_enum64"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_enum64 extends Struct {
    public @Unsigned int name_off;

    public @Unsigned int val_lo32;

    public @Unsigned int val_hi32;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_struct_metas"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_struct_metas extends Struct {
    public @Unsigned int cnt;

    public btf_struct_meta @Size(0) [] types;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum btf_kfunc_hook"
  )
  public enum btf_kfunc_hook implements Enum<btf_kfunc_hook>, TypedEnum<btf_kfunc_hook, java.lang. @Unsigned Integer> {
    /**
     * {@code BTF_KFUNC_HOOK_COMMON = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BTF_KFUNC_HOOK_COMMON"
    )
    BTF_KFUNC_HOOK_COMMON,

    /**
     * {@code BTF_KFUNC_HOOK_XDP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BTF_KFUNC_HOOK_XDP"
    )
    BTF_KFUNC_HOOK_XDP,

    /**
     * {@code BTF_KFUNC_HOOK_TC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BTF_KFUNC_HOOK_TC"
    )
    BTF_KFUNC_HOOK_TC,

    /**
     * {@code BTF_KFUNC_HOOK_STRUCT_OPS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BTF_KFUNC_HOOK_STRUCT_OPS"
    )
    BTF_KFUNC_HOOK_STRUCT_OPS,

    /**
     * {@code BTF_KFUNC_HOOK_TRACING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BTF_KFUNC_HOOK_TRACING"
    )
    BTF_KFUNC_HOOK_TRACING,

    /**
     * {@code BTF_KFUNC_HOOK_SYSCALL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BTF_KFUNC_HOOK_SYSCALL"
    )
    BTF_KFUNC_HOOK_SYSCALL,

    /**
     * {@code BTF_KFUNC_HOOK_FMODRET = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BTF_KFUNC_HOOK_FMODRET"
    )
    BTF_KFUNC_HOOK_FMODRET,

    /**
     * {@code BTF_KFUNC_HOOK_CGROUP = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BTF_KFUNC_HOOK_CGROUP"
    )
    BTF_KFUNC_HOOK_CGROUP,

    /**
     * {@code BTF_KFUNC_HOOK_SCHED_ACT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BTF_KFUNC_HOOK_SCHED_ACT"
    )
    BTF_KFUNC_HOOK_SCHED_ACT,

    /**
     * {@code BTF_KFUNC_HOOK_SK_SKB = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BTF_KFUNC_HOOK_SK_SKB"
    )
    BTF_KFUNC_HOOK_SK_SKB,

    /**
     * {@code BTF_KFUNC_HOOK_SOCKET_FILTER = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BTF_KFUNC_HOOK_SOCKET_FILTER"
    )
    BTF_KFUNC_HOOK_SOCKET_FILTER,

    /**
     * {@code BTF_KFUNC_HOOK_LWT = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BTF_KFUNC_HOOK_LWT"
    )
    BTF_KFUNC_HOOK_LWT,

    /**
     * {@code BTF_KFUNC_HOOK_NETFILTER = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BTF_KFUNC_HOOK_NETFILTER"
    )
    BTF_KFUNC_HOOK_NETFILTER,

    /**
     * {@code BTF_KFUNC_HOOK_KPROBE = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BTF_KFUNC_HOOK_KPROBE"
    )
    BTF_KFUNC_HOOK_KPROBE,

    /**
     * {@code BTF_KFUNC_HOOK_MAX = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BTF_KFUNC_HOOK_MAX"
    )
    BTF_KFUNC_HOOK_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_kfunc_hook_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_kfunc_hook_filter extends Struct {
    public @OriginalName("btf_kfunc_filter_t") Ptr<?> @Size(16) [] filters;

    public @Unsigned int nr_filters;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_kfunc_set_tab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_kfunc_set_tab extends Struct {
    public Ptr<btf_id_set8> @Size(14) [] sets;

    public btf_kfunc_hook_filter @Size(14) [] hook_filters;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_id_dtor_kfunc_tab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_id_dtor_kfunc_tab extends Struct {
    public @Unsigned int cnt;

    public btf_id_dtor_kfunc @Size(0) [] dtors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_struct_ops_tab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_struct_ops_tab extends Struct {
    public @Unsigned int cnt;

    public @Unsigned int capacity;

    public bpf_struct_ops_desc @Size(0) [] ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_sec_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_sec_info extends Struct {
    public @Unsigned int off;

    public @Unsigned int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_verifier_env"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_verifier_env extends Struct {
    public Ptr<btf> btf;

    public Ptr<java.lang.Character> visit_states;

    public resolve_vertex @Size(32) [] stack;

    public bpf_verifier_log log;

    public @Unsigned int log_type_id;

    public @Unsigned int top_stack;

    public verifier_phase phase;

    public resolve_mode resolve_mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_show"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_show extends Struct {
    public @Unsigned long flags;

    public Ptr<?> target;

    public Ptr<?> showfn;

    public Ptr<btf> btf;

    public state_of_btf_show state;

    public obj_of_btf_show obj;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_kind_operations"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_kind_operations extends Struct {
    public Ptr<?> check_meta;

    public Ptr<?> resolve;

    public Ptr<?> check_member;

    public Ptr<?> check_kflag_member;

    public Ptr<?> log_details;

    public Ptr<?> show;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_field_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_field_info extends Struct {
    public btf_field_type type;

    public @Unsigned int off;

    @InlineUnion(17744)
    public kptr_of_anon_member_of_btf_field_info kptr;

    @InlineUnion(17744)
    public graph_root_of_anon_member_of_btf_field_info graph_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum btf_arg_tag"
  )
  public enum btf_arg_tag implements Enum<btf_arg_tag>, TypedEnum<btf_arg_tag, java.lang. @Unsigned Integer> {
    /**
     * {@code ARG_TAG_CTX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ARG_TAG_CTX"
    )
    ARG_TAG_CTX,

    /**
     * {@code ARG_TAG_NONNULL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ARG_TAG_NONNULL"
    )
    ARG_TAG_NONNULL,

    /**
     * {@code ARG_TAG_TRUSTED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ARG_TAG_TRUSTED"
    )
    ARG_TAG_TRUSTED,

    /**
     * {@code ARG_TAG_UNTRUSTED = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ARG_TAG_UNTRUSTED"
    )
    ARG_TAG_UNTRUSTED,

    /**
     * {@code ARG_TAG_NULLABLE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ARG_TAG_NULLABLE"
    )
    ARG_TAG_NULLABLE,

    /**
     * {@code ARG_TAG_ARENA = 32}
     */
    @EnumMember(
        value = 32L,
        name = "ARG_TAG_ARENA"
    )
    ARG_TAG_ARENA
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_show_snprintf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_show_snprintf extends Struct {
    public btf_show show;

    public int len_left;

    public int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_module"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_module extends Struct {
    public list_head list;

    public Ptr<module> module;

    public Ptr<btf> btf;

    public Ptr<bin_attribute> sysfs_attr;

    public int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum btf_field_iter_kind"
  )
  public enum btf_field_iter_kind implements Enum<btf_field_iter_kind>, TypedEnum<btf_field_iter_kind, java.lang. @Unsigned Integer> {
    /**
     * {@code BTF_FIELD_ITER_IDS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BTF_FIELD_ITER_IDS"
    )
    BTF_FIELD_ITER_IDS,

    /**
     * {@code BTF_FIELD_ITER_STRS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BTF_FIELD_ITER_STRS"
    )
    BTF_FIELD_ITER_STRS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_field_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_field_desc extends Struct {
    public int t_off_cnt;

    public int @Size(2) [] t_offs;

    public int m_sz;

    public int m_off_cnt;

    public int @Size(1) [] m_offs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_field_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_field_iter extends Struct {
    public btf_field_desc desc;

    public Ptr<?> p;

    public int m_idx;

    public int off_idx;

    public int vlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_relocate"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_relocate extends Struct {
    public Ptr<btf> btf;

    public Ptr<btf> base_btf;

    public Ptr<btf> dist_base_btf;

    public @Unsigned int nr_base_types;

    public @Unsigned int nr_split_types;

    public @Unsigned int nr_dist_base_types;

    public int dist_str_len;

    public int base_str_len;

    public Ptr<java.lang. @Unsigned Integer> id_map;

    public Ptr<java.lang. @Unsigned Integer> str_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct btf_name_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class btf_name_info extends Struct {
    public String name;

    public boolean needs_size;

    public @Unsigned int size;

    public @Unsigned int id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int id; unsigned int flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class AnonymousType1247127272C51 extends Struct {
    public @Unsigned int id;

    public @Unsigned int flags;
  }
}
