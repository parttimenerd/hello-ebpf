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
 * Generated class for BPF runtime types that start with ext4
 */
@java.lang.SuppressWarnings("unused")
public final class Ext4Definitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_block_zero_page_range(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<address_space> mapping,
      @OriginalName("loff_t") long from, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_check_dir_entry((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static int __ext4_check_dir_entry(String function, @Unsigned int line, Ptr<inode> dir,
      Ptr<file> filp, Ptr<ext4_dir_entry_2> de, Ptr<buffer_head> bh, String buf, int size,
      @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_error($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5, $arg6, (const u8*)$arg7, $arg8_)")
  public static void __ext4_error(Ptr<super_block> sb, String function, @Unsigned int line,
      boolean force_ro, int error, @Unsigned long block, String fmt, java.lang.Object... param7) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_error_file($arg1, (const u8*)$arg2, $arg3, $arg4, (const u8*)$arg5, $arg6_)")
  public static void __ext4_error_file(Ptr<file> file, String function, @Unsigned int line,
      @Unsigned @OriginalName("ext4_fsblk_t") long block, String fmt, java.lang.Object... param5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_error_inode($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5, (const u8*)$arg6, $arg7_)")
  public static void __ext4_error_inode(Ptr<inode> inode, String function, @Unsigned int line,
      @Unsigned @OriginalName("ext4_fsblk_t") long block, int error, String fmt,
      java.lang.Object... param6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_expand_extra_isize(Ptr<inode> inode, @Unsigned int new_extra_isize,
      Ptr<ext4_iloc> iloc, Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<java.lang.Integer> no_expand) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_ext_check((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int __ext4_ext_check(String function, @Unsigned int line, Ptr<inode> inode,
      Ptr<ext4_extent_header> eh, int depth, @Unsigned @OriginalName("ext4_fsblk_t") long pblk,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_ext_dirty((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int __ext4_ext_dirty(String where, @Unsigned int line,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_ext_path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ext4_fc_track_create(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ext4_fc_track_link(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ext4_fc_track_unlink(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_fill_super(Ptr<fs_context> fc, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> __ext4_find_entry(Ptr<inode> dir, Ptr<ext4_filename> fname,
      Ptr<Ptr<ext4_dir_entry_2>> res_dir, Ptr<java.lang.Integer> inlined) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_forget((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int __ext4_forget(String where, @Unsigned int line,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, int is_metadata, Ptr<inode> inode,
      Ptr<buffer_head> bh, @Unsigned @OriginalName("ext4_fsblk_t") long blocknr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_get_inode_loc(Ptr<super_block> sb, @Unsigned long ino, Ptr<inode> inode,
      Ptr<ext4_iloc> iloc, Ptr<java.lang. @Unsigned @OriginalName("ext4_fsblk_t") Long> ret_block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_get_inode_loc_noinmem(Ptr<inode> inode, Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_grp_locked_error((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, (const u8*)$arg7, $arg8_)")
  public static void __ext4_grp_locked_error(String function, @Unsigned int line,
      Ptr<super_block> sb, @Unsigned @OriginalName("ext4_group_t") int grp, @Unsigned long ino,
      @Unsigned @OriginalName("ext4_fsblk_t") long block, String fmt, java.lang.Object... param7) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_handle_dirty_metadata((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int __ext4_handle_dirty_metadata(String where, @Unsigned int line,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_iget($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static Ptr<inode> __ext4_iget(Ptr<super_block> sb, @Unsigned long ino,
      @OriginalName("ext4_iget_flags") EXT4_IGET flags, String function, @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __ext4_ioctl(Ptr<file> filp, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_journal_ensure_credits(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, int check_cred, int extend_cred,
      int revoke_cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_journal_get_create_access((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int __ext4_journal_get_create_access(String where, @Unsigned int line,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<super_block> sb,
      Ptr<buffer_head> bh, ext4_journal_trigger_type trigger_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_journal_get_write_access((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int __ext4_journal_get_write_access(String where, @Unsigned int line,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<super_block> sb,
      Ptr<buffer_head> bh, ext4_journal_trigger_type trigger_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("handle_t") jbd2_journal_handle> __ext4_journal_start_reserved(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, @Unsigned int line, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("handle_t") jbd2_journal_handle> __ext4_journal_start_sb(
      Ptr<inode> inode, Ptr<super_block> sb, @Unsigned int line, int type, int blocks,
      int rsv_blocks, int revoke_creds) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_journal_stop((const u8*)$arg1, $arg2, $arg3)")
  public static int __ext4_journal_stop(String where, @Unsigned int line,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_journalled_invalidate_folio(Ptr<folio> folio, @Unsigned long offset,
      @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_link(Ptr<inode> dir, Ptr<inode> inode, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_mark_inode_dirty($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static int __ext4_mark_inode_dirty(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, String func,
      @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_msg($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4_)")
  public static void __ext4_msg(Ptr<super_block> sb, String prefix, String fmt,
      java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_new_inode($arg1, $arg2, $arg3, $arg4, (const struct qstr*)$arg5, $arg6, $arg7, $arg8, $arg9, $arg10, $arg11)")
  public static Ptr<inode> __ext4_new_inode(Ptr<mnt_idmap> idmap,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> dir,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<qstr> qstr, @Unsigned int goal,
      Ptr<java.lang. @Unsigned @OriginalName("uid_t") Integer> owner, @Unsigned int i_flags,
      int handle_type, @Unsigned int line_no, int nblocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_read_dirblock($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static Ptr<buffer_head> __ext4_read_dirblock(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int block, dirblock_type_t type, String func,
      @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_remount(Ptr<fs_context> fc, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_set_acl(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, int type, Ptr<posix_acl> acl, int xattr_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_std_error($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void __ext4_std_error(Ptr<super_block> sb, String function, @Unsigned int line,
      int errno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_unlink($arg1, (const struct qstr*)$arg2, $arg3, $arg4)")
  public static int __ext4_unlink(Ptr<inode> dir, Ptr<qstr> d_name, Ptr<inode> inode,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ext4_update_other_inode_time(Ptr<super_block> sb, @Unsigned long orig_ino,
      @Unsigned long ino, Ptr<ext4_inode> raw_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_warning($arg1, (const u8*)$arg2, $arg3, (const u8*)$arg4, $arg5_)")
  public static void __ext4_warning(Ptr<super_block> sb, String function, @Unsigned int line,
      String fmt, java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ext4_warning_inode((const struct inode*)$arg1, (const u8*)$arg2, $arg3, (const u8*)$arg4, $arg5_)")
  public static void __ext4_warning_inode(Ptr<inode> inode, String function, @Unsigned int line,
      String fmt, java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ext4_xattr_set_credits(Ptr<super_block> sb, Ptr<inode> inode,
      Ptr<buffer_head> block_bh, @Unsigned long value_len, boolean is_create) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int _ext4_get_block(Ptr<inode> inode,
      @Unsigned @OriginalName("sector_t") long iblock, Ptr<buffer_head> bh, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int _ext4_show_options(Ptr<seq_file> seq, Ptr<super_block> sb, int nodefs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_acl_from_disk((const void*)$arg1, $arg2)")
  public static Ptr<posix_acl> ext4_acl_from_disk(Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_acl_to_disk((const struct posix_acl*)$arg1, $arg2)")
  public static Ptr<?> ext4_acl_to_disk(Ptr<posix_acl> acl, Ptr<java.lang. @Unsigned Long> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_acquire_dquot(Ptr<dquot> dquot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_add_dirent_to_inline(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<ext4_filename> fname,
      Ptr<inode> dir, Ptr<inode> inode, Ptr<ext4_iloc> iloc, Ptr<?> inline_start, int inline_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_add_entry(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<dentry> dentry, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_add_nondir(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<dentry> dentry, Ptr<Ptr<inode>> inodep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_alloc_branch(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<ext4_allocation_request> ar, int indirect_blks,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> offsets,
      Ptr<Indirect> branch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_alloc_da_blocks(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_alloc_flex_bg_array(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int ngroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_alloc_group_tables(Ptr<super_block> sb,
      Ptr<ext4_new_flex_group_data> flex_gd, @Unsigned int flexbg_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> ext4_alloc_inode(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_io_end_vec> ext4_alloc_io_end_vec(
      Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_append(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_apply_options(Ptr<fs_context> fc, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_atomic_write_init(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_attr_show(Ptr<kobject> kobj, Ptr<attribute> attr,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_attr_store($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long ext4_attr_store(Ptr<kobject> kobj,
      Ptr<attribute> attr, String buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_begin_enable_verity(Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_bg_has_super(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ext4_bg_num_gdb(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_bio_write_folio(Ptr<ext4_io_submit> io, Ptr<folio> folio,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_block_bitmap(Ptr<super_block> sb,
      Ptr<ext4_group_desc> bg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_block_bitmap_csum_set(Ptr<super_block> sb, Ptr<ext4_group_desc> gdp,
      Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_block_bitmap_csum_verify(Ptr<super_block> sb, Ptr<ext4_group_desc> gdp,
      Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_block_bitmap_set(Ptr<super_block> sb, Ptr<ext4_group_desc> bg,
      @Unsigned @OriginalName("ext4_fsblk_t") long blk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_block_group_meta_init(Ptr<super_block> sb, int silent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_block_page_mkwrite(Ptr<inode> inode, Ptr<folio> folio, Ptr<?> get_block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_block_to_path(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int i_block,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> offsets,
      Ptr<java.lang.Integer> boundary) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_block_truncate_page(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<address_space> mapping,
      @OriginalName("loff_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_block_write_begin(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<folio> folio,
      @OriginalName("loff_t") long pos, @Unsigned int len, Ptr<?> get_block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_block_zero_page_range(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<address_space> mapping,
      @OriginalName("loff_t") long from, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("sector_t") long ext4_bmap(Ptr<address_space> mapping,
      @Unsigned @OriginalName("sector_t") long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_bread(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int block, int map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_bread_batch(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int block, int bh_count, boolean wait,
      Ptr<Ptr<buffer_head>> bhs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_break_layouts(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_buffered_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_cache_extents(Ptr<inode> inode, Ptr<ext4_extent_header> eh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_calculate_overhead(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_can_truncate(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_change_inode_journal_flag(Ptr<inode> inode, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_check_all_de(Ptr<inode> dir, Ptr<buffer_head> bh, Ptr<?> buf,
      int buf_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_check_blockref((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int ext4_check_blockref(String function, @Unsigned int line, Ptr<inode> inode,
      Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> p, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_check_descriptors(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long sb_block,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_group_t") Integer> first_not_zeroed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_check_feature_compatibility(Ptr<super_block> sb, Ptr<ext4_super_block> es,
      int silent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_check_geometry(Ptr<super_block> sb, Ptr<ext4_super_block> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_check_map_extents_env(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_check_opt_consistency(Ptr<fs_context> fc, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_chunk_trans_blocks(Ptr<inode> inode, int nrblocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_chunk_trans_extent(Ptr<inode> inode, int nrblocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_claim_free_clusters(Ptr<ext4_sb_info> sbi, long nclusters,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_clear_blocks(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<buffer_head> bh,
      @Unsigned @OriginalName("ext4_fsblk_t") long block_to_free, @Unsigned long count,
      Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> first,
      Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_clear_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_clear_inode_es(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_clear_journal_err(Ptr<super_block> sb, Ptr<ext4_super_block> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_clear_request_list() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_clu_alloc_state(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_clu_mapped(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lclu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_commit_super(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long ext4_compat_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_convert_inline_data(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_convert_inline_data_nolock(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_convert_inline_data_to_extent(Ptr<address_space> mapping,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_convert_meta_bg(Ptr<super_block> sb, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_convert_unwritten_extents(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("ssize_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_convert_unwritten_extents_atomic(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("ssize_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_convert_unwritten_io_end_vec(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ext4_count_dirs(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_count_free(String bitmap, @Unsigned int numchars) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_count_free_clusters(
      Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ext4_count_free_inodes(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_create(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode, boolean excl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_create_inline_data(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_cross_rename(Ptr<inode> old_dir, Ptr<dentry> old_dentry,
      Ptr<inode> new_dir, Ptr<dentry> new_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_da_get_block_prep(Ptr<inode> inode,
      @Unsigned @OriginalName("sector_t") long iblock, Ptr<buffer_head> bh, int create) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_da_map_blocks(Ptr<inode> inode, Ptr<ext4_map_blocks> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_da_release_space(Ptr<inode> inode, int to_free) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_da_reserve_space(Ptr<inode> inode, int nr_resv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_da_update_reserve_space(Ptr<inode> inode, int used, int quota_claim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_da_write_begin((const struct kiocb*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int ext4_da_write_begin(Ptr<kiocb> iocb, Ptr<address_space> mapping,
      @OriginalName("loff_t") long pos, @Unsigned int len, Ptr<Ptr<folio>> foliop,
      Ptr<Ptr<?>> fsdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_da_write_end((const struct kiocb*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int ext4_da_write_end(Ptr<kiocb> iocb, Ptr<address_space> mapping,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied, Ptr<folio> folio,
      Ptr<?> fsdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_datasem_ensure_credits(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, int check_cred,
      int restart_cred, int revoke_cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int ext4_dax_fault(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int ext4_dax_huge_fault(Ptr<vm_fault> vmf,
      @Unsigned int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_dax_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_dax_writepages(Ptr<address_space> mapping, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ext4_decode_error($arg1, $arg2, $arg3))")
  public static String ext4_decode_error(Ptr<super_block> sb, int errno, String nbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_delete_entry(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> dir, Ptr<ext4_dir_entry_2> de_del, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_delete_inline_entry(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> dir,
      Ptr<ext4_dir_entry_2> de_del, Ptr<buffer_head> bh, Ptr<java.lang.Integer> has_inline_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_destroy_inline_data(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_destroy_inline_data_nolock(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_destroy_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_destroy_system_zone(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_dio_alignment(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_dio_write_checks(Ptr<kiocb> iocb,
      Ptr<iov_iter> from, Ptr<java.lang. @OriginalName("bool") Boolean> ilock_shared,
      Ptr<java.lang. @OriginalName("bool") Boolean> extend,
      Ptr<java.lang. @OriginalName("bool") Boolean> unwritten, Ptr<java.lang.Integer> dio_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_dio_write_end_io(Ptr<kiocb> iocb, @OriginalName("ssize_t") long size,
      int error, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_dio_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long ext4_dir_llseek(Ptr<file> file,
      @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_dir_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_dirblock_csum_verify(Ptr<inode> inode, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_dirty_folio(Ptr<address_space> mapping, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_dirty_inode(Ptr<inode> inode, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_discard_allocated_blocks(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_discard_preallocations(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_discard_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long ext4_do_fallocate(Ptr<file> file, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long len, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_do_update_inode(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_do_writepages(Ptr<mpage_da_data> mpd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_double_down_write_data_sem(Ptr<inode> first, Ptr<inode> second) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_double_up_write_data_sem(Ptr<inode> orig_inode, Ptr<inode> donor_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_drop_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_dx_add_entry(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<ext4_filename> fname, Ptr<inode> dir, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_dx_find_entry(Ptr<inode> dir, Ptr<ext4_filename> fname,
      Ptr<Ptr<ext4_dir_entry_2>> res_dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_dx_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_empty_dir(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_enable_quotas(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ext4_encrypted_get_link($arg1, $arg2, $arg3))")
  public static String ext4_encrypted_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_encrypted_symlink_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int ext4_encrypted_symlink_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path,
      Ptr<kstat> stat, @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_end_bio(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_end_bitmap_read(Ptr<buffer_head> bh, int uptodate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_end_buffer_io_sync(Ptr<buffer_head> bh, int uptodate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_end_enable_verity($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static int ext4_end_enable_verity(Ptr<file> filp, Ptr<?> desc, @Unsigned long desc_size,
      @Unsigned long merkle_tree_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_end_io_end(Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_end_io_rsv_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_es_cache_extent(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk, @Unsigned int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_es_can_be_merged(Ptr<extent_status> es1, Ptr<extent_status> es2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ext4_es_count(Ptr<shrinker> shrink, Ptr<shrink_control> sc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_es_find_extent_range($arg1, (int (*)(struct extent_status*))$arg2, $arg3, $arg4, $arg5)")
  public static void ext4_es_find_extent_range(Ptr<inode> inode, Ptr<?> matching_fn,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int end, Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_es_free_extent(Ptr<inode> inode, Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_es_init_tree(Ptr<ext4_es_tree> tree) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_es_insert_delayed_extent(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len, boolean lclu_allocated,
      boolean end_allocated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_es_insert_extent(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk, @Unsigned int status,
      boolean delalloc_reserve_used) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_es_is_delayed(Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_es_is_mapped(Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_es_lookup_extent(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> next_lblk,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_es_register_shrinker(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_es_remove_extent(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ext4_es_scan(Ptr<shrinker> shrink, Ptr<shrink_control> sc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_es_scan_clu($arg1, (int (*)(struct extent_status*))$arg2, $arg3)")
  public static boolean ext4_es_scan_clu(Ptr<inode> inode, Ptr<?> matching_fn,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_es_scan_range($arg1, (int (*)(struct extent_status*))$arg2, $arg3, $arg4)")
  public static boolean ext4_es_scan_range(Ptr<inode> inode, Ptr<?> matching_fn,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_es_unregister_shrinker(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_evict_ea_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_evict_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_es() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_fs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_mballoc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_pageio() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_pending() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_post_read_processing() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_sysfs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_exit_system_zone() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_expand_extra_isize(Ptr<inode> inode, @Unsigned int new_extra_isize,
      Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_expand_extra_isize_ea(Ptr<inode> inode, int new_extra_isize,
      Ptr<ext4_inode> raw_inode, Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_expand_inode_array(Ptr<Ptr<ext4_xattr_inode_array>> ea_inode_array,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_calc_credits_for_single_extent(Ptr<inode> inode, int nrblocks,
      Ptr<ext4_ext_path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_check_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_clear_bb(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_ext_path> ext4_ext_convert_to_initialized(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, Ptr<ext4_ext_path> path, int flags,
      Ptr<java.lang. @Unsigned Integer> allocated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_correct_indexes(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_ext_path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_lblk_t") int ext4_ext_determine_insert_hole(
      Ptr<inode> inode, Ptr<ext4_ext_path> path, @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_ext_find_goal(Ptr<inode> inode,
      Ptr<ext4_ext_path> path, @Unsigned @OriginalName("ext4_lblk_t") int block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_grow_indepth(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_ext_path> ext4_ext_handle_unwritten_extents(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, Ptr<ext4_ext_path> path, int flags,
      Ptr<java.lang. @Unsigned Integer> allocated,
      @Unsigned @OriginalName("ext4_fsblk_t") long newblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_index_trans_blocks(Ptr<inode> inode, int extents) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_ext_init(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_ext_path> ext4_ext_insert_extent(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_ext_path> path, Ptr<ext4_extent> newext, int gb_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_insert_index(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_ext_path> curp, int logical,
      @Unsigned @OriginalName("ext4_fsblk_t") long ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_map_blocks(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_migrate(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_lblk_t") int ext4_ext_next_allocated_block(
      Ptr<ext4_ext_path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_precache(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_ext_release(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_remove_space(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_replay_set_iblocks(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_ext_replay_shrink_inode(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_replay_update_ex(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start, int len, int unwritten,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_rm_idx(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_ext_path> path, int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_rm_leaf(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_ext_path> path, Ptr<partial_cluster> partial,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_search_left(Ptr<inode> inode, Ptr<ext4_ext_path> path,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> logical,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_fsblk_t") Long> phys) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_search_right(Ptr<inode> inode, Ptr<ext4_ext_path> path,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> logical,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_fsblk_t") Long> phys, Ptr<ext4_extent> ret_ex,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_shift_extents(Ptr<inode> inode,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int shift, SHIFT_DIRECTION SHIFT) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_shift_path_extents(Ptr<ext4_ext_path> path,
      @Unsigned @OriginalName("ext4_lblk_t") int shift, Ptr<inode> inode,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, SHIFT_DIRECTION SHIFT) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_split(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, @Unsigned int flags, Ptr<ext4_ext_path> path, Ptr<ext4_extent> newext,
      int at) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_swap_inode_data(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<inode> tmp_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_ext_tree_init(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_truncate(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_ext_try_to_merge(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_ext_path> path, Ptr<ext4_extent> ex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ext_try_to_merge_right(Ptr<inode> inode, Ptr<ext4_ext_path> path,
      Ptr<ext4_extent> ex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_ext_try_to_merge_up(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_ext_path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_extent_block_csum_set(Ptr<inode> inode, Ptr<ext4_extent_header> eh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long ext4_fallocate(Ptr<file> file, int mode, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_fc_add_dentry_tlv(Ptr<super_block> sb,
      Ptr<java.lang. @Unsigned Integer> crc, Ptr<ext4_fc_dentry_update> fc_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_fc_add_tlv(Ptr<super_block> sb, @Unsigned short tag,
      @Unsigned short len, Ptr<java.lang.Character> val, Ptr<java.lang. @Unsigned Integer> crc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_cleanup(Ptr<@OriginalName("journal_t") journal_s> journal, int full,
      @Unsigned @OriginalName("tid_t") int tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_commit(Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_del(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_destroy_dentry_cache() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_free(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_info_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_init(Ptr<super_block> sb,
      Ptr<@OriginalName("journal_t") journal_s> journal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_init_dentry_cache() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_init_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_mark_ineligible(Ptr<super_block> sb, int reason,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_perform_commit(Ptr<@OriginalName("journal_t") journal_s> journal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_record_regions(Ptr<super_block> sb, int ino,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk, int len, int replay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_replay(Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<buffer_head> bh, passtype pass, int off,
      @Unsigned @OriginalName("tid_t") int expected_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_fc_replay_check_excluded(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long blk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_replay_cleanup(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_replay_inode(Ptr<super_block> sb, Ptr<ext4_fc_tl_mem> tl,
      Ptr<java.lang.Character> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang.Character> ext4_fc_reserve_space(Ptr<super_block> sb, int len,
      Ptr<java.lang. @Unsigned Integer> crc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_set_bitmaps_and_counters(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_submit_bh(Ptr<super_block> sb, boolean is_tail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_track_create(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_track_inode(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_track_link(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_track_range(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_track_unlink(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fc_update_stats(Ptr<super_block> sb, int status,
      @Unsigned long commit_time, int nblks, @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_write_inode(Ptr<inode> inode, Ptr<java.lang. @Unsigned Integer> crc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_write_inode_data(Ptr<inode> inode,
      Ptr<java.lang. @Unsigned Integer> crc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fc_write_tail(Ptr<super_block> sb, @Unsigned int crc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_feat_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_feature_set_ok(Ptr<super_block> sb, int readonly) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> ext4_fh_to_dentry(Ptr<super_block> sb, Ptr<fid> fid, int fh_len,
      int fh_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> ext4_fh_to_parent(Ptr<super_block> sb, Ptr<fid> fid, int fh_len,
      int fh_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fiemap(Ptr<inode> inode, Ptr<fiemap_extent_info> fieinfo,
      @Unsigned long start, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_file_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int ext4_file_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_file_mmap_prepare(Ptr<vm_area_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_file_open(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_file_read_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_file_splice_read(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<pipe_inode_info> pipe,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_file_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fileattr_get(Ptr<dentry> dentry, Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fileattr_set(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fill_es_cache_info(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int block,
      @Unsigned @OriginalName("ext4_lblk_t") int num, Ptr<fiemap_extent_info> fieinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fill_raw_inode(Ptr<inode> inode, Ptr<ext4_inode> raw_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fill_super(Ptr<super_block> sb, Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_find_delete_entry($arg1, $arg2, (const struct qstr*)$arg3)")
  public static int ext4_find_delete_entry(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> dir, Ptr<qstr> d_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_find_dest_de(Ptr<inode> dir, Ptr<buffer_head> bh, Ptr<?> buf, int buf_size,
      Ptr<ext4_filename> fname, Ptr<Ptr<ext4_dir_entry_2>> dest_de) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_find_entry($arg1, (const struct qstr*)$arg2, $arg3, $arg4)")
  public static Ptr<buffer_head> ext4_find_entry(Ptr<inode> dir, Ptr<qstr> d_name,
      Ptr<Ptr<ext4_dir_entry_2>> res_dir, Ptr<java.lang.Integer> inlined) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_ext_path> ext4_find_extent(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int block, Ptr<ext4_ext_path> path, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_find_inline_data_nolock(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_find_inline_entry(Ptr<inode> dir, Ptr<ext4_filename> fname,
      Ptr<Ptr<ext4_dir_entry_2>> res_dir, Ptr<java.lang.Integer> has_inline_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Indirect> ext4_find_shared(Ptr<inode> inode, int depth,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> offsets, Ptr<Indirect> chain,
      Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> top) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_finish_bio(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_flex_group_add(Ptr<super_block> sb, Ptr<inode> resize_inode,
      Ptr<ext4_new_flex_group_data> flex_gd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_flex_groups_free(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fname_free_filename(Ptr<ext4_filename> fname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_fname_from_fscrypt_name($arg1, (const struct fscrypt_name*)$arg2)")
  public static void ext4_fname_from_fscrypt_name(Ptr<ext4_filename> dst, Ptr<fscrypt_name> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_fname_prepare_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      Ptr<ext4_filename> fname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_fname_setup_ci_filename($arg1, (const struct qstr*)$arg2, $arg3)")
  public static int ext4_fname_setup_ci_filename(Ptr<inode> dir, Ptr<qstr> iname,
      Ptr<ext4_filename> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_fname_setup_filename($arg1, (const struct qstr*)$arg2, $arg3, $arg4)")
  public static int ext4_fname_setup_filename(Ptr<inode> dir, Ptr<qstr> iname, int lookup,
      Ptr<ext4_filename> fname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_force_commit(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_force_shutdown(Ptr<super_block> sb, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_blocks(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<buffer_head> bh, @Unsigned @OriginalName("ext4_fsblk_t") long block,
      @Unsigned long count, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_branches(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<buffer_head> parent_bh,
      Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> first,
      Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> last, int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_free_clusters_after_init(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<ext4_group_desc> gdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_ext_path(Ptr<ext4_ext_path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_free_group_clusters(Ptr<super_block> sb,
      Ptr<ext4_group_desc> bg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_group_clusters_set(Ptr<super_block> sb, Ptr<ext4_group_desc> bg,
      @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_in_core_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_inode(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_free_inodes_count(Ptr<super_block> sb, Ptr<ext4_group_desc> bg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_inodes_set(Ptr<super_block> sb, Ptr<ext4_group_desc> bg,
      @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_free_link(Ptr<?> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_freeze(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fsmap_from_internal(Ptr<super_block> sb, Ptr<fsmap> dest,
      Ptr<ext4_fsmap> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_fsmap_to_internal(Ptr<super_block> sb, Ptr<ext4_fsmap> dest,
      Ptr<fsmap> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_generic_attr_show(Ptr<ext4_attr> a,
      Ptr<ext4_sb_info> sbi, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_generic_attr_store($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long ext4_generic_attr_store(Ptr<ext4_attr> a,
      Ptr<ext4_sb_info> sbi, String buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_generic_delete_entry(Ptr<inode> dir, Ptr<ext4_dir_entry_2> de_del,
      Ptr<buffer_head> bh, Ptr<?> entry_buf, int buf_size, int csum_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_generic_write_checks(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_generic_write_inline_data(Ptr<address_space> mapping, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len, Ptr<Ptr<folio>> foliop,
      Ptr<Ptr<?>> fsdata, boolean da) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<posix_acl> ext4_get_acl(Ptr<inode> inode, int type, boolean rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_block(Ptr<inode> inode,
      @Unsigned @OriginalName("sector_t") long iblock, Ptr<buffer_head> bh, int create) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_block_unwritten(Ptr<inode> inode,
      @Unsigned @OriginalName("sector_t") long iblock, Ptr<buffer_head> bh_result, int create) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Indirect> ext4_get_branch(Ptr<inode> inode, int depth,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> offsets, Ptr<Indirect> chain,
      Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_context(Ptr<inode> inode, Ptr<?> ctx, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Ptr<dquot>> ext4_get_dquots(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const union fscrypt_policy*)ext4_get_dummy_policy($arg1))")
  public static Ptr<fscrypt_policy> ext4_get_dummy_policy(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_es_cache(Ptr<inode> inode, Ptr<fiemap_extent_info> fieinfo,
      @Unsigned long start, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_fc_inode_loc(Ptr<super_block> sb, @Unsigned long ino,
      Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_get_first_inline_block(Ptr<inode> inode,
      Ptr<Ptr<ext4_dir_entry_2>> parent_de, Ptr<java.lang.Integer> retval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_group_desc> ext4_get_group_desc(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<Ptr<buffer_head>> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_group_info> ext4_get_group_info(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_get_group_no_and_offset(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long blocknr,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_group_t") Integer> blockgrpp,
      Ptr<java.lang. @OriginalName("ext4_grpblk_t") Integer> offsetp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_group_t") int ext4_get_group_number(
      Ptr<super_block> sb, @Unsigned @OriginalName("ext4_fsblk_t") long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_inode_loc(Ptr<inode> inode, Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_inode_usage(Ptr<inode> inode,
      Ptr<java.lang. @OriginalName("qsize_t") Long> usage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> ext4_get_io_end(
      Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> ext4_get_journal_blkdev(Ptr<super_block> sb,
      @Unsigned @OriginalName("dev_t") int j_dev,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_fsblk_t") Long> j_start,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_fsblk_t") Long> j_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> ext4_get_journal_inode(Ptr<super_block> sb, @Unsigned int journal_inum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ext4_get_link($arg1, $arg2, $arg3))")
  public static String ext4_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_max_inline_size(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> ext4_get_parent(Ptr<dentry> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_projid(Ptr<inode> inode, Ptr<kprojid_t> projid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang. @OriginalName("qsize_t") Long> ext4_get_reserved_space(
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_tree(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_verity_descriptor(Ptr<inode> inode, Ptr<?> buf,
      @Unsigned long buf_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_get_verity_descriptor_location(Ptr<inode> inode,
      Ptr<java.lang. @Unsigned Long> desc_size_ret, Ptr<java.lang. @Unsigned Long> desc_pos_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int ext4_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_getblk(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int block, int map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap(Ptr<super_block> sb, Ptr<ext4_fsmap_head> head,
      @OriginalName("ext4_fsmap_format_t") Ptr<?> formatter, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_getfsmap_compare($arg1, (const struct list_head*)$arg2, (const struct list_head*)$arg3)")
  public static int ext4_getfsmap_compare(Ptr<?> priv, Ptr<list_head> a, Ptr<list_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap_datadev(Ptr<super_block> sb, Ptr<ext4_fsmap> keys,
      Ptr<ext4_getfsmap_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap_datadev_helper(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int agno, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_getfsmap_dev_compare((const void*)$arg1, (const void*)$arg2)")
  public static int ext4_getfsmap_dev_compare(Ptr<?> p1, Ptr<?> p2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap_find_fixed_metadata(Ptr<super_block> sb,
      Ptr<list_head> meta_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap_format(Ptr<ext4_fsmap> xfm, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap_helper(Ptr<super_block> sb, Ptr<ext4_getfsmap_info> info,
      Ptr<ext4_fsmap> rec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_getfsmap_is_valid_device(Ptr<super_block> sb, Ptr<ext4_fsmap> fm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap_logdev(Ptr<super_block> sb, Ptr<ext4_fsmap> keys,
      Ptr<ext4_getfsmap_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_getfsmap_meta_helper(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int agno, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_group_add(Ptr<super_block> sb, Ptr<ext4_new_group_data> input) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_group_add_blocks(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<super_block> sb, @Unsigned @OriginalName("ext4_fsblk_t") long block,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__le16") short ext4_group_desc_csum(Ptr<super_block> sb,
      @Unsigned int block_group, Ptr<ext4_group_desc> gdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_group_desc_csum_set(Ptr<super_block> sb, @Unsigned int block_group,
      Ptr<ext4_group_desc> gdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_group_desc_csum_verify(Ptr<super_block> sb, @Unsigned int block_group,
      Ptr<ext4_group_desc> gdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_group_desc_free(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_group_desc_init(Ptr<super_block> sb, Ptr<ext4_super_block> es,
      @Unsigned @OriginalName("ext4_fsblk_t") long logical_sb_block,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_group_t") Integer> first_not_zeroed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_group_extend(Ptr<super_block> sb, Ptr<ext4_super_block> es,
      @Unsigned @OriginalName("ext4_fsblk_t") long n_blocks_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_group_extend_no_check(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long o_blocks_count,
      @OriginalName("ext4_grpblk_t") int add) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_handle_clustersize(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_handle_dirty_dirblock(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_handle_error($arg1, $arg2, $arg3, $arg4, $arg5, (const u8*)$arg6, $arg7)")
  public static void ext4_handle_error(Ptr<super_block> sb, boolean force_ro, int error,
      @Unsigned int ino, @Unsigned long block, String func, @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_handle_inode_extension(Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("ssize_t") long written,
      @OriginalName("ssize_t") long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_has_free_clusters(Ptr<ext4_sb_info> sbi, long nclusters,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_has_stable_inodes(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_htree_fill_tree(Ptr<file> dir_file, @Unsigned int start_hash,
      @Unsigned int start_minor_hash, Ptr<java.lang. @Unsigned Integer> next_hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_htree_free_dir_info(Ptr<dir_private_info> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_htree_next_block(Ptr<inode> dir, @Unsigned int hash, Ptr<dx_frame> frame,
      Ptr<dx_frame> frames, Ptr<java.lang. @Unsigned Integer> start_hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_htree_store_dirent(Ptr<file> dir_file, @Unsigned int hash,
      @Unsigned int minor_hash, Ptr<ext4_dir_entry_2> dirent, Ptr<fscrypt_str> ent_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_inc_count(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ind_map_blocks(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ind_migrate(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ind_remove_space(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ind_trans_blocks(Ptr<inode> inode, int nrblocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_ind_truncate(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ind_truncate_ensure_credits(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<buffer_head> bh, int revoke_creds) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_acl(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<inode> dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_block_bitmap(Ptr<super_block> sb, Ptr<buffer_head> bh,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<ext4_group_desc> gdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_dirblock(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<buffer_head> bh, @Unsigned int parent_ino, Ptr<?> inline_buf,
      int inline_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_es() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_fs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_fs_context(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_inode_table(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, int barrier) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> ext4_init_io_end(Ptr<inode> inode,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_init_journal_params(Ptr<super_block> sb,
      Ptr<@OriginalName("journal_t") journal_s> journal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_mballoc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_new_dir(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> dir, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_orphan_info(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_pageio() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_pending() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_init_pending_tree(Ptr<ext4_pending_tree> tree) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_post_read_processing() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_init_security($arg1, $arg2, $arg3, (const struct qstr*)$arg4)")
  public static int ext4_init_security(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<inode> dir, Ptr<qstr> qstr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_symlink_block(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<fscrypt_str> disk_link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_sysfs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_init_system_zone() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_initialize_dirent_tail(Ptr<buffer_head> bh, @Unsigned int blocksize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_initxattrs($arg1, (const struct xattr*)$arg2, $arg3)")
  public static int ext4_initxattrs(Ptr<inode> inode, Ptr<xattr> xattr_array, Ptr<?> fs_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inline_data_iomap(Ptr<inode> inode, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inline_data_truncate(Ptr<inode> inode, Ptr<java.lang.Integer> has_inline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inlinedir_to_tree(Ptr<file> dir_file, Ptr<inode> dir,
      @Unsigned @OriginalName("ext4_lblk_t") int block, Ptr<dx_hash_info> hinfo,
      @Unsigned int start_hash, @Unsigned int start_minor_hash,
      Ptr<java.lang.Integer> has_inline_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inode_attach_jinode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_inode_bitmap(Ptr<super_block> sb,
      Ptr<ext4_group_desc> bg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_inode_bitmap_csum_set(Ptr<super_block> sb, Ptr<ext4_group_desc> gdp,
      Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inode_bitmap_csum_verify(Ptr<super_block> sb, Ptr<ext4_group_desc> gdp,
      Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_inode_bitmap_set(Ptr<super_block> sb, Ptr<ext4_group_desc> bg,
      @Unsigned @OriginalName("ext4_fsblk_t") long blk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inode_block_valid(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_fsblk_t") long start_blk, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_inode_csum(Ptr<inode> inode, Ptr<ext4_inode> raw,
      Ptr<ext4_inode_info> ei) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_inode_csum_set(Ptr<inode> inode, Ptr<ext4_inode> raw,
      Ptr<ext4_inode_info> ei) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_inode_extension_cleanup(Ptr<inode> inode, boolean need_trunc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inode_is_fast_symlink(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_inode_journal_mode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_inode_table(Ptr<super_block> sb,
      Ptr<ext4_group_desc> bg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_inode_table_set(Ptr<super_block> sb, Ptr<ext4_group_desc> bg,
      @Unsigned @OriginalName("ext4_fsblk_t") long blk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_inode_to_goal_block(
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_insert_delayed_blocks(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_insert_dentry(Ptr<inode> dir, Ptr<inode> inode, Ptr<ext4_dir_entry_2> de,
      int buf_size, Ptr<ext4_filename> fname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_invalidate_folio(Ptr<folio> folio, @Unsigned long offset,
      @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_io_end_defer_completion(
      Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_io_submit_init(Ptr<ext4_io_submit> io, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ioc_getfsmap(Ptr<super_block> sb, Ptr<fsmap_head> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long ext4_ioctl(Ptr<file> filp, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ioctl_get_encryption_pwsalt(Ptr<file> filp, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ioctl_getlabel(Ptr<ext4_sb_info> sbi, String user_label) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ioctl_getuuid(Ptr<ext4_sb_info> sbi, Ptr<fsuuid> ufsuuid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long ext4_ioctl_group_add(Ptr<file> file, Ptr<ext4_new_group_data> input) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ioctl_setflags(Ptr<inode> inode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_ioctl_setlabel($arg1, (const u8*)$arg2)")
  public static int ext4_ioctl_setlabel(Ptr<file> filp, String user_label) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_ioctl_setproject(Ptr<inode> inode, @Unsigned int projid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_iomap_alloc(Ptr<inode> inode, Ptr<ext4_map_blocks> map,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_iomap_begin(Ptr<inode> inode, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long length, @Unsigned int flags, Ptr<iomap> iomap,
      Ptr<iomap> srcmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_iomap_begin_report(Ptr<inode> inode, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long length, @Unsigned int flags, Ptr<iomap> iomap,
      Ptr<iomap> srcmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_iomap_end(Ptr<inode> inode, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long length, @OriginalName("ssize_t") long written,
      @Unsigned int flags, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_iomap_overwrite_begin(Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long length, @Unsigned int flags,
      Ptr<iomap> iomap, Ptr<iomap> srcmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_iomap_swap_activate(Ptr<swap_info_struct> sis, Ptr<file> file,
      Ptr<java.lang. @Unsigned @OriginalName("sector_t") Long> span) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_iomap_xattr_begin(Ptr<inode> inode, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long length, @Unsigned int flags, Ptr<iomap> iomap,
      Ptr<iomap> srcmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_is_pending(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_issue_discard(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group,
      @OriginalName("ext4_grpblk_t") int cluster, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_issue_zeroout(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_itable_unused_count(Ptr<super_block> sb,
      Ptr<ext4_group_desc> bg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_itable_unused_set(Ptr<super_block> sb, Ptr<ext4_group_desc> bg,
      @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_jbd2_inode_add_write(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @OriginalName("loff_t") long start_byte, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_journal_bmap(Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<java.lang. @Unsigned @OriginalName("sector_t") Long> block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_journal_check_start(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_journal_commit_callback(Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> txn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_journal_destroy(Ptr<ext4_sb_info> sbi,
      Ptr<@OriginalName("journal_t") journal_s> journal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_journal_finish_inode_data_buffers(Ptr<jbd2_inode> jinode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_journal_folio_buffers(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<folio> folio,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_journal_submit_inode_data_buffers(Ptr<jbd2_inode> jinode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_journalled_dirty_folio(Ptr<address_space> mapping, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_journalled_invalidate_folio(Ptr<folio> folio, @Unsigned long offset,
      @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_journalled_submit_inode_data_buffers(Ptr<jbd2_inode> jinode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_journalled_write_end((const struct kiocb*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int ext4_journalled_write_end(Ptr<kiocb> iocb, Ptr<address_space> mapping,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied, Ptr<folio> folio,
      Ptr<?> fsdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_journalled_zero_new_buffers(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, Ptr<folio> folio,
      @Unsigned int from, @Unsigned int to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_kill_sb(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_kvfree_array_rcu(Ptr<?> to_free) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_io_end_vec> ext4_last_io_end_vec(
      Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_lazyinit_thread(Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_link(Ptr<dentry> old_dentry, Ptr<inode> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_list_backups(Ptr<super_block> sb,
      Ptr<java.lang. @Unsigned Integer> three, Ptr<java.lang. @Unsigned Integer> five,
      Ptr<java.lang. @Unsigned Integer> seven) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_listxattr(Ptr<dentry> dentry, String buffer,
      @Unsigned long buffer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long ext4_llseek(Ptr<file> file,
      @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_load_and_init_journal(Ptr<super_block> sb, Ptr<ext4_super_block> es,
      Ptr<ext4_fs_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_load_journal(Ptr<super_block> sb, Ptr<ext4_super_block> es,
      @Unsigned long journal_devnum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_load_super(Ptr<super_block> sb,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_fsblk_t") Long> lsb, int silent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_lock_group(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> ext4_lookup(Ptr<inode> dir, Ptr<dentry> dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_map_create_blocks(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_map_query_blocks(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_map_query_blocks_next_in_leaf(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, @Unsigned int orig_mlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mark_bitmap_end(int start_bit, int end_bit, String bitmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mark_dquot_dirty(Ptr<dquot> dquot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mark_group_bitmap_corrupted(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mark_iloc_dirty(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mark_inode_used(Ptr<super_block> sb, int ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mark_recovery_complete(Ptr<super_block> sb, Ptr<ext4_super_block> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_match($arg1, (const struct ext4_filename*)$arg2, $arg3)")
  public static boolean ext4_match(Ptr<inode> parent, Ptr<ext4_filename> fname,
      Ptr<ext4_dir_entry_2> de) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_maybe_update_superblock(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_add_groupinfo(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, Ptr<ext4_group_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_alloc_groupinfo(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int ngroups) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_check_limits(Ptr<ext4_allocation_context> ac, Ptr<ext4_buddy> e4b,
      int finish_group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_clear_bb(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, @Unsigned @OriginalName("ext4_fsblk_t") long block, @Unsigned long count,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_collect_stats(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_complex_scan_group(Ptr<ext4_allocation_context> ac,
      Ptr<ext4_buddy> e4b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_discard_group_preallocations(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, Ptr<java.lang.Integer> busy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_discard_lg_preallocations(Ptr<super_block> sb,
      Ptr<ext4_locality_group> lg, int order, int total_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_mb_discard_preallocations_should_retry(Ptr<super_block> sb,
      Ptr<ext4_allocation_context> ac, Ptr<java.lang. @Unsigned Long> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_find_by_goal(Ptr<ext4_allocation_context> ac, Ptr<ext4_buddy> e4b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_free_metadata(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<ext4_buddy> e4b,
      Ptr<ext4_free_data> new_entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_generate_buddy(Ptr<super_block> sb, Ptr<?> buddy, Ptr<?> bitmap,
      @Unsigned @OriginalName("ext4_group_t") int group, Ptr<ext4_group_info> grp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_generate_from_pa(Ptr<super_block> sb, Ptr<?> bitmap,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_mb_good_group(Ptr<ext4_allocation_context> ac,
      @Unsigned @OriginalName("ext4_group_t") int group, criteria cr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_good_group_nolock(Ptr<ext4_allocation_context> ac,
      @Unsigned @OriginalName("ext4_group_t") int group, criteria cr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_init(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_init_backend(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_init_cache(Ptr<folio> folio, String incore,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_init_group(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_initialize_context(Ptr<ext4_allocation_context> ac,
      Ptr<ext4_allocation_request> ar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_load_buddy_gfp(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, Ptr<ext4_buddy> e4b,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_mark_bb(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long block, int len, boolean state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_mark_context(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<super_block> sb, boolean state, @Unsigned @OriginalName("ext4_group_t") int group,
      @OriginalName("ext4_grpblk_t") int blkoff, @OriginalName("ext4_grpblk_t") int len, int flags,
      Ptr<java.lang. @OriginalName("ext4_grpblk_t") Integer> ret_changed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_mark_diskspace_used(Ptr<ext4_allocation_context> ac,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, @Unsigned int reserv_clstrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_mark_pa_deleted(Ptr<super_block> sb, Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_mb_new_blocks(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<ext4_allocation_request> ar,
      Ptr<java.lang.Integer> errp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_mb_new_blocks_simple(
      Ptr<ext4_allocation_request> ar, Ptr<java.lang.Integer> errp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_new_group_pa(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_new_inode_pa(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_normalize_request(Ptr<ext4_allocation_context> ac,
      Ptr<ext4_allocation_request> ar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_pa_adjust_overlap(Ptr<ext4_allocation_context> ac,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_lblk_t") Integer> start,
      Ptr<java.lang. @OriginalName("loff_t") Long> end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_pa_callback(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_pa_put_free(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_group_t") int ext4_mb_prefetch(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @Unsigned int nr,
      Ptr<java.lang.Integer> cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_prefetch_fini(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_regular_allocator(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_release(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_release_context(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_release_group_pa(Ptr<ext4_buddy> e4b, Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_release_inode_pa(Ptr<ext4_buddy> e4b, Ptr<buffer_head> bitmap_bh,
      Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_scan_aligned(Ptr<ext4_allocation_context> ac, Ptr<ext4_buddy> e4b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_scan_group(Ptr<ext4_allocation_context> ac,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_scan_groups_best_avail(Ptr<ext4_allocation_context> ac,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_scan_groups_linear(Ptr<ext4_allocation_context> ac,
      @Unsigned @OriginalName("ext4_group_t") int ngroups,
      Ptr<java.lang. @Unsigned @OriginalName("ext4_group_t") Integer> start,
      @Unsigned @OriginalName("ext4_group_t") int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_scan_groups_xa_range(Ptr<ext4_allocation_context> ac, Ptr<xarray> xa,
      @Unsigned @OriginalName("ext4_group_t") int start,
      @Unsigned @OriginalName("ext4_group_t") int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> ext4_mb_seq_groups_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_seq_groups_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> ext4_mb_seq_groups_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_seq_groups_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> ext4_mb_seq_structs_summary_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mb_seq_structs_summary_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> ext4_mb_seq_structs_summary_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_seq_structs_summary_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_simple_scan_group(Ptr<ext4_allocation_context> ac,
      Ptr<ext4_buddy> e4b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_try_best_found(Ptr<ext4_allocation_context> ac, Ptr<ext4_buddy> e4b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_use_best_found(Ptr<ext4_allocation_context> ac, Ptr<ext4_buddy> e4b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_mb_use_inode_pa(Ptr<ext4_allocation_context> ac,
      Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_mb_use_preallocated(Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mballoc_query_range(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int first,
      @OriginalName("ext4_grpblk_t") int end,
      @OriginalName("ext4_mballoc_query_range_fn") Ptr<?> meta_formatter,
      @OriginalName("ext4_mballoc_query_range_fn") Ptr<?> formatter, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_meta_trans_blocks(Ptr<inode> inode, int lblocks, int pextents) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> ext4_mkdir(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mknod(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned @OriginalName("dev_t") int rdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_move_extents(Ptr<file> o_filp, Ptr<file> d_filp, @Unsigned long orig_blk,
      @Unsigned long donor_blk, @Unsigned long len, Ptr<java.lang. @Unsigned Long> moved_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_mpage_readpages(Ptr<inode> inode, Ptr<readahead_control> rac,
      Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_multi_mount_protect(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long mmp_block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_new_meta_blocks(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_fsblk_t") long goal, @Unsigned int flags,
      Ptr<java.lang. @Unsigned Long> count, Ptr<java.lang.Integer> errp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_nfs_commit_metadata(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> ext4_nfs_get_inode(Ptr<super_block> sb, @Unsigned long ino,
      @Unsigned int generation) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_nonda_switch(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_normal_submit_inode_data_buffers(Ptr<jbd2_inode> jinode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_notify_error_sysfs(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_num_base_meta_blocks(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_num_overhead_clusters(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<ext4_group_desc> gdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_orphan_add(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_orphan_cleanup(Ptr<super_block> sb, Ptr<ext4_super_block> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_orphan_del(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_orphan_file_add(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_orphan_file_block_trigger(Ptr<jbd2_buffer_trigger_type> triggers,
      Ptr<buffer_head> bh, Ptr<?> data, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_orphan_file_empty(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> ext4_orphan_get(Ptr<super_block> sb, @Unsigned long ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int ext4_page_mkwrite(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_parse_param(Ptr<fs_context> fc, Ptr<fs_parameter> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_percpu_param_destroy(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_percpu_param_init(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_prepare_inline_data(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_process_freed_data(Ptr<super_block> sb,
      @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_process_orphan(Ptr<inode> inode, Ptr<java.lang.Integer> nr_truncates,
      Ptr<java.lang.Integer> nr_orphans) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_punch_hole(Ptr<file> file, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_put_io_end(Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_put_io_end_defer(Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_put_super(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_quota_off(Ptr<super_block> sb, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_quota_on($arg1, $arg2, $arg3, (const struct path*)$arg4)")
  public static int ext4_quota_on(Ptr<super_block> sb, int type, int format_id, Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ext4_quota_read(Ptr<super_block> sb, int type,
      String data, @Unsigned long len, @OriginalName("loff_t") long off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_quota_write($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static @OriginalName("ssize_t") long ext4_quota_write(Ptr<super_block> sb, int type,
      String data, @Unsigned long len, @OriginalName("loff_t") long off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_rcu_ptr_callback(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_read_bh(Ptr<buffer_head> bh,
      @Unsigned @OriginalName("blk_opf_t") int op_flags, Ptr<?> end_io, boolean simu_fail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_read_bh_lock(Ptr<buffer_head> bh,
      @Unsigned @OriginalName("blk_opf_t") int op_flags, boolean wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_read_bh_nowait(Ptr<buffer_head> bh,
      @Unsigned @OriginalName("blk_opf_t") int op_flags, Ptr<?> end_io, boolean simu_fail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_read_block_bitmap(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_read_block_bitmap_nowait(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group, boolean ignore_locked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_read_folio(Ptr<file> file, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_read_inline_data(Ptr<inode> inode, Ptr<?> buffer, @Unsigned int len,
      Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_read_inline_dir(Ptr<file> file, Ptr<dir_context> ctx,
      Ptr<java.lang.Integer> has_inline_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_read_inline_folio(Ptr<inode> inode, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> ext4_read_inline_link(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_read_inode_bitmap(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> ext4_read_merkle_tree_page(Ptr<inode> inode, @Unsigned long index,
      @Unsigned long num_ra_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_readahead(Ptr<readahead_control> rac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_readpage_inline(Ptr<inode> inode, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_reconfigure(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_register_li_request(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int first_not_zeroed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_register_sysfs(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_release_dir(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_release_dquot(Ptr<dquot> dquot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_release_file(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_release_folio(Ptr<folio> folio,
      @Unsigned @OriginalName("gfp_t") int wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_release_io_end(Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_release_orphan_info(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_release_system_zone(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_remove_blocks(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_extent> ex, Ptr<partial_cluster> partial,
      @Unsigned @OriginalName("ext4_lblk_t") int from,
      @Unsigned @OriginalName("ext4_lblk_t") int to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_remove_pending(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_rename(Ptr<mnt_idmap> idmap, Ptr<inode> old_dir, Ptr<dentry> old_dentry,
      Ptr<inode> new_dir, Ptr<dentry> new_dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_rename2(Ptr<mnt_idmap> idmap, Ptr<inode> old_dir, Ptr<dentry> old_dentry,
      Ptr<inode> new_dir, Ptr<dentry> new_dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_rename_dir_finish(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<ext4_renament> ent,
      @Unsigned int dir_ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_rename_dir_prepare(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<ext4_renament> ent,
      boolean is_cross) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_rereserve_cluster(Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_reserve_inode_write(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_iloc> iloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_reset_inode_seed(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_resetent(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<ext4_renament> ent, @Unsigned int ino, @Unsigned int file_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_resize_begin(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_resize_end(Ptr<super_block> sb, boolean update_backups) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_resize_fs(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long n_blocks_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_rmdir(Ptr<inode> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_run_li_request(Ptr<ext4_li_request> elr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_sample_last_mounted(Ptr<super_block> sb, Ptr<vfsmount> mnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_sb_block_valid(Ptr<super_block> sb, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_fsblk_t") long start_blk, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_sb_bread(Ptr<super_block> sb,
      @Unsigned @OriginalName("sector_t") long block,
      @Unsigned @OriginalName("blk_opf_t") int op_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_sb_bread_nofail(Ptr<super_block> sb,
      @Unsigned @OriginalName("sector_t") long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_sb_bread_unmovable(Ptr<super_block> sb,
      @Unsigned @OriginalName("sector_t") long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_sb_breadahead_unmovable(Ptr<super_block> sb,
      @Unsigned @OriginalName("sector_t") long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_sb_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_sb_setlabel($arg1, (const void*)$arg2)")
  public static void ext4_sb_setlabel(Ptr<ext4_super_block> es, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_sb_setuuid($arg1, (const void*)$arg2)")
  public static void ext4_sb_setuuid(Ptr<ext4_super_block> es, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_search_dir(Ptr<buffer_head> bh, String search_buf, int buf_size,
      Ptr<inode> dir, Ptr<ext4_filename> fname, @Unsigned int offset,
      Ptr<Ptr<ext4_dir_entry_2>> res_dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_seq_es_shrinker_info_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_seq_mb_stats_show(Ptr<seq_file> seq, Ptr<?> offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_seq_options_show(Ptr<seq_file> seq, Ptr<?> offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_set_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<posix_acl> acl,
      int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_set_aops(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_set_context($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static int ext4_set_context(Ptr<inode> inode, Ptr<?> ctx, @Unsigned long len,
      Ptr<?> fs_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_set_def_opts(Ptr<super_block> sb, Ptr<ext4_super_block> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_set_inode_flags(Ptr<inode> inode, boolean init) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_set_inode_mapping_order(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_set_iomap(Ptr<inode> inode, Ptr<iomap> iomap, Ptr<ext4_map_blocks> map,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long length,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_setent(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<ext4_renament> ent, @Unsigned int ino, @Unsigned int file_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_setup_new_descs(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<super_block> sb, Ptr<ext4_new_flex_group_data> flex_gd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_setup_next_flex_gd(Ptr<super_block> sb,
      Ptr<ext4_new_flex_group_data> flex_gd,
      @Unsigned @OriginalName("ext4_fsblk_t") long n_blocks_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_setup_super(Ptr<super_block> sb, Ptr<ext4_super_block> es, int read_only) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_setup_system_zone(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_should_retry_alloc(Ptr<super_block> sb, Ptr<java.lang.Integer> retries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_show_options(Ptr<seq_file> seq, Ptr<dentry> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_shutdown(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_ext_path> ext4_split_convert_extents(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, Ptr<ext4_ext_path> path, int flags,
      Ptr<java.lang. @Unsigned Integer> allocated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_ext_path> ext4_split_extent(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_ext_path> path, Ptr<ext4_map_blocks> map, int split_flag, int flags,
      Ptr<java.lang. @Unsigned Integer> allocated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ext4_ext_path> ext4_split_extent_at(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_ext_path> path, @Unsigned @OriginalName("ext4_lblk_t") int split, int split_flag,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_statfs(Ptr<dentry> dentry, Ptr<kstatfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_stop_mmpd(Ptr<ext4_sb_info> sbi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__le32") int ext4_superblock_csum(
      Ptr<ext4_super_block> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_superblock_csum_set(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_swap_extents(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode1, Ptr<inode> inode2, @Unsigned @OriginalName("ext4_lblk_t") int lblk1,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk2,
      @Unsigned @OriginalName("ext4_lblk_t") int count, int unwritten, Ptr<java.lang.Integer> erp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_symlink($arg1, $arg2, $arg3, (const u8*)$arg4)")
  public static int ext4_symlink(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> dentry,
      String symname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_sync_file(Ptr<file> file, @OriginalName("loff_t") long start,
      @OriginalName("loff_t") long end, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_sync_fs(Ptr<super_block> sb, int wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_tmpfile(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<file> file,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ext4_grpblk_t") int ext4_trim_all_free(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int max, @OriginalName("ext4_grpblk_t") int minblocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_trim_fs(Ptr<super_block> sb, Ptr<fstrim_range> range) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_trim_interrupted() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_truncate(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_truncate_page_cache_block_range(Ptr<inode> inode,
      @OriginalName("loff_t") long start, @OriginalName("loff_t") long end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_try_add_inline_entry(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<ext4_filename> fname,
      Ptr<inode> dir, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_try_create_inline_dir(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> parent,
      Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_try_to_trim_range(Ptr<super_block> sb, Ptr<ext4_buddy> e4b,
      @OriginalName("ext4_grpblk_t") int start, @OriginalName("ext4_grpblk_t") int max,
      @OriginalName("ext4_grpblk_t") int minblocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_try_to_write_inline_data(Ptr<address_space> mapping, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len, Ptr<Ptr<folio>> foliop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_unfreeze(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_unlink(Ptr<inode> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_unregister_li_request(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_unregister_sysfs(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_update_backup_sb($arg1, $arg2, $arg3, $arg4, (const void*)$arg5)")
  public static int ext4_update_backup_sb(Ptr<super_block> sb,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      @Unsigned @OriginalName("ext4_group_t") int grp, Ptr<?> func, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_update_dir_count(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<ext4_renament> ent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_update_disksize_before_punch(Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_update_dx_flag(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_update_dynamic_rev(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_update_final_de(Ptr<?> de_buf, int old_size, int new_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_update_inline_data(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_update_overhead(Ptr<super_block> sb, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_update_primary_sb($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static int ext4_update_primary_sb(Ptr<super_block> sb,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<?> func, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_update_superblocks_fn($arg1, $arg2, (const void*)$arg3)")
  public static int ext4_update_superblocks_fn(Ptr<super_block> sb, Ptr<?> func, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ext4_used_dirs_count(Ptr<super_block> sb, Ptr<ext4_group_desc> bg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_used_dirs_set(Ptr<super_block> sb, Ptr<ext4_group_desc> bg,
      @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ext4_fsblk_t") long ext4_valid_block_bitmap(
      Ptr<super_block> sb, Ptr<ext4_group_desc> desc,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_validate_block_bitmap(Ptr<super_block> sb, Ptr<ext4_group_desc> desc,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_validate_inode_bitmap(Ptr<super_block> sb, Ptr<ext4_group_desc> desc,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_wait_block_bitmap(Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int block_group, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_wait_dax_page(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_walk_page_buffers($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, (int (*)(jbd2_journal_handle*, struct inode*, struct buffer_head*))$arg7)")
  public static int ext4_walk_page_buffers(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<buffer_head> head, @Unsigned int from, @Unsigned int to, Ptr<java.lang.Integer> partial,
      Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_write_begin((const struct kiocb*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int ext4_write_begin(Ptr<kiocb> iocb, Ptr<address_space> mapping,
      @OriginalName("loff_t") long pos, @Unsigned int len, Ptr<Ptr<folio>> foliop,
      Ptr<Ptr<?>> fsdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_write_dquot(Ptr<dquot> dquot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_write_end((const struct kiocb*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int ext4_write_end(Ptr<kiocb> iocb, Ptr<address_space> mapping,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied, Ptr<folio> folio,
      Ptr<?> fsdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_write_info(Ptr<super_block> sb, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_write_inline_data(Ptr<inode> inode, Ptr<ext4_iloc> iloc, Ptr<?> buffer,
      @OriginalName("loff_t") long pos, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_write_inline_data_end(Ptr<inode> inode, @OriginalName("loff_t") long pos,
      @Unsigned int len, @Unsigned int copied, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_write_inode(Ptr<inode> inode, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_write_merkle_tree_block($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static int ext4_write_merkle_tree_block(Ptr<inode> inode, Ptr<?> buf, @Unsigned long pos,
      @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_writepages(Ptr<address_space> mapping, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__le32") int ext4_xattr_block_csum(Ptr<inode> inode,
      @Unsigned @OriginalName("sector_t") long block_nr, Ptr<ext4_xattr_header> hdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_block_get($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static int ext4_xattr_block_get(Ptr<inode> inode, int name_index, String name,
      Ptr<?> buffer, @Unsigned long buffer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_block_set(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_xattr_info> i, Ptr<ext4_xattr_block_find> bs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_cmp(Ptr<ext4_xattr_header> header1, Ptr<ext4_xattr_header> header2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mb_cache> ext4_xattr_create_cache() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_delete_inode(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<Ptr<ext4_xattr_inode_array>> ea_inode_array, int extra_credits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_xattr_destroy_cache(Ptr<mb_cache> cache) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ext4_xattr_free_space(Ptr<ext4_xattr_entry> last,
      Ptr<java.lang. @Unsigned Long> min_offs, Ptr<?> base, Ptr<java.lang.Integer> total) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_get($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static int ext4_xattr_get(Ptr<inode> inode, int name_index, String name, Ptr<?> buffer,
      @Unsigned long buffer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<buffer_head> ext4_xattr_get_block(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_hurd_get((const struct xattr_handler*)$arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static int ext4_xattr_hurd_get(Ptr<xattr_handler> handler, Ptr<dentry> unused,
      Ptr<inode> inode, String name, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_xattr_hurd_list(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_hurd_set((const struct xattr_handler*)$arg1, $arg2, $arg3, $arg4, (const u8*)$arg5, (const void*)$arg6, $arg7, $arg8)")
  public static int ext4_xattr_hurd_set(Ptr<xattr_handler> handler, Ptr<mnt_idmap> idmap,
      Ptr<dentry> unused, Ptr<inode> inode, String name, Ptr<?> value, @Unsigned long size,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_ibody_get($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static int ext4_xattr_ibody_get(Ptr<inode> inode, int name_index, String name,
      Ptr<?> buffer, @Unsigned long buffer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_ibody_set(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, Ptr<ext4_xattr_info> i, Ptr<ext4_xattr_ibody_find> is) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_xattr_inode_array_free(Ptr<ext4_xattr_inode_array> ea_inode_array) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_inode_cache_find($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static Ptr<inode> ext4_xattr_inode_cache_find(Ptr<inode> inode, Ptr<?> value,
      @Unsigned long value_len, @Unsigned int hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> ext4_xattr_inode_create(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @Unsigned int hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_xattr_inode_dec_ref_all(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> parent,
      Ptr<buffer_head> bh, Ptr<ext4_xattr_entry> first, boolean block_csum,
      Ptr<Ptr<ext4_xattr_inode_array>> ea_inode_array, int extra_credits, boolean skip_quota) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_xattr_inode_free_quota(Ptr<inode> parent, Ptr<inode> ea_inode,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_inode_get(Ptr<inode> inode, Ptr<ext4_xattr_entry> entry,
      Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_inode_iget(Ptr<inode> parent, @Unsigned long ea_ino,
      @Unsigned int ea_inode_hash, Ptr<Ptr<inode>> ea_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_inode_inc_ref_all(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> parent,
      Ptr<ext4_xattr_entry> first) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_inode_lookup_create($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static Ptr<inode> ext4_xattr_inode_lookup_create(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, Ptr<?> value,
      @Unsigned long value_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_inode_read(Ptr<inode> ea_inode, Ptr<?> buf, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_inode_update_ref(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> ea_inode,
      int ref_change) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_inode_write($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static int ext4_xattr_inode_write(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> ea_inode, Ptr<?> buf,
      int bufsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_list_entries(Ptr<dentry> dentry, Ptr<ext4_xattr_entry> entry,
      String buffer, @Unsigned long buffer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_make_inode_space(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_inode> raw_inode, int isize_diff, @Unsigned long ifree, @Unsigned long bfree,
      Ptr<java.lang.Integer> total_ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_move_to_block(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<ext4_inode> raw_inode, Ptr<ext4_xattr_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_xattr_release_block(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<buffer_head> bh, Ptr<Ptr<ext4_xattr_inode_array>> ea_inode_array, int extra_credits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_security_get((const struct xattr_handler*)$arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static int ext4_xattr_security_get(Ptr<xattr_handler> handler, Ptr<dentry> unused,
      Ptr<inode> inode, String name, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_security_set((const struct xattr_handler*)$arg1, $arg2, $arg3, $arg4, (const u8*)$arg5, (const void*)$arg6, $arg7, $arg8)")
  public static int ext4_xattr_security_set(Ptr<xattr_handler> handler, Ptr<mnt_idmap> idmap,
      Ptr<dentry> unused, Ptr<inode> inode, String name, Ptr<?> value, @Unsigned long size,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_set($arg1, $arg2, (const u8*)$arg3, (const void*)$arg4, $arg5, $arg6)")
  public static int ext4_xattr_set(Ptr<inode> inode, int name_index, String name, Ptr<?> value,
      @Unsigned long value_len, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_set_credits(Ptr<inode> inode, @Unsigned long value_len,
      boolean is_create, Ptr<java.lang.Integer> credits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_xattr_set_entry(Ptr<ext4_xattr_info> i, Ptr<ext4_xattr_search> s,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<inode> new_ea_inode, boolean is_block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_set_handle($arg1, $arg2, $arg3, (const u8*)$arg4, (const void*)$arg5, $arg6, $arg7)")
  public static int ext4_xattr_set_handle(Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle,
      Ptr<inode> inode, int name_index, String name, Ptr<?> value, @Unsigned long value_len,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_xattr_shift_entries(Ptr<ext4_xattr_entry> entry, int value_offs_shift,
      Ptr<?> to, Ptr<?> from, @Unsigned long n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_trusted_get((const struct xattr_handler*)$arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static int ext4_xattr_trusted_get(Ptr<xattr_handler> handler, Ptr<dentry> unused,
      Ptr<inode> inode, String name, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_xattr_trusted_list(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_trusted_set((const struct xattr_handler*)$arg1, $arg2, $arg3, $arg4, (const u8*)$arg5, (const void*)$arg6, $arg7, $arg8)")
  public static int ext4_xattr_trusted_set(Ptr<xattr_handler> handler, Ptr<mnt_idmap> idmap,
      Ptr<dentry> unused, Ptr<inode> inode, String name, Ptr<?> value, @Unsigned long size,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_user_get((const struct xattr_handler*)$arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static int ext4_xattr_user_get(Ptr<xattr_handler> handler, Ptr<dentry> unused,
      Ptr<inode> inode, String name, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ext4_xattr_user_list(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ext4_xattr_user_set((const struct xattr_handler*)$arg1, $arg2, $arg3, $arg4, (const u8*)$arg5, (const void*)$arg6, $arg7, $arg8)")
  public static int ext4_xattr_user_set(Ptr<xattr_handler> handler, Ptr<mnt_idmap> idmap,
      Ptr<dentry> unused, Ptr<inode> inode, String name, Ptr<?> value, @Unsigned long size,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ext4_zero_partial_blocks(
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      @OriginalName("loff_t") long lstart, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long ext4_zero_range(Ptr<file> file, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long len, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ext4_zeroout_es(Ptr<inode> inode, Ptr<ext4_extent> ex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_allocation_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_allocation_request extends Struct {
    public Ptr<inode> inode;

    public @Unsigned int len;

    public @Unsigned @OriginalName("ext4_lblk_t") int logical;

    public @Unsigned @OriginalName("ext4_lblk_t") int lleft;

    public @Unsigned @OriginalName("ext4_lblk_t") int lright;

    public @Unsigned @OriginalName("ext4_fsblk_t") long goal;

    public @Unsigned @OriginalName("ext4_fsblk_t") long pleft;

    public @Unsigned @OriginalName("ext4_fsblk_t") long pright;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_system_blocks"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_system_blocks extends Struct {
    public rb_root root;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_group_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_group_desc extends Struct {
    public @Unsigned @OriginalName("__le32") int bg_block_bitmap_lo;

    public @Unsigned @OriginalName("__le32") int bg_inode_bitmap_lo;

    public @Unsigned @OriginalName("__le32") int bg_inode_table_lo;

    public @Unsigned @OriginalName("__le16") short bg_free_blocks_count_lo;

    public @Unsigned @OriginalName("__le16") short bg_free_inodes_count_lo;

    public @Unsigned @OriginalName("__le16") short bg_used_dirs_count_lo;

    public @Unsigned @OriginalName("__le16") short bg_flags;

    public @Unsigned @OriginalName("__le32") int bg_exclude_bitmap_lo;

    public @Unsigned @OriginalName("__le16") short bg_block_bitmap_csum_lo;

    public @Unsigned @OriginalName("__le16") short bg_inode_bitmap_csum_lo;

    public @Unsigned @OriginalName("__le16") short bg_itable_unused_lo;

    public @Unsigned @OriginalName("__le16") short bg_checksum;

    public @Unsigned @OriginalName("__le32") int bg_block_bitmap_hi;

    public @Unsigned @OriginalName("__le32") int bg_inode_bitmap_hi;

    public @Unsigned @OriginalName("__le32") int bg_inode_table_hi;

    public @Unsigned @OriginalName("__le16") short bg_free_blocks_count_hi;

    public @Unsigned @OriginalName("__le16") short bg_free_inodes_count_hi;

    public @Unsigned @OriginalName("__le16") short bg_used_dirs_count_hi;

    public @Unsigned @OriginalName("__le16") short bg_itable_unused_hi;

    public @Unsigned @OriginalName("__le32") int bg_exclude_bitmap_hi;

    public @Unsigned @OriginalName("__le16") short bg_block_bitmap_csum_hi;

    public @Unsigned @OriginalName("__le16") short bg_inode_bitmap_csum_hi;

    public @Unsigned int bg_reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_es_tree"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_es_tree extends Struct {
    public rb_root root;

    public Ptr<extent_status> cache_es;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_es_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_es_stats extends Struct {
    public @Unsigned long es_stats_shrunk;

    public percpu_counter es_stats_cache_hits;

    public percpu_counter es_stats_cache_misses;

    public @Unsigned long es_stats_scan_time;

    public @Unsigned long es_stats_max_scan_time;

    public percpu_counter es_stats_all_cnt;

    public percpu_counter es_stats_shk_cnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_pending_tree"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_pending_tree extends Struct {
    public rb_root root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_stats extends Struct {
    public @Unsigned int @Size(10) [] fc_ineligible_reason_count;

    public @Unsigned long fc_num_commits;

    public @Unsigned long fc_ineligible_commits;

    public @Unsigned long fc_failed_commits;

    public @Unsigned long fc_skipped_commits;

    public @Unsigned long fc_numblks;

    public @Unsigned long s_fc_avg_commit_time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_alloc_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_alloc_region extends Struct {
    public @Unsigned @OriginalName("ext4_lblk_t") int lblk;

    public @Unsigned @OriginalName("ext4_fsblk_t") long pblk;

    public int ino;

    public int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_replay_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_replay_state extends Struct {
    public int fc_replay_num_tags;

    public int fc_replay_expected_off;

    public int fc_current_pass;

    public int fc_cur_tag;

    public int fc_crc;

    public Ptr<ext4_fc_alloc_region> fc_regions;

    public int fc_regions_size;

    public int fc_regions_used;

    public int fc_regions_valid;

    public Ptr<java.lang.Integer> fc_modified_inodes;

    public int fc_modified_inodes_used;

    public int fc_modified_inodes_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_inode_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_inode_info extends Struct {
    public @Unsigned @OriginalName("__le32") int @Size(15) [] i_data;

    public @Unsigned int i_dtime;

    public @Unsigned @OriginalName("ext4_fsblk_t") long i_file_acl;

    public @Unsigned @OriginalName("ext4_group_t") int i_block_group;

    public @Unsigned @OriginalName("ext4_lblk_t") int i_dir_start_lookup;

    public @Unsigned long i_flags;

    public rw_semaphore xattr_sem;

    @InlineUnion(24276)
    public list_head i_orphan;

    @InlineUnion(24276)
    public @Unsigned int i_orphan_idx;

    public list_head i_fc_dilist;

    public list_head i_fc_list;

    public @Unsigned @OriginalName("ext4_lblk_t") int i_fc_lblk_start;

    public @Unsigned @OriginalName("ext4_lblk_t") int i_fc_lblk_len;

    public @OriginalName("spinlock_t") spinlock i_raw_lock;

    public @OriginalName("wait_queue_head_t") wait_queue_head i_fc_wait;

    public @OriginalName("spinlock_t") spinlock i_fc_lock;

    public @OriginalName("loff_t") long i_disksize;

    public rw_semaphore i_data_sem;

    public inode vfs_inode;

    public Ptr<jbd2_inode> jinode;

    public timespec64 i_crtime;

    public atomic_t i_prealloc_active;

    public @Unsigned int i_reserved_data_blocks;

    public rb_root i_prealloc_node;

    public rwlock_t i_prealloc_lock;

    public ext4_es_tree i_es_tree;

    public rwlock_t i_es_lock;

    public list_head i_es_list;

    public @Unsigned int i_es_all_nr;

    public @Unsigned int i_es_shk_nr;

    public @Unsigned @OriginalName("ext4_lblk_t") int i_es_shrink_lblk;

    public @Unsigned @OriginalName("ext4_group_t") int i_last_alloc_group;

    public ext4_pending_tree i_pending_tree;

    public @Unsigned short i_extra_isize;

    public @Unsigned short i_inline_off;

    public @Unsigned short i_inline_size;

    public @OriginalName("qsize_t") long i_reserved_quota;

    public @OriginalName("spinlock_t") spinlock i_block_reservation_lock;

    public @OriginalName("spinlock_t") spinlock i_completed_io_lock;

    public list_head i_rsv_conversion_list;

    public work_struct i_rsv_conversion_work;

    public @Unsigned @OriginalName("tid_t") int i_sync_tid;

    public @Unsigned @OriginalName("tid_t") int i_datasync_tid;

    public Ptr<dquot> @Size(3) [] i_dquot;

    public @Unsigned int i_csum_seed;

    public kprojid_t i_projid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_super_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_super_block extends Struct {
    public @Unsigned @OriginalName("__le32") int s_inodes_count;

    public @Unsigned @OriginalName("__le32") int s_blocks_count_lo;

    public @Unsigned @OriginalName("__le32") int s_r_blocks_count_lo;

    public @Unsigned @OriginalName("__le32") int s_free_blocks_count_lo;

    public @Unsigned @OriginalName("__le32") int s_free_inodes_count;

    public @Unsigned @OriginalName("__le32") int s_first_data_block;

    public @Unsigned @OriginalName("__le32") int s_log_block_size;

    public @Unsigned @OriginalName("__le32") int s_log_cluster_size;

    public @Unsigned @OriginalName("__le32") int s_blocks_per_group;

    public @Unsigned @OriginalName("__le32") int s_clusters_per_group;

    public @Unsigned @OriginalName("__le32") int s_inodes_per_group;

    public @Unsigned @OriginalName("__le32") int s_mtime;

    public @Unsigned @OriginalName("__le32") int s_wtime;

    public @Unsigned @OriginalName("__le16") short s_mnt_count;

    public @Unsigned @OriginalName("__le16") short s_max_mnt_count;

    public @Unsigned @OriginalName("__le16") short s_magic;

    public @Unsigned @OriginalName("__le16") short s_state;

    public @Unsigned @OriginalName("__le16") short s_errors;

    public @Unsigned @OriginalName("__le16") short s_minor_rev_level;

    public @Unsigned @OriginalName("__le32") int s_lastcheck;

    public @Unsigned @OriginalName("__le32") int s_checkinterval;

    public @Unsigned @OriginalName("__le32") int s_creator_os;

    public @Unsigned @OriginalName("__le32") int s_rev_level;

    public @Unsigned @OriginalName("__le16") short s_def_resuid;

    public @Unsigned @OriginalName("__le16") short s_def_resgid;

    public @Unsigned @OriginalName("__le32") int s_first_ino;

    public @Unsigned @OriginalName("__le16") short s_inode_size;

    public @Unsigned @OriginalName("__le16") short s_block_group_nr;

    public @Unsigned @OriginalName("__le32") int s_feature_compat;

    public @Unsigned @OriginalName("__le32") int s_feature_incompat;

    public @Unsigned @OriginalName("__le32") int s_feature_ro_compat;

    public char @Size(16) [] s_uuid;

    public char @Size(16) [] s_volume_name;

    public char @Size(64) [] s_last_mounted;

    public @Unsigned @OriginalName("__le32") int s_algorithm_usage_bitmap;

    public char s_prealloc_blocks;

    public char s_prealloc_dir_blocks;

    public @Unsigned @OriginalName("__le16") short s_reserved_gdt_blocks;

    public char @Size(16) [] s_journal_uuid;

    public @Unsigned @OriginalName("__le32") int s_journal_inum;

    public @Unsigned @OriginalName("__le32") int s_journal_dev;

    public @Unsigned @OriginalName("__le32") int s_last_orphan;

    public @Unsigned @OriginalName("__le32") int @Size(4) [] s_hash_seed;

    public char s_def_hash_version;

    public char s_jnl_backup_type;

    public @Unsigned @OriginalName("__le16") short s_desc_size;

    public @Unsigned @OriginalName("__le32") int s_default_mount_opts;

    public @Unsigned @OriginalName("__le32") int s_first_meta_bg;

    public @Unsigned @OriginalName("__le32") int s_mkfs_time;

    public @Unsigned @OriginalName("__le32") int @Size(17) [] s_jnl_blocks;

    public @Unsigned @OriginalName("__le32") int s_blocks_count_hi;

    public @Unsigned @OriginalName("__le32") int s_r_blocks_count_hi;

    public @Unsigned @OriginalName("__le32") int s_free_blocks_count_hi;

    public @Unsigned @OriginalName("__le16") short s_min_extra_isize;

    public @Unsigned @OriginalName("__le16") short s_want_extra_isize;

    public @Unsigned @OriginalName("__le32") int s_flags;

    public @Unsigned @OriginalName("__le16") short s_raid_stride;

    public @Unsigned @OriginalName("__le16") short s_mmp_update_interval;

    public @Unsigned @OriginalName("__le64") long s_mmp_block;

    public @Unsigned @OriginalName("__le32") int s_raid_stripe_width;

    public char s_log_groups_per_flex;

    public char s_checksum_type;

    public char s_encryption_level;

    public char s_reserved_pad;

    public @Unsigned @OriginalName("__le64") long s_kbytes_written;

    public @Unsigned @OriginalName("__le32") int s_snapshot_inum;

    public @Unsigned @OriginalName("__le32") int s_snapshot_id;

    public @Unsigned @OriginalName("__le64") long s_snapshot_r_blocks_count;

    public @Unsigned @OriginalName("__le32") int s_snapshot_list;

    public @Unsigned @OriginalName("__le32") int s_error_count;

    public @Unsigned @OriginalName("__le32") int s_first_error_time;

    public @Unsigned @OriginalName("__le32") int s_first_error_ino;

    public @Unsigned @OriginalName("__le64") long s_first_error_block;

    public char @Size(32) [] s_first_error_func;

    public @Unsigned @OriginalName("__le32") int s_first_error_line;

    public @Unsigned @OriginalName("__le32") int s_last_error_time;

    public @Unsigned @OriginalName("__le32") int s_last_error_ino;

    public @Unsigned @OriginalName("__le32") int s_last_error_line;

    public @Unsigned @OriginalName("__le64") long s_last_error_block;

    public char @Size(32) [] s_last_error_func;

    public char @Size(64) [] s_mount_opts;

    public @Unsigned @OriginalName("__le32") int s_usr_quota_inum;

    public @Unsigned @OriginalName("__le32") int s_grp_quota_inum;

    public @Unsigned @OriginalName("__le32") int s_overhead_clusters;

    public @Unsigned @OriginalName("__le32") int @Size(2) [] s_backup_bgs;

    public char @Size(4) [] s_encrypt_algos;

    public char @Size(16) [] s_encrypt_pw_salt;

    public @Unsigned @OriginalName("__le32") int s_lpf_ino;

    public @Unsigned @OriginalName("__le32") int s_prj_quota_inum;

    public @Unsigned @OriginalName("__le32") int s_checksum_seed;

    public char s_wtime_hi;

    public char s_mtime_hi;

    public char s_mkfs_time_hi;

    public char s_lastcheck_hi;

    public char s_first_error_time_hi;

    public char s_last_error_time_hi;

    public char s_first_error_errcode;

    public char s_last_error_errcode;

    public @Unsigned @OriginalName("__le16") short s_encoding;

    public @Unsigned @OriginalName("__le16") short s_encoding_flags;

    public @Unsigned @OriginalName("__le32") int s_orphan_file_inum;

    public @Unsigned @OriginalName("__le32") int @Size(94) [] s_reserved;

    public @Unsigned @OriginalName("__le32") int s_checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_journal_trigger"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_journal_trigger extends Struct {
    public jbd2_buffer_trigger_type tr_triggers;

    public Ptr<super_block> sb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_orphan_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_orphan_block extends Struct {
    public atomic_t ob_free_entries;

    public Ptr<buffer_head> ob_bh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_orphan_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_orphan_info extends Struct {
    public int of_blocks;

    public @Unsigned int of_csum_seed;

    public Ptr<ext4_orphan_block> of_binfo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_sb_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_sb_info extends Struct {
    public @Unsigned long s_desc_size;

    public @Unsigned long s_inodes_per_block;

    public @Unsigned long s_blocks_per_group;

    public @Unsigned long s_clusters_per_group;

    public @Unsigned long s_inodes_per_group;

    public @Unsigned long s_itb_per_group;

    public @Unsigned long s_gdb_count;

    public @Unsigned long s_desc_per_block;

    public @Unsigned @OriginalName("ext4_group_t") int s_groups_count;

    public @Unsigned @OriginalName("ext4_group_t") int s_blockfile_groups;

    public @Unsigned long s_overhead;

    public @Unsigned int s_cluster_ratio;

    public @Unsigned int s_cluster_bits;

    public @OriginalName("loff_t") long s_bitmap_maxbytes;

    public Ptr<buffer_head> s_sbh;

    public Ptr<ext4_super_block> s_es;

    public Ptr<Ptr<buffer_head>> s_group_desc;

    public @Unsigned int s_mount_opt;

    public @Unsigned int s_mount_opt2;

    public @Unsigned long s_mount_flags;

    public @Unsigned int s_def_mount_opt;

    public @Unsigned int s_def_mount_opt2;

    public @Unsigned @OriginalName("ext4_fsblk_t") long s_sb_block;

    public atomic64_t s_resv_clusters;

    public kuid_t s_resuid;

    public kgid_t s_resgid;

    public @Unsigned short s_mount_state;

    public @Unsigned short s_pad;

    public int s_addr_per_block_bits;

    public int s_desc_per_block_bits;

    public int s_inode_size;

    public int s_first_ino;

    public @Unsigned int s_inode_readahead_blks;

    public @Unsigned int s_inode_goal;

    public @Unsigned int @Size(4) [] s_hash_seed;

    public int s_def_hash_version;

    public int s_hash_unsigned;

    public percpu_counter s_freeclusters_counter;

    public percpu_counter s_freeinodes_counter;

    public percpu_counter s_dirs_counter;

    public percpu_counter s_dirtyclusters_counter;

    public percpu_counter s_sra_exceeded_retry_limit;

    public Ptr<blockgroup_lock> s_blockgroup_lock;

    public Ptr<proc_dir_entry> s_proc;

    public kobject s_kobj;

    public completion s_kobj_unregister;

    public Ptr<super_block> s_sb;

    public Ptr<buffer_head> s_mmp_bh;

    public Ptr<journal_s> s_journal;

    public @Unsigned long s_ext4_flags;

    public mutex s_orphan_lock;

    public list_head s_orphan;

    public ext4_orphan_info s_orphan_info;

    public @Unsigned long s_commit_interval;

    public @Unsigned int s_max_batch_time;

    public @Unsigned int s_min_batch_time;

    public Ptr<file> s_journal_bdev_file;

    public String @Size(3) [] s_qf_names;

    public int s_jquota_fmt;

    public @Unsigned int s_want_extra_isize;

    public Ptr<ext4_system_blocks> s_system_blks;

    public Ptr<Ptr<Ptr<ext4_group_info>>> s_group_info;

    public Ptr<inode> s_buddy_cache;

    public @OriginalName("spinlock_t") spinlock s_md_lock;

    public Ptr<java.lang. @Unsigned Short> s_mb_offsets;

    public Ptr<java.lang. @Unsigned Integer> s_mb_maxs;

    public @Unsigned int s_group_info_size;

    public atomic_t s_mb_free_pending;

    public list_head @Size(2) [] s_freed_data_list;

    public list_head s_discard_list;

    public work_struct s_discard_work;

    public atomic_t s_retry_alloc_pending;

    public Ptr<xarray> s_mb_avg_fragment_size;

    public Ptr<xarray> s_mb_largest_free_orders;

    public @Unsigned long s_stripe;

    public @Unsigned int s_mb_max_linear_groups;

    public @Unsigned int s_mb_stream_request;

    public @Unsigned int s_mb_max_to_scan;

    public @Unsigned int s_mb_min_to_scan;

    public @Unsigned int s_mb_stats;

    public @Unsigned int s_mb_order2_reqs;

    public @Unsigned int s_mb_group_prealloc;

    public @Unsigned int s_max_dir_size_kb;

    public @Unsigned int s_mb_prefetch;

    public @Unsigned int s_mb_prefetch_limit;

    public @Unsigned int s_mb_best_avail_max_trim_order;

    public @Unsigned int s_sb_update_sec;

    public @Unsigned int s_sb_update_kb;

    public Ptr<java.lang. @Unsigned @OriginalName("ext4_group_t") Integer> s_mb_last_groups;

    public @Unsigned int s_mb_nr_global_goals;

    public atomic_t s_bal_reqs;

    public atomic_t s_bal_success;

    public atomic_t s_bal_allocated;

    public atomic_t s_bal_ex_scanned;

    public atomic_t @Size(5) [] s_bal_cX_ex_scanned;

    public atomic_t s_bal_groups_scanned;

    public atomic_t s_bal_goals;

    public atomic_t s_bal_stream_goals;

    public atomic_t s_bal_len_goals;

    public atomic_t s_bal_breaks;

    public atomic_t s_bal_2orders;

    public atomic64_t @Size(5) [] s_bal_cX_groups_considered;

    public atomic64_t @Size(5) [] s_bal_cX_hits;

    public atomic64_t @Size(5) [] s_bal_cX_failed;

    public atomic_t s_mb_buddies_generated;

    public atomic64_t s_mb_generation_time;

    public atomic_t s_mb_lost_chunks;

    public atomic_t s_mb_preallocated;

    public atomic_t s_mb_discarded;

    public atomic_t s_lock_busy;

    public Ptr<ext4_locality_group> s_locality_groups;

    public @Unsigned long s_sectors_written_start;

    public @Unsigned long s_kbytes_written;

    public @Unsigned int s_extent_max_zeroout_kb;

    public @Unsigned int s_log_groups_per_flex;

    public Ptr<Ptr<flex_groups>> s_flex_groups;

    public @Unsigned @OriginalName("ext4_group_t") int s_flex_groups_allocated;

    public Ptr<workqueue_struct> rsv_conversion_wq;

    public timer_list s_err_report;

    public Ptr<ext4_li_request> s_li_request;

    public @Unsigned int s_li_wait_mult;

    public Ptr<task_struct> s_mmp_tsk;

    public @Unsigned long s_last_trim_minblks;

    public @Unsigned int s_csum_seed;

    public Ptr<shrinker> s_es_shrinker;

    public list_head s_es_list;

    public long s_es_nr_inode;

    public ext4_es_stats s_es_stats;

    public Ptr<mb_cache> s_ea_block_cache;

    public Ptr<mb_cache> s_ea_inode_cache;

    public @OriginalName("spinlock_t") spinlock s_es_lock;

    public ext4_journal_trigger @Size(1) [] s_journal_triggers;

    public ratelimit_state s_err_ratelimit_state;

    public ratelimit_state s_warning_ratelimit_state;

    public ratelimit_state s_msg_ratelimit_state;

    public atomic_t s_warning_count;

    public atomic_t s_msg_count;

    public fscrypt_dummy_policy s_dummy_enc_policy;

    public percpu_rw_semaphore s_writepages_rwsem;

    public Ptr<dax_device> s_daxdev;

    public @Unsigned long s_dax_part_off;

    public @Unsigned @OriginalName("errseq_t") int s_bdev_wb_err;

    public @OriginalName("spinlock_t") spinlock s_bdev_wb_lock;

    public @OriginalName("spinlock_t") spinlock s_error_lock;

    public int s_add_error_count;

    public int s_first_error_code;

    public @Unsigned int s_first_error_line;

    public @Unsigned int s_first_error_ino;

    public @Unsigned long s_first_error_block;

    public String s_first_error_func;

    public @OriginalName("time64_t") long s_first_error_time;

    public int s_last_error_code;

    public @Unsigned int s_last_error_line;

    public @Unsigned int s_last_error_ino;

    public @Unsigned long s_last_error_block;

    public String s_last_error_func;

    public @OriginalName("time64_t") long s_last_error_time;

    public work_struct s_sb_upd_work;

    public @Unsigned int s_awu_min;

    public @Unsigned int s_awu_max;

    public atomic_t s_fc_subtid;

    public list_head @Size(2) [] s_fc_q;

    public list_head @Size(2) [] s_fc_dentry_q;

    public @Unsigned int s_fc_bytes;

    public mutex s_fc_lock;

    public Ptr<buffer_head> s_fc_bh;

    public ext4_fc_stats s_fc_stats;

    public @Unsigned @OriginalName("tid_t") int s_fc_ineligible_tid;

    public ext4_fc_replay_state s_fc_replay_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_group_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_group_info extends Struct {
    public @Unsigned long bb_state;

    public rb_root bb_free_root;

    public @OriginalName("ext4_grpblk_t") int bb_first_free;

    public @OriginalName("ext4_grpblk_t") int bb_free;

    public @OriginalName("ext4_grpblk_t") int bb_fragments;

    public int bb_avg_fragment_size_order;

    public @OriginalName("ext4_grpblk_t") int bb_largest_free_order;

    public @Unsigned @OriginalName("ext4_group_t") int bb_group;

    public list_head bb_prealloc_list;

    public rw_semaphore alloc_sem;

    public @OriginalName("ext4_grpblk_t") int @Size(0) [] bb_counters;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_locality_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_locality_group extends Struct {
    public mutex lg_mutex;

    public list_head @Size(10) [] lg_prealloc_list;

    public @OriginalName("spinlock_t") spinlock lg_prealloc_lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_li_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_li_request extends Struct {
    public Ptr<super_block> lr_super;

    public ext4_li_mode lr_mode;

    public @Unsigned @OriginalName("ext4_group_t") int lr_first_not_zeroed;

    public @Unsigned @OriginalName("ext4_group_t") int lr_next_group;

    public list_head lr_request;

    public @Unsigned long lr_next_sched;

    public @Unsigned long lr_timeout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ext4_li_mode"
  )
  public enum ext4_li_mode implements Enum<ext4_li_mode>, TypedEnum<ext4_li_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code EXT4_LI_MODE_PREFETCH_BBITMAP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "EXT4_LI_MODE_PREFETCH_BBITMAP"
    )
    EXT4_LI_MODE_PREFETCH_BBITMAP,

    /**
     * {@code EXT4_LI_MODE_ITABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "EXT4_LI_MODE_ITABLE"
    )
    EXT4_LI_MODE_ITABLE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_map_blocks"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_map_blocks extends Struct {
    public @Unsigned @OriginalName("ext4_fsblk_t") long m_pblk;

    public @Unsigned @OriginalName("ext4_lblk_t") int m_lblk;

    public @Unsigned int m_len;

    public @Unsigned int m_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_system_zone"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_system_zone extends Struct {
    public rb_node node;

    public @Unsigned @OriginalName("ext4_fsblk_t") long start_blk;

    public @Unsigned int count;

    public @Unsigned int ino;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ext4_journal_trigger_type"
  )
  public enum ext4_journal_trigger_type implements Enum<ext4_journal_trigger_type>, TypedEnum<ext4_journal_trigger_type, java.lang. @Unsigned Integer> {
    /**
     * {@code EXT4_JTR_ORPHAN_FILE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "EXT4_JTR_ORPHAN_FILE"
    )
    EXT4_JTR_ORPHAN_FILE,

    /**
     * {@code EXT4_JTR_NONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "EXT4_JTR_NONE"
    )
    EXT4_JTR_NONE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_dir_entry_hash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_dir_entry_hash extends Struct {
    public @Unsigned @OriginalName("__le32") int hash;

    public @Unsigned @OriginalName("__le32") int minor_hash;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_dir_entry_2"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_dir_entry_2 extends Struct {
    public @Unsigned @OriginalName("__le32") int inode;

    public @Unsigned @OriginalName("__le16") short rec_len;

    public char name_len;

    public char file_type;

    public char @Size(255) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_io_end_vec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_io_end_vec extends Struct {
    public list_head list;

    public @OriginalName("loff_t") long offset;

    public @OriginalName("ssize_t") long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_io_end"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_io_end extends Struct {
    public list_head list;

    public Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle;

    public Ptr<inode> inode;

    public Ptr<bio> bio;

    public @Unsigned int flag;

    public @OriginalName("refcount_t") refcount_struct count;

    public list_head list_vec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_iloc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_iloc extends Struct {
    public Ptr<buffer_head> bh;

    public @Unsigned long offset;

    public @Unsigned @OriginalName("ext4_group_t") int block_group;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_extent_tail"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_extent_tail extends Struct {
    public @Unsigned @OriginalName("__le32") int et_checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_extent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_extent extends Struct {
    public @Unsigned @OriginalName("__le32") int ee_block;

    public @Unsigned @OriginalName("__le16") short ee_len;

    public @Unsigned @OriginalName("__le16") short ee_start_hi;

    public @Unsigned @OriginalName("__le32") int ee_start_lo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_extent_idx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_extent_idx extends Struct {
    public @Unsigned @OriginalName("__le32") int ei_block;

    public @Unsigned @OriginalName("__le32") int ei_leaf_lo;

    public @Unsigned @OriginalName("__le16") short ei_leaf_hi;

    public @Unsigned short ei_unused;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_extent_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_extent_header extends Struct {
    public @Unsigned @OriginalName("__le16") short eh_magic;

    public @Unsigned @OriginalName("__le16") short eh_entries;

    public @Unsigned @OriginalName("__le16") short eh_max;

    public @Unsigned @OriginalName("__le16") short eh_depth;

    public @Unsigned @OriginalName("__le32") int eh_generation;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_ext_path"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_ext_path extends Struct {
    public @Unsigned @OriginalName("ext4_fsblk_t") long p_block;

    public @Unsigned short p_depth;

    public @Unsigned short p_maxdepth;

    public Ptr<ext4_extent> p_ext;

    public Ptr<ext4_extent_idx> p_idx;

    public Ptr<ext4_extent_header> p_hdr;

    public Ptr<buffer_head> p_bh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fsmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fsmap extends Struct {
    public list_head fmr_list;

    public @Unsigned @OriginalName("dev_t") int fmr_device;

    public @Unsigned @OriginalName("uint32_t") int fmr_flags;

    public @Unsigned @OriginalName("uint64_t") long fmr_physical;

    public @Unsigned @OriginalName("uint64_t") long fmr_owner;

    public @Unsigned @OriginalName("uint64_t") long fmr_length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fsmap_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fsmap_head extends Struct {
    public @Unsigned @OriginalName("uint32_t") int fmh_iflags;

    public @Unsigned @OriginalName("uint32_t") int fmh_oflags;

    public @Unsigned int fmh_count;

    public @Unsigned int fmh_entries;

    public ext4_fsmap @Size(2) [] fmh_keys;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_getfsmap_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_getfsmap_info extends Struct {
    public Ptr<ext4_fsmap_head> gfi_head;

    public @OriginalName("ext4_fsmap_format_t") Ptr<?> gfi_formatter;

    public Ptr<?> gfi_format_arg;

    public @Unsigned @OriginalName("ext4_fsblk_t") long gfi_next_fsblk;

    public @Unsigned int gfi_dev;

    public @Unsigned @OriginalName("ext4_group_t") int gfi_agno;

    public ext4_fsmap gfi_low;

    public ext4_fsmap gfi_high;

    public ext4_fsmap gfi_lastfree;

    public list_head gfi_meta_list;

    public boolean gfi_last;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_getfsmap_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_getfsmap_dev extends Struct {
    public Ptr<?> gfd_fn;

    public @Unsigned int gfd_dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_inode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_inode extends Struct {
    public @Unsigned @OriginalName("__le16") short i_mode;

    public @Unsigned @OriginalName("__le16") short i_uid;

    public @Unsigned @OriginalName("__le32") int i_size_lo;

    public @Unsigned @OriginalName("__le32") int i_atime;

    public @Unsigned @OriginalName("__le32") int i_ctime;

    public @Unsigned @OriginalName("__le32") int i_mtime;

    public @Unsigned @OriginalName("__le32") int i_dtime;

    public @Unsigned @OriginalName("__le16") short i_gid;

    public @Unsigned @OriginalName("__le16") short i_links_count;

    public @Unsigned @OriginalName("__le32") int i_blocks_lo;

    public @Unsigned @OriginalName("__le32") int i_flags;

    public osd1_of_ext4_inode osd1;

    public @Unsigned @OriginalName("__le32") int @Size(15) [] i_block;

    public @Unsigned @OriginalName("__le32") int i_generation;

    public @Unsigned @OriginalName("__le32") int i_file_acl_lo;

    public @Unsigned @OriginalName("__le32") int i_size_high;

    public @Unsigned @OriginalName("__le32") int i_obso_faddr;

    public osd2_of_ext4_inode osd2;

    public @Unsigned @OriginalName("__le16") short i_extra_isize;

    public @Unsigned @OriginalName("__le16") short i_checksum_hi;

    public @Unsigned @OriginalName("__le32") int i_ctime_extra;

    public @Unsigned @OriginalName("__le32") int i_mtime_extra;

    public @Unsigned @OriginalName("__le32") int i_atime_extra;

    public @Unsigned @OriginalName("__le32") int i_crtime;

    public @Unsigned @OriginalName("__le32") int i_crtime_extra;

    public @Unsigned @OriginalName("__le32") int i_version_hi;

    public @Unsigned @OriginalName("__le32") int i_projid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_filename"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_filename extends Struct {
    public Ptr<qstr> usr_fname;

    public fscrypt_str disk_name;

    public dx_hash_info hinfo;

    public fscrypt_str crypto_buf;

    public qstr cf_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_ibody_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_ibody_header extends Struct {
    public @Unsigned @OriginalName("__le32") int h_magic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_entry extends Struct {
    public char e_name_len;

    public char e_name_index;

    public @Unsigned @OriginalName("__le16") short e_value_offs;

    public @Unsigned @OriginalName("__le32") int e_value_inum;

    public @Unsigned @OriginalName("__le32") int e_value_size;

    public @Unsigned @OriginalName("__le32") int e_hash;

    public char @Size(0) [] e_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_info extends Struct {
    public String name;

    public Ptr<?> value;

    public @Unsigned long value_len;

    public int name_index;

    public int in_inode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_search"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_search extends Struct {
    public Ptr<ext4_xattr_entry> first;

    public Ptr<?> base;

    public Ptr<?> end;

    public Ptr<ext4_xattr_entry> here;

    public int not_found;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_ibody_find"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_ibody_find extends Struct {
    public ext4_xattr_search s;

    public ext4_iloc iloc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_io_submit"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_io_submit extends Struct {
    public Ptr<writeback_control> io_wbc;

    public Ptr<bio> io_bio;

    public Ptr<@OriginalName("ext4_io_end_t") ext4_io_end> io_end;

    public @Unsigned @OriginalName("sector_t") long io_next_block;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_inode_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_inode_array extends Struct {
    public @Unsigned int count;

    public Ptr<inode> @Size(0) [] inodes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_new_group_input"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_new_group_input extends Struct {
    public @Unsigned int group;

    public @Unsigned long block_bitmap;

    public @Unsigned long inode_bitmap;

    public @Unsigned long inode_table;

    public @Unsigned int blocks_count;

    public @Unsigned short reserved_blocks;

    public @Unsigned short unused;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_new_group_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_new_group_data extends Struct {
    public @Unsigned int group;

    public @Unsigned long block_bitmap;

    public @Unsigned long inode_bitmap;

    public @Unsigned long inode_table;

    public @Unsigned int blocks_count;

    public @Unsigned short reserved_blocks;

    public @Unsigned short mdata_blocks;

    public @Unsigned int free_clusters_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_free_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_free_data extends Struct {
    public list_head efd_list;

    public rb_node efd_node;

    public @Unsigned @OriginalName("ext4_group_t") int efd_group;

    public @OriginalName("ext4_grpblk_t") int efd_start_cluster;

    public @OriginalName("ext4_grpblk_t") int efd_count;

    public @Unsigned @OriginalName("tid_t") int efd_tid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_prealloc_space"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_prealloc_space extends Struct {
    public pa_node_of_ext4_prealloc_space pa_node;

    public list_head pa_group_list;

    public u_of_ext4_prealloc_space u;

    public @OriginalName("spinlock_t") spinlock pa_lock;

    public atomic_t pa_count;

    public @Unsigned int pa_deleted;

    public @Unsigned @OriginalName("ext4_fsblk_t") long pa_pstart;

    public @Unsigned @OriginalName("ext4_lblk_t") int pa_lstart;

    public @OriginalName("ext4_grpblk_t") int pa_len;

    public @OriginalName("ext4_grpblk_t") int pa_free;

    public @Unsigned short pa_type;

    public pa_node_lock_of_ext4_prealloc_space pa_node_lock;

    public Ptr<inode> pa_inode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_free_extent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_free_extent extends Struct {
    public @Unsigned @OriginalName("ext4_lblk_t") int fe_logical;

    public @OriginalName("ext4_grpblk_t") int fe_start;

    public @Unsigned @OriginalName("ext4_group_t") int fe_group;

    public @OriginalName("ext4_grpblk_t") int fe_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_allocation_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_allocation_context extends Struct {
    public Ptr<inode> ac_inode;

    public Ptr<super_block> ac_sb;

    public ext4_free_extent ac_o_ex;

    public ext4_free_extent ac_g_ex;

    public ext4_free_extent ac_b_ex;

    public ext4_free_extent ac_f_ex;

    public @OriginalName("ext4_grpblk_t") int ac_orig_goal_len;

    public @Unsigned @OriginalName("ext4_group_t") int ac_prefetch_grp;

    public @Unsigned int ac_prefetch_ios;

    public @Unsigned int ac_prefetch_nr;

    public int ac_first_err;

    public @Unsigned int ac_flags;

    public @Unsigned short ac_groups_scanned;

    public @Unsigned short ac_found;

    public @Unsigned short @Size(5) [] ac_cX_found;

    public @Unsigned short ac_tail;

    public @Unsigned short ac_buddy;

    public char ac_status;

    public char ac_criteria;

    public char ac_2order;

    public char ac_op;

    public Ptr<ext4_buddy> ac_e4b;

    public Ptr<folio> ac_bitmap_folio;

    public Ptr<folio> ac_buddy_folio;

    public Ptr<ext4_prealloc_space> ac_pa;

    public Ptr<ext4_locality_group> ac_lg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_buddy"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_buddy extends Struct {
    public Ptr<folio> bd_buddy_folio;

    public Ptr<?> bd_buddy;

    public Ptr<folio> bd_bitmap_folio;

    public Ptr<?> bd_bitmap;

    public Ptr<ext4_group_info> bd_info;

    public Ptr<super_block> bd_sb;

    public @Unsigned short bd_blkbits;

    public @Unsigned @OriginalName("ext4_group_t") int bd_group;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_dir_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_dir_entry extends Struct {
    public @Unsigned @OriginalName("__le32") int inode;

    public @Unsigned @OriginalName("__le16") short rec_len;

    public @Unsigned @OriginalName("__le16") short name_len;

    public char @Size(255) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_dir_entry_tail"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_dir_entry_tail extends Struct {
    public @Unsigned @OriginalName("__le32") int det_reserved_zero1;

    public @Unsigned @OriginalName("__le16") short det_rec_len;

    public char det_reserved_zero2;

    public char det_reserved_ft;

    public @Unsigned @OriginalName("__le32") int det_checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_renament"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_renament extends Struct {
    public Ptr<inode> dir;

    public Ptr<dentry> dentry;

    public Ptr<inode> inode;

    public boolean is_dir;

    public int dir_nlink_delta;

    public Ptr<buffer_head> bh;

    public Ptr<ext4_dir_entry_2> de;

    public int inlined;

    public Ptr<buffer_head> dir_bh;

    public Ptr<ext4_dir_entry_2> parent_de;

    public int dir_inlined;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_rcu_ptr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_rcu_ptr extends Struct {
    public callback_head rcu;

    public Ptr<?> ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_new_flex_group_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_new_flex_group_data extends Struct {
    public Ptr<ext4_new_group_data> groups;

    public Ptr<java.lang. @Unsigned Short> bg_flags;

    public @Unsigned @OriginalName("ext4_group_t") int resize_bg;

    public @Unsigned @OriginalName("ext4_group_t") int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_lazy_init"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_lazy_init extends Struct {
    public @Unsigned long li_state;

    public list_head li_request_list;

    public mutex li_list_mtx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_err_translation"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_err_translation extends Struct {
    public int code;

    public int errno;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_sb_encodings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_sb_encodings extends Struct {
    public @Unsigned short magic;

    public String name;

    public @Unsigned int version;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fs_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fs_context extends Struct {
    public String @Size(3) [] s_qf_names;

    public fscrypt_dummy_policy dummy_enc_policy;

    public int s_jquota_fmt;

    public @Unsigned short qname_spec;

    public @Unsigned long vals_s_flags;

    public @Unsigned long mask_s_flags;

    public @Unsigned long journal_devnum;

    public @Unsigned long s_commit_interval;

    public @Unsigned long s_stripe;

    public @Unsigned int s_inode_readahead_blks;

    public @Unsigned int s_want_extra_isize;

    public @Unsigned int s_li_wait_mult;

    public @Unsigned int s_max_dir_size_kb;

    public @Unsigned int journal_ioprio;

    public @Unsigned int vals_s_mount_opt;

    public @Unsigned int mask_s_mount_opt;

    public @Unsigned int vals_s_mount_opt2;

    public @Unsigned int mask_s_mount_opt2;

    public @Unsigned int opt_flags;

    public @Unsigned int spec;

    public @Unsigned int s_max_batch_time;

    public @Unsigned int s_min_batch_time;

    public kuid_t s_resuid;

    public kgid_t s_resgid;

    public @Unsigned @OriginalName("ext4_fsblk_t") long s_sb_block;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_mount_options"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_mount_options extends Struct {
    public @Unsigned long s_mount_opt;

    public @Unsigned long s_mount_opt2;

    public kuid_t s_resuid;

    public kgid_t s_resgid;

    public @Unsigned long s_commit_interval;

    public @Unsigned int s_min_batch_time;

    public @Unsigned int s_max_batch_time;

    public int s_jquota_fmt;

    public String @Size(3) [] s_qf_names;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_attr extends Struct {
    public attribute attr;

    public short attr_id;

    public short attr_ptr;

    public @Unsigned short attr_size;

    public u_of_ext4_attr u;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_header extends Struct {
    public @Unsigned @OriginalName("__le32") int h_magic;

    public @Unsigned @OriginalName("__le32") int h_refcount;

    public @Unsigned @OriginalName("__le32") int h_blocks;

    public @Unsigned @OriginalName("__le32") int h_hash;

    public @Unsigned @OriginalName("__le32") int h_checksum;

    public @Unsigned int @Size(3) [] h_reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_xattr_block_find"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_xattr_block_find extends Struct {
    public ext4_xattr_search s;

    public Ptr<buffer_head> bh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_tl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_tl extends Struct {
    public @Unsigned @OriginalName("__le16") short fc_tag;

    public @Unsigned @OriginalName("__le16") short fc_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_head extends Struct {
    public @Unsigned @OriginalName("__le32") int fc_features;

    public @Unsigned @OriginalName("__le32") int fc_tid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_add_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_add_range extends Struct {
    public @Unsigned @OriginalName("__le32") int fc_ino;

    public char @Size(12) [] fc_ex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_del_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_del_range extends Struct {
    public @Unsigned @OriginalName("__le32") int fc_ino;

    public @Unsigned @OriginalName("__le32") int fc_lblk;

    public @Unsigned @OriginalName("__le32") int fc_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_dentry_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_dentry_info extends Struct {
    public @Unsigned @OriginalName("__le32") int fc_parent_ino;

    public @Unsigned @OriginalName("__le32") int fc_ino;

    public char @Size(0) [] fc_dname;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_inode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_inode extends Struct {
    public @Unsigned @OriginalName("__le32") int fc_ino;

    public char @Size(0) [] fc_raw_inode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_tail"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_tail extends Struct {
    public @Unsigned @OriginalName("__le32") int fc_tid;

    public @Unsigned @OriginalName("__le32") int fc_crc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_dentry_update"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_dentry_update extends Struct {
    public int fcd_op;

    public int fcd_parent;

    public int fcd_ino;

    public name_snapshot fcd_name;

    public list_head fcd_list;

    public list_head fcd_dilist;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_fc_tl_mem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_fc_tl_mem extends Struct {
    public @Unsigned short fc_tag;

    public @Unsigned short fc_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ext4_orphan_block_tail"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_orphan_block_tail extends Struct {
    public @Unsigned @OriginalName("__le32") int ob_magic;

    public @Unsigned @OriginalName("__le32") int ob_checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int e_tag; short unsigned int e_perm; unsigned int e_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_acl_entry extends Struct {
    public @Unsigned @OriginalName("__le16") short e_tag;

    public @Unsigned @OriginalName("__le16") short e_perm;

    public @Unsigned @OriginalName("__le32") int e_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int a_version; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ext4_acl_header extends Struct {
    public @Unsigned @OriginalName("__le32") int a_version;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum passtype"
  )
  public enum passtype implements Enum<passtype>, TypedEnum<passtype, java.lang. @Unsigned Integer> {
    /**
     * {@code PASS_SCAN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PASS_SCAN"
    )
    PASS_SCAN,

    /**
     * {@code PASS_REVOKE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PASS_REVOKE"
    )
    PASS_REVOKE,

    /**
     * {@code PASS_REPLAY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PASS_REPLAY"
    )
    PASS_REPLAY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum criteria"
  )
  public enum criteria implements Enum<criteria>, TypedEnum<criteria, java.lang. @Unsigned Integer> {
    /**
     * {@code CR_POWER2_ALIGNED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "CR_POWER2_ALIGNED"
    )
    CR_POWER2_ALIGNED,

    /**
     * {@code CR_GOAL_LEN_FAST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "CR_GOAL_LEN_FAST"
    )
    CR_GOAL_LEN_FAST,

    /**
     * {@code CR_BEST_AVAIL_LEN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "CR_BEST_AVAIL_LEN"
    )
    CR_BEST_AVAIL_LEN,

    /**
     * {@code CR_GOAL_LEN_SLOW = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CR_GOAL_LEN_SLOW"
    )
    CR_GOAL_LEN_SLOW,

    /**
     * {@code CR_ANY_FREE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "CR_ANY_FREE"
    )
    CR_ANY_FREE,

    /**
     * {@code EXT4_MB_NUM_CRS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "EXT4_MB_NUM_CRS"
    )
    EXT4_MB_NUM_CRS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fsuuid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fsuuid extends Struct {
    public @Unsigned int fsu_len;

    public @Unsigned int fsu_flags;

    public char @Size(0) [] fsu_uuid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum SHIFT_DIRECTION"
  )
  public enum SHIFT_DIRECTION implements Enum<SHIFT_DIRECTION>, TypedEnum<SHIFT_DIRECTION, java.lang. @Unsigned Integer> {
    /**
     * {@code SHIFT_LEFT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SHIFT_LEFT"
    )
    SHIFT_LEFT,

    /**
     * {@code SHIFT_RIGHT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SHIFT_RIGHT"
    )
    SHIFT_RIGHT
  }
}
