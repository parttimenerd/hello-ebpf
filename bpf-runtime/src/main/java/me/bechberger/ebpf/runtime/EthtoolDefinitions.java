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
 * Generated class for BPF runtime types that start with ethtool
 */
@java.lang.SuppressWarnings("unused")
public final class EthtoolDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ethtool_cmis_cdb_execute_cmd(Ptr<net_device> dev,
      Ptr<ethtool_module_eeprom> page_data, char page, @Unsigned int offset, @Unsigned int length,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __ethtool_dev_mm_supported(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int __ethtool_get_flags(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ethtool_get_link(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ethtool_get_link_ksettings(Ptr<net_device> dev,
      Ptr<ethtool_link_ksettings> link_ksettings) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ethtool_get_sset_count(Ptr<net_device> dev, int sset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ethtool_get_strings(Ptr<net_device> dev, @Unsigned int stringset,
      Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ethtool_get_ts_info(Ptr<net_device> dev, Ptr<kernel_ethtool_ts_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ethtool_set_flags(Ptr<net_device> dev, @Unsigned int data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_aggregate_ctrl_stats(Ptr<net_device> dev,
      Ptr<ethtool_eth_ctrl_stats> ctrl_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_aggregate_mac_stats(Ptr<net_device> dev,
      Ptr<ethtool_eth_mac_stats> mac_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_aggregate_pause_stats(Ptr<net_device> dev,
      Ptr<ethtool_pause_stats> pause_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_aggregate_phy_stats(Ptr<net_device> dev,
      Ptr<ethtool_eth_phy_stats> phy_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_aggregate_rmon_stats(Ptr<net_device> dev,
      Ptr<ethtool_rmon_stats> rmon_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_check_max_channel(Ptr<net_device> dev, ethtool_channels channels,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_check_ops((const struct ethtool_ops*)$arg1)")
  public static int ethtool_check_ops(Ptr<ethtool_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_check_rss_ctx_busy(Ptr<net_device> dev, @Unsigned int rss_context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_cmis_cdb_check_completion_flag(char cmis_rev,
      Ptr<java.lang.Character> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_cmis_cdb_compose_args(Ptr<ethtool_cmis_cdb_cmd_args> args,
      ethtool_cmis_cdb_cmd_id cmd, Ptr<java.lang.Character> lpl, char lpl_len,
      Ptr<java.lang.Character> epl, @Unsigned short epl_len, @Unsigned short max_duration,
      char read_write_len_ext, @Unsigned short msleep_pre_rpl, char rpl_exp_len, char flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_cmis_cdb_execute_cmd(Ptr<net_device> dev,
      Ptr<ethtool_cmis_cdb_cmd_args> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_cmis_cdb_fini(Ptr<ethtool_cmis_cdb> cdb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_cmis_cdb_init($arg1, (const struct ethtool_module_fw_flash_params*)$arg2, $arg3)")
  public static Ptr<ethtool_cmis_cdb> ethtool_cmis_cdb_init(Ptr<net_device> dev,
      Ptr<ethtool_module_fw_flash_params> params,
      Ptr<ethnl_module_fw_flash_ntf_params> ntf_params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_cmis_fw_update(Ptr<ethtool_cmis_fw_update_params> fw_update) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ethtool_cmis_get_max_lpl_size(char num_of_byte_octs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_cmis_module_poll($arg1, $arg2, $arg3, (_Bool (*)(u8))$arg4, (_Bool (*)(u8))$arg5)")
  public static int ethtool_cmis_module_poll(Ptr<net_device> dev, Ptr<cmis_wait_for_cond_rpl> rpl,
      @Unsigned int offset, Ptr<?> cond_success, Ptr<?> cond_fail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_cmis_page_init(Ptr<ethtool_module_eeprom> page_data, char page,
      @Unsigned int offset, @Unsigned int length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_cmis_wait_for_cond($arg1, $arg2, $arg3, $arg4, $arg5, (_Bool (*)(u8))$arg6, (_Bool (*)(u8))$arg7, $arg8)")
  public static int ethtool_cmis_wait_for_cond(Ptr<net_device> dev, char flags, char flag,
      @Unsigned short max_duration, @Unsigned int offset, Ptr<?> cond_success, Ptr<?> cond_fail,
      Ptr<java.lang.Character> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_convert_legacy_u32_to_link_mode(Ptr<java.lang. @Unsigned Long> dst,
      @Unsigned int legacy_u32) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_convert_link_mode_to_legacy_u32($arg1, (const long unsigned int*)$arg2)")
  public static boolean ethtool_convert_link_mode_to_legacy_u32(
      Ptr<java.lang. @Unsigned Integer> legacy_u32, Ptr<java.lang. @Unsigned Long> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_copy_validate_indir(Ptr<java.lang. @Unsigned Integer> indir,
      Ptr<?> useraddr, Ptr<ethtool_rxnfc> rx_rings, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ethtool_dev_mm_supported(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_fec_to_link_modes(@Unsigned int fec,
      Ptr<java.lang. @Unsigned Long> link_modes, Ptr<java.lang.Character> fec_auto) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_forced_speed_maps_init(Ptr<ethtool_forced_speed_map> maps,
      @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_get_any_eeprom($arg1, $arg2, (int (*)(struct net_device*, struct ethtool_eeprom*, u8*))$arg3, $arg4)")
  public static int ethtool_get_any_eeprom(Ptr<net_device> dev, Ptr<?> useraddr, Ptr<?> getter,
      @Unsigned int total_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_channels(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_coalesce(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_drvinfo(Ptr<net_device> dev, Ptr<ethtool_devlink_compat> rsp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_dump_data(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_eee(Ptr<net_device> dev, String useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_link_ksettings(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ethtool_get_max_rxfh_channel(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_max_rxnfc_channel(Ptr<net_device> dev,
      Ptr<java.lang. @Unsigned Long> max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_module_eeprom_call(Ptr<net_device> dev, Ptr<ethtool_eeprom> ee,
      Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_module_info_call(Ptr<net_device> dev,
      Ptr<ethtool_modinfo> modinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_per_queue_coalesce(Ptr<net_device> dev, Ptr<?> useraddr,
      Ptr<ethtool_per_queue_op> per_queue_opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_phc_vclocks(Ptr<net_device> dev,
      Ptr<Ptr<java.lang.Integer>> vclock_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_phy_stats(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_regs(Ptr<net_device> dev, String useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_rxfh(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_rxfh_fields(Ptr<net_device> dev, @Unsigned int cmd,
      Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_rxfh_indir(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_rxnfc(Ptr<net_device> dev, @Unsigned int cmd, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_rxnfc_rule_count(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_settings(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_sset_info(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_stats(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_strings(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_ts_info_by_layer(Ptr<net_device> dev,
      Ptr<kernel_ethtool_ts_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_ts_info_by_phc(Ptr<net_device> dev,
      Ptr<kernel_ethtool_ts_info> info, Ptr<hwtstamp_provider_desc> hwprov_desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_get_tunable(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_init_tsinfo(Ptr<kernel_ethtool_ts_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_intersect_link_masks(Ptr<ethtool_link_ksettings> dst,
      Ptr<ethtool_link_ksettings> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_link_modes_to_fecparam(Ptr<ethtool_fecparam> fec,
      Ptr<java.lang. @Unsigned Long> link_modes, char fec_auto) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_mmsv_apply(Ptr<ethtool_mmsv> mmsv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_mmsv_event_handle(Ptr<ethtool_mmsv> mmsv, ethtool_mmsv_event event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_mmsv_get_mm(Ptr<ethtool_mmsv> mmsv, Ptr<ethtool_mm_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_mmsv_init($arg1, $arg2, (const struct ethtool_mmsv_ops*)$arg3)")
  public static void ethtool_mmsv_init(Ptr<ethtool_mmsv> mmsv, Ptr<net_device> dev,
      Ptr<ethtool_mmsv_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_mmsv_link_state_handle(Ptr<ethtool_mmsv> mmsv, boolean up) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_mmsv_set_mm(Ptr<ethtool_mmsv> mmsv, Ptr<ethtool_mm_cfg> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_mmsv_stop(Ptr<ethtool_mmsv> mmsv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_mmsv_verify_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_net_get_ts_info_by_phc(Ptr<net_device> dev,
      Ptr<kernel_ethtool_ts_info> info, Ptr<hwtstamp_provider_desc> hwprov_desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_notify(Ptr<net_device> dev, @Unsigned int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ethtool_op_get_link(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_op_get_ts_info(Ptr<net_device> dev, Ptr<kernel_ethtool_ts_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_params_from_link_mode(Ptr<ethtool_link_ksettings> link_ksettings,
      ethtool_link_mode_bit_indices link_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<phy_device> ethtool_phy_get_ts_info_by_phc(Ptr<net_device> dev,
      Ptr<kernel_ethtool_ts_info> info, Ptr<hwtstamp_provider_desc> hwprov_desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_phys_id(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_puts($arg1, (const u8*)$arg2)")
  public static void ethtool_puts(Ptr<Ptr<java.lang.Character>> data, String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_ringparam_get_cfg(Ptr<net_device> dev, Ptr<ethtool_ringparam> param,
      Ptr<kernel_ethtool_ringparam> kparam, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_rss_notify(Ptr<net_device> dev, @Unsigned int type,
      @Unsigned int rss_context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_rx_flow_rule_create((const struct ethtool_rx_flow_spec_input*)$arg1)")
  public static Ptr<ethtool_rx_flow_rule> ethtool_rx_flow_rule_create(
      Ptr<ethtool_rx_flow_spec_input> input) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_rx_flow_rule_destroy(Ptr<ethtool_rx_flow_rule> flow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_rxfh_config_is_sym(@Unsigned long rxfh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ethtool_rxfh_context_lost(Ptr<net_device> dev, @Unsigned int context_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_rxfh_ctx_alloc((const struct ethtool_ops*)$arg1, $arg2, $arg3)")
  public static Ptr<ethtool_rxfh_context> ethtool_rxfh_ctx_alloc(Ptr<ethtool_ops> ops,
      @Unsigned int indir_size, @Unsigned int key_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_rxnfc_copy_from_compat($arg1, (const struct compat_ethtool_rxnfc*)$arg2, $arg3)")
  public static int ethtool_rxnfc_copy_from_compat(Ptr<ethtool_rxnfc> rxnfc,
      Ptr<compat_ethtool_rxnfc> useraddr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_rxnfc_copy_from_user($arg1, (const void*)$arg2, $arg3)")
  public static int ethtool_rxnfc_copy_from_user(Ptr<ethtool_rxnfc> rxnfc, Ptr<?> useraddr,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_rxnfc_copy_struct(@Unsigned int cmd, Ptr<ethtool_rxnfc> info,
      Ptr<java.lang. @Unsigned Long> info_size, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_rxnfc_copy_to_compat($arg1, (const struct ethtool_rxnfc*)$arg2, $arg3, (const unsigned int*)$arg4)")
  public static int ethtool_rxnfc_copy_to_compat(Ptr<?> useraddr, Ptr<ethtool_rxnfc> rxnfc,
      @Unsigned long size, Ptr<java.lang. @Unsigned Integer> rule_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_rxnfc_copy_to_user($arg1, (const struct ethtool_rxnfc*)$arg2, $arg3, (const unsigned int*)$arg4)")
  public static int ethtool_rxnfc_copy_to_user(Ptr<?> useraddr, Ptr<ethtool_rxnfc> rxnfc,
      @Unsigned long size, Ptr<java.lang. @Unsigned Integer> rule_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_self_test(Ptr<net_device> dev, String useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_channels(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_coalesce(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ethtool_set_coalesce_supported(Ptr<net_device> dev,
      Ptr<ethtool_coalesce> coalesce) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_eee(Ptr<net_device> dev, String useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_eeprom(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_set_ethtool_phy_ops((const struct ethtool_phy_ops*)$arg1)")
  public static void ethtool_set_ethtool_phy_ops(Ptr<ethtool_phy_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_link_ksettings(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_per_queue(Ptr<net_device> dev, Ptr<?> useraddr,
      @Unsigned int sub_cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_per_queue_coalesce(Ptr<net_device> dev, Ptr<?> useraddr,
      Ptr<ethtool_per_queue_op> per_queue_opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_ringparam(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_rxfh(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_rxfh_fields(Ptr<net_device> dev, @Unsigned int cmd,
      Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_rxfh_indir(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_rxnfc(Ptr<net_device> dev, @Unsigned int cmd, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ethtool_set_settings(Ptr<net_device> dev, Ptr<?> useraddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_sprintf($arg1, (const u8*)$arg2, $arg3_)")
  public static void ethtool_sprintf(Ptr<Ptr<java.lang.Character>> data, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_virtdev_set_link_ksettings($arg1, (const struct ethtool_link_ksettings*)$arg2, $arg3, $arg4)")
  public static int ethtool_virtdev_set_link_ksettings(Ptr<net_device> dev,
      Ptr<ethtool_link_ksettings> cmd, Ptr<java.lang. @Unsigned Integer> dev_speed,
      Ptr<java.lang.Character> dev_duplex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ethtool_virtdev_validate_cmd((const struct ethtool_link_ksettings*)$arg1)")
  public static boolean ethtool_virtdev_validate_cmd(Ptr<ethtool_link_ksettings> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_ops extends Struct {
    public @Unsigned int supported_input_xfrm;

    public @Unsigned int cap_link_lanes_supported;

    public @Unsigned int rxfh_per_ctx_fields;

    public @Unsigned int rxfh_per_ctx_key;

    public @Unsigned int cap_rss_rxnfc_adds;

    public @Unsigned int rxfh_indir_space;

    public @Unsigned short rxfh_key_space;

    public @Unsigned short rxfh_priv_size;

    public @Unsigned int rxfh_max_num_contexts;

    public @Unsigned int supported_coalesce_params;

    public @Unsigned int supported_ring_params;

    public @Unsigned int supported_hwtstamp_qualifiers;

    public Ptr<?> get_drvinfo;

    public Ptr<?> get_regs_len;

    public Ptr<?> get_regs;

    public Ptr<?> get_wol;

    public Ptr<?> set_wol;

    public Ptr<?> get_msglevel;

    public Ptr<?> set_msglevel;

    public Ptr<?> nway_reset;

    public Ptr<?> get_link;

    public Ptr<?> get_link_ext_state;

    public Ptr<?> get_link_ext_stats;

    public Ptr<?> get_eeprom_len;

    public Ptr<?> get_eeprom;

    public Ptr<?> set_eeprom;

    public Ptr<?> get_coalesce;

    public Ptr<?> set_coalesce;

    public Ptr<?> get_ringparam;

    public Ptr<?> set_ringparam;

    public Ptr<?> get_pause_stats;

    public Ptr<?> get_pauseparam;

    public Ptr<?> set_pauseparam;

    public Ptr<?> self_test;

    public Ptr<?> get_strings;

    public Ptr<?> set_phys_id;

    public Ptr<?> get_ethtool_stats;

    public Ptr<?> begin;

    public Ptr<?> complete;

    public Ptr<?> get_priv_flags;

    public Ptr<?> set_priv_flags;

    public Ptr<?> get_sset_count;

    public Ptr<?> get_rxnfc;

    public Ptr<?> set_rxnfc;

    public Ptr<?> flash_device;

    public Ptr<?> reset;

    public Ptr<?> get_rxfh_key_size;

    public Ptr<?> get_rxfh_indir_size;

    public Ptr<?> get_rxfh;

    public Ptr<?> set_rxfh;

    public Ptr<?> get_rxfh_fields;

    public Ptr<?> set_rxfh_fields;

    public Ptr<?> create_rxfh_context;

    public Ptr<?> modify_rxfh_context;

    public Ptr<?> remove_rxfh_context;

    public Ptr<?> get_channels;

    public Ptr<?> set_channels;

    public Ptr<?> get_dump_flag;

    public Ptr<?> get_dump_data;

    public Ptr<?> set_dump;

    public Ptr<?> get_ts_info;

    public Ptr<?> get_ts_stats;

    public Ptr<?> get_module_info;

    public Ptr<?> get_module_eeprom;

    public Ptr<?> get_eee;

    public Ptr<?> set_eee;

    public Ptr<?> get_tunable;

    public Ptr<?> set_tunable;

    public Ptr<?> get_per_queue_coalesce;

    public Ptr<?> set_per_queue_coalesce;

    public Ptr<?> get_link_ksettings;

    public Ptr<?> set_link_ksettings;

    public Ptr<?> get_fec_stats;

    public Ptr<?> get_fecparam;

    public Ptr<?> set_fecparam;

    public Ptr<?> get_ethtool_phy_stats;

    public Ptr<?> get_phy_tunable;

    public Ptr<?> set_phy_tunable;

    public Ptr<?> get_module_eeprom_by_page;

    public Ptr<?> set_module_eeprom_by_page;

    public Ptr<?> get_eth_phy_stats;

    public Ptr<?> get_eth_mac_stats;

    public Ptr<?> get_eth_ctrl_stats;

    public Ptr<?> get_rmon_stats;

    public Ptr<?> get_module_power_mode;

    public Ptr<?> set_module_power_mode;

    public Ptr<?> get_mm;

    public Ptr<?> set_mm;

    public Ptr<?> get_mm_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_netdev_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_netdev_state extends Struct {
    public xarray rss_ctx;

    public mutex rss_lock;

    public @Unsigned int wol_enabled;

    public @Unsigned int module_fw_flash_in_progress;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_drvinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_drvinfo extends Struct {
    public @Unsigned int cmd;

    public char @Size(32) [] driver;

    public char @Size(32) [] version;

    public char @Size(32) [] fw_version;

    public char @Size(32) [] bus_info;

    public char @Size(32) [] erom_version;

    public char @Size(12) [] reserved2;

    public @Unsigned int n_priv_flags;

    public @Unsigned int n_stats;

    public @Unsigned int testinfo_len;

    public @Unsigned int eedump_len;

    public @Unsigned int regdump_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_wolinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_wolinfo extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int supported;

    public @Unsigned int wolopts;

    public char @Size(6) [] sopass;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_tunable"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_tunable extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int id;

    public @Unsigned int type_id;

    public @Unsigned int len;

    public Ptr<?> @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_regs extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int version;

    public @Unsigned int len;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_eeprom"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_eeprom extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int magic;

    public @Unsigned int offset;

    public @Unsigned int len;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_modinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_modinfo extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int type;

    public @Unsigned int eeprom_len;

    public @Unsigned int @Size(8) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_coalesce"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_coalesce extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int rx_coalesce_usecs;

    public @Unsigned int rx_max_coalesced_frames;

    public @Unsigned int rx_coalesce_usecs_irq;

    public @Unsigned int rx_max_coalesced_frames_irq;

    public @Unsigned int tx_coalesce_usecs;

    public @Unsigned int tx_max_coalesced_frames;

    public @Unsigned int tx_coalesce_usecs_irq;

    public @Unsigned int tx_max_coalesced_frames_irq;

    public @Unsigned int stats_block_coalesce_usecs;

    public @Unsigned int use_adaptive_rx_coalesce;

    public @Unsigned int use_adaptive_tx_coalesce;

    public @Unsigned int pkt_rate_low;

    public @Unsigned int rx_coalesce_usecs_low;

    public @Unsigned int rx_max_coalesced_frames_low;

    public @Unsigned int tx_coalesce_usecs_low;

    public @Unsigned int tx_max_coalesced_frames_low;

    public @Unsigned int pkt_rate_high;

    public @Unsigned int rx_coalesce_usecs_high;

    public @Unsigned int rx_max_coalesced_frames_high;

    public @Unsigned int tx_coalesce_usecs_high;

    public @Unsigned int tx_max_coalesced_frames_high;

    public @Unsigned int rate_sample_interval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_ringparam"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_ringparam extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int rx_max_pending;

    public @Unsigned int rx_mini_max_pending;

    public @Unsigned int rx_jumbo_max_pending;

    public @Unsigned int tx_max_pending;

    public @Unsigned int rx_pending;

    public @Unsigned int rx_mini_pending;

    public @Unsigned int rx_jumbo_pending;

    public @Unsigned int tx_pending;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_channels"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_channels extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int max_rx;

    public @Unsigned int max_tx;

    public @Unsigned int max_other;

    public @Unsigned int max_combined;

    public @Unsigned int rx_count;

    public @Unsigned int tx_count;

    public @Unsigned int other_count;

    public @Unsigned int combined_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_pauseparam"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_pauseparam extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int autoneg;

    public @Unsigned int rx_pause;

    public @Unsigned int tx_pause;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_ext_state"
  )
  public enum ethtool_link_ext_state implements Enum<ethtool_link_ext_state>, TypedEnum<ethtool_link_ext_state, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_EXT_STATE_AUTONEG = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_LINK_EXT_STATE_AUTONEG"
    )
    ETHTOOL_LINK_EXT_STATE_AUTONEG,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE"
    )
    ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH"
    )
    ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY"
    )
    ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_NO_CABLE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_LINK_EXT_STATE_NO_CABLE"
    )
    ETHTOOL_LINK_EXT_STATE_NO_CABLE,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE"
    )
    ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE"
    )
    ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE"
    )
    ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED"
    )
    ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_OVERHEAT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ETHTOOL_LINK_EXT_STATE_OVERHEAT"
    )
    ETHTOOL_LINK_EXT_STATE_OVERHEAT,

    /**
     * {@code ETHTOOL_LINK_EXT_STATE_MODULE = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ETHTOOL_LINK_EXT_STATE_MODULE"
    )
    ETHTOOL_LINK_EXT_STATE_MODULE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_ext_substate_autoneg"
  )
  public enum ethtool_link_ext_substate_autoneg implements Enum<ethtool_link_ext_substate_autoneg>, TypedEnum<ethtool_link_ext_substate_autoneg, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_ext_substate_link_training"
  )
  public enum ethtool_link_ext_substate_link_training implements Enum<ethtool_link_ext_substate_link_training>, TypedEnum<ethtool_link_ext_substate_link_training, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_ext_substate_link_logical_mismatch"
  )
  public enum ethtool_link_ext_substate_link_logical_mismatch implements Enum<ethtool_link_ext_substate_link_logical_mismatch>, TypedEnum<ethtool_link_ext_substate_link_logical_mismatch, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_ext_substate_bad_signal_integrity"
  )
  public enum ethtool_link_ext_substate_bad_signal_integrity implements Enum<ethtool_link_ext_substate_bad_signal_integrity>, TypedEnum<ethtool_link_ext_substate_bad_signal_integrity, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_ext_substate_cable_issue"
  )
  public enum ethtool_link_ext_substate_cable_issue implements Enum<ethtool_link_ext_substate_cable_issue>, TypedEnum<ethtool_link_ext_substate_cable_issue, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE,

    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_ext_substate_module"
  )
  public enum ethtool_link_ext_substate_module implements Enum<ethtool_link_ext_substate_module>, TypedEnum<ethtool_link_ext_substate_module, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY"
    )
    ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_mac_stats_src"
  )
  public enum ethtool_mac_stats_src implements Enum<ethtool_mac_stats_src>, TypedEnum<ethtool_mac_stats_src, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_MAC_STATS_SRC_AGGREGATE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_MAC_STATS_SRC_AGGREGATE"
    )
    ETHTOOL_MAC_STATS_SRC_AGGREGATE,

    /**
     * {@code ETHTOOL_MAC_STATS_SRC_EMAC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_MAC_STATS_SRC_EMAC"
    )
    ETHTOOL_MAC_STATS_SRC_EMAC,

    /**
     * {@code ETHTOOL_MAC_STATS_SRC_PMAC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_MAC_STATS_SRC_PMAC"
    )
    ETHTOOL_MAC_STATS_SRC_PMAC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_module_power_mode_policy"
  )
  public enum ethtool_module_power_mode_policy implements Enum<ethtool_module_power_mode_policy>, TypedEnum<ethtool_module_power_mode_policy, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH"
    )
    ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH,

    /**
     * {@code ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO"
    )
    ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_module_power_mode"
  )
  public enum ethtool_module_power_mode implements Enum<ethtool_module_power_mode>, TypedEnum<ethtool_module_power_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_MODULE_POWER_MODE_LOW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_MODULE_POWER_MODE_LOW"
    )
    ETHTOOL_MODULE_POWER_MODE_LOW,

    /**
     * {@code ETHTOOL_MODULE_POWER_MODE_HIGH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_MODULE_POWER_MODE_HIGH"
    )
    ETHTOOL_MODULE_POWER_MODE_HIGH
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_mm_verify_status"
  )
  public enum ethtool_mm_verify_status implements Enum<ethtool_mm_verify_status>, TypedEnum<ethtool_mm_verify_status, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_MM_VERIFY_STATUS_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_MM_VERIFY_STATUS_UNKNOWN"
    )
    ETHTOOL_MM_VERIFY_STATUS_UNKNOWN,

    /**
     * {@code ETHTOOL_MM_VERIFY_STATUS_INITIAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_MM_VERIFY_STATUS_INITIAL"
    )
    ETHTOOL_MM_VERIFY_STATUS_INITIAL,

    /**
     * {@code ETHTOOL_MM_VERIFY_STATUS_VERIFYING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_MM_VERIFY_STATUS_VERIFYING"
    )
    ETHTOOL_MM_VERIFY_STATUS_VERIFYING,

    /**
     * {@code ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED"
    )
    ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED,

    /**
     * {@code ETHTOOL_MM_VERIFY_STATUS_FAILED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_MM_VERIFY_STATUS_FAILED"
    )
    ETHTOOL_MM_VERIFY_STATUS_FAILED,

    /**
     * {@code ETHTOOL_MM_VERIFY_STATUS_DISABLED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_MM_VERIFY_STATUS_DISABLED"
    )
    ETHTOOL_MM_VERIFY_STATUS_DISABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_test"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_test extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int flags;

    public @Unsigned int reserved;

    public @Unsigned int len;

    public @Unsigned long @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_stats extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int n_stats;

    public @Unsigned long @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_tcpip4_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_tcpip4_spec extends Struct {
    public @Unsigned @OriginalName("__be32") int ip4src;

    public @Unsigned @OriginalName("__be32") int ip4dst;

    public @Unsigned @OriginalName("__be16") short psrc;

    public @Unsigned @OriginalName("__be16") short pdst;

    public char tos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_ah_espip4_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_ah_espip4_spec extends Struct {
    public @Unsigned @OriginalName("__be32") int ip4src;

    public @Unsigned @OriginalName("__be32") int ip4dst;

    public @Unsigned @OriginalName("__be32") int spi;

    public char tos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_usrip4_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_usrip4_spec extends Struct {
    public @Unsigned @OriginalName("__be32") int ip4src;

    public @Unsigned @OriginalName("__be32") int ip4dst;

    public @Unsigned @OriginalName("__be32") int l4_4_bytes;

    public char tos;

    public char ip_ver;

    public char proto;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_tcpip6_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_tcpip6_spec extends Struct {
    public @Unsigned @OriginalName("__be32") int @Size(4) [] ip6src;

    public @Unsigned @OriginalName("__be32") int @Size(4) [] ip6dst;

    public @Unsigned @OriginalName("__be16") short psrc;

    public @Unsigned @OriginalName("__be16") short pdst;

    public char tclass;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_ah_espip6_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_ah_espip6_spec extends Struct {
    public @Unsigned @OriginalName("__be32") int @Size(4) [] ip6src;

    public @Unsigned @OriginalName("__be32") int @Size(4) [] ip6dst;

    public @Unsigned @OriginalName("__be32") int spi;

    public char tclass;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_usrip6_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_usrip6_spec extends Struct {
    public @Unsigned @OriginalName("__be32") int @Size(4) [] ip6src;

    public @Unsigned @OriginalName("__be32") int @Size(4) [] ip6dst;

    public @Unsigned @OriginalName("__be32") int l4_4_bytes;

    public char tclass;

    public char l4_proto;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union ethtool_flow_union"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_flow_union extends Union {
    public ethtool_tcpip4_spec tcp_ip4_spec;

    public ethtool_tcpip4_spec udp_ip4_spec;

    public ethtool_tcpip4_spec sctp_ip4_spec;

    public ethtool_ah_espip4_spec ah_ip4_spec;

    public ethtool_ah_espip4_spec esp_ip4_spec;

    public ethtool_usrip4_spec usr_ip4_spec;

    public ethtool_tcpip6_spec tcp_ip6_spec;

    public ethtool_tcpip6_spec udp_ip6_spec;

    public ethtool_tcpip6_spec sctp_ip6_spec;

    public ethtool_ah_espip6_spec ah_ip6_spec;

    public ethtool_ah_espip6_spec esp_ip6_spec;

    public ethtool_usrip6_spec usr_ip6_spec;

    public ethhdr ether_spec;

    public char @Size(52) [] hdata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_flow_ext"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_flow_ext extends Struct {
    public char @Size(2) [] padding;

    public char @Size(6) [] h_dest;

    public @Unsigned @OriginalName("__be16") short vlan_etype;

    public @Unsigned @OriginalName("__be16") short vlan_tci;

    public @Unsigned @OriginalName("__be32") int @Size(2) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rx_flow_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rx_flow_spec extends Struct {
    public @Unsigned int flow_type;

    public ethtool_flow_union h_u;

    public ethtool_flow_ext h_ext;

    public ethtool_flow_union m_u;

    public ethtool_flow_ext m_ext;

    public @Unsigned long ring_cookie;

    public @Unsigned int location;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rxnfc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rxnfc extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int flow_type;

    public @Unsigned long data;

    public ethtool_rx_flow_spec fs;

    @InlineUnion(27371)
    public @Unsigned int rule_cnt;

    @InlineUnion(27371)
    public @Unsigned int rss_context;

    public @Unsigned int @Size(0) [] rule_locs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_flash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_flash extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int region;

    public char @Size(128) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_dump"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_dump extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int version;

    public @Unsigned int flag;

    public @Unsigned int len;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_fecparam"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_fecparam extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int active_fec;

    public @Unsigned int fec;

    public @Unsigned int reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_link_mode_bit_indices"
  )
  public enum ethtool_link_mode_bit_indices implements Enum<ethtool_link_mode_bit_indices>, TypedEnum<ethtool_link_mode_bit_indices, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_LINK_MODE_10baseT_Half_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_LINK_MODE_10baseT_Half_BIT"
    )
    ETHTOOL_LINK_MODE_10baseT_Half_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10baseT_Full_BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_LINK_MODE_10baseT_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10baseT_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100baseT_Half_BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_LINK_MODE_100baseT_Half_BIT"
    )
    ETHTOOL_LINK_MODE_100baseT_Half_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100baseT_Full_BIT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_LINK_MODE_100baseT_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100baseT_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_1000baseT_Half_BIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_LINK_MODE_1000baseT_Half_BIT"
    )
    ETHTOOL_LINK_MODE_1000baseT_Half_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_1000baseT_Full_BIT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_LINK_MODE_1000baseT_Full_BIT"
    )
    ETHTOOL_LINK_MODE_1000baseT_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_Autoneg_BIT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETHTOOL_LINK_MODE_Autoneg_BIT"
    )
    ETHTOOL_LINK_MODE_Autoneg_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_TP_BIT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ETHTOOL_LINK_MODE_TP_BIT"
    )
    ETHTOOL_LINK_MODE_TP_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_AUI_BIT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETHTOOL_LINK_MODE_AUI_BIT"
    )
    ETHTOOL_LINK_MODE_AUI_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_MII_BIT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ETHTOOL_LINK_MODE_MII_BIT"
    )
    ETHTOOL_LINK_MODE_MII_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_FIBRE_BIT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ETHTOOL_LINK_MODE_FIBRE_BIT"
    )
    ETHTOOL_LINK_MODE_FIBRE_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_BNC_BIT = 11}
     */
    @EnumMember(
        value = 11L,
        name = "ETHTOOL_LINK_MODE_BNC_BIT"
    )
    ETHTOOL_LINK_MODE_BNC_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseT_Full_BIT = 12}
     */
    @EnumMember(
        value = 12L,
        name = "ETHTOOL_LINK_MODE_10000baseT_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseT_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_Pause_BIT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "ETHTOOL_LINK_MODE_Pause_BIT"
    )
    ETHTOOL_LINK_MODE_Pause_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_Asym_Pause_BIT = 14}
     */
    @EnumMember(
        value = 14L,
        name = "ETHTOOL_LINK_MODE_Asym_Pause_BIT"
    )
    ETHTOOL_LINK_MODE_Asym_Pause_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_2500baseX_Full_BIT = 15}
     */
    @EnumMember(
        value = 15L,
        name = "ETHTOOL_LINK_MODE_2500baseX_Full_BIT"
    )
    ETHTOOL_LINK_MODE_2500baseX_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_Backplane_BIT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ETHTOOL_LINK_MODE_Backplane_BIT"
    )
    ETHTOOL_LINK_MODE_Backplane_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_1000baseKX_Full_BIT = 17}
     */
    @EnumMember(
        value = 17L,
        name = "ETHTOOL_LINK_MODE_1000baseKX_Full_BIT"
    )
    ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT = 18}
     */
    @EnumMember(
        value = 18L,
        name = "ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseKR_Full_BIT = 19}
     */
    @EnumMember(
        value = 19L,
        name = "ETHTOOL_LINK_MODE_10000baseKR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseR_FEC_BIT = 20}
     */
    @EnumMember(
        value = 20L,
        name = "ETHTOOL_LINK_MODE_10000baseR_FEC_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseR_FEC_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21}
     */
    @EnumMember(
        value = 21L,
        name = "ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT = 22}
     */
    @EnumMember(
        value = 22L,
        name = "ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23}
     */
    @EnumMember(
        value = 23L,
        name = "ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24}
     */
    @EnumMember(
        value = 24L,
        name = "ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT = 25}
     */
    @EnumMember(
        value = 25L,
        name = "ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT = 26}
     */
    @EnumMember(
        value = 26L,
        name = "ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT = 27}
     */
    @EnumMember(
        value = 27L,
        name = "ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT = 28}
     */
    @EnumMember(
        value = 28L,
        name = "ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT = 29}
     */
    @EnumMember(
        value = 29L,
        name = "ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT = 30}
     */
    @EnumMember(
        value = 30L,
        name = "ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_25000baseCR_Full_BIT = 31}
     */
    @EnumMember(
        value = 31L,
        name = "ETHTOOL_LINK_MODE_25000baseCR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_25000baseKR_Full_BIT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "ETHTOOL_LINK_MODE_25000baseKR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_25000baseSR_Full_BIT = 33}
     */
    @EnumMember(
        value = 33L,
        name = "ETHTOOL_LINK_MODE_25000baseSR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT = 34}
     */
    @EnumMember(
        value = 34L,
        name = "ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT = 35}
     */
    @EnumMember(
        value = 35L,
        name = "ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT = 36}
     */
    @EnumMember(
        value = 36L,
        name = "ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT = 37}
     */
    @EnumMember(
        value = 37L,
        name = "ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT = 38}
     */
    @EnumMember(
        value = 38L,
        name = "ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT = 39}
     */
    @EnumMember(
        value = 39L,
        name = "ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT = 40}
     */
    @EnumMember(
        value = 40L,
        name = "ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_1000baseX_Full_BIT = 41}
     */
    @EnumMember(
        value = 41L,
        name = "ETHTOOL_LINK_MODE_1000baseX_Full_BIT"
    )
    ETHTOOL_LINK_MODE_1000baseX_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseCR_Full_BIT = 42}
     */
    @EnumMember(
        value = 42L,
        name = "ETHTOOL_LINK_MODE_10000baseCR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseCR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseSR_Full_BIT = 43}
     */
    @EnumMember(
        value = 43L,
        name = "ETHTOOL_LINK_MODE_10000baseSR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseLR_Full_BIT = 44}
     */
    @EnumMember(
        value = 44L,
        name = "ETHTOOL_LINK_MODE_10000baseLR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT = 45}
     */
    @EnumMember(
        value = 45L,
        name = "ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10000baseER_Full_BIT = 46}
     */
    @EnumMember(
        value = 46L,
        name = "ETHTOOL_LINK_MODE_10000baseER_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10000baseER_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_2500baseT_Full_BIT = 47}
     */
    @EnumMember(
        value = 47L,
        name = "ETHTOOL_LINK_MODE_2500baseT_Full_BIT"
    )
    ETHTOOL_LINK_MODE_2500baseT_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_5000baseT_Full_BIT = 48}
     */
    @EnumMember(
        value = 48L,
        name = "ETHTOOL_LINK_MODE_5000baseT_Full_BIT"
    )
    ETHTOOL_LINK_MODE_5000baseT_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_FEC_NONE_BIT = 49}
     */
    @EnumMember(
        value = 49L,
        name = "ETHTOOL_LINK_MODE_FEC_NONE_BIT"
    )
    ETHTOOL_LINK_MODE_FEC_NONE_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_FEC_RS_BIT = 50}
     */
    @EnumMember(
        value = 50L,
        name = "ETHTOOL_LINK_MODE_FEC_RS_BIT"
    )
    ETHTOOL_LINK_MODE_FEC_RS_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_FEC_BASER_BIT = 51}
     */
    @EnumMember(
        value = 51L,
        name = "ETHTOOL_LINK_MODE_FEC_BASER_BIT"
    )
    ETHTOOL_LINK_MODE_FEC_BASER_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseKR_Full_BIT = 52}
     */
    @EnumMember(
        value = 52L,
        name = "ETHTOOL_LINK_MODE_50000baseKR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseKR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseSR_Full_BIT = 53}
     */
    @EnumMember(
        value = 53L,
        name = "ETHTOOL_LINK_MODE_50000baseSR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseSR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseCR_Full_BIT = 54}
     */
    @EnumMember(
        value = 54L,
        name = "ETHTOOL_LINK_MODE_50000baseCR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseCR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT = 55}
     */
    @EnumMember(
        value = 55L,
        name = "ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_50000baseDR_Full_BIT = 56}
     */
    @EnumMember(
        value = 56L,
        name = "ETHTOOL_LINK_MODE_50000baseDR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_50000baseDR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT = 57}
     */
    @EnumMember(
        value = 57L,
        name = "ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT = 58}
     */
    @EnumMember(
        value = 58L,
        name = "ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT = 59}
     */
    @EnumMember(
        value = 59L,
        name = "ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT = 60}
     */
    @EnumMember(
        value = 60L,
        name = "ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT = 61}
     */
    @EnumMember(
        value = 61L,
        name = "ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT = 62}
     */
    @EnumMember(
        value = 62L,
        name = "ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT = 63}
     */
    @EnumMember(
        value = 63L,
        name = "ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT = 64}
     */
    @EnumMember(
        value = 64L,
        name = "ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT = 65}
     */
    @EnumMember(
        value = 65L,
        name = "ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT = 66}
     */
    @EnumMember(
        value = 66L,
        name = "ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100baseT1_Full_BIT = 67}
     */
    @EnumMember(
        value = 67L,
        name = "ETHTOOL_LINK_MODE_100baseT1_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100baseT1_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_1000baseT1_Full_BIT = 68}
     */
    @EnumMember(
        value = 68L,
        name = "ETHTOOL_LINK_MODE_1000baseT1_Full_BIT"
    )
    ETHTOOL_LINK_MODE_1000baseT1_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT = 69}
     */
    @EnumMember(
        value = 69L,
        name = "ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT = 70}
     */
    @EnumMember(
        value = 70L,
        name = "ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT = 71}
     */
    @EnumMember(
        value = 71L,
        name = "ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT = 72}
     */
    @EnumMember(
        value = 72L,
        name = "ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT = 73}
     */
    @EnumMember(
        value = 73L,
        name = "ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_FEC_LLRS_BIT = 74}
     */
    @EnumMember(
        value = 74L,
        name = "ETHTOOL_LINK_MODE_FEC_LLRS_BIT"
    )
    ETHTOOL_LINK_MODE_FEC_LLRS_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseKR_Full_BIT = 75}
     */
    @EnumMember(
        value = 75L,
        name = "ETHTOOL_LINK_MODE_100000baseKR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseKR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseSR_Full_BIT = 76}
     */
    @EnumMember(
        value = 76L,
        name = "ETHTOOL_LINK_MODE_100000baseSR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseSR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT = 77}
     */
    @EnumMember(
        value = 77L,
        name = "ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseCR_Full_BIT = 78}
     */
    @EnumMember(
        value = 78L,
        name = "ETHTOOL_LINK_MODE_100000baseCR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseCR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100000baseDR_Full_BIT = 79}
     */
    @EnumMember(
        value = 79L,
        name = "ETHTOOL_LINK_MODE_100000baseDR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100000baseDR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT = 80}
     */
    @EnumMember(
        value = 80L,
        name = "ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT = 81}
     */
    @EnumMember(
        value = 81L,
        name = "ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT = 82}
     */
    @EnumMember(
        value = 82L,
        name = "ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT = 83}
     */
    @EnumMember(
        value = 83L,
        name = "ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT = 84}
     */
    @EnumMember(
        value = 84L,
        name = "ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT = 85}
     */
    @EnumMember(
        value = 85L,
        name = "ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT = 86}
     */
    @EnumMember(
        value = 86L,
        name = "ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT = 87}
     */
    @EnumMember(
        value = 87L,
        name = "ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT = 88}
     */
    @EnumMember(
        value = 88L,
        name = "ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT = 89}
     */
    @EnumMember(
        value = 89L,
        name = "ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100baseFX_Half_BIT = 90}
     */
    @EnumMember(
        value = 90L,
        name = "ETHTOOL_LINK_MODE_100baseFX_Half_BIT"
    )
    ETHTOOL_LINK_MODE_100baseFX_Half_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_100baseFX_Full_BIT = 91}
     */
    @EnumMember(
        value = 91L,
        name = "ETHTOOL_LINK_MODE_100baseFX_Full_BIT"
    )
    ETHTOOL_LINK_MODE_100baseFX_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10baseT1L_Full_BIT = 92}
     */
    @EnumMember(
        value = 92L,
        name = "ETHTOOL_LINK_MODE_10baseT1L_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10baseT1L_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT = 93}
     */
    @EnumMember(
        value = 93L,
        name = "ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT = 94}
     */
    @EnumMember(
        value = 94L,
        name = "ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseDR8_Full_BIT = 95}
     */
    @EnumMember(
        value = 95L,
        name = "ETHTOOL_LINK_MODE_800000baseDR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseDR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseDR8_2_Full_BIT = 96}
     */
    @EnumMember(
        value = 96L,
        name = "ETHTOOL_LINK_MODE_800000baseDR8_2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseDR8_2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT = 97}
     */
    @EnumMember(
        value = 97L,
        name = "ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseVR8_Full_BIT = 98}
     */
    @EnumMember(
        value = 98L,
        name = "ETHTOOL_LINK_MODE_800000baseVR8_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseVR8_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10baseT1S_Full_BIT = 99}
     */
    @EnumMember(
        value = 99L,
        name = "ETHTOOL_LINK_MODE_10baseT1S_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10baseT1S_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10baseT1S_Half_BIT = 100}
     */
    @EnumMember(
        value = 100L,
        name = "ETHTOOL_LINK_MODE_10baseT1S_Half_BIT"
    )
    ETHTOOL_LINK_MODE_10baseT1S_Half_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT = 101}
     */
    @EnumMember(
        value = 101L,
        name = "ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT"
    )
    ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT = 102}
     */
    @EnumMember(
        value = 102L,
        name = "ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseCR_Full_BIT = 103}
     */
    @EnumMember(
        value = 103L,
        name = "ETHTOOL_LINK_MODE_200000baseCR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseCR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseKR_Full_BIT = 104}
     */
    @EnumMember(
        value = 104L,
        name = "ETHTOOL_LINK_MODE_200000baseKR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseKR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseDR_Full_BIT = 105}
     */
    @EnumMember(
        value = 105L,
        name = "ETHTOOL_LINK_MODE_200000baseDR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseDR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseDR_2_Full_BIT = 106}
     */
    @EnumMember(
        value = 106L,
        name = "ETHTOOL_LINK_MODE_200000baseDR_2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseDR_2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseSR_Full_BIT = 107}
     */
    @EnumMember(
        value = 107L,
        name = "ETHTOOL_LINK_MODE_200000baseSR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseSR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_200000baseVR_Full_BIT = 108}
     */
    @EnumMember(
        value = 108L,
        name = "ETHTOOL_LINK_MODE_200000baseVR_Full_BIT"
    )
    ETHTOOL_LINK_MODE_200000baseVR_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseCR2_Full_BIT = 109}
     */
    @EnumMember(
        value = 109L,
        name = "ETHTOOL_LINK_MODE_400000baseCR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseCR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseKR2_Full_BIT = 110}
     */
    @EnumMember(
        value = 110L,
        name = "ETHTOOL_LINK_MODE_400000baseKR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseKR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseDR2_Full_BIT = 111}
     */
    @EnumMember(
        value = 111L,
        name = "ETHTOOL_LINK_MODE_400000baseDR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseDR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseDR2_2_Full_BIT = 112}
     */
    @EnumMember(
        value = 112L,
        name = "ETHTOOL_LINK_MODE_400000baseDR2_2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseDR2_2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseSR2_Full_BIT = 113}
     */
    @EnumMember(
        value = 113L,
        name = "ETHTOOL_LINK_MODE_400000baseSR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseSR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_400000baseVR2_Full_BIT = 114}
     */
    @EnumMember(
        value = 114L,
        name = "ETHTOOL_LINK_MODE_400000baseVR2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_400000baseVR2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseCR4_Full_BIT = 115}
     */
    @EnumMember(
        value = 115L,
        name = "ETHTOOL_LINK_MODE_800000baseCR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseCR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseKR4_Full_BIT = 116}
     */
    @EnumMember(
        value = 116L,
        name = "ETHTOOL_LINK_MODE_800000baseKR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseKR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseDR4_Full_BIT = 117}
     */
    @EnumMember(
        value = 117L,
        name = "ETHTOOL_LINK_MODE_800000baseDR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseDR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseDR4_2_Full_BIT = 118}
     */
    @EnumMember(
        value = 118L,
        name = "ETHTOOL_LINK_MODE_800000baseDR4_2_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseDR4_2_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseSR4_Full_BIT = 119}
     */
    @EnumMember(
        value = 119L,
        name = "ETHTOOL_LINK_MODE_800000baseSR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseSR4_Full_BIT,

    /**
     * {@code ETHTOOL_LINK_MODE_800000baseVR4_Full_BIT = 120}
     */
    @EnumMember(
        value = 120L,
        name = "ETHTOOL_LINK_MODE_800000baseVR4_Full_BIT"
    )
    ETHTOOL_LINK_MODE_800000baseVR4_Full_BIT,

    /**
     * {@code __ETHTOOL_LINK_MODE_MASK_NBITS = 121}
     */
    @EnumMember(
        value = 121L,
        name = "__ETHTOOL_LINK_MODE_MASK_NBITS"
    )
    __ETHTOOL_LINK_MODE_MASK_NBITS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_link_settings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_link_settings extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int speed;

    public char duplex;

    public char port;

    public char phy_address;

    public char autoneg;

    public char mdio_support;

    public char eth_tp_mdix;

    public char eth_tp_mdix_ctrl;

    public byte link_mode_masks_nwords;

    public char transceiver;

    public char master_slave_cfg;

    public char master_slave_state;

    public char rate_matching;

    public @Unsigned int @Size(7) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_phys_id_state"
  )
  public enum ethtool_phys_id_state implements Enum<ethtool_phys_id_state>, TypedEnum<ethtool_phys_id_state, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_ID_INACTIVE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_ID_INACTIVE"
    )
    ETHTOOL_ID_INACTIVE,

    /**
     * {@code ETHTOOL_ID_ACTIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_ID_ACTIVE"
    )
    ETHTOOL_ID_ACTIVE,

    /**
     * {@code ETHTOOL_ID_ON = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_ID_ON"
    )
    ETHTOOL_ID_ON,

    /**
     * {@code ETHTOOL_ID_OFF = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_ID_OFF"
    )
    ETHTOOL_ID_OFF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_link_ext_state_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_link_ext_state_info extends Struct {
    public ethtool_link_ext_state link_ext_state;

    @InlineUnion(27380)
    public ethtool_link_ext_substate_autoneg autoneg;

    @InlineUnion(27380)
    public ethtool_link_ext_substate_link_training link_training;

    @InlineUnion(27380)
    public ethtool_link_ext_substate_link_logical_mismatch link_logical_mismatch;

    @InlineUnion(27380)
    public ethtool_link_ext_substate_bad_signal_integrity bad_signal_integrity;

    @InlineUnion(27380)
    public ethtool_link_ext_substate_cable_issue cable_issue;

    @InlineUnion(27380)
    public ethtool_link_ext_substate_module module;

    @InlineUnion(27380)
    public @Unsigned int __link_ext_substate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_link_ext_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_link_ext_stats extends Struct {
    public @Unsigned long link_down_events;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rxfh_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rxfh_context extends Struct {
    public @Unsigned int indir_size;

    public @Unsigned int key_size;

    public @Unsigned short priv_size;

    public char hfunc;

    public char input_xfrm;

    public char indir_configured;

    public char key_configured;

    public @Unsigned int key_off;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_link_ksettings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_link_ksettings extends Struct {
    public ethtool_link_settings base;

    public link_modes_of_ethtool_link_ksettings link_modes;

    public @Unsigned int lanes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_keee"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_keee extends Struct {
    public @Unsigned long @Size(2) [] supported;

    public @Unsigned long @Size(2) [] advertised;

    public @Unsigned long @Size(2) [] lp_advertised;

    public @Unsigned int tx_lpi_timer;

    public boolean tx_lpi_enabled;

    public boolean eee_active;

    public boolean eee_enabled;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_eth_mac_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_eth_mac_stats extends Struct {
    public ethtool_mac_stats_src src;

    @InlineUnion(27390)
    public anon_member_of_anon_member_of_ethtool_eth_mac_stats_and_stats_of_anon_member_of_ethtool_eth_mac_stats anon1$0;

    @InlineUnion(27390)
    public anon_member_of_anon_member_of_ethtool_eth_mac_stats_and_stats_of_anon_member_of_ethtool_eth_mac_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_eth_phy_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_eth_phy_stats extends Struct {
    public ethtool_mac_stats_src src;

    @InlineUnion(27393)
    public anon_member_of_anon_member_of_ethtool_eth_phy_stats_and_stats_of_anon_member_of_ethtool_eth_phy_stats anon1$0;

    @InlineUnion(27393)
    public anon_member_of_anon_member_of_ethtool_eth_phy_stats_and_stats_of_anon_member_of_ethtool_eth_phy_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_eth_ctrl_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_eth_ctrl_stats extends Struct {
    public ethtool_mac_stats_src src;

    @InlineUnion(27396)
    public anon_member_of_anon_member_of_ethtool_eth_ctrl_stats_and_stats_of_anon_member_of_ethtool_eth_ctrl_stats anon1$0;

    @InlineUnion(27396)
    public anon_member_of_anon_member_of_ethtool_eth_ctrl_stats_and_stats_of_anon_member_of_ethtool_eth_ctrl_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_pause_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_pause_stats extends Struct {
    public ethtool_mac_stats_src src;

    @InlineUnion(27399)
    public anon_member_of_anon_member_of_ethtool_pause_stats_and_stats_of_anon_member_of_ethtool_pause_stats anon1$0;

    @InlineUnion(27399)
    public anon_member_of_anon_member_of_ethtool_pause_stats_and_stats_of_anon_member_of_ethtool_pause_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_fec_stat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_fec_stat extends Struct {
    public @Unsigned long total;

    public @Unsigned long @Size(8) [] lanes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_fec_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_fec_stats extends Struct {
    public ethtool_fec_stat corrected_blocks;

    public ethtool_fec_stat uncorrectable_blocks;

    public ethtool_fec_stat corrected_bits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rmon_hist_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rmon_hist_range extends Struct {
    public @Unsigned short low;

    public @Unsigned short high;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rmon_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rmon_stats extends Struct {
    public ethtool_mac_stats_src src;

    @InlineUnion(27406)
    public anon_member_of_anon_member_of_ethtool_rmon_stats_and_stats_of_anon_member_of_ethtool_rmon_stats anon1$0;

    @InlineUnion(27406)
    public anon_member_of_anon_member_of_ethtool_rmon_stats_and_stats_of_anon_member_of_ethtool_rmon_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_ts_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_ts_stats extends Struct {
    @InlineUnion(27409)
    public anon_member_of_anon_member_of_ethtool_ts_stats_and_tx_stats_of_anon_member_of_ethtool_ts_stats anon0$0;

    @InlineUnion(27409)
    public anon_member_of_anon_member_of_ethtool_ts_stats_and_tx_stats_of_anon_member_of_ethtool_ts_stats tx_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_module_eeprom"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_module_eeprom extends Struct {
    public @Unsigned int offset;

    public @Unsigned int length;

    public char page;

    public char bank;

    public char i2c_address;

    public Ptr<java.lang.Character> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_module_power_mode_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_module_power_mode_params extends Struct {
    public ethtool_module_power_mode_policy policy;

    public ethtool_module_power_mode mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_mm_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_mm_state extends Struct {
    public @Unsigned int verify_time;

    public @Unsigned int max_verify_time;

    public ethtool_mm_verify_status verify_status;

    public boolean tx_enabled;

    public boolean tx_active;

    public boolean pmac_enabled;

    public boolean verify_enabled;

    public @Unsigned int tx_min_frag_size;

    public @Unsigned int rx_min_frag_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_mm_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_mm_cfg extends Struct {
    public @Unsigned int verify_time;

    public boolean verify_enabled;

    public boolean tx_enabled;

    public boolean pmac_enabled;

    public @Unsigned int tx_min_frag_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_mm_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_mm_stats extends Struct {
    public @Unsigned long MACMergeFrameAssErrorCount;

    public @Unsigned long MACMergeFrameSmdErrorCount;

    public @Unsigned long MACMergeFrameAssOkCount;

    public @Unsigned long MACMergeFragCountRx;

    public @Unsigned long MACMergeFragCountTx;

    public @Unsigned long MACMergeHoldCount;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rxfh_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rxfh_param extends Struct {
    public char hfunc;

    public @Unsigned int indir_size;

    public Ptr<java.lang. @Unsigned Integer> indir;

    public @Unsigned int key_size;

    public Ptr<java.lang.Character> key;

    public @Unsigned int rss_context;

    public char rss_delete;

    public char input_xfrm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rxfh_fields"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rxfh_fields extends Struct {
    public @Unsigned int data;

    public @Unsigned int flow_type;

    public @Unsigned int rss_context;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_phy_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_phy_stats extends Struct {
    public @Unsigned long rx_packets;

    public @Unsigned long rx_bytes;

    public @Unsigned long rx_errors;

    public @Unsigned long tx_packets;

    public @Unsigned long tx_bytes;

    public @Unsigned long tx_errors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_phy_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_phy_ops extends Struct {
    public Ptr<?> get_sset_count;

    public Ptr<?> get_strings;

    public Ptr<?> get_stats;

    public Ptr<?> get_plca_cfg;

    public Ptr<?> set_plca_cfg;

    public Ptr<?> get_plca_status;

    public Ptr<?> start_cable_test;

    public Ptr<?> start_cable_test_tdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_state"
  )
  public enum ethtool_c33_pse_ext_state implements Enum<ethtool_c33_pse_ext_state>, TypedEnum<ethtool_c33_pse_ext_state, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION"
    )
    ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID"
    )
    ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE"
    )
    ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED"
    )
    ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM"
    )
    ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED"
    )
    ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE"
    )
    ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE"
    )
    ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED"
    )
    ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_substate_error_condition"
  )
  public enum ethtool_c33_pse_ext_substate_error_condition implements Enum<ethtool_c33_pse_ext_substate_error_condition>, TypedEnum<ethtool_c33_pse_ext_substate_error_condition, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_substate_mr_pse_enable"
  )
  public enum ethtool_c33_pse_ext_substate_mr_pse_enable implements Enum<ethtool_c33_pse_ext_substate_mr_pse_enable>, TypedEnum<ethtool_c33_pse_ext_substate_mr_pse_enable, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_substate_option_detect_ted"
  )
  public enum ethtool_c33_pse_ext_substate_option_detect_ted implements Enum<ethtool_c33_pse_ext_substate_option_detect_ted>, TypedEnum<ethtool_c33_pse_ext_substate_option_detect_ted, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_substate_option_vport_lim"
  )
  public enum ethtool_c33_pse_ext_substate_option_vport_lim implements Enum<ethtool_c33_pse_ext_substate_option_vport_lim>, TypedEnum<ethtool_c33_pse_ext_substate_option_vport_lim, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_substate_ovld_detected"
  )
  public enum ethtool_c33_pse_ext_substate_ovld_detected implements Enum<ethtool_c33_pse_ext_substate_ovld_detected>, TypedEnum<ethtool_c33_pse_ext_substate_ovld_detected, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_substate_power_not_available"
  )
  public enum ethtool_c33_pse_ext_substate_power_not_available implements Enum<ethtool_c33_pse_ext_substate_power_not_available>, TypedEnum<ethtool_c33_pse_ext_substate_power_not_available, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT,

    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_ext_substate_short_detected"
  )
  public enum ethtool_c33_pse_ext_substate_short_detected implements Enum<ethtool_c33_pse_ext_substate_short_detected>, TypedEnum<ethtool_c33_pse_ext_substate_short_detected, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION"
    )
    ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_pse_types"
  )
  public enum ethtool_pse_types implements Enum<ethtool_pse_types>, TypedEnum<ethtool_pse_types, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_PSE_UNKNOWN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_PSE_UNKNOWN"
    )
    ETHTOOL_PSE_UNKNOWN,

    /**
     * {@code ETHTOOL_PSE_PODL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_PSE_PODL"
    )
    ETHTOOL_PSE_PODL,

    /**
     * {@code ETHTOOL_PSE_C33 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_PSE_C33"
    )
    ETHTOOL_PSE_C33
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_admin_state"
  )
  public enum ethtool_c33_pse_admin_state implements Enum<ethtool_c33_pse_admin_state>, TypedEnum<ethtool_c33_pse_admin_state, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN"
    )
    ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN,

    /**
     * {@code ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED"
    )
    ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED,

    /**
     * {@code ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED"
    )
    ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_c33_pse_pw_d_status"
  )
  public enum ethtool_c33_pse_pw_d_status implements Enum<ethtool_c33_pse_pw_d_status>, TypedEnum<ethtool_c33_pse_pw_d_status, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN"
    )
    ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN,

    /**
     * {@code ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED"
    )
    ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED,

    /**
     * {@code ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING"
    )
    ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING,

    /**
     * {@code ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING"
    )
    ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING,

    /**
     * {@code ETHTOOL_C33_PSE_PW_D_STATUS_TEST = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_C33_PSE_PW_D_STATUS_TEST"
    )
    ETHTOOL_C33_PSE_PW_D_STATUS_TEST,

    /**
     * {@code ETHTOOL_C33_PSE_PW_D_STATUS_FAULT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETHTOOL_C33_PSE_PW_D_STATUS_FAULT"
    )
    ETHTOOL_C33_PSE_PW_D_STATUS_FAULT,

    /**
     * {@code ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT"
    )
    ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_podl_pse_admin_state"
  )
  public enum ethtool_podl_pse_admin_state implements Enum<ethtool_podl_pse_admin_state>, TypedEnum<ethtool_podl_pse_admin_state, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_PODL_PSE_ADMIN_STATE_UNKNOWN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_PODL_PSE_ADMIN_STATE_UNKNOWN"
    )
    ETHTOOL_PODL_PSE_ADMIN_STATE_UNKNOWN,

    /**
     * {@code ETHTOOL_PODL_PSE_ADMIN_STATE_DISABLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_PODL_PSE_ADMIN_STATE_DISABLED"
    )
    ETHTOOL_PODL_PSE_ADMIN_STATE_DISABLED,

    /**
     * {@code ETHTOOL_PODL_PSE_ADMIN_STATE_ENABLED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_PODL_PSE_ADMIN_STATE_ENABLED"
    )
    ETHTOOL_PODL_PSE_ADMIN_STATE_ENABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_podl_pse_pw_d_status"
  )
  public enum ethtool_podl_pse_pw_d_status implements Enum<ethtool_podl_pse_pw_d_status>, TypedEnum<ethtool_podl_pse_pw_d_status, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_PODL_PSE_PW_D_STATUS_UNKNOWN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_PODL_PSE_PW_D_STATUS_UNKNOWN"
    )
    ETHTOOL_PODL_PSE_PW_D_STATUS_UNKNOWN,

    /**
     * {@code ETHTOOL_PODL_PSE_PW_D_STATUS_DISABLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_PODL_PSE_PW_D_STATUS_DISABLED"
    )
    ETHTOOL_PODL_PSE_PW_D_STATUS_DISABLED,

    /**
     * {@code ETHTOOL_PODL_PSE_PW_D_STATUS_SEARCHING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_PODL_PSE_PW_D_STATUS_SEARCHING"
    )
    ETHTOOL_PODL_PSE_PW_D_STATUS_SEARCHING,

    /**
     * {@code ETHTOOL_PODL_PSE_PW_D_STATUS_DELIVERING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_PODL_PSE_PW_D_STATUS_DELIVERING"
    )
    ETHTOOL_PODL_PSE_PW_D_STATUS_DELIVERING,

    /**
     * {@code ETHTOOL_PODL_PSE_PW_D_STATUS_SLEEP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_PODL_PSE_PW_D_STATUS_SLEEP"
    )
    ETHTOOL_PODL_PSE_PW_D_STATUS_SLEEP,

    /**
     * {@code ETHTOOL_PODL_PSE_PW_D_STATUS_IDLE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETHTOOL_PODL_PSE_PW_D_STATUS_IDLE"
    )
    ETHTOOL_PODL_PSE_PW_D_STATUS_IDLE,

    /**
     * {@code ETHTOOL_PODL_PSE_PW_D_STATUS_ERROR = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ETHTOOL_PODL_PSE_PW_D_STATUS_ERROR"
    )
    ETHTOOL_PODL_PSE_PW_D_STATUS_ERROR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_pse_event"
  )
  public enum ethtool_pse_event implements Enum<ethtool_pse_event>, TypedEnum<ethtool_pse_event, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_PSE_EVENT_OVER_CURRENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_PSE_EVENT_OVER_CURRENT"
    )
    ETHTOOL_PSE_EVENT_OVER_CURRENT,

    /**
     * {@code ETHTOOL_PSE_EVENT_OVER_TEMP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_PSE_EVENT_OVER_TEMP"
    )
    ETHTOOL_PSE_EVENT_OVER_TEMP,

    /**
     * {@code ETHTOOL_C33_PSE_EVENT_DETECTION = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_C33_PSE_EVENT_DETECTION"
    )
    ETHTOOL_C33_PSE_EVENT_DETECTION,

    /**
     * {@code ETHTOOL_C33_PSE_EVENT_CLASSIFICATION = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETHTOOL_C33_PSE_EVENT_CLASSIFICATION"
    )
    ETHTOOL_C33_PSE_EVENT_CLASSIFICATION,

    /**
     * {@code ETHTOOL_C33_PSE_EVENT_DISCONNECTION = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ETHTOOL_C33_PSE_EVENT_DISCONNECTION"
    )
    ETHTOOL_C33_PSE_EVENT_DISCONNECTION,

    /**
     * {@code ETHTOOL_PSE_EVENT_OVER_BUDGET = 32}
     */
    @EnumMember(
        value = 32L,
        name = "ETHTOOL_PSE_EVENT_OVER_BUDGET"
    )
    ETHTOOL_PSE_EVENT_OVER_BUDGET,

    /**
     * {@code ETHTOOL_PSE_EVENT_SW_PW_CONTROL_ERROR = 64}
     */
    @EnumMember(
        value = 64L,
        name = "ETHTOOL_PSE_EVENT_SW_PW_CONTROL_ERROR"
    )
    ETHTOOL_PSE_EVENT_SW_PW_CONTROL_ERROR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_c33_pse_ext_state_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_c33_pse_ext_state_info extends Struct {
    public ethtool_c33_pse_ext_state c33_pse_ext_state;

    @InlineUnion(50527)
    public ethtool_c33_pse_ext_substate_error_condition error_condition;

    @InlineUnion(50527)
    public ethtool_c33_pse_ext_substate_mr_pse_enable mr_pse_enable;

    @InlineUnion(50527)
    public ethtool_c33_pse_ext_substate_option_detect_ted option_detect_ted;

    @InlineUnion(50527)
    public ethtool_c33_pse_ext_substate_option_vport_lim option_vport_lim;

    @InlineUnion(50527)
    public ethtool_c33_pse_ext_substate_ovld_detected ovld_detected;

    @InlineUnion(50527)
    public ethtool_c33_pse_ext_substate_power_not_available power_not_available;

    @InlineUnion(50527)
    public ethtool_c33_pse_ext_substate_short_detected short_detected;

    @InlineUnion(50527)
    public @Unsigned int __c33_pse_ext_substate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_c33_pse_pw_limit_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_c33_pse_pw_limit_range extends Struct {
    public @Unsigned int min;

    public @Unsigned int max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_pse_control_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_pse_control_status extends Struct {
    public @Unsigned int pw_d_id;

    public ethtool_podl_pse_admin_state podl_admin_state;

    public ethtool_podl_pse_pw_d_status podl_pw_status;

    public ethtool_c33_pse_admin_state c33_admin_state;

    public ethtool_c33_pse_pw_d_status c33_pw_status;

    public @Unsigned int c33_pw_class;

    public @Unsigned int c33_actual_pw;

    public ethtool_c33_pse_ext_state_info c33_ext_state_info;

    public @Unsigned int c33_avail_pw_limit;

    public Ptr<ethtool_c33_pse_pw_limit_range> c33_pw_limit_ranges;

    public @Unsigned int c33_pw_limit_nb_ranges;

    public @Unsigned int prio_max;

    public @Unsigned int prio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_stringset"
  )
  public enum ethtool_stringset implements Enum<ethtool_stringset>, TypedEnum<ethtool_stringset, java.lang. @Unsigned Integer> {
    /**
     * {@code ETH_SS_TEST = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETH_SS_TEST"
    )
    ETH_SS_TEST,

    /**
     * {@code ETH_SS_STATS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETH_SS_STATS"
    )
    ETH_SS_STATS,

    /**
     * {@code ETH_SS_PRIV_FLAGS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETH_SS_PRIV_FLAGS"
    )
    ETH_SS_PRIV_FLAGS,

    /**
     * {@code ETH_SS_NTUPLE_FILTERS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETH_SS_NTUPLE_FILTERS"
    )
    ETH_SS_NTUPLE_FILTERS,

    /**
     * {@code ETH_SS_FEATURES = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETH_SS_FEATURES"
    )
    ETH_SS_FEATURES,

    /**
     * {@code ETH_SS_RSS_HASH_FUNCS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETH_SS_RSS_HASH_FUNCS"
    )
    ETH_SS_RSS_HASH_FUNCS,

    /**
     * {@code ETH_SS_TUNABLES = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ETH_SS_TUNABLES"
    )
    ETH_SS_TUNABLES,

    /**
     * {@code ETH_SS_PHY_STATS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ETH_SS_PHY_STATS"
    )
    ETH_SS_PHY_STATS,

    /**
     * {@code ETH_SS_PHY_TUNABLES = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETH_SS_PHY_TUNABLES"
    )
    ETH_SS_PHY_TUNABLES,

    /**
     * {@code ETH_SS_LINK_MODES = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ETH_SS_LINK_MODES"
    )
    ETH_SS_LINK_MODES,

    /**
     * {@code ETH_SS_MSG_CLASSES = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ETH_SS_MSG_CLASSES"
    )
    ETH_SS_MSG_CLASSES,

    /**
     * {@code ETH_SS_WOL_MODES = 11}
     */
    @EnumMember(
        value = 11L,
        name = "ETH_SS_WOL_MODES"
    )
    ETH_SS_WOL_MODES,

    /**
     * {@code ETH_SS_SOF_TIMESTAMPING = 12}
     */
    @EnumMember(
        value = 12L,
        name = "ETH_SS_SOF_TIMESTAMPING"
    )
    ETH_SS_SOF_TIMESTAMPING,

    /**
     * {@code ETH_SS_TS_TX_TYPES = 13}
     */
    @EnumMember(
        value = 13L,
        name = "ETH_SS_TS_TX_TYPES"
    )
    ETH_SS_TS_TX_TYPES,

    /**
     * {@code ETH_SS_TS_RX_FILTERS = 14}
     */
    @EnumMember(
        value = 14L,
        name = "ETH_SS_TS_RX_FILTERS"
    )
    ETH_SS_TS_RX_FILTERS,

    /**
     * {@code ETH_SS_UDP_TUNNEL_TYPES = 15}
     */
    @EnumMember(
        value = 15L,
        name = "ETH_SS_UDP_TUNNEL_TYPES"
    )
    ETH_SS_UDP_TUNNEL_TYPES,

    /**
     * {@code ETH_SS_STATS_STD = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ETH_SS_STATS_STD"
    )
    ETH_SS_STATS_STD,

    /**
     * {@code ETH_SS_STATS_ETH_PHY = 17}
     */
    @EnumMember(
        value = 17L,
        name = "ETH_SS_STATS_ETH_PHY"
    )
    ETH_SS_STATS_ETH_PHY,

    /**
     * {@code ETH_SS_STATS_ETH_MAC = 18}
     */
    @EnumMember(
        value = 18L,
        name = "ETH_SS_STATS_ETH_MAC"
    )
    ETH_SS_STATS_ETH_MAC,

    /**
     * {@code ETH_SS_STATS_ETH_CTRL = 19}
     */
    @EnumMember(
        value = 19L,
        name = "ETH_SS_STATS_ETH_CTRL"
    )
    ETH_SS_STATS_ETH_CTRL,

    /**
     * {@code ETH_SS_STATS_RMON = 20}
     */
    @EnumMember(
        value = 20L,
        name = "ETH_SS_STATS_RMON"
    )
    ETH_SS_STATS_RMON,

    /**
     * {@code ETH_SS_STATS_PHY = 21}
     */
    @EnumMember(
        value = 21L,
        name = "ETH_SS_STATS_PHY"
    )
    ETH_SS_STATS_PHY,

    /**
     * {@code ETH_SS_TS_FLAGS = 22}
     */
    @EnumMember(
        value = 22L,
        name = "ETH_SS_TS_FLAGS"
    )
    ETH_SS_TS_FLAGS,

    /**
     * {@code ETH_SS_COUNT = 23}
     */
    @EnumMember(
        value = 23L,
        name = "ETH_SS_COUNT"
    )
    ETH_SS_COUNT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_tcp_data_split"
  )
  public enum ethtool_tcp_data_split implements Enum<ethtool_tcp_data_split>, TypedEnum<ethtool_tcp_data_split, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_TCP_DATA_SPLIT_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_TCP_DATA_SPLIT_UNKNOWN"
    )
    ETHTOOL_TCP_DATA_SPLIT_UNKNOWN,

    /**
     * {@code ETHTOOL_TCP_DATA_SPLIT_DISABLED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_TCP_DATA_SPLIT_DISABLED"
    )
    ETHTOOL_TCP_DATA_SPLIT_DISABLED,

    /**
     * {@code ETHTOOL_TCP_DATA_SPLIT_ENABLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_TCP_DATA_SPLIT_ENABLED"
    )
    ETHTOOL_TCP_DATA_SPLIT_ENABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_test_flags"
  )
  public enum ethtool_test_flags implements Enum<ethtool_test_flags>, TypedEnum<ethtool_test_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code ETH_TEST_FL_OFFLINE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETH_TEST_FL_OFFLINE"
    )
    ETH_TEST_FL_OFFLINE,

    /**
     * {@code ETH_TEST_FL_FAILED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETH_TEST_FL_FAILED"
    )
    ETH_TEST_FL_FAILED,

    /**
     * {@code ETH_TEST_FL_EXTERNAL_LB = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETH_TEST_FL_EXTERNAL_LB"
    )
    ETH_TEST_FL_EXTERNAL_LB,

    /**
     * {@code ETH_TEST_FL_EXTERNAL_LB_DONE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETH_TEST_FL_EXTERNAL_LB_DONE"
    )
    ETH_TEST_FL_EXTERNAL_LB_DONE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_cmd extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int supported;

    public @Unsigned int advertising;

    public @Unsigned short speed;

    public char duplex;

    public char port;

    public char phy_address;

    public char transceiver;

    public char autoneg;

    public char mdio_support;

    public @Unsigned int maxtxpkt;

    public @Unsigned int maxrxpkt;

    public @Unsigned short speed_hi;

    public char eth_tp_mdix;

    public char eth_tp_mdix_ctrl;

    public @Unsigned int lp_advertising;

    public @Unsigned int @Size(2) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_value"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_value extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_eee"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_eee extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int supported;

    public @Unsigned int advertised;

    public @Unsigned int lp_advertised;

    public @Unsigned int eee_active;

    public @Unsigned int eee_enabled;

    public @Unsigned int tx_lpi_enabled;

    public @Unsigned int tx_lpi_timer;

    public @Unsigned int @Size(2) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_gstrings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_gstrings extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int string_set;

    public @Unsigned int len;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_sset_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_sset_info extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int reserved;

    public @Unsigned long sset_mask;

    public @Unsigned int @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_perm_addr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_perm_addr extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int size;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_flags"
  )
  public enum ethtool_flags implements Enum<ethtool_flags>, TypedEnum<ethtool_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code ETH_FLAG_TXVLAN = 128}
     */
    @EnumMember(
        value = 128L,
        name = "ETH_FLAG_TXVLAN"
    )
    ETH_FLAG_TXVLAN,

    /**
     * {@code ETH_FLAG_RXVLAN = 256}
     */
    @EnumMember(
        value = 256L,
        name = "ETH_FLAG_RXVLAN"
    )
    ETH_FLAG_RXVLAN,

    /**
     * {@code ETH_FLAG_LRO = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "ETH_FLAG_LRO"
    )
    ETH_FLAG_LRO,

    /**
     * {@code ETH_FLAG_NTUPLE = 134217728}
     */
    @EnumMember(
        value = 134217728L,
        name = "ETH_FLAG_NTUPLE"
    )
    ETH_FLAG_NTUPLE,

    /**
     * {@code ETH_FLAG_RXHASH = 268435456}
     */
    @EnumMember(
        value = 268435456L,
        name = "ETH_FLAG_RXHASH"
    )
    ETH_FLAG_RXHASH
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rxfh"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rxfh extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int rss_context;

    public @Unsigned int indir_size;

    public @Unsigned int key_size;

    public char hfunc;

    public char input_xfrm;

    public char @Size(2) [] rsvd8;

    public @Unsigned int rsvd32;

    public @Unsigned int @Size(0) [] rss_config;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_get_features_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_get_features_block extends Struct {
    public @Unsigned int available;

    public @Unsigned int requested;

    public @Unsigned int active;

    public @Unsigned int never_changed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_gfeatures"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_gfeatures extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int size;

    public ethtool_get_features_block @Size(0) [] features;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_set_features_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_set_features_block extends Struct {
    public @Unsigned int valid;

    public @Unsigned int requested;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_sfeatures"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_sfeatures extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int size;

    public ethtool_set_features_block @Size(0) [] features;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_ts_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_ts_info extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int so_timestamping;

    public int phc_index;

    public @Unsigned int tx_types;

    public @Unsigned int @Size(3) [] tx_reserved;

    public @Unsigned int rx_filters;

    public @Unsigned int @Size(3) [] rx_reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_sfeatures_retval_bits"
  )
  public enum ethtool_sfeatures_retval_bits implements Enum<ethtool_sfeatures_retval_bits>, TypedEnum<ethtool_sfeatures_retval_bits, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_F_UNSUPPORTED__BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_F_UNSUPPORTED__BIT"
    )
    ETHTOOL_F_UNSUPPORTED__BIT,

    /**
     * {@code ETHTOOL_F_WISH__BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_F_WISH__BIT"
    )
    ETHTOOL_F_WISH__BIT,

    /**
     * {@code ETHTOOL_F_COMPAT__BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_F_COMPAT__BIT"
    )
    ETHTOOL_F_COMPAT__BIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_per_queue_op"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_per_queue_op extends Struct {
    public @Unsigned int cmd;

    public @Unsigned int sub_command;

    public @Unsigned int @Size(128) [] queue_mask;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_fec_config_bits"
  )
  public enum ethtool_fec_config_bits implements Enum<ethtool_fec_config_bits>, TypedEnum<ethtool_fec_config_bits, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_FEC_NONE_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_FEC_NONE_BIT"
    )
    ETHTOOL_FEC_NONE_BIT,

    /**
     * {@code ETHTOOL_FEC_AUTO_BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_FEC_AUTO_BIT"
    )
    ETHTOOL_FEC_AUTO_BIT,

    /**
     * {@code ETHTOOL_FEC_OFF_BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_FEC_OFF_BIT"
    )
    ETHTOOL_FEC_OFF_BIT,

    /**
     * {@code ETHTOOL_FEC_RS_BIT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_FEC_RS_BIT"
    )
    ETHTOOL_FEC_RS_BIT,

    /**
     * {@code ETHTOOL_FEC_BASER_BIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_FEC_BASER_BIT"
    )
    ETHTOOL_FEC_BASER_BIT,

    /**
     * {@code ETHTOOL_FEC_LLRS_BIT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ETHTOOL_FEC_LLRS_BIT"
    )
    ETHTOOL_FEC_LLRS_BIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rx_flow_rule"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rx_flow_rule extends Struct {
    public Ptr<flow_rule> rule;

    public @Unsigned long @Size(0) [] priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rx_flow_spec_input"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rx_flow_spec_input extends Struct {
    public Ptr<ethtool_rx_flow_spec> fs;

    public @Unsigned int rss_ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_devlink_compat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_devlink_compat extends Struct {
    public Ptr<devlink> devlink;

    @InlineUnion(60932)
    public ethtool_flash efl;

    @InlineUnion(60932)
    public ethtool_drvinfo info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_link_usettings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_link_usettings extends Struct {
    public ethtool_link_settings base;

    public link_modes_of_ethtool_link_usettings link_modes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rx_flow_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rx_flow_key extends Struct {
    public flow_dissector_key_basic basic;

    @InlineUnion(60948)
    public flow_dissector_key_ipv4_addrs ipv4;

    @InlineUnion(60948)
    public flow_dissector_key_ipv6_addrs ipv6;

    public flow_dissector_key_ports tp;

    public flow_dissector_key_ip ip;

    public flow_dissector_key_vlan vlan;

    public flow_dissector_key_eth_addrs eth_addrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_rx_flow_match"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_rx_flow_match extends Struct {
    public flow_dissector dissector;

    public ethtool_rx_flow_key key;

    public ethtool_rx_flow_key mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_forced_speed_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_forced_speed_map extends Struct {
    public @Unsigned int speed;

    public @Unsigned long @Size(2) [] caps;

    public Ptr<java.lang. @Unsigned Integer> cap_arr;

    public @Unsigned int arr_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_header_flags"
  )
  public enum ethtool_header_flags implements Enum<ethtool_header_flags>, TypedEnum<ethtool_header_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_FLAG_COMPACT_BITSETS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_FLAG_COMPACT_BITSETS"
    )
    ETHTOOL_FLAG_COMPACT_BITSETS,

    /**
     * {@code ETHTOOL_FLAG_OMIT_REPLY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_FLAG_OMIT_REPLY"
    )
    ETHTOOL_FLAG_OMIT_REPLY,

    /**
     * {@code ETHTOOL_FLAG_STATS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_FLAG_STATS"
    )
    ETHTOOL_FLAG_STATS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_multicast_groups"
  )
  public enum ethtool_multicast_groups implements Enum<ethtool_multicast_groups>, TypedEnum<ethtool_multicast_groups, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHNL_MCGRP_MONITOR = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHNL_MCGRP_MONITOR"
    )
    ETHNL_MCGRP_MONITOR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_supported_ring_param"
  )
  public enum ethtool_supported_ring_param implements Enum<ethtool_supported_ring_param>, TypedEnum<ethtool_supported_ring_param, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_RING_USE_RX_BUF_LEN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_RING_USE_RX_BUF_LEN"
    )
    ETHTOOL_RING_USE_RX_BUF_LEN,

    /**
     * {@code ETHTOOL_RING_USE_CQE_SIZE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_RING_USE_CQE_SIZE"
    )
    ETHTOOL_RING_USE_CQE_SIZE,

    /**
     * {@code ETHTOOL_RING_USE_TX_PUSH = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_RING_USE_TX_PUSH"
    )
    ETHTOOL_RING_USE_TX_PUSH,

    /**
     * {@code ETHTOOL_RING_USE_RX_PUSH = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETHTOOL_RING_USE_RX_PUSH"
    )
    ETHTOOL_RING_USE_RX_PUSH,

    /**
     * {@code ETHTOOL_RING_USE_TX_PUSH_BUF_LEN = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ETHTOOL_RING_USE_TX_PUSH_BUF_LEN"
    )
    ETHTOOL_RING_USE_TX_PUSH_BUF_LEN,

    /**
     * {@code ETHTOOL_RING_USE_TCP_DATA_SPLIT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "ETHTOOL_RING_USE_TCP_DATA_SPLIT"
    )
    ETHTOOL_RING_USE_TCP_DATA_SPLIT,

    /**
     * {@code ETHTOOL_RING_USE_HDS_THRS = 64}
     */
    @EnumMember(
        value = 64L,
        name = "ETHTOOL_RING_USE_HDS_THRS"
    )
    ETHTOOL_RING_USE_HDS_THRS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_mmsv_event"
  )
  public enum ethtool_mmsv_event implements Enum<ethtool_mmsv_event>, TypedEnum<ethtool_mmsv_event, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_MMSV_LP_SENT_VERIFY_MPACKET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_MMSV_LP_SENT_VERIFY_MPACKET"
    )
    ETHTOOL_MMSV_LP_SENT_VERIFY_MPACKET,

    /**
     * {@code ETHTOOL_MMSV_LD_SENT_VERIFY_MPACKET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_MMSV_LD_SENT_VERIFY_MPACKET"
    )
    ETHTOOL_MMSV_LD_SENT_VERIFY_MPACKET,

    /**
     * {@code ETHTOOL_MMSV_LP_SENT_RESPONSE_MPACKET = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_MMSV_LP_SENT_RESPONSE_MPACKET"
    )
    ETHTOOL_MMSV_LP_SENT_RESPONSE_MPACKET
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_mpacket"
  )
  public enum ethtool_mpacket implements Enum<ethtool_mpacket>, TypedEnum<ethtool_mpacket, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_MPACKET_VERIFY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_MPACKET_VERIFY"
    )
    ETHTOOL_MPACKET_VERIFY,

    /**
     * {@code ETHTOOL_MPACKET_RESPONSE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_MPACKET_RESPONSE"
    )
    ETHTOOL_MPACKET_RESPONSE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_mmsv_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_mmsv_ops extends Struct {
    public Ptr<?> configure_tx;

    public Ptr<?> configure_pmac;

    public Ptr<?> send_mpacket;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_mmsv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_mmsv extends Struct {
    public Ptr<ethtool_mmsv_ops> ops;

    public Ptr<net_device> dev;

    public @OriginalName("spinlock_t") spinlock lock;

    public ethtool_mm_verify_status status;

    public timer_list verify_timer;

    public boolean verify_enabled;

    public int verify_retries;

    public boolean pmac_enabled;

    public @Unsigned int verify_time;

    public boolean tx_enabled;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_module_fw_flash_status"
  )
  public enum ethtool_module_fw_flash_status implements Enum<ethtool_module_fw_flash_status>, TypedEnum<ethtool_module_fw_flash_status, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED"
    )
    ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED,

    /**
     * {@code ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS"
    )
    ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS,

    /**
     * {@code ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED"
    )
    ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED,

    /**
     * {@code ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR"
    )
    ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_module_fw_flash_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_module_fw_flash_params extends Struct {
    public @Unsigned @OriginalName("__be32") int password;

    public char password_valid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_cmis_fw_update_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_cmis_fw_update_params extends Struct {
    public Ptr<net_device> dev;

    public ethtool_module_fw_flash_params params;

    public ethnl_module_fw_flash_ntf_params ntf_params;

    public Ptr<firmware> fw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_module_fw_flash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_module_fw_flash extends Struct {
    public list_head list;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public work_struct work;

    public ethtool_cmis_fw_update_params fw_update;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_reset_flags"
  )
  public enum ethtool_reset_flags implements Enum<ethtool_reset_flags>, TypedEnum<ethtool_reset_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code ETH_RESET_MGMT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ETH_RESET_MGMT"
    )
    ETH_RESET_MGMT,

    /**
     * {@code ETH_RESET_IRQ = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ETH_RESET_IRQ"
    )
    ETH_RESET_IRQ,

    /**
     * {@code ETH_RESET_DMA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ETH_RESET_DMA"
    )
    ETH_RESET_DMA,

    /**
     * {@code ETH_RESET_FILTER = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ETH_RESET_FILTER"
    )
    ETH_RESET_FILTER,

    /**
     * {@code ETH_RESET_OFFLOAD = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ETH_RESET_OFFLOAD"
    )
    ETH_RESET_OFFLOAD,

    /**
     * {@code ETH_RESET_MAC = 32}
     */
    @EnumMember(
        value = 32L,
        name = "ETH_RESET_MAC"
    )
    ETH_RESET_MAC,

    /**
     * {@code ETH_RESET_PHY = 64}
     */
    @EnumMember(
        value = 64L,
        name = "ETH_RESET_PHY"
    )
    ETH_RESET_PHY,

    /**
     * {@code ETH_RESET_RAM = 128}
     */
    @EnumMember(
        value = 128L,
        name = "ETH_RESET_RAM"
    )
    ETH_RESET_RAM,

    /**
     * {@code ETH_RESET_AP = 256}
     */
    @EnumMember(
        value = 256L,
        name = "ETH_RESET_AP"
    )
    ETH_RESET_AP,

    /**
     * {@code ETH_RESET_DEDICATED = 65535}
     */
    @EnumMember(
        value = 65535L,
        name = "ETH_RESET_DEDICATED"
    )
    ETH_RESET_DEDICATED,

    /**
     * {@code ETH_RESET_ALL = -1}
     */
    @EnumMember(
        value = -1L,
        name = "ETH_RESET_ALL"
    )
    ETH_RESET_ALL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_cmis_cdb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_cmis_cdb extends Struct {
    public char cmis_rev;

    public char read_write_len_ext;

    public @Unsigned short max_completion_time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ethtool_cmis_cdb_cmd_id"
  )
  public enum ethtool_cmis_cdb_cmd_id implements Enum<ethtool_cmis_cdb_cmd_id>, TypedEnum<ethtool_cmis_cdb_cmd_id, java.lang. @Unsigned Integer> {
    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_QUERY_STATUS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ETHTOOL_CMIS_CDB_CMD_QUERY_STATUS"
    )
    ETHTOOL_CMIS_CDB_CMD_QUERY_STATUS,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_MODULE_FEATURES = 64}
     */
    @EnumMember(
        value = 64L,
        name = "ETHTOOL_CMIS_CDB_CMD_MODULE_FEATURES"
    )
    ETHTOOL_CMIS_CDB_CMD_MODULE_FEATURES,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_FW_MANAGMENT_FEATURES = 65}
     */
    @EnumMember(
        value = 65L,
        name = "ETHTOOL_CMIS_CDB_CMD_FW_MANAGMENT_FEATURES"
    )
    ETHTOOL_CMIS_CDB_CMD_FW_MANAGMENT_FEATURES,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_START_FW_DOWNLOAD = 257}
     */
    @EnumMember(
        value = 257L,
        name = "ETHTOOL_CMIS_CDB_CMD_START_FW_DOWNLOAD"
    )
    ETHTOOL_CMIS_CDB_CMD_START_FW_DOWNLOAD,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_WRITE_FW_BLOCK_LPL = 259}
     */
    @EnumMember(
        value = 259L,
        name = "ETHTOOL_CMIS_CDB_CMD_WRITE_FW_BLOCK_LPL"
    )
    ETHTOOL_CMIS_CDB_CMD_WRITE_FW_BLOCK_LPL,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_WRITE_FW_BLOCK_EPL = 260}
     */
    @EnumMember(
        value = 260L,
        name = "ETHTOOL_CMIS_CDB_CMD_WRITE_FW_BLOCK_EPL"
    )
    ETHTOOL_CMIS_CDB_CMD_WRITE_FW_BLOCK_EPL,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_COMPLETE_FW_DOWNLOAD = 263}
     */
    @EnumMember(
        value = 263L,
        name = "ETHTOOL_CMIS_CDB_CMD_COMPLETE_FW_DOWNLOAD"
    )
    ETHTOOL_CMIS_CDB_CMD_COMPLETE_FW_DOWNLOAD,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_RUN_FW_IMAGE = 265}
     */
    @EnumMember(
        value = 265L,
        name = "ETHTOOL_CMIS_CDB_CMD_RUN_FW_IMAGE"
    )
    ETHTOOL_CMIS_CDB_CMD_RUN_FW_IMAGE,

    /**
     * {@code ETHTOOL_CMIS_CDB_CMD_COMMIT_FW_IMAGE = 266}
     */
    @EnumMember(
        value = 266L,
        name = "ETHTOOL_CMIS_CDB_CMD_COMMIT_FW_IMAGE"
    )
    ETHTOOL_CMIS_CDB_CMD_COMMIT_FW_IMAGE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_cmis_cdb_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_cmis_cdb_request extends Struct {
    public @Unsigned @OriginalName("__be16") short id;

    @InlineUnion(61324)
    public anon_member_of_anon_member_of_ethtool_cmis_cdb_request_and_body_of_anon_member_of_ethtool_cmis_cdb_request anon1$0;

    @InlineUnion(61324)
    public anon_member_of_anon_member_of_ethtool_cmis_cdb_request_and_body_of_anon_member_of_ethtool_cmis_cdb_request body;

    public Ptr<java.lang.Character> epl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_cmis_cdb_cmd_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_cmis_cdb_cmd_args extends Struct {
    public ethtool_cmis_cdb_request req;

    public @Unsigned short max_duration;

    public char read_write_len_ext;

    public char msleep_pre_rpl;

    public char rpl_exp_len;

    public char flags;

    public String err_msg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_cmis_cdb_rpl_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_cmis_cdb_rpl_hdr extends Struct {
    public char rpl_len;

    public char rpl_chk_code;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethtool_cmis_cdb_rpl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethtool_cmis_cdb_rpl extends Struct {
    public ethtool_cmis_cdb_rpl_hdr hdr;

    public char @Size(120) [] payload;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ethhdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ethhdr extends Struct {
    public char @Size(6) [] h_dest;

    public char @Size(6) [] h_source;

    public @Unsigned @OriginalName("__be16") short h_proto;
  }
}
