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
 * Generated class for BPF runtime types that start with fuse
 */
@java.lang.SuppressWarnings("unused")
public final class FuseDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long __fuse_copy_file_range(Ptr<file> file_in,
      @OriginalName("loff_t") long pos_in, Ptr<file> file_out, @OriginalName("loff_t") long pos_out,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int __fuse_dax_fault(Ptr<vm_fault> vmf,
      @Unsigned int order, boolean write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<posix_acl> __fuse_get_acl(Ptr<fuse_conn> fc, Ptr<inode> inode, int type,
      boolean rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long __fuse_simple_request(Ptr<mnt_idmap> idmap,
      Ptr<fuse_mount> fm, Ptr<fuse_args> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_abort_conn(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_access(Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_add_dirent_to_cache(Ptr<file> file, Ptr<fuse_dirent> dirent,
      @OriginalName("loff_t") long pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_aio_complete(Ptr<fuse_io_priv> io, int err,
      @OriginalName("ssize_t") long pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_aio_complete_req(Ptr<fuse_mount> fm, Ptr<fuse_args> args, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_forget_link> fuse_alloc_forget() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> fuse_alloc_inode(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_allow_current_process(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_args_to_req(Ptr<fuse_req> req, Ptr<fuse_args> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_async_req_send(Ptr<fuse_mount> fm,
      Ptr<fuse_io_args> ia, @Unsigned long num_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_atomic_open(Ptr<inode> dir, Ptr<dentry> entry, Ptr<file> file,
      @Unsigned int flags, @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_backing_close(Ptr<fuse_conn> fc, int backing_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_backing_files_free(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_backing_files_init(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_backing_free(Ptr<fuse_backing> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_backing> fuse_backing_get(Ptr<fuse_backing> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_backing_id_free(int id, Ptr<?> p, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_backing_open(Ptr<fuse_conn> fc, Ptr<fuse_backing_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_backing_put(Ptr<fuse_backing> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_block_alloc(Ptr<fuse_conn> fc, boolean for_background) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("sector_t") long fuse_bmap(Ptr<address_space> mapping,
      @Unsigned @OriginalName("sector_t") long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_cache_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_change_attributes(Ptr<inode> inode, Ptr<fuse_attr> attr,
      Ptr<fuse_statx> sx, @Unsigned long attr_valid, @Unsigned long attr_version) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_change_attributes_common(Ptr<inode> inode, Ptr<fuse_attr> attr,
      Ptr<fuse_statx> sx, @Unsigned long attr_valid, @Unsigned int cache_mask,
      @Unsigned long evict_ctr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_change_attributes_i(Ptr<inode> inode, Ptr<fuse_attr> attr,
      Ptr<fuse_statx> sx, @Unsigned long attr_valid, @Unsigned long attr_version,
      @Unsigned long evict_ctr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_change_entry_timeout(Ptr<dentry> entry, Ptr<fuse_entry_out> o) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_check_timeout(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_conn_abort_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long fuse_conn_abort_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_conn_congestion_threshold_read(Ptr<file> file,
      String buf, @Unsigned long len, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_conn_congestion_threshold_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long fuse_conn_congestion_threshold_write(Ptr<file> file,
      String buf, @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_conn_destroy(Ptr<fuse_mount> fm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_conn> fuse_conn_get(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_conn_init($arg1, $arg2, $arg3, (const struct fuse_iqueue_ops*)$arg4, $arg5)")
  public static void fuse_conn_init(Ptr<fuse_conn> fc, Ptr<fuse_mount> fm,
      Ptr<user_namespace> user_ns, Ptr<fuse_iqueue_ops> fiq_ops, Ptr<?> fiq_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_conn_max_background_read(Ptr<file> file,
      String buf, @Unsigned long len, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_conn_max_background_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long fuse_conn_max_background_write(Ptr<file> file,
      String buf, @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_conn_put(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_conn_waiting_read(Ptr<file> file, String buf,
      @Unsigned long len, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_copy_args(Ptr<fuse_copy_state> cs, @Unsigned int numargs,
      @Unsigned int argpages, Ptr<fuse_arg> args, int zeroing) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_copy_do(Ptr<fuse_copy_state> cs, Ptr<Ptr<?>> val,
      Ptr<java.lang. @Unsigned Integer> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_copy_file_range(Ptr<file> src_file,
      @OriginalName("loff_t") long src_off, Ptr<file> dst_file,
      @OriginalName("loff_t") long dst_off, @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_copy_fill(Ptr<fuse_copy_state> cs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_copy_finish(Ptr<fuse_copy_state> cs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_copy_folio(Ptr<fuse_copy_state> cs, Ptr<Ptr<folio>> foliop,
      @Unsigned int offset, @Unsigned int count, int zeroing) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_copy_init(Ptr<fuse_copy_state> cs, boolean write, Ptr<iov_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_copy_ioctl_iovec_old(Ptr<iovec> dst, Ptr<?> src,
      @Unsigned long transferred, @Unsigned int count, boolean is_compat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_copy_out_args(Ptr<fuse_copy_state> cs, Ptr<fuse_args> args,
      @Unsigned int nbytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_create(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> entry,
      @Unsigned @OriginalName("umode_t") short mode, boolean excl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_create_open(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> entry,
      Ptr<file> file, @Unsigned int flags, @Unsigned @OriginalName("umode_t") short mode,
      @Unsigned int opcode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_ctl_add_conn(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_ctl_add_dentry($arg1, $arg2, (const u8*)$arg3, $arg4, (const struct inode_operations*)$arg5, (const struct file_operations*)$arg6)")
  public static Ptr<dentry> fuse_ctl_add_dentry(Ptr<dentry> parent, Ptr<fuse_conn> fc, String name,
      int mode, Ptr<inode_operations> iop, Ptr<file_operations> fop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_ctl_cleanup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_ctl_fill_super(Ptr<super_block> sb, Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_ctl_get_tree(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_ctl_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_ctl_init_fs_context(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_ctl_kill_sb(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_ctl_remove_conn(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dax_break_layouts(Ptr<inode> inode, @Unsigned long dmap_start,
      @Unsigned long dmap_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dax_cancel_work(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_dax_check_alignment(Ptr<fuse_conn> fc, @Unsigned int map_alignment) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dax_conn_alloc(Ptr<fuse_conn> fc, fuse_dax_mode dax_mode,
      Ptr<dax_device> dax_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dax_conn_free(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dax_dontcache(Ptr<inode> inode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int fuse_dax_fault(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dax_free_mem_worker(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int fuse_dax_huge_fault(Ptr<vm_fault> vmf,
      @Unsigned int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_dax_inode_alloc(Ptr<super_block> sb, Ptr<fuse_inode> fi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dax_inode_cleanup(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dax_inode_init(Ptr<inode> inode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dax_mem_range_init(Ptr<fuse_conn_dax> fcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dax_mmap(Ptr<file> file, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int fuse_dax_page_mkwrite(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int fuse_dax_pfn_mkwrite(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dax_read_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dax_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vfsmount> fuse_dentry_automount(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_dentry_delete((const struct dentry*)$arg1)")
  public static int fuse_dentry_delete(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_dentry_revalidate($arg1, (const struct qstr*)$arg2, $arg3, $arg4)")
  public static int fuse_dentry_revalidate(Ptr<inode> dir, Ptr<qstr> name, Ptr<dentry> entry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dentry_settime(Ptr<dentry> dentry, @Unsigned long time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_dev> fuse_dev_alloc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_dev> fuse_dev_alloc_install(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_cleanup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dev_do_read(Ptr<fuse_dev> fud, Ptr<file> file,
      Ptr<fuse_copy_state> cs, @Unsigned long nbytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dev_do_write(Ptr<fuse_dev> fud,
      Ptr<fuse_copy_state> cs, @Unsigned long nbytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_end_requests(Ptr<list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dev_fasync(int fd, Ptr<file> file, int on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_free(Ptr<fuse_dev> fud) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dev_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_install(Ptr<fuse_dev> fud, Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_dev_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dev_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int fuse_dev_poll(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_queue_forget(Ptr<fuse_iqueue> fiq, Ptr<fuse_forget_link> forget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_queue_interrupt(Ptr<fuse_iqueue> fiq, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_queue_req(Ptr<fuse_iqueue> fiq, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dev_read(Ptr<kiocb> iocb, Ptr<iov_iter> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dev_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_dev_show_fdinfo(Ptr<seq_file> seq, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dev_splice_read(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<pipe_inode_info> pipe,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dev_splice_write(Ptr<pipe_inode_info> pipe,
      Ptr<file> out, Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_dev_write(Ptr<kiocb> iocb, Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_dir_compat_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dir_fsync(Ptr<file> file, @OriginalName("loff_t") long start,
      @OriginalName("loff_t") long end, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_dir_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dir_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_dir_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_direct_IO(Ptr<kiocb> iocb, Ptr<iov_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_direct_io(Ptr<fuse_io_priv> io,
      Ptr<iov_iter> iter, Ptr<java.lang. @OriginalName("loff_t") Long> ppos, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_direct_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_do_getattr(Ptr<mnt_idmap> idmap, Ptr<inode> inode, Ptr<kstat> stat,
      Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_do_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_do_open(Ptr<fuse_mount> fm, @Unsigned long nodeid, Ptr<file> file,
      boolean isdir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_do_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<iattr> attr,
      Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_do_statx(Ptr<mnt_idmap> idmap, Ptr<inode> inode, Ptr<file> file,
      Ptr<kstat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_do_truncate(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_emit(Ptr<file> file, Ptr<dir_context> ctx, Ptr<fuse_dirent> dirent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_encode_fh(Ptr<inode> inode, Ptr<java.lang. @Unsigned Integer> fh,
      Ptr<java.lang.Integer> max_len, Ptr<inode> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_entry_unlinked(Ptr<dentry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_evict_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> fuse_fh_to_dentry(Ptr<super_block> sb, Ptr<fid> fid, int fh_len,
      int fh_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> fuse_fh_to_parent(Ptr<super_block> sb, Ptr<fid> fid, int fh_len,
      int fh_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_file_accessed(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_file> fuse_file_alloc(Ptr<fuse_mount> fm, boolean release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_file_cached_io_open(Ptr<inode> inode, Ptr<fuse_file> ff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_file_compat_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_file_fallocate(Ptr<file> file, int mode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_file_flock(Ptr<file> file, int cmd, Ptr<file_lock> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_file_free(Ptr<fuse_file> ff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_file_io_open(Ptr<file> file, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_file_io_release(Ptr<fuse_file> ff, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_file_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long fuse_file_llseek(Ptr<file> file,
      @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_file_mmap(Ptr<file> file, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_file> fuse_file_open(Ptr<fuse_mount> fm, @Unsigned long nodeid,
      @Unsigned int open_flags, boolean isdir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int fuse_file_poll(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_file_put(Ptr<fuse_file> ff, boolean sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_file_read_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_file_release(Ptr<inode> inode, Ptr<fuse_file> ff,
      @Unsigned int open_flags, @OriginalName("fl_owner_t") Ptr<?> id, boolean isdir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_file_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_fileattr_get(Ptr<dentry> dentry, Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_fileattr_set(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_fill_iomap(Ptr<inode> inode, @OriginalName("loff_t") long pos,
      @OriginalName("loff_t") long length, Ptr<iomap> iomap, Ptr<fuse_dax_mapping> dmap,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_fill_super(Ptr<super_block> sb, Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_fill_super_common(Ptr<super_block> sb, Ptr<fuse_fs_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_fill_super_submount(Ptr<super_block> sb, Ptr<fuse_inode> parent_fi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_fill_write_pages(Ptr<fuse_io_args> ia,
      Ptr<address_space> mapping, Ptr<iov_iter> ii, @OriginalName("loff_t") long pos,
      @Unsigned int max_folios) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_fillattr(Ptr<mnt_idmap> idmap, Ptr<inode> inode, Ptr<fuse_attr> attr,
      Ptr<kstat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_finish_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_flush(Ptr<file> file, @OriginalName("fl_owner_t") Ptr<?> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_flush_time_update(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_flush_times(Ptr<inode> inode, Ptr<fuse_file> ff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_flush_writepages(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_free_conn(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_free_dax_mem_ranges(Ptr<list_head> mem_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_free_fsc(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_free_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_fs_cleanup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_fsync(Ptr<file> file, @OriginalName("loff_t") long start,
      @OriginalName("loff_t") long end, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_fsync_common(Ptr<file> file, @OriginalName("loff_t") long start,
      @OriginalName("loff_t") long end, int datasync, int opcode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<posix_acl> fuse_get_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int fuse_get_cache_mask(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> fuse_get_dentry(Ptr<super_block> sb, Ptr<fuse_inode_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<posix_acl> fuse_get_inode_acl(Ptr<inode> inode, int type, boolean rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)fuse_get_link($arg1, $arg2, $arg3))")
  public static String fuse_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> fuse_get_parent(Ptr<dentry> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_req> fuse_get_req(Ptr<mnt_idmap> idmap, Ptr<fuse_mount> fm,
      boolean for_background) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_get_tree(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_get_tree_submount(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long fuse_get_unique(Ptr<fuse_iqueue> fiq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_get_user_pages(Ptr<fuse_args_pages> ap, Ptr<iov_iter> ii,
      Ptr<java.lang. @Unsigned Long> nbytesp, int write, @Unsigned int max_pages,
      boolean use_pages_for_kvec_io) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int fuse_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_getlk(Ptr<file> file, Ptr<file_lock> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_getxattr($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long fuse_getxattr(Ptr<inode> inode, String name,
      Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> fuse_iget(Ptr<super_block> sb, @Unsigned long nodeid, int generation,
      Ptr<fuse_attr> attr, @Unsigned long attr_valid, @Unsigned long attr_version,
      @Unsigned long evict_ctr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> fuse_ilookup(Ptr<fuse_conn> fc, @Unsigned long nodeid,
      Ptr<Ptr<fuse_mount>> fm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_init_common(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_init_dir(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_init_file_inode(Ptr<inode> inode, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_init_fs_context(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_init_fs_context_submount(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_init_inode(Ptr<inode> inode, Ptr<fuse_attr> attr, Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_init_symlink(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_inode_eq(Ptr<inode> inode, Ptr<?> _nodeidp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_inode_init_once(Ptr<?> foo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_inode_set(Ptr<inode> inode, Ptr<?> _nodeidp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_inode_uncached_io_end(Ptr<fuse_inode> fi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_inode_uncached_io_start(Ptr<fuse_inode> fi, Ptr<fuse_backing> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_invalid_attr(Ptr<fuse_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_invalidate_atime(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_invalidate_attr(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_invalidate_attr_mask(Ptr<inode> inode, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_invalidate_entry_cache(Ptr<dentry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_io_args> fuse_io_alloc(Ptr<fuse_io_priv> io, @Unsigned int nfolios) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long fuse_ioctl_common(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_iomap_begin(Ptr<inode> inode, @OriginalName("loff_t") long offset,
      @OriginalName("loff_t") long length, @Unsigned int flags, Ptr<iomap> iomap,
      Ptr<iomap> srcmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_iomap_end(Ptr<inode> inode, @OriginalName("loff_t") long pos,
      @OriginalName("loff_t") long length, @OriginalName("ssize_t") long written,
      @Unsigned int flags, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_iomap_read_folio_range((const struct iomap_iter*)$arg1, $arg2, $arg3, $arg4)")
  public static int fuse_iomap_read_folio_range(Ptr<iomap_iter> iter, Ptr<folio> folio,
      @OriginalName("loff_t") long pos, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_iomap_writeback_range(
      Ptr<iomap_writepage_ctx> wpc, Ptr<folio> folio, @Unsigned long pos, @Unsigned int len,
      @Unsigned long end_pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_iomap_writeback_submit(Ptr<iomap_writepage_ctx> wpc, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_kill_sb_anon(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_kill_sb_blk(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_launder_folio(Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int fuse_len_args(@Unsigned int numargs, Ptr<fuse_arg> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_link(Ptr<dentry> entry, Ptr<inode> newdir, Ptr<dentry> newent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_listxattr(Ptr<dentry> entry, String list,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_lock_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long fuse_lock_owner_id(Ptr<fuse_conn> fc,
      @OriginalName("fl_owner_t") Ptr<?> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> fuse_lookup(Ptr<inode> dir, Ptr<dentry> entry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_lookup_name($arg1, $arg2, (const struct qstr*)$arg3, $arg4, $arg5)")
  public static int fuse_lookup_name(Ptr<super_block> sb, @Unsigned long nodeid, Ptr<qstr> name,
      Ptr<fuse_entry_out> outarg, Ptr<Ptr<inode>> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long fuse_lseek(Ptr<file> file,
      @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> fuse_mkdir(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> entry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_mknod(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> entry,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned @OriginalName("dev_t") int rdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_mount_destroy(Ptr<fuse_mount> fm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_mount_remove(Ptr<fuse_mount> fm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_notify(Ptr<fuse_conn> fc, fuse_notify_code code, @Unsigned int size,
      Ptr<fuse_copy_state> cs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_notify_poll_wakeup(Ptr<fuse_conn> fc,
      Ptr<fuse_notify_poll_wakeup_out> outarg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_notify_store(Ptr<fuse_conn> fc, @Unsigned int size,
      Ptr<fuse_copy_state> cs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int fuse_page_mkwrite(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_pages_realloc(Ptr<fuse_fill_wb_data> data, @Unsigned int max_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_parse_param(Ptr<fs_context> fsc, Ptr<fs_parameter> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_passthrough_end_write(Ptr<kiocb> iocb,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_passthrough_mmap(Ptr<file> file,
      Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_backing> fuse_passthrough_open(Ptr<file> file, Ptr<inode> inode,
      int backing_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_passthrough_read_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_passthrough_release(Ptr<fuse_file> ff, Ptr<fuse_backing> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_passthrough_splice_read(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<pipe_inode_info> pipe,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_passthrough_splice_write(
      Ptr<pipe_inode_info> pipe, Ptr<file> out, Ptr<java.lang. @OriginalName("loff_t") Long> ppos,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_passthrough_write_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_perform_write(Ptr<kiocb> iocb,
      Ptr<iov_iter> ii) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_permission(Ptr<mnt_idmap> idmap, Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_pqueue_init(Ptr<fuse_pqueue> fpq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_prepare_release(Ptr<fuse_inode> fi, Ptr<fuse_file> ff,
      @Unsigned int flags, int opcode, boolean sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_priv_ioctl(Ptr<inode> inode, Ptr<fuse_file> ff, @Unsigned int cmd,
      Ptr<?> ptr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_file> fuse_priv_ioctl_prepare(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_put_request(Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_queue_forget(Ptr<fuse_conn> fc, Ptr<fuse_forget_link> forget,
      @Unsigned long nodeid, @Unsigned long nlookup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_read_args_fill(Ptr<fuse_io_args> ia, Ptr<file> file,
      @OriginalName("loff_t") long pos, @Unsigned long count, int opcode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_read_folio(Ptr<file> file, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_read_update_size(Ptr<inode> inode, @OriginalName("loff_t") long size,
      @Unsigned long attr_ver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_readahead(Ptr<readahead_control> rac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_readdir_cached(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_readdir_uncached(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_readlink_folio(Ptr<inode> inode, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_readpages_end(Ptr<fuse_mount> fm, Ptr<fuse_args> args, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_reconfigure(Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_release_common(Ptr<file> file, boolean isdir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_release_end(Ptr<fuse_mount> fm, Ptr<fuse_args> args, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_release_nowrite(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_remove_pending_req(Ptr<fuse_req> req,
      Ptr<@OriginalName("spinlock_t") spinlock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_removexattr($arg1, (const u8*)$arg2)")
  public static int fuse_removexattr(Ptr<inode> inode, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_rename2(Ptr<mnt_idmap> idmap, Ptr<inode> olddir, Ptr<dentry> oldent,
      Ptr<inode> newdir, Ptr<dentry> newent, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_rename_common(Ptr<mnt_idmap> idmap, Ptr<inode> olddir, Ptr<dentry> oldent,
      Ptr<inode> newdir, Ptr<dentry> newent, @Unsigned int flags, int opcode,
      @Unsigned long argsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int fuse_req_hash(@Unsigned long unique) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_req> fuse_request_alloc(Ptr<fuse_mount> fm,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_request_end(Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_request_expired(Ptr<fuse_conn> fc, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_req> fuse_request_find(Ptr<fuse_pqueue> fpq, @Unsigned long unique) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_request_queue_background(Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_resend(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_retrieve(Ptr<fuse_mount> fm, Ptr<inode> inode,
      Ptr<fuse_notify_retrieve_out> outarg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_retrieve_end(Ptr<fuse_mount> fm, Ptr<fuse_args> args, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_reverse_inval_entry(Ptr<fuse_conn> fc, @Unsigned long parent_nodeid,
      @Unsigned long child_nodeid, Ptr<qstr> name, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_reverse_inval_inode(Ptr<fuse_conn> fc, @Unsigned long nodeid,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_rmdir(Ptr<inode> dir, Ptr<dentry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_send_destroy(Ptr<fuse_mount> fm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_send_init(Ptr<fuse_mount> fm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_send_one(Ptr<fuse_iqueue> fiq, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_send_open(Ptr<fuse_mount> fm, @Unsigned long nodeid,
      @Unsigned int open_flags, int opcode, Ptr<fuse_open_out> outargp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_send_removemapping(Ptr<inode> inode, Ptr<fuse_removemapping_in> inargp,
      Ptr<fuse_removemapping_one> remove_one) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_set_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<posix_acl> acl,
      int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_set_initialized(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_set_no_super(Ptr<super_block> sb, Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_set_nowrite(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> entry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_setlk(Ptr<file> file, Ptr<file_lock> fl, int flock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_setup_enable_verity(@Unsigned long arg, Ptr<iovec> iov,
      Ptr<java.lang. @Unsigned Integer> in_iovs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_setup_new_dax_mapping(Ptr<inode> inode, @OriginalName("loff_t") long pos,
      @OriginalName("loff_t") long length, @Unsigned int flags, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_setup_one_mapping(Ptr<inode> inode, @Unsigned long start_idx,
      Ptr<fuse_dax_mapping> dmap, boolean writable, boolean upgrade) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_setxattr($arg1, (const u8*)$arg2, (const void*)$arg3, $arg4, $arg5, $arg6)")
  public static int fuse_setxattr(Ptr<inode> inode, String name, Ptr<?> value, @Unsigned long size,
      int flags, @Unsigned int extra_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_show_options(Ptr<seq_file> m, Ptr<dentry> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_simple_background(Ptr<fuse_mount> fm, Ptr<fuse_args> args,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_splice_read(Ptr<file> in,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos, Ptr<pipe_inode_info> pipe,
      @Unsigned long len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long fuse_splice_write(Ptr<pipe_inode_info> pipe,
      Ptr<file> out, Ptr<java.lang. @OriginalName("loff_t") Long> ppos, @Unsigned long len,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_statfs(Ptr<dentry> dentry, Ptr<kstatfs> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_symlink($arg1, $arg2, $arg3, (const u8*)$arg4)")
  public static int fuse_symlink(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> entry,
      String link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_symlink_read_folio(Ptr<file> _null, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_sync_bucket> fuse_sync_bucket_alloc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_sync_fs(Ptr<super_block> sb, int wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_sync_release(Ptr<fuse_inode> fi, Ptr<fuse_file> ff, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_sysctl_register() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_sysctl_unregister() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_sysfs_cleanup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_test_super(Ptr<super_block> sb, Ptr<fs_context> fsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long fuse_time_to_jiffies(@Unsigned long sec, @Unsigned int nsec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_tmpfile(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<file> file,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_try_move_folio(Ptr<fuse_copy_state> cs, Ptr<Ptr<folio>> foliop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_umount_begin(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_unlink(Ptr<inode> dir, Ptr<dentry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_unlock_inode(Ptr<inode> inode, boolean locked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_update_attributes(Ptr<inode> inode, Ptr<file> file, @Unsigned int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_update_ctime(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_update_get_attr(Ptr<mnt_idmap> idmap, Ptr<inode> inode, Ptr<file> file,
      Ptr<kstat> stat, @Unsigned int request_mask, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_abort_end_requests(Ptr<fuse_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_add_req_to_ring_ent(Ptr<fuse_ring_ent> ent, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_async_stop_queues(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_uring_commit_fetch(Ptr<io_uring_cmd> cmd, int issue_flags,
      Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_uring_copy_from_ring(Ptr<fuse_ring> ring, Ptr<fuse_req> req,
      Ptr<fuse_ring_ent> ent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_uring_copy_to_ring(Ptr<fuse_ring_ent> ent, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_ring> fuse_uring_create(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_ring_queue> fuse_uring_create_queue(Ptr<fuse_ring> ring, int qid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_destruct(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_uring_enabled() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_flush_bg(Ptr<fuse_ring_queue> queue) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_next_fuse_req(Ptr<fuse_ring_ent> ent, Ptr<fuse_ring_queue> queue,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_uring_queue_bq_req(Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_queue_fuse_req(Ptr<fuse_iqueue> fiq, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_uring_register(Ptr<io_uring_cmd> cmd, @Unsigned int issue_flags,
      Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_uring_remove_pending_req(Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_req_end(Ptr<fuse_ring_ent> ent, Ptr<fuse_req> req, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_uring_request_expired(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_send_in_task(Ptr<io_uring_cmd> cmd, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_stop_list_entries(Ptr<list_head> head, Ptr<fuse_ring_queue> queue,
      fuse_ring_req_state exp_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_uring_stop_queues(Ptr<fuse_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fuse_ring_queue> fuse_uring_task_to_queue(Ptr<fuse_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_valid_type(int m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_vma_close(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_wait_aborted(Ptr<fuse_conn> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_wait_dax_page(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int fuse_write_flags(Ptr<kiocb> iocb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_write_inode(Ptr<inode> inode, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean fuse_write_update_attr(Ptr<inode> inode, @OriginalName("loff_t") long pos,
      @OriginalName("ssize_t") long written) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_writepage_end(Ptr<fuse_mount> fm, Ptr<fuse_args> args, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_writepage_finish(Ptr<fuse_writepage_args> wpa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void fuse_writepage_free(Ptr<fuse_writepage_args> wpa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int fuse_writepages(Ptr<address_space> mapping, Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_xattr_get((const struct xattr_handler*)$arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static int fuse_xattr_get(Ptr<xattr_handler> handler, Ptr<dentry> dentry, Ptr<inode> inode,
      String name, Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("fuse_xattr_set((const struct xattr_handler*)$arg1, $arg2, $arg3, $arg4, (const u8*)$arg5, (const void*)$arg6, $arg7, $arg8)")
  public static int fuse_xattr_set(Ptr<xattr_handler> handler, Ptr<mnt_idmap> idmap,
      Ptr<dentry> dentry, Ptr<inode> inode, String name, Ptr<?> value, @Unsigned long size,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_opcode"
  )
  public enum fuse_opcode implements Enum<fuse_opcode>, TypedEnum<fuse_opcode, java.lang. @Unsigned Integer> {
    /**
     * {@code FUSE_LOOKUP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FUSE_LOOKUP"
    )
    FUSE_LOOKUP,

    /**
     * {@code FUSE_FORGET = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FUSE_FORGET"
    )
    FUSE_FORGET,

    /**
     * {@code FUSE_GETATTR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FUSE_GETATTR"
    )
    FUSE_GETATTR,

    /**
     * {@code FUSE_SETATTR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FUSE_SETATTR"
    )
    FUSE_SETATTR,

    /**
     * {@code FUSE_READLINK = 5}
     */
    @EnumMember(
        value = 5L,
        name = "FUSE_READLINK"
    )
    FUSE_READLINK,

    /**
     * {@code FUSE_SYMLINK = 6}
     */
    @EnumMember(
        value = 6L,
        name = "FUSE_SYMLINK"
    )
    FUSE_SYMLINK,

    /**
     * {@code FUSE_MKNOD = 8}
     */
    @EnumMember(
        value = 8L,
        name = "FUSE_MKNOD"
    )
    FUSE_MKNOD,

    /**
     * {@code FUSE_MKDIR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "FUSE_MKDIR"
    )
    FUSE_MKDIR,

    /**
     * {@code FUSE_UNLINK = 10}
     */
    @EnumMember(
        value = 10L,
        name = "FUSE_UNLINK"
    )
    FUSE_UNLINK,

    /**
     * {@code FUSE_RMDIR = 11}
     */
    @EnumMember(
        value = 11L,
        name = "FUSE_RMDIR"
    )
    FUSE_RMDIR,

    /**
     * {@code FUSE_RENAME = 12}
     */
    @EnumMember(
        value = 12L,
        name = "FUSE_RENAME"
    )
    FUSE_RENAME,

    /**
     * {@code FUSE_LINK = 13}
     */
    @EnumMember(
        value = 13L,
        name = "FUSE_LINK"
    )
    FUSE_LINK,

    /**
     * {@code FUSE_OPEN = 14}
     */
    @EnumMember(
        value = 14L,
        name = "FUSE_OPEN"
    )
    FUSE_OPEN,

    /**
     * {@code FUSE_READ = 15}
     */
    @EnumMember(
        value = 15L,
        name = "FUSE_READ"
    )
    FUSE_READ,

    /**
     * {@code FUSE_WRITE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "FUSE_WRITE"
    )
    FUSE_WRITE,

    /**
     * {@code FUSE_STATFS = 17}
     */
    @EnumMember(
        value = 17L,
        name = "FUSE_STATFS"
    )
    FUSE_STATFS,

    /**
     * {@code FUSE_RELEASE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "FUSE_RELEASE"
    )
    FUSE_RELEASE,

    /**
     * {@code FUSE_FSYNC = 20}
     */
    @EnumMember(
        value = 20L,
        name = "FUSE_FSYNC"
    )
    FUSE_FSYNC,

    /**
     * {@code FUSE_SETXATTR = 21}
     */
    @EnumMember(
        value = 21L,
        name = "FUSE_SETXATTR"
    )
    FUSE_SETXATTR,

    /**
     * {@code FUSE_GETXATTR = 22}
     */
    @EnumMember(
        value = 22L,
        name = "FUSE_GETXATTR"
    )
    FUSE_GETXATTR,

    /**
     * {@code FUSE_LISTXATTR = 23}
     */
    @EnumMember(
        value = 23L,
        name = "FUSE_LISTXATTR"
    )
    FUSE_LISTXATTR,

    /**
     * {@code FUSE_REMOVEXATTR = 24}
     */
    @EnumMember(
        value = 24L,
        name = "FUSE_REMOVEXATTR"
    )
    FUSE_REMOVEXATTR,

    /**
     * {@code FUSE_FLUSH = 25}
     */
    @EnumMember(
        value = 25L,
        name = "FUSE_FLUSH"
    )
    FUSE_FLUSH,

    /**
     * {@code FUSE_INIT = 26}
     */
    @EnumMember(
        value = 26L,
        name = "FUSE_INIT"
    )
    FUSE_INIT,

    /**
     * {@code FUSE_OPENDIR = 27}
     */
    @EnumMember(
        value = 27L,
        name = "FUSE_OPENDIR"
    )
    FUSE_OPENDIR,

    /**
     * {@code FUSE_READDIR = 28}
     */
    @EnumMember(
        value = 28L,
        name = "FUSE_READDIR"
    )
    FUSE_READDIR,

    /**
     * {@code FUSE_RELEASEDIR = 29}
     */
    @EnumMember(
        value = 29L,
        name = "FUSE_RELEASEDIR"
    )
    FUSE_RELEASEDIR,

    /**
     * {@code FUSE_FSYNCDIR = 30}
     */
    @EnumMember(
        value = 30L,
        name = "FUSE_FSYNCDIR"
    )
    FUSE_FSYNCDIR,

    /**
     * {@code FUSE_GETLK = 31}
     */
    @EnumMember(
        value = 31L,
        name = "FUSE_GETLK"
    )
    FUSE_GETLK,

    /**
     * {@code FUSE_SETLK = 32}
     */
    @EnumMember(
        value = 32L,
        name = "FUSE_SETLK"
    )
    FUSE_SETLK,

    /**
     * {@code FUSE_SETLKW = 33}
     */
    @EnumMember(
        value = 33L,
        name = "FUSE_SETLKW"
    )
    FUSE_SETLKW,

    /**
     * {@code FUSE_ACCESS = 34}
     */
    @EnumMember(
        value = 34L,
        name = "FUSE_ACCESS"
    )
    FUSE_ACCESS,

    /**
     * {@code FUSE_CREATE = 35}
     */
    @EnumMember(
        value = 35L,
        name = "FUSE_CREATE"
    )
    FUSE_CREATE,

    /**
     * {@code FUSE_INTERRUPT = 36}
     */
    @EnumMember(
        value = 36L,
        name = "FUSE_INTERRUPT"
    )
    FUSE_INTERRUPT,

    /**
     * {@code FUSE_BMAP = 37}
     */
    @EnumMember(
        value = 37L,
        name = "FUSE_BMAP"
    )
    FUSE_BMAP,

    /**
     * {@code FUSE_DESTROY = 38}
     */
    @EnumMember(
        value = 38L,
        name = "FUSE_DESTROY"
    )
    FUSE_DESTROY,

    /**
     * {@code FUSE_IOCTL = 39}
     */
    @EnumMember(
        value = 39L,
        name = "FUSE_IOCTL"
    )
    FUSE_IOCTL,

    /**
     * {@code FUSE_POLL = 40}
     */
    @EnumMember(
        value = 40L,
        name = "FUSE_POLL"
    )
    FUSE_POLL,

    /**
     * {@code FUSE_NOTIFY_REPLY = 41}
     */
    @EnumMember(
        value = 41L,
        name = "FUSE_NOTIFY_REPLY"
    )
    FUSE_NOTIFY_REPLY,

    /**
     * {@code FUSE_BATCH_FORGET = 42}
     */
    @EnumMember(
        value = 42L,
        name = "FUSE_BATCH_FORGET"
    )
    FUSE_BATCH_FORGET,

    /**
     * {@code FUSE_FALLOCATE = 43}
     */
    @EnumMember(
        value = 43L,
        name = "FUSE_FALLOCATE"
    )
    FUSE_FALLOCATE,

    /**
     * {@code FUSE_READDIRPLUS = 44}
     */
    @EnumMember(
        value = 44L,
        name = "FUSE_READDIRPLUS"
    )
    FUSE_READDIRPLUS,

    /**
     * {@code FUSE_RENAME2 = 45}
     */
    @EnumMember(
        value = 45L,
        name = "FUSE_RENAME2"
    )
    FUSE_RENAME2,

    /**
     * {@code FUSE_LSEEK = 46}
     */
    @EnumMember(
        value = 46L,
        name = "FUSE_LSEEK"
    )
    FUSE_LSEEK,

    /**
     * {@code FUSE_COPY_FILE_RANGE = 47}
     */
    @EnumMember(
        value = 47L,
        name = "FUSE_COPY_FILE_RANGE"
    )
    FUSE_COPY_FILE_RANGE,

    /**
     * {@code FUSE_SETUPMAPPING = 48}
     */
    @EnumMember(
        value = 48L,
        name = "FUSE_SETUPMAPPING"
    )
    FUSE_SETUPMAPPING,

    /**
     * {@code FUSE_REMOVEMAPPING = 49}
     */
    @EnumMember(
        value = 49L,
        name = "FUSE_REMOVEMAPPING"
    )
    FUSE_REMOVEMAPPING,

    /**
     * {@code FUSE_SYNCFS = 50}
     */
    @EnumMember(
        value = 50L,
        name = "FUSE_SYNCFS"
    )
    FUSE_SYNCFS,

    /**
     * {@code FUSE_TMPFILE = 51}
     */
    @EnumMember(
        value = 51L,
        name = "FUSE_TMPFILE"
    )
    FUSE_TMPFILE,

    /**
     * {@code FUSE_STATX = 52}
     */
    @EnumMember(
        value = 52L,
        name = "FUSE_STATX"
    )
    FUSE_STATX,

    /**
     * {@code CUSE_INIT = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "CUSE_INIT"
    )
    CUSE_INIT,

    /**
     * {@code CUSE_INIT_BSWAP_RESERVED = 1048576}
     */
    @EnumMember(
        value = 1048576L,
        name = "CUSE_INIT_BSWAP_RESERVED"
    )
    CUSE_INIT_BSWAP_RESERVED,

    /**
     * {@code FUSE_INIT_BSWAP_RESERVED = 436207616}
     */
    @EnumMember(
        value = 436207616L,
        name = "FUSE_INIT_BSWAP_RESERVED"
    )
    FUSE_INIT_BSWAP_RESERVED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_notify_code"
  )
  public enum fuse_notify_code implements Enum<fuse_notify_code>, TypedEnum<fuse_notify_code, java.lang. @Unsigned Integer> {
    /**
     * {@code FUSE_NOTIFY_POLL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FUSE_NOTIFY_POLL"
    )
    FUSE_NOTIFY_POLL,

    /**
     * {@code FUSE_NOTIFY_INVAL_INODE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FUSE_NOTIFY_INVAL_INODE"
    )
    FUSE_NOTIFY_INVAL_INODE,

    /**
     * {@code FUSE_NOTIFY_INVAL_ENTRY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FUSE_NOTIFY_INVAL_ENTRY"
    )
    FUSE_NOTIFY_INVAL_ENTRY,

    /**
     * {@code FUSE_NOTIFY_STORE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FUSE_NOTIFY_STORE"
    )
    FUSE_NOTIFY_STORE,

    /**
     * {@code FUSE_NOTIFY_RETRIEVE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "FUSE_NOTIFY_RETRIEVE"
    )
    FUSE_NOTIFY_RETRIEVE,

    /**
     * {@code FUSE_NOTIFY_DELETE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "FUSE_NOTIFY_DELETE"
    )
    FUSE_NOTIFY_DELETE,

    /**
     * {@code FUSE_NOTIFY_RESEND = 7}
     */
    @EnumMember(
        value = 7L,
        name = "FUSE_NOTIFY_RESEND"
    )
    FUSE_NOTIFY_RESEND,

    /**
     * {@code FUSE_NOTIFY_INC_EPOCH = 8}
     */
    @EnumMember(
        value = 8L,
        name = "FUSE_NOTIFY_INC_EPOCH"
    )
    FUSE_NOTIFY_INC_EPOCH,

    /**
     * {@code FUSE_NOTIFY_CODE_MAX = 9}
     */
    @EnumMember(
        value = 9L,
        name = "FUSE_NOTIFY_CODE_MAX"
    )
    FUSE_NOTIFY_CODE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_forget_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_forget_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long nlookup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_forget_one"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_forget_one extends Struct {
    public @Unsigned @OriginalName("uint64_t") long nodeid;

    public @Unsigned @OriginalName("uint64_t") long nlookup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_batch_forget_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_batch_forget_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int count;

    public @Unsigned @OriginalName("uint32_t") int dummy;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_open_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_open_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint32_t") int open_flags;

    public @OriginalName("int32_t") int backing_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_release_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_release_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int release_flags;

    public @Unsigned @OriginalName("uint64_t") long lock_owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_interrupt_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_interrupt_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long unique;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_notify_poll_wakeup_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_notify_poll_wakeup_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long kh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_in_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_in_header extends Struct {
    public @Unsigned @OriginalName("uint32_t") int len;

    public @Unsigned @OriginalName("uint32_t") int opcode;

    public @Unsigned @OriginalName("uint64_t") long unique;

    public @Unsigned @OriginalName("uint64_t") long nodeid;

    public @Unsigned @OriginalName("uint32_t") int uid;

    public @Unsigned @OriginalName("uint32_t") int gid;

    public @Unsigned @OriginalName("uint32_t") int pid;

    public @Unsigned @OriginalName("uint16_t") short total_extlen;

    public @Unsigned @OriginalName("uint16_t") short padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_out_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_out_header extends Struct {
    public @Unsigned @OriginalName("uint32_t") int len;

    public @OriginalName("int32_t") int error;

    public @Unsigned @OriginalName("uint64_t") long unique;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_notify_inval_inode_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_notify_inval_inode_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long ino;

    public @OriginalName("int64_t") long off;

    public @OriginalName("int64_t") long len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_notify_inval_entry_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_notify_inval_entry_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long parent;

    public @Unsigned @OriginalName("uint32_t") int namelen;

    public @Unsigned @OriginalName("uint32_t") int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_notify_delete_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_notify_delete_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long parent;

    public @Unsigned @OriginalName("uint64_t") long child;

    public @Unsigned @OriginalName("uint32_t") int namelen;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_notify_store_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_notify_store_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long nodeid;

    public @Unsigned @OriginalName("uint64_t") long offset;

    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_notify_retrieve_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_notify_retrieve_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long notify_unique;

    public @Unsigned @OriginalName("uint64_t") long nodeid;

    public @Unsigned @OriginalName("uint64_t") long offset;

    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_notify_retrieve_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_notify_retrieve_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long dummy1;

    public @Unsigned @OriginalName("uint64_t") long offset;

    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int dummy2;

    public @Unsigned @OriginalName("uint64_t") long dummy3;

    public @Unsigned @OriginalName("uint64_t") long dummy4;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_backing_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_backing_map extends Struct {
    public @OriginalName("int32_t") int fd;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint64_t") long padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_forget_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_forget_link extends Struct {
    public fuse_forget_one forget_one;

    public Ptr<fuse_forget_link> next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_file"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_file extends Struct {
    public Ptr<fuse_mount> fm;

    public Ptr<fuse_file_args> args;

    public @Unsigned long kh;

    public @Unsigned long fh;

    public @Unsigned long nodeid;

    public @OriginalName("refcount_t") refcount_struct count;

    public @Unsigned int open_flags;

    public list_head write_entry;

    public readdir_of_fuse_file readdir;

    public rb_node polled_node;

    public @OriginalName("wait_queue_head_t") wait_queue_head poll_wait;

    public iomode_of_fuse_file iomode;

    public Ptr<file> passthrough;

    public Ptr<cred> cred;

    public boolean flock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_mount"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_mount extends Struct {
    public Ptr<fuse_conn> fc;

    public Ptr<super_block> sb;

    public list_head fc_entry;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union fuse_file_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_file_args extends Union {
    public fuse_open_out open_outarg;

    public fuse_release_args release_args;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_in_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_in_arg extends Struct {
    public @Unsigned int size;

    public Ptr<?> value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_arg extends Struct {
    public @Unsigned int size;

    public Ptr<?> value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_folio_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_folio_desc extends Struct {
    public @Unsigned int length;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_args extends Struct {
    public @Unsigned @OriginalName("uint64_t") long nodeid;

    public @Unsigned @OriginalName("uint32_t") int opcode;

    public @OriginalName("uint8_t") char in_numargs;

    public @OriginalName("uint8_t") char out_numargs;

    public @OriginalName("uint8_t") char ext_idx;

    public boolean force;

    public boolean noreply;

    public boolean nocreds;

    public boolean in_pages;

    public boolean out_pages;

    public boolean user_pages;

    public boolean out_argvar;

    public boolean page_zeroing;

    public boolean page_replace;

    public boolean may_block;

    public boolean is_ext;

    public boolean is_pinned;

    public boolean invalidate_vmap;

    public fuse_in_arg @Size(4) [] in_args;

    public fuse_arg @Size(2) [] out_args;

    public Ptr<?> end;

    public Ptr<?> vmap_base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_args_pages"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_args_pages extends Struct {
    public fuse_args args;

    public Ptr<Ptr<folio>> folios;

    public Ptr<fuse_folio_desc> descs;

    public @Unsigned int num_folios;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_release_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_release_args extends Struct {
    public fuse_args args;

    public fuse_release_in inarg;

    public Ptr<inode> inode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_req_flag"
  )
  public enum fuse_req_flag implements Enum<fuse_req_flag>, TypedEnum<fuse_req_flag, java.lang. @Unsigned Integer> {
    /**
     * {@code FR_ISREPLY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FR_ISREPLY"
    )
    FR_ISREPLY,

    /**
     * {@code FR_FORCE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FR_FORCE"
    )
    FR_FORCE,

    /**
     * {@code FR_BACKGROUND = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FR_BACKGROUND"
    )
    FR_BACKGROUND,

    /**
     * {@code FR_WAITING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FR_WAITING"
    )
    FR_WAITING,

    /**
     * {@code FR_ABORTED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FR_ABORTED"
    )
    FR_ABORTED,

    /**
     * {@code FR_INTERRUPTED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "FR_INTERRUPTED"
    )
    FR_INTERRUPTED,

    /**
     * {@code FR_LOCKED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "FR_LOCKED"
    )
    FR_LOCKED,

    /**
     * {@code FR_PENDING = 7}
     */
    @EnumMember(
        value = 7L,
        name = "FR_PENDING"
    )
    FR_PENDING,

    /**
     * {@code FR_SENT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "FR_SENT"
    )
    FR_SENT,

    /**
     * {@code FR_FINISHED = 9}
     */
    @EnumMember(
        value = 9L,
        name = "FR_FINISHED"
    )
    FR_FINISHED,

    /**
     * {@code FR_PRIVATE = 10}
     */
    @EnumMember(
        value = 10L,
        name = "FR_PRIVATE"
    )
    FR_PRIVATE,

    /**
     * {@code FR_ASYNC = 11}
     */
    @EnumMember(
        value = 11L,
        name = "FR_ASYNC"
    )
    FR_ASYNC,

    /**
     * {@code FR_URING = 12}
     */
    @EnumMember(
        value = 12L,
        name = "FR_URING"
    )
    FR_URING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_req"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_req extends Struct {
    public list_head list;

    public list_head intr_entry;

    public Ptr<fuse_args> args;

    public @OriginalName("refcount_t") refcount_struct count;

    public @Unsigned long flags;

    public in_of_fuse_req in;

    public out_of_fuse_req out;

    public @OriginalName("wait_queue_head_t") wait_queue_head waitq;

    public Ptr<?> argbuf;

    public Ptr<fuse_mount> fm;

    public Ptr<?> ring_entry;

    public Ptr<?> ring_queue;

    public @Unsigned long create_time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_iqueue_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_iqueue_ops extends Struct {
    public Ptr<?> send_forget;

    public Ptr<?> send_interrupt;

    public Ptr<?> send_req;

    public Ptr<?> release;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_iqueue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_iqueue extends Struct {
    public @Unsigned int connected;

    public @OriginalName("spinlock_t") spinlock lock;

    public @OriginalName("wait_queue_head_t") wait_queue_head waitq;

    public @Unsigned long reqctr;

    public list_head pending;

    public list_head interrupts;

    public fuse_forget_link forget_list_head;

    public Ptr<fuse_forget_link> forget_list_tail;

    public int forget_batch;

    public Ptr<fasync_struct> fasync;

    public Ptr<fuse_iqueue_ops> ops;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_pqueue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_pqueue extends Struct {
    public @Unsigned int connected;

    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<list_head> processing;

    public list_head io;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_dev extends Struct {
    public Ptr<fuse_conn> fc;

    public fuse_pqueue pq;

    public list_head entry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_conn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_conn extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public @OriginalName("refcount_t") refcount_struct count;

    public atomic_t dev_count;

    public atomic_t epoch;

    public callback_head rcu;

    public kuid_t user_id;

    public kgid_t group_id;

    public Ptr<pid_namespace> pid_ns;

    public Ptr<user_namespace> user_ns;

    public @Unsigned int max_read;

    public @Unsigned int max_write;

    public @Unsigned int max_pages;

    public @Unsigned int max_pages_limit;

    public fuse_iqueue iq;

    public atomic64_t khctr;

    public rb_root polled_files;

    public @Unsigned int max_background;

    public @Unsigned int congestion_threshold;

    public @Unsigned int num_background;

    public @Unsigned int active_background;

    public list_head bg_queue;

    public @OriginalName("spinlock_t") spinlock bg_lock;

    public int initialized;

    public int blocked;

    public @OriginalName("wait_queue_head_t") wait_queue_head blocked_waitq;

    public @Unsigned int connected;

    public boolean aborted;

    public @Unsigned int conn_error;

    public @Unsigned int conn_init;

    public @Unsigned int async_read;

    public @Unsigned int abort_err;

    public @Unsigned int atomic_o_trunc;

    public @Unsigned int export_support;

    public @Unsigned int writeback_cache;

    public @Unsigned int parallel_dirops;

    public @Unsigned int handle_killpriv;

    public @Unsigned int cache_symlinks;

    public @Unsigned int legacy_opts_show;

    public @Unsigned int handle_killpriv_v2;

    public @Unsigned int no_open;

    public @Unsigned int no_opendir;

    public @Unsigned int no_fsync;

    public @Unsigned int no_fsyncdir;

    public @Unsigned int no_flush;

    public @Unsigned int no_setxattr;

    public @Unsigned int setxattr_ext;

    public @Unsigned int no_getxattr;

    public @Unsigned int no_listxattr;

    public @Unsigned int no_removexattr;

    public @Unsigned int no_lock;

    public @Unsigned int no_access;

    public @Unsigned int no_create;

    public @Unsigned int no_interrupt;

    public @Unsigned int no_bmap;

    public @Unsigned int no_poll;

    public @Unsigned int big_writes;

    public @Unsigned int dont_mask;

    public @Unsigned int no_flock;

    public @Unsigned int no_fallocate;

    public @Unsigned int no_rename2;

    public @Unsigned int auto_inval_data;

    public @Unsigned int explicit_inval_data;

    public @Unsigned int do_readdirplus;

    public @Unsigned int readdirplus_auto;

    public @Unsigned int async_dio;

    public @Unsigned int no_lseek;

    public @Unsigned int posix_acl;

    public @Unsigned int default_permissions;

    public @Unsigned int allow_other;

    public @Unsigned int no_copy_file_range;

    public @Unsigned int destroy;

    public @Unsigned int delete_stale;

    public @Unsigned int no_control;

    public @Unsigned int no_force_umount;

    public @Unsigned int auto_submounts;

    public @Unsigned int sync_fs;

    public @Unsigned int init_security;

    public @Unsigned int create_supp_group;

    public @Unsigned int inode_dax;

    public @Unsigned int no_tmpfile;

    public @Unsigned int direct_io_allow_mmap;

    public @Unsigned int no_statx;

    public @Unsigned int passthrough;

    public @Unsigned int use_pages_for_kvec_io;

    public @Unsigned int no_link;

    public @Unsigned int io_uring;

    public int max_stack_depth;

    public atomic_t num_waiting;

    public @Unsigned int minor;

    public list_head entry;

    public @Unsigned @OriginalName("dev_t") int dev;

    public @Unsigned int @Size(4) [] scramble_key;

    public atomic64_t attr_version;

    public atomic64_t evict_ctr;

    public @Unsigned int name_max;

    public Ptr<?> release;

    public rw_semaphore killsb;

    public list_head devices;

    public fuse_dax_mode dax_mode;

    public Ptr<fuse_conn_dax> dax;

    public list_head mounts;

    public Ptr<fuse_sync_bucket> curr_bucket;

    public idr backing_files_map;

    public Ptr<fuse_ring> ring;

    public timeout_of_fuse_conn timeout;

    public char blkbits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_dax_mode"
  )
  public enum fuse_dax_mode implements Enum<fuse_dax_mode>, TypedEnum<fuse_dax_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code FUSE_DAX_INODE_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FUSE_DAX_INODE_DEFAULT"
    )
    FUSE_DAX_INODE_DEFAULT,

    /**
     * {@code FUSE_DAX_ALWAYS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FUSE_DAX_ALWAYS"
    )
    FUSE_DAX_ALWAYS,

    /**
     * {@code FUSE_DAX_NEVER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FUSE_DAX_NEVER"
    )
    FUSE_DAX_NEVER,

    /**
     * {@code FUSE_DAX_INODE_USER = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FUSE_DAX_INODE_USER"
    )
    FUSE_DAX_INODE_USER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_sync_bucket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_sync_bucket extends Struct {
    public atomic_t count;

    public @OriginalName("wait_queue_head_t") wait_queue_head waitq;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_ring"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_ring extends Struct {
    public Ptr<fuse_conn> fc;

    public @Unsigned long nr_queues;

    public @Unsigned long max_payload_sz;

    public Ptr<Ptr<fuse_ring_queue>> queues;

    public @Unsigned int stop_debug_log;

    public @OriginalName("wait_queue_head_t") wait_queue_head stop_waitq;

    public delayed_work async_teardown_work;

    public @Unsigned long teardown_time;

    public atomic_t queue_refs;

    public boolean ready;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_ring_queue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_ring_queue extends Struct {
    public Ptr<fuse_ring> ring;

    public @Unsigned int qid;

    public @OriginalName("spinlock_t") spinlock lock;

    public list_head ent_avail_queue;

    public list_head ent_w_req_queue;

    public list_head ent_commit_queue;

    public list_head ent_in_userspace;

    public list_head ent_released;

    public list_head fuse_req_queue;

    public list_head fuse_req_bg_queue;

    public fuse_pqueue fpq;

    public @Unsigned int active_background;

    public boolean stopped;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_copy_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_copy_state extends Struct {
    public Ptr<fuse_req> req;

    public Ptr<iov_iter> iter;

    public Ptr<pipe_buffer> pipebufs;

    public Ptr<pipe_buffer> currbuf;

    public Ptr<pipe_inode_info> pipe;

    public @Unsigned long nr_segs;

    public Ptr<page> pg;

    public @Unsigned int len;

    public @Unsigned int offset;

    public boolean write;

    public boolean move_folios;

    public boolean is_uring;

    public ring_of_fuse_copy_state ring;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_retrieve_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_retrieve_args extends Struct {
    public fuse_args_pages ap;

    public fuse_notify_retrieve_in inarg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_attr extends Struct {
    public @Unsigned @OriginalName("uint64_t") long ino;

    public @Unsigned @OriginalName("uint64_t") long size;

    public @Unsigned @OriginalName("uint64_t") long blocks;

    public @Unsigned @OriginalName("uint64_t") long atime;

    public @Unsigned @OriginalName("uint64_t") long mtime;

    public @Unsigned @OriginalName("uint64_t") long ctime;

    public @Unsigned @OriginalName("uint32_t") int atimensec;

    public @Unsigned @OriginalName("uint32_t") int mtimensec;

    public @Unsigned @OriginalName("uint32_t") int ctimensec;

    public @Unsigned @OriginalName("uint32_t") int mode;

    public @Unsigned @OriginalName("uint32_t") int nlink;

    public @Unsigned @OriginalName("uint32_t") int uid;

    public @Unsigned @OriginalName("uint32_t") int gid;

    public @Unsigned @OriginalName("uint32_t") int rdev;

    public @Unsigned @OriginalName("uint32_t") int blksize;

    public @Unsigned @OriginalName("uint32_t") int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_sx_time"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_sx_time extends Struct {
    public @OriginalName("int64_t") long tv_sec;

    public @Unsigned @OriginalName("uint32_t") int tv_nsec;

    public @OriginalName("int32_t") int __reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_statx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_statx extends Struct {
    public @Unsigned @OriginalName("uint32_t") int mask;

    public @Unsigned @OriginalName("uint32_t") int blksize;

    public @Unsigned @OriginalName("uint64_t") long attributes;

    public @Unsigned @OriginalName("uint32_t") int nlink;

    public @Unsigned @OriginalName("uint32_t") int uid;

    public @Unsigned @OriginalName("uint32_t") int gid;

    public @Unsigned @OriginalName("uint16_t") short mode;

    public @Unsigned @OriginalName("uint16_t") short @Size(1) [] __spare0;

    public @Unsigned @OriginalName("uint64_t") long ino;

    public @Unsigned @OriginalName("uint64_t") long size;

    public @Unsigned @OriginalName("uint64_t") long blocks;

    public @Unsigned @OriginalName("uint64_t") long attributes_mask;

    public fuse_sx_time atime;

    public fuse_sx_time btime;

    public fuse_sx_time ctime;

    public fuse_sx_time mtime;

    public @Unsigned @OriginalName("uint32_t") int rdev_major;

    public @Unsigned @OriginalName("uint32_t") int rdev_minor;

    public @Unsigned @OriginalName("uint32_t") int dev_major;

    public @Unsigned @OriginalName("uint32_t") int dev_minor;

    public @Unsigned @OriginalName("uint64_t") long @Size(14) [] __spare2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_ext_type"
  )
  public enum fuse_ext_type implements Enum<fuse_ext_type>, TypedEnum<fuse_ext_type, java.lang. @Unsigned Integer> {
    /**
     * {@code FUSE_MAX_NR_SECCTX = 31}
     */
    @EnumMember(
        value = 31L,
        name = "FUSE_MAX_NR_SECCTX"
    )
    FUSE_MAX_NR_SECCTX,

    /**
     * {@code FUSE_EXT_GROUPS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "FUSE_EXT_GROUPS"
    )
    FUSE_EXT_GROUPS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_entry_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_entry_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long nodeid;

    public @Unsigned @OriginalName("uint64_t") long generation;

    public @Unsigned @OriginalName("uint64_t") long entry_valid;

    public @Unsigned @OriginalName("uint64_t") long attr_valid;

    public @Unsigned @OriginalName("uint32_t") int entry_valid_nsec;

    public @Unsigned @OriginalName("uint32_t") int attr_valid_nsec;

    public fuse_attr attr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_getattr_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_getattr_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int getattr_flags;

    public @Unsigned @OriginalName("uint32_t") int dummy;

    public @Unsigned @OriginalName("uint64_t") long fh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_attr_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_attr_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long attr_valid;

    public @Unsigned @OriginalName("uint32_t") int attr_valid_nsec;

    public @Unsigned @OriginalName("uint32_t") int dummy;

    public fuse_attr attr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_statx_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_statx_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int getattr_flags;

    public @Unsigned @OriginalName("uint32_t") int reserved;

    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint32_t") int sx_flags;

    public @Unsigned @OriginalName("uint32_t") int sx_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_statx_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_statx_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long attr_valid;

    public @Unsigned @OriginalName("uint32_t") int attr_valid_nsec;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint64_t") long @Size(2) [] spare;

    public fuse_statx stat;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_mknod_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_mknod_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int mode;

    public @Unsigned @OriginalName("uint32_t") int rdev;

    public @Unsigned @OriginalName("uint32_t") int umask;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_mkdir_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_mkdir_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int mode;

    public @Unsigned @OriginalName("uint32_t") int umask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_rename2_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_rename2_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long newdir;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_link_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_link_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long oldnodeid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_setattr_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_setattr_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int valid;

    public @Unsigned @OriginalName("uint32_t") int padding;

    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long size;

    public @Unsigned @OriginalName("uint64_t") long lock_owner;

    public @Unsigned @OriginalName("uint64_t") long atime;

    public @Unsigned @OriginalName("uint64_t") long mtime;

    public @Unsigned @OriginalName("uint64_t") long ctime;

    public @Unsigned @OriginalName("uint32_t") int atimensec;

    public @Unsigned @OriginalName("uint32_t") int mtimensec;

    public @Unsigned @OriginalName("uint32_t") int ctimensec;

    public @Unsigned @OriginalName("uint32_t") int mode;

    public @Unsigned @OriginalName("uint32_t") int unused4;

    public @Unsigned @OriginalName("uint32_t") int uid;

    public @Unsigned @OriginalName("uint32_t") int gid;

    public @Unsigned @OriginalName("uint32_t") int unused5;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_create_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_create_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int mode;

    public @Unsigned @OriginalName("uint32_t") int umask;

    public @Unsigned @OriginalName("uint32_t") int open_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_access_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_access_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int mask;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_secctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_secctx extends Struct {
    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_secctx_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_secctx_header extends Struct {
    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int nr_secctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_ext_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_ext_header extends Struct {
    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_supp_groups"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_supp_groups extends Struct {
    public @Unsigned @OriginalName("uint32_t") int nr_groups;

    public @Unsigned @OriginalName("uint32_t") int @Size(0) [] groups;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_submount_lookup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_submount_lookup extends Struct {
    public @OriginalName("refcount_t") refcount_struct count;

    public @Unsigned long nodeid;

    public Ptr<fuse_forget_link> forget;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_backing"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_backing extends Struct {
    public Ptr<file> file;

    public Ptr<cred> cred;

    public @OriginalName("refcount_t") refcount_struct count;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_inode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_inode extends Struct {
    public inode inode;

    public @Unsigned long nodeid;

    public @Unsigned long nlookup;

    public Ptr<fuse_forget_link> forget;

    public @Unsigned long i_time;

    public @Unsigned int inval_mask;

    public @Unsigned @OriginalName("umode_t") short orig_i_mode;

    public timespec64 i_btime;

    public @Unsigned long orig_ino;

    public @Unsigned long attr_version;

    @InlineUnion(26237)
    public anon_member_of_anon_member_of_fuse_inode anon10$0;

    @InlineUnion(26237)
    public rdc_of_anon_member_of_fuse_inode rdc;

    public @Unsigned long state;

    public mutex mutex;

    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<fuse_inode_dax> dax;

    public Ptr<fuse_submount_lookup> submount_lookup;

    public Ptr<fuse_backing> fb;

    public char cached_i_blkbits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_file_lock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_file_lock extends Struct {
    public @Unsigned @OriginalName("uint64_t") long start;

    public @Unsigned @OriginalName("uint64_t") long end;

    public @Unsigned @OriginalName("uint32_t") int type;

    public @Unsigned @OriginalName("uint32_t") int pid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_open_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_open_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int open_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_flush_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_flush_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint32_t") int unused;

    public @Unsigned @OriginalName("uint32_t") int padding;

    public @Unsigned @OriginalName("uint64_t") long lock_owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_read_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_read_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long offset;

    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int read_flags;

    public @Unsigned @OriginalName("uint64_t") long lock_owner;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_write_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_write_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long offset;

    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int write_flags;

    public @Unsigned @OriginalName("uint64_t") long lock_owner;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_write_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_write_out extends Struct {
    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_fsync_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_fsync_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint32_t") int fsync_flags;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_lk_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_lk_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long owner;

    public fuse_file_lock lk;

    public @Unsigned @OriginalName("uint32_t") int lk_flags;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_lk_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_lk_out extends Struct {
    public fuse_file_lock lk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_bmap_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_bmap_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long block;

    public @Unsigned @OriginalName("uint32_t") int blocksize;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_bmap_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_bmap_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long block;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_poll_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_poll_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long kh;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int events;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_poll_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_poll_out extends Struct {
    public @Unsigned @OriginalName("uint32_t") int revents;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_fallocate_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_fallocate_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long offset;

    public @Unsigned @OriginalName("uint64_t") long length;

    public @Unsigned @OriginalName("uint32_t") int mode;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_lseek_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_lseek_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long offset;

    public @Unsigned @OriginalName("uint32_t") int whence;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_lseek_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_lseek_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_copy_file_range_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_copy_file_range_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh_in;

    public @Unsigned @OriginalName("uint64_t") long off_in;

    public @Unsigned @OriginalName("uint64_t") long nodeid_out;

    public @Unsigned @OriginalName("uint64_t") long fh_out;

    public @Unsigned @OriginalName("uint64_t") long off_out;

    public @Unsigned @OriginalName("uint64_t") long len;

    public @Unsigned @OriginalName("uint64_t") long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_io_priv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_io_priv extends Struct {
    public kref refcnt;

    public int async;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned int reqs;

    public @OriginalName("ssize_t") long bytes;

    public @Unsigned long size;

    public @Unsigned long offset;

    public boolean write;

    public boolean should_dirty;

    public int err;

    public Ptr<kiocb> iocb;

    public Ptr<completion> done;

    public boolean blocking;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_io_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_io_args extends Struct {
    @InlineUnion(26279)
    public read_of_anon_member_of_fuse_io_args read;

    @InlineUnion(26279)
    public write_of_anon_member_of_fuse_io_args write;

    public fuse_args_pages ap;

    public Ptr<fuse_io_priv> io;

    public Ptr<fuse_file> ff;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_writepage_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_writepage_args extends Struct {
    public fuse_io_args ia;

    public list_head queue_entry;

    public Ptr<inode> inode;

    public Ptr<fuse_sync_bucket> bucket;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_fill_wb_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_fill_wb_data extends Struct {
    public Ptr<fuse_writepage_args> wpa;

    public Ptr<fuse_file> ff;

    public @Unsigned int max_folios;

    public @Unsigned int nr_bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_kstatfs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_kstatfs extends Struct {
    public @Unsigned @OriginalName("uint64_t") long blocks;

    public @Unsigned @OriginalName("uint64_t") long bfree;

    public @Unsigned @OriginalName("uint64_t") long bavail;

    public @Unsigned @OriginalName("uint64_t") long files;

    public @Unsigned @OriginalName("uint64_t") long ffree;

    public @Unsigned @OriginalName("uint32_t") int bsize;

    public @Unsigned @OriginalName("uint32_t") int namelen;

    public @Unsigned @OriginalName("uint32_t") int frsize;

    public @Unsigned @OriginalName("uint32_t") int padding;

    public @Unsigned @OriginalName("uint32_t") int @Size(6) [] spare;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_statfs_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_statfs_out extends Struct {
    public fuse_kstatfs st;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_init_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_init_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int major;

    public @Unsigned @OriginalName("uint32_t") int minor;

    public @Unsigned @OriginalName("uint32_t") int max_readahead;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int flags2;

    public @Unsigned @OriginalName("uint32_t") int @Size(11) [] unused;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_init_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_init_out extends Struct {
    public @Unsigned @OriginalName("uint32_t") int major;

    public @Unsigned @OriginalName("uint32_t") int minor;

    public @Unsigned @OriginalName("uint32_t") int max_readahead;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint16_t") short max_background;

    public @Unsigned @OriginalName("uint16_t") short congestion_threshold;

    public @Unsigned @OriginalName("uint32_t") int max_write;

    public @Unsigned @OriginalName("uint32_t") int time_gran;

    public @Unsigned @OriginalName("uint16_t") short max_pages;

    public @Unsigned @OriginalName("uint16_t") short map_alignment;

    public @Unsigned @OriginalName("uint32_t") int flags2;

    public @Unsigned @OriginalName("uint32_t") int max_stack_depth;

    public @Unsigned @OriginalName("uint16_t") short request_timeout;

    public @Unsigned @OriginalName("uint16_t") short @Size(11) [] unused;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_syncfs_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_syncfs_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_fs_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_fs_context extends Struct {
    public int fd;

    public Ptr<file> file;

    public @Unsigned int rootmode;

    public kuid_t user_id;

    public kgid_t group_id;

    public boolean is_bdev;

    public boolean fd_present;

    public boolean rootmode_present;

    public boolean user_id_present;

    public boolean group_id_present;

    public boolean default_permissions;

    public boolean allow_other;

    public boolean destroy;

    public boolean no_control;

    public boolean no_force_umount;

    public boolean legacy_opts_show;

    public fuse_dax_mode dax_mode;

    public @Unsigned int max_read;

    public @Unsigned int blksize;

    public String subtype;

    public Ptr<dax_device> dax_dev;

    public Ptr<Ptr<?>> fudptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_inode_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_inode_handle extends Struct {
    public @Unsigned long nodeid;

    public @Unsigned int generation;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_init_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_init_args extends Struct {
    public fuse_args args;

    public fuse_init_in in;

    public fuse_init_out out;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_setxattr_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_setxattr_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int setxattr_flags;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_getxattr_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_getxattr_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_getxattr_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_getxattr_out extends Struct {
    public @Unsigned @OriginalName("uint32_t") int size;

    public @Unsigned @OriginalName("uint32_t") int padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_dirent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_dirent extends Struct {
    public @Unsigned @OriginalName("uint64_t") long ino;

    public @Unsigned @OriginalName("uint64_t") long off;

    public @Unsigned @OriginalName("uint32_t") int namelen;

    public @Unsigned @OriginalName("uint32_t") int type;

    public char @Size(0) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_direntplus"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_direntplus extends Struct {
    public fuse_entry_out entry_out;

    public fuse_dirent dirent;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_parse_result"
  )
  public enum fuse_parse_result implements Enum<fuse_parse_result>, TypedEnum<fuse_parse_result, java.lang.Integer> {
    /**
     * {@code FOUND_ERR = -1}
     */
    @EnumMember(
        value = -1L,
        name = "FOUND_ERR"
    )
    FOUND_ERR,

    /**
     * {@code FOUND_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FOUND_NONE"
    )
    FOUND_NONE,

    /**
     * {@code FOUND_SOME = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FOUND_SOME"
    )
    FOUND_SOME,

    /**
     * {@code FOUND_ALL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FOUND_ALL"
    )
    FOUND_ALL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_ioctl_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_ioctl_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int cmd;

    public @Unsigned @OriginalName("uint64_t") long arg;

    public @Unsigned @OriginalName("uint32_t") int in_size;

    public @Unsigned @OriginalName("uint32_t") int out_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_ioctl_iovec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_ioctl_iovec extends Struct {
    public @Unsigned @OriginalName("uint64_t") long base;

    public @Unsigned @OriginalName("uint64_t") long len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_ioctl_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_ioctl_out extends Struct {
    public @OriginalName("int32_t") int result;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public @Unsigned @OriginalName("uint32_t") int in_iovs;

    public @Unsigned @OriginalName("uint32_t") int out_iovs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_setupmapping_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_setupmapping_in extends Struct {
    public @Unsigned @OriginalName("uint64_t") long fh;

    public @Unsigned @OriginalName("uint64_t") long foffset;

    public @Unsigned @OriginalName("uint64_t") long len;

    public @Unsigned @OriginalName("uint64_t") long flags;

    public @Unsigned @OriginalName("uint64_t") long moffset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_removemapping_in"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_removemapping_in extends Struct {
    public @Unsigned @OriginalName("uint32_t") int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_removemapping_one"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_removemapping_one extends Struct {
    public @Unsigned @OriginalName("uint64_t") long moffset;

    public @Unsigned @OriginalName("uint64_t") long len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_inode_dax"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_inode_dax extends Struct {
    public rw_semaphore sem;

    public rb_root_cached tree;

    public @Unsigned long nr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_conn_dax"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_conn_dax extends Struct {
    public Ptr<dax_device> dev;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned long nr_busy_ranges;

    public list_head busy_ranges;

    public delayed_work free_work;

    public @OriginalName("wait_queue_head_t") wait_queue_head range_waitq;

    public long nr_free_ranges;

    public list_head free_ranges;

    public @Unsigned long nr_ranges;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_dax_mapping"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_dax_mapping extends Struct {
    public Ptr<inode> inode;

    public list_head list;

    public interval_tree_node itn;

    public list_head busy_list;

    public @Unsigned long window_offset;

    public @OriginalName("loff_t") long length;

    public boolean writable;

    public @OriginalName("refcount_t") refcount_struct refcnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_uring_ent_in_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_uring_ent_in_out extends Struct {
    public @Unsigned @OriginalName("uint64_t") long flags;

    public @Unsigned @OriginalName("uint64_t") long commit_id;

    public @Unsigned @OriginalName("uint32_t") int payload_sz;

    public @Unsigned @OriginalName("uint32_t") int padding;

    public @Unsigned @OriginalName("uint64_t") long reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_uring_req_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_uring_req_header extends Struct {
    public char @Size(128) [] in_out;

    public char @Size(128) [] op_in;

    public fuse_uring_ent_in_out ring_ent_in_out;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_uring_cmd"
  )
  public enum fuse_uring_cmd implements Enum<fuse_uring_cmd>, TypedEnum<fuse_uring_cmd, java.lang. @Unsigned Integer> {
    /**
     * {@code FUSE_IO_URING_CMD_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FUSE_IO_URING_CMD_INVALID"
    )
    FUSE_IO_URING_CMD_INVALID,

    /**
     * {@code FUSE_IO_URING_CMD_REGISTER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FUSE_IO_URING_CMD_REGISTER"
    )
    FUSE_IO_URING_CMD_REGISTER,

    /**
     * {@code FUSE_IO_URING_CMD_COMMIT_AND_FETCH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FUSE_IO_URING_CMD_COMMIT_AND_FETCH"
    )
    FUSE_IO_URING_CMD_COMMIT_AND_FETCH
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_uring_cmd_req"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_uring_cmd_req extends Struct {
    public @Unsigned @OriginalName("uint64_t") long flags;

    public @Unsigned @OriginalName("uint64_t") long commit_id;

    public @Unsigned @OriginalName("uint16_t") short qid;

    public @OriginalName("uint8_t") char @Size(6) [] padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum fuse_ring_req_state"
  )
  public enum fuse_ring_req_state implements Enum<fuse_ring_req_state>, TypedEnum<fuse_ring_req_state, java.lang. @Unsigned Integer> {
    /**
     * {@code FRRS_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FRRS_INVALID"
    )
    FRRS_INVALID,

    /**
     * {@code FRRS_COMMIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FRRS_COMMIT"
    )
    FRRS_COMMIT,

    /**
     * {@code FRRS_AVAILABLE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FRRS_AVAILABLE"
    )
    FRRS_AVAILABLE,

    /**
     * {@code FRRS_FUSE_REQ = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FRRS_FUSE_REQ"
    )
    FRRS_FUSE_REQ,

    /**
     * {@code FRRS_USERSPACE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FRRS_USERSPACE"
    )
    FRRS_USERSPACE,

    /**
     * {@code FRRS_TEARDOWN = 5}
     */
    @EnumMember(
        value = 5L,
        name = "FRRS_TEARDOWN"
    )
    FRRS_TEARDOWN,

    /**
     * {@code FRRS_RELEASED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "FRRS_RELEASED"
    )
    FRRS_RELEASED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_ring_ent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_ring_ent extends Struct {
    public Ptr<fuse_uring_req_header> headers;

    public Ptr<?> payload;

    public Ptr<fuse_ring_queue> queue;

    public Ptr<io_uring_cmd> cmd;

    public list_head list;

    public fuse_ring_req_state state;

    public Ptr<fuse_req> fuse_req;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct fuse_uring_pdu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class fuse_uring_pdu extends Struct {
    public Ptr<fuse_ring_ent> ent;
  }
}
