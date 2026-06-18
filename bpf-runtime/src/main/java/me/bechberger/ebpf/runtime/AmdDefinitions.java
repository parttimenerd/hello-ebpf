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
 * Generated class for BPF runtime types that start with amd
 */
@java.lang.SuppressWarnings("unused")
public final class AmdDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __amd_smn_rw(char i_off, char d_off, @Unsigned short node,
      @Unsigned int address, Ptr<java.lang. @Unsigned Integer> value, boolean write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_atl_register_decoder((long unsigned int (*)(struct atl_err*))$arg1)")
  public static void amd_atl_register_decoder(Ptr<?> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_atl_unregister_decoder() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short amd_branches_is_visible(Ptr<kobject> kobj,
      Ptr<attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_brs_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_brs_disable_all() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_brs_drain() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_brs_enable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_brs_enable_all() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_brs_hw_config(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_brs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short amd_brs_is_visible(Ptr<kobject> kobj,
      Ptr<attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_brs_lopwr_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_brs_reset() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_bus_cpu_online(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_cache_northbridges() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_cc_platform_has(cc_attr attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_check_microcode() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long amd_convert_umc_mca_addr_to_sys_addr(Ptr<atl_err> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_core_pmu_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_cppc_supported() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_deferred_error_interrupt() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_detect_prefcore(Ptr<java.lang. @OriginalName("bool") Boolean> detected) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_disable_seq_and_redirect_scrub(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_e400_c1e_apic_setup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_enc_cache_flush_required() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_enc_status_change_finish(@Unsigned long vaddr, int npages, boolean enc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_enc_status_change_prepare(@Unsigned long vaddr, int npages, boolean enc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_enc_tlb_flush_required(boolean enc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long amd_event_sysfs_show(String page,
      @Unsigned long config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_filter_mce(Ptr<mce> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_flush_garts() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_gart_present() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_get_boost_ratio_numerator(@Unsigned int cpu,
      Ptr<java.lang. @Unsigned Long> numerator) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long amd_get_dr_addr_mask(@Unsigned int dr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<event_constraint> amd_get_event_constraints(Ptr<cpu_hw_events> cpuc, int idx,
      Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<event_constraint> amd_get_event_constraints_f15h(Ptr<cpu_hw_events> cpuc,
      int idx, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<event_constraint> amd_get_event_constraints_f17h(Ptr<cpu_hw_events> cpuc,
      int idx, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<event_constraint> amd_get_event_constraints_f19h(Ptr<cpu_hw_events> cpuc,
      int idx, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)amd_get_fname($arg1, $arg2))")
  public static String amd_get_fname(Ptr<pinctrl_dev> pctrldev, @Unsigned int selector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_get_functions_count(Ptr<pinctrl_dev> pctldev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)amd_get_group_name($arg1, $arg2))")
  public static String amd_get_group_name(Ptr<pinctrl_dev> pctldev, @Unsigned int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_get_group_pins($arg1, $arg2, (const unsigned int**)$arg3, $arg4)")
  public static int amd_get_group_pins(Ptr<pinctrl_dev> pctldev, @Unsigned int group,
      Ptr<Ptr<java.lang. @Unsigned Integer>> pins, Ptr<java.lang. @Unsigned Integer> num_pins) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_get_groups($arg1, $arg2, (const const u8***)$arg3, (const unsigned int*)$arg4)")
  public static int amd_get_groups(Ptr<pinctrl_dev> pctrldev, @Unsigned int selector,
      Ptr<Ptr<String>> groups, Ptr<java.lang. @Unsigned Integer> num_groups) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_get_groups_count(Ptr<pinctrl_dev> pctldev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_get_highest_perf(@Unsigned int cpu,
      Ptr<java.lang. @Unsigned Integer> highest_perf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<resource> amd_get_mmconfig_range(Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_get_subcaches(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_check_pending() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_gpio_check_wake(Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_dbg_show(Ptr<seq_file> s, Ptr<gpio_chip> gc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_direction_input(Ptr<gpio_chip> gc, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_direction_output(Ptr<gpio_chip> gc, @Unsigned int offset, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_driver_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_driver_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_get_direction(Ptr<gpio_chip> gc, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_get_value(Ptr<gpio_chip> gc, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_hibernate(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_irq_disable(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_irq_enable(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_irq_eoi(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn amd_gpio_irq_handler(int irq,
      Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_irq_mask(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_irq_set_type(Ptr<irq_data> d, @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_irq_set_wake(Ptr<irq_data> d, @Unsigned int on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_irq_unmask(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_probe(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_gpio_remove(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_set_config(Ptr<gpio_chip> gc, @Unsigned int pin,
      @Unsigned long config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_set_debounce(Ptr<amd_gpio> gpio_dev, @Unsigned int offset,
      @Unsigned int debounce) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_set_value(Ptr<gpio_chip> gc, @Unsigned int offset, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_gpio_should_save(Ptr<amd_gpio> gpio_dev, @Unsigned int pin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_gpio_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_alloc_class_data(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_hfi_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_fill_metadata(Ptr<amd_hfi_data> amd_hfi_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_offline(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_online(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_pm_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_pm_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_hfi_probe(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_hfi_remove(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_hfi_sched_itmt_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_i2c_dw_xfer_quirk(Ptr<i2c_adapter> adap, Ptr<i2c_msg> msgs, int num_msgs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_ibs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<amd_northbridge> amd_init_l3_cache(int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_activate_guest_mode(Ptr<?> data, int cpu, boolean ga_log_intr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_alloc_ppr_log(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_apply_ivrs_quirks() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_attach_device(Ptr<iommu_domain> dom, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_iommu_capable(Ptr<device> dev, iommu_cap cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_clear_gcr3(Ptr<iommu_dev_data> dev_data,
      @Unsigned @OriginalName("ioasid_t") int pasid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_complete_ppr(Ptr<device> dev, @Unsigned int pasid, int status,
      int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_create_irq_domain(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_deactivate_guest_mode(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_def_domain_type(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_detect() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_dev_flush_pasid_pages(Ptr<iommu_dev_data> dev_data,
      @Unsigned @OriginalName("ioasid_t") int pasid, @Unsigned long address, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_group> amd_iommu_device_group(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_iommu_domain_alloc_paging_flags($arg1, $arg2, (const struct iommu_user_data*)$arg3)")
  public static Ptr<iommu_domain> amd_iommu_domain_alloc_paging_flags(Ptr<device> dev,
      @Unsigned int flags, Ptr<iommu_user_data> user_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_domain> amd_iommu_domain_alloc_sva(Ptr<device> dev, Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_domain_flush_pages(Ptr<protection_domain> domain,
      @Unsigned long address, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_domain_free(Ptr<iommu_domain> dom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_enable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_enable_faulting(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_enable_interrupts() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_enable_ppr_log(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_iommu_enforce_cache_coherency(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_flush_all_caches(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_flush_iotlb_all(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_free_ppr_log(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dev_table_entry> amd_iommu_get_ivhd_dte_flags(@Unsigned short segid,
      @Unsigned short devid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_get_num_iommus() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_get_resv_regions(Ptr<device> dev, Ptr<list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_iommu_gt_ppr_supported() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_iommu_ht_range_ignore() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_init_identity_domain() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_init_pci() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn amd_iommu_int_handler(int irq, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn amd_iommu_int_thread(int irq, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn amd_iommu_int_thread_evtlog(int irq,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn amd_iommu_int_thread_galog(int irq,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn amd_iommu_int_thread_pprlog(int irq,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_iopf_add_device(Ptr<amd_iommu> iommu, Ptr<iommu_dev_data> dev_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_iopf_init(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_iopf_remove_device(Ptr<amd_iommu> iommu,
      Ptr<iommu_dev_data> dev_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_iopf_uninit(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_iotlb_sync(Ptr<iommu_domain> domain,
      Ptr<iommu_iotlb_gather> gather) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_iotlb_sync_map(Ptr<iommu_domain> dom, @Unsigned long iova,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("phys_addr_t") long amd_iommu_iova_to_phys(
      Ptr<iommu_domain> dom, @Unsigned @OriginalName("dma_addr_t") long iova) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_iommu_is_attach_deferred(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_map_pages(Ptr<iommu_domain> dom, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long pgsize,
      @Unsigned long pgcount, int iommu_prot, @Unsigned @OriginalName("gfp_t") int gfp,
      Ptr<java.lang. @Unsigned Long> mapped) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_page_response(Ptr<device> dev, Ptr<iopf_fault> evt,
      Ptr<iommu_page_response> resp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_iommu_pasid_supported() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char amd_iommu_pc_get_max_banks(@Unsigned int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char amd_iommu_pc_get_max_counters(@Unsigned int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_pc_get_reg(Ptr<amd_iommu> iommu, char bank, char cntr, char fxn,
      Ptr<java.lang. @Unsigned Long> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_pc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_pc_set_reg(Ptr<amd_iommu> iommu, char bank, char cntr, char fxn,
      Ptr<java.lang. @Unsigned Long> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_iommu_pc_supported() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_poll_ppr_log(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_prepare() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_device> amd_iommu_probe_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_read_and_clear_dirty(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned long size, @Unsigned long flags, Ptr<iommu_dirty_bitmap> dirty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_reenable(int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_iommu_register_ga_log_notifier((int (*)(unsigned int))$arg1)")
  public static int amd_iommu_register_ga_log_notifier(Ptr<?> notifier) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_release_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_remove_dev_pasid(Ptr<device> dev,
      @Unsigned @OriginalName("ioasid_t") int pasid, Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_report_page_fault(Ptr<amd_iommu> iommu, @Unsigned short devid,
      @Unsigned short domain_id, @Unsigned long address, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_restart_event_logging(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_restart_ga_log(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_iommu_restart_log($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void amd_iommu_restart_log(Ptr<amd_iommu> iommu, String evt_type, char cntrl_intr,
      char cntrl_log, @Unsigned int status_run_mask, @Unsigned int status_overflow_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_restart_ppr_log(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_resume() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_set_dirty_tracking(Ptr<iommu_domain> domain, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_set_gcr3(Ptr<iommu_dev_data> dev_data,
      @Unsigned @OriginalName("ioasid_t") int pasid, @Unsigned long gcr3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_set_rlookup_table(Ptr<amd_iommu> iommu, @Unsigned short devid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long amd_iommu_show_cap(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long amd_iommu_show_features(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_snp_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_suspend() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long amd_iommu_unmap_pages(Ptr<iommu_domain> dom, @Unsigned long iova,
      @Unsigned long pgsize, @Unsigned long pgcount, Ptr<iommu_iotlb_gather> gather) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_iommu_update_and_flush_device_table(Ptr<protection_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_iommu_update_ga(Ptr<?> data, int cpu, boolean ga_log_intr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_ir_set_affinity($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static int amd_ir_set_affinity(Ptr<irq_data> data, Ptr<cpumask> mask, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_ir_set_vcpu_affinity(Ptr<irq_data> data, Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_irq_ack(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_mce_is_memory_error(Ptr<mce> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_mce_usable_address(Ptr<mce> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_nb_has_feature(@Unsigned int feature) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short amd_nb_num() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pci_dev> amd_node_get_func(@Unsigned short node, char func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_numa_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pinconf_get(Ptr<pinctrl_dev> pctldev, @Unsigned int pin,
      Ptr<java.lang. @Unsigned Long> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pinconf_group_get(Ptr<pinctrl_dev> pctldev, @Unsigned int group,
      Ptr<java.lang. @Unsigned Long> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pinconf_group_set(Ptr<pinctrl_dev> pctldev, @Unsigned int group,
      Ptr<java.lang. @Unsigned Long> configs, @Unsigned int num_configs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pinconf_set(Ptr<pinctrl_dev> pctldev, @Unsigned int pin,
      Ptr<java.lang. @Unsigned Long> configs, @Unsigned int num_configs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_add_event(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_addr_offset(int index, boolean eventsel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_brs_add(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_brs_del(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_brs_sched_task(Ptr<perf_event_pmu_context> pmu_ctx,
      Ptr<task_struct> task, boolean sched_in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_check_overflow() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_cpu_dead(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_cpu_prepare(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_cpu_starting(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_del_event(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_disable_all() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_disable_event(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_disable_virt() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_enable_all(int added) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_enable_event(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_enable_virt() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long amd_pmu_event_map(int hw_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_handle_irq(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_hw_config(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_add(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_del(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_disable_all() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_enable_all() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_filter() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_lbr_hw_config(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_lbr_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_read() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_reset() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_lbr_sched_task(Ptr<perf_event_pmu_context> pmu_ctx,
      Ptr<task_struct> task, boolean sched_in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_limit_period(Ptr<perf_event> event, Ptr<java.lang.Long> left) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_pmu_test_overflow_status(int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_pmu_test_overflow_topbit(int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_v2_disable_all() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_v2_enable_all(int added) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pmu_v2_enable_event(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_v2_handle_irq(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pmu_v2_snapshot_branch_stack(Ptr<perf_branch_entry> entries,
      @Unsigned int cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pogo_errata_restore_misc_reg(Ptr<slot> p_slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_postcore_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_prefcore_param(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pstate_adjust_perf(@Unsigned int cpu, @Unsigned long _min_perf,
      @Unsigned long target_perf, @Unsigned long capacity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_change_driver_mode(int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_change_mode_without_dvr_change(int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pstate_cpu_exit(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_cpu_init(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_cpu_offline(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_cpu_online(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pstate_epp_cpu_exit(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_epp_cpu_init(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_epp_resume(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_epp_set_policy(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_epp_update_limit(Ptr<cpufreq_policy> policy, boolean policy_change) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int amd_pstate_fast_switch(Ptr<cpufreq_policy> policy,
      @Unsigned int target_freq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)amd_pstate_get_mode_string($arg1))")
  public static String amd_pstate_get_mode_string(amd_pstate_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_get_status() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_init_boost_support(Ptr<amd_cpudata> cpudata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_init_freq(Ptr<amd_cpudata> cpudata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pstate_init_prefcore(Ptr<amd_cpudata> cpudata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_param(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_register_driver(int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_resume(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean amd_pstate_sample(Ptr<amd_cpudata> cpudata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_set_boost(Ptr<cpufreq_policy> policy, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_set_driver(int mode_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_suspend(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_target(Ptr<cpufreq_policy> policy, @Unsigned int target_freq,
      @Unsigned int relation) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_unregister_driver(int dummy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pstate_update(Ptr<amd_cpudata> cpudata, char min_perf, char des_perf,
      char max_perf, boolean fast_switch, int gov_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_update_freq(Ptr<cpufreq_policy> policy, @Unsigned int target_freq,
      boolean fast_switch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pstate_update_limits(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_pstate_update_min_max_limit(Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("amd_pstate_update_status((const u8*)$arg1, $arg2)")
  public static int amd_pstate_update_status(String buf, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_pstate_verify(Ptr<cpufreq_policy_data> policy_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_put_event_constraints(Ptr<cpu_hw_events> cpuc, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_put_event_constraints_f17h(Ptr<cpu_hw_events> cpuc,
      Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_router_probe(Ptr<irq_router> r, Ptr<pci_dev> router,
      @Unsigned short device) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_rp_pme_resume(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_rp_pme_suspend(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_set_dr_addr_mask(@Unsigned long mask, @Unsigned int dr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_set_mux(Ptr<pinctrl_dev> pctrldev, @Unsigned int function,
      @Unsigned int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_set_subcaches(int cpu, @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_smn_enable_dfs(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_smn_hsmp_rdwr(@Unsigned short node, @Unsigned int address,
      Ptr<java.lang. @Unsigned Integer> value, boolean write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_smn_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_smn_read(@Unsigned short node, @Unsigned int address,
      Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_smn_write(@Unsigned short node, @Unsigned int address,
      @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_special_default_mtrr() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void amd_threshold_interrupt() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_wbrf_register_notifier(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_wbrf_retrieve_freq_band(Ptr<device> dev, Ptr<wbrf_ranges_in_out> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int amd_wbrf_unregister_notifier(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_nb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_nb extends Struct {
    public int nb_id;

    public int refcnt;

    public Ptr<perf_event> @Size(64) [] owners;

    public event_constraint @Size(64) [] event_constraints;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union amd_debug_extn_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_debug_extn_cfg extends Union {
    public @Unsigned long val;

    public anon_member_of_amd_debug_extn_cfg anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_iommu_event_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_iommu_event_desc extends Struct {
    public device_attribute attr;

    public String event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_l3_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_l3_cache extends Struct {
    public @Unsigned int indices;

    public char @Size(4) [] subcaches;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_northbridge"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_northbridge extends Struct {
    public Ptr<pci_dev> misc;

    public Ptr<pci_dev> link;

    public amd_l3_cache l3_cache;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int synd1; long long unsigned int synd2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_of_vendor_info extends Struct {
    public @Unsigned long synd1;

    public @Unsigned long synd2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum amd_pref_core"
  )
  public enum amd_pref_core implements Enum<amd_pref_core>, TypedEnum<amd_pref_core, java.lang. @Unsigned Integer> {
    /**
     * {@code AMD_PREF_CORE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "AMD_PREF_CORE_UNKNOWN"
    )
    AMD_PREF_CORE_UNKNOWN,

    /**
     * {@code AMD_PREF_CORE_SUPPORTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "AMD_PREF_CORE_SUPPORTED"
    )
    AMD_PREF_CORE_SUPPORTED,

    /**
     * {@code AMD_PREF_CORE_UNSUPPORTED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "AMD_PREF_CORE_UNSUPPORTED"
    )
    AMD_PREF_CORE_UNSUPPORTED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_nb_bus_dev_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_nb_bus_dev_range extends Struct {
    public char bus;

    public char dev_base;

    public char dev_limit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_northbridge_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_northbridge_info extends Struct {
    public @Unsigned short num;

    public @Unsigned long flags;

    public Ptr<amd_northbridge> nb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_function"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_function extends Struct {
    public String name;

    public String @Size(4) [] groups;

    public @Unsigned int ngroups;

    public int index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_gpio"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_gpio extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public Ptr<?> base;

    public Ptr<?> iomux_base;

    public Ptr<pingroup> groups;

    public @Unsigned int ngroups;

    public Ptr<pinctrl_dev> pctrl;

    public gpio_chip gc;

    public @Unsigned int hwbank_num;

    public Ptr<resource> res;

    public Ptr<platform_device> pdev;

    public Ptr<java.lang. @Unsigned Integer> saved_regs;

    public int irq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum amd_functions"
  )
  public enum amd_functions implements Enum<amd_functions>, TypedEnum<amd_functions, java.lang. @Unsigned Integer> {
    /**
     * {@code IMX_F0_GPIO0 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IMX_F0_GPIO0"
    )
    IMX_F0_GPIO0,

    /**
     * {@code IMX_F1_GPIO0 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IMX_F1_GPIO0"
    )
    IMX_F1_GPIO0,

    /**
     * {@code IMX_F2_GPIO0 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IMX_F2_GPIO0"
    )
    IMX_F2_GPIO0,

    /**
     * {@code IMX_F3_GPIO0 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IMX_F3_GPIO0"
    )
    IMX_F3_GPIO0,

    /**
     * {@code IMX_F0_GPIO1 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IMX_F0_GPIO1"
    )
    IMX_F0_GPIO1,

    /**
     * {@code IMX_F1_GPIO1 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IMX_F1_GPIO1"
    )
    IMX_F1_GPIO1,

    /**
     * {@code IMX_F2_GPIO1 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IMX_F2_GPIO1"
    )
    IMX_F2_GPIO1,

    /**
     * {@code IMX_F3_GPIO1 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IMX_F3_GPIO1"
    )
    IMX_F3_GPIO1,

    /**
     * {@code IMX_F0_GPIO2 = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IMX_F0_GPIO2"
    )
    IMX_F0_GPIO2,

    /**
     * {@code IMX_F1_GPIO2 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IMX_F1_GPIO2"
    )
    IMX_F1_GPIO2,

    /**
     * {@code IMX_F2_GPIO2 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IMX_F2_GPIO2"
    )
    IMX_F2_GPIO2,

    /**
     * {@code IMX_F3_GPIO2 = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IMX_F3_GPIO2"
    )
    IMX_F3_GPIO2,

    /**
     * {@code IMX_F0_GPIO3 = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IMX_F0_GPIO3"
    )
    IMX_F0_GPIO3,

    /**
     * {@code IMX_F1_GPIO3 = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IMX_F1_GPIO3"
    )
    IMX_F1_GPIO3,

    /**
     * {@code IMX_F2_GPIO3 = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IMX_F2_GPIO3"
    )
    IMX_F2_GPIO3,

    /**
     * {@code IMX_F3_GPIO3 = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IMX_F3_GPIO3"
    )
    IMX_F3_GPIO3,

    /**
     * {@code IMX_F0_GPIO4 = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IMX_F0_GPIO4"
    )
    IMX_F0_GPIO4,

    /**
     * {@code IMX_F1_GPIO4 = 17}
     */
    @EnumMember(
        value = 17L,
        name = "IMX_F1_GPIO4"
    )
    IMX_F1_GPIO4,

    /**
     * {@code IMX_F2_GPIO4 = 18}
     */
    @EnumMember(
        value = 18L,
        name = "IMX_F2_GPIO4"
    )
    IMX_F2_GPIO4,

    /**
     * {@code IMX_F3_GPIO4 = 19}
     */
    @EnumMember(
        value = 19L,
        name = "IMX_F3_GPIO4"
    )
    IMX_F3_GPIO4,

    /**
     * {@code IMX_F0_GPIO5 = 20}
     */
    @EnumMember(
        value = 20L,
        name = "IMX_F0_GPIO5"
    )
    IMX_F0_GPIO5,

    /**
     * {@code IMX_F1_GPIO5 = 21}
     */
    @EnumMember(
        value = 21L,
        name = "IMX_F1_GPIO5"
    )
    IMX_F1_GPIO5,

    /**
     * {@code IMX_F2_GPIO5 = 22}
     */
    @EnumMember(
        value = 22L,
        name = "IMX_F2_GPIO5"
    )
    IMX_F2_GPIO5,

    /**
     * {@code IMX_F3_GPIO5 = 23}
     */
    @EnumMember(
        value = 23L,
        name = "IMX_F3_GPIO5"
    )
    IMX_F3_GPIO5,

    /**
     * {@code IMX_F0_GPIO6 = 24}
     */
    @EnumMember(
        value = 24L,
        name = "IMX_F0_GPIO6"
    )
    IMX_F0_GPIO6,

    /**
     * {@code IMX_F1_GPIO6 = 25}
     */
    @EnumMember(
        value = 25L,
        name = "IMX_F1_GPIO6"
    )
    IMX_F1_GPIO6,

    /**
     * {@code IMX_F2_GPIO6 = 26}
     */
    @EnumMember(
        value = 26L,
        name = "IMX_F2_GPIO6"
    )
    IMX_F2_GPIO6,

    /**
     * {@code IMX_F3_GPIO6 = 27}
     */
    @EnumMember(
        value = 27L,
        name = "IMX_F3_GPIO6"
    )
    IMX_F3_GPIO6,

    /**
     * {@code IMX_F0_GPIO7 = 28}
     */
    @EnumMember(
        value = 28L,
        name = "IMX_F0_GPIO7"
    )
    IMX_F0_GPIO7,

    /**
     * {@code IMX_F1_GPIO7 = 29}
     */
    @EnumMember(
        value = 29L,
        name = "IMX_F1_GPIO7"
    )
    IMX_F1_GPIO7,

    /**
     * {@code IMX_F2_GPIO7 = 30}
     */
    @EnumMember(
        value = 30L,
        name = "IMX_F2_GPIO7"
    )
    IMX_F2_GPIO7,

    /**
     * {@code IMX_F3_GPIO7 = 31}
     */
    @EnumMember(
        value = 31L,
        name = "IMX_F3_GPIO7"
    )
    IMX_F3_GPIO7,

    /**
     * {@code IMX_F0_GPIO8 = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IMX_F0_GPIO8"
    )
    IMX_F0_GPIO8,

    /**
     * {@code IMX_F1_GPIO8 = 33}
     */
    @EnumMember(
        value = 33L,
        name = "IMX_F1_GPIO8"
    )
    IMX_F1_GPIO8,

    /**
     * {@code IMX_F2_GPIO8 = 34}
     */
    @EnumMember(
        value = 34L,
        name = "IMX_F2_GPIO8"
    )
    IMX_F2_GPIO8,

    /**
     * {@code IMX_F3_GPIO8 = 35}
     */
    @EnumMember(
        value = 35L,
        name = "IMX_F3_GPIO8"
    )
    IMX_F3_GPIO8,

    /**
     * {@code IMX_F0_GPIO9 = 36}
     */
    @EnumMember(
        value = 36L,
        name = "IMX_F0_GPIO9"
    )
    IMX_F0_GPIO9,

    /**
     * {@code IMX_F1_GPIO9 = 37}
     */
    @EnumMember(
        value = 37L,
        name = "IMX_F1_GPIO9"
    )
    IMX_F1_GPIO9,

    /**
     * {@code IMX_F2_GPIO9 = 38}
     */
    @EnumMember(
        value = 38L,
        name = "IMX_F2_GPIO9"
    )
    IMX_F2_GPIO9,

    /**
     * {@code IMX_F3_GPIO9 = 39}
     */
    @EnumMember(
        value = 39L,
        name = "IMX_F3_GPIO9"
    )
    IMX_F3_GPIO9,

    /**
     * {@code IMX_F0_GPIO10 = 40}
     */
    @EnumMember(
        value = 40L,
        name = "IMX_F0_GPIO10"
    )
    IMX_F0_GPIO10,

    /**
     * {@code IMX_F1_GPIO10 = 41}
     */
    @EnumMember(
        value = 41L,
        name = "IMX_F1_GPIO10"
    )
    IMX_F1_GPIO10,

    /**
     * {@code IMX_F2_GPIO10 = 42}
     */
    @EnumMember(
        value = 42L,
        name = "IMX_F2_GPIO10"
    )
    IMX_F2_GPIO10,

    /**
     * {@code IMX_F3_GPIO10 = 43}
     */
    @EnumMember(
        value = 43L,
        name = "IMX_F3_GPIO10"
    )
    IMX_F3_GPIO10,

    /**
     * {@code IMX_F0_GPIO11 = 44}
     */
    @EnumMember(
        value = 44L,
        name = "IMX_F0_GPIO11"
    )
    IMX_F0_GPIO11,

    /**
     * {@code IMX_F1_GPIO11 = 45}
     */
    @EnumMember(
        value = 45L,
        name = "IMX_F1_GPIO11"
    )
    IMX_F1_GPIO11,

    /**
     * {@code IMX_F2_GPIO11 = 46}
     */
    @EnumMember(
        value = 46L,
        name = "IMX_F2_GPIO11"
    )
    IMX_F2_GPIO11,

    /**
     * {@code IMX_F3_GPIO11 = 47}
     */
    @EnumMember(
        value = 47L,
        name = "IMX_F3_GPIO11"
    )
    IMX_F3_GPIO11,

    /**
     * {@code IMX_F0_GPIO12 = 48}
     */
    @EnumMember(
        value = 48L,
        name = "IMX_F0_GPIO12"
    )
    IMX_F0_GPIO12,

    /**
     * {@code IMX_F1_GPIO12 = 49}
     */
    @EnumMember(
        value = 49L,
        name = "IMX_F1_GPIO12"
    )
    IMX_F1_GPIO12,

    /**
     * {@code IMX_F2_GPIO12 = 50}
     */
    @EnumMember(
        value = 50L,
        name = "IMX_F2_GPIO12"
    )
    IMX_F2_GPIO12,

    /**
     * {@code IMX_F3_GPIO12 = 51}
     */
    @EnumMember(
        value = 51L,
        name = "IMX_F3_GPIO12"
    )
    IMX_F3_GPIO12,

    /**
     * {@code IMX_F0_GPIO13 = 52}
     */
    @EnumMember(
        value = 52L,
        name = "IMX_F0_GPIO13"
    )
    IMX_F0_GPIO13,

    /**
     * {@code IMX_F1_GPIO13 = 53}
     */
    @EnumMember(
        value = 53L,
        name = "IMX_F1_GPIO13"
    )
    IMX_F1_GPIO13,

    /**
     * {@code IMX_F2_GPIO13 = 54}
     */
    @EnumMember(
        value = 54L,
        name = "IMX_F2_GPIO13"
    )
    IMX_F2_GPIO13,

    /**
     * {@code IMX_F3_GPIO13 = 55}
     */
    @EnumMember(
        value = 55L,
        name = "IMX_F3_GPIO13"
    )
    IMX_F3_GPIO13,

    /**
     * {@code IMX_F0_GPIO14 = 56}
     */
    @EnumMember(
        value = 56L,
        name = "IMX_F0_GPIO14"
    )
    IMX_F0_GPIO14,

    /**
     * {@code IMX_F1_GPIO14 = 57}
     */
    @EnumMember(
        value = 57L,
        name = "IMX_F1_GPIO14"
    )
    IMX_F1_GPIO14,

    /**
     * {@code IMX_F2_GPIO14 = 58}
     */
    @EnumMember(
        value = 58L,
        name = "IMX_F2_GPIO14"
    )
    IMX_F2_GPIO14,

    /**
     * {@code IMX_F3_GPIO14 = 59}
     */
    @EnumMember(
        value = 59L,
        name = "IMX_F3_GPIO14"
    )
    IMX_F3_GPIO14,

    /**
     * {@code IMX_F0_GPIO15 = 60}
     */
    @EnumMember(
        value = 60L,
        name = "IMX_F0_GPIO15"
    )
    IMX_F0_GPIO15,

    /**
     * {@code IMX_F1_GPIO15 = 61}
     */
    @EnumMember(
        value = 61L,
        name = "IMX_F1_GPIO15"
    )
    IMX_F1_GPIO15,

    /**
     * {@code IMX_F2_GPIO15 = 62}
     */
    @EnumMember(
        value = 62L,
        name = "IMX_F2_GPIO15"
    )
    IMX_F2_GPIO15,

    /**
     * {@code IMX_F3_GPIO15 = 63}
     */
    @EnumMember(
        value = 63L,
        name = "IMX_F3_GPIO15"
    )
    IMX_F3_GPIO15,

    /**
     * {@code IMX_F0_GPIO16 = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IMX_F0_GPIO16"
    )
    IMX_F0_GPIO16,

    /**
     * {@code IMX_F1_GPIO16 = 65}
     */
    @EnumMember(
        value = 65L,
        name = "IMX_F1_GPIO16"
    )
    IMX_F1_GPIO16,

    /**
     * {@code IMX_F2_GPIO16 = 66}
     */
    @EnumMember(
        value = 66L,
        name = "IMX_F2_GPIO16"
    )
    IMX_F2_GPIO16,

    /**
     * {@code IMX_F3_GPIO16 = 67}
     */
    @EnumMember(
        value = 67L,
        name = "IMX_F3_GPIO16"
    )
    IMX_F3_GPIO16,

    /**
     * {@code IMX_F0_GPIO17 = 68}
     */
    @EnumMember(
        value = 68L,
        name = "IMX_F0_GPIO17"
    )
    IMX_F0_GPIO17,

    /**
     * {@code IMX_F1_GPIO17 = 69}
     */
    @EnumMember(
        value = 69L,
        name = "IMX_F1_GPIO17"
    )
    IMX_F1_GPIO17,

    /**
     * {@code IMX_F2_GPIO17 = 70}
     */
    @EnumMember(
        value = 70L,
        name = "IMX_F2_GPIO17"
    )
    IMX_F2_GPIO17,

    /**
     * {@code IMX_F3_GPIO17 = 71}
     */
    @EnumMember(
        value = 71L,
        name = "IMX_F3_GPIO17"
    )
    IMX_F3_GPIO17,

    /**
     * {@code IMX_F0_GPIO18 = 72}
     */
    @EnumMember(
        value = 72L,
        name = "IMX_F0_GPIO18"
    )
    IMX_F0_GPIO18,

    /**
     * {@code IMX_F1_GPIO18 = 73}
     */
    @EnumMember(
        value = 73L,
        name = "IMX_F1_GPIO18"
    )
    IMX_F1_GPIO18,

    /**
     * {@code IMX_F2_GPIO18 = 74}
     */
    @EnumMember(
        value = 74L,
        name = "IMX_F2_GPIO18"
    )
    IMX_F2_GPIO18,

    /**
     * {@code IMX_F3_GPIO18 = 75}
     */
    @EnumMember(
        value = 75L,
        name = "IMX_F3_GPIO18"
    )
    IMX_F3_GPIO18,

    /**
     * {@code IMX_F0_GPIO19 = 76}
     */
    @EnumMember(
        value = 76L,
        name = "IMX_F0_GPIO19"
    )
    IMX_F0_GPIO19,

    /**
     * {@code IMX_F1_GPIO19 = 77}
     */
    @EnumMember(
        value = 77L,
        name = "IMX_F1_GPIO19"
    )
    IMX_F1_GPIO19,

    /**
     * {@code IMX_F2_GPIO19 = 78}
     */
    @EnumMember(
        value = 78L,
        name = "IMX_F2_GPIO19"
    )
    IMX_F2_GPIO19,

    /**
     * {@code IMX_F3_GPIO19 = 79}
     */
    @EnumMember(
        value = 79L,
        name = "IMX_F3_GPIO19"
    )
    IMX_F3_GPIO19,

    /**
     * {@code IMX_F0_GPIO20 = 80}
     */
    @EnumMember(
        value = 80L,
        name = "IMX_F0_GPIO20"
    )
    IMX_F0_GPIO20,

    /**
     * {@code IMX_F1_GPIO20 = 81}
     */
    @EnumMember(
        value = 81L,
        name = "IMX_F1_GPIO20"
    )
    IMX_F1_GPIO20,

    /**
     * {@code IMX_F2_GPIO20 = 82}
     */
    @EnumMember(
        value = 82L,
        name = "IMX_F2_GPIO20"
    )
    IMX_F2_GPIO20,

    /**
     * {@code IMX_F3_GPIO20 = 83}
     */
    @EnumMember(
        value = 83L,
        name = "IMX_F3_GPIO20"
    )
    IMX_F3_GPIO20,

    /**
     * {@code IMX_F0_GPIO21 = 84}
     */
    @EnumMember(
        value = 84L,
        name = "IMX_F0_GPIO21"
    )
    IMX_F0_GPIO21,

    /**
     * {@code IMX_F1_GPIO21 = 85}
     */
    @EnumMember(
        value = 85L,
        name = "IMX_F1_GPIO21"
    )
    IMX_F1_GPIO21,

    /**
     * {@code IMX_F2_GPIO21 = 86}
     */
    @EnumMember(
        value = 86L,
        name = "IMX_F2_GPIO21"
    )
    IMX_F2_GPIO21,

    /**
     * {@code IMX_F3_GPIO21 = 87}
     */
    @EnumMember(
        value = 87L,
        name = "IMX_F3_GPIO21"
    )
    IMX_F3_GPIO21,

    /**
     * {@code IMX_F0_GPIO22 = 88}
     */
    @EnumMember(
        value = 88L,
        name = "IMX_F0_GPIO22"
    )
    IMX_F0_GPIO22,

    /**
     * {@code IMX_F1_GPIO22 = 89}
     */
    @EnumMember(
        value = 89L,
        name = "IMX_F1_GPIO22"
    )
    IMX_F1_GPIO22,

    /**
     * {@code IMX_F2_GPIO22 = 90}
     */
    @EnumMember(
        value = 90L,
        name = "IMX_F2_GPIO22"
    )
    IMX_F2_GPIO22,

    /**
     * {@code IMX_F3_GPIO22 = 91}
     */
    @EnumMember(
        value = 91L,
        name = "IMX_F3_GPIO22"
    )
    IMX_F3_GPIO22,

    /**
     * {@code IMX_F0_GPIO23 = 92}
     */
    @EnumMember(
        value = 92L,
        name = "IMX_F0_GPIO23"
    )
    IMX_F0_GPIO23,

    /**
     * {@code IMX_F1_GPIO23 = 93}
     */
    @EnumMember(
        value = 93L,
        name = "IMX_F1_GPIO23"
    )
    IMX_F1_GPIO23,

    /**
     * {@code IMX_F2_GPIO23 = 94}
     */
    @EnumMember(
        value = 94L,
        name = "IMX_F2_GPIO23"
    )
    IMX_F2_GPIO23,

    /**
     * {@code IMX_F3_GPIO23 = 95}
     */
    @EnumMember(
        value = 95L,
        name = "IMX_F3_GPIO23"
    )
    IMX_F3_GPIO23,

    /**
     * {@code IMX_F0_GPIO24 = 96}
     */
    @EnumMember(
        value = 96L,
        name = "IMX_F0_GPIO24"
    )
    IMX_F0_GPIO24,

    /**
     * {@code IMX_F1_GPIO24 = 97}
     */
    @EnumMember(
        value = 97L,
        name = "IMX_F1_GPIO24"
    )
    IMX_F1_GPIO24,

    /**
     * {@code IMX_F2_GPIO24 = 98}
     */
    @EnumMember(
        value = 98L,
        name = "IMX_F2_GPIO24"
    )
    IMX_F2_GPIO24,

    /**
     * {@code IMX_F3_GPIO24 = 99}
     */
    @EnumMember(
        value = 99L,
        name = "IMX_F3_GPIO24"
    )
    IMX_F3_GPIO24,

    /**
     * {@code IMX_F0_GPIO25 = 100}
     */
    @EnumMember(
        value = 100L,
        name = "IMX_F0_GPIO25"
    )
    IMX_F0_GPIO25,

    /**
     * {@code IMX_F1_GPIO25 = 101}
     */
    @EnumMember(
        value = 101L,
        name = "IMX_F1_GPIO25"
    )
    IMX_F1_GPIO25,

    /**
     * {@code IMX_F2_GPIO25 = 102}
     */
    @EnumMember(
        value = 102L,
        name = "IMX_F2_GPIO25"
    )
    IMX_F2_GPIO25,

    /**
     * {@code IMX_F3_GPIO25 = 103}
     */
    @EnumMember(
        value = 103L,
        name = "IMX_F3_GPIO25"
    )
    IMX_F3_GPIO25,

    /**
     * {@code IMX_F0_GPIO26 = 104}
     */
    @EnumMember(
        value = 104L,
        name = "IMX_F0_GPIO26"
    )
    IMX_F0_GPIO26,

    /**
     * {@code IMX_F1_GPIO26 = 105}
     */
    @EnumMember(
        value = 105L,
        name = "IMX_F1_GPIO26"
    )
    IMX_F1_GPIO26,

    /**
     * {@code IMX_F2_GPIO26 = 106}
     */
    @EnumMember(
        value = 106L,
        name = "IMX_F2_GPIO26"
    )
    IMX_F2_GPIO26,

    /**
     * {@code IMX_F3_GPIO26 = 107}
     */
    @EnumMember(
        value = 107L,
        name = "IMX_F3_GPIO26"
    )
    IMX_F3_GPIO26,

    /**
     * {@code IMX_F0_GPIO27 = 108}
     */
    @EnumMember(
        value = 108L,
        name = "IMX_F0_GPIO27"
    )
    IMX_F0_GPIO27,

    /**
     * {@code IMX_F1_GPIO27 = 109}
     */
    @EnumMember(
        value = 109L,
        name = "IMX_F1_GPIO27"
    )
    IMX_F1_GPIO27,

    /**
     * {@code IMX_F2_GPIO27 = 110}
     */
    @EnumMember(
        value = 110L,
        name = "IMX_F2_GPIO27"
    )
    IMX_F2_GPIO27,

    /**
     * {@code IMX_F3_GPIO27 = 111}
     */
    @EnumMember(
        value = 111L,
        name = "IMX_F3_GPIO27"
    )
    IMX_F3_GPIO27,

    /**
     * {@code IMX_F0_GPIO28 = 112}
     */
    @EnumMember(
        value = 112L,
        name = "IMX_F0_GPIO28"
    )
    IMX_F0_GPIO28,

    /**
     * {@code IMX_F1_GPIO28 = 113}
     */
    @EnumMember(
        value = 113L,
        name = "IMX_F1_GPIO28"
    )
    IMX_F1_GPIO28,

    /**
     * {@code IMX_F2_GPIO28 = 114}
     */
    @EnumMember(
        value = 114L,
        name = "IMX_F2_GPIO28"
    )
    IMX_F2_GPIO28,

    /**
     * {@code IMX_F3_GPIO28 = 115}
     */
    @EnumMember(
        value = 115L,
        name = "IMX_F3_GPIO28"
    )
    IMX_F3_GPIO28,

    /**
     * {@code IMX_F0_GPIO29 = 116}
     */
    @EnumMember(
        value = 116L,
        name = "IMX_F0_GPIO29"
    )
    IMX_F0_GPIO29,

    /**
     * {@code IMX_F1_GPIO29 = 117}
     */
    @EnumMember(
        value = 117L,
        name = "IMX_F1_GPIO29"
    )
    IMX_F1_GPIO29,

    /**
     * {@code IMX_F2_GPIO29 = 118}
     */
    @EnumMember(
        value = 118L,
        name = "IMX_F2_GPIO29"
    )
    IMX_F2_GPIO29,

    /**
     * {@code IMX_F3_GPIO29 = 119}
     */
    @EnumMember(
        value = 119L,
        name = "IMX_F3_GPIO29"
    )
    IMX_F3_GPIO29,

    /**
     * {@code IMX_F0_GPIO30 = 120}
     */
    @EnumMember(
        value = 120L,
        name = "IMX_F0_GPIO30"
    )
    IMX_F0_GPIO30,

    /**
     * {@code IMX_F1_GPIO30 = 121}
     */
    @EnumMember(
        value = 121L,
        name = "IMX_F1_GPIO30"
    )
    IMX_F1_GPIO30,

    /**
     * {@code IMX_F2_GPIO30 = 122}
     */
    @EnumMember(
        value = 122L,
        name = "IMX_F2_GPIO30"
    )
    IMX_F2_GPIO30,

    /**
     * {@code IMX_F3_GPIO30 = 123}
     */
    @EnumMember(
        value = 123L,
        name = "IMX_F3_GPIO30"
    )
    IMX_F3_GPIO30,

    /**
     * {@code IMX_F0_GPIO31 = 124}
     */
    @EnumMember(
        value = 124L,
        name = "IMX_F0_GPIO31"
    )
    IMX_F0_GPIO31,

    /**
     * {@code IMX_F1_GPIO31 = 125}
     */
    @EnumMember(
        value = 125L,
        name = "IMX_F1_GPIO31"
    )
    IMX_F1_GPIO31,

    /**
     * {@code IMX_F2_GPIO31 = 126}
     */
    @EnumMember(
        value = 126L,
        name = "IMX_F2_GPIO31"
    )
    IMX_F2_GPIO31,

    /**
     * {@code IMX_F3_GPIO31 = 127}
     */
    @EnumMember(
        value = 127L,
        name = "IMX_F3_GPIO31"
    )
    IMX_F3_GPIO31,

    /**
     * {@code IMX_F0_GPIO32 = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IMX_F0_GPIO32"
    )
    IMX_F0_GPIO32,

    /**
     * {@code IMX_F1_GPIO32 = 129}
     */
    @EnumMember(
        value = 129L,
        name = "IMX_F1_GPIO32"
    )
    IMX_F1_GPIO32,

    /**
     * {@code IMX_F2_GPIO32 = 130}
     */
    @EnumMember(
        value = 130L,
        name = "IMX_F2_GPIO32"
    )
    IMX_F2_GPIO32,

    /**
     * {@code IMX_F3_GPIO32 = 131}
     */
    @EnumMember(
        value = 131L,
        name = "IMX_F3_GPIO32"
    )
    IMX_F3_GPIO32,

    /**
     * {@code IMX_F0_GPIO33 = 132}
     */
    @EnumMember(
        value = 132L,
        name = "IMX_F0_GPIO33"
    )
    IMX_F0_GPIO33,

    /**
     * {@code IMX_F1_GPIO33 = 133}
     */
    @EnumMember(
        value = 133L,
        name = "IMX_F1_GPIO33"
    )
    IMX_F1_GPIO33,

    /**
     * {@code IMX_F2_GPIO33 = 134}
     */
    @EnumMember(
        value = 134L,
        name = "IMX_F2_GPIO33"
    )
    IMX_F2_GPIO33,

    /**
     * {@code IMX_F3_GPIO33 = 135}
     */
    @EnumMember(
        value = 135L,
        name = "IMX_F3_GPIO33"
    )
    IMX_F3_GPIO33,

    /**
     * {@code IMX_F0_GPIO34 = 136}
     */
    @EnumMember(
        value = 136L,
        name = "IMX_F0_GPIO34"
    )
    IMX_F0_GPIO34,

    /**
     * {@code IMX_F1_GPIO34 = 137}
     */
    @EnumMember(
        value = 137L,
        name = "IMX_F1_GPIO34"
    )
    IMX_F1_GPIO34,

    /**
     * {@code IMX_F2_GPIO34 = 138}
     */
    @EnumMember(
        value = 138L,
        name = "IMX_F2_GPIO34"
    )
    IMX_F2_GPIO34,

    /**
     * {@code IMX_F3_GPIO34 = 139}
     */
    @EnumMember(
        value = 139L,
        name = "IMX_F3_GPIO34"
    )
    IMX_F3_GPIO34,

    /**
     * {@code IMX_F0_GPIO35 = 140}
     */
    @EnumMember(
        value = 140L,
        name = "IMX_F0_GPIO35"
    )
    IMX_F0_GPIO35,

    /**
     * {@code IMX_F1_GPIO35 = 141}
     */
    @EnumMember(
        value = 141L,
        name = "IMX_F1_GPIO35"
    )
    IMX_F1_GPIO35,

    /**
     * {@code IMX_F2_GPIO35 = 142}
     */
    @EnumMember(
        value = 142L,
        name = "IMX_F2_GPIO35"
    )
    IMX_F2_GPIO35,

    /**
     * {@code IMX_F3_GPIO35 = 143}
     */
    @EnumMember(
        value = 143L,
        name = "IMX_F3_GPIO35"
    )
    IMX_F3_GPIO35,

    /**
     * {@code IMX_F0_GPIO36 = 144}
     */
    @EnumMember(
        value = 144L,
        name = "IMX_F0_GPIO36"
    )
    IMX_F0_GPIO36,

    /**
     * {@code IMX_F1_GPIO36 = 145}
     */
    @EnumMember(
        value = 145L,
        name = "IMX_F1_GPIO36"
    )
    IMX_F1_GPIO36,

    /**
     * {@code IMX_F2_GPIO36 = 146}
     */
    @EnumMember(
        value = 146L,
        name = "IMX_F2_GPIO36"
    )
    IMX_F2_GPIO36,

    /**
     * {@code IMX_F3_GPIO36 = 147}
     */
    @EnumMember(
        value = 147L,
        name = "IMX_F3_GPIO36"
    )
    IMX_F3_GPIO36,

    /**
     * {@code IMX_F0_GPIO37 = 148}
     */
    @EnumMember(
        value = 148L,
        name = "IMX_F0_GPIO37"
    )
    IMX_F0_GPIO37,

    /**
     * {@code IMX_F1_GPIO37 = 149}
     */
    @EnumMember(
        value = 149L,
        name = "IMX_F1_GPIO37"
    )
    IMX_F1_GPIO37,

    /**
     * {@code IMX_F2_GPIO37 = 150}
     */
    @EnumMember(
        value = 150L,
        name = "IMX_F2_GPIO37"
    )
    IMX_F2_GPIO37,

    /**
     * {@code IMX_F3_GPIO37 = 151}
     */
    @EnumMember(
        value = 151L,
        name = "IMX_F3_GPIO37"
    )
    IMX_F3_GPIO37,

    /**
     * {@code IMX_F0_GPIO38 = 152}
     */
    @EnumMember(
        value = 152L,
        name = "IMX_F0_GPIO38"
    )
    IMX_F0_GPIO38,

    /**
     * {@code IMX_F1_GPIO38 = 153}
     */
    @EnumMember(
        value = 153L,
        name = "IMX_F1_GPIO38"
    )
    IMX_F1_GPIO38,

    /**
     * {@code IMX_F2_GPIO38 = 154}
     */
    @EnumMember(
        value = 154L,
        name = "IMX_F2_GPIO38"
    )
    IMX_F2_GPIO38,

    /**
     * {@code IMX_F3_GPIO38 = 155}
     */
    @EnumMember(
        value = 155L,
        name = "IMX_F3_GPIO38"
    )
    IMX_F3_GPIO38,

    /**
     * {@code IMX_F0_GPIO39 = 156}
     */
    @EnumMember(
        value = 156L,
        name = "IMX_F0_GPIO39"
    )
    IMX_F0_GPIO39,

    /**
     * {@code IMX_F1_GPIO39 = 157}
     */
    @EnumMember(
        value = 157L,
        name = "IMX_F1_GPIO39"
    )
    IMX_F1_GPIO39,

    /**
     * {@code IMX_F2_GPIO39 = 158}
     */
    @EnumMember(
        value = 158L,
        name = "IMX_F2_GPIO39"
    )
    IMX_F2_GPIO39,

    /**
     * {@code IMX_F3_GPIO39 = 159}
     */
    @EnumMember(
        value = 159L,
        name = "IMX_F3_GPIO39"
    )
    IMX_F3_GPIO39,

    /**
     * {@code IMX_F0_GPIO40 = 160}
     */
    @EnumMember(
        value = 160L,
        name = "IMX_F0_GPIO40"
    )
    IMX_F0_GPIO40,

    /**
     * {@code IMX_F1_GPIO40 = 161}
     */
    @EnumMember(
        value = 161L,
        name = "IMX_F1_GPIO40"
    )
    IMX_F1_GPIO40,

    /**
     * {@code IMX_F2_GPIO40 = 162}
     */
    @EnumMember(
        value = 162L,
        name = "IMX_F2_GPIO40"
    )
    IMX_F2_GPIO40,

    /**
     * {@code IMX_F3_GPIO40 = 163}
     */
    @EnumMember(
        value = 163L,
        name = "IMX_F3_GPIO40"
    )
    IMX_F3_GPIO40,

    /**
     * {@code IMX_F0_GPIO41 = 164}
     */
    @EnumMember(
        value = 164L,
        name = "IMX_F0_GPIO41"
    )
    IMX_F0_GPIO41,

    /**
     * {@code IMX_F1_GPIO41 = 165}
     */
    @EnumMember(
        value = 165L,
        name = "IMX_F1_GPIO41"
    )
    IMX_F1_GPIO41,

    /**
     * {@code IMX_F2_GPIO41 = 166}
     */
    @EnumMember(
        value = 166L,
        name = "IMX_F2_GPIO41"
    )
    IMX_F2_GPIO41,

    /**
     * {@code IMX_F3_GPIO41 = 167}
     */
    @EnumMember(
        value = 167L,
        name = "IMX_F3_GPIO41"
    )
    IMX_F3_GPIO41,

    /**
     * {@code IMX_F0_GPIO42 = 168}
     */
    @EnumMember(
        value = 168L,
        name = "IMX_F0_GPIO42"
    )
    IMX_F0_GPIO42,

    /**
     * {@code IMX_F1_GPIO42 = 169}
     */
    @EnumMember(
        value = 169L,
        name = "IMX_F1_GPIO42"
    )
    IMX_F1_GPIO42,

    /**
     * {@code IMX_F2_GPIO42 = 170}
     */
    @EnumMember(
        value = 170L,
        name = "IMX_F2_GPIO42"
    )
    IMX_F2_GPIO42,

    /**
     * {@code IMX_F3_GPIO42 = 171}
     */
    @EnumMember(
        value = 171L,
        name = "IMX_F3_GPIO42"
    )
    IMX_F3_GPIO42,

    /**
     * {@code IMX_F0_GPIO43 = 172}
     */
    @EnumMember(
        value = 172L,
        name = "IMX_F0_GPIO43"
    )
    IMX_F0_GPIO43,

    /**
     * {@code IMX_F1_GPIO43 = 173}
     */
    @EnumMember(
        value = 173L,
        name = "IMX_F1_GPIO43"
    )
    IMX_F1_GPIO43,

    /**
     * {@code IMX_F2_GPIO43 = 174}
     */
    @EnumMember(
        value = 174L,
        name = "IMX_F2_GPIO43"
    )
    IMX_F2_GPIO43,

    /**
     * {@code IMX_F3_GPIO43 = 175}
     */
    @EnumMember(
        value = 175L,
        name = "IMX_F3_GPIO43"
    )
    IMX_F3_GPIO43,

    /**
     * {@code IMX_F0_GPIO44 = 176}
     */
    @EnumMember(
        value = 176L,
        name = "IMX_F0_GPIO44"
    )
    IMX_F0_GPIO44,

    /**
     * {@code IMX_F1_GPIO44 = 177}
     */
    @EnumMember(
        value = 177L,
        name = "IMX_F1_GPIO44"
    )
    IMX_F1_GPIO44,

    /**
     * {@code IMX_F2_GPIO44 = 178}
     */
    @EnumMember(
        value = 178L,
        name = "IMX_F2_GPIO44"
    )
    IMX_F2_GPIO44,

    /**
     * {@code IMX_F3_GPIO44 = 179}
     */
    @EnumMember(
        value = 179L,
        name = "IMX_F3_GPIO44"
    )
    IMX_F3_GPIO44,

    /**
     * {@code IMX_F0_GPIO45 = 180}
     */
    @EnumMember(
        value = 180L,
        name = "IMX_F0_GPIO45"
    )
    IMX_F0_GPIO45,

    /**
     * {@code IMX_F1_GPIO45 = 181}
     */
    @EnumMember(
        value = 181L,
        name = "IMX_F1_GPIO45"
    )
    IMX_F1_GPIO45,

    /**
     * {@code IMX_F2_GPIO45 = 182}
     */
    @EnumMember(
        value = 182L,
        name = "IMX_F2_GPIO45"
    )
    IMX_F2_GPIO45,

    /**
     * {@code IMX_F3_GPIO45 = 183}
     */
    @EnumMember(
        value = 183L,
        name = "IMX_F3_GPIO45"
    )
    IMX_F3_GPIO45,

    /**
     * {@code IMX_F0_GPIO46 = 184}
     */
    @EnumMember(
        value = 184L,
        name = "IMX_F0_GPIO46"
    )
    IMX_F0_GPIO46,

    /**
     * {@code IMX_F1_GPIO46 = 185}
     */
    @EnumMember(
        value = 185L,
        name = "IMX_F1_GPIO46"
    )
    IMX_F1_GPIO46,

    /**
     * {@code IMX_F2_GPIO46 = 186}
     */
    @EnumMember(
        value = 186L,
        name = "IMX_F2_GPIO46"
    )
    IMX_F2_GPIO46,

    /**
     * {@code IMX_F3_GPIO46 = 187}
     */
    @EnumMember(
        value = 187L,
        name = "IMX_F3_GPIO46"
    )
    IMX_F3_GPIO46,

    /**
     * {@code IMX_F0_GPIO47 = 188}
     */
    @EnumMember(
        value = 188L,
        name = "IMX_F0_GPIO47"
    )
    IMX_F0_GPIO47,

    /**
     * {@code IMX_F1_GPIO47 = 189}
     */
    @EnumMember(
        value = 189L,
        name = "IMX_F1_GPIO47"
    )
    IMX_F1_GPIO47,

    /**
     * {@code IMX_F2_GPIO47 = 190}
     */
    @EnumMember(
        value = 190L,
        name = "IMX_F2_GPIO47"
    )
    IMX_F2_GPIO47,

    /**
     * {@code IMX_F3_GPIO47 = 191}
     */
    @EnumMember(
        value = 191L,
        name = "IMX_F3_GPIO47"
    )
    IMX_F3_GPIO47,

    /**
     * {@code IMX_F0_GPIO48 = 192}
     */
    @EnumMember(
        value = 192L,
        name = "IMX_F0_GPIO48"
    )
    IMX_F0_GPIO48,

    /**
     * {@code IMX_F1_GPIO48 = 193}
     */
    @EnumMember(
        value = 193L,
        name = "IMX_F1_GPIO48"
    )
    IMX_F1_GPIO48,

    /**
     * {@code IMX_F2_GPIO48 = 194}
     */
    @EnumMember(
        value = 194L,
        name = "IMX_F2_GPIO48"
    )
    IMX_F2_GPIO48,

    /**
     * {@code IMX_F3_GPIO48 = 195}
     */
    @EnumMember(
        value = 195L,
        name = "IMX_F3_GPIO48"
    )
    IMX_F3_GPIO48,

    /**
     * {@code IMX_F0_GPIO49 = 196}
     */
    @EnumMember(
        value = 196L,
        name = "IMX_F0_GPIO49"
    )
    IMX_F0_GPIO49,

    /**
     * {@code IMX_F1_GPIO49 = 197}
     */
    @EnumMember(
        value = 197L,
        name = "IMX_F1_GPIO49"
    )
    IMX_F1_GPIO49,

    /**
     * {@code IMX_F2_GPIO49 = 198}
     */
    @EnumMember(
        value = 198L,
        name = "IMX_F2_GPIO49"
    )
    IMX_F2_GPIO49,

    /**
     * {@code IMX_F3_GPIO49 = 199}
     */
    @EnumMember(
        value = 199L,
        name = "IMX_F3_GPIO49"
    )
    IMX_F3_GPIO49,

    /**
     * {@code IMX_F0_GPIO50 = 200}
     */
    @EnumMember(
        value = 200L,
        name = "IMX_F0_GPIO50"
    )
    IMX_F0_GPIO50,

    /**
     * {@code IMX_F1_GPIO50 = 201}
     */
    @EnumMember(
        value = 201L,
        name = "IMX_F1_GPIO50"
    )
    IMX_F1_GPIO50,

    /**
     * {@code IMX_F2_GPIO50 = 202}
     */
    @EnumMember(
        value = 202L,
        name = "IMX_F2_GPIO50"
    )
    IMX_F2_GPIO50,

    /**
     * {@code IMX_F3_GPIO50 = 203}
     */
    @EnumMember(
        value = 203L,
        name = "IMX_F3_GPIO50"
    )
    IMX_F3_GPIO50,

    /**
     * {@code IMX_F0_GPIO51 = 204}
     */
    @EnumMember(
        value = 204L,
        name = "IMX_F0_GPIO51"
    )
    IMX_F0_GPIO51,

    /**
     * {@code IMX_F1_GPIO51 = 205}
     */
    @EnumMember(
        value = 205L,
        name = "IMX_F1_GPIO51"
    )
    IMX_F1_GPIO51,

    /**
     * {@code IMX_F2_GPIO51 = 206}
     */
    @EnumMember(
        value = 206L,
        name = "IMX_F2_GPIO51"
    )
    IMX_F2_GPIO51,

    /**
     * {@code IMX_F3_GPIO51 = 207}
     */
    @EnumMember(
        value = 207L,
        name = "IMX_F3_GPIO51"
    )
    IMX_F3_GPIO51,

    /**
     * {@code IMX_F0_GPIO52 = 208}
     */
    @EnumMember(
        value = 208L,
        name = "IMX_F0_GPIO52"
    )
    IMX_F0_GPIO52,

    /**
     * {@code IMX_F1_GPIO52 = 209}
     */
    @EnumMember(
        value = 209L,
        name = "IMX_F1_GPIO52"
    )
    IMX_F1_GPIO52,

    /**
     * {@code IMX_F2_GPIO52 = 210}
     */
    @EnumMember(
        value = 210L,
        name = "IMX_F2_GPIO52"
    )
    IMX_F2_GPIO52,

    /**
     * {@code IMX_F3_GPIO52 = 211}
     */
    @EnumMember(
        value = 211L,
        name = "IMX_F3_GPIO52"
    )
    IMX_F3_GPIO52,

    /**
     * {@code IMX_F0_GPIO53 = 212}
     */
    @EnumMember(
        value = 212L,
        name = "IMX_F0_GPIO53"
    )
    IMX_F0_GPIO53,

    /**
     * {@code IMX_F1_GPIO53 = 213}
     */
    @EnumMember(
        value = 213L,
        name = "IMX_F1_GPIO53"
    )
    IMX_F1_GPIO53,

    /**
     * {@code IMX_F2_GPIO53 = 214}
     */
    @EnumMember(
        value = 214L,
        name = "IMX_F2_GPIO53"
    )
    IMX_F2_GPIO53,

    /**
     * {@code IMX_F3_GPIO53 = 215}
     */
    @EnumMember(
        value = 215L,
        name = "IMX_F3_GPIO53"
    )
    IMX_F3_GPIO53,

    /**
     * {@code IMX_F0_GPIO54 = 216}
     */
    @EnumMember(
        value = 216L,
        name = "IMX_F0_GPIO54"
    )
    IMX_F0_GPIO54,

    /**
     * {@code IMX_F1_GPIO54 = 217}
     */
    @EnumMember(
        value = 217L,
        name = "IMX_F1_GPIO54"
    )
    IMX_F1_GPIO54,

    /**
     * {@code IMX_F2_GPIO54 = 218}
     */
    @EnumMember(
        value = 218L,
        name = "IMX_F2_GPIO54"
    )
    IMX_F2_GPIO54,

    /**
     * {@code IMX_F3_GPIO54 = 219}
     */
    @EnumMember(
        value = 219L,
        name = "IMX_F3_GPIO54"
    )
    IMX_F3_GPIO54,

    /**
     * {@code IMX_F0_GPIO55 = 220}
     */
    @EnumMember(
        value = 220L,
        name = "IMX_F0_GPIO55"
    )
    IMX_F0_GPIO55,

    /**
     * {@code IMX_F1_GPIO55 = 221}
     */
    @EnumMember(
        value = 221L,
        name = "IMX_F1_GPIO55"
    )
    IMX_F1_GPIO55,

    /**
     * {@code IMX_F2_GPIO55 = 222}
     */
    @EnumMember(
        value = 222L,
        name = "IMX_F2_GPIO55"
    )
    IMX_F2_GPIO55,

    /**
     * {@code IMX_F3_GPIO55 = 223}
     */
    @EnumMember(
        value = 223L,
        name = "IMX_F3_GPIO55"
    )
    IMX_F3_GPIO55,

    /**
     * {@code IMX_F0_GPIO56 = 224}
     */
    @EnumMember(
        value = 224L,
        name = "IMX_F0_GPIO56"
    )
    IMX_F0_GPIO56,

    /**
     * {@code IMX_F1_GPIO56 = 225}
     */
    @EnumMember(
        value = 225L,
        name = "IMX_F1_GPIO56"
    )
    IMX_F1_GPIO56,

    /**
     * {@code IMX_F2_GPIO56 = 226}
     */
    @EnumMember(
        value = 226L,
        name = "IMX_F2_GPIO56"
    )
    IMX_F2_GPIO56,

    /**
     * {@code IMX_F3_GPIO56 = 227}
     */
    @EnumMember(
        value = 227L,
        name = "IMX_F3_GPIO56"
    )
    IMX_F3_GPIO56,

    /**
     * {@code IMX_F0_GPIO57 = 228}
     */
    @EnumMember(
        value = 228L,
        name = "IMX_F0_GPIO57"
    )
    IMX_F0_GPIO57,

    /**
     * {@code IMX_F1_GPIO57 = 229}
     */
    @EnumMember(
        value = 229L,
        name = "IMX_F1_GPIO57"
    )
    IMX_F1_GPIO57,

    /**
     * {@code IMX_F2_GPIO57 = 230}
     */
    @EnumMember(
        value = 230L,
        name = "IMX_F2_GPIO57"
    )
    IMX_F2_GPIO57,

    /**
     * {@code IMX_F3_GPIO57 = 231}
     */
    @EnumMember(
        value = 231L,
        name = "IMX_F3_GPIO57"
    )
    IMX_F3_GPIO57,

    /**
     * {@code IMX_F0_GPIO58 = 232}
     */
    @EnumMember(
        value = 232L,
        name = "IMX_F0_GPIO58"
    )
    IMX_F0_GPIO58,

    /**
     * {@code IMX_F1_GPIO58 = 233}
     */
    @EnumMember(
        value = 233L,
        name = "IMX_F1_GPIO58"
    )
    IMX_F1_GPIO58,

    /**
     * {@code IMX_F2_GPIO58 = 234}
     */
    @EnumMember(
        value = 234L,
        name = "IMX_F2_GPIO58"
    )
    IMX_F2_GPIO58,

    /**
     * {@code IMX_F3_GPIO58 = 235}
     */
    @EnumMember(
        value = 235L,
        name = "IMX_F3_GPIO58"
    )
    IMX_F3_GPIO58,

    /**
     * {@code IMX_F0_GPIO59 = 236}
     */
    @EnumMember(
        value = 236L,
        name = "IMX_F0_GPIO59"
    )
    IMX_F0_GPIO59,

    /**
     * {@code IMX_F1_GPIO59 = 237}
     */
    @EnumMember(
        value = 237L,
        name = "IMX_F1_GPIO59"
    )
    IMX_F1_GPIO59,

    /**
     * {@code IMX_F2_GPIO59 = 238}
     */
    @EnumMember(
        value = 238L,
        name = "IMX_F2_GPIO59"
    )
    IMX_F2_GPIO59,

    /**
     * {@code IMX_F3_GPIO59 = 239}
     */
    @EnumMember(
        value = 239L,
        name = "IMX_F3_GPIO59"
    )
    IMX_F3_GPIO59,

    /**
     * {@code IMX_F0_GPIO60 = 240}
     */
    @EnumMember(
        value = 240L,
        name = "IMX_F0_GPIO60"
    )
    IMX_F0_GPIO60,

    /**
     * {@code IMX_F1_GPIO60 = 241}
     */
    @EnumMember(
        value = 241L,
        name = "IMX_F1_GPIO60"
    )
    IMX_F1_GPIO60,

    /**
     * {@code IMX_F2_GPIO60 = 242}
     */
    @EnumMember(
        value = 242L,
        name = "IMX_F2_GPIO60"
    )
    IMX_F2_GPIO60,

    /**
     * {@code IMX_F3_GPIO60 = 243}
     */
    @EnumMember(
        value = 243L,
        name = "IMX_F3_GPIO60"
    )
    IMX_F3_GPIO60,

    /**
     * {@code IMX_F0_GPIO61 = 244}
     */
    @EnumMember(
        value = 244L,
        name = "IMX_F0_GPIO61"
    )
    IMX_F0_GPIO61,

    /**
     * {@code IMX_F1_GPIO61 = 245}
     */
    @EnumMember(
        value = 245L,
        name = "IMX_F1_GPIO61"
    )
    IMX_F1_GPIO61,

    /**
     * {@code IMX_F2_GPIO61 = 246}
     */
    @EnumMember(
        value = 246L,
        name = "IMX_F2_GPIO61"
    )
    IMX_F2_GPIO61,

    /**
     * {@code IMX_F3_GPIO61 = 247}
     */
    @EnumMember(
        value = 247L,
        name = "IMX_F3_GPIO61"
    )
    IMX_F3_GPIO61,

    /**
     * {@code IMX_F0_GPIO62 = 248}
     */
    @EnumMember(
        value = 248L,
        name = "IMX_F0_GPIO62"
    )
    IMX_F0_GPIO62,

    /**
     * {@code IMX_F1_GPIO62 = 249}
     */
    @EnumMember(
        value = 249L,
        name = "IMX_F1_GPIO62"
    )
    IMX_F1_GPIO62,

    /**
     * {@code IMX_F2_GPIO62 = 250}
     */
    @EnumMember(
        value = 250L,
        name = "IMX_F2_GPIO62"
    )
    IMX_F2_GPIO62,

    /**
     * {@code IMX_F3_GPIO62 = 251}
     */
    @EnumMember(
        value = 251L,
        name = "IMX_F3_GPIO62"
    )
    IMX_F3_GPIO62,

    /**
     * {@code IMX_F0_GPIO64 = 252}
     */
    @EnumMember(
        value = 252L,
        name = "IMX_F0_GPIO64"
    )
    IMX_F0_GPIO64,

    /**
     * {@code IMX_F1_GPIO64 = 253}
     */
    @EnumMember(
        value = 253L,
        name = "IMX_F1_GPIO64"
    )
    IMX_F1_GPIO64,

    /**
     * {@code IMX_F2_GPIO64 = 254}
     */
    @EnumMember(
        value = 254L,
        name = "IMX_F2_GPIO64"
    )
    IMX_F2_GPIO64,

    /**
     * {@code IMX_F3_GPIO64 = 255}
     */
    @EnumMember(
        value = 255L,
        name = "IMX_F3_GPIO64"
    )
    IMX_F3_GPIO64,

    /**
     * {@code IMX_F0_GPIO65 = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IMX_F0_GPIO65"
    )
    IMX_F0_GPIO65,

    /**
     * {@code IMX_F1_GPIO65 = 257}
     */
    @EnumMember(
        value = 257L,
        name = "IMX_F1_GPIO65"
    )
    IMX_F1_GPIO65,

    /**
     * {@code IMX_F2_GPIO65 = 258}
     */
    @EnumMember(
        value = 258L,
        name = "IMX_F2_GPIO65"
    )
    IMX_F2_GPIO65,

    /**
     * {@code IMX_F3_GPIO65 = 259}
     */
    @EnumMember(
        value = 259L,
        name = "IMX_F3_GPIO65"
    )
    IMX_F3_GPIO65,

    /**
     * {@code IMX_F0_GPIO66 = 260}
     */
    @EnumMember(
        value = 260L,
        name = "IMX_F0_GPIO66"
    )
    IMX_F0_GPIO66,

    /**
     * {@code IMX_F1_GPIO66 = 261}
     */
    @EnumMember(
        value = 261L,
        name = "IMX_F1_GPIO66"
    )
    IMX_F1_GPIO66,

    /**
     * {@code IMX_F2_GPIO66 = 262}
     */
    @EnumMember(
        value = 262L,
        name = "IMX_F2_GPIO66"
    )
    IMX_F2_GPIO66,

    /**
     * {@code IMX_F3_GPIO66 = 263}
     */
    @EnumMember(
        value = 263L,
        name = "IMX_F3_GPIO66"
    )
    IMX_F3_GPIO66,

    /**
     * {@code IMX_F0_GPIO67 = 264}
     */
    @EnumMember(
        value = 264L,
        name = "IMX_F0_GPIO67"
    )
    IMX_F0_GPIO67,

    /**
     * {@code IMX_F1_GPIO67 = 265}
     */
    @EnumMember(
        value = 265L,
        name = "IMX_F1_GPIO67"
    )
    IMX_F1_GPIO67,

    /**
     * {@code IMX_F2_GPIO67 = 266}
     */
    @EnumMember(
        value = 266L,
        name = "IMX_F2_GPIO67"
    )
    IMX_F2_GPIO67,

    /**
     * {@code IMX_F3_GPIO67 = 267}
     */
    @EnumMember(
        value = 267L,
        name = "IMX_F3_GPIO67"
    )
    IMX_F3_GPIO67,

    /**
     * {@code IMX_F0_GPIO68 = 268}
     */
    @EnumMember(
        value = 268L,
        name = "IMX_F0_GPIO68"
    )
    IMX_F0_GPIO68,

    /**
     * {@code IMX_F1_GPIO68 = 269}
     */
    @EnumMember(
        value = 269L,
        name = "IMX_F1_GPIO68"
    )
    IMX_F1_GPIO68,

    /**
     * {@code IMX_F2_GPIO68 = 270}
     */
    @EnumMember(
        value = 270L,
        name = "IMX_F2_GPIO68"
    )
    IMX_F2_GPIO68,

    /**
     * {@code IMX_F3_GPIO68 = 271}
     */
    @EnumMember(
        value = 271L,
        name = "IMX_F3_GPIO68"
    )
    IMX_F3_GPIO68,

    /**
     * {@code IMX_F0_GPIO69 = 272}
     */
    @EnumMember(
        value = 272L,
        name = "IMX_F0_GPIO69"
    )
    IMX_F0_GPIO69,

    /**
     * {@code IMX_F1_GPIO69 = 273}
     */
    @EnumMember(
        value = 273L,
        name = "IMX_F1_GPIO69"
    )
    IMX_F1_GPIO69,

    /**
     * {@code IMX_F2_GPIO69 = 274}
     */
    @EnumMember(
        value = 274L,
        name = "IMX_F2_GPIO69"
    )
    IMX_F2_GPIO69,

    /**
     * {@code IMX_F3_GPIO69 = 275}
     */
    @EnumMember(
        value = 275L,
        name = "IMX_F3_GPIO69"
    )
    IMX_F3_GPIO69,

    /**
     * {@code IMX_F0_GPIO70 = 276}
     */
    @EnumMember(
        value = 276L,
        name = "IMX_F0_GPIO70"
    )
    IMX_F0_GPIO70,

    /**
     * {@code IMX_F1_GPIO70 = 277}
     */
    @EnumMember(
        value = 277L,
        name = "IMX_F1_GPIO70"
    )
    IMX_F1_GPIO70,

    /**
     * {@code IMX_F2_GPIO70 = 278}
     */
    @EnumMember(
        value = 278L,
        name = "IMX_F2_GPIO70"
    )
    IMX_F2_GPIO70,

    /**
     * {@code IMX_F3_GPIO70 = 279}
     */
    @EnumMember(
        value = 279L,
        name = "IMX_F3_GPIO70"
    )
    IMX_F3_GPIO70,

    /**
     * {@code IMX_F0_GPIO71 = 280}
     */
    @EnumMember(
        value = 280L,
        name = "IMX_F0_GPIO71"
    )
    IMX_F0_GPIO71,

    /**
     * {@code IMX_F1_GPIO71 = 281}
     */
    @EnumMember(
        value = 281L,
        name = "IMX_F1_GPIO71"
    )
    IMX_F1_GPIO71,

    /**
     * {@code IMX_F2_GPIO71 = 282}
     */
    @EnumMember(
        value = 282L,
        name = "IMX_F2_GPIO71"
    )
    IMX_F2_GPIO71,

    /**
     * {@code IMX_F3_GPIO71 = 283}
     */
    @EnumMember(
        value = 283L,
        name = "IMX_F3_GPIO71"
    )
    IMX_F3_GPIO71,

    /**
     * {@code IMX_F0_GPIO72 = 284}
     */
    @EnumMember(
        value = 284L,
        name = "IMX_F0_GPIO72"
    )
    IMX_F0_GPIO72,

    /**
     * {@code IMX_F1_GPIO72 = 285}
     */
    @EnumMember(
        value = 285L,
        name = "IMX_F1_GPIO72"
    )
    IMX_F1_GPIO72,

    /**
     * {@code IMX_F2_GPIO72 = 286}
     */
    @EnumMember(
        value = 286L,
        name = "IMX_F2_GPIO72"
    )
    IMX_F2_GPIO72,

    /**
     * {@code IMX_F3_GPIO72 = 287}
     */
    @EnumMember(
        value = 287L,
        name = "IMX_F3_GPIO72"
    )
    IMX_F3_GPIO72,

    /**
     * {@code IMX_F0_GPIO73 = 288}
     */
    @EnumMember(
        value = 288L,
        name = "IMX_F0_GPIO73"
    )
    IMX_F0_GPIO73,

    /**
     * {@code IMX_F1_GPIO73 = 289}
     */
    @EnumMember(
        value = 289L,
        name = "IMX_F1_GPIO73"
    )
    IMX_F1_GPIO73,

    /**
     * {@code IMX_F2_GPIO73 = 290}
     */
    @EnumMember(
        value = 290L,
        name = "IMX_F2_GPIO73"
    )
    IMX_F2_GPIO73,

    /**
     * {@code IMX_F3_GPIO73 = 291}
     */
    @EnumMember(
        value = 291L,
        name = "IMX_F3_GPIO73"
    )
    IMX_F3_GPIO73,

    /**
     * {@code IMX_F0_GPIO74 = 292}
     */
    @EnumMember(
        value = 292L,
        name = "IMX_F0_GPIO74"
    )
    IMX_F0_GPIO74,

    /**
     * {@code IMX_F1_GPIO74 = 293}
     */
    @EnumMember(
        value = 293L,
        name = "IMX_F1_GPIO74"
    )
    IMX_F1_GPIO74,

    /**
     * {@code IMX_F2_GPIO74 = 294}
     */
    @EnumMember(
        value = 294L,
        name = "IMX_F2_GPIO74"
    )
    IMX_F2_GPIO74,

    /**
     * {@code IMX_F3_GPIO74 = 295}
     */
    @EnumMember(
        value = 295L,
        name = "IMX_F3_GPIO74"
    )
    IMX_F3_GPIO74,

    /**
     * {@code IMX_F0_GPIO75 = 296}
     */
    @EnumMember(
        value = 296L,
        name = "IMX_F0_GPIO75"
    )
    IMX_F0_GPIO75,

    /**
     * {@code IMX_F1_GPIO75 = 297}
     */
    @EnumMember(
        value = 297L,
        name = "IMX_F1_GPIO75"
    )
    IMX_F1_GPIO75,

    /**
     * {@code IMX_F2_GPIO75 = 298}
     */
    @EnumMember(
        value = 298L,
        name = "IMX_F2_GPIO75"
    )
    IMX_F2_GPIO75,

    /**
     * {@code IMX_F3_GPIO75 = 299}
     */
    @EnumMember(
        value = 299L,
        name = "IMX_F3_GPIO75"
    )
    IMX_F3_GPIO75,

    /**
     * {@code IMX_F0_GPIO76 = 300}
     */
    @EnumMember(
        value = 300L,
        name = "IMX_F0_GPIO76"
    )
    IMX_F0_GPIO76,

    /**
     * {@code IMX_F1_GPIO76 = 301}
     */
    @EnumMember(
        value = 301L,
        name = "IMX_F1_GPIO76"
    )
    IMX_F1_GPIO76,

    /**
     * {@code IMX_F2_GPIO76 = 302}
     */
    @EnumMember(
        value = 302L,
        name = "IMX_F2_GPIO76"
    )
    IMX_F2_GPIO76,

    /**
     * {@code IMX_F3_GPIO76 = 303}
     */
    @EnumMember(
        value = 303L,
        name = "IMX_F3_GPIO76"
    )
    IMX_F3_GPIO76,

    /**
     * {@code IMX_F0_GPIO77 = 304}
     */
    @EnumMember(
        value = 304L,
        name = "IMX_F0_GPIO77"
    )
    IMX_F0_GPIO77,

    /**
     * {@code IMX_F1_GPIO77 = 305}
     */
    @EnumMember(
        value = 305L,
        name = "IMX_F1_GPIO77"
    )
    IMX_F1_GPIO77,

    /**
     * {@code IMX_F2_GPIO77 = 306}
     */
    @EnumMember(
        value = 306L,
        name = "IMX_F2_GPIO77"
    )
    IMX_F2_GPIO77,

    /**
     * {@code IMX_F3_GPIO77 = 307}
     */
    @EnumMember(
        value = 307L,
        name = "IMX_F3_GPIO77"
    )
    IMX_F3_GPIO77,

    /**
     * {@code IMX_F0_GPIO78 = 308}
     */
    @EnumMember(
        value = 308L,
        name = "IMX_F0_GPIO78"
    )
    IMX_F0_GPIO78,

    /**
     * {@code IMX_F1_GPIO78 = 309}
     */
    @EnumMember(
        value = 309L,
        name = "IMX_F1_GPIO78"
    )
    IMX_F1_GPIO78,

    /**
     * {@code IMX_F2_GPIO78 = 310}
     */
    @EnumMember(
        value = 310L,
        name = "IMX_F2_GPIO78"
    )
    IMX_F2_GPIO78,

    /**
     * {@code IMX_F3_GPIO78 = 311}
     */
    @EnumMember(
        value = 311L,
        name = "IMX_F3_GPIO78"
    )
    IMX_F3_GPIO78,

    /**
     * {@code IMX_F0_GPIO79 = 312}
     */
    @EnumMember(
        value = 312L,
        name = "IMX_F0_GPIO79"
    )
    IMX_F0_GPIO79,

    /**
     * {@code IMX_F1_GPIO79 = 313}
     */
    @EnumMember(
        value = 313L,
        name = "IMX_F1_GPIO79"
    )
    IMX_F1_GPIO79,

    /**
     * {@code IMX_F2_GPIO79 = 314}
     */
    @EnumMember(
        value = 314L,
        name = "IMX_F2_GPIO79"
    )
    IMX_F2_GPIO79,

    /**
     * {@code IMX_F3_GPIO79 = 315}
     */
    @EnumMember(
        value = 315L,
        name = "IMX_F3_GPIO79"
    )
    IMX_F3_GPIO79,

    /**
     * {@code IMX_F0_GPIO80 = 316}
     */
    @EnumMember(
        value = 316L,
        name = "IMX_F0_GPIO80"
    )
    IMX_F0_GPIO80,

    /**
     * {@code IMX_F1_GPIO80 = 317}
     */
    @EnumMember(
        value = 317L,
        name = "IMX_F1_GPIO80"
    )
    IMX_F1_GPIO80,

    /**
     * {@code IMX_F2_GPIO80 = 318}
     */
    @EnumMember(
        value = 318L,
        name = "IMX_F2_GPIO80"
    )
    IMX_F2_GPIO80,

    /**
     * {@code IMX_F3_GPIO80 = 319}
     */
    @EnumMember(
        value = 319L,
        name = "IMX_F3_GPIO80"
    )
    IMX_F3_GPIO80,

    /**
     * {@code IMX_F0_GPIO81 = 320}
     */
    @EnumMember(
        value = 320L,
        name = "IMX_F0_GPIO81"
    )
    IMX_F0_GPIO81,

    /**
     * {@code IMX_F1_GPIO81 = 321}
     */
    @EnumMember(
        value = 321L,
        name = "IMX_F1_GPIO81"
    )
    IMX_F1_GPIO81,

    /**
     * {@code IMX_F2_GPIO81 = 322}
     */
    @EnumMember(
        value = 322L,
        name = "IMX_F2_GPIO81"
    )
    IMX_F2_GPIO81,

    /**
     * {@code IMX_F3_GPIO81 = 323}
     */
    @EnumMember(
        value = 323L,
        name = "IMX_F3_GPIO81"
    )
    IMX_F3_GPIO81,

    /**
     * {@code IMX_F0_GPIO82 = 324}
     */
    @EnumMember(
        value = 324L,
        name = "IMX_F0_GPIO82"
    )
    IMX_F0_GPIO82,

    /**
     * {@code IMX_F1_GPIO82 = 325}
     */
    @EnumMember(
        value = 325L,
        name = "IMX_F1_GPIO82"
    )
    IMX_F1_GPIO82,

    /**
     * {@code IMX_F2_GPIO82 = 326}
     */
    @EnumMember(
        value = 326L,
        name = "IMX_F2_GPIO82"
    )
    IMX_F2_GPIO82,

    /**
     * {@code IMX_F3_GPIO82 = 327}
     */
    @EnumMember(
        value = 327L,
        name = "IMX_F3_GPIO82"
    )
    IMX_F3_GPIO82,

    /**
     * {@code IMX_F0_GPIO83 = 328}
     */
    @EnumMember(
        value = 328L,
        name = "IMX_F0_GPIO83"
    )
    IMX_F0_GPIO83,

    /**
     * {@code IMX_F1_GPIO83 = 329}
     */
    @EnumMember(
        value = 329L,
        name = "IMX_F1_GPIO83"
    )
    IMX_F1_GPIO83,

    /**
     * {@code IMX_F2_GPIO83 = 330}
     */
    @EnumMember(
        value = 330L,
        name = "IMX_F2_GPIO83"
    )
    IMX_F2_GPIO83,

    /**
     * {@code IMX_F3_GPIO83 = 331}
     */
    @EnumMember(
        value = 331L,
        name = "IMX_F3_GPIO83"
    )
    IMX_F3_GPIO83,

    /**
     * {@code IMX_F0_GPIO84 = 332}
     */
    @EnumMember(
        value = 332L,
        name = "IMX_F0_GPIO84"
    )
    IMX_F0_GPIO84,

    /**
     * {@code IMX_F1_GPIO84 = 333}
     */
    @EnumMember(
        value = 333L,
        name = "IMX_F1_GPIO84"
    )
    IMX_F1_GPIO84,

    /**
     * {@code IMX_F2_GPIO84 = 334}
     */
    @EnumMember(
        value = 334L,
        name = "IMX_F2_GPIO84"
    )
    IMX_F2_GPIO84,

    /**
     * {@code IMX_F3_GPIO84 = 335}
     */
    @EnumMember(
        value = 335L,
        name = "IMX_F3_GPIO84"
    )
    IMX_F3_GPIO84,

    /**
     * {@code IMX_F0_GPIO85 = 336}
     */
    @EnumMember(
        value = 336L,
        name = "IMX_F0_GPIO85"
    )
    IMX_F0_GPIO85,

    /**
     * {@code IMX_F1_GPIO85 = 337}
     */
    @EnumMember(
        value = 337L,
        name = "IMX_F1_GPIO85"
    )
    IMX_F1_GPIO85,

    /**
     * {@code IMX_F2_GPIO85 = 338}
     */
    @EnumMember(
        value = 338L,
        name = "IMX_F2_GPIO85"
    )
    IMX_F2_GPIO85,

    /**
     * {@code IMX_F3_GPIO85 = 339}
     */
    @EnumMember(
        value = 339L,
        name = "IMX_F3_GPIO85"
    )
    IMX_F3_GPIO85,

    /**
     * {@code IMX_F0_GPIO86 = 340}
     */
    @EnumMember(
        value = 340L,
        name = "IMX_F0_GPIO86"
    )
    IMX_F0_GPIO86,

    /**
     * {@code IMX_F1_GPIO86 = 341}
     */
    @EnumMember(
        value = 341L,
        name = "IMX_F1_GPIO86"
    )
    IMX_F1_GPIO86,

    /**
     * {@code IMX_F2_GPIO86 = 342}
     */
    @EnumMember(
        value = 342L,
        name = "IMX_F2_GPIO86"
    )
    IMX_F2_GPIO86,

    /**
     * {@code IMX_F3_GPIO86 = 343}
     */
    @EnumMember(
        value = 343L,
        name = "IMX_F3_GPIO86"
    )
    IMX_F3_GPIO86,

    /**
     * {@code IMX_F0_GPIO87 = 344}
     */
    @EnumMember(
        value = 344L,
        name = "IMX_F0_GPIO87"
    )
    IMX_F0_GPIO87,

    /**
     * {@code IMX_F1_GPIO87 = 345}
     */
    @EnumMember(
        value = 345L,
        name = "IMX_F1_GPIO87"
    )
    IMX_F1_GPIO87,

    /**
     * {@code IMX_F2_GPIO87 = 346}
     */
    @EnumMember(
        value = 346L,
        name = "IMX_F2_GPIO87"
    )
    IMX_F2_GPIO87,

    /**
     * {@code IMX_F3_GPIO87 = 347}
     */
    @EnumMember(
        value = 347L,
        name = "IMX_F3_GPIO87"
    )
    IMX_F3_GPIO87,

    /**
     * {@code IMX_F0_GPIO88 = 348}
     */
    @EnumMember(
        value = 348L,
        name = "IMX_F0_GPIO88"
    )
    IMX_F0_GPIO88,

    /**
     * {@code IMX_F1_GPIO88 = 349}
     */
    @EnumMember(
        value = 349L,
        name = "IMX_F1_GPIO88"
    )
    IMX_F1_GPIO88,

    /**
     * {@code IMX_F2_GPIO88 = 350}
     */
    @EnumMember(
        value = 350L,
        name = "IMX_F2_GPIO88"
    )
    IMX_F2_GPIO88,

    /**
     * {@code IMX_F3_GPIO88 = 351}
     */
    @EnumMember(
        value = 351L,
        name = "IMX_F3_GPIO88"
    )
    IMX_F3_GPIO88,

    /**
     * {@code IMX_F0_GPIO89 = 352}
     */
    @EnumMember(
        value = 352L,
        name = "IMX_F0_GPIO89"
    )
    IMX_F0_GPIO89,

    /**
     * {@code IMX_F1_GPIO89 = 353}
     */
    @EnumMember(
        value = 353L,
        name = "IMX_F1_GPIO89"
    )
    IMX_F1_GPIO89,

    /**
     * {@code IMX_F2_GPIO89 = 354}
     */
    @EnumMember(
        value = 354L,
        name = "IMX_F2_GPIO89"
    )
    IMX_F2_GPIO89,

    /**
     * {@code IMX_F3_GPIO89 = 355}
     */
    @EnumMember(
        value = 355L,
        name = "IMX_F3_GPIO89"
    )
    IMX_F3_GPIO89,

    /**
     * {@code IMX_F0_GPIO90 = 356}
     */
    @EnumMember(
        value = 356L,
        name = "IMX_F0_GPIO90"
    )
    IMX_F0_GPIO90,

    /**
     * {@code IMX_F1_GPIO90 = 357}
     */
    @EnumMember(
        value = 357L,
        name = "IMX_F1_GPIO90"
    )
    IMX_F1_GPIO90,

    /**
     * {@code IMX_F2_GPIO90 = 358}
     */
    @EnumMember(
        value = 358L,
        name = "IMX_F2_GPIO90"
    )
    IMX_F2_GPIO90,

    /**
     * {@code IMX_F3_GPIO90 = 359}
     */
    @EnumMember(
        value = 359L,
        name = "IMX_F3_GPIO90"
    )
    IMX_F3_GPIO90,

    /**
     * {@code IMX_F0_GPIO91 = 360}
     */
    @EnumMember(
        value = 360L,
        name = "IMX_F0_GPIO91"
    )
    IMX_F0_GPIO91,

    /**
     * {@code IMX_F1_GPIO91 = 361}
     */
    @EnumMember(
        value = 361L,
        name = "IMX_F1_GPIO91"
    )
    IMX_F1_GPIO91,

    /**
     * {@code IMX_F2_GPIO91 = 362}
     */
    @EnumMember(
        value = 362L,
        name = "IMX_F2_GPIO91"
    )
    IMX_F2_GPIO91,

    /**
     * {@code IMX_F3_GPIO91 = 363}
     */
    @EnumMember(
        value = 363L,
        name = "IMX_F3_GPIO91"
    )
    IMX_F3_GPIO91,

    /**
     * {@code IMX_F0_GPIO92 = 364}
     */
    @EnumMember(
        value = 364L,
        name = "IMX_F0_GPIO92"
    )
    IMX_F0_GPIO92,

    /**
     * {@code IMX_F1_GPIO92 = 365}
     */
    @EnumMember(
        value = 365L,
        name = "IMX_F1_GPIO92"
    )
    IMX_F1_GPIO92,

    /**
     * {@code IMX_F2_GPIO92 = 366}
     */
    @EnumMember(
        value = 366L,
        name = "IMX_F2_GPIO92"
    )
    IMX_F2_GPIO92,

    /**
     * {@code IMX_F3_GPIO92 = 367}
     */
    @EnumMember(
        value = 367L,
        name = "IMX_F3_GPIO92"
    )
    IMX_F3_GPIO92,

    /**
     * {@code IMX_F0_GPIO93 = 368}
     */
    @EnumMember(
        value = 368L,
        name = "IMX_F0_GPIO93"
    )
    IMX_F0_GPIO93,

    /**
     * {@code IMX_F1_GPIO93 = 369}
     */
    @EnumMember(
        value = 369L,
        name = "IMX_F1_GPIO93"
    )
    IMX_F1_GPIO93,

    /**
     * {@code IMX_F2_GPIO93 = 370}
     */
    @EnumMember(
        value = 370L,
        name = "IMX_F2_GPIO93"
    )
    IMX_F2_GPIO93,

    /**
     * {@code IMX_F3_GPIO93 = 371}
     */
    @EnumMember(
        value = 371L,
        name = "IMX_F3_GPIO93"
    )
    IMX_F3_GPIO93,

    /**
     * {@code IMX_F0_GPIO94 = 372}
     */
    @EnumMember(
        value = 372L,
        name = "IMX_F0_GPIO94"
    )
    IMX_F0_GPIO94,

    /**
     * {@code IMX_F1_GPIO94 = 373}
     */
    @EnumMember(
        value = 373L,
        name = "IMX_F1_GPIO94"
    )
    IMX_F1_GPIO94,

    /**
     * {@code IMX_F2_GPIO94 = 374}
     */
    @EnumMember(
        value = 374L,
        name = "IMX_F2_GPIO94"
    )
    IMX_F2_GPIO94,

    /**
     * {@code IMX_F3_GPIO94 = 375}
     */
    @EnumMember(
        value = 375L,
        name = "IMX_F3_GPIO94"
    )
    IMX_F3_GPIO94,

    /**
     * {@code IMX_F0_GPIO95 = 376}
     */
    @EnumMember(
        value = 376L,
        name = "IMX_F0_GPIO95"
    )
    IMX_F0_GPIO95,

    /**
     * {@code IMX_F1_GPIO95 = 377}
     */
    @EnumMember(
        value = 377L,
        name = "IMX_F1_GPIO95"
    )
    IMX_F1_GPIO95,

    /**
     * {@code IMX_F2_GPIO95 = 378}
     */
    @EnumMember(
        value = 378L,
        name = "IMX_F2_GPIO95"
    )
    IMX_F2_GPIO95,

    /**
     * {@code IMX_F3_GPIO95 = 379}
     */
    @EnumMember(
        value = 379L,
        name = "IMX_F3_GPIO95"
    )
    IMX_F3_GPIO95,

    /**
     * {@code IMX_F0_GPIO96 = 380}
     */
    @EnumMember(
        value = 380L,
        name = "IMX_F0_GPIO96"
    )
    IMX_F0_GPIO96,

    /**
     * {@code IMX_F1_GPIO96 = 381}
     */
    @EnumMember(
        value = 381L,
        name = "IMX_F1_GPIO96"
    )
    IMX_F1_GPIO96,

    /**
     * {@code IMX_F2_GPIO96 = 382}
     */
    @EnumMember(
        value = 382L,
        name = "IMX_F2_GPIO96"
    )
    IMX_F2_GPIO96,

    /**
     * {@code IMX_F3_GPIO96 = 383}
     */
    @EnumMember(
        value = 383L,
        name = "IMX_F3_GPIO96"
    )
    IMX_F3_GPIO96,

    /**
     * {@code IMX_F0_GPIO97 = 384}
     */
    @EnumMember(
        value = 384L,
        name = "IMX_F0_GPIO97"
    )
    IMX_F0_GPIO97,

    /**
     * {@code IMX_F1_GPIO97 = 385}
     */
    @EnumMember(
        value = 385L,
        name = "IMX_F1_GPIO97"
    )
    IMX_F1_GPIO97,

    /**
     * {@code IMX_F2_GPIO97 = 386}
     */
    @EnumMember(
        value = 386L,
        name = "IMX_F2_GPIO97"
    )
    IMX_F2_GPIO97,

    /**
     * {@code IMX_F3_GPIO97 = 387}
     */
    @EnumMember(
        value = 387L,
        name = "IMX_F3_GPIO97"
    )
    IMX_F3_GPIO97,

    /**
     * {@code IMX_F0_GPIO98 = 388}
     */
    @EnumMember(
        value = 388L,
        name = "IMX_F0_GPIO98"
    )
    IMX_F0_GPIO98,

    /**
     * {@code IMX_F1_GPIO98 = 389}
     */
    @EnumMember(
        value = 389L,
        name = "IMX_F1_GPIO98"
    )
    IMX_F1_GPIO98,

    /**
     * {@code IMX_F2_GPIO98 = 390}
     */
    @EnumMember(
        value = 390L,
        name = "IMX_F2_GPIO98"
    )
    IMX_F2_GPIO98,

    /**
     * {@code IMX_F3_GPIO98 = 391}
     */
    @EnumMember(
        value = 391L,
        name = "IMX_F3_GPIO98"
    )
    IMX_F3_GPIO98,

    /**
     * {@code IMX_F0_GPIO99 = 392}
     */
    @EnumMember(
        value = 392L,
        name = "IMX_F0_GPIO99"
    )
    IMX_F0_GPIO99,

    /**
     * {@code IMX_F1_GPIO99 = 393}
     */
    @EnumMember(
        value = 393L,
        name = "IMX_F1_GPIO99"
    )
    IMX_F1_GPIO99,

    /**
     * {@code IMX_F2_GPIO99 = 394}
     */
    @EnumMember(
        value = 394L,
        name = "IMX_F2_GPIO99"
    )
    IMX_F2_GPIO99,

    /**
     * {@code IMX_F3_GPIO99 = 395}
     */
    @EnumMember(
        value = 395L,
        name = "IMX_F3_GPIO99"
    )
    IMX_F3_GPIO99,

    /**
     * {@code IMX_F0_GPIO100 = 396}
     */
    @EnumMember(
        value = 396L,
        name = "IMX_F0_GPIO100"
    )
    IMX_F0_GPIO100,

    /**
     * {@code IMX_F1_GPIO100 = 397}
     */
    @EnumMember(
        value = 397L,
        name = "IMX_F1_GPIO100"
    )
    IMX_F1_GPIO100,

    /**
     * {@code IMX_F2_GPIO100 = 398}
     */
    @EnumMember(
        value = 398L,
        name = "IMX_F2_GPIO100"
    )
    IMX_F2_GPIO100,

    /**
     * {@code IMX_F3_GPIO100 = 399}
     */
    @EnumMember(
        value = 399L,
        name = "IMX_F3_GPIO100"
    )
    IMX_F3_GPIO100,

    /**
     * {@code IMX_F0_GPIO101 = 400}
     */
    @EnumMember(
        value = 400L,
        name = "IMX_F0_GPIO101"
    )
    IMX_F0_GPIO101,

    /**
     * {@code IMX_F1_GPIO101 = 401}
     */
    @EnumMember(
        value = 401L,
        name = "IMX_F1_GPIO101"
    )
    IMX_F1_GPIO101,

    /**
     * {@code IMX_F2_GPIO101 = 402}
     */
    @EnumMember(
        value = 402L,
        name = "IMX_F2_GPIO101"
    )
    IMX_F2_GPIO101,

    /**
     * {@code IMX_F3_GPIO101 = 403}
     */
    @EnumMember(
        value = 403L,
        name = "IMX_F3_GPIO101"
    )
    IMX_F3_GPIO101,

    /**
     * {@code IMX_F0_GPIO102 = 404}
     */
    @EnumMember(
        value = 404L,
        name = "IMX_F0_GPIO102"
    )
    IMX_F0_GPIO102,

    /**
     * {@code IMX_F1_GPIO102 = 405}
     */
    @EnumMember(
        value = 405L,
        name = "IMX_F1_GPIO102"
    )
    IMX_F1_GPIO102,

    /**
     * {@code IMX_F2_GPIO102 = 406}
     */
    @EnumMember(
        value = 406L,
        name = "IMX_F2_GPIO102"
    )
    IMX_F2_GPIO102,

    /**
     * {@code IMX_F3_GPIO102 = 407}
     */
    @EnumMember(
        value = 407L,
        name = "IMX_F3_GPIO102"
    )
    IMX_F3_GPIO102,

    /**
     * {@code IMX_F0_GPIO103 = 408}
     */
    @EnumMember(
        value = 408L,
        name = "IMX_F0_GPIO103"
    )
    IMX_F0_GPIO103,

    /**
     * {@code IMX_F1_GPIO103 = 409}
     */
    @EnumMember(
        value = 409L,
        name = "IMX_F1_GPIO103"
    )
    IMX_F1_GPIO103,

    /**
     * {@code IMX_F2_GPIO103 = 410}
     */
    @EnumMember(
        value = 410L,
        name = "IMX_F2_GPIO103"
    )
    IMX_F2_GPIO103,

    /**
     * {@code IMX_F3_GPIO103 = 411}
     */
    @EnumMember(
        value = 411L,
        name = "IMX_F3_GPIO103"
    )
    IMX_F3_GPIO103,

    /**
     * {@code IMX_F0_GPIO104 = 412}
     */
    @EnumMember(
        value = 412L,
        name = "IMX_F0_GPIO104"
    )
    IMX_F0_GPIO104,

    /**
     * {@code IMX_F1_GPIO104 = 413}
     */
    @EnumMember(
        value = 413L,
        name = "IMX_F1_GPIO104"
    )
    IMX_F1_GPIO104,

    /**
     * {@code IMX_F2_GPIO104 = 414}
     */
    @EnumMember(
        value = 414L,
        name = "IMX_F2_GPIO104"
    )
    IMX_F2_GPIO104,

    /**
     * {@code IMX_F3_GPIO104 = 415}
     */
    @EnumMember(
        value = 415L,
        name = "IMX_F3_GPIO104"
    )
    IMX_F3_GPIO104,

    /**
     * {@code IMX_F0_GPIO105 = 416}
     */
    @EnumMember(
        value = 416L,
        name = "IMX_F0_GPIO105"
    )
    IMX_F0_GPIO105,

    /**
     * {@code IMX_F1_GPIO105 = 417}
     */
    @EnumMember(
        value = 417L,
        name = "IMX_F1_GPIO105"
    )
    IMX_F1_GPIO105,

    /**
     * {@code IMX_F2_GPIO105 = 418}
     */
    @EnumMember(
        value = 418L,
        name = "IMX_F2_GPIO105"
    )
    IMX_F2_GPIO105,

    /**
     * {@code IMX_F3_GPIO105 = 419}
     */
    @EnumMember(
        value = 419L,
        name = "IMX_F3_GPIO105"
    )
    IMX_F3_GPIO105,

    /**
     * {@code IMX_F0_GPIO106 = 420}
     */
    @EnumMember(
        value = 420L,
        name = "IMX_F0_GPIO106"
    )
    IMX_F0_GPIO106,

    /**
     * {@code IMX_F1_GPIO106 = 421}
     */
    @EnumMember(
        value = 421L,
        name = "IMX_F1_GPIO106"
    )
    IMX_F1_GPIO106,

    /**
     * {@code IMX_F2_GPIO106 = 422}
     */
    @EnumMember(
        value = 422L,
        name = "IMX_F2_GPIO106"
    )
    IMX_F2_GPIO106,

    /**
     * {@code IMX_F3_GPIO106 = 423}
     */
    @EnumMember(
        value = 423L,
        name = "IMX_F3_GPIO106"
    )
    IMX_F3_GPIO106,

    /**
     * {@code IMX_F0_GPIO107 = 424}
     */
    @EnumMember(
        value = 424L,
        name = "IMX_F0_GPIO107"
    )
    IMX_F0_GPIO107,

    /**
     * {@code IMX_F1_GPIO107 = 425}
     */
    @EnumMember(
        value = 425L,
        name = "IMX_F1_GPIO107"
    )
    IMX_F1_GPIO107,

    /**
     * {@code IMX_F2_GPIO107 = 426}
     */
    @EnumMember(
        value = 426L,
        name = "IMX_F2_GPIO107"
    )
    IMX_F2_GPIO107,

    /**
     * {@code IMX_F3_GPIO107 = 427}
     */
    @EnumMember(
        value = 427L,
        name = "IMX_F3_GPIO107"
    )
    IMX_F3_GPIO107,

    /**
     * {@code IMX_F0_GPIO108 = 428}
     */
    @EnumMember(
        value = 428L,
        name = "IMX_F0_GPIO108"
    )
    IMX_F0_GPIO108,

    /**
     * {@code IMX_F1_GPIO108 = 429}
     */
    @EnumMember(
        value = 429L,
        name = "IMX_F1_GPIO108"
    )
    IMX_F1_GPIO108,

    /**
     * {@code IMX_F2_GPIO108 = 430}
     */
    @EnumMember(
        value = 430L,
        name = "IMX_F2_GPIO108"
    )
    IMX_F2_GPIO108,

    /**
     * {@code IMX_F3_GPIO108 = 431}
     */
    @EnumMember(
        value = 431L,
        name = "IMX_F3_GPIO108"
    )
    IMX_F3_GPIO108,

    /**
     * {@code IMX_F0_GPIO109 = 432}
     */
    @EnumMember(
        value = 432L,
        name = "IMX_F0_GPIO109"
    )
    IMX_F0_GPIO109,

    /**
     * {@code IMX_F1_GPIO109 = 433}
     */
    @EnumMember(
        value = 433L,
        name = "IMX_F1_GPIO109"
    )
    IMX_F1_GPIO109,

    /**
     * {@code IMX_F2_GPIO109 = 434}
     */
    @EnumMember(
        value = 434L,
        name = "IMX_F2_GPIO109"
    )
    IMX_F2_GPIO109,

    /**
     * {@code IMX_F3_GPIO109 = 435}
     */
    @EnumMember(
        value = 435L,
        name = "IMX_F3_GPIO109"
    )
    IMX_F3_GPIO109,

    /**
     * {@code IMX_F0_GPIO110 = 436}
     */
    @EnumMember(
        value = 436L,
        name = "IMX_F0_GPIO110"
    )
    IMX_F0_GPIO110,

    /**
     * {@code IMX_F1_GPIO110 = 437}
     */
    @EnumMember(
        value = 437L,
        name = "IMX_F1_GPIO110"
    )
    IMX_F1_GPIO110,

    /**
     * {@code IMX_F2_GPIO110 = 438}
     */
    @EnumMember(
        value = 438L,
        name = "IMX_F2_GPIO110"
    )
    IMX_F2_GPIO110,

    /**
     * {@code IMX_F3_GPIO110 = 439}
     */
    @EnumMember(
        value = 439L,
        name = "IMX_F3_GPIO110"
    )
    IMX_F3_GPIO110,

    /**
     * {@code IMX_F0_GPIO111 = 440}
     */
    @EnumMember(
        value = 440L,
        name = "IMX_F0_GPIO111"
    )
    IMX_F0_GPIO111,

    /**
     * {@code IMX_F1_GPIO111 = 441}
     */
    @EnumMember(
        value = 441L,
        name = "IMX_F1_GPIO111"
    )
    IMX_F1_GPIO111,

    /**
     * {@code IMX_F2_GPIO111 = 442}
     */
    @EnumMember(
        value = 442L,
        name = "IMX_F2_GPIO111"
    )
    IMX_F2_GPIO111,

    /**
     * {@code IMX_F3_GPIO111 = 443}
     */
    @EnumMember(
        value = 443L,
        name = "IMX_F3_GPIO111"
    )
    IMX_F3_GPIO111,

    /**
     * {@code IMX_F0_GPIO112 = 444}
     */
    @EnumMember(
        value = 444L,
        name = "IMX_F0_GPIO112"
    )
    IMX_F0_GPIO112,

    /**
     * {@code IMX_F1_GPIO112 = 445}
     */
    @EnumMember(
        value = 445L,
        name = "IMX_F1_GPIO112"
    )
    IMX_F1_GPIO112,

    /**
     * {@code IMX_F2_GPIO112 = 446}
     */
    @EnumMember(
        value = 446L,
        name = "IMX_F2_GPIO112"
    )
    IMX_F2_GPIO112,

    /**
     * {@code IMX_F3_GPIO112 = 447}
     */
    @EnumMember(
        value = 447L,
        name = "IMX_F3_GPIO112"
    )
    IMX_F3_GPIO112,

    /**
     * {@code IMX_F0_GPIO113 = 448}
     */
    @EnumMember(
        value = 448L,
        name = "IMX_F0_GPIO113"
    )
    IMX_F0_GPIO113,

    /**
     * {@code IMX_F1_GPIO113 = 449}
     */
    @EnumMember(
        value = 449L,
        name = "IMX_F1_GPIO113"
    )
    IMX_F1_GPIO113,

    /**
     * {@code IMX_F2_GPIO113 = 450}
     */
    @EnumMember(
        value = 450L,
        name = "IMX_F2_GPIO113"
    )
    IMX_F2_GPIO113,

    /**
     * {@code IMX_F3_GPIO113 = 451}
     */
    @EnumMember(
        value = 451L,
        name = "IMX_F3_GPIO113"
    )
    IMX_F3_GPIO113,

    /**
     * {@code IMX_F0_GPIO114 = 452}
     */
    @EnumMember(
        value = 452L,
        name = "IMX_F0_GPIO114"
    )
    IMX_F0_GPIO114,

    /**
     * {@code IMX_F1_GPIO114 = 453}
     */
    @EnumMember(
        value = 453L,
        name = "IMX_F1_GPIO114"
    )
    IMX_F1_GPIO114,

    /**
     * {@code IMX_F2_GPIO114 = 454}
     */
    @EnumMember(
        value = 454L,
        name = "IMX_F2_GPIO114"
    )
    IMX_F2_GPIO114,

    /**
     * {@code IMX_F3_GPIO114 = 455}
     */
    @EnumMember(
        value = 455L,
        name = "IMX_F3_GPIO114"
    )
    IMX_F3_GPIO114,

    /**
     * {@code IMX_F0_GPIO115 = 456}
     */
    @EnumMember(
        value = 456L,
        name = "IMX_F0_GPIO115"
    )
    IMX_F0_GPIO115,

    /**
     * {@code IMX_F1_GPIO115 = 457}
     */
    @EnumMember(
        value = 457L,
        name = "IMX_F1_GPIO115"
    )
    IMX_F1_GPIO115,

    /**
     * {@code IMX_F2_GPIO115 = 458}
     */
    @EnumMember(
        value = 458L,
        name = "IMX_F2_GPIO115"
    )
    IMX_F2_GPIO115,

    /**
     * {@code IMX_F3_GPIO115 = 459}
     */
    @EnumMember(
        value = 459L,
        name = "IMX_F3_GPIO115"
    )
    IMX_F3_GPIO115,

    /**
     * {@code IMX_F0_GPIO116 = 460}
     */
    @EnumMember(
        value = 460L,
        name = "IMX_F0_GPIO116"
    )
    IMX_F0_GPIO116,

    /**
     * {@code IMX_F1_GPIO116 = 461}
     */
    @EnumMember(
        value = 461L,
        name = "IMX_F1_GPIO116"
    )
    IMX_F1_GPIO116,

    /**
     * {@code IMX_F2_GPIO116 = 462}
     */
    @EnumMember(
        value = 462L,
        name = "IMX_F2_GPIO116"
    )
    IMX_F2_GPIO116,

    /**
     * {@code IMX_F3_GPIO116 = 463}
     */
    @EnumMember(
        value = 463L,
        name = "IMX_F3_GPIO116"
    )
    IMX_F3_GPIO116,

    /**
     * {@code IMX_F0_GPIO117 = 464}
     */
    @EnumMember(
        value = 464L,
        name = "IMX_F0_GPIO117"
    )
    IMX_F0_GPIO117,

    /**
     * {@code IMX_F1_GPIO117 = 465}
     */
    @EnumMember(
        value = 465L,
        name = "IMX_F1_GPIO117"
    )
    IMX_F1_GPIO117,

    /**
     * {@code IMX_F2_GPIO117 = 466}
     */
    @EnumMember(
        value = 466L,
        name = "IMX_F2_GPIO117"
    )
    IMX_F2_GPIO117,

    /**
     * {@code IMX_F3_GPIO117 = 467}
     */
    @EnumMember(
        value = 467L,
        name = "IMX_F3_GPIO117"
    )
    IMX_F3_GPIO117,

    /**
     * {@code IMX_F0_GPIO118 = 468}
     */
    @EnumMember(
        value = 468L,
        name = "IMX_F0_GPIO118"
    )
    IMX_F0_GPIO118,

    /**
     * {@code IMX_F1_GPIO118 = 469}
     */
    @EnumMember(
        value = 469L,
        name = "IMX_F1_GPIO118"
    )
    IMX_F1_GPIO118,

    /**
     * {@code IMX_F2_GPIO118 = 470}
     */
    @EnumMember(
        value = 470L,
        name = "IMX_F2_GPIO118"
    )
    IMX_F2_GPIO118,

    /**
     * {@code IMX_F3_GPIO118 = 471}
     */
    @EnumMember(
        value = 471L,
        name = "IMX_F3_GPIO118"
    )
    IMX_F3_GPIO118,

    /**
     * {@code IMX_F0_GPIO119 = 472}
     */
    @EnumMember(
        value = 472L,
        name = "IMX_F0_GPIO119"
    )
    IMX_F0_GPIO119,

    /**
     * {@code IMX_F1_GPIO119 = 473}
     */
    @EnumMember(
        value = 473L,
        name = "IMX_F1_GPIO119"
    )
    IMX_F1_GPIO119,

    /**
     * {@code IMX_F2_GPIO119 = 474}
     */
    @EnumMember(
        value = 474L,
        name = "IMX_F2_GPIO119"
    )
    IMX_F2_GPIO119,

    /**
     * {@code IMX_F3_GPIO119 = 475}
     */
    @EnumMember(
        value = 475L,
        name = "IMX_F3_GPIO119"
    )
    IMX_F3_GPIO119,

    /**
     * {@code IMX_F0_GPIO120 = 476}
     */
    @EnumMember(
        value = 476L,
        name = "IMX_F0_GPIO120"
    )
    IMX_F0_GPIO120,

    /**
     * {@code IMX_F1_GPIO120 = 477}
     */
    @EnumMember(
        value = 477L,
        name = "IMX_F1_GPIO120"
    )
    IMX_F1_GPIO120,

    /**
     * {@code IMX_F2_GPIO120 = 478}
     */
    @EnumMember(
        value = 478L,
        name = "IMX_F2_GPIO120"
    )
    IMX_F2_GPIO120,

    /**
     * {@code IMX_F3_GPIO120 = 479}
     */
    @EnumMember(
        value = 479L,
        name = "IMX_F3_GPIO120"
    )
    IMX_F3_GPIO120,

    /**
     * {@code IMX_F0_GPIO121 = 480}
     */
    @EnumMember(
        value = 480L,
        name = "IMX_F0_GPIO121"
    )
    IMX_F0_GPIO121,

    /**
     * {@code IMX_F1_GPIO121 = 481}
     */
    @EnumMember(
        value = 481L,
        name = "IMX_F1_GPIO121"
    )
    IMX_F1_GPIO121,

    /**
     * {@code IMX_F2_GPIO121 = 482}
     */
    @EnumMember(
        value = 482L,
        name = "IMX_F2_GPIO121"
    )
    IMX_F2_GPIO121,

    /**
     * {@code IMX_F3_GPIO121 = 483}
     */
    @EnumMember(
        value = 483L,
        name = "IMX_F3_GPIO121"
    )
    IMX_F3_GPIO121,

    /**
     * {@code IMX_F0_GPIO122 = 484}
     */
    @EnumMember(
        value = 484L,
        name = "IMX_F0_GPIO122"
    )
    IMX_F0_GPIO122,

    /**
     * {@code IMX_F1_GPIO122 = 485}
     */
    @EnumMember(
        value = 485L,
        name = "IMX_F1_GPIO122"
    )
    IMX_F1_GPIO122,

    /**
     * {@code IMX_F2_GPIO122 = 486}
     */
    @EnumMember(
        value = 486L,
        name = "IMX_F2_GPIO122"
    )
    IMX_F2_GPIO122,

    /**
     * {@code IMX_F3_GPIO122 = 487}
     */
    @EnumMember(
        value = 487L,
        name = "IMX_F3_GPIO122"
    )
    IMX_F3_GPIO122,

    /**
     * {@code IMX_F0_GPIO123 = 488}
     */
    @EnumMember(
        value = 488L,
        name = "IMX_F0_GPIO123"
    )
    IMX_F0_GPIO123,

    /**
     * {@code IMX_F1_GPIO123 = 489}
     */
    @EnumMember(
        value = 489L,
        name = "IMX_F1_GPIO123"
    )
    IMX_F1_GPIO123,

    /**
     * {@code IMX_F2_GPIO123 = 490}
     */
    @EnumMember(
        value = 490L,
        name = "IMX_F2_GPIO123"
    )
    IMX_F2_GPIO123,

    /**
     * {@code IMX_F3_GPIO123 = 491}
     */
    @EnumMember(
        value = 491L,
        name = "IMX_F3_GPIO123"
    )
    IMX_F3_GPIO123,

    /**
     * {@code IMX_F0_GPIO124 = 492}
     */
    @EnumMember(
        value = 492L,
        name = "IMX_F0_GPIO124"
    )
    IMX_F0_GPIO124,

    /**
     * {@code IMX_F1_GPIO124 = 493}
     */
    @EnumMember(
        value = 493L,
        name = "IMX_F1_GPIO124"
    )
    IMX_F1_GPIO124,

    /**
     * {@code IMX_F2_GPIO124 = 494}
     */
    @EnumMember(
        value = 494L,
        name = "IMX_F2_GPIO124"
    )
    IMX_F2_GPIO124,

    /**
     * {@code IMX_F3_GPIO124 = 495}
     */
    @EnumMember(
        value = 495L,
        name = "IMX_F3_GPIO124"
    )
    IMX_F3_GPIO124,

    /**
     * {@code IMX_F0_GPIO125 = 496}
     */
    @EnumMember(
        value = 496L,
        name = "IMX_F0_GPIO125"
    )
    IMX_F0_GPIO125,

    /**
     * {@code IMX_F1_GPIO125 = 497}
     */
    @EnumMember(
        value = 497L,
        name = "IMX_F1_GPIO125"
    )
    IMX_F1_GPIO125,

    /**
     * {@code IMX_F2_GPIO125 = 498}
     */
    @EnumMember(
        value = 498L,
        name = "IMX_F2_GPIO125"
    )
    IMX_F2_GPIO125,

    /**
     * {@code IMX_F3_GPIO125 = 499}
     */
    @EnumMember(
        value = 499L,
        name = "IMX_F3_GPIO125"
    )
    IMX_F3_GPIO125,

    /**
     * {@code IMX_F0_GPIO126 = 500}
     */
    @EnumMember(
        value = 500L,
        name = "IMX_F0_GPIO126"
    )
    IMX_F0_GPIO126,

    /**
     * {@code IMX_F1_GPIO126 = 501}
     */
    @EnumMember(
        value = 501L,
        name = "IMX_F1_GPIO126"
    )
    IMX_F1_GPIO126,

    /**
     * {@code IMX_F2_GPIO126 = 502}
     */
    @EnumMember(
        value = 502L,
        name = "IMX_F2_GPIO126"
    )
    IMX_F2_GPIO126,

    /**
     * {@code IMX_F3_GPIO126 = 503}
     */
    @EnumMember(
        value = 503L,
        name = "IMX_F3_GPIO126"
    )
    IMX_F3_GPIO126,

    /**
     * {@code IMX_F0_GPIO127 = 504}
     */
    @EnumMember(
        value = 504L,
        name = "IMX_F0_GPIO127"
    )
    IMX_F0_GPIO127,

    /**
     * {@code IMX_F1_GPIO127 = 505}
     */
    @EnumMember(
        value = 505L,
        name = "IMX_F1_GPIO127"
    )
    IMX_F1_GPIO127,

    /**
     * {@code IMX_F2_GPIO127 = 506}
     */
    @EnumMember(
        value = 506L,
        name = "IMX_F2_GPIO127"
    )
    IMX_F2_GPIO127,

    /**
     * {@code IMX_F3_GPIO127 = 507}
     */
    @EnumMember(
        value = 507L,
        name = "IMX_F3_GPIO127"
    )
    IMX_F3_GPIO127,

    /**
     * {@code IMX_F0_GPIO128 = 508}
     */
    @EnumMember(
        value = 508L,
        name = "IMX_F0_GPIO128"
    )
    IMX_F0_GPIO128,

    /**
     * {@code IMX_F1_GPIO128 = 509}
     */
    @EnumMember(
        value = 509L,
        name = "IMX_F1_GPIO128"
    )
    IMX_F1_GPIO128,

    /**
     * {@code IMX_F2_GPIO128 = 510}
     */
    @EnumMember(
        value = 510L,
        name = "IMX_F2_GPIO128"
    )
    IMX_F2_GPIO128,

    /**
     * {@code IMX_F3_GPIO128 = 511}
     */
    @EnumMember(
        value = 511L,
        name = "IMX_F3_GPIO128"
    )
    IMX_F3_GPIO128,

    /**
     * {@code IMX_F0_GPIO129 = 512}
     */
    @EnumMember(
        value = 512L,
        name = "IMX_F0_GPIO129"
    )
    IMX_F0_GPIO129,

    /**
     * {@code IMX_F1_GPIO129 = 513}
     */
    @EnumMember(
        value = 513L,
        name = "IMX_F1_GPIO129"
    )
    IMX_F1_GPIO129,

    /**
     * {@code IMX_F2_GPIO129 = 514}
     */
    @EnumMember(
        value = 514L,
        name = "IMX_F2_GPIO129"
    )
    IMX_F2_GPIO129,

    /**
     * {@code IMX_F3_GPIO129 = 515}
     */
    @EnumMember(
        value = 515L,
        name = "IMX_F3_GPIO129"
    )
    IMX_F3_GPIO129,

    /**
     * {@code IMX_F0_GPIO130 = 516}
     */
    @EnumMember(
        value = 516L,
        name = "IMX_F0_GPIO130"
    )
    IMX_F0_GPIO130,

    /**
     * {@code IMX_F1_GPIO130 = 517}
     */
    @EnumMember(
        value = 517L,
        name = "IMX_F1_GPIO130"
    )
    IMX_F1_GPIO130,

    /**
     * {@code IMX_F2_GPIO130 = 518}
     */
    @EnumMember(
        value = 518L,
        name = "IMX_F2_GPIO130"
    )
    IMX_F2_GPIO130,

    /**
     * {@code IMX_F3_GPIO130 = 519}
     */
    @EnumMember(
        value = 519L,
        name = "IMX_F3_GPIO130"
    )
    IMX_F3_GPIO130,

    /**
     * {@code IMX_F0_GPIO131 = 520}
     */
    @EnumMember(
        value = 520L,
        name = "IMX_F0_GPIO131"
    )
    IMX_F0_GPIO131,

    /**
     * {@code IMX_F1_GPIO131 = 521}
     */
    @EnumMember(
        value = 521L,
        name = "IMX_F1_GPIO131"
    )
    IMX_F1_GPIO131,

    /**
     * {@code IMX_F2_GPIO131 = 522}
     */
    @EnumMember(
        value = 522L,
        name = "IMX_F2_GPIO131"
    )
    IMX_F2_GPIO131,

    /**
     * {@code IMX_F3_GPIO131 = 523}
     */
    @EnumMember(
        value = 523L,
        name = "IMX_F3_GPIO131"
    )
    IMX_F3_GPIO131,

    /**
     * {@code IMX_F0_GPIO132 = 524}
     */
    @EnumMember(
        value = 524L,
        name = "IMX_F0_GPIO132"
    )
    IMX_F0_GPIO132,

    /**
     * {@code IMX_F1_GPIO132 = 525}
     */
    @EnumMember(
        value = 525L,
        name = "IMX_F1_GPIO132"
    )
    IMX_F1_GPIO132,

    /**
     * {@code IMX_F2_GPIO132 = 526}
     */
    @EnumMember(
        value = 526L,
        name = "IMX_F2_GPIO132"
    )
    IMX_F2_GPIO132,

    /**
     * {@code IMX_F3_GPIO132 = 527}
     */
    @EnumMember(
        value = 527L,
        name = "IMX_F3_GPIO132"
    )
    IMX_F3_GPIO132,

    /**
     * {@code IMX_F0_GPIO133 = 528}
     */
    @EnumMember(
        value = 528L,
        name = "IMX_F0_GPIO133"
    )
    IMX_F0_GPIO133,

    /**
     * {@code IMX_F1_GPIO133 = 529}
     */
    @EnumMember(
        value = 529L,
        name = "IMX_F1_GPIO133"
    )
    IMX_F1_GPIO133,

    /**
     * {@code IMX_F2_GPIO133 = 530}
     */
    @EnumMember(
        value = 530L,
        name = "IMX_F2_GPIO133"
    )
    IMX_F2_GPIO133,

    /**
     * {@code IMX_F3_GPIO133 = 531}
     */
    @EnumMember(
        value = 531L,
        name = "IMX_F3_GPIO133"
    )
    IMX_F3_GPIO133,

    /**
     * {@code IMX_F0_GPIO134 = 532}
     */
    @EnumMember(
        value = 532L,
        name = "IMX_F0_GPIO134"
    )
    IMX_F0_GPIO134,

    /**
     * {@code IMX_F1_GPIO134 = 533}
     */
    @EnumMember(
        value = 533L,
        name = "IMX_F1_GPIO134"
    )
    IMX_F1_GPIO134,

    /**
     * {@code IMX_F2_GPIO134 = 534}
     */
    @EnumMember(
        value = 534L,
        name = "IMX_F2_GPIO134"
    )
    IMX_F2_GPIO134,

    /**
     * {@code IMX_F3_GPIO134 = 535}
     */
    @EnumMember(
        value = 535L,
        name = "IMX_F3_GPIO134"
    )
    IMX_F3_GPIO134,

    /**
     * {@code IMX_F0_GPIO135 = 536}
     */
    @EnumMember(
        value = 536L,
        name = "IMX_F0_GPIO135"
    )
    IMX_F0_GPIO135,

    /**
     * {@code IMX_F1_GPIO135 = 537}
     */
    @EnumMember(
        value = 537L,
        name = "IMX_F1_GPIO135"
    )
    IMX_F1_GPIO135,

    /**
     * {@code IMX_F2_GPIO135 = 538}
     */
    @EnumMember(
        value = 538L,
        name = "IMX_F2_GPIO135"
    )
    IMX_F2_GPIO135,

    /**
     * {@code IMX_F3_GPIO135 = 539}
     */
    @EnumMember(
        value = 539L,
        name = "IMX_F3_GPIO135"
    )
    IMX_F3_GPIO135,

    /**
     * {@code IMX_F0_GPIO136 = 540}
     */
    @EnumMember(
        value = 540L,
        name = "IMX_F0_GPIO136"
    )
    IMX_F0_GPIO136,

    /**
     * {@code IMX_F1_GPIO136 = 541}
     */
    @EnumMember(
        value = 541L,
        name = "IMX_F1_GPIO136"
    )
    IMX_F1_GPIO136,

    /**
     * {@code IMX_F2_GPIO136 = 542}
     */
    @EnumMember(
        value = 542L,
        name = "IMX_F2_GPIO136"
    )
    IMX_F2_GPIO136,

    /**
     * {@code IMX_F3_GPIO136 = 543}
     */
    @EnumMember(
        value = 543L,
        name = "IMX_F3_GPIO136"
    )
    IMX_F3_GPIO136,

    /**
     * {@code IMX_F0_GPIO137 = 544}
     */
    @EnumMember(
        value = 544L,
        name = "IMX_F0_GPIO137"
    )
    IMX_F0_GPIO137,

    /**
     * {@code IMX_F1_GPIO137 = 545}
     */
    @EnumMember(
        value = 545L,
        name = "IMX_F1_GPIO137"
    )
    IMX_F1_GPIO137,

    /**
     * {@code IMX_F2_GPIO137 = 546}
     */
    @EnumMember(
        value = 546L,
        name = "IMX_F2_GPIO137"
    )
    IMX_F2_GPIO137,

    /**
     * {@code IMX_F3_GPIO137 = 547}
     */
    @EnumMember(
        value = 547L,
        name = "IMX_F3_GPIO137"
    )
    IMX_F3_GPIO137,

    /**
     * {@code IMX_F0_GPIO138 = 548}
     */
    @EnumMember(
        value = 548L,
        name = "IMX_F0_GPIO138"
    )
    IMX_F0_GPIO138,

    /**
     * {@code IMX_F1_GPIO138 = 549}
     */
    @EnumMember(
        value = 549L,
        name = "IMX_F1_GPIO138"
    )
    IMX_F1_GPIO138,

    /**
     * {@code IMX_F2_GPIO138 = 550}
     */
    @EnumMember(
        value = 550L,
        name = "IMX_F2_GPIO138"
    )
    IMX_F2_GPIO138,

    /**
     * {@code IMX_F3_GPIO138 = 551}
     */
    @EnumMember(
        value = 551L,
        name = "IMX_F3_GPIO138"
    )
    IMX_F3_GPIO138,

    /**
     * {@code IMX_F0_GPIO139 = 552}
     */
    @EnumMember(
        value = 552L,
        name = "IMX_F0_GPIO139"
    )
    IMX_F0_GPIO139,

    /**
     * {@code IMX_F1_GPIO139 = 553}
     */
    @EnumMember(
        value = 553L,
        name = "IMX_F1_GPIO139"
    )
    IMX_F1_GPIO139,

    /**
     * {@code IMX_F2_GPIO139 = 554}
     */
    @EnumMember(
        value = 554L,
        name = "IMX_F2_GPIO139"
    )
    IMX_F2_GPIO139,

    /**
     * {@code IMX_F3_GPIO139 = 555}
     */
    @EnumMember(
        value = 555L,
        name = "IMX_F3_GPIO139"
    )
    IMX_F3_GPIO139,

    /**
     * {@code IMX_F0_GPIO140 = 556}
     */
    @EnumMember(
        value = 556L,
        name = "IMX_F0_GPIO140"
    )
    IMX_F0_GPIO140,

    /**
     * {@code IMX_F1_GPIO140 = 557}
     */
    @EnumMember(
        value = 557L,
        name = "IMX_F1_GPIO140"
    )
    IMX_F1_GPIO140,

    /**
     * {@code IMX_F2_GPIO140 = 558}
     */
    @EnumMember(
        value = 558L,
        name = "IMX_F2_GPIO140"
    )
    IMX_F2_GPIO140,

    /**
     * {@code IMX_F3_GPIO140 = 559}
     */
    @EnumMember(
        value = 559L,
        name = "IMX_F3_GPIO140"
    )
    IMX_F3_GPIO140,

    /**
     * {@code IMX_F0_GPIO141 = 560}
     */
    @EnumMember(
        value = 560L,
        name = "IMX_F0_GPIO141"
    )
    IMX_F0_GPIO141,

    /**
     * {@code IMX_F1_GPIO141 = 561}
     */
    @EnumMember(
        value = 561L,
        name = "IMX_F1_GPIO141"
    )
    IMX_F1_GPIO141,

    /**
     * {@code IMX_F2_GPIO141 = 562}
     */
    @EnumMember(
        value = 562L,
        name = "IMX_F2_GPIO141"
    )
    IMX_F2_GPIO141,

    /**
     * {@code IMX_F3_GPIO141 = 563}
     */
    @EnumMember(
        value = 563L,
        name = "IMX_F3_GPIO141"
    )
    IMX_F3_GPIO141,

    /**
     * {@code IMX_F0_GPIO142 = 564}
     */
    @EnumMember(
        value = 564L,
        name = "IMX_F0_GPIO142"
    )
    IMX_F0_GPIO142,

    /**
     * {@code IMX_F1_GPIO142 = 565}
     */
    @EnumMember(
        value = 565L,
        name = "IMX_F1_GPIO142"
    )
    IMX_F1_GPIO142,

    /**
     * {@code IMX_F2_GPIO142 = 566}
     */
    @EnumMember(
        value = 566L,
        name = "IMX_F2_GPIO142"
    )
    IMX_F2_GPIO142,

    /**
     * {@code IMX_F3_GPIO142 = 567}
     */
    @EnumMember(
        value = 567L,
        name = "IMX_F3_GPIO142"
    )
    IMX_F3_GPIO142,

    /**
     * {@code IMX_F0_GPIO143 = 568}
     */
    @EnumMember(
        value = 568L,
        name = "IMX_F0_GPIO143"
    )
    IMX_F0_GPIO143,

    /**
     * {@code IMX_F1_GPIO143 = 569}
     */
    @EnumMember(
        value = 569L,
        name = "IMX_F1_GPIO143"
    )
    IMX_F1_GPIO143,

    /**
     * {@code IMX_F2_GPIO143 = 570}
     */
    @EnumMember(
        value = 570L,
        name = "IMX_F2_GPIO143"
    )
    IMX_F2_GPIO143,

    /**
     * {@code IMX_F3_GPIO143 = 571}
     */
    @EnumMember(
        value = 571L,
        name = "IMX_F3_GPIO143"
    )
    IMX_F3_GPIO143,

    /**
     * {@code IMX_F0_GPIO144 = 572}
     */
    @EnumMember(
        value = 572L,
        name = "IMX_F0_GPIO144"
    )
    IMX_F0_GPIO144,

    /**
     * {@code IMX_F1_GPIO144 = 573}
     */
    @EnumMember(
        value = 573L,
        name = "IMX_F1_GPIO144"
    )
    IMX_F1_GPIO144,

    /**
     * {@code IMX_F2_GPIO144 = 574}
     */
    @EnumMember(
        value = 574L,
        name = "IMX_F2_GPIO144"
    )
    IMX_F2_GPIO144,

    /**
     * {@code IMX_F3_GPIO144 = 575}
     */
    @EnumMember(
        value = 575L,
        name = "IMX_F3_GPIO144"
    )
    IMX_F3_GPIO144
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_lps0_hid_device_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_lps0_hid_device_data extends Struct {
    public boolean check_off_by_one;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int nid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_of_anon_member_of_io_pgtable_cfg extends Struct {
    public int nid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_iommu_pi_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_iommu_pi_data extends Struct {
    public @Unsigned long vapic_addr;

    public @Unsigned int ga_tag;

    public @Unsigned int vector;

    public int cpu;

    public boolean ga_log_intr;

    public boolean is_guest_mode;

    public Ptr<?> ir_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_io_pgtable"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_io_pgtable extends Struct {
    public @OriginalName("seqcount_t") seqcount seqcount;

    public io_pgtable pgtbl;

    public int mode;

    public Ptr<java.lang. @Unsigned Long> root;

    public Ptr<java.lang. @Unsigned Long> pgd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_iommu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_iommu extends Struct {
    public list_head list;

    public int index;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public Ptr<pci_dev> dev;

    public Ptr<pci_dev> root_pdev;

    public @Unsigned long mmio_phys;

    public @Unsigned long mmio_phys_end;

    public Ptr<java.lang.Character> mmio_base;

    public @Unsigned int cap;

    public char acpi_flags;

    public @Unsigned long features;

    public @Unsigned long features2;

    public @Unsigned short devid;

    public @Unsigned short cap_ptr;

    public Ptr<amd_iommu_pci_seg> pci_seg;

    public @Unsigned long exclusion_start;

    public @Unsigned long exclusion_length;

    public Ptr<java.lang.Character> cmd_buf;

    public @Unsigned int cmd_buf_head;

    public @Unsigned int cmd_buf_tail;

    public Ptr<java.lang.Character> evt_buf;

    public char @Size(16) [] evt_irq_name;

    public Ptr<java.lang.Character> ppr_log;

    public char @Size(16) [] ppr_irq_name;

    public Ptr<java.lang.Character> ga_log;

    public char @Size(16) [] ga_irq_name;

    public Ptr<java.lang.Character> ga_log_tail;

    public boolean int_enabled;

    public boolean need_sync;

    public boolean irtcachedis_enabled;

    public iommu_device iommu;

    public @Unsigned int stored_addr_lo;

    public @Unsigned int stored_addr_hi;

    public @Unsigned int @Size(108) [] stored_l1;

    public @Unsigned int @Size(131) [] stored_l2;

    public char max_banks;

    public char max_counters;

    public Ptr<irq_domain> ir_domain;

    public Ptr<amd_irte_ops> irte_ops;

    public @Unsigned int flags;

    public Ptr<java.lang. @Unsigned Long> cmd_sem;

    public atomic64_t cmd_sem_val;

    public @Unsigned long cmd_sem_paddr;

    public Ptr<iopf_queue> iopf_queue;

    public char @Size(32) [] iopfq_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_iommu_pci_seg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_iommu_pci_seg extends Struct {
    public list_head list;

    public llist_head dev_data_list;

    public @Unsigned short id;

    public @Unsigned short last_bdf;

    public @Unsigned int dev_table_size;

    public Ptr<dev_table_entry> dev_table;

    public Ptr<Ptr<amd_iommu>> rlookup_table;

    public Ptr<Ptr<irq_remap_table>> irq_lookup_table;

    public Ptr<dev_table_entry> old_dev_tbl_cpy;

    public Ptr<java.lang. @Unsigned Short> alias_table;

    public list_head unity_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_irte_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_irte_ops extends Struct {
    public Ptr<?> prepare;

    public Ptr<?> activate;

    public Ptr<?> deactivate;

    public Ptr<?> set_affinity;

    public Ptr<?> get;

    public Ptr<?> set_allocated;

    public Ptr<?> is_allocated;

    public Ptr<?> clear_allocated;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum amd_iommu_intr_mode_type"
  )
  public enum amd_iommu_intr_mode_type implements Enum<amd_iommu_intr_mode_type>, TypedEnum<amd_iommu_intr_mode_type, java.lang. @Unsigned Integer> {
    /**
     * {@code AMD_IOMMU_GUEST_IR_LEGACY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "AMD_IOMMU_GUEST_IR_LEGACY"
    )
    AMD_IOMMU_GUEST_IR_LEGACY,

    /**
     * {@code AMD_IOMMU_GUEST_IR_LEGACY_GA = 1}
     */
    @EnumMember(
        value = 1L,
        name = "AMD_IOMMU_GUEST_IR_LEGACY_GA"
    )
    AMD_IOMMU_GUEST_IR_LEGACY_GA,

    /**
     * {@code AMD_IOMMU_GUEST_IR_VAPIC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "AMD_IOMMU_GUEST_IR_VAPIC"
    )
    AMD_IOMMU_GUEST_IR_VAPIC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_ir_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_ir_data extends Struct {
    public Ptr<amd_iommu> iommu;

    public irq_2_irte irq_2_irte;

    public msi_msg msi_entry;

    public Ptr<?> entry;

    public Ptr<irq_cfg> cfg;

    public int ga_vector;

    public @Unsigned long ga_root_ptr;

    public @Unsigned int ga_tag;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum amd_chipset_gen"
  )
  public enum amd_chipset_gen implements Enum<amd_chipset_gen>, TypedEnum<amd_chipset_gen, java.lang. @Unsigned Integer> {
    /**
     * {@code NOT_AMD_CHIPSET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NOT_AMD_CHIPSET"
    )
    NOT_AMD_CHIPSET,

    /**
     * {@code AMD_CHIPSET_SB600 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "AMD_CHIPSET_SB600"
    )
    AMD_CHIPSET_SB600,

    /**
     * {@code AMD_CHIPSET_SB700 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "AMD_CHIPSET_SB700"
    )
    AMD_CHIPSET_SB700,

    /**
     * {@code AMD_CHIPSET_SB800 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "AMD_CHIPSET_SB800"
    )
    AMD_CHIPSET_SB800,

    /**
     * {@code AMD_CHIPSET_HUDSON2 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "AMD_CHIPSET_HUDSON2"
    )
    AMD_CHIPSET_HUDSON2,

    /**
     * {@code AMD_CHIPSET_BOLTON = 5}
     */
    @EnumMember(
        value = 5L,
        name = "AMD_CHIPSET_BOLTON"
    )
    AMD_CHIPSET_BOLTON,

    /**
     * {@code AMD_CHIPSET_YANGTZE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "AMD_CHIPSET_YANGTZE"
    )
    AMD_CHIPSET_YANGTZE,

    /**
     * {@code AMD_CHIPSET_TAISHAN = 7}
     */
    @EnumMember(
        value = 7L,
        name = "AMD_CHIPSET_TAISHAN"
    )
    AMD_CHIPSET_TAISHAN,

    /**
     * {@code AMD_CHIPSET_UNKNOWN = 8}
     */
    @EnumMember(
        value = 8L,
        name = "AMD_CHIPSET_UNKNOWN"
    )
    AMD_CHIPSET_UNKNOWN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_chipset_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_chipset_type extends Struct {
    public amd_chipset_gen gen;

    public char rev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_chipset_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_chipset_info extends Struct {
    public Ptr<pci_dev> nb_dev;

    public Ptr<pci_dev> smbus_dev;

    public int nb_type;

    public amd_chipset_type sb_type;

    public int isoc_reqs;

    public int probe_count;

    public boolean need_pll_quirk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_aperf_mperf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_aperf_mperf extends Struct {
    public @Unsigned long aperf;

    public @Unsigned long mperf;

    public @Unsigned long tsc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_cpudata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_cpudata extends Struct {
    public int cpu;

    public freq_qos_request @Size(2) [] req;

    public @Unsigned long cppc_req_cached;

    public perf_cached perf;

    public char prefcore_ranking;

    public @Unsigned int min_limit_freq;

    public @Unsigned int max_limit_freq;

    public @Unsigned int nominal_freq;

    public @Unsigned int lowest_nonlinear_freq;

    public amd_aperf_mperf cur;

    public amd_aperf_mperf prev;

    public @Unsigned long freq;

    public boolean boost_supported;

    public boolean hw_prefcore;

    public @Unsigned int policy;

    public boolean suspended;

    public char epp_default;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum amd_pstate_mode"
  )
  public enum amd_pstate_mode implements Enum<amd_pstate_mode>, TypedEnum<amd_pstate_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code AMD_PSTATE_UNDEFINED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "AMD_PSTATE_UNDEFINED"
    )
    AMD_PSTATE_UNDEFINED,

    /**
     * {@code AMD_PSTATE_DISABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "AMD_PSTATE_DISABLE"
    )
    AMD_PSTATE_DISABLE,

    /**
     * {@code AMD_PSTATE_PASSIVE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "AMD_PSTATE_PASSIVE"
    )
    AMD_PSTATE_PASSIVE,

    /**
     * {@code AMD_PSTATE_ACTIVE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "AMD_PSTATE_ACTIVE"
    )
    AMD_PSTATE_ACTIVE,

    /**
     * {@code AMD_PSTATE_GUIDED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "AMD_PSTATE_GUIDED"
    )
    AMD_PSTATE_GUIDED,

    /**
     * {@code AMD_PSTATE_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "AMD_PSTATE_MAX"
    )
    AMD_PSTATE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_wbrf_ranges_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_wbrf_ranges_out extends Struct {
    public @Unsigned int num_of_ranges;

    public freq_band_range @Size(11) [] band_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_shmem_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_shmem_info extends Struct {
    public acpi_pcct_ext_pcc_shared_memory header;

    public @Unsigned int version_number;

    public @Unsigned int n_logical_processors;

    public @Unsigned int n_capabilities;

    public @Unsigned int table_update_context;

    public @Unsigned int n_bitmaps;

    public @Unsigned int reserved;

    public @Unsigned int @Size(0) [] table_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_hfi_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_hfi_data extends Struct {
    public String name;

    public Ptr<device> dev;

    public Ptr<pcc_mbox_chan> pcc_chan;

    public Ptr<?> pcc_comm_addr;

    public Ptr<acpi_subtable_header> pcct_entry;

    public Ptr<amd_shmem_info> shmem;

    public Ptr<dentry> dbgfs_dir;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_hfi_classes"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_hfi_classes extends Struct {
    public @Unsigned int perf;

    public @Unsigned int eff;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_hfi_cpuinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_hfi_cpuinfo extends Struct {
    public int cpu;

    public @Unsigned int apic_id;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpus;

    public short class_index;

    public char nr_class;

    public Ptr<java.lang.Integer> ipcc_scores;

    public Ptr<amd_hfi_classes> amd_hfi_classes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct amd_hostbridge"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class amd_hostbridge extends Struct {
    public @Unsigned int bus;

    public @Unsigned int slot;

    public @Unsigned int device;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_2_irte"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_2_irte extends Struct {
    public @Unsigned short devid;

    public @Unsigned short index;
  }
}
