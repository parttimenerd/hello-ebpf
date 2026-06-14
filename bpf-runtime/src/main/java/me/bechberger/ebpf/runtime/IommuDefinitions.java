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
 * Generated class for BPF runtime types that start with iommu
 */
@java.lang.SuppressWarnings("unused")
public final class IommuDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_attach_device(Ptr<iommu_domain> domain, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_attach_group(Ptr<iommu_domain> domain, Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_calculate_agaw(Ptr<intel_iommu> iommu, int max_gaw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__iommu_copy_struct_from_user($arg1, (const struct iommu_user_data*)$arg2, $arg3, $arg4, $arg5)")
  public static int __iommu_copy_struct_from_user(Ptr<?> dst_data, Ptr<iommu_user_data> src_data,
      @Unsigned int data_type, @Unsigned long data_len, @Unsigned long min_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_device_set_domain(Ptr<iommu_group> group, Ptr<device> dev,
      Ptr<iommu_domain> new_domain, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Ptr<page>> __iommu_dma_alloc_noncontiguous(Ptr<device> dev, @Unsigned long size,
      Ptr<sg_table> sgt, @Unsigned @OriginalName("gfp_t") int gfp, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_dma_free(Ptr<device> dev, @Unsigned long size, Ptr<?> cpu_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_dma_iova_unlink(Ptr<device> dev, Ptr<dma_iova_state> state,
      @Unsigned long offset, @Unsigned long size, dma_data_direction dir, @Unsigned long attrs,
      boolean free_iova) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long __iommu_dma_map(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys, @Unsigned long size, int prot,
      @Unsigned long dma_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_dma_unmap(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_flush_context(Ptr<intel_iommu> iommu, @Unsigned short did,
      @Unsigned short source_id, char function_mask, @Unsigned long type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_flush_iotlb(Ptr<intel_iommu> iommu, @Unsigned short did,
      @Unsigned long addr, @Unsigned int size_order, @Unsigned long type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_free_desc(Ptr<ioptdesc> iopt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_group_free_device(Ptr<iommu_group> group, Ptr<group_device> grp_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_group_remove_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_group_set_domain_internal(Ptr<iommu_group> group,
      Ptr<iommu_domain> new_domain, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_domain> __iommu_paging_domain_alloc_flags(Ptr<device> dev,
      @Unsigned int type, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_probe_device(Ptr<device> dev, Ptr<list_head> group_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_queue_command_sync(Ptr<amd_iommu> iommu, Ptr<iommu_cmd> cmd,
      boolean sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __iommu_release_dma_ownership(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_set_group_pasid(Ptr<iommu_domain> domain, Ptr<iommu_group> group,
      @Unsigned @OriginalName("ioasid_t") int pasid, Ptr<iommu_domain> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__iommu_setup_intcapxt($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static int __iommu_setup_intcapxt(Ptr<amd_iommu> iommu, String devname, int hwirq,
      @OriginalName("irq_handler_t") Ptr<?> thread_fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __iommu_take_dma_ownership(Ptr<iommu_group> group, Ptr<?> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __iommu_unmap(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned long size, Ptr<iommu_iotlb_gather> iotlb_gather) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long _iommu_cpumask_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long _iommu_event_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> iommu_alloc_4k_pages(Ptr<amd_iommu> iommu,
      @Unsigned @OriginalName("gfp_t") int gfp, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("ioasid_t") int iommu_alloc_global_pasid(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> iommu_alloc_pages_node_sz(int nid, @Unsigned @OriginalName("gfp_t") int gfp,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_resv_region> iommu_alloc_resv_region(
      @Unsigned @OriginalName("phys_addr_t") long start, @Unsigned long length, int prot,
      iommu_resv_type type, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_alloc_root_entry(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_apply_resume_quirks(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_area_alloc(Ptr<java.lang. @Unsigned Long> map,
      @Unsigned long size, @Unsigned long start, @Unsigned int nr, @Unsigned long shift,
      @Unsigned long boundary_size, @Unsigned long align_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_attach_device(Ptr<iommu_domain> domain, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_attach_device_pasid(Ptr<iommu_domain> domain, Ptr<device> dev,
      @Unsigned @OriginalName("ioasid_t") int pasid, Ptr<iommu_attach_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_attach_group(Ptr<iommu_domain> domain, Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_attach_group_handle(Ptr<iommu_domain> domain, Ptr<iommu_group> group,
      Ptr<iommu_attach_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_attach_handle> iommu_attach_handle_get(Ptr<iommu_group> group,
      @Unsigned @OriginalName("ioasid_t") int pasid, @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_bus_notifier(Ptr<notifier_block> nb, @Unsigned long action, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_calculate_agaw(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_calculate_max_sagaw(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_call_iopf_notifier(Ptr<amd_iommu> iommu,
      Ptr<java.lang. @Unsigned Long> raw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short iommu_clocks_is_visible(Ptr<kobject> kobj,
      Ptr<attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_completion_wait(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<context_entry> iommu_context_addr(Ptr<intel_iommu> iommu, char bus, char devfn,
      int alloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_create_device_direct_mappings(Ptr<iommu_domain> domain, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean iommu_default_passthrough() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_deferred_attach(Ptr<device> dev, Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_deinit_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_detach_device(Ptr<iommu_domain> domain, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_detach_device_pasid(Ptr<iommu_domain> domain, Ptr<device> dev,
      @Unsigned @OriginalName("ioasid_t") int pasid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_detach_group(Ptr<iommu_domain> domain, Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_detach_group_handle(Ptr<iommu_domain> domain, Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dev_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_device_claim_dma_owner(Ptr<device> dev, Ptr<?> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_device_link(Ptr<iommu_device> iommu, Ptr<device> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_device_register($arg1, (const struct iommu_ops*)$arg2, $arg3)")
  public static int iommu_device_register(Ptr<iommu_device> iommu, Ptr<iommu_ops> ops,
      Ptr<device> hwdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_device_release_dma_owner(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_device_sysfs_add($arg1, $arg2, (const struct attribute_group**)$arg3, (const u8*)$arg4, $arg5_)")
  public static int iommu_device_sysfs_add(Ptr<iommu_device> iommu, Ptr<device> parent,
      Ptr<Ptr<attribute_group>> groups, String fmt, java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_device_sysfs_remove(Ptr<iommu_device> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_device_unlink(Ptr<iommu_device> iommu, Ptr<device> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_device_unregister(Ptr<iommu_device> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_device_unuse_default_domain(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_device_use_default_domain(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_disable(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_disable_irq_remapping(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_disable_protect_mem_regions(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_disable_translation(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> iommu_dma_alloc(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> handle,
      @Unsigned @OriginalName("gfp_t") int gfp, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long iommu_dma_alloc_iova(
      Ptr<iommu_domain> domain, @Unsigned long size, @Unsigned long dma_limit, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> iommu_dma_alloc_noncontiguous(Ptr<device> dev, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int gfp, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> iommu_dma_alloc_pages(Ptr<device> dev, @Unsigned long size,
      Ptr<Ptr<page>> pagep, @Unsigned @OriginalName("gfp_t") int gfp, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_forcedac_setup(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_free(Ptr<device> dev, @Unsigned long size, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long handle, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_free_iova(Ptr<iommu_domain> domain,
      @Unsigned @OriginalName("dma_addr_t") long iova, @Unsigned long size,
      Ptr<iommu_iotlb_gather> gather) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_free_noncontiguous(Ptr<device> dev, @Unsigned long size,
      Ptr<sg_table> sgt, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_dma_get_merge_boundary(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_dma_msi_page> iommu_dma_get_msi_page(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long msi_addr, Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_get_resv_regions(Ptr<device> dev, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_get_sgtable(Ptr<device> dev, Ptr<sg_table> sgt, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_init_domain(Ptr<iommu_domain> domain, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_init_fq(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_iova_bounce_and_link(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr,
      @Unsigned @OriginalName("phys_addr_t") long phys, @Unsigned long bounce_len,
      dma_data_direction dir, @Unsigned long attrs, @Unsigned long iova_start_pad) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long iommu_dma_map_page(Ptr<device> dev,
      Ptr<page> page, @Unsigned long offset, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long iommu_dma_map_resource(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_map_sg(Ptr<device> dev, Ptr<scatterlist> sg, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("phys_addr_t") long iommu_dma_map_swiotlb(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_dma_max_mapping_size(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_mmap(Ptr<device> dev, Ptr<vm_area_struct> vma, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_mmap_noncontiguous(Ptr<device> dev, Ptr<vm_area_struct> vma,
      @Unsigned long size, Ptr<sg_table> sgt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_dma_opt_mapping_size() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_dma_ranges_sort($arg1, (const struct list_head*)$arg2, (const struct list_head*)$arg3)")
  public static int iommu_dma_ranges_sort(Ptr<?> priv, Ptr<list_head> a, Ptr<list_head> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_setup(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_dma_sw_msi(Ptr<iommu_domain> domain, Ptr<msi_desc> desc,
      @Unsigned @OriginalName("phys_addr_t") long msi_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_sync_sg_for_cpu(Ptr<device> dev, Ptr<scatterlist> sgl, int nelems,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_sync_sg_for_device(Ptr<device> dev, Ptr<scatterlist> sgl, int nelems,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_sync_single_for_cpu(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_sync_single_for_device(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_unmap_page(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_unmap_resource(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long handle, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_unmap_sg(Ptr<device> dev, Ptr<scatterlist> sg, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_dma_unmap_sg_swiotlb(Ptr<device> dev, Ptr<scatterlist> sg, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> iommu_dma_vmap_noncontiguous(Ptr<device> dev, @Unsigned long size,
      Ptr<sg_table> sgt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_domain_free(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_enable_command_buffer(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_enable_event_buffer(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_enable_irq_remapping(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_enable_irtcachedis(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_enable_pci_ats(Ptr<device_domain_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_enable_translation(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_feature_enable(Ptr<amd_iommu> iommu, char bit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_feature_set(Ptr<amd_iommu> iommu, @Unsigned long val,
      @Unsigned long mask, char shift) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_flush_dte(Ptr<amd_iommu> iommu, @Unsigned short devid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_flush_irt_and_complete(Ptr<amd_iommu> iommu, @Unsigned short devid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_flush_write_buffer(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_free_global_pasid(@Unsigned @OriginalName("ioasid_t") int pasid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_free_pages(Ptr<?> virt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_fwspec_add_ids($arg1, (const unsigned int*)$arg2, $arg3)")
  public static int iommu_fwspec_add_ids(Ptr<device> dev, Ptr<java.lang. @Unsigned Integer> ids,
      int num_ids) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_fwspec_free(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_fwspec_init(Ptr<device> dev, Ptr<fwnode_handle> iommu_fwnode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_get_default_domain_type(Ptr<iommu_group> group, int target_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_get_dma_cookie(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_domain> iommu_get_dma_domain(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_domain> iommu_get_domain_for_dev(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_get_group_resv_regions(Ptr<iommu_group> group, Ptr<list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_get_msi_cookie(Ptr<iommu_domain> domain,
      @Unsigned @OriginalName("dma_addr_t") long base) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_get_resv_regions(Ptr<device> dev, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_go_to_state(iommu_init_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_group_add_device(Ptr<iommu_group> group, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_group> iommu_group_alloc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<group_device> iommu_group_alloc_device(Ptr<iommu_group> group,
      Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long iommu_group_attr_show(Ptr<kobject> kobj,
      Ptr<attribute> __attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_group_attr_store($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long iommu_group_attr_store(Ptr<kobject> kobj,
      Ptr<attribute> __attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_group_claim_dma_owner(Ptr<iommu_group> group, Ptr<?> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_domain> iommu_group_default_domain(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean iommu_group_dma_owner_claimed(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_group_for_each_dev($arg1, $arg2, (int (*)(struct device*, void*))$arg3)")
  public static int iommu_group_for_each_dev(Ptr<iommu_group> group, Ptr<?> data, Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_group> iommu_group_get(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> iommu_group_get_iommudata(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean iommu_group_has_isolated_msi(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_group_id(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_group_put(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_group> iommu_group_ref_get(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_group_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_group_release_dma_owner(Ptr<iommu_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_group_remove_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_group_set_iommudata($arg1, $arg2, (void (*)(void*))$arg3)")
  public static void iommu_group_set_iommudata(Ptr<iommu_group> group, Ptr<?> iommu_data,
      Ptr<?> release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_group_set_name($arg1, (const u8*)$arg2)")
  public static int iommu_group_set_name(Ptr<iommu_group> group, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long iommu_group_show_name(Ptr<iommu_group> group,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long iommu_group_show_resv_regions(Ptr<iommu_group> group,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long iommu_group_show_type(Ptr<iommu_group> group,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("iommu_group_store_type($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long iommu_group_store_type(Ptr<iommu_group> group,
      String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_init_flags(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_init_noop() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_init_pci(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_insert_resv_region(Ptr<iommu_resv_region> _new, Ptr<list_head> regions) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("phys_addr_t") long iommu_iova_to_phys(
      Ptr<iommu_domain> domain, @Unsigned @OriginalName("dma_addr_t") long iova) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_load_old_irte(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_make_shared(Ptr<?> va, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_map(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long size, int prot,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_map_nosync(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long size, int prot,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long iommu_map_sg(Ptr<iommu_domain> domain,
      @Unsigned long iova, Ptr<scatterlist> sg, @Unsigned int nents, int prot,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short iommu_mem_blocked_is_visible(
      Ptr<kobject> kobj, Ptr<attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> iommu_memremap(@Unsigned long paddr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short iommu_mrds_is_visible(Ptr<kobject> kobj,
      Ptr<attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct iommu_ops*)iommu_ops_from_fwnode((const struct fwnode_handle*)$arg1))")
  public static Ptr<iommu_ops> iommu_ops_from_fwnode(Ptr<fwnode_handle> fwnode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_domain> iommu_paging_domain_alloc_flags(Ptr<device> dev,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_pc_get_set_reg(Ptr<amd_iommu> iommu, char bank, char cntr, char fxn,
      Ptr<java.lang. @Unsigned Long> value, boolean is_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_pgsize(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long size,
      Ptr<java.lang. @Unsigned Long> count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_pmu_add(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_pmu_assign_event(Ptr<iommu_pmu> iommu_pmu, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_del(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_disable(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_enable(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_pmu_event_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_event_update(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn iommu_pmu_irq_handler(int irq,
      Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_register(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_start(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_stop(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_pmu_unregister(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_poll_events(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_poll_ga_log(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_print_event(Ptr<amd_iommu> iommu, Ptr<?> __evt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_probe_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_put_dma_cookie(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_put_msi_cookie(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_put_pages_list(Ptr<iommu_pages_list> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_put_resv_regions(Ptr<device> dev, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int iommu_read_l2(Ptr<amd_iommu> iommu, char address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_replace_device_pasid(Ptr<iommu_domain> domain, Ptr<device> dev,
      @Unsigned @OriginalName("ioasid_t") int pasid, Ptr<iommu_attach_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_replace_group_handle(Ptr<iommu_group> group, Ptr<iommu_domain> new_domain,
      Ptr<iommu_attach_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_report_device_fault(Ptr<device> dev, Ptr<iopf_fault> evt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short iommu_requests_is_visible(
      Ptr<kobject> kobj, Ptr<attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_resume() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_set_def_domain_type(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_set_default_passthrough(boolean cmd_line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_set_default_translated(boolean cmd_line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_set_device_table(Ptr<amd_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_set_dma_strict() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_set_fault_handler(Ptr<iommu_domain> domain,
      @OriginalName("iommu_fault_handler_t") Ptr<?> handler, Ptr<?> token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_set_irq_remapping(Ptr<intel_iommu> iommu, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_set_pgtable_quirks(Ptr<iommu_domain> domain, @Unsigned long quirk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_set_root_entry(Ptr<intel_iommu> iommu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_setup(String p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_setup_default_domain(Ptr<iommu_group> group, int target_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_setup_dma_ops(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_shutdown_noop() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_subsys_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_suspend() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<iommu_sva> iommu_sva_bind_device(Ptr<device> dev, Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_sva_domain_free(Ptr<iommu_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int iommu_sva_get_pasid(Ptr<iommu_sva> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_sva_handle_iopf(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_sva_iopf_handler(Ptr<iopf_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_sva_set_dev_pasid(Ptr<iommu_domain> domain, Ptr<device> dev,
      @Unsigned @OriginalName("ioasid_t") int pasid, Ptr<iommu_domain> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void iommu_sva_unbind_device(Ptr<iommu_sva> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_sync_map(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_unmap(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_unmap_fast(Ptr<iommu_domain> domain, @Unsigned long iova,
      @Unsigned long size, Ptr<iommu_iotlb_gather> iotlb_gather) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("phys_addr_t") long iommu_v1_iova_to_phys(
      Ptr<io_pgtable_ops> ops, @Unsigned long iova) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_v1_map_pages(Ptr<io_pgtable_ops> ops, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long pgsize,
      @Unsigned long pgcount, int prot, @Unsigned @OriginalName("gfp_t") int gfp,
      Ptr<java.lang. @Unsigned Long> mapped) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_v1_read_and_clear_dirty(Ptr<io_pgtable_ops> ops, @Unsigned long iova,
      @Unsigned long size, @Unsigned long flags, Ptr<iommu_dirty_bitmap> dirty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_v1_unmap_pages(Ptr<io_pgtable_ops> ops, @Unsigned long iova,
      @Unsigned long pgsize, @Unsigned long pgcount, Ptr<iommu_iotlb_gather> gather) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("phys_addr_t") long iommu_v2_iova_to_phys(
      Ptr<io_pgtable_ops> ops, @Unsigned long iova) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int iommu_v2_map_pages(Ptr<io_pgtable_ops> ops, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long pgsize,
      @Unsigned long pgcount, int prot, @Unsigned @OriginalName("gfp_t") int gfp,
      Ptr<java.lang. @Unsigned Long> mapped) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long iommu_v2_unmap_pages(Ptr<io_pgtable_ops> ops, @Unsigned long iova,
      @Unsigned long pgsize, @Unsigned long pgcount, Ptr<iommu_iotlb_gather> gather) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_mm_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_mm_data extends Struct {
    public @Unsigned int pasid;

    public list_head sva_domains;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_hw_info_type"
  )
  public enum iommu_hw_info_type implements Enum<iommu_hw_info_type>, TypedEnum<iommu_hw_info_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_HW_INFO_TYPE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_HW_INFO_TYPE_NONE"
    )
    IOMMU_HW_INFO_TYPE_NONE,

    /**
     * {@code IOMMU_HW_INFO_TYPE_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_HW_INFO_TYPE_DEFAULT"
    )
    IOMMU_HW_INFO_TYPE_DEFAULT,

    /**
     * {@code IOMMU_HW_INFO_TYPE_INTEL_VTD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_HW_INFO_TYPE_INTEL_VTD"
    )
    IOMMU_HW_INFO_TYPE_INTEL_VTD,

    /**
     * {@code IOMMU_HW_INFO_TYPE_ARM_SMMUV3 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_HW_INFO_TYPE_ARM_SMMUV3"
    )
    IOMMU_HW_INFO_TYPE_ARM_SMMUV3,

    /**
     * {@code IOMMU_HW_INFO_TYPE_TEGRA241_CMDQV = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IOMMU_HW_INFO_TYPE_TEGRA241_CMDQV"
    )
    IOMMU_HW_INFO_TYPE_TEGRA241_CMDQV
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_viommu_type"
  )
  public enum iommu_viommu_type implements Enum<iommu_viommu_type>, TypedEnum<iommu_viommu_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_VIOMMU_TYPE_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_VIOMMU_TYPE_DEFAULT"
    )
    IOMMU_VIOMMU_TYPE_DEFAULT,

    /**
     * {@code IOMMU_VIOMMU_TYPE_ARM_SMMUV3 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_VIOMMU_TYPE_ARM_SMMUV3"
    )
    IOMMU_VIOMMU_TYPE_ARM_SMMUV3,

    /**
     * {@code IOMMU_VIOMMU_TYPE_TEGRA241_CMDQV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_VIOMMU_TYPE_TEGRA241_CMDQV"
    )
    IOMMU_VIOMMU_TYPE_TEGRA241_CMDQV
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_fault_page_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_fault_page_request extends Struct {
    public @Unsigned int flags;

    public @Unsigned int pasid;

    public @Unsigned int grpid;

    public @Unsigned int perm;

    public @Unsigned long addr;

    public @Unsigned long @Size(2) [] private_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_fault"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_fault extends Struct {
    public @Unsigned int type;

    public iommu_fault_page_request prm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_page_response"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_page_response extends Struct {
    public @Unsigned int pasid;

    public @Unsigned int grpid;

    public @Unsigned int code;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_attach_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_attach_handle extends Struct {
    public Ptr<iommu_domain> domain;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_fault_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_fault_param extends Struct {
    public mutex lock;

    public @OriginalName("refcount_t") refcount_struct users;

    public callback_head rcu;

    public Ptr<device> dev;

    public Ptr<iopf_queue> queue;

    public list_head queue_list;

    public list_head partial;

    public list_head faults;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_domain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_domain extends Struct {
    public @Unsigned int type;

    public iommu_domain_cookie_type cookie_type;

    public Ptr<iommu_domain_ops> ops;

    public Ptr<iommu_dirty_ops> dirty_ops;

    public Ptr<iommu_ops> owner;

    public @Unsigned long pgsize_bitmap;

    public iommu_domain_geometry geometry;

    public Ptr<?> iopf_handler;

    @InlineUnion(6912)
    public Ptr<iommu_dma_cookie> iova_cookie;

    @InlineUnion(6912)
    public Ptr<iommu_dma_msi_cookie> msi_cookie;

    @InlineUnion(6912)
    public Ptr<iommufd_hw_pagetable> iommufd_hwpt;

    @InlineUnion(6912)
    public anon_member_of_anon_member_of_iommu_domain anon8$3;

    @InlineUnion(6912)
    public anon_member_of_anon_member_of_iommu_domain anon8$4;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_domain_geometry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_domain_geometry extends Struct {
    public @Unsigned @OriginalName("dma_addr_t") long aperture_start;

    public @Unsigned @OriginalName("dma_addr_t") long aperture_end;

    public boolean force_aperture;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_domain_cookie_type"
  )
  public enum iommu_domain_cookie_type implements Enum<iommu_domain_cookie_type>, TypedEnum<iommu_domain_cookie_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_COOKIE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_COOKIE_NONE"
    )
    IOMMU_COOKIE_NONE,

    /**
     * {@code IOMMU_COOKIE_DMA_IOVA = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_COOKIE_DMA_IOVA"
    )
    IOMMU_COOKIE_DMA_IOVA,

    /**
     * {@code IOMMU_COOKIE_DMA_MSI = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_COOKIE_DMA_MSI"
    )
    IOMMU_COOKIE_DMA_MSI,

    /**
     * {@code IOMMU_COOKIE_FAULT_HANDLER = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IOMMU_COOKIE_FAULT_HANDLER"
    )
    IOMMU_COOKIE_FAULT_HANDLER,

    /**
     * {@code IOMMU_COOKIE_SVA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IOMMU_COOKIE_SVA"
    )
    IOMMU_COOKIE_SVA,

    /**
     * {@code IOMMU_COOKIE_IOMMUFD = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IOMMU_COOKIE_IOMMUFD"
    )
    IOMMU_COOKIE_IOMMUFD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_domain_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_domain_ops extends Struct {
    public Ptr<?> attach_dev;

    public Ptr<?> set_dev_pasid;

    public Ptr<?> map_pages;

    public Ptr<?> unmap_pages;

    public Ptr<?> flush_iotlb_all;

    public Ptr<?> iotlb_sync_map;

    public Ptr<?> iotlb_sync;

    public Ptr<?> cache_invalidate_user;

    public Ptr<?> iova_to_phys;

    public Ptr<?> enforce_cache_coherency;

    public Ptr<?> set_pgtable_quirks;

    public Ptr<?> free;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_dirty_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_dirty_ops extends Struct {
    public Ptr<?> set_dirty_tracking;

    public Ptr<?> read_and_clear_dirty;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_ops extends Struct {
    public Ptr<?> capable;

    public Ptr<?> hw_info;

    public Ptr<?> domain_alloc_identity;

    public Ptr<?> domain_alloc_paging_flags;

    public Ptr<?> domain_alloc_paging;

    public Ptr<?> domain_alloc_sva;

    public Ptr<?> domain_alloc_nested;

    public Ptr<?> probe_device;

    public Ptr<?> release_device;

    public Ptr<?> probe_finalize;

    public Ptr<?> device_group;

    public Ptr<?> get_resv_regions;

    public Ptr<?> of_xlate;

    public Ptr<?> is_attach_deferred;

    public Ptr<?> page_response;

    public Ptr<?> def_domain_type;

    public Ptr<?> get_viommu_size;

    public Ptr<?> viommu_init;

    public Ptr<iommu_domain_ops> default_domain_ops;

    public Ptr<module> owner;

    public Ptr<iommu_domain> identity_domain;

    public Ptr<iommu_domain> blocked_domain;

    public Ptr<iommu_domain> release_domain;

    public Ptr<iommu_domain> default_domain;

    public char user_pasid_table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_cap"
  )
  public enum iommu_cap implements Enum<iommu_cap>, TypedEnum<iommu_cap, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_CAP_CACHE_COHERENCY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_CAP_CACHE_COHERENCY"
    )
    IOMMU_CAP_CACHE_COHERENCY,

    /**
     * {@code IOMMU_CAP_NOEXEC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_CAP_NOEXEC"
    )
    IOMMU_CAP_NOEXEC,

    /**
     * {@code IOMMU_CAP_PRE_BOOT_PROTECTION = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_CAP_PRE_BOOT_PROTECTION"
    )
    IOMMU_CAP_PRE_BOOT_PROTECTION,

    /**
     * {@code IOMMU_CAP_ENFORCE_CACHE_COHERENCY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IOMMU_CAP_ENFORCE_CACHE_COHERENCY"
    )
    IOMMU_CAP_ENFORCE_CACHE_COHERENCY,

    /**
     * {@code IOMMU_CAP_DEFERRED_FLUSH = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IOMMU_CAP_DEFERRED_FLUSH"
    )
    IOMMU_CAP_DEFERRED_FLUSH,

    /**
     * {@code IOMMU_CAP_DIRTY_TRACKING = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IOMMU_CAP_DIRTY_TRACKING"
    )
    IOMMU_CAP_DIRTY_TRACKING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_pages_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_pages_list extends Struct {
    public list_head pages;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_iotlb_gather"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_iotlb_gather extends Struct {
    public @Unsigned long start;

    public @Unsigned long end;

    public @Unsigned long pgsize;

    public iommu_pages_list freelist;

    public boolean queued;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_dirty_bitmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_dirty_bitmap extends Struct {
    public Ptr<iova_bitmap> bitmap;

    public Ptr<iommu_iotlb_gather> gather;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_user_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_user_data extends Struct {
    public @Unsigned int type;

    public Ptr<?> uptr;

    public @Unsigned long len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_user_data_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_user_data_array extends Struct {
    public @Unsigned int type;

    public Ptr<?> uptr;

    public @Unsigned long entry_len;

    public @Unsigned int entry_num;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_device extends Struct {
    public list_head list;

    public Ptr<iommu_ops> ops;

    public Ptr<fwnode_handle> fwnode;

    public Ptr<device> dev;

    public Ptr<iommu_group> singleton_group;

    public @Unsigned int max_pasids;

    public boolean ready;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_fwspec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_fwspec extends Struct {
    public Ptr<fwnode_handle> iommu_fwnode;

    public @Unsigned int flags;

    public @Unsigned int num_ids;

    public @Unsigned int @Size(0) [] ids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_veventq_type"
  )
  public enum iommu_veventq_type implements Enum<iommu_veventq_type>, TypedEnum<iommu_veventq_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_VEVENTQ_TYPE_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_VEVENTQ_TYPE_DEFAULT"
    )
    IOMMU_VEVENTQ_TYPE_DEFAULT,

    /**
     * {@code IOMMU_VEVENTQ_TYPE_ARM_SMMUV3 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_VEVENTQ_TYPE_ARM_SMMUV3"
    )
    IOMMU_VEVENTQ_TYPE_ARM_SMMUV3,

    /**
     * {@code IOMMU_VEVENTQ_TYPE_TEGRA241_CMDQV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_VEVENTQ_TYPE_TEGRA241_CMDQV"
    )
    IOMMU_VEVENTQ_TYPE_TEGRA241_CMDQV
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_hw_queue_type"
  )
  public enum iommu_hw_queue_type implements Enum<iommu_hw_queue_type>, TypedEnum<iommu_hw_queue_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_HW_QUEUE_TYPE_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_HW_QUEUE_TYPE_DEFAULT"
    )
    IOMMU_HW_QUEUE_TYPE_DEFAULT,

    /**
     * {@code IOMMU_HW_QUEUE_TYPE_TEGRA241_CMDQV = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_HW_QUEUE_TYPE_TEGRA241_CMDQV"
    )
    IOMMU_HW_QUEUE_TYPE_TEGRA241_CMDQV
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_resv_type"
  )
  public enum iommu_resv_type implements Enum<iommu_resv_type>, TypedEnum<iommu_resv_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_RESV_DIRECT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_RESV_DIRECT"
    )
    IOMMU_RESV_DIRECT,

    /**
     * {@code IOMMU_RESV_DIRECT_RELAXABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_RESV_DIRECT_RELAXABLE"
    )
    IOMMU_RESV_DIRECT_RELAXABLE,

    /**
     * {@code IOMMU_RESV_RESERVED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_RESV_RESERVED"
    )
    IOMMU_RESV_RESERVED,

    /**
     * {@code IOMMU_RESV_MSI = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IOMMU_RESV_MSI"
    )
    IOMMU_RESV_MSI,

    /**
     * {@code IOMMU_RESV_SW_MSI = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IOMMU_RESV_SW_MSI"
    )
    IOMMU_RESV_SW_MSI
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_resv_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_resv_region extends Struct {
    public list_head list;

    public @Unsigned @OriginalName("phys_addr_t") long start;

    public @Unsigned long length;

    public int prot;

    public iommu_resv_type type;

    public Ptr<?> free;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_flush_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_flush_ops extends Struct {
    public Ptr<?> tlb_flush_all;

    public Ptr<?> tlb_flush_walk;

    public Ptr<?> tlb_add_page;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_dev_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_dev_data extends Struct {
    public mutex mutex;

    public @OriginalName("spinlock_t") spinlock dte_lock;

    public list_head list;

    public llist_node dev_data_list;

    public Ptr<protection_domain> domain;

    public gcr3_tbl_info gcr3_info;

    public Ptr<device> dev;

    public @Unsigned short devid;

    public @Unsigned int max_irqs;

    public @Unsigned int max_pasids;

    public @Unsigned int flags;

    public int ats_qdep;

    public char ats_enabled;

    public char pri_enabled;

    public char pasid_enabled;

    public char pri_tlp;

    public char ppr;

    public boolean use_vapic;

    public boolean defer_attach;

    public ratelimit_state rs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_cmd extends Struct {
    public @Unsigned int @Size(4) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_init_state"
  )
  public enum iommu_init_state implements Enum<iommu_init_state>, TypedEnum<iommu_init_state, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_START_STATE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_START_STATE"
    )
    IOMMU_START_STATE,

    /**
     * {@code IOMMU_IVRS_DETECTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_IVRS_DETECTED"
    )
    IOMMU_IVRS_DETECTED,

    /**
     * {@code IOMMU_ACPI_FINISHED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_ACPI_FINISHED"
    )
    IOMMU_ACPI_FINISHED,

    /**
     * {@code IOMMU_ENABLED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IOMMU_ENABLED"
    )
    IOMMU_ENABLED,

    /**
     * {@code IOMMU_PCI_INIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IOMMU_PCI_INIT"
    )
    IOMMU_PCI_INIT,

    /**
     * {@code IOMMU_INTERRUPTS_EN = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IOMMU_INTERRUPTS_EN"
    )
    IOMMU_INTERRUPTS_EN,

    /**
     * {@code IOMMU_INITIALIZED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IOMMU_INITIALIZED"
    )
    IOMMU_INITIALIZED,

    /**
     * {@code IOMMU_NOT_FOUND = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IOMMU_NOT_FOUND"
    )
    IOMMU_NOT_FOUND,

    /**
     * {@code IOMMU_INIT_ERROR = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IOMMU_INIT_ERROR"
    )
    IOMMU_INIT_ERROR,

    /**
     * {@code IOMMU_CMDLINE_DISABLED = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IOMMU_CMDLINE_DISABLED"
    )
    IOMMU_CMDLINE_DISABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_fault_type"
  )
  public enum iommu_fault_type implements Enum<iommu_fault_type>, TypedEnum<iommu_fault_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_FAULT_PAGE_REQ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_FAULT_PAGE_REQ"
    )
    IOMMU_FAULT_PAGE_REQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_page_response_code"
  )
  public enum iommu_page_response_code implements Enum<iommu_page_response_code>, TypedEnum<iommu_page_response_code, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_PAGE_RESP_SUCCESS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_PAGE_RESP_SUCCESS"
    )
    IOMMU_PAGE_RESP_SUCCESS,

    /**
     * {@code IOMMU_PAGE_RESP_INVALID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_PAGE_RESP_INVALID"
    )
    IOMMU_PAGE_RESP_INVALID,

    /**
     * {@code IOMMU_PAGE_RESP_FAILURE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_PAGE_RESP_FAILURE"
    )
    IOMMU_PAGE_RESP_FAILURE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_hwpt_vtd_s1"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_hwpt_vtd_s1 extends Struct {
    public @Unsigned long flags;

    public @Unsigned long pgtbl_addr;

    public @Unsigned int addr_width;

    public @Unsigned int __reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_hw_info_vtd_flags"
  )
  public enum iommu_hw_info_vtd_flags implements Enum<iommu_hw_info_vtd_flags>, TypedEnum<iommu_hw_info_vtd_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_HW_INFO_VTD_ERRATA_772415_SPR17 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_HW_INFO_VTD_ERRATA_772415_SPR17"
    )
    IOMMU_HW_INFO_VTD_ERRATA_772415_SPR17
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_hw_info_vtd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_hw_info_vtd extends Struct {
    public @Unsigned int flags;

    public @Unsigned int __reserved;

    public @Unsigned long cap_reg;

    public @Unsigned long ecap_reg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_flush"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_flush extends Struct {
    public Ptr<?> flush_context;

    public Ptr<?> flush_iotlb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_domain_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_domain_info extends Struct {
    public Ptr<intel_iommu> iommu;

    public @Unsigned int refcnt;

    public @Unsigned short did;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_pmu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_pmu extends Struct {
    public Ptr<intel_iommu> iommu;

    public @Unsigned int num_cntr;

    public @Unsigned int num_eg;

    public @Unsigned int cntr_width;

    public @Unsigned int cntr_stride;

    public @Unsigned int filter;

    public Ptr<?> base;

    public Ptr<?> cfg_reg;

    public Ptr<?> cntr_reg;

    public Ptr<?> overflow;

    public Ptr<java.lang. @Unsigned Long> evcap;

    public Ptr<Ptr<java.lang. @Unsigned Integer>> cntr_evcap;

    public pmu pmu;

    public @Unsigned long @Size(1) [] used_mask;

    public Ptr<perf_event> @Size(64) [] event_list;

    public char @Size(16) [] irq_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_hwpt_vtd_s1_flags"
  )
  public enum iommu_hwpt_vtd_s1_flags implements Enum<iommu_hwpt_vtd_s1_flags>, TypedEnum<iommu_hwpt_vtd_s1_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_VTD_S1_SRE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_VTD_S1_SRE"
    )
    IOMMU_VTD_S1_SRE,

    /**
     * {@code IOMMU_VTD_S1_EAFE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_VTD_S1_EAFE"
    )
    IOMMU_VTD_S1_EAFE,

    /**
     * {@code IOMMU_VTD_S1_WPE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IOMMU_VTD_S1_WPE"
    )
    IOMMU_VTD_S1_WPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_hwpt_data_type"
  )
  public enum iommu_hwpt_data_type implements Enum<iommu_hwpt_data_type>, TypedEnum<iommu_hwpt_data_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_HWPT_DATA_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_HWPT_DATA_NONE"
    )
    IOMMU_HWPT_DATA_NONE,

    /**
     * {@code IOMMU_HWPT_DATA_VTD_S1 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_HWPT_DATA_VTD_S1"
    )
    IOMMU_HWPT_DATA_VTD_S1,

    /**
     * {@code IOMMU_HWPT_DATA_ARM_SMMUV3 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOMMU_HWPT_DATA_ARM_SMMUV3"
    )
    IOMMU_HWPT_DATA_ARM_SMMUV3
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_hwpt_invalidate_data_type"
  )
  public enum iommu_hwpt_invalidate_data_type implements Enum<iommu_hwpt_invalidate_data_type>, TypedEnum<iommu_hwpt_invalidate_data_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_HWPT_INVALIDATE_DATA_VTD_S1 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_HWPT_INVALIDATE_DATA_VTD_S1"
    )
    IOMMU_HWPT_INVALIDATE_DATA_VTD_S1,

    /**
     * {@code IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3"
    )
    IOMMU_VIOMMU_INVALIDATE_DATA_ARM_SMMUV3
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_hwpt_vtd_s1_invalidate_flags"
  )
  public enum iommu_hwpt_vtd_s1_invalidate_flags implements Enum<iommu_hwpt_vtd_s1_invalidate_flags>, TypedEnum<iommu_hwpt_vtd_s1_invalidate_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_VTD_INV_FLAGS_LEAF = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_VTD_INV_FLAGS_LEAF"
    )
    IOMMU_VTD_INV_FLAGS_LEAF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_hwpt_vtd_s1_invalidate"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_hwpt_vtd_s1_invalidate extends Struct {
    public @Unsigned long addr;

    public @Unsigned long npages;

    public @Unsigned int flags;

    public @Unsigned int __reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_group extends Struct {
    public kobject kobj;

    public Ptr<kobject> devices_kobj;

    public list_head devices;

    public xarray pasid_array;

    public mutex mutex;

    public Ptr<?> iommu_data;

    public Ptr<?> iommu_data_release;

    public String name;

    public int id;

    public Ptr<iommu_domain> default_domain;

    public Ptr<iommu_domain> blocking_domain;

    public Ptr<iommu_domain> domain;

    public list_head entry;

    public @Unsigned int owner_cnt;

    public Ptr<?> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_group_attribute"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_group_attribute extends Struct {
    public attribute attr;

    public Ptr<?> show;

    public Ptr<?> store;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_dma_cookie"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_dma_cookie extends Struct {
    public iova_domain iovad;

    public list_head msi_page_list;

    @InlineUnion(44008)
    public Ptr<iova_fq> single_fq;

    @InlineUnion(44008)
    public Ptr<iova_fq> percpu_fq;

    public atomic64_t fq_flush_start_cnt;

    public atomic64_t fq_flush_finish_cnt;

    public timer_list fq_timer;

    public atomic_t fq_timer_on;

    public Ptr<iommu_domain> fq_domain;

    public iommu_dma_options options;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_dma_msi_cookie"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_dma_msi_cookie extends Struct {
    public @Unsigned @OriginalName("dma_addr_t") long msi_iova;

    public list_head msi_page_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_dma_msi_page"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_dma_msi_page extends Struct {
    public list_head list;

    public @Unsigned @OriginalName("dma_addr_t") long iova;

    public @Unsigned @OriginalName("phys_addr_t") long phys;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum iommu_dma_queue_type"
  )
  public enum iommu_dma_queue_type implements Enum<iommu_dma_queue_type>, TypedEnum<iommu_dma_queue_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IOMMU_DMA_OPTS_PER_CPU_QUEUE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOMMU_DMA_OPTS_PER_CPU_QUEUE"
    )
    IOMMU_DMA_OPTS_PER_CPU_QUEUE,

    /**
     * {@code IOMMU_DMA_OPTS_SINGLE_QUEUE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOMMU_DMA_OPTS_SINGLE_QUEUE"
    )
    IOMMU_DMA_OPTS_SINGLE_QUEUE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_dma_options"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_dma_options extends Struct {
    public iommu_dma_queue_type qt;

    public @Unsigned long fq_size;

    public @Unsigned int fq_timeout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct iommu_sva"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class iommu_sva extends Struct {
    public iommu_attach_handle handle;

    public Ptr<device> dev;

    public @OriginalName("refcount_t") refcount_struct users;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ioptdesc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ioptdesc extends Struct {
    public @Unsigned long __page_flags;

    public list_head iopt_freelist_elm;

    public @Unsigned long __page_mapping;

    public @Unsigned long __index;

    public Ptr<?> _private;

    public @Unsigned int __page_type;

    public atomic_t __page_refcount;

    public @Unsigned long memcg_data;
  }
}
