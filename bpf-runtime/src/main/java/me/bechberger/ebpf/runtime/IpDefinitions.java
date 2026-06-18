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
 * Generated class for BPF runtime types that start with ip
 */
@java.lang.SuppressWarnings("unused")
public final class IpDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ____ip_mc_inc_group(Ptr<in_device> in_dev,
      @Unsigned @OriginalName("__be32") int addr, @Unsigned int mode,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ip_append_data($arg1, $arg2, $arg3, $arg4, $arg5, (int (*)(void*, u8*, int, int, int, struct sk_buff*))$arg6, $arg7, $arg8, $arg9, $arg10)")
  public static int __ip_append_data(Ptr<sock> sk, Ptr<flowi4> fl4, Ptr<sk_buff_head> queue,
      Ptr<inet_cork> cork, Ptr<page_frag> pfrag, Ptr<?> getfrag, Ptr<?> from, int length,
      int transhdrlen, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<net_device> __ip_dev_find(Ptr<net> net,
      @Unsigned @OriginalName("__be32") int addr, boolean devref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ip_do_redirect(Ptr<rtable> rt, Ptr<sk_buff> skb, Ptr<flowi4> fl4,
      boolean kill_route) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ip_finish_output(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ip_local_out(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> __ip_make_skb(Ptr<sock> sk, Ptr<flowi4> fl4, Ptr<sk_buff_head> queue,
      Ptr<inet_cork> cork) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ip_mc_dec_group(Ptr<in_device> in_dev,
      @Unsigned @OriginalName("__be32") int addr, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ip_mc_inc_group(Ptr<in_device> in_dev,
      @Unsigned @OriginalName("__be32") int addr, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ip_mc_join_group(Ptr<sock> sk, Ptr<ip_mreqn> imr, @Unsigned int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ip_options_compile(Ptr<net> net, Ptr<ip_options> opt, Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ip_options_echo($arg1, $arg2, $arg3, (const struct ip_options*)$arg4)")
  public static int __ip_options_echo(Ptr<net> net, Ptr<ip_options> dopt, Ptr<sk_buff> skb,
      Ptr<ip_options> sopt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ip_queue_xmit(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<flowi> fl, char tos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ip_rt_update_pmtu(Ptr<rtable> rt, Ptr<flowi4> fl4, @Unsigned int mtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ip_select_ident(Ptr<net> net, Ptr<iphdr> iph, int segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ip_sock_set_tos(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_addr_string($arg1, $arg2, (const void*)$arg3, $arg4, (const u8*)$arg5)")
  public static String ip_addr_string(String buf, String end, Ptr<?> ptr, printf_spec spec,
      String fmt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_append_data($arg1, $arg2, (int (*)(void*, u8*, int, int, int, struct sk_buff*))$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static int ip_append_data(Ptr<sock> sk, Ptr<flowi4> fl4, Ptr<?> getfrag, Ptr<?> from,
      int length, int transhdrlen, Ptr<ipcm_cookie> ipc, Ptr<Ptr<rtable>> rtp,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_build_and_send_pkt($arg1, (const struct sock*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int ip_build_and_send_pkt(Ptr<sk_buff> skb, Ptr<sock> sk,
      @Unsigned @OriginalName("__be32") int saddr, @Unsigned @OriginalName("__be32") int daddr,
      Ptr<ip_options_rcu> opt, char tos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ip_call_ra_chain(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> ip_check_defrag(Ptr<net> net, Ptr<sk_buff> skb, @Unsigned int user) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_check_mc_rcu(Ptr<in_device> in_dev,
      @Unsigned @OriginalName("__be32") int mc_addr, @Unsigned @OriginalName("__be32") int src_addr,
      char proto) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_cmsg_recv_offset(Ptr<msghdr> msg, Ptr<sock> sk, Ptr<sk_buff> skb, int tlen,
      int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_cmsg_send(Ptr<sock> sk, Ptr<msghdr> msg, Ptr<ipcm_cookie> ipc,
      boolean allow_ipv6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_compute_csum((const void*)$arg1, $arg2)")
  public static @Unsigned @OriginalName("__sum16") short ip_compute_csum(Ptr<?> buff, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_copy_metadata(Ptr<sk_buff> to, Ptr<sk_buff> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_defrag(Ptr<net> net, Ptr<sk_buff> skb, @Unsigned int user) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_do_fragment($arg1, $arg2, $arg3, (int (*)(struct net*, struct sock*, struct sk_buff*))$arg4)")
  public static int ip_do_fragment(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<?> output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_do_redirect(Ptr<dst_entry> dst, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_encap(Ptr<net> net, Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int saddr, @Unsigned @OriginalName("__be32") int daddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_error(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_expire(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_fib_check_default(@Unsigned @OriginalName("__be32") int gw,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_fib_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dst_metrics> ip_fib_metrics_init(Ptr<nlattr> fc_mx, int fc_mx_len,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_fib_net_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_finish_output(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_finish_output2(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_flush_pending_frames(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_forward(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_forward_finish(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_forward_options(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_frag_init(Ptr<sk_buff> skb, @Unsigned int hlen, @Unsigned int ll_rs,
      @Unsigned int mtu, boolean DF, Ptr<ip_frag_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> ip_frag_next(Ptr<sk_buff> skb, Ptr<ip_frag_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_frag_queue(Ptr<ipq> qp, Ptr<sk_buff> skb, Ptr<java.lang.Integer> refs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_frag_reasm(Ptr<ipq> qp, Ptr<sk_buff> skb, Ptr<sk_buff> prev_tail,
      Ptr<net_device> dev, Ptr<java.lang.Integer> refs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_fraglist_init(Ptr<sk_buff> skb, Ptr<iphdr> iph, @Unsigned int hlen,
      Ptr<ip_fraglist_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_fraglist_prepare(Ptr<sk_buff> skb, Ptr<ip_fraglist_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_fragment($arg1, $arg2, $arg3, $arg4, (int (*)(struct net*, struct sock*, struct sk_buff*))$arg5)")
  public static int ip_fragment(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb, @Unsigned int mtu,
      Ptr<?> output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_generic_getfrag(Ptr<?> from, String to, int offset, int len, int odd,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_get_mcast_msfilter(Ptr<sock> sk, sockptr_t optval, sockptr_t optlen,
      int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_getsockopt(Ptr<sock> sk, int level, int optname, String optval,
      Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_handle_martian_source(Ptr<net_device> dev, Ptr<in_device> in_dev,
      Ptr<sk_buff> skb, @Unsigned @OriginalName("__be32") int daddr,
      @Unsigned @OriginalName("__be32") int saddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_icmp_error(Ptr<sock> sk, Ptr<sk_buff> skb, int err,
      @Unsigned @OriginalName("__be16") short port, @Unsigned int info,
      Ptr<java.lang.Character> payload) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_icmp_error_rfc4884((const struct sk_buff*)$arg1, $arg2, $arg3, $arg4)")
  public static void ip_icmp_error_rfc4884(Ptr<sk_buff> skb, Ptr<sock_ee_data_rfc4884> out,
      int thlen, int off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_ipgre_mc_map($arg1, (const u8*)$arg2, $arg3)")
  public static void ip_ipgre_mc_map(@Unsigned @OriginalName("__be32") int naddr, String broadcast,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_list_rcv(Ptr<list_head> head, Ptr<packet_type> pt,
      Ptr<net_device> orig_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_local_deliver(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_local_deliver_finish(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_local_error(Ptr<sock> sk, int err,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be16") short port,
      @Unsigned int info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_local_out(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_ma_put(Ptr<ip_mc_list> im) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_make_skb($arg1, $arg2, (int (*)(void*, u8*, int, int, int, struct sk_buff*))$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9, $arg10)")
  public static Ptr<sk_buff> ip_make_skb(Ptr<sock> sk, Ptr<flowi4> fl4, Ptr<?> getfrag, Ptr<?> from,
      int length, int transhdrlen, Ptr<ipcm_cookie> ipc, Ptr<Ptr<rtable>> rtp, Ptr<inet_cork> cork,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_add_src(Ptr<in_device> in_dev,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> pmca, int sfmode, int sfcount,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> psfsrc, int delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_check_igmp(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_clear_src(Ptr<ip_mc_list> pmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_del1_src(Ptr<ip_mc_list> pmc, int sfmode,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> psfsrc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_del_src(Ptr<in_device> in_dev,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> pmca, int sfmode, int sfcount,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> psfsrc, int delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_destroy_dev(Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_down(Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_drop_socket(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<in_device> ip_mc_find_dev(Ptr<net> net, Ptr<ip_mreqn> imr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_finish_output(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_gsfget(Ptr<sock> sk, Ptr<group_filter> gsf, sockptr_t optval,
      @Unsigned long ss_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_inc_group(Ptr<in_device> in_dev,
      @Unsigned @OriginalName("__be32") int addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_init_dev(Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_join_group(Ptr<sock> sk, Ptr<ip_mreqn> imr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_join_group_ssm(Ptr<sock> sk, Ptr<ip_mreqn> imr, @Unsigned int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_leave_group(Ptr<sock> sk, Ptr<ip_mreqn> imr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_leave_src(Ptr<sock> sk, Ptr<ip_mc_socklist> iml, Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_msfget(Ptr<sock> sk, Ptr<ip_msfilter> msf, sockptr_t optval,
      sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_msfilter(Ptr<sock> sk, Ptr<ip_msfilter> msf, int ifindex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_output(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_remap(Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_mc_sf_allow((const struct sock*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int ip_mc_sf_allow(Ptr<sock> sk, @Unsigned @OriginalName("__be32") int loc_addr,
      @Unsigned @OriginalName("__be32") int rmt_addr, int dif, int sdif) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mc_source(int add, int omode, Ptr<sock> sk, Ptr<ip_mreq_source> mreqs,
      int ifindex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_unmap(Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mc_up(Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__sum16") short ip_mc_validate_checksum(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static skb_drop_reason ip_mc_validate_source(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be32") int saddr,
      @OriginalName("dscp_t") char dscp, Ptr<net_device> dev, Ptr<in_device> in_dev,
      Ptr<java.lang. @Unsigned Integer> itag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mcast_join_leave(Ptr<sock> sk, int optname, sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_metrics_convert(Ptr<nlattr> fc_mx, int fc_mx_len,
      Ptr<java.lang. @Unsigned Integer> metrics, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_misc_proc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_mr_forward(Ptr<net> net, Ptr<mr_table> mrt, Ptr<net_device> dev,
      Ptr<sk_buff> skb, Ptr<mfc_cache> c, int local) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mr_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mr_input(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mr_output(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mroute_getsockopt(Ptr<sock> sk, int optname, sockptr_t optval,
      sockptr_t optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_mroute_setsockopt(Ptr<sock> sk, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ip_mtu_from_fib_result(Ptr<fib_result> res,
      @Unsigned @OriginalName("__be32") int daddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_multipath_l3_keys((const struct sk_buff*)$arg1, $arg2)")
  public static void ip_multipath_l3_keys(Ptr<sk_buff> skb, Ptr<flow_keys> hash_keys) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_options_build(Ptr<sk_buff> skb, Ptr<ip_options> opt,
      @Unsigned @OriginalName("__be32") int daddr, Ptr<rtable> rt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_options_compile(Ptr<net> net, Ptr<ip_options> opt, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_options_fragment(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_options_get(Ptr<net> net, Ptr<Ptr<ip_options_rcu>> optp, sockptr_t data,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_options_rcv_srr(Ptr<sk_buff> skb, Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_options_undo(Ptr<ip_options> opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_output(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_proc_exit_net(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_proc_init_net(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_protocol_deliver_rcu(Ptr<net> net, Ptr<sk_buff> skb, int protocol) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_push_pending_frames(Ptr<sock> sk, Ptr<flowi4> fl4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_queue_xmit(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<flowi> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_ra_control($arg1, $arg2, (void (*)(struct sock*))$arg3)")
  public static int ip_ra_control(Ptr<sock> sk, char on, Ptr<?> destructor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_ra_destroy_rcu(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_rcv(Ptr<sk_buff> skb, Ptr<net_device> dev, Ptr<packet_type> pt,
      Ptr<net_device> orig_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sk_buff> ip_rcv_core(Ptr<sk_buff> skb, Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_rcv_finish(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_rcv_finish_core($arg1, $arg2, $arg3, (const struct sk_buff*)$arg4)")
  public static int ip_rcv_finish_core(Ptr<net> net, Ptr<sk_buff> skb, Ptr<net_device> dev,
      Ptr<sk_buff> hint) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ip_rcv_options(Ptr<sk_buff> skb, Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_recv_error(Ptr<sock> sk, Ptr<msghdr> msg, int len,
      Ptr<java.lang.Integer> addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_reply_glue_bits(Ptr<?> dptr, String to, int offset, int len, int odd,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static skb_drop_reason ip_route_input_noref(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be32") int saddr,
      @OriginalName("dscp_t") char dscp, Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static skb_drop_reason ip_route_input_rcu(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be32") int saddr,
      @OriginalName("dscp_t") char dscp, Ptr<net_device> dev, Ptr<fib_result> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static skb_drop_reason ip_route_input_slow(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be32") int saddr,
      @OriginalName("dscp_t") char dscp, Ptr<net_device> dev, Ptr<fib_result> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_route_me_harder(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb,
      @Unsigned int addr_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_route_output_flow($arg1, $arg2, (const struct sock*)$arg3)")
  public static Ptr<rtable> ip_route_output_flow(Ptr<net> net, Ptr<flowi4> flp4, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_route_output_key_hash($arg1, $arg2, (const struct sk_buff*)$arg3)")
  public static Ptr<rtable> ip_route_output_key_hash(Ptr<net> net, Ptr<flowi4> fl4,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_route_output_key_hash_rcu($arg1, $arg2, $arg3, (const struct sk_buff*)$arg4)")
  public static Ptr<rtable> ip_route_output_key_hash_rcu(Ptr<net> net, Ptr<flowi4> fl4,
      Ptr<fib_result> res, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_route_use_hint($arg1, $arg2, $arg3, $arg4, $arg5, (const struct sk_buff*)$arg6)")
  public static skb_drop_reason ip_route_use_hint(Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned @OriginalName("__be32") int saddr,
      @OriginalName("dscp_t") char dscp, Ptr<net_device> dev, Ptr<sk_buff> hint) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_rt_bug(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_rt_do_proc_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_rt_do_proc_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_rt_get_source(Ptr<java.lang.Character> addr, Ptr<sk_buff> skb,
      Ptr<rtable> rt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_rt_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_rt_ioctl(Ptr<net> net, @Unsigned int cmd, Ptr<rtentry> rt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_rt_multicast_event(Ptr<in_device> in_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_rt_send_redirect(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_rt_update_pmtu(Ptr<dst_entry> dst, Ptr<sock> sk, Ptr<sk_buff> skb,
      @Unsigned int mtu, boolean confirm_neigh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_send_check(Ptr<iphdr> iph) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_send_skb(Ptr<net> net, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_send_unicast_reply($arg1, (const struct sock*)$arg2, $arg3, (const struct ip_options*)$arg4, $arg5, $arg6, (const struct ip_reply_arg*)$arg7, $arg8, $arg9, $arg10)")
  public static void ip_send_unicast_reply(Ptr<sock> sk, Ptr<sock> orig_sk, Ptr<sk_buff> skb,
      Ptr<ip_options> sopt, @Unsigned @OriginalName("__be32") int daddr,
      @Unsigned @OriginalName("__be32") int saddr, Ptr<ip_reply_arg> arg, @Unsigned int len,
      @Unsigned long transmit_time, @Unsigned int txhash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_setsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_setup_cork(Ptr<sock> sk, Ptr<inet_cork> cork, Ptr<ipcm_cookie> ipc,
      Ptr<Ptr<rtable>> rtp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_skb_dst_mtu($arg1, (const struct sk_buff*)$arg2)")
  public static @Unsigned int ip_skb_dst_mtu(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_sock_set_freebind(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_sock_set_mtu_discover(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_sock_set_pktinfo(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_sock_set_recverr(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_sock_set_tos(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_static_sysctl_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_sublist_rcv(Ptr<list_head> head, Ptr<net_device> dev, Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_sublist_rcv_finish(Ptr<list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_tun_build_state($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6)")
  public static int ip_tun_build_state(Ptr<net> net, Ptr<nlattr> attr, @Unsigned int family,
      Ptr<?> cfg, Ptr<Ptr<lwtunnel_state>> ts, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_tun_cmp_encap(Ptr<lwtunnel_state> a, Ptr<lwtunnel_state> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_tun_destroy_state(Ptr<lwtunnel_state> lwtstate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_tun_encap_nlsize(Ptr<lwtunnel_state> lwtstate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_tun_fill_encap_info(Ptr<sk_buff> skb, Ptr<lwtunnel_state> lwtstate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_tun_opts_nlsize(Ptr<ip_tunnel_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_tun_parse_opts(Ptr<nlattr> attr, Ptr<ip_tunnel_info> info,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ip_tun_parse_opts_geneve(Ptr<nlattr> attr, Ptr<ip_tunnel_info> info,
      int opts_len, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_tunnel_core_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_tunnel_info_opts_get($arg1, (const struct ip_tunnel_info*)$arg2)")
  public static void ip_tunnel_info_opts_get(Ptr<?> to, Ptr<ip_tunnel_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_tunnel_need_metadata() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ip_tunnel_netlink_encap_parms(Ptr<Ptr<nlattr>> data,
      Ptr<ip_tunnel_encap> encap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_tunnel_netlink_parms(Ptr<Ptr<nlattr>> data,
      Ptr<ip_tunnel_parm_kern> parms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_tunnel_parse_protocol((const struct sk_buff*)$arg1)")
  public static @Unsigned @OriginalName("__be16") short ip_tunnel_parse_protocol(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ip_tunnel_unneed_metadata() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ip_valid_fib_dump_req($arg1, (const struct nlmsghdr*)$arg2, $arg3, $arg4)")
  public static int ip_valid_fib_dump_req(Ptr<net> net, Ptr<nlmsghdr> nlh,
      Ptr<fib_dump_filter> filter, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_conntrack_stat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_conntrack_stat extends Struct {
    public @Unsigned int found;

    public @Unsigned int invalid;

    public @Unsigned int insert;

    public @Unsigned int insert_failed;

    public @Unsigned int clash_resolve;

    public @Unsigned int drop;

    public @Unsigned int early_drop;

    public @Unsigned int error;

    public @Unsigned int expect_new;

    public @Unsigned int expect_create;

    public @Unsigned int expect_delete;

    public @Unsigned int search_restart;

    public @Unsigned int chaintoolong;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ip_conntrack_dir"
  )
  public enum ip_conntrack_dir implements Enum<ip_conntrack_dir>, TypedEnum<ip_conntrack_dir, java.lang. @Unsigned Integer> {
    /**
     * {@code IP_CT_DIR_ORIGINAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IP_CT_DIR_ORIGINAL"
    )
    IP_CT_DIR_ORIGINAL,

    /**
     * {@code IP_CT_DIR_REPLY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IP_CT_DIR_REPLY"
    )
    IP_CT_DIR_REPLY,

    /**
     * {@code IP_CT_DIR_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IP_CT_DIR_MAX"
    )
    IP_CT_DIR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_ra_chain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_ra_chain extends Struct {
    public Ptr<ip_ra_chain> next;

    public Ptr<sock> sk;

    @InlineUnion(17565)
    public Ptr<?> destructor;

    @InlineUnion(17565)
    public Ptr<sock> saved_sk;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_options"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_options extends Struct {
    public @Unsigned @OriginalName("__be32") int faddr;

    public @Unsigned @OriginalName("__be32") int nexthop;

    public char optlen;

    public char srr;

    public char rr;

    public char ts;

    public char is_strictroute;

    public char srr_is_hit;

    public char is_changed;

    public char rr_needaddr;

    public char ts_needtime;

    public char ts_needaddr;

    public char router_alert;

    public char cipso;

    public char __pad2;

    public char @Size(0) [] __data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_options_rcu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_options_rcu extends Struct {
    public callback_head rcu;

    public ip_options opt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_parm_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_parm_kern extends Struct {
    public char @Size(16) [] name;

    public @Unsigned long @Size(1) [] i_flags;

    public @Unsigned long @Size(1) [] o_flags;

    public @Unsigned @OriginalName("__be32") int i_key;

    public @Unsigned @OriginalName("__be32") int o_key;

    public int link;

    public iphdr iph;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_auth_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_auth_hdr extends Struct {
    public char nexthdr;

    public char hdrlen;

    public @Unsigned @OriginalName("__be16") short reserved;

    public @Unsigned @OriginalName("__be32") int spi;

    public @Unsigned @OriginalName("__be32") int seq_no;

    public char @Size(0) [] auth_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ip_conntrack_info"
  )
  public enum ip_conntrack_info implements Enum<ip_conntrack_info>, TypedEnum<ip_conntrack_info, java.lang. @Unsigned Integer> {
    /**
     * {@code IP_CT_ESTABLISHED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IP_CT_ESTABLISHED"
    )
    IP_CT_ESTABLISHED,

    /**
     * {@code IP_CT_RELATED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IP_CT_RELATED"
    )
    IP_CT_RELATED,

    /**
     * {@code IP_CT_NEW = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IP_CT_NEW"
    )
    IP_CT_NEW,

    /**
     * {@code IP_CT_IS_REPLY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IP_CT_IS_REPLY"
    )
    IP_CT_IS_REPLY,

    /**
     * {@code IP_CT_ESTABLISHED_REPLY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IP_CT_ESTABLISHED_REPLY"
    )
    IP_CT_ESTABLISHED_REPLY,

    /**
     * {@code IP_CT_RELATED_REPLY = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IP_CT_RELATED_REPLY"
    )
    IP_CT_RELATED_REPLY,

    /**
     * {@code IP_CT_NUMBER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IP_CT_NUMBER"
    )
    IP_CT_NUMBER,

    /**
     * {@code IP_CT_UNTRACKED = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IP_CT_UNTRACKED"
    )
    IP_CT_UNTRACKED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_esp_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_esp_hdr extends Struct {
    public @Unsigned @OriginalName("__be32") int spi;

    public @Unsigned @OriginalName("__be32") int seq_no;

    public char @Size(0) [] enc_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_ct_tcp_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_ct_tcp_state extends Struct {
    public @Unsigned @OriginalName("u_int32_t") int td_end;

    public @Unsigned @OriginalName("u_int32_t") int td_maxend;

    public @Unsigned @OriginalName("u_int32_t") int td_maxwin;

    public @Unsigned @OriginalName("u_int32_t") int td_maxack;

    public @OriginalName("u_int8_t") char td_scale;

    public @OriginalName("u_int8_t") char flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_ct_tcp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_ct_tcp extends Struct {
    public ip_ct_tcp_state @Size(2) [] seen;

    public @OriginalName("u_int8_t") char state;

    public @OriginalName("u_int8_t") char last_dir;

    public @OriginalName("u_int8_t") char retrans;

    public @OriginalName("u_int8_t") char last_index;

    public @Unsigned @OriginalName("u_int32_t") int last_seq;

    public @Unsigned @OriginalName("u_int32_t") int last_ack;

    public @Unsigned @OriginalName("u_int32_t") int last_end;

    public @Unsigned @OriginalName("u_int16_t") short last_win;

    public @OriginalName("u_int8_t") char last_wscale;

    public @OriginalName("u_int8_t") char last_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_ct_sctp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_ct_sctp extends Struct {
    public sctp_conntrack state;

    public @Unsigned @OriginalName("__be32") int @Size(2) [] vtag;

    public char @Size(2) [] init;

    public char last_dir;

    public char flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_info extends Struct {
    public ip_tunnel_key key;

    public ip_tunnel_encap encap;

    public dst_cache dst_cache;

    public char options_len;

    public char mode;

    public char @Size(0) [] options;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_key extends Struct {
    public @Unsigned @OriginalName("__be64") long tun_id;

    public u_of_ip_tunnel_key u;

    public @Unsigned long @Size(1) [] tun_flags;

    public @Unsigned @OriginalName("__be32") int label;

    public @Unsigned int nhid;

    public char tos;

    public char ttl;

    public @Unsigned @OriginalName("__be16") short tp_src;

    public @Unsigned @OriginalName("__be16") short tp_dst;

    public char flow_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_encap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_encap extends Struct {
    public @Unsigned short type;

    public @Unsigned short flags;

    public @Unsigned @OriginalName("__be16") short sport;

    public @Unsigned @OriginalName("__be16") short dport;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_rt_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_rt_info extends Struct {
    public @Unsigned @OriginalName("__be32") int daddr;

    public @Unsigned @OriginalName("__be32") int saddr;

    public @OriginalName("u_int8_t") char tos;

    public @Unsigned @OriginalName("u_int32_t") int mark;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_mreqn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_mreqn extends Struct {
    public in_addr imr_multiaddr;

    public in_addr imr_address;

    public int imr_ifindex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_mc_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_mc_list extends Struct {
    public Ptr<in_device> _interface;

    public @Unsigned @OriginalName("__be32") int multiaddr;

    public @Unsigned int sfmode;

    public Ptr<ip_sf_list> sources;

    public Ptr<ip_sf_list> tomb;

    public @Unsigned long @Size(2) [] sfcount;

    @InlineUnion(61563)
    public Ptr<ip_mc_list> next;

    @InlineUnion(61563)
    public Ptr<ip_mc_list> next_rcu;

    public Ptr<ip_mc_list> next_hash;

    public timer_list timer;

    public int users;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @OriginalName("spinlock_t") spinlock lock;

    public char tm_running;

    public char reporter;

    public char unsolicit_count;

    public char loaded;

    public char gsquery;

    public char crcount;

    public @Unsigned long mca_cstamp;

    public @Unsigned long mca_tstamp;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_sf_socklist"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_sf_socklist extends Struct {
    public @Unsigned int sl_max;

    public @Unsigned int sl_count;

    public callback_head rcu;

    public @Unsigned @OriginalName("__be32") int @Size(0) [] sl_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_mc_socklist"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_mc_socklist extends Struct {
    public Ptr<ip_mc_socklist> next_rcu;

    public ip_mreqn multi;

    public @Unsigned int sfmode;

    public Ptr<ip_sf_socklist> sflist;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_sf_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_sf_list extends Struct {
    public Ptr<ip_sf_list> sf_next;

    public @Unsigned long @Size(2) [] sf_count;

    public @Unsigned @OriginalName("__be32") int sf_inaddr;

    public char sf_gsresp;

    public char sf_oldin;

    public char sf_crcount;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_rt_acct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_rt_acct extends Struct {
    public @Unsigned int o_bytes;

    public @Unsigned int o_packets;

    public @Unsigned int i_bytes;

    public @Unsigned int i_packets;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ip_defrag_users"
  )
  public enum ip_defrag_users implements Enum<ip_defrag_users>, TypedEnum<ip_defrag_users, java.lang. @Unsigned Integer> {
    /**
     * {@code IP_DEFRAG_LOCAL_DELIVER = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IP_DEFRAG_LOCAL_DELIVER"
    )
    IP_DEFRAG_LOCAL_DELIVER,

    /**
     * {@code IP_DEFRAG_CALL_RA_CHAIN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IP_DEFRAG_CALL_RA_CHAIN"
    )
    IP_DEFRAG_CALL_RA_CHAIN,

    /**
     * {@code IP_DEFRAG_CONNTRACK_IN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IP_DEFRAG_CONNTRACK_IN"
    )
    IP_DEFRAG_CONNTRACK_IN,

    /**
     * {@code __IP_DEFRAG_CONNTRACK_IN_END = 65537}
     */
    @EnumMember(
        value = 65537L,
        name = "__IP_DEFRAG_CONNTRACK_IN_END"
    )
    __IP_DEFRAG_CONNTRACK_IN_END,

    /**
     * {@code IP_DEFRAG_CONNTRACK_OUT = 65538}
     */
    @EnumMember(
        value = 65538L,
        name = "IP_DEFRAG_CONNTRACK_OUT"
    )
    IP_DEFRAG_CONNTRACK_OUT,

    /**
     * {@code __IP_DEFRAG_CONNTRACK_OUT_END = 131073}
     */
    @EnumMember(
        value = 131073L,
        name = "__IP_DEFRAG_CONNTRACK_OUT_END"
    )
    __IP_DEFRAG_CONNTRACK_OUT_END,

    /**
     * {@code IP_DEFRAG_CONNTRACK_BRIDGE_IN = 131074}
     */
    @EnumMember(
        value = 131074L,
        name = "IP_DEFRAG_CONNTRACK_BRIDGE_IN"
    )
    IP_DEFRAG_CONNTRACK_BRIDGE_IN,

    /**
     * {@code __IP_DEFRAG_CONNTRACK_BRIDGE_IN = 196609}
     */
    @EnumMember(
        value = 196609L,
        name = "__IP_DEFRAG_CONNTRACK_BRIDGE_IN"
    )
    __IP_DEFRAG_CONNTRACK_BRIDGE_IN,

    /**
     * {@code IP_DEFRAG_VS_IN = 196610}
     */
    @EnumMember(
        value = 196610L,
        name = "IP_DEFRAG_VS_IN"
    )
    IP_DEFRAG_VS_IN,

    /**
     * {@code IP_DEFRAG_VS_OUT = 196611}
     */
    @EnumMember(
        value = 196611L,
        name = "IP_DEFRAG_VS_OUT"
    )
    IP_DEFRAG_VS_OUT,

    /**
     * {@code IP_DEFRAG_VS_FWD = 196612}
     */
    @EnumMember(
        value = 196612L,
        name = "IP_DEFRAG_VS_FWD"
    )
    IP_DEFRAG_VS_FWD,

    /**
     * {@code IP_DEFRAG_AF_PACKET = 196613}
     */
    @EnumMember(
        value = 196613L,
        name = "IP_DEFRAG_AF_PACKET"
    )
    IP_DEFRAG_AF_PACKET,

    /**
     * {@code IP_DEFRAG_MACVLAN = 196614}
     */
    @EnumMember(
        value = 196614L,
        name = "IP_DEFRAG_MACVLAN"
    )
    IP_DEFRAG_MACVLAN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_options_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_options_data extends Struct {
    public ip_options_rcu opt;

    public char @Size(40) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_fraglist_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_fraglist_iter extends Struct {
    public Ptr<sk_buff> frag;

    public Ptr<iphdr> iph;

    public int offset;

    public @Unsigned int hlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_frag_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_frag_state extends Struct {
    public boolean DF;

    public @Unsigned int hlen;

    public @Unsigned int ll_rs;

    public @Unsigned int mtu;

    public @Unsigned int left;

    public int offset;

    public int ptr;

    public @Unsigned @OriginalName("__be16") short not_last_frag;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_reply_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_reply_arg extends Struct {
    public kvec @Size(1) [] iov;

    public int flags;

    public @Unsigned @OriginalName("__wsum") int csum;

    public int csumoffset;

    public int bound_dev_if;

    public char tos;

    public kuid_t uid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_mreq_source"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_mreq_source extends Struct {
    public @Unsigned @OriginalName("__be32") int imr_multiaddr;

    public @Unsigned @OriginalName("__be32") int imr_interface;

    public @Unsigned @OriginalName("__be32") int imr_sourceaddr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_msfilter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_msfilter extends Struct {
    public @Unsigned @OriginalName("__be32") int imsf_multiaddr;

    public @Unsigned @OriginalName("__be32") int imsf_interface;

    public @Unsigned int imsf_fmode;

    public @Unsigned int imsf_numsrc;

    @InlineUnion(61703)
    public @Unsigned @OriginalName("__be32") int @Size(1) [] imsf_slist;

    @InlineUnion(61703)
    public anon_member_of_anon_member_of_ip_msfilter anon4$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_encap_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_encap_ops extends Struct {
    public Ptr<?> encap_hlen;

    public Ptr<?> build_header;

    public Ptr<?> err_handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ip_conntrack_status"
  )
  public enum ip_conntrack_status implements Enum<ip_conntrack_status>, TypedEnum<ip_conntrack_status, java.lang. @Unsigned Integer> {
    /**
     * {@code IPS_EXPECTED_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IPS_EXPECTED_BIT"
    )
    IPS_EXPECTED_BIT,

    /**
     * {@code IPS_EXPECTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IPS_EXPECTED"
    )
    IPS_EXPECTED,

    /**
     * {@code IPS_SEEN_REPLY_BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IPS_SEEN_REPLY_BIT"
    )
    IPS_SEEN_REPLY_BIT,

    /**
     * {@code IPS_SEEN_REPLY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IPS_SEEN_REPLY"
    )
    IPS_SEEN_REPLY,

    /**
     * {@code IPS_ASSURED_BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IPS_ASSURED_BIT"
    )
    IPS_ASSURED_BIT,

    /**
     * {@code IPS_ASSURED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IPS_ASSURED"
    )
    IPS_ASSURED,

    /**
     * {@code IPS_CONFIRMED_BIT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IPS_CONFIRMED_BIT"
    )
    IPS_CONFIRMED_BIT,

    /**
     * {@code IPS_CONFIRMED = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IPS_CONFIRMED"
    )
    IPS_CONFIRMED,

    /**
     * {@code IPS_SRC_NAT_BIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IPS_SRC_NAT_BIT"
    )
    IPS_SRC_NAT_BIT,

    /**
     * {@code IPS_SRC_NAT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IPS_SRC_NAT"
    )
    IPS_SRC_NAT,

    /**
     * {@code IPS_DST_NAT_BIT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IPS_DST_NAT_BIT"
    )
    IPS_DST_NAT_BIT,

    /**
     * {@code IPS_DST_NAT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IPS_DST_NAT"
    )
    IPS_DST_NAT,

    /**
     * {@code IPS_NAT_MASK = 48}
     */
    @EnumMember(
        value = 48L,
        name = "IPS_NAT_MASK"
    )
    IPS_NAT_MASK,

    /**
     * {@code IPS_SEQ_ADJUST_BIT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IPS_SEQ_ADJUST_BIT"
    )
    IPS_SEQ_ADJUST_BIT,

    /**
     * {@code IPS_SEQ_ADJUST = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IPS_SEQ_ADJUST"
    )
    IPS_SEQ_ADJUST,

    /**
     * {@code IPS_SRC_NAT_DONE_BIT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IPS_SRC_NAT_DONE_BIT"
    )
    IPS_SRC_NAT_DONE_BIT,

    /**
     * {@code IPS_SRC_NAT_DONE = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IPS_SRC_NAT_DONE"
    )
    IPS_SRC_NAT_DONE,

    /**
     * {@code IPS_DST_NAT_DONE_BIT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IPS_DST_NAT_DONE_BIT"
    )
    IPS_DST_NAT_DONE_BIT,

    /**
     * {@code IPS_DST_NAT_DONE = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IPS_DST_NAT_DONE"
    )
    IPS_DST_NAT_DONE,

    /**
     * {@code IPS_NAT_DONE_MASK = 384}
     */
    @EnumMember(
        value = 384L,
        name = "IPS_NAT_DONE_MASK"
    )
    IPS_NAT_DONE_MASK,

    /**
     * {@code IPS_DYING_BIT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IPS_DYING_BIT"
    )
    IPS_DYING_BIT,

    /**
     * {@code IPS_DYING = 512}
     */
    @EnumMember(
        value = 512L,
        name = "IPS_DYING"
    )
    IPS_DYING,

    /**
     * {@code IPS_FIXED_TIMEOUT_BIT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IPS_FIXED_TIMEOUT_BIT"
    )
    IPS_FIXED_TIMEOUT_BIT,

    /**
     * {@code IPS_FIXED_TIMEOUT = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "IPS_FIXED_TIMEOUT"
    )
    IPS_FIXED_TIMEOUT,

    /**
     * {@code IPS_TEMPLATE_BIT = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IPS_TEMPLATE_BIT"
    )
    IPS_TEMPLATE_BIT,

    /**
     * {@code IPS_TEMPLATE = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "IPS_TEMPLATE"
    )
    IPS_TEMPLATE,

    /**
     * {@code IPS_UNTRACKED_BIT = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IPS_UNTRACKED_BIT"
    )
    IPS_UNTRACKED_BIT,

    /**
     * {@code IPS_UNTRACKED = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IPS_UNTRACKED"
    )
    IPS_UNTRACKED,

    /**
     * {@code IPS_NAT_CLASH_BIT = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IPS_NAT_CLASH_BIT"
    )
    IPS_NAT_CLASH_BIT,

    /**
     * {@code IPS_NAT_CLASH = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IPS_NAT_CLASH"
    )
    IPS_NAT_CLASH,

    /**
     * {@code IPS_HELPER_BIT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IPS_HELPER_BIT"
    )
    IPS_HELPER_BIT,

    /**
     * {@code IPS_HELPER = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "IPS_HELPER"
    )
    IPS_HELPER,

    /**
     * {@code IPS_OFFLOAD_BIT = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IPS_OFFLOAD_BIT"
    )
    IPS_OFFLOAD_BIT,

    /**
     * {@code IPS_OFFLOAD = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "IPS_OFFLOAD"
    )
    IPS_OFFLOAD,

    /**
     * {@code IPS_HW_OFFLOAD_BIT = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IPS_HW_OFFLOAD_BIT"
    )
    IPS_HW_OFFLOAD_BIT,

    /**
     * {@code IPS_HW_OFFLOAD = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "IPS_HW_OFFLOAD"
    )
    IPS_HW_OFFLOAD,

    /**
     * {@code IPS_UNCHANGEABLE_MASK = 56313}
     */
    @EnumMember(
        value = 56313L,
        name = "IPS_UNCHANGEABLE_MASK"
    )
    IPS_UNCHANGEABLE_MASK,

    /**
     * {@code __IPS_MAX_BIT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "__IPS_MAX_BIT"
    )
    __IPS_MAX_BIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ipv4_addr; struct in6_addr ipv6_addr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_addr_of_addr_of_ident_of_icmp_ext_echo_iio extends Union {
    public @Unsigned @OriginalName("__be32") int ipv4_addr;

    public in6_addr ipv6_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_beet_phdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_beet_phdr extends Struct {
    public char nexthdr;

    public char hdrlen;

    public char padlen;

    public char reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel extends Struct {
    public Ptr<ip_tunnel> next;

    public hlist_node hash_node;

    public Ptr<net_device> dev;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public Ptr<net> net;

    public @Unsigned long err_time;

    public int err_count;

    public @Unsigned int i_seqno;

    public atomic_t o_seqno;

    public int tun_hlen;

    public @Unsigned int index;

    public char erspan_ver;

    public char dir;

    public @Unsigned short hwid;

    public dst_cache dst_cache;

    public ip_tunnel_parm_kern parms;

    public int mlink;

    public int encap_hlen;

    public int hlen;

    public ip_tunnel_encap encap;

    public ip_tunnel_6rd_parm ip6rd;

    public Ptr<ip_tunnel_prl_entry> prl;

    public @Unsigned int prl_count;

    public ip_tunnel_fan fan;

    public @Unsigned int ip_tnl_net_id;

    public gro_cells gro_cells;

    public @Unsigned int fwmark;

    public boolean collect_md;

    public boolean ignore_df;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_6rd_parm"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_6rd_parm extends Struct {
    public in6_addr prefix;

    public @Unsigned @OriginalName("__be32") int relay_prefix;

    public @Unsigned short prefixlen;

    public @Unsigned short relay_prefixlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_prl_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_prl_entry extends Struct {
    public Ptr<ip_tunnel_prl_entry> next;

    public @Unsigned @OriginalName("__be32") int addr;

    public @Unsigned short flags;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ip_tunnel_fan"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ip_tunnel_fan extends Struct {
    public list_head fan_maps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ipq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ipq extends Struct {
    public inet_frag_queue q;

    public char ecn;

    public @Unsigned short max_df_size;

    public int iif;

    public @Unsigned int rid;

    public Ptr<inet_peer> peer;
  }
}
