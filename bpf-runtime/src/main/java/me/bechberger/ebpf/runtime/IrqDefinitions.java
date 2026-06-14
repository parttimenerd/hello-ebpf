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
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
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
 * Generated class for BPF runtime types that start with irq
 */
@java.lang.SuppressWarnings("unused")
public final class IrqDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__irq_alloc_descs($arg1, $arg2, $arg3, $arg4, $arg5, (const struct irq_affinity_desc*)$arg6)")
  public static int __irq_alloc_descs(int irq, @Unsigned int from, @Unsigned int cnt, int node,
      Ptr<module> owner, Ptr<irq_affinity_desc> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_alloc_domain_generic_chips($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static int __irq_alloc_domain_generic_chips(Ptr<irq_domain> d, int irqs_per_chip,
      int num_ct, String name, @OriginalName("irq_flow_handler_t") Ptr<?> handler,
      @Unsigned int clr, @Unsigned int set, irq_gc_flags gcflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_apply_affinity_hint($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static int __irq_apply_affinity_hint(@Unsigned int irq, Ptr<cpumask> m,
      boolean setaffinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_disable(Ptr<irq_desc> desc, boolean mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_do_set_handler($arg1, $arg2, $arg3, (const u8*)$arg4)")
  public static void __irq_do_set_handler(Ptr<irq_desc> desc,
      @OriginalName("irq_flow_handler_t") Ptr<?> handle, int is_chained, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __irq_domain_activate_irq(Ptr<irq_data> irqd, boolean reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_domain_alloc_fwnode($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static Ptr<fwnode_handle> __irq_domain_alloc_fwnode(@Unsigned int type, int id,
      String name, Ptr<java.lang. @Unsigned @OriginalName("phys_addr_t") Long> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_domain_alloc_irqs($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, (const struct irq_affinity_desc*)$arg7)")
  public static int __irq_domain_alloc_irqs(Ptr<irq_domain> domain, int irq_base,
      @Unsigned int nr_irqs, int node, Ptr<?> arg, boolean realloc,
      Ptr<irq_affinity_desc> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_domain_create((const struct irq_domain_info*)$arg1)")
  public static Ptr<irq_domain> __irq_domain_create(Ptr<irq_domain_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_domain_deactivate_irq(Ptr<irq_data> irq_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_domain_instantiate((const struct irq_domain_info*)$arg1, $arg2, $arg3)")
  public static Ptr<irq_domain> __irq_domain_instantiate(Ptr<irq_domain_info> info,
      boolean cond_alloc_descs, boolean force_associate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_exit_rcu() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_desc> __irq_get_desc_lock(@Unsigned int irq,
      Ptr<java.lang. @Unsigned Long> flags, boolean bus, @Unsigned int check) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __irq_get_irqchip_state(Ptr<irq_data> data, irqchip_irq_state which,
      Ptr<java.lang. @OriginalName("bool") Boolean> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_move_irq(Ptr<irq_data> idata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_msi_compose_msg(Ptr<irq_cfg> cfg, Ptr<msi_msg> msg, boolean dmar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_put_desc_unlock(Ptr<irq_desc> desc, @Unsigned long flags, boolean bus) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_desc> __irq_resolve_mapping(Ptr<irq_domain> domain,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq,
      Ptr<java.lang. @Unsigned Integer> irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_set_affinity($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static int __irq_set_affinity(@Unsigned int irq, Ptr<cpumask> mask, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__irq_set_handler($arg1, $arg2, $arg3, (const u8*)$arg4)")
  public static void __irq_set_handler(@Unsigned int irq,
      @OriginalName("irq_flow_handler_t") Ptr<?> handle, int is_chained, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __irq_set_trigger(Ptr<irq_desc> desc, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __irq_startup(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_wake_thread(Ptr<irq_desc> desc, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __irq_work_queue_local(Ptr<irq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_activate(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_activate_and_startup(Ptr<irq_desc> desc, boolean resend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_affinity_hint_proc_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_affinity_list_proc_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_affinity_list_proc_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_affinity_list_proc_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long irq_affinity_list_proc_write(Ptr<file> file,
      String buffer, @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_affinity_online_cpu(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_affinity_proc_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_affinity_proc_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_affinity_proc_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long irq_affinity_proc_write(Ptr<file> file, String buffer,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_affinity_setup(String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_alloc_generic_chip((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static Ptr<irq_chip_generic> irq_alloc_generic_chip(String name, int num_ct,
      @Unsigned int irq_base, Ptr<?> reg_base, @OriginalName("irq_flow_handler_t") Ptr<?> handler) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_matrix> irq_alloc_matrix(@Unsigned int matrix_bits,
      @Unsigned int alloc_start, @Unsigned int alloc_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_calc_affinity_vectors($arg1, $arg2, (const struct irq_affinity*)$arg3)")
  public static @Unsigned int irq_calc_affinity_vectors(@Unsigned int minvec, @Unsigned int maxvec,
      Ptr<irq_affinity> affd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_can_handle_pm(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_can_move_in_process_context(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_can_set_affinity(@Unsigned int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_can_set_affinity_usr(@Unsigned int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_check_status_bit(@Unsigned int irq, @Unsigned int bitmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_ack_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_compose_msi_msg(Ptr<irq_data> data, Ptr<msi_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_disable_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_enable_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_eoi_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_get_parent_state(Ptr<irq_data> data, irqchip_irq_state which,
      Ptr<java.lang. @OriginalName("bool") Boolean> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_mask_ack_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_mask_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_pm_get(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_pm_put(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_release_resources_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_request_resources_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_retrigger_hierarchy(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_chip_set_affinity_parent($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static int irq_chip_set_affinity_parent(Ptr<irq_data> data, Ptr<cpumask> dest,
      boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_set_parent_state(Ptr<irq_data> data, irqchip_irq_state which,
      boolean val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_set_type_parent(Ptr<irq_data> data, @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_set_vcpu_affinity_parent(Ptr<irq_data> data, Ptr<?> vcpu_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_chip_set_wake_parent(Ptr<irq_data> data, @Unsigned int on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_shutdown_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_chip_startup_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_chip_unmask_parent(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_complete_move(Ptr<irq_cfg> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_cpu_rmap_add(Ptr<cpu_rmap> rmap, int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_cpu_rmap_notify($arg1, (const cpumask*)$arg2)")
  public static void irq_cpu_rmap_notify(Ptr<irq_affinity_notify> notify,
      Ptr<@OriginalName("cpumask_t") cpumask> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_cpu_rmap_release(Ptr<kref> ref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_cpu_rmap_remove(Ptr<cpu_rmap> rmap, int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_affinity_desc> irq_create_affinity_masks(@Unsigned int nvecs,
      Ptr<irq_affinity> affd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_create_fwspec_mapping(Ptr<irq_fwspec> fwspec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_create_mapping_affinity($arg1, $arg2, (const struct irq_affinity_desc*)$arg3)")
  public static @Unsigned int irq_create_mapping_affinity(Ptr<irq_domain> domain,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq, Ptr<irq_affinity_desc> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_create_mapping_affinity_locked($arg1, $arg2, (const struct irq_affinity_desc*)$arg3)")
  public static @Unsigned int irq_create_mapping_affinity_locked(Ptr<irq_domain> domain,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq, Ptr<irq_affinity_desc> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_create_of_mapping(Ptr<of_phandle_args> irq_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn irq_default_primary_handler(int irq,
      Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_disable(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_dispose_mapping(@Unsigned int virq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_dma_fence_array_work(Ptr<irq_work> wrk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_do_set_affinity($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static int irq_do_set_affinity(Ptr<irq_data> data, Ptr<cpumask> mask, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_activate_irq(Ptr<irq_data> irq_data, boolean reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_alloc_generic_chips($arg1, (const struct irq_domain_chip_generic_info*)$arg2)")
  public static int irq_domain_alloc_generic_chips(Ptr<irq_domain> d,
      Ptr<irq_domain_chip_generic_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_alloc_irqs_hierarchy(Ptr<irq_domain> domain, @Unsigned int irq_base,
      @Unsigned int nr_irqs, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_alloc_irqs_locked($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, (const struct irq_affinity_desc*)$arg7)")
  public static int irq_domain_alloc_irqs_locked(Ptr<irq_domain> domain, int irq_base,
      @Unsigned int nr_irqs, int node, Ptr<?> arg, boolean realloc,
      Ptr<irq_affinity_desc> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_alloc_irqs_parent(Ptr<irq_domain> domain, @Unsigned int irq_base,
      @Unsigned int nr_irqs, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_associate(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_associate_locked(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_associate_many(Ptr<irq_domain> domain, @Unsigned int irq_base,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq_base, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_create_legacy($arg1, $arg2, $arg3, $arg4, (const struct irq_domain_ops*)$arg5, $arg6)")
  public static Ptr<irq_domain> irq_domain_create_legacy(Ptr<fwnode_handle> fwnode,
      @Unsigned int size, @Unsigned int first_irq,
      @Unsigned @OriginalName("irq_hw_number_t") long first_hwirq, Ptr<irq_domain_ops> ops,
      Ptr<?> host_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_domain> irq_domain_create_sim(Ptr<fwnode_handle> fwnode,
      @Unsigned int num_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_create_sim_full($arg1, $arg2, (const struct irq_sim_ops*)$arg3, $arg4)")
  public static Ptr<irq_domain> irq_domain_create_sim_full(Ptr<fwnode_handle> fwnode,
      @Unsigned int num_irqs, Ptr<irq_sim_ops> ops, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_create_simple($arg1, $arg2, $arg3, (const struct irq_domain_ops*)$arg4, $arg5)")
  public static Ptr<irq_domain> irq_domain_create_simple(Ptr<fwnode_handle> fwnode,
      @Unsigned int size, @Unsigned int first_irq, Ptr<irq_domain_ops> ops, Ptr<?> host_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_deactivate_irq(Ptr<irq_data> irq_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_disconnect_hierarchy(Ptr<irq_domain> domain, @Unsigned int virq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_fix_revmap(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_free(Ptr<irq_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_free_fwnode(Ptr<fwnode_handle> fwnode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_free_irqs(@Unsigned int virq, @Unsigned int nr_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_free_irqs_common(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned int nr_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_free_irqs_hierarchy(Ptr<irq_domain> domain, @Unsigned int irq_base,
      @Unsigned int nr_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_free_irqs_parent(Ptr<irq_domain> domain, @Unsigned int irq_base,
      @Unsigned int nr_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_free_irqs_top(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned int nr_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_data> irq_domain_get_irq_data(Ptr<irq_domain> domain, @Unsigned int virq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_instantiate((const struct irq_domain_info*)$arg1)")
  public static Ptr<irq_domain> irq_domain_instantiate(Ptr<irq_domain_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_pop_irq(Ptr<irq_domain> domain, int virq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_push_irq(Ptr<irq_domain> domain, int virq, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_remove(Ptr<irq_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_remove_generic_chips(Ptr<irq_domain> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_remove_sim(Ptr<irq_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_reset_irq_data(Ptr<irq_data> irq_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_set_hwirq_and_chip($arg1, $arg2, $arg3, (const struct irq_chip*)$arg4, $arg5)")
  public static int irq_domain_set_hwirq_and_chip(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq, Ptr<irq_chip> chip, Ptr<?> chip_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_set_info($arg1, $arg2, $arg3, (const struct irq_chip*)$arg4, $arg5, $arg6, $arg7, (const u8*)$arg8)")
  public static void irq_domain_set_info(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned @OriginalName("irq_hw_number_t") long hwirq, Ptr<irq_chip> chip, Ptr<?> chip_data,
      @OriginalName("irq_flow_handler_t") Ptr<?> handler, Ptr<?> handler_data,
      String handler_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_set_name($arg1, (const struct irq_domain_info*)$arg2)")
  public static int irq_domain_set_name(Ptr<irq_domain> domain, Ptr<irq_domain_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_translate_onecell(Ptr<irq_domain> d, Ptr<irq_fwspec> fwspec,
      Ptr<java.lang. @Unsigned Long> out_hwirq, Ptr<java.lang. @Unsigned Integer> out_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_translate_twocell(Ptr<irq_domain> d, Ptr<irq_fwspec> fwspec,
      Ptr<java.lang. @Unsigned Long> out_hwirq, Ptr<java.lang. @Unsigned Integer> out_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_domain_translate_twothreecell(Ptr<irq_domain> d, Ptr<irq_fwspec> fwspec,
      Ptr<java.lang. @Unsigned Long> out_hwirq, Ptr<java.lang. @Unsigned Integer> out_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_domain_update_bus_token(Ptr<irq_domain> domain,
      irq_domain_bus_token bus_token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_xlate_onecell($arg1, $arg2, (const unsigned int*)$arg3, $arg4, $arg5, $arg6)")
  public static int irq_domain_xlate_onecell(Ptr<irq_domain> d, Ptr<device_node> ctrlr,
      Ptr<java.lang. @Unsigned Integer> intspec, @Unsigned int intsize,
      Ptr<java.lang. @Unsigned Long> out_hwirq, Ptr<java.lang. @Unsigned Integer> out_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_xlate_onetwocell($arg1, $arg2, (const unsigned int*)$arg3, $arg4, $arg5, $arg6)")
  public static int irq_domain_xlate_onetwocell(Ptr<irq_domain> d, Ptr<device_node> ctrlr,
      Ptr<java.lang. @Unsigned Integer> intspec, @Unsigned int intsize,
      Ptr<java.lang. @Unsigned Long> out_hwirq, Ptr<java.lang. @Unsigned Integer> out_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_xlate_twocell($arg1, $arg2, (const unsigned int*)$arg3, $arg4, $arg5, $arg6)")
  public static int irq_domain_xlate_twocell(Ptr<irq_domain> d, Ptr<device_node> ctrlr,
      Ptr<java.lang. @Unsigned Integer> intspec, @Unsigned int intsize,
      Ptr<java.lang. @Unsigned @OriginalName("irq_hw_number_t") Long> out_hwirq,
      Ptr<java.lang. @Unsigned Integer> out_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_domain_xlate_twothreecell($arg1, $arg2, (const unsigned int*)$arg3, $arg4, $arg5, $arg6)")
  public static int irq_domain_xlate_twothreecell(Ptr<irq_domain> d, Ptr<device_node> ctrlr,
      Ptr<java.lang. @Unsigned Integer> intspec, @Unsigned int intsize,
      Ptr<java.lang. @Unsigned @OriginalName("irq_hw_number_t") Long> out_hwirq,
      Ptr<java.lang. @Unsigned Integer> out_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_effective_aff_list_proc_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_effective_aff_proc_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_enable(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_enter() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_enter_rcu() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_evtchn_from_virq(@Unsigned int cpu, @Unsigned int virq,
      Ptr<java.lang. @Unsigned @OriginalName("evtchn_port_t") Integer> evtchn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_exit_rcu() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_finalize_oneshot(Ptr<irq_desc> desc, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_domain> irq_find_matching_fwspec(Ptr<irq_fwspec> fwspec,
      irq_domain_bus_token bus_token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_fixup_move_pending(Ptr<irq_desc> desc, boolean force_clear) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_force_affinity($arg1, (const struct cpumask*)$arg2)")
  public static int irq_force_affinity(@Unsigned int irq, Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_force_complete_move(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn irq_forced_secondary_handler(int irq,
      Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn irq_forced_thread_fn(Ptr<irq_desc> desc,
      Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_fpu_usable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_free_descs(@Unsigned int from, @Unsigned int cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_from_evtchn(@Unsigned @OriginalName("evtchn_port_t") int evtchn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_ack_clr_bit(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_ack_set_bit(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_eoi(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_data> irq_gc_get_irq_data(Ptr<irq_chip_generic> gc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_init_mask_cache(Ptr<irq_chip_generic> gc, irq_gc_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_gc_init_ops() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_mask_clr_bit(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_mask_disable_and_ack_set(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_mask_disable_reg(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_mask_set_bit(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_noop(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_resume() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_gc_set_wake(Ptr<irq_data> d, @Unsigned int on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_shutdown() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_gc_suspend() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_gc_unmask_enable_reg(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_domain> irq_get_default_domain() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_chip_generic> irq_get_domain_generic_chip(Ptr<irq_domain> d,
      @Unsigned int hw_irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_data> irq_get_irq_data(@Unsigned int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_get_irqchip_state(@Unsigned int irq, irqchip_irq_state which,
      Ptr<java.lang. @OriginalName("bool") Boolean> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_get_next_irq(@Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_get_nr_irqs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_get_pending(Ptr<cpumask> mask, Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_get_percpu_devid_partition(@Unsigned int irq, Ptr<cpumask> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_has_action(@Unsigned int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_init_generic_chip($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static void irq_init_generic_chip(Ptr<irq_chip_generic> gc, String name, int num_ct,
      @Unsigned int irq_base, Ptr<?> reg_base, @OriginalName("irq_flow_handler_t") Ptr<?> handler) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_init_percpu_irqstack(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_insert_desc(@Unsigned int irq, Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_is_level(int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_kobj_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_lock_sparse() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_map_generic_chip(Ptr<irq_domain> d, @Unsigned int virq,
      @Unsigned @OriginalName("irq_hw_number_t") long hw_irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_matrix_alloc($arg1, (const struct cpumask*)$arg2, $arg3, $arg4)")
  public static int irq_matrix_alloc(Ptr<irq_matrix> m, Ptr<cpumask> msk, boolean reserved,
      Ptr<java.lang. @Unsigned Integer> mapped_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_matrix_alloc_managed($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static int irq_matrix_alloc_managed(Ptr<irq_matrix> m, Ptr<cpumask> msk,
      Ptr<java.lang. @Unsigned Integer> mapped_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_matrix_allocated(Ptr<irq_matrix> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_matrix_assign(Ptr<irq_matrix> m, @Unsigned int bit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_matrix_assign_system(Ptr<irq_matrix> m, @Unsigned int bit,
      boolean replace) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_matrix_available(Ptr<irq_matrix> m, boolean cpudown) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_matrix_free(Ptr<irq_matrix> m, @Unsigned int cpu, @Unsigned int bit,
      boolean managed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_matrix_offline(Ptr<irq_matrix> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_matrix_online(Ptr<irq_matrix> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_matrix_remove_managed($arg1, (const struct cpumask*)$arg2)")
  public static void irq_matrix_remove_managed(Ptr<irq_matrix> m, Ptr<cpumask> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_matrix_remove_reserved(Ptr<irq_matrix> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_matrix_reserve(Ptr<irq_matrix> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_matrix_reserve_managed($arg1, (const struct cpumask*)$arg2)")
  public static int irq_matrix_reserve_managed(Ptr<irq_matrix> m, Ptr<cpumask> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_matrix_reserved(Ptr<irq_matrix> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_migrate_all_off_this_cpu() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_modify_status(@Unsigned int irq, @Unsigned long clr, @Unsigned long set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_move_masked_irq(Ptr<irq_data> idata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_needs_fixup(Ptr<irq_data> d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn irq_nested_primary_handler(int irq,
      Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_node_proc_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_percpu_disable(Ptr<irq_desc> desc, @Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_percpu_enable(Ptr<irq_desc> desc, @Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_percpu_is_enabled(@Unsigned int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_pm_handle_wakeup(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_pm_init_ops() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_pm_install_action(Ptr<irq_desc> desc, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_pm_remove_action(Ptr<irq_desc> desc, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_pm_syscore_resume() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_poll_complete(Ptr<irq_poll> iop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_poll_cpu_dead(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_poll_disable(Ptr<irq_poll> iop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_poll_enable(Ptr<irq_poll> iop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_poll_init(Ptr<irq_poll> iop, int weight, Ptr<?> poll_fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_poll_sched(Ptr<irq_poll> iop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_poll_setup() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_poll_softirq() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_readl_be(Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_remap_enable_fault_handling() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_remapping_activate(Ptr<irq_domain> domain, Ptr<irq_data> irq_data,
      boolean reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_remapping_alloc(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned int nr_irqs, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_remapping_cap(irq_remap_cap cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_remapping_deactivate(Ptr<irq_domain> domain, Ptr<irq_data> irq_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_remapping_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_remapping_enable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_remapping_free(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned int nr_irqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_remapping_prepare() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_remapping_reenable(int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_remapping_restore_boot_irq_mode() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_remapping_select(Ptr<irq_domain> d, Ptr<irq_fwspec> fwspec,
      irq_domain_bus_token bus_token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_remove_generic_chip(Ptr<irq_chip_generic> gc, @Unsigned int msk,
      @Unsigned int clr, @Unsigned int set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_resend_init(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_safe_dev_in_sleep_domain($arg1, (const struct generic_pm_domain*)$arg2)")
  public static boolean irq_safe_dev_in_sleep_domain(Ptr<device> dev,
      Ptr<generic_pm_domain> genpd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_set_affinity($arg1, (const struct cpumask*)$arg2)")
  public static int irq_set_affinity(@Unsigned int irq, Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_set_affinity_deactivated($arg1, (const struct cpumask*)$arg2)")
  public static boolean irq_set_affinity_deactivated(Ptr<irq_data> data, Ptr<cpumask> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_set_affinity_locked($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static int irq_set_affinity_locked(Ptr<irq_data> data, Ptr<cpumask> mask, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_affinity_notifier(@Unsigned int irq, Ptr<irq_affinity_notify> notify) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_set_chained_handler_and_data(@Unsigned int irq,
      @OriginalName("irq_flow_handler_t") Ptr<?> handle, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_set_chip($arg1, (const struct irq_chip*)$arg2)")
  public static int irq_set_chip(@Unsigned int irq, Ptr<irq_chip> chip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_set_chip_and_handler_name($arg1, (const struct irq_chip*)$arg2, $arg3, (const u8*)$arg4)")
  public static void irq_set_chip_and_handler_name(@Unsigned int irq, Ptr<irq_chip> chip,
      @OriginalName("irq_flow_handler_t") Ptr<?> handle, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_chip_data(@Unsigned int irq, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_set_default_domain(Ptr<irq_domain> domain) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_handler_data(@Unsigned int irq, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_irq_type(@Unsigned int irq, @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_irq_wake(@Unsigned int irq, @Unsigned int on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_irqchip_state(@Unsigned int irq, irqchip_irq_state which, boolean val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_msi_desc(@Unsigned int irq, Ptr<msi_desc> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_msi_desc_off(@Unsigned int irq_base, @Unsigned int irq_offset,
      Ptr<msi_desc> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int irq_set_nr_irqs(@Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_parent(int irq, int parent_irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_percpu_devid(@Unsigned int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("irq_set_percpu_devid_partition($arg1, (const struct cpumask*)$arg2)")
  public static int irq_set_percpu_devid_partition(@Unsigned int irq, Ptr<cpumask> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_set_vcpu_affinity(@Unsigned int irq, Ptr<?> vcpu_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_setup_affinity(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_setup_alt_chip(Ptr<irq_data> d, @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_setup_generic_chip(Ptr<irq_chip_generic> gc, @Unsigned int msk,
      irq_gc_flags flags, @Unsigned int clr, @Unsigned int set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long irq_show(Ptr<device> dev, Ptr<device_attribute> attr,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_shutdown(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_shutdown_and_deactivate(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_sim_domain_map(Ptr<irq_domain> domain, @Unsigned int virq,
      @Unsigned @OriginalName("irq_hw_number_t") long hw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_sim_domain_unmap(Ptr<irq_domain> domain, @Unsigned int virq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_sim_get_irqchip_state(Ptr<irq_data> data, irqchip_irq_state which,
      Ptr<java.lang. @OriginalName("bool") Boolean> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_sim_handle_irq(Ptr<irq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_sim_irqmask(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_sim_irqunmask(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_sim_release_resources(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_sim_request_resources(Ptr<irq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_sim_set_irqchip_state(Ptr<irq_data> data, irqchip_irq_state which,
      boolean state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_sim_set_type(Ptr<irq_data> data, @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_spurious_proc_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_startup(Ptr<irq_desc> desc, boolean resend, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_startup_managed(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_thread(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_thread_check_affinity(Ptr<irq_desc> desc, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_thread_dtor(Ptr<callback_head> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn irq_thread_fn(Ptr<irq_desc> desc,
      Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<irq_desc> irq_to_desc(@Unsigned int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_to_pcap(Ptr<pcap_chip> pcap, int irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_unlock_sparse() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_unmap_generic_chip(Ptr<irq_domain> d, @Unsigned int virq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_update_affinity_desc(@Unsigned int irq, Ptr<irq_affinity_desc> affinity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_wait_on_inprogress(Ptr<irq_desc> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_wake_thread(@Unsigned int irq, Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int irq_work_init_threads() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_work_needs_cpu() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_work_queue(Ptr<irq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean irq_work_queue_on(Ptr<irq_work> work, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_work_run() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_work_run_list(Ptr<llist_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_work_single(Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_work_sync(Ptr<irq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_work_tick() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void irq_writel_be(@Unsigned int val, Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_work extends Struct {
    public __call_single_node node;

    public Ptr<?> func;

    public rcuwait irqwait;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_affinity_notify"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_affinity_notify extends Struct {
    public @Unsigned int irq;

    public kref kref;

    public work_struct work;

    public Ptr<?> notify;

    public Ptr<?> release;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 kvm_cpu_l1tf_flush_l1d; unsigned int __nmi_count; unsigned int apic_timer_irqs; unsigned int irq_spurious_count; unsigned int icr_read_retry_count; unsigned int kvm_posted_intr_ipis; unsigned int kvm_posted_intr_wakeup_ipis; unsigned int kvm_posted_intr_nested_ipis; unsigned int x86_platform_ipis; unsigned int apic_perf_irqs; unsigned int apic_irq_work_irqs; unsigned int irq_resched_count; unsigned int irq_call_count; unsigned int irq_tlb_count; unsigned int irq_thermal_count; unsigned int irq_threshold_count; unsigned int irq_deferred_error_count; unsigned int irq_hv_callback_count; unsigned int irq_hv_reenlightenment_count; unsigned int hyperv_stimer0_count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_cpustat_t extends Struct {
    public char kvm_cpu_l1tf_flush_l1d;

    public @Unsigned int __nmi_count;

    public @Unsigned int apic_timer_irqs;

    public @Unsigned int irq_spurious_count;

    public @Unsigned int icr_read_retry_count;

    public @Unsigned int kvm_posted_intr_ipis;

    public @Unsigned int kvm_posted_intr_wakeup_ipis;

    public @Unsigned int kvm_posted_intr_nested_ipis;

    public @Unsigned int x86_platform_ipis;

    public @Unsigned int apic_perf_irqs;

    public @Unsigned int apic_irq_work_irqs;

    public @Unsigned int irq_resched_count;

    public @Unsigned int irq_call_count;

    public @Unsigned int irq_tlb_count;

    public @Unsigned int irq_thermal_count;

    public @Unsigned int irq_threshold_count;

    public @Unsigned int irq_deferred_error_count;

    public @Unsigned int irq_hv_callback_count;

    public @Unsigned int irq_hv_reenlightenment_count;

    public @Unsigned int hyperv_stimer0_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_domain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_domain extends Struct {
    public list_head link;

    public String name;

    public Ptr<irq_domain_ops> ops;

    public Ptr<?> host_data;

    public @Unsigned int flags;

    public @Unsigned int mapcount;

    public mutex mutex;

    public Ptr<irq_domain> root;

    public Ptr<fwnode_handle> fwnode;

    public irq_domain_bus_token bus_token;

    public Ptr<irq_domain_chip_generic> gc;

    public Ptr<device> dev;

    public Ptr<device> pm_dev;

    public Ptr<irq_domain> parent;

    public Ptr<msi_parent_ops> msi_parent_ops;

    public Ptr<?> exit;

    public @Unsigned @OriginalName("irq_hw_number_t") long hwirq_max;

    public @Unsigned int revmap_size;

    public xarray revmap_tree;

    public Ptr<irq_data> @Size(0) [] revmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum irq_domain_bus_token"
  )
  public enum irq_domain_bus_token implements Enum<irq_domain_bus_token>, TypedEnum<irq_domain_bus_token, java.lang. @Unsigned Integer> {
    /**
     * {@code DOMAIN_BUS_ANY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DOMAIN_BUS_ANY"
    )
    DOMAIN_BUS_ANY,

    /**
     * {@code DOMAIN_BUS_WIRED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DOMAIN_BUS_WIRED"
    )
    DOMAIN_BUS_WIRED,

    /**
     * {@code DOMAIN_BUS_GENERIC_MSI = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DOMAIN_BUS_GENERIC_MSI"
    )
    DOMAIN_BUS_GENERIC_MSI,

    /**
     * {@code DOMAIN_BUS_PCI_MSI = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DOMAIN_BUS_PCI_MSI"
    )
    DOMAIN_BUS_PCI_MSI,

    /**
     * {@code DOMAIN_BUS_PLATFORM_MSI = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DOMAIN_BUS_PLATFORM_MSI"
    )
    DOMAIN_BUS_PLATFORM_MSI,

    /**
     * {@code DOMAIN_BUS_NEXUS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DOMAIN_BUS_NEXUS"
    )
    DOMAIN_BUS_NEXUS,

    /**
     * {@code DOMAIN_BUS_IPI = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DOMAIN_BUS_IPI"
    )
    DOMAIN_BUS_IPI,

    /**
     * {@code DOMAIN_BUS_FSL_MC_MSI = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DOMAIN_BUS_FSL_MC_MSI"
    )
    DOMAIN_BUS_FSL_MC_MSI,

    /**
     * {@code DOMAIN_BUS_TI_SCI_INTA_MSI = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DOMAIN_BUS_TI_SCI_INTA_MSI"
    )
    DOMAIN_BUS_TI_SCI_INTA_MSI,

    /**
     * {@code DOMAIN_BUS_WAKEUP = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DOMAIN_BUS_WAKEUP"
    )
    DOMAIN_BUS_WAKEUP,

    /**
     * {@code DOMAIN_BUS_VMD_MSI = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DOMAIN_BUS_VMD_MSI"
    )
    DOMAIN_BUS_VMD_MSI,

    /**
     * {@code DOMAIN_BUS_PCI_DEVICE_MSI = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DOMAIN_BUS_PCI_DEVICE_MSI"
    )
    DOMAIN_BUS_PCI_DEVICE_MSI,

    /**
     * {@code DOMAIN_BUS_PCI_DEVICE_MSIX = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DOMAIN_BUS_PCI_DEVICE_MSIX"
    )
    DOMAIN_BUS_PCI_DEVICE_MSIX,

    /**
     * {@code DOMAIN_BUS_DMAR = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DOMAIN_BUS_DMAR"
    )
    DOMAIN_BUS_DMAR,

    /**
     * {@code DOMAIN_BUS_AMDVI = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DOMAIN_BUS_AMDVI"
    )
    DOMAIN_BUS_AMDVI,

    /**
     * {@code DOMAIN_BUS_DEVICE_MSI = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DOMAIN_BUS_DEVICE_MSI"
    )
    DOMAIN_BUS_DEVICE_MSI,

    /**
     * {@code DOMAIN_BUS_WIRED_TO_MSI = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DOMAIN_BUS_WIRED_TO_MSI"
    )
    DOMAIN_BUS_WIRED_TO_MSI
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_desc extends Struct {
    public irq_common_data irq_common_data;

    public irq_data irq_data;

    public Ptr<irqstat> kstat_irqs;

    public @OriginalName("irq_flow_handler_t") Ptr<?> handle_irq;

    public Ptr<irqaction> action;

    public @Unsigned int status_use_accessors;

    public @Unsigned int core_internal_state__do_not_mess_with_it;

    public @Unsigned int depth;

    public @Unsigned int wake_depth;

    public @Unsigned int tot_count;

    public @Unsigned int irq_count;

    public @Unsigned long last_unhandled;

    public @Unsigned int irqs_unhandled;

    public atomic_t threads_handled;

    public int threads_handled_last;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public Ptr<cpumask> percpu_enabled;

    public Ptr<cpumask> percpu_affinity;

    public Ptr<cpumask> affinity_hint;

    public Ptr<irq_affinity_notify> affinity_notify;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> pending_mask;

    public @Unsigned long threads_oneshot;

    public atomic_t threads_active;

    public @OriginalName("wait_queue_head_t") wait_queue_head wait_for_threads;

    public @Unsigned int nr_actions;

    public @Unsigned int no_suspend_depth;

    public @Unsigned int cond_suspend_depth;

    public @Unsigned int force_resume_depth;

    public Ptr<proc_dir_entry> dir;

    public callback_head rcu;

    public kobject kobj;

    public mutex request_mutex;

    public int parent_irq;

    public Ptr<module> owner;

    public String name;

    public hlist_node resend_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_common_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_common_data extends Struct {
    public @Unsigned int state_use_accessors;

    public @Unsigned int node;

    public Ptr<?> handler_data;

    public Ptr<msi_desc> msi_desc;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> affinity;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> effective_affinity;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_data extends Struct {
    public @Unsigned int mask;

    public @Unsigned int irq;

    public @Unsigned @OriginalName("irq_hw_number_t") long hwirq;

    public Ptr<irq_common_data> common;

    public Ptr<irq_chip> chip;

    public Ptr<irq_domain> domain;

    public Ptr<irq_data> parent_data;

    public Ptr<?> chip_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_chip"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_chip extends Struct {
    public String name;

    public Ptr<?> irq_startup;

    public Ptr<?> irq_shutdown;

    public Ptr<?> irq_enable;

    public Ptr<?> irq_disable;

    public Ptr<?> irq_ack;

    public Ptr<?> irq_mask;

    public Ptr<?> irq_mask_ack;

    public Ptr<?> irq_unmask;

    public Ptr<?> irq_eoi;

    public Ptr<?> irq_set_affinity;

    public Ptr<?> irq_retrigger;

    public Ptr<?> irq_set_type;

    public Ptr<?> irq_set_wake;

    public Ptr<?> irq_bus_lock;

    public Ptr<?> irq_bus_sync_unlock;

    public Ptr<?> irq_suspend;

    public Ptr<?> irq_resume;

    public Ptr<?> irq_pm_shutdown;

    public Ptr<?> irq_calc_mask;

    public Ptr<?> irq_print_chip;

    public Ptr<?> irq_request_resources;

    public Ptr<?> irq_release_resources;

    public Ptr<?> irq_compose_msi_msg;

    public Ptr<?> irq_write_msi_msg;

    public Ptr<?> irq_get_irqchip_state;

    public Ptr<?> irq_set_irqchip_state;

    public Ptr<?> irq_set_vcpu_affinity;

    public Ptr<?> ipi_send_single;

    public Ptr<?> ipi_send_mask;

    public Ptr<?> irq_nmi_setup;

    public Ptr<?> irq_nmi_teardown;

    public Ptr<?> irq_force_complete_move;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum irq_alloc_type"
  )
  public enum irq_alloc_type implements Enum<irq_alloc_type>, TypedEnum<irq_alloc_type, java.lang. @Unsigned Integer> {
    /**
     * {@code X86_IRQ_ALLOC_TYPE_IOAPIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "X86_IRQ_ALLOC_TYPE_IOAPIC"
    )
    X86_IRQ_ALLOC_TYPE_IOAPIC,

    /**
     * {@code X86_IRQ_ALLOC_TYPE_HPET = 2}
     */
    @EnumMember(
        value = 2L,
        name = "X86_IRQ_ALLOC_TYPE_HPET"
    )
    X86_IRQ_ALLOC_TYPE_HPET,

    /**
     * {@code X86_IRQ_ALLOC_TYPE_PCI_MSI = 3}
     */
    @EnumMember(
        value = 3L,
        name = "X86_IRQ_ALLOC_TYPE_PCI_MSI"
    )
    X86_IRQ_ALLOC_TYPE_PCI_MSI,

    /**
     * {@code X86_IRQ_ALLOC_TYPE_PCI_MSIX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "X86_IRQ_ALLOC_TYPE_PCI_MSIX"
    )
    X86_IRQ_ALLOC_TYPE_PCI_MSIX,

    /**
     * {@code X86_IRQ_ALLOC_TYPE_DMAR = 5}
     */
    @EnumMember(
        value = 5L,
        name = "X86_IRQ_ALLOC_TYPE_DMAR"
    )
    X86_IRQ_ALLOC_TYPE_DMAR,

    /**
     * {@code X86_IRQ_ALLOC_TYPE_AMDVI = 6}
     */
    @EnumMember(
        value = 6L,
        name = "X86_IRQ_ALLOC_TYPE_AMDVI"
    )
    X86_IRQ_ALLOC_TYPE_AMDVI,

    /**
     * {@code X86_IRQ_ALLOC_TYPE_UV = 7}
     */
    @EnumMember(
        value = 7L,
        name = "X86_IRQ_ALLOC_TYPE_UV"
    )
    X86_IRQ_ALLOC_TYPE_UV
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_alloc_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_alloc_info extends Struct {
    public irq_alloc_type type;

    public @Unsigned int flags;

    public @Unsigned int devid;

    public @Unsigned @OriginalName("irq_hw_number_t") long hwirq;

    public Ptr<cpumask> mask;

    public Ptr<msi_desc> desc;

    public Ptr<?> data;

    @InlineUnion(5001)
    public ioapic_alloc_info ioapic;

    @InlineUnion(5001)
    public uv_alloc_info uv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_chip_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_chip_regs extends Struct {
    public @Unsigned long enable;

    public @Unsigned long disable;

    public @Unsigned long mask;

    public @Unsigned long ack;

    public @Unsigned long eoi;

    public @Unsigned long type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_chip_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_chip_type extends Struct {
    public irq_chip chip;

    public irq_chip_regs regs;

    public @OriginalName("irq_flow_handler_t") Ptr<?> handler;

    public @Unsigned int type;

    public @Unsigned int mask_cache_priv;

    public Ptr<java.lang. @Unsigned Integer> mask_cache;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_chip_generic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_chip_generic extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public Ptr<?> reg_base;

    public Ptr<?> reg_readl;

    public Ptr<?> reg_writel;

    public Ptr<?> suspend;

    public Ptr<?> resume;

    public @Unsigned int irq_base;

    public @Unsigned int irq_cnt;

    public @Unsigned int mask_cache;

    public @Unsigned int wake_enabled;

    public @Unsigned int wake_active;

    public @Unsigned int num_ct;

    public Ptr<?> _private;

    public @Unsigned long installed;

    public @Unsigned long unused;

    public Ptr<irq_domain> domain;

    public list_head list;

    public irq_chip_type @Size(0) [] chip_types;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum irq_gc_flags"
  )
  public enum irq_gc_flags implements Enum<irq_gc_flags>, TypedEnum<irq_gc_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IRQ_GC_INIT_MASK_CACHE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IRQ_GC_INIT_MASK_CACHE"
    )
    IRQ_GC_INIT_MASK_CACHE,

    /**
     * {@code IRQ_GC_INIT_NESTED_LOCK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IRQ_GC_INIT_NESTED_LOCK"
    )
    IRQ_GC_INIT_NESTED_LOCK,

    /**
     * {@code IRQ_GC_MASK_CACHE_PER_TYPE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IRQ_GC_MASK_CACHE_PER_TYPE"
    )
    IRQ_GC_MASK_CACHE_PER_TYPE,

    /**
     * {@code IRQ_GC_NO_MASK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IRQ_GC_NO_MASK"
    )
    IRQ_GC_NO_MASK,

    /**
     * {@code IRQ_GC_BE_IO = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IRQ_GC_BE_IO"
    )
    IRQ_GC_BE_IO
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_domain_chip_generic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_domain_chip_generic extends Struct {
    public @Unsigned int irqs_per_chip;

    public @Unsigned int num_chips;

    public @Unsigned int irq_flags_to_clear;

    public @Unsigned int irq_flags_to_set;

    public irq_gc_flags gc_flags;

    public Ptr<?> exit;

    public Ptr<irq_chip_generic> @Size(0) [] gc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_fwspec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_fwspec extends Struct {
    public Ptr<fwnode_handle> fwnode;

    public int param_count;

    public @Unsigned int @Size(16) [] param;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_domain_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_domain_ops extends Struct {
    public Ptr<?> match;

    public Ptr<?> select;

    public Ptr<?> map;

    public Ptr<?> unmap;

    public Ptr<?> xlate;

    public Ptr<?> alloc;

    public Ptr<?> free;

    public Ptr<?> activate;

    public Ptr<?> deactivate;

    public Ptr<?> translate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_affinity_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_affinity_desc extends Struct {
    public cpumask mask;

    public @Unsigned int is_managed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_stack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_stack extends Struct {
    public char @Size(16384) [] stack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_cfg extends Struct {
    public @Unsigned int dest_apicid;

    public @Unsigned int vector;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_domain_chip_generic_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_domain_chip_generic_info extends Struct {
    public String name;

    public @OriginalName("irq_flow_handler_t") Ptr<?> handler;

    public @Unsigned int irqs_per_chip;

    public @Unsigned int num_ct;

    public @Unsigned int irq_flags_to_clear;

    public @Unsigned int irq_flags_to_set;

    public irq_gc_flags gc_flags;

    public Ptr<?> init;

    public Ptr<?> exit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_domain_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_domain_info extends Struct {
    public Ptr<fwnode_handle> fwnode;

    public @Unsigned int domain_flags;

    public @Unsigned int size;

    public @Unsigned @OriginalName("irq_hw_number_t") long hwirq_max;

    public int direct_max;

    public @Unsigned int hwirq_base;

    public @Unsigned int virq_base;

    public irq_domain_bus_token bus_token;

    public String name_suffix;

    public Ptr<irq_domain_ops> ops;

    public Ptr<?> host_data;

    public Ptr<device> dev;

    public Ptr<irq_domain> parent;

    public Ptr<irq_domain_chip_generic_info> dgc_info;

    public Ptr<?> init;

    public Ptr<?> exit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_pin_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_pin_list extends Struct {
    public list_head list;

    public int apic;

    public int pin;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { enum kfunc_class_of_irq_of_anon_member_of_bpf_reg_state kfunc_class; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_of_anon_member_of_bpf_reg_state extends Struct {
    public kfunc_class_of_irq_of_anon_member_of_bpf_reg_state kfunc_class;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_devres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_devres extends Struct {
    public @Unsigned int irq;

    public Ptr<?> dev_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_desc_devres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_desc_devres extends Struct {
    public @Unsigned int from;

    public @Unsigned int cnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_generic_chip_devres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_generic_chip_devres extends Struct {
    public Ptr<irq_chip_generic> gc;

    public @Unsigned int msk;

    public @Unsigned int clr;

    public @Unsigned int set;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_sim_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_sim_ops extends Struct {
    public Ptr<?> irq_sim_irq_requested;

    public Ptr<?> irq_sim_irq_released;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_sim_work_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_sim_work_ctx extends Struct {
    public irq_work work;

    public @Unsigned int irq_count;

    public Ptr<java.lang. @Unsigned Long> pending;

    public Ptr<irq_domain> domain;

    public irq_sim_ops ops;

    public Ptr<?> user_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_sim_irq_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_sim_irq_ctx extends Struct {
    public boolean enabled;

    public Ptr<irq_sim_work_ctx> work_ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_affinity"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_affinity extends Struct {
    public @Unsigned int pre_vectors;

    public @Unsigned int post_vectors;

    public @Unsigned int nr_sets;

    public @Unsigned int @Size(4) [] set_size;

    public Ptr<?> calc_sets;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_matrix"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_matrix extends Struct {
    public @Unsigned int matrix_bits;

    public @Unsigned int alloc_start;

    public @Unsigned int alloc_end;

    public @Unsigned int alloc_size;

    public @Unsigned int global_available;

    public @Unsigned int global_reserved;

    public @Unsigned int systembits_inalloc;

    public @Unsigned int total_allocated;

    public @Unsigned int online_maps;

    public Ptr<cpumap> maps;

    public Ptr<java.lang. @Unsigned Long> system_map;

    public @Unsigned long @Size(0) [] scratch_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_poll"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_poll extends Struct {
    public list_head list;

    public @Unsigned long state;

    public int weight;

    public Ptr<?> poll;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_glue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_glue extends Struct {
    public irq_affinity_notify notify;

    public Ptr<cpu_rmap> rmap;

    public @Unsigned short index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int sense; unsigned int masked; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_of_sx150x_pinctrl extends Struct {
    public @Unsigned int sense;

    public @Unsigned int masked;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_override_cmp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_override_cmp extends Struct {
    public Ptr<dmi_system_id> system;

    public char irq;

    public char triggering;

    public char polarity;

    public char shareable;

    public boolean override;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_info extends Struct {
    public list_head list;

    public list_head eoi_list;

    public rcu_work rwork;

    public short refcnt;

    public char spurious_cnt;

    public char is_accounted;

    public short type;

    public char mask_reason;

    public char is_active;

    public @Unsigned int irq;

    public @Unsigned @OriginalName("evtchn_port_t") int evtchn;

    public @Unsigned short cpu;

    public @Unsigned short eoi_cpu;

    public @Unsigned int irq_epoch;

    public @Unsigned long eoi_time;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public boolean is_static;

    public u_of_irq_info u;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_remap_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_remap_table extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public @Unsigned int min_index;

    public Ptr<java.lang. @Unsigned Integer> table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_remap_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_remap_ops extends Struct {
    public int capability;

    public Ptr<?> prepare;

    public Ptr<?> enable;

    public Ptr<?> disable;

    public Ptr<?> reenable;

    public Ptr<?> enable_faulting;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum irq_remap_cap"
  )
  public enum irq_remap_cap implements Enum<irq_remap_cap>, TypedEnum<irq_remap_cap, java.lang. @Unsigned Integer> {
    /**
     * {@code IRQ_POSTING_CAP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IRQ_POSTING_CAP"
    )
    IRQ_POSTING_CAP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_affinity_devres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_affinity_devres extends Struct {
    public @Unsigned int count;

    public @Unsigned int @Size(0) [] irq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_routing_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_routing_table extends Struct {
    public @Unsigned int signature;

    public @Unsigned short version;

    public @Unsigned short size;

    public char rtr_bus;

    public char rtr_devfn;

    public @Unsigned short exclusive_irqs;

    public @Unsigned short rtr_vendor;

    public @Unsigned short rtr_device;

    public @Unsigned int miniport_data;

    public char @Size(11) [] rfu;

    public char checksum;

    public irq_info @Size(0) [] slots;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_router"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_router extends Struct {
    public String name;

    public @Unsigned short vendor;

    public @Unsigned short device;

    public Ptr<?> get;

    public Ptr<?> set;

    public Ptr<?> lvl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irq_router_handler"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irq_router_handler extends Struct {
    public @Unsigned short vendor;

    public Ptr<?> probe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct irqstat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class irqstat extends Struct {
    public @Unsigned int cnt;
  }
}
