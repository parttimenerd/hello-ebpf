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
 * Generated class for BPF runtime types that start with kvm
 */
@java.lang.SuppressWarnings("unused")
public final class KvmDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("uint32_t") int __kvm_cpuid_base() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __kvm_handle_async_pf(Ptr<pt_regs> regs, @Unsigned int token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int kvm_alloc_cpumask() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_apic_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int kvm_arch_para_features() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int kvm_arch_para_hints() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_async_pf_task_wait_schedule(@Unsigned int token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_async_pf_task_wake(@Unsigned int token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean kvm_check_and_clear_guest_paused() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long kvm_clock_get_cycles(Ptr<clocksource> cs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int kvm_cpu_down_prepare(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int kvm_cpu_online(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("uint32_t") int kvm_cpuid_base() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_crash_shutdown(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int kvm_cs_enable(Ptr<clocksource> cs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("uint32_t") int kvm_detect() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_disable_host_haltpoll(Ptr<?> i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_enable_host_haltpoll(Ptr<?> i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("kvm_flush_tlb_multi((const struct cpumask*)$arg1, (const struct flush_tlb_info*)$arg2)")
  public static void kvm_flush_tlb_multi(Ptr<cpumask> cpumask, Ptr<flush_tlb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long kvm_get_tsc_khz() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_get_wallclock(Ptr<timespec64> now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_guest_apic_eoi_write() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_guest_cpu_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_guest_cpu_offline(boolean shutdown) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_guest_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_init_platform() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_io_delay() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_kick_cpu(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean kvm_msi_ext_dest_id() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean kvm_para_available() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_pv_guest_cpu_reboot(Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int kvm_pv_reboot_notify(Ptr<notifier_block> nb, @Unsigned long code,
      Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int kvm_read_and_reset_apf_flags() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_register_clock(String txt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_restore_sched_clock_state() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_resume() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_save_sched_clock_state() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long kvm_sched_clock_read() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("kvm_send_ipi_mask((const struct cpumask*)$arg1, $arg2)")
  public static void kvm_send_ipi_mask(Ptr<cpumask> mask, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("kvm_send_ipi_mask_allbutself((const struct cpumask*)$arg1, $arg2)")
  public static void kvm_send_ipi_mask_allbutself(Ptr<cpumask> mask, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("kvm_set_posted_intr_wakeup_handler((void (*)())$arg1)")
  public static void kvm_set_posted_intr_wakeup_handler(Ptr<?> handler) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("kvm_set_wallclock((const struct timespec64*)$arg1)")
  public static int kvm_set_wallclock(Ptr<timespec64> now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_setup_secondary_clock() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int kvm_setup_vsyscall_timeinfo() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean kvm_sev_es_hcall_finish(Ptr<ghcb> ghcb, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_sev_es_hcall_prepare(Ptr<ghcb> ghcb, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_sev_hc_page_enc_status(@Unsigned long pfn, int npages, boolean enc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_smp_prepare_boot_cpu() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("kvm_smp_send_call_func_ipi((const struct cpumask*)$arg1)")
  public static void kvm_smp_send_call_func_ipi(Ptr<cpumask> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_spinlock_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long kvm_steal_clock(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int kvm_suspend() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void kvm_wait(Ptr<java.lang.Character> ptr, char val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_regs extends Struct {
    public @Unsigned long rax;

    public @Unsigned long rbx;

    public @Unsigned long rcx;

    public @Unsigned long rdx;

    public @Unsigned long rsi;

    public @Unsigned long rdi;

    public @Unsigned long rsp;

    public @Unsigned long rbp;

    public @Unsigned long r8;

    public @Unsigned long r9;

    public @Unsigned long r10;

    public @Unsigned long r11;

    public @Unsigned long r12;

    public @Unsigned long r13;

    public @Unsigned long r14;

    public @Unsigned long r15;

    public @Unsigned long rip;

    public @Unsigned long rflags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_segment"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_segment extends Struct {
    public @Unsigned long base;

    public @Unsigned int limit;

    public @Unsigned short selector;

    public char type;

    public char present;

    public char dpl;

    public char db;

    public char s;

    public char l;

    public char g;

    public char avl;

    public char unusable;

    public char padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_dtable"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_dtable extends Struct {
    public @Unsigned long base;

    public @Unsigned short limit;

    public @Unsigned short @Size(3) [] padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_sregs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_sregs extends Struct {
    public kvm_segment cs;

    public kvm_segment ds;

    public kvm_segment es;

    public kvm_segment fs;

    public kvm_segment gs;

    public kvm_segment ss;

    public kvm_segment tr;

    public kvm_segment ldt;

    public kvm_dtable gdt;

    public kvm_dtable idt;

    public @Unsigned long cr0;

    public @Unsigned long cr2;

    public @Unsigned long cr3;

    public @Unsigned long cr4;

    public @Unsigned long cr8;

    public @Unsigned long efer;

    public @Unsigned long apic_base;

    public @Unsigned long @Size(4) [] interrupt_bitmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_cpuid_entry2"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_cpuid_entry2 extends Struct {
    public @Unsigned int function;

    public @Unsigned int index;

    public @Unsigned int flags;

    public @Unsigned int eax;

    public @Unsigned int ebx;

    public @Unsigned int ecx;

    public @Unsigned int edx;

    public @Unsigned int @Size(3) [] padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_debug_exit_arch"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_debug_exit_arch extends Struct {
    public @Unsigned int exception;

    public @Unsigned int pad;

    public @Unsigned long pc;

    public @Unsigned long dr6;

    public @Unsigned long dr7;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_events"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_events extends Struct {
    public exception_of_kvm_vcpu_events exception;

    public interrupt_of_kvm_vcpu_events interrupt;

    public nmi_of_kvm_vcpu_events nmi;

    public @Unsigned int sipi_vector;

    public @Unsigned int flags;

    public smi_of_kvm_vcpu_events smi;

    public triple_fault_of_kvm_vcpu_events triple_fault;

    public char @Size(26) [] reserved;

    public char exception_has_payload;

    public @Unsigned long exception_payload;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_sync_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_sync_regs extends Struct {
    public kvm_regs regs;

    public kvm_sregs sregs;

    public kvm_vcpu_events events;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vmx_nested_state_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vmx_nested_state_data extends Struct {
    public char @Size(4096) [] vmcs12;

    public char @Size(4096) [] shadow_vmcs12;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vmx_nested_state_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vmx_nested_state_hdr extends Struct {
    public @Unsigned long vmxon_pa;

    public @Unsigned long vmcs12_pa;

    public smm_of_kvm_vmx_nested_state_hdr smm;

    public @Unsigned short pad;

    public @Unsigned int flags;

    public @Unsigned long preemption_timer_deadline;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_svm_nested_state_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_svm_nested_state_data extends Struct {
    public char @Size(4096) [] vmcb12;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_svm_nested_state_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_svm_nested_state_hdr extends Struct {
    public @Unsigned long vmcb_pa;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_nested_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_nested_state extends Struct {
    public @Unsigned short flags;

    public @Unsigned short format;

    public @Unsigned int size;

    public hdr_of_kvm_nested_state hdr;

    public data_of_kvm_nested_state data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_xen_hvm_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_xen_hvm_config extends Struct {
    public @Unsigned int flags;

    public @Unsigned int msr;

    public @Unsigned long blob_addr_32;

    public @Unsigned long blob_addr_64;

    public char blob_size_32;

    public char blob_size_64;

    public char @Size(30) [] pad2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_hyperv_exit"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_hyperv_exit extends Struct {
    public @Unsigned int type;

    public @Unsigned int pad1;

    public u_of_kvm_hyperv_exit u;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_xen_exit"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_xen_exit extends Struct {
    public @Unsigned int type;

    public u_of_kvm_xen_exit u;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_run"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_run extends Struct {
    public char request_interrupt_window;

    public char immediate_exit__unsafe;

    public char @Size(6) [] padding1;

    public @Unsigned int exit_reason;

    public char ready_for_interrupt_injection;

    public char if_flag;

    public @Unsigned short flags;

    public @Unsigned long cr8;

    public @Unsigned long apic_base;

    @InlineUnion(5191)
    public hw_of_anon_member_of_kvm_run hw;

    @InlineUnion(5191)
    public fail_entry_of_anon_member_of_kvm_run fail_entry;

    @InlineUnion(5191)
    public ex_of_anon_member_of_kvm_run ex;

    @InlineUnion(5191)
    public io_of_anon_member_of_kvm_run io;

    @InlineUnion(5191)
    public debug_of_anon_member_of_kvm_run debug;

    @InlineUnion(5191)
    public iocsr_io_of_anon_member_of_kvm_run_and_mmio_of_anon_member_of_kvm_run mmio;

    @InlineUnion(5191)
    public iocsr_io_of_anon_member_of_kvm_run_and_mmio_of_anon_member_of_kvm_run iocsr_io;

    @InlineUnion(5191)
    public hypercall_of_anon_member_of_kvm_run hypercall;

    @InlineUnion(5191)
    public tpr_access_of_anon_member_of_kvm_run tpr_access;

    @InlineUnion(5191)
    public s390_sieic_of_anon_member_of_kvm_run s390_sieic;

    @InlineUnion(5191)
    public @Unsigned long s390_reset_flags;

    @InlineUnion(5191)
    public s390_ucontrol_of_anon_member_of_kvm_run s390_ucontrol;

    @InlineUnion(5191)
    public dcr_of_anon_member_of_kvm_run dcr;

    @InlineUnion(5191)
    public internal_of_anon_member_of_kvm_run internal;

    @InlineUnion(5191)
    public emulation_failure_of_anon_member_of_kvm_run emulation_failure;

    @InlineUnion(5191)
    public osi_of_anon_member_of_kvm_run osi;

    @InlineUnion(5191)
    public papr_hcall_of_anon_member_of_kvm_run papr_hcall;

    @InlineUnion(5191)
    public s390_tsch_of_anon_member_of_kvm_run s390_tsch;

    @InlineUnion(5191)
    public epr_of_anon_member_of_kvm_run epr;

    @InlineUnion(5191)
    public system_event_of_anon_member_of_kvm_run system_event;

    @InlineUnion(5191)
    public s390_stsi_of_anon_member_of_kvm_run s390_stsi;

    @InlineUnion(5191)
    public eoi_of_anon_member_of_kvm_run eoi;

    @InlineUnion(5191)
    public kvm_hyperv_exit hyperv;

    @InlineUnion(5191)
    public arm_nisv_of_anon_member_of_kvm_run arm_nisv;

    @InlineUnion(5191)
    public msr_of_anon_member_of_kvm_run msr;

    @InlineUnion(5191)
    public kvm_xen_exit xen;

    @InlineUnion(5191)
    public riscv_sbi_of_anon_member_of_kvm_run riscv_sbi;

    @InlineUnion(5191)
    public riscv_csr_of_anon_member_of_kvm_run riscv_csr;

    @InlineUnion(5191)
    public notify_of_anon_member_of_kvm_run_and_v2_of_jailhouse_setup_data notify;

    @InlineUnion(5191)
    public memory_fault_of_anon_member_of_kvm_run memory_fault;

    @InlineUnion(5191)
    public tdx_of_anon_member_of_kvm_run tdx;

    @InlineUnion(5191)
    public char @Size(256) [] padding;

    public @Unsigned long kvm_valid_regs;

    public @Unsigned long kvm_dirty_regs;

    public s_of_kvm_run s;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_coalesced_mmio"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_coalesced_mmio extends Struct {
    public @Unsigned long phys_addr;

    public @Unsigned int len;

    @InlineUnion(5194)
    public @Unsigned int pad;

    @InlineUnion(5194)
    public @Unsigned int pio;

    public char @Size(8) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_coalesced_mmio_ring"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_coalesced_mmio_ring extends Struct {
    public @Unsigned int first;

    public @Unsigned int last;

    public kvm_coalesced_mmio @Size(0) [] coalesced_mmio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_enc_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_enc_region extends Struct {
    public @Unsigned long addr;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_dirty_gfn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_dirty_gfn extends Struct {
    public @Unsigned int flags;

    public @Unsigned int slot;

    public @Unsigned long offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_stats_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_stats_desc extends Struct {
    public @Unsigned int flags;

    public short exponent;

    public @Unsigned short size;

    public @Unsigned int offset;

    public @Unsigned int bucket_size;

    public char @Size(0) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_memory_slot"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_memory_slot extends Struct {
    public hlist_node @Size(2) [] id_node;

    public interval_tree_node @Size(2) [] hva_node;

    public rb_node @Size(2) [] gfn_node;

    public @Unsigned @OriginalName("gfn_t") long base_gfn;

    public @Unsigned long npages;

    public Ptr<java.lang. @Unsigned Long> dirty_bitmap;

    public kvm_arch_memory_slot arch;

    public @Unsigned long userspace_addr;

    public @Unsigned int flags;

    public short id;

    public @Unsigned short as_id;

    public gmem_of_kvm_memory_slot gmem;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_mmu_memory_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_mmu_memory_cache extends Struct {
    public @Unsigned @OriginalName("gfp_t") int gfp_zero;

    public @Unsigned @OriginalName("gfp_t") int gfp_custom;

    public @Unsigned long init_value;

    public Ptr<kmem_cache> kmem_cache;

    public int capacity;

    public int nobjs;

    public Ptr<Ptr<?>> objects;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vm_stat_generic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vm_stat_generic extends Struct {
    public @Unsigned long remote_tlb_flush;

    public @Unsigned long remote_tlb_flush_requests;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_stat_generic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_stat_generic extends Struct {
    public @Unsigned long halt_successful_poll;

    public @Unsigned long halt_attempted_poll;

    public @Unsigned long halt_poll_invalid;

    public @Unsigned long halt_wakeup;

    public @Unsigned long halt_poll_success_ns;

    public @Unsigned long halt_poll_fail_ns;

    public @Unsigned long halt_wait_ns;

    public @Unsigned long @Size(32) [] halt_poll_success_hist;

    public @Unsigned long @Size(32) [] halt_poll_fail_hist;

    public @Unsigned long @Size(32) [] halt_wait_hist;

    public @Unsigned long blocking;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_page_track_notifier_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_page_track_notifier_head extends Struct {
    public srcu_struct track_srcu;

    public hlist_head track_notifier_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum kvm_reg"
  )
  public enum kvm_reg implements Enum<kvm_reg>, TypedEnum<kvm_reg, java.lang. @Unsigned Integer> {
    /**
     * {@code VCPU_REGS_RAX = 0}
     */
    @EnumMember(
        value = 0L,
        name = "VCPU_REGS_RAX"
    )
    VCPU_REGS_RAX,

    /**
     * {@code VCPU_REGS_RCX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "VCPU_REGS_RCX"
    )
    VCPU_REGS_RCX,

    /**
     * {@code VCPU_REGS_RDX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "VCPU_REGS_RDX"
    )
    VCPU_REGS_RDX,

    /**
     * {@code VCPU_REGS_RBX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "VCPU_REGS_RBX"
    )
    VCPU_REGS_RBX,

    /**
     * {@code VCPU_REGS_RSP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "VCPU_REGS_RSP"
    )
    VCPU_REGS_RSP,

    /**
     * {@code VCPU_REGS_RBP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "VCPU_REGS_RBP"
    )
    VCPU_REGS_RBP,

    /**
     * {@code VCPU_REGS_RSI = 6}
     */
    @EnumMember(
        value = 6L,
        name = "VCPU_REGS_RSI"
    )
    VCPU_REGS_RSI,

    /**
     * {@code VCPU_REGS_RDI = 7}
     */
    @EnumMember(
        value = 7L,
        name = "VCPU_REGS_RDI"
    )
    VCPU_REGS_RDI,

    /**
     * {@code VCPU_REGS_R8 = 8}
     */
    @EnumMember(
        value = 8L,
        name = "VCPU_REGS_R8"
    )
    VCPU_REGS_R8,

    /**
     * {@code VCPU_REGS_R9 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "VCPU_REGS_R9"
    )
    VCPU_REGS_R9,

    /**
     * {@code VCPU_REGS_R10 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "VCPU_REGS_R10"
    )
    VCPU_REGS_R10,

    /**
     * {@code VCPU_REGS_R11 = 11}
     */
    @EnumMember(
        value = 11L,
        name = "VCPU_REGS_R11"
    )
    VCPU_REGS_R11,

    /**
     * {@code VCPU_REGS_R12 = 12}
     */
    @EnumMember(
        value = 12L,
        name = "VCPU_REGS_R12"
    )
    VCPU_REGS_R12,

    /**
     * {@code VCPU_REGS_R13 = 13}
     */
    @EnumMember(
        value = 13L,
        name = "VCPU_REGS_R13"
    )
    VCPU_REGS_R13,

    /**
     * {@code VCPU_REGS_R14 = 14}
     */
    @EnumMember(
        value = 14L,
        name = "VCPU_REGS_R14"
    )
    VCPU_REGS_R14,

    /**
     * {@code VCPU_REGS_R15 = 15}
     */
    @EnumMember(
        value = 15L,
        name = "VCPU_REGS_R15"
    )
    VCPU_REGS_R15,

    /**
     * {@code VCPU_REGS_RIP = 16}
     */
    @EnumMember(
        value = 16L,
        name = "VCPU_REGS_RIP"
    )
    VCPU_REGS_RIP,

    /**
     * {@code NR_VCPU_REGS = 17}
     */
    @EnumMember(
        value = 17L,
        name = "NR_VCPU_REGS"
    )
    NR_VCPU_REGS,

    /**
     * {@code VCPU_EXREG_PDPTR = 17}
     */
    @EnumMember(
        value = 17L,
        name = "VCPU_EXREG_PDPTR"
    )
    VCPU_EXREG_PDPTR,

    /**
     * {@code VCPU_EXREG_CR0 = 18}
     */
    @EnumMember(
        value = 18L,
        name = "VCPU_EXREG_CR0"
    )
    VCPU_EXREG_CR0,

    /**
     * {@code VCPU_EXREG_CR3 = 19}
     */
    @EnumMember(
        value = 19L,
        name = "VCPU_EXREG_CR3"
    )
    VCPU_EXREG_CR3,

    /**
     * {@code VCPU_EXREG_CR4 = 20}
     */
    @EnumMember(
        value = 20L,
        name = "VCPU_EXREG_CR4"
    )
    VCPU_EXREG_CR4,

    /**
     * {@code VCPU_EXREG_RFLAGS = 21}
     */
    @EnumMember(
        value = 21L,
        name = "VCPU_EXREG_RFLAGS"
    )
    VCPU_EXREG_RFLAGS,

    /**
     * {@code VCPU_EXREG_SEGMENTS = 22}
     */
    @EnumMember(
        value = 22L,
        name = "VCPU_EXREG_SEGMENTS"
    )
    VCPU_EXREG_SEGMENTS,

    /**
     * {@code VCPU_EXREG_EXIT_INFO_1 = 23}
     */
    @EnumMember(
        value = 23L,
        name = "VCPU_EXREG_EXIT_INFO_1"
    )
    VCPU_EXREG_EXIT_INFO_1,

    /**
     * {@code VCPU_EXREG_EXIT_INFO_2 = 24}
     */
    @EnumMember(
        value = 24L,
        name = "VCPU_EXREG_EXIT_INFO_2"
    )
    VCPU_EXREG_EXIT_INFO_2
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union kvm_mmu_page_role"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_mmu_page_role extends Union {
    public @Unsigned int word;

    public anon_member_of_kvm_mmu_page_role anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union kvm_mmu_extended_role"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_mmu_extended_role extends Union {
    public @Unsigned int word;

    public anon_member_of_kvm_mmu_extended_role anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union kvm_cpu_role"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_cpu_role extends Union {
    public @Unsigned long as_u64;

    public anon_member_of_kvm_cpu_role anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_rmap_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_rmap_head extends Struct {
    public @OriginalName("atomic_long_t") atomic64_t val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_pio_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_pio_request extends Struct {
    public @Unsigned long count;

    public int in;

    public int port;

    public int size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_mmu_root_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_mmu_root_info extends Struct {
    public @Unsigned @OriginalName("gpa_t") long pgd;

    public @Unsigned @OriginalName("hpa_t") long hpa;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_mmu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_mmu extends Struct {
    public Ptr<?> get_guest_pgd;

    public Ptr<?> get_pdptr;

    public Ptr<?> page_fault;

    public Ptr<?> inject_page_fault;

    public Ptr<?> gva_to_gpa;

    public Ptr<?> sync_spte;

    public kvm_mmu_root_info root;

    public @Unsigned @OriginalName("hpa_t") long mirror_root_hpa;

    public kvm_cpu_role cpu_role;

    public kvm_mmu_page_role root_role;

    public @Unsigned int pkru_mask;

    public kvm_mmu_root_info @Size(3) [] prev_roots;

    public char @Size(16) [] permissions;

    public Ptr<java.lang. @Unsigned Long> pae_root;

    public Ptr<java.lang. @Unsigned Long> pml4_root;

    public Ptr<java.lang. @Unsigned Long> pml5_root;

    public rsvd_bits_validate shadow_zero_check;

    public rsvd_bits_validate guest_rsvd_check;

    public @Unsigned long @Size(4) [] pdptrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu extends Struct {
    public Ptr<kvm> kvm;

    public preempt_notifier preempt_notifier;

    public int cpu;

    public int vcpu_id;

    public int vcpu_idx;

    public int ____srcu_idx;

    public int mode;

    public @Unsigned long requests;

    public @Unsigned long guest_debug;

    public mutex mutex;

    public Ptr<kvm_run> run;

    public rcuwait wait;

    public Ptr<pid> pid;

    public rwlock_t pid_lock;

    public int sigset_active;

    public sigset_t sigset;

    public @Unsigned int halt_poll_ns;

    public boolean valid_wakeup;

    public int mmio_needed;

    public int mmio_read_completed;

    public int mmio_is_write;

    public int mmio_cur_fragment;

    public int mmio_nr_fragments;

    public kvm_mmio_fragment @Size(2) [] mmio_fragments;

    public async_pf_of_kvm_vcpu async_pf;

    public spin_loop_of_kvm_vcpu spin_loop;

    public boolean wants_to_run;

    public boolean preempted;

    public boolean ready;

    public boolean scheduled_out;

    public kvm_vcpu_arch arch;

    public kvm_vcpu_stat stat;

    public char @Size(48) [] stats_id;

    public kvm_dirty_ring dirty_ring;

    public Ptr<kvm_memory_slot> last_used_slot;

    public @Unsigned long last_used_slot_gen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_pmc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_pmc extends Struct {
    public pmc_type type;

    public char idx;

    public boolean is_paused;

    public boolean intr;

    public @Unsigned long counter;

    public @Unsigned long emulated_counter;

    public @Unsigned long eventsel;

    public Ptr<perf_event> perf_event;

    public Ptr<kvm_vcpu> vcpu;

    public @Unsigned long current_config;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_pmu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_pmu extends Struct {
    public char version;

    public @Unsigned int nr_arch_gp_counters;

    public @Unsigned int nr_arch_fixed_counters;

    public @Unsigned int available_event_types;

    public @Unsigned long fixed_ctr_ctrl;

    public @Unsigned long fixed_ctr_ctrl_rsvd;

    public @Unsigned long global_ctrl;

    public @Unsigned long global_status;

    public @Unsigned long @Size(2) [] counter_bitmask;

    public @Unsigned long global_ctrl_rsvd;

    public @Unsigned long global_status_rsvd;

    public @Unsigned long reserved_bits;

    public @Unsigned long raw_event_mask;

    public kvm_pmc @Size(8) [] gp_counters;

    public kvm_pmc @Size(3) [] fixed_counters;

    @InlineUnion(5289)
    public @Unsigned long @Size(1) [] reprogram_pmi;

    @InlineUnion(5289)
    public atomic64_t __reprogram_pmi;

    public @Unsigned long @Size(1) [] all_valid_pmc_idx;

    public @Unsigned long @Size(1) [] pmc_in_use;

    public @Unsigned long ds_area;

    public @Unsigned long pebs_enable;

    public @Unsigned long pebs_enable_rsvd;

    public @Unsigned long pebs_data_cfg;

    public @Unsigned long pebs_data_cfg_rsvd;

    public @Unsigned long host_cross_mapped_mask;

    public boolean need_cleanup;

    public char event_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_mtrr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_mtrr extends Struct {
    public @Unsigned long @Size(16) [] var;

    public @Unsigned long fixed_64k;

    public @Unsigned long @Size(2) [] fixed_16k;

    public @Unsigned long @Size(8) [] fixed_4k;

    public @Unsigned long deftype;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_hv_stimer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_hv_stimer extends Struct {
    public hrtimer timer;

    public int index;

    public hv_stimer_config config;

    public @Unsigned long count;

    public @Unsigned long exp_time;

    public hv_message msg;

    public boolean msg_pending;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_hv_synic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_hv_synic extends Struct {
    public @Unsigned long version;

    public @Unsigned long control;

    public @Unsigned long msg_page;

    public @Unsigned long evt_page;

    public atomic64_t @Size(16) [] sint;

    public atomic_t @Size(16) [] sint_to_gsi;

    public @Unsigned long @Size(4) [] auto_eoi_bitmap;

    public @Unsigned long @Size(4) [] vec_bitmap;

    public boolean active;

    public boolean dont_zero_synic_pages;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_hv_tlb_flush_fifo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_hv_tlb_flush_fifo extends Struct {
    public @OriginalName("spinlock_t") spinlock write_lock;

    public entries_of_kvm_vcpu_hv_tlb_flush_fifo entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_hv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_hv extends Struct {
    public Ptr<kvm_vcpu> vcpu;

    public @Unsigned int vp_index;

    public @Unsigned long hv_vapic;

    public long runtime_offset;

    public kvm_vcpu_hv_synic synic;

    public kvm_hyperv_exit exit;

    public kvm_vcpu_hv_stimer @Size(4) [] stimer;

    public @Unsigned long @Size(1) [] stimer_pending_bitmap;

    public boolean enforce_cpuid;

    public cpuid_cache_of_kvm_vcpu_hv cpuid_cache;

    public kvm_vcpu_hv_tlb_flush_fifo @Size(2) [] tlb_flush_fifo;

    public @Unsigned long @Size(64) [] sparse_banks;

    public @Unsigned long @Size(64) [] vcpu_mask;

    public hv_vp_assist_page vp_assist_page;

    public nested_of_kvm_vcpu_hv nested;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_hypervisor_cpuid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_hypervisor_cpuid extends Struct {
    public @Unsigned int base;

    public @Unsigned int limit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_xen"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_xen extends Struct {
    public @Unsigned long hypercall_rip;

    public @Unsigned int current_runstate;

    public char upcall_vector;

    public gfn_to_pfn_cache vcpu_info_cache;

    public gfn_to_pfn_cache vcpu_time_info_cache;

    public gfn_to_pfn_cache runstate_cache;

    public gfn_to_pfn_cache runstate2_cache;

    public @Unsigned long last_steal;

    public @Unsigned long runstate_entry_time;

    public @Unsigned long @Size(4) [] runstate_times;

    public @Unsigned long evtchn_pending_sel;

    public @Unsigned int vcpu_id;

    public @Unsigned int timer_virq;

    public @Unsigned long timer_expires;

    public atomic_t timer_pending;

    public hrtimer timer;

    public int poll_evtchn;

    public timer_list poll_timer;

    public kvm_hypervisor_cpuid cpuid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_queued_exception"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_queued_exception extends Struct {
    public boolean pending;

    public boolean injected;

    public boolean has_error_code;

    public char vector;

    public @Unsigned int error_code;

    public @Unsigned long payload;

    public boolean has_payload;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum kvm_only_cpuid_leafs"
  )
  public enum kvm_only_cpuid_leafs implements Enum<kvm_only_cpuid_leafs>, TypedEnum<kvm_only_cpuid_leafs, java.lang. @Unsigned Integer> {
    /**
     * {@code CPUID_12_EAX = 22}
     */
    @EnumMember(
        value = 22L,
        name = "CPUID_12_EAX"
    )
    CPUID_12_EAX,

    /**
     * {@code CPUID_7_1_EDX = 23}
     */
    @EnumMember(
        value = 23L,
        name = "CPUID_7_1_EDX"
    )
    CPUID_7_1_EDX,

    /**
     * {@code CPUID_8000_0007_EDX = 24}
     */
    @EnumMember(
        value = 24L,
        name = "CPUID_8000_0007_EDX"
    )
    CPUID_8000_0007_EDX,

    /**
     * {@code CPUID_8000_0022_EAX = 25}
     */
    @EnumMember(
        value = 25L,
        name = "CPUID_8000_0022_EAX"
    )
    CPUID_8000_0022_EAX,

    /**
     * {@code CPUID_7_2_EDX = 26}
     */
    @EnumMember(
        value = 26L,
        name = "CPUID_7_2_EDX"
    )
    CPUID_7_2_EDX,

    /**
     * {@code CPUID_24_0_EBX = 27}
     */
    @EnumMember(
        value = 27L,
        name = "CPUID_24_0_EBX"
    )
    CPUID_24_0_EBX,

    /**
     * {@code CPUID_8000_0021_ECX = 28}
     */
    @EnumMember(
        value = 28L,
        name = "CPUID_8000_0021_ECX"
    )
    CPUID_8000_0021_ECX,

    /**
     * {@code NR_KVM_CPU_CAPS = 29}
     */
    @EnumMember(
        value = 29L,
        name = "NR_KVM_CPU_CAPS"
    )
    NR_KVM_CPU_CAPS,

    /**
     * {@code NKVMCAPINTS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "NKVMCAPINTS"
    )
    NKVMCAPINTS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_queued_interrupt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_queued_interrupt extends Struct {
    public boolean injected;

    public boolean soft;

    public char nr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_arch"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_arch extends Struct {
    public @Unsigned long @Size(17) [] regs;

    public @Unsigned int regs_avail;

    public @Unsigned int regs_dirty;

    public @Unsigned long cr0;

    public @Unsigned long cr0_guest_owned_bits;

    public @Unsigned long cr2;

    public @Unsigned long cr3;

    public @Unsigned long cr4;

    public @Unsigned long cr4_guest_owned_bits;

    public @Unsigned long cr4_guest_rsvd_bits;

    public @Unsigned long cr8;

    public @Unsigned int host_pkru;

    public @Unsigned int pkru;

    public @Unsigned int hflags;

    public @Unsigned long efer;

    public @Unsigned long host_debugctl;

    public @Unsigned long apic_base;

    public @OriginalName("kvm_lapic") Ptr<?> apic;

    public boolean load_eoi_exitmap_pending;

    public @Unsigned long @Size(4) [] ioapic_handled_vectors;

    public @Unsigned long apic_attention;

    public @OriginalName("int32_t") int apic_arb_prio;

    public int mp_state;

    public @Unsigned long ia32_misc_enable_msr;

    public @Unsigned long smbase;

    public @Unsigned long smi_count;

    public boolean at_instruction_boundary;

    public boolean tpr_access_reporting;

    public boolean xfd_no_write_intercept;

    public @Unsigned long ia32_xss;

    public @Unsigned long microcode_version;

    public @Unsigned long arch_capabilities;

    public @Unsigned long perf_capabilities;

    public Ptr<kvm_mmu> mmu;

    public kvm_mmu root_mmu;

    public kvm_mmu guest_mmu;

    public kvm_mmu nested_mmu;

    public Ptr<kvm_mmu> walk_mmu;

    public kvm_mmu_memory_cache mmu_pte_list_desc_cache;

    public kvm_mmu_memory_cache mmu_shadow_page_cache;

    public kvm_mmu_memory_cache mmu_shadowed_info_cache;

    public kvm_mmu_memory_cache mmu_page_header_cache;

    public kvm_mmu_memory_cache mmu_external_spt_cache;

    public fpu_guest guest_fpu;

    public @Unsigned long xcr0;

    public @Unsigned long guest_supported_xcr0;

    public kvm_pio_request pio;

    public Ptr<?> pio_data;

    public Ptr<?> sev_pio_data;

    public @Unsigned int sev_pio_count;

    public char event_exit_inst_len;

    public boolean exception_from_userspace;

    public kvm_queued_exception exception;

    public kvm_queued_exception exception_vmexit;

    public kvm_queued_interrupt interrupt;

    public int halt_request;

    public int cpuid_nent;

    public Ptr<kvm_cpuid_entry2> cpuid_entries;

    public boolean cpuid_dynamic_bits_dirty;

    public boolean is_amd_compatible;

    public @Unsigned int @Size(29) [] cpu_caps;

    public @Unsigned long reserved_gpa_bits;

    public int maxphyaddr;

    public @OriginalName("x86_emulate_ctxt") Ptr<?> emulate_ctxt;

    public boolean emulate_regs_need_sync_to_vcpu;

    public boolean emulate_regs_need_sync_from_vcpu;

    public Ptr<?> complete_userspace_io;

    public @Unsigned long cui_linear_rip;

    public int cui_rdmsr_imm_reg;

    public @Unsigned @OriginalName("gpa_t") long time;

    public @OriginalName("s8") byte pvclock_tsc_shift;

    public @Unsigned int pvclock_tsc_mul;

    public @Unsigned int hw_tsc_khz;

    public gfn_to_pfn_cache pv_time;

    public boolean pvclock_set_guest_stopped_request;

    public st_of_kvm_vcpu_arch st;

    public @Unsigned long l1_tsc_offset;

    public @Unsigned long tsc_offset;

    public @Unsigned long last_guest_tsc;

    public @Unsigned long last_host_tsc;

    public @Unsigned long tsc_offset_adjustment;

    public @Unsigned long this_tsc_nsec;

    public @Unsigned long this_tsc_write;

    public @Unsigned long this_tsc_generation;

    public boolean tsc_catchup;

    public boolean tsc_always_catchup;

    public @OriginalName("s8") byte virtual_tsc_shift;

    public @Unsigned int virtual_tsc_mult;

    public @Unsigned int virtual_tsc_khz;

    public long ia32_tsc_adjust_msr;

    public @Unsigned long msr_ia32_power_ctl;

    public @Unsigned long l1_tsc_scaling_ratio;

    public @Unsigned long tsc_scaling_ratio;

    public atomic_t nmi_queued;

    public @Unsigned int nmi_pending;

    public boolean nmi_injected;

    public boolean smi_pending;

    public char handling_intr_from_guest;

    public kvm_mtrr mtrr_state;

    public @Unsigned long pat;

    public @Unsigned int switch_db_regs;

    public @Unsigned long @Size(4) [] db;

    public @Unsigned long dr6;

    public @Unsigned long dr7;

    public @Unsigned long @Size(4) [] eff_db;

    public @Unsigned long guest_debug_dr7;

    public @Unsigned long msr_platform_info;

    public @Unsigned long msr_misc_features_enables;

    public @Unsigned long mcg_cap;

    public @Unsigned long mcg_status;

    public @Unsigned long mcg_ctl;

    public @Unsigned long mcg_ext_ctl;

    public Ptr<java.lang. @Unsigned Long> mce_banks;

    public Ptr<java.lang. @Unsigned Long> mci_ctl2_banks;

    public @Unsigned long mmio_gva;

    public @Unsigned int mmio_access;

    public @Unsigned @OriginalName("gfn_t") long mmio_gfn;

    public @Unsigned long mmio_gen;

    public kvm_pmu pmu;

    public @Unsigned long singlestep_rip;

    public boolean hyperv_enabled;

    public Ptr<kvm_vcpu_hv> hyperv;

    public kvm_vcpu_xen xen;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> wbinvd_dirty_mask;

    public @Unsigned long last_retry_eip;

    public @Unsigned long last_retry_addr;

    public apf_of_kvm_vcpu_arch apf;

    public osvw_of_kvm_vcpu_arch osvw;

    public pv_eoi_of_kvm_vcpu_arch pv_eoi;

    public @Unsigned long msr_kvm_poll_control;

    public pv_of_kvm_vcpu_arch pv;

    public int pending_ioapic_eoi;

    public int pending_external_vector;

    public int highest_stale_pending_ioapic_eoi;

    public boolean preempted_in_kernel;

    public boolean l1tf_flush_l1d;

    public int last_vmentry_cpu;

    public @Unsigned long msr_hwcr;

    public pv_cpuid_of_kvm_vcpu_arch pv_cpuid;

    public boolean guest_state_protected;

    public boolean guest_tsc_protected;

    public boolean pdptrs_from_userspace;

    public @Unsigned @OriginalName("hpa_t") long hv_root_tdp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_lpage_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_lpage_info extends Struct {
    public int disallow_lpage;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_arch_memory_slot"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_arch_memory_slot extends Struct {
    public Ptr<kvm_rmap_head> @Size(3) [] rmap;

    public Ptr<kvm_lpage_info> @Size(2) [] lpage_info;

    public Ptr<java.lang. @Unsigned Short> gfn_write_track;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum kvm_apic_logical_mode"
  )
  public enum kvm_apic_logical_mode implements Enum<kvm_apic_logical_mode>, TypedEnum<kvm_apic_logical_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code KVM_APIC_MODE_SW_DISABLED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "KVM_APIC_MODE_SW_DISABLED"
    )
    KVM_APIC_MODE_SW_DISABLED,

    /**
     * {@code KVM_APIC_MODE_XAPIC_CLUSTER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "KVM_APIC_MODE_XAPIC_CLUSTER"
    )
    KVM_APIC_MODE_XAPIC_CLUSTER,

    /**
     * {@code KVM_APIC_MODE_XAPIC_FLAT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "KVM_APIC_MODE_XAPIC_FLAT"
    )
    KVM_APIC_MODE_XAPIC_FLAT,

    /**
     * {@code KVM_APIC_MODE_X2APIC = 3}
     */
    @EnumMember(
        value = 3L,
        name = "KVM_APIC_MODE_X2APIC"
    )
    KVM_APIC_MODE_X2APIC,

    /**
     * {@code KVM_APIC_MODE_MAP_DISABLED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "KVM_APIC_MODE_MAP_DISABLED"
    )
    KVM_APIC_MODE_MAP_DISABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_apic_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_apic_map extends Struct {
    public callback_head rcu;

    public kvm_apic_logical_mode logical_mode;

    public @Unsigned int max_apic_id;

    @InlineUnion(5339)
    public @OriginalName("kvm_lapic") Ptr<?> @Size(8) [] xapic_flat_map;

    @InlineUnion(5339)
    public @OriginalName("kvm_lapic") Ptr<?> @Size(64) [] xapic_cluster_map;

    public @OriginalName("kvm_lapic") Ptr<?> @Size(0) [] phys_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_hv_syndbg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_hv_syndbg extends Struct {
    public control_of_kvm_hv_syndbg control;

    public @Unsigned long options;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_hv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_hv extends Struct {
    public mutex hv_lock;

    public @Unsigned long hv_guest_os_id;

    public @Unsigned long hv_hypercall;

    public @Unsigned long hv_tsc_page;

    public hv_tsc_page_status hv_tsc_page_status;

    public @Unsigned long @Size(5) [] hv_crash_param;

    public @Unsigned long hv_crash_ctl;

    public ms_hyperv_tsc_page tsc_ref;

    public idr conn_to_evt;

    public @Unsigned long hv_reenlightenment_control;

    public @Unsigned long hv_tsc_emulation_control;

    public @Unsigned long hv_tsc_emulation_status;

    public @Unsigned long hv_invtsc_control;

    public atomic_t num_mismatched_vp_indexes;

    public @Unsigned int synic_auto_eoi_used;

    public kvm_hv_syndbg hv_syndbg;

    public boolean xsaves_xsavec_checked;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_xen"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_xen extends Struct {
    public mutex xen_lock;

    public @Unsigned int xen_version;

    public boolean long_mode;

    public boolean runstate_update_flag;

    public char upcall_vector;

    public gfn_to_pfn_cache shinfo_cache;

    public idr evtchn_ports;

    public @Unsigned long @Size(64) [] poll_mask;

    public kvm_xen_hvm_config hvm_config;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum kvm_irqchip_mode"
  )
  public enum kvm_irqchip_mode implements Enum<kvm_irqchip_mode>, TypedEnum<kvm_irqchip_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code KVM_IRQCHIP_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "KVM_IRQCHIP_NONE"
    )
    KVM_IRQCHIP_NONE,

    /**
     * {@code KVM_IRQCHIP_KERNEL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "KVM_IRQCHIP_KERNEL"
    )
    KVM_IRQCHIP_KERNEL,

    /**
     * {@code KVM_IRQCHIP_SPLIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "KVM_IRQCHIP_SPLIT"
    )
    KVM_IRQCHIP_SPLIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_x86_msr_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_x86_msr_filter extends Struct {
    public char count;

    public boolean default_allow;

    public msr_bitmap_range @Size(16) [] ranges;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_x86_pmu_event_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_x86_pmu_event_filter extends Struct {
    public @Unsigned int action;

    public @Unsigned int nevents;

    public @Unsigned int fixed_counter_bitmap;

    public @Unsigned int flags;

    public @Unsigned int nr_includes;

    public @Unsigned int nr_excludes;

    public Ptr<java.lang. @Unsigned Long> includes;

    public Ptr<java.lang. @Unsigned Long> excludes;

    public @Unsigned long @Size(0) [] events;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_arch"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_arch extends Struct {
    public @Unsigned long n_used_mmu_pages;

    public @Unsigned long n_requested_mmu_pages;

    public @Unsigned long n_max_mmu_pages;

    public @Unsigned int indirect_shadow_pages;

    public char mmu_valid_gen;

    public char vm_type;

    public boolean has_private_mem;

    public boolean has_protected_state;

    public boolean pre_fault_allowed;

    public Ptr<hlist_head> mmu_page_hash;

    public list_head active_mmu_pages;

    public list_head possible_nx_huge_pages;

    public kvm_page_track_notifier_head track_notifier_head;

    public @OriginalName("spinlock_t") spinlock mmu_unsync_pages_lock;

    public @Unsigned long shadow_mmio_value;

    public atomic_t noncoherent_dma_count;

    public @Unsigned long nr_possible_bypass_irqs;

    public @OriginalName("kvm_pic") Ptr<?> vpic;

    public @OriginalName("kvm_ioapic") Ptr<?> vioapic;

    public @OriginalName("kvm_pit") Ptr<?> vpit;

    public atomic_t vapics_in_nmi_mode;

    public mutex apic_map_lock;

    public Ptr<kvm_apic_map> apic_map;

    public atomic_t apic_map_dirty;

    public boolean apic_access_memslot_enabled;

    public boolean apic_access_memslot_inhibited;

    public rw_semaphore apicv_update_lock;

    public @Unsigned long apicv_inhibit_reasons;

    public @Unsigned @OriginalName("gpa_t") long wall_clock;

    public @Unsigned long disabled_exits;

    public long kvmclock_offset;

    public @OriginalName("raw_spinlock_t") raw_spinlock tsc_write_lock;

    public @Unsigned long last_tsc_nsec;

    public @Unsigned long last_tsc_write;

    public @Unsigned int last_tsc_khz;

    public @Unsigned long last_tsc_offset;

    public @Unsigned long cur_tsc_nsec;

    public @Unsigned long cur_tsc_write;

    public @Unsigned long cur_tsc_offset;

    public @Unsigned long cur_tsc_generation;

    public int nr_vcpus_matched_tsc;

    public @Unsigned int default_tsc_khz;

    public boolean user_set_tsc;

    public @Unsigned long apic_bus_cycle_ns;

    public @OriginalName("seqcount_raw_spinlock_t") seqcount_raw_spinlock pvclock_sc;

    public boolean use_master_clock;

    public @Unsigned long master_kernel_ns;

    public @Unsigned long master_cycle_now;

    public delayed_work kvmclock_update_work;

    public delayed_work kvmclock_sync_work;

    public kvm_hv hyperv;

    public kvm_xen xen;

    public boolean backwards_tsc_observed;

    public boolean boot_vcpu_runs_old_kvmclock;

    public @Unsigned int bsp_vcpu_id;

    public @Unsigned long disabled_quirks;

    public kvm_irqchip_mode irqchip_mode;

    public char nr_reserved_ioapic_pins;

    public boolean disabled_lapic_found;

    public boolean x2apic_format;

    public boolean x2apic_broadcast_quirk_disabled;

    public boolean has_mapped_host_mmio;

    public boolean guest_can_read_msr_platform_info;

    public boolean exception_payload_enabled;

    public boolean triple_fault_event;

    public boolean bus_lock_detection_enabled;

    public boolean enable_pmu;

    public @Unsigned int notify_window;

    public @Unsigned int notify_vmexit_flags;

    public boolean exit_on_emulation_error;

    public @Unsigned int user_space_msr_mask;

    public Ptr<kvm_x86_msr_filter> msr_filter;

    public @Unsigned int hypercall_exit_enabled;

    public boolean sgx_provisioning_allowed;

    public Ptr<kvm_x86_pmu_event_filter> pmu_event_filter;

    public Ptr<vhost_task> nx_huge_page_recovery_thread;

    public @Unsigned long nx_huge_page_last;

    public once nx_once;

    public list_head tdp_mmu_roots;

    public @OriginalName("spinlock_t") spinlock tdp_mmu_pages_lock;

    public boolean shadow_root_allocated;

    public boolean external_write_tracking_enabled;

    public @Unsigned @OriginalName("hpa_t") long hv_root_tdp;

    public @OriginalName("spinlock_t") spinlock hv_root_tdp_lock;

    public Ptr<hv_partition_assist_pg> hv_pa_pg;

    public @Unsigned int max_vcpu_ids;

    public boolean disable_nx_huge_pages;

    public kvm_mmu_memory_cache split_shadow_page_cache;

    public kvm_mmu_memory_cache split_page_header_cache;

    public kvm_mmu_memory_cache split_desc_cache;

    public @Unsigned @OriginalName("gfn_t") long gfn_direct_bits;

    public int cpu_dirty_log_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vm_stat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vm_stat extends Struct {
    public kvm_vm_stat_generic generic;

    public @Unsigned long mmu_shadow_zapped;

    public @Unsigned long mmu_pte_write;

    public @Unsigned long mmu_pde_zapped;

    public @Unsigned long mmu_flooded;

    public @Unsigned long mmu_recycled;

    public @Unsigned long mmu_cache_miss;

    public @Unsigned long mmu_unsync;

    @InlineUnion(5367)
    public anon_member_of_anon_member_of_kvm_vm_stat anon8$0;

    @InlineUnion(5367)
    public atomic64_t @Size(3) [] pages;

    public @Unsigned long nx_lpage_splits;

    public @Unsigned long max_mmu_page_hash_collisions;

    public @Unsigned long max_mmu_rmap_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_stat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_stat extends Struct {
    public kvm_vcpu_stat_generic generic;

    public @Unsigned long pf_taken;

    public @Unsigned long pf_fixed;

    public @Unsigned long pf_emulate;

    public @Unsigned long pf_spurious;

    public @Unsigned long pf_fast;

    public @Unsigned long pf_mmio_spte_created;

    public @Unsigned long pf_guest;

    public @Unsigned long tlb_flush;

    public @Unsigned long invlpg;

    public @Unsigned long exits;

    public @Unsigned long io_exits;

    public @Unsigned long mmio_exits;

    public @Unsigned long signal_exits;

    public @Unsigned long irq_window_exits;

    public @Unsigned long nmi_window_exits;

    public @Unsigned long l1d_flush;

    public @Unsigned long halt_exits;

    public @Unsigned long request_irq_exits;

    public @Unsigned long irq_exits;

    public @Unsigned long host_state_reload;

    public @Unsigned long fpu_reload;

    public @Unsigned long insn_emulation;

    public @Unsigned long insn_emulation_fail;

    public @Unsigned long hypercalls;

    public @Unsigned long irq_injections;

    public @Unsigned long nmi_injections;

    public @Unsigned long req_event;

    public @Unsigned long nested_run;

    public @Unsigned long directed_yield_attempted;

    public @Unsigned long directed_yield_successful;

    public @Unsigned long preemption_reported;

    public @Unsigned long preemption_other;

    public @Unsigned long guest_mode;

    public @Unsigned long notify_window_exits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_x86_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_x86_ops extends Struct {
    public String name;

    public Ptr<?> check_processor_compatibility;

    public Ptr<?> enable_virtualization_cpu;

    public Ptr<?> disable_virtualization_cpu;

    public Ptr<?> emergency_disable_virtualization_cpu;

    public Ptr<?> hardware_unsetup;

    public Ptr<?> has_emulated_msr;

    public Ptr<?> vcpu_after_set_cpuid;

    public @Unsigned int vm_size;

    public Ptr<?> vm_init;

    public Ptr<?> vm_destroy;

    public Ptr<?> vm_pre_destroy;

    public Ptr<?> vcpu_precreate;

    public Ptr<?> vcpu_create;

    public Ptr<?> vcpu_free;

    public Ptr<?> vcpu_reset;

    public Ptr<?> prepare_switch_to_guest;

    public Ptr<?> vcpu_load;

    public Ptr<?> vcpu_put;

    public @Unsigned long HOST_OWNED_DEBUGCTL;

    public Ptr<?> update_exception_bitmap;

    public Ptr<?> get_msr;

    public Ptr<?> set_msr;

    public Ptr<?> get_segment_base;

    public Ptr<?> get_segment;

    public Ptr<?> get_cpl;

    public Ptr<?> get_cpl_no_cache;

    public Ptr<?> set_segment;

    public Ptr<?> get_cs_db_l_bits;

    public Ptr<?> is_valid_cr0;

    public Ptr<?> set_cr0;

    public Ptr<?> post_set_cr3;

    public Ptr<?> is_valid_cr4;

    public Ptr<?> set_cr4;

    public Ptr<?> set_efer;

    public Ptr<?> get_idt;

    public Ptr<?> set_idt;

    public Ptr<?> get_gdt;

    public Ptr<?> set_gdt;

    public Ptr<?> sync_dirty_debug_regs;

    public Ptr<?> set_dr7;

    public Ptr<?> cache_reg;

    public Ptr<?> get_rflags;

    public Ptr<?> set_rflags;

    public Ptr<?> get_if_flag;

    public Ptr<?> flush_tlb_all;

    public Ptr<?> flush_tlb_current;

    public Ptr<?> flush_remote_tlbs;

    public Ptr<?> flush_remote_tlbs_range;

    public Ptr<?> flush_tlb_gva;

    public Ptr<?> flush_tlb_guest;

    public Ptr<?> vcpu_pre_run;

    public Ptr<?> vcpu_run;

    public Ptr<?> handle_exit;

    public Ptr<?> skip_emulated_instruction;

    public Ptr<?> update_emulated_instruction;

    public Ptr<?> set_interrupt_shadow;

    public Ptr<?> get_interrupt_shadow;

    public Ptr<?> patch_hypercall;

    public Ptr<?> inject_irq;

    public Ptr<?> inject_nmi;

    public Ptr<?> inject_exception;

    public Ptr<?> cancel_injection;

    public Ptr<?> interrupt_allowed;

    public Ptr<?> nmi_allowed;

    public Ptr<?> get_nmi_mask;

    public Ptr<?> set_nmi_mask;

    public Ptr<?> is_vnmi_pending;

    public Ptr<?> set_vnmi_pending;

    public Ptr<?> enable_nmi_window;

    public Ptr<?> enable_irq_window;

    public Ptr<?> update_cr8_intercept;

    public boolean x2apic_icr_is_split;

    public @Unsigned long required_apicv_inhibits;

    public boolean allow_apicv_in_x2apic_without_x2apic_virtualization;

    public Ptr<?> refresh_apicv_exec_ctrl;

    public Ptr<?> hwapic_isr_update;

    public Ptr<?> load_eoi_exitmap;

    public Ptr<?> set_virtual_apic_mode;

    public Ptr<?> set_apic_access_page_addr;

    public Ptr<?> deliver_interrupt;

    public Ptr<?> sync_pir_to_irr;

    public Ptr<?> set_tss_addr;

    public Ptr<?> set_identity_map_addr;

    public Ptr<?> get_mt_mask;

    public Ptr<?> load_mmu_pgd;

    public Ptr<?> link_external_spt;

    public Ptr<?> set_external_spte;

    public Ptr<?> free_external_spt;

    public Ptr<?> remove_external_spte;

    public Ptr<?> has_wbinvd_exit;

    public Ptr<?> get_l2_tsc_offset;

    public Ptr<?> get_l2_tsc_multiplier;

    public Ptr<?> write_tsc_offset;

    public Ptr<?> write_tsc_multiplier;

    public Ptr<?> get_exit_info;

    public Ptr<?> get_entry_info;

    public Ptr<?> check_intercept;

    public Ptr<?> handle_exit_irqoff;

    public Ptr<?> update_cpu_dirty_logging;

    public Ptr<kvm_x86_nested_ops> nested_ops;

    public Ptr<?> vcpu_blocking;

    public Ptr<?> vcpu_unblocking;

    public Ptr<?> pi_update_irte;

    public Ptr<?> pi_start_bypass;

    public Ptr<?> apicv_pre_state_restore;

    public Ptr<?> apicv_post_state_restore;

    public Ptr<?> dy_apicv_has_pending_interrupt;

    public Ptr<?> protected_apic_has_interrupt;

    public Ptr<?> set_hv_timer;

    public Ptr<?> cancel_hv_timer;

    public Ptr<?> setup_mce;

    public Ptr<?> smi_allowed;

    public Ptr<?> enter_smm;

    public Ptr<?> leave_smm;

    public Ptr<?> enable_smi_window;

    public Ptr<?> dev_get_attr;

    public Ptr<?> mem_enc_ioctl;

    public Ptr<?> vcpu_mem_enc_ioctl;

    public Ptr<?> mem_enc_register_region;

    public Ptr<?> mem_enc_unregister_region;

    public Ptr<?> vm_copy_enc_context_from;

    public Ptr<?> vm_move_enc_context_from;

    public Ptr<?> guest_memory_reclaimed;

    public Ptr<?> get_feature_msr;

    public Ptr<?> check_emulate_instruction;

    public Ptr<?> apic_init_signal_blocked;

    public Ptr<?> enable_l2_tlb_flush;

    public Ptr<?> migrate_timers;

    public Ptr<?> recalc_msr_intercepts;

    public Ptr<?> complete_emulated_msr;

    public Ptr<?> vcpu_deliver_sipi_vector;

    public Ptr<?> vcpu_get_apicv_inhibit_reasons;

    public Ptr<?> get_untagged_addr;

    public Ptr<?> alloc_apic_backing_page;

    public Ptr<?> gmem_prepare;

    public Ptr<?> gmem_invalidate;

    public Ptr<?> private_max_mapping_level;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_x86_nested_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_x86_nested_ops extends Struct {
    public Ptr<?> leave_nested;

    public Ptr<?> is_exception_vmexit;

    public Ptr<?> check_events;

    public Ptr<?> has_events;

    public Ptr<?> triple_fault;

    public Ptr<?> get_state;

    public Ptr<?> set_state;

    public Ptr<?> get_nested_state_pages;

    public Ptr<?> write_log_dirty;

    public Ptr<?> enable_evmcs;

    public Ptr<?> get_evmcs_version;

    public Ptr<?> hv_inject_synthetic_vmexit_post_tlb_flush;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_dirty_ring"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_dirty_ring extends Struct {
    public @Unsigned int dirty_index;

    public @Unsigned int reset_index;

    public @Unsigned int size;

    public @Unsigned int soft_limit;

    public Ptr<kvm_dirty_gfn> dirty_gfns;

    public int index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_io_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_io_range extends Struct {
    public @Unsigned @OriginalName("gpa_t") long addr;

    public int len;

    public @OriginalName("kvm_io_device") Ptr<?> dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_io_bus"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_io_bus extends Struct {
    public int dev_count;

    public int ioeventfd_count;

    public kvm_io_range @Size(0) [] range;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum kvm_bus"
  )
  public enum kvm_bus implements Enum<kvm_bus>, TypedEnum<kvm_bus, java.lang. @Unsigned Integer> {
    /**
     * {@code KVM_MMIO_BUS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "KVM_MMIO_BUS"
    )
    KVM_MMIO_BUS,

    /**
     * {@code KVM_PIO_BUS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "KVM_PIO_BUS"
    )
    KVM_PIO_BUS,

    /**
     * {@code KVM_VIRTIO_CCW_NOTIFY_BUS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "KVM_VIRTIO_CCW_NOTIFY_BUS"
    )
    KVM_VIRTIO_CCW_NOTIFY_BUS,

    /**
     * {@code KVM_FAST_MMIO_BUS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "KVM_FAST_MMIO_BUS"
    )
    KVM_FAST_MMIO_BUS,

    /**
     * {@code KVM_IOCSR_BUS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "KVM_IOCSR_BUS"
    )
    KVM_IOCSR_BUS,

    /**
     * {@code KVM_NR_BUSES = 5}
     */
    @EnumMember(
        value = 5L,
        name = "KVM_NR_BUSES"
    )
    KVM_NR_BUSES
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_mmio_fragment"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_mmio_fragment extends Struct {
    public @Unsigned @OriginalName("gpa_t") long gpa;

    public Ptr<?> data;

    public @Unsigned int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_irq_routing_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_irq_routing_table extends Struct {
    public int @Size(72) [] chip;

    public @Unsigned int nr_rt_entries;

    public hlist_head @Size(0) [] map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_memslots"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_memslots extends Struct {
    public @Unsigned long generation;

    public @OriginalName("atomic_long_t") atomic64_t last_used_slot;

    public rb_root_cached hva_tree;

    public rb_root gfn_tree;

    public hlist_head @Size(128) [] id_hash;

    public int node_idx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_stat_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_stat_data extends Struct {
    public Ptr<kvm> kvm;

    public Ptr<_kvm_stats_desc> desc;

    public kvm_stat_kind kind;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum kvm_stat_kind"
  )
  public enum kvm_stat_kind implements Enum<kvm_stat_kind>, TypedEnum<kvm_stat_kind, java.lang. @Unsigned Integer> {
    /**
     * {@code KVM_STAT_VM = 0}
     */
    @EnumMember(
        value = 0L,
        name = "KVM_STAT_VM"
    )
    KVM_STAT_VM,

    /**
     * {@code KVM_STAT_VCPU = 1}
     */
    @EnumMember(
        value = 1L,
        name = "KVM_STAT_VCPU"
    )
    KVM_STAT_VCPU
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct _kvm_stats_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class _kvm_stats_desc extends Struct {
    public kvm_stats_desc desc;

    public char @Size(48) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_steal_time"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_steal_time extends Struct {
    public @Unsigned long steal;

    public @Unsigned int version;

    public @Unsigned int flags;

    public char preempted;

    public char @Size(3) [] u8_pad;

    public @Unsigned int @Size(11) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_vcpu_pv_apf_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_vcpu_pv_apf_data extends Struct {
    public @Unsigned int flags;

    public @Unsigned int token;

    public char @Size(56) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_task_sleep_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_task_sleep_node extends Struct {
    public hlist_node link;

    public swait_queue_head wq;

    public @Unsigned int token;

    public int cpu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct kvm_task_sleep_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class kvm_task_sleep_head extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public hlist_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct once"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class once extends Struct {
    public atomic_t state;

    public mutex lock;
  }
}
