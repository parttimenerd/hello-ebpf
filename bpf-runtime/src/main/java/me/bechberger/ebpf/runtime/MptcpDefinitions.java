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
 * Generated class for BPF runtime types that start with mptcp
 */
@java.lang.SuppressWarnings("unused")
public final class MptcpDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_check_push(Ptr<sock> sk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_clean_una(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_clear_xmit(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_close(Ptr<sock> sk, long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_close_ssk(Ptr<sock> sk, Ptr<sock> ssk,
      Ptr<mptcp_subflow_context> subflow, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_data_acked(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_destroy_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_error_report(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __mptcp_expand_seq(@Unsigned long old_seq, @Unsigned long cur_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_finish_join(Ptr<mptcp_sock> msk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_init_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__sum16") short __mptcp_make_csum(@Unsigned long data_seq,
      @Unsigned int subflow_seq, @Unsigned short data_len,
      @Unsigned @OriginalName("__wsum") int sum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_move_skb(Ptr<mptcp_sock> msk, Ptr<sock> ssk, Ptr<sk_buff> skb,
      @Unsigned int offset, @Unsigned long copy_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_move_skbs(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_move_skbs_from_subflow(Ptr<mptcp_sock> msk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> __mptcp_nmpc_sk(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_ofo_queue(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_pm_kernel_worker(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_pm_send_ack(Ptr<mptcp_sock> msk, Ptr<mptcp_subflow_context> subflow,
      boolean prio, boolean backup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_push_pending(Ptr<sock> sk, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __mptcp_recvmsg_mskq(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long len,
      int flags, int copied_total, Ptr<scm_timestamping_internal> tss,
      Ptr<java.lang.Integer> cmsg_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_retrans(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_retransmit_pending_data(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__mptcp_subflow_connect($arg1, (const struct mptcp_pm_local*)$arg2, (const struct mptcp_addr_info*)$arg3)")
  public static int __mptcp_subflow_connect(Ptr<sock> sk, Ptr<mptcp_pm_local> local,
      Ptr<mptcp_addr_info> remote) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__mptcp_subflow_fully_established($arg1, $arg2, (const struct mptcp_options_received*)$arg3)")
  public static void __mptcp_subflow_fully_established(Ptr<mptcp_sock> msk,
      Ptr<mptcp_subflow_context> subflow, Ptr<mptcp_options_received> mp_opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_subflow_push_pending(Ptr<sock> sk, Ptr<sock> ssk, boolean first) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_subflow_send_ack(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_sync_state(Ptr<sock> sk, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __mptcp_try_fallback(Ptr<mptcp_sock> msk, int fb_mib) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_unaccepted_force_close(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __mptcp_wr_shutdown(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_active_detect_blackhole(Ptr<sock> ssk, boolean expired) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_active_disable(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_active_enable(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_active_should_disable(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_addresses_equal((const struct mptcp_addr_info*)$arg1, (const struct mptcp_addr_info*)$arg2, $arg3)")
  public static boolean mptcp_addresses_equal(Ptr<mptcp_addr_info> a, Ptr<mptcp_addr_info> b,
      boolean use_port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_allow_join_id0((const struct net*)$arg1)")
  public static int mptcp_allow_join_id0(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_bind(Ptr<socket> sock, Ptr<sockaddr> uaddr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_ca_reset(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_can_accept_new_subflow((const struct mptcp_sock*)$arg1)")
  public static boolean mptcp_can_accept_new_subflow(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_cancel_work(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_check_and_set_pending(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_check_data_fin(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_check_listen_stop(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_check_send_data_fin(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_cleanup_rbuf(Ptr<mptcp_sock> msk, int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_close(Ptr<sock> sk, long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_close_ssk(Ptr<sock> sk, Ptr<sock> ssk,
      Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_close_timeout((const struct sock*)$arg1)")
  public static @Unsigned int mptcp_close_timeout(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_close_wake_up(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_connect(Ptr<sock> sk, Ptr<sockaddr> uaddr, int addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_copy_inaddrs($arg1, (const struct sock*)$arg2)")
  public static void mptcp_copy_inaddrs(Ptr<sock> msk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_crypto_hmac_sha(@Unsigned long key1, @Unsigned long key2,
      Ptr<java.lang.Character> msg, int len, Ptr<?> hmac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_crypto_key_sha(@Unsigned long key,
      Ptr<java.lang. @Unsigned Integer> token, Ptr<java.lang. @Unsigned Long> idsn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_data_queue_ofo(Ptr<mptcp_sock> msk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_data_ready(Ptr<sock> sk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_destroy(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_destroy_common(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_diag_fill_info(Ptr<mptcp_sock> msk, Ptr<mptcp_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_diag_subflow_init(Ptr<tcp_ulp_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_disconnect(Ptr<sock> sk, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_do_fastclose(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_enter_memory_pressure(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_established_options(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned Integer> size, @Unsigned int remaining,
      Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_established_options_add_addr(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned Integer> size, @Unsigned int remaining,
      Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_established_options_dss(Ptr<sock> sk, Ptr<sk_buff> skb,
      boolean snd_data_fin_enable, Ptr<java.lang. @Unsigned Integer> size,
      Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_established_options_mp(Ptr<sock> sk, Ptr<sk_buff> skb,
      boolean snd_data_fin_enable, Ptr<java.lang. @Unsigned Integer> size,
      Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_established_options_mp_fail(Ptr<sock> sk,
      Ptr<java.lang. @Unsigned Integer> size, @Unsigned int remaining,
      Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_event($arg1, (const struct mptcp_sock*)$arg2, (const struct sock*)$arg3, $arg4)")
  public static void mptcp_event(mptcp_event_type type, Ptr<mptcp_sock> msk, Ptr<sock> ssk,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_event_add_subflow($arg1, (const struct sock*)$arg2)")
  public static int mptcp_event_add_subflow(Ptr<sk_buff> skb, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_event_addr_announced((const struct sock*)$arg1, (const struct mptcp_addr_info*)$arg2)")
  public static void mptcp_event_addr_announced(Ptr<sock> ssk, Ptr<mptcp_addr_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_event_addr_removed((const struct mptcp_sock*)$arg1, $arg2)")
  public static void mptcp_event_addr_removed(Ptr<mptcp_sock> msk,
      @OriginalName("uint8_t") char id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_event_pm_listener((const struct sock*)$arg1, $arg2)")
  public static void mptcp_event_pm_listener(Ptr<sock> ssk, mptcp_event_type event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_event_put_token_and_ssk($arg1, (const struct mptcp_sock*)$arg2, (const struct sock*)$arg3)")
  public static int mptcp_event_put_token_and_ssk(Ptr<sk_buff> skb, Ptr<mptcp_sock> msk,
      Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_fastopen_subflow_synack_set_params(Ptr<mptcp_subflow_context> subflow,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_finish_connect(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_finish_join(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_get_add_addr_timeout((const struct net*)$arg1)")
  public static @Unsigned int mptcp_get_add_addr_timeout(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_get_available_schedulers(String buf, @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_get_options((const struct sk_buff*)$arg1, $arg2)")
  public static void mptcp_get_options(Ptr<sk_buff> skb, Ptr<mptcp_options_received> mp_opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)mptcp_get_path_manager((const struct net*)$arg1))")
  public static String mptcp_get_path_manager(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_get_pm_type((const struct net*)$arg1)")
  public static int mptcp_get_pm_type(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_get_port(Ptr<sock> sk, @Unsigned short snum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_get_reset_option((const struct sk_buff*)$arg1)")
  public static @Unsigned @OriginalName("__be32") int mptcp_get_reset_option(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)mptcp_get_scheduler((const struct net*)$arg1))")
  public static String mptcp_get_scheduler(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_get_sub_addrs((const struct sock*)$arg1, $arg2)")
  public static void mptcp_get_sub_addrs(Ptr<sock> sk, Ptr<mptcp_subflow_addrs> a) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_get_subflow_data(Ptr<mptcp_subflow_data> sfd, String optval,
      Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_getsockopt(Ptr<sock> sk, int level, int optname, String optval,
      Ptr<java.lang.Integer> option) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_getsockopt_full_info(Ptr<mptcp_sock> msk, String optval,
      Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_getsockopt_sol_tcp(Ptr<mptcp_sock> msk, int optname, String optval,
      Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_getsockopt_subflow_addrs(Ptr<mptcp_sock> msk, String optval,
      Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_getsockopt_tcpinfo(Ptr<mptcp_sock> msk, String optval,
      Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_hash(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_incoming_options(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_info2sockaddr((const struct mptcp_addr_info*)$arg1, $arg2, $arg3)")
  public static void mptcp_info2sockaddr(Ptr<mptcp_addr_info> info,
      Ptr<__kernel_sockaddr_storage> addr, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_init_sched(Ptr<mptcp_sock> msk, Ptr<mptcp_sched_ops> sched) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_init_sock(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_ioctl(Ptr<sock> sk, int cmd, Ptr<java.lang.Integer> karg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_ioctl_outq((const struct mptcp_sock*)$arg1, $arg2)")
  public static int mptcp_ioctl_outq(Ptr<mptcp_sock> msk, @Unsigned long v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_is_checksum_enabled((const struct net*)$arg1)")
  public static int mptcp_is_checksum_enabled(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_is_enabled((const struct net*)$arg1)")
  public static int mptcp_is_enabled(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_join_cookie_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int mptcp_join_entry_hash(Ptr<sk_buff> skb, Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_listen(Ptr<socket> sock, int backlog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_local_address((const struct sock_common*)$arg1, $arg2)")
  public static void mptcp_local_address(Ptr<sock_common> skc, Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_lookup_subflow_by_saddr((const struct list_head*)$arg1, (const struct mptcp_addr_info*)$arg2)")
  public static boolean mptcp_lookup_subflow_by_saddr(Ptr<list_head> list,
      Ptr<mptcp_addr_info> saddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_mib_alloc(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_napi_poll(Ptr<napi_struct> napi, int budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_net_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_net_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_nl_fill_addr(Ptr<sk_buff> skb, Ptr<mptcp_pm_addr_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_nl_mcast_send(Ptr<net> net, Ptr<sk_buff> nlskb,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_nl_remove_id_zero_address(Ptr<net> net, Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_nl_remove_subflow_and_signal_addr($arg1, (const struct mptcp_pm_addr_entry*)$arg2)")
  public static int mptcp_nl_remove_subflow_and_signal_addr(Ptr<net> net,
      Ptr<mptcp_pm_addr_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_parse_option((const struct sk_buff*)$arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void mptcp_parse_option(Ptr<sk_buff> skb, String ptr, int opsize,
      Ptr<mptcp_options_received> mp_opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_pending_data_fin(Ptr<sock> sk, Ptr<java.lang. @Unsigned Long> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_add_addr_echoed($arg1, (const struct mptcp_addr_info*)$arg2)")
  public static void mptcp_pm_add_addr_echoed(Ptr<mptcp_sock> msk, Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_add_addr_received((const struct sock*)$arg1, (const struct mptcp_addr_info*)$arg2)")
  public static void mptcp_pm_add_addr_received(Ptr<sock> ssk, Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_add_addr_send_ack(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_add_addr_signal($arg1, (const struct sk_buff*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static boolean mptcp_pm_add_addr_signal(Ptr<mptcp_sock> msk, Ptr<sk_buff> skb,
      @Unsigned int opt_size, @Unsigned int remaining, Ptr<mptcp_addr_info> addr,
      Ptr<java.lang. @OriginalName("bool") Boolean> echo,
      Ptr<java.lang. @OriginalName("bool") Boolean> drop_other_suboptions) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_add_timer(Ptr<timer_list> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_addr_families_match((const struct sock*)$arg1, (const struct mptcp_addr_info*)$arg2, (const struct mptcp_addr_info*)$arg3)")
  public static boolean mptcp_pm_addr_families_match(Ptr<sock> sk, Ptr<mptcp_addr_info> loc,
      Ptr<mptcp_addr_info> rem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_addr_send_ack(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_alloc_anno_list($arg1, (const struct mptcp_addr_info*)$arg2)")
  public static boolean mptcp_pm_alloc_anno_list(Ptr<mptcp_sock> msk, Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_pm_allow_new_subflow(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_announce_addr($arg1, (const struct mptcp_addr_info*)$arg2, $arg3)")
  public static int mptcp_pm_announce_addr(Ptr<mptcp_sock> msk, Ptr<mptcp_addr_info> addr,
      boolean echo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_connection_closed(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_create_subflow_or_signal_addr(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_data_init(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_data_reset(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_del_add_timer($arg1, (const struct mptcp_addr_info*)$arg2, $arg3)")
  public static Ptr<mptcp_pm_add_entry> mptcp_pm_del_add_timer(Ptr<mptcp_sock> msk,
      Ptr<mptcp_addr_info> addr, boolean check_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_destroy(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_find((const u8*)$arg1)")
  public static Ptr<mptcp_pm_ops> mptcp_pm_find(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_flush_addrs_and_subflows(Ptr<mptcp_sock> msk,
      Ptr<list_head> rm_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_fully_established($arg1, (const struct sock*)$arg2)")
  public static void mptcp_pm_fully_established(Ptr<mptcp_sock> msk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_genl_fill_addr(Ptr<sk_buff> msg, Ptr<netlink_callback> cb,
      Ptr<mptcp_pm_addr_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_get_add_addr_accept_max((const struct mptcp_sock*)$arg1)")
  public static @Unsigned int mptcp_pm_get_add_addr_accept_max(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_get_add_addr_signal_max((const struct mptcp_sock*)$arg1)")
  public static @Unsigned int mptcp_pm_get_add_addr_signal_max(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_get_available(String buf, @Unsigned long maxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_get_local_addr_max((const struct mptcp_sock*)$arg1)")
  public static @Unsigned int mptcp_pm_get_local_addr_max(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_get_local_id(Ptr<mptcp_sock> msk, Ptr<sock_common> skc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_get_subflows_max((const struct mptcp_sock*)$arg1)")
  public static @Unsigned int mptcp_pm_get_subflows_max(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_has_addr_attr_id((const struct nlattr*)$arg1, $arg2)")
  public static boolean mptcp_pm_has_addr_attr_id(Ptr<nlattr> attr, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_pm_is_backup(Ptr<mptcp_sock> msk, Ptr<sock_common> skc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_kernel_register() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_mp_fail_received(Ptr<sock> sk, @Unsigned long fail_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_mp_prio_received(Ptr<sock> ssk, char bkup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_mp_prio_send_ack(Ptr<mptcp_sock> msk, Ptr<mptcp_addr_info> addr,
      Ptr<mptcp_addr_info> rem, char bkup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_new_connection($arg1, (const struct sock*)$arg2, $arg3)")
  public static void mptcp_pm_new_connection(Ptr<mptcp_sock> msk, Ptr<sock> ssk, int server_side) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_add_addr_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_nl_add_addr_received(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_announce_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_append_new_local_addr(Ptr<pm_nl_pernet> pernet,
      Ptr<mptcp_pm_addr_entry> entry, boolean needs_id, boolean replace) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_pm_nl_check_work_pending(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_create_listen_socket(Ptr<sock> sk, Ptr<mptcp_pm_addr_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_del_addr_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_dump_addr(Ptr<sk_buff> msg, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_flush_addrs_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_get_addr(char id, Ptr<mptcp_pm_addr_entry> addr,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_get_addr_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_get_addr_dumpit(Ptr<sk_buff> msg, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_get_limits_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_get_local_id(Ptr<mptcp_sock> msk, Ptr<mptcp_pm_addr_entry> skc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_nl_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_pm_nl_is_backup(Ptr<mptcp_sock> msk, Ptr<mptcp_addr_info> skc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_remove_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_nl_rm_addr(Ptr<mptcp_sock> msk, char rm_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_set_flags(Ptr<mptcp_pm_addr_entry> local, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_set_flags_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_set_limits_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_subflow_create_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_nl_subflow_destroy_doit(Ptr<sk_buff> skb, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_parse_addr(Ptr<nlattr> attr, Ptr<genl_info> info,
      Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_parse_entry(Ptr<nlattr> attr, Ptr<genl_info> info,
      boolean require_family, Ptr<mptcp_pm_addr_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_parse_pm_addr_attr($arg1, (const struct nlattr*)$arg2, $arg3, $arg4, $arg5)")
  public static int mptcp_pm_parse_pm_addr_attr(Ptr<Ptr<nlattr>> tb, Ptr<nlattr> attr,
      Ptr<genl_info> info, Ptr<mptcp_addr_info> addr, boolean require_family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_register(Ptr<mptcp_pm_ops> pm_ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_remove_addr($arg1, (const struct mptcp_rm_list*)$arg2)")
  public static int mptcp_pm_remove_addr(Ptr<mptcp_sock> msk, Ptr<mptcp_rm_list> rm_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_remove_addr_entry(Ptr<mptcp_sock> msk,
      Ptr<mptcp_pm_addr_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_rm_addr_or_subflow($arg1, (const struct mptcp_rm_list*)$arg2, $arg3)")
  public static void mptcp_pm_rm_addr_or_subflow(Ptr<mptcp_sock> msk, Ptr<mptcp_rm_list> rm_list,
      linux_mptcp_mib_field rm_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_rm_addr_received($arg1, (const struct mptcp_rm_list*)$arg2)")
  public static void mptcp_pm_rm_addr_received(Ptr<mptcp_sock> msk, Ptr<mptcp_rm_list> rm_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_pm_rm_addr_signal(Ptr<mptcp_sock> msk, @Unsigned int remaining,
      Ptr<mptcp_rm_list> rm_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_rm_subflow($arg1, (const struct mptcp_rm_list*)$arg2)")
  public static void mptcp_pm_rm_subflow(Ptr<mptcp_sock> msk, Ptr<mptcp_rm_list> rm_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_pm_schedule_work(Ptr<mptcp_sock> msk, mptcp_pm_status new_status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_send_ack(Ptr<mptcp_sock> msk, Ptr<mptcp_subflow_context> subflow,
      boolean prio, boolean backup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_sport_in_anno_list($arg1, (const struct sock*)$arg2)")
  public static boolean mptcp_pm_sport_in_anno_list(Ptr<mptcp_sock> msk, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_subflow_check_next($arg1, (const struct mptcp_subflow_context*)$arg2)")
  public static void mptcp_pm_subflow_check_next(Ptr<mptcp_sock> msk,
      Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_pm_subflow_chk_stale((const struct mptcp_sock*)$arg1, $arg2)")
  public static void mptcp_pm_subflow_chk_stale(Ptr<mptcp_sock> msk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_subflow_established(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_unregister(Ptr<mptcp_pm_ops> pm_ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_userspace_register() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_pm_validate(Ptr<mptcp_pm_ops> pm_ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_pm_worker(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int mptcp_poll(Ptr<file> file, Ptr<socket> sock,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_propagate_state($arg1, $arg2, $arg3, (const struct mptcp_options_received*)$arg4)")
  public static void mptcp_propagate_state(Ptr<sock> sk, Ptr<sock> ssk,
      Ptr<mptcp_subflow_context> subflow, Ptr<mptcp_options_received> mp_opt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_proto_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_proto_v6_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_put_subflow_data(Ptr<mptcp_subflow_data> sfd, String optval,
      @Unsigned int copied, Ptr<java.lang.Integer> optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_rcv_space_adjust(Ptr<mptcp_sock> msk, int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_rcv_space_init($arg1, (const struct sock*)$arg2)")
  public static void mptcp_rcv_space_init(Ptr<mptcp_sock> msk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_recvmsg(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long len, int flags,
      Ptr<java.lang.Integer> addr_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_register_scheduler(Ptr<mptcp_sched_ops> sched) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_release_cb(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_release_sched(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_remote_address((const struct sock_common*)$arg1, $arg2)")
  public static void mptcp_remote_address(Ptr<sock_common> skc, Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_remove_anno_list_by_saddr($arg1, (const struct mptcp_addr_info*)$arg2)")
  public static boolean mptcp_remove_anno_list_by_saddr(Ptr<mptcp_sock> msk,
      Ptr<mptcp_addr_info> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_reset_tout_timer(Ptr<mptcp_sock> msk, @Unsigned long fail_tout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_retransmit_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_sched_default_get_retrans(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_sched_default_get_send(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_sched_find((const u8*)$arg1)")
  public static Ptr<mptcp_sched_ops> mptcp_sched_find(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_sched_get_retrans(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_sched_get_send(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_sched_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_schedule_work(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_send_ack(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_sendmsg(Ptr<sock> sk, Ptr<msghdr> msg, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_sendmsg_frag(Ptr<sock> sk, Ptr<sock> ssk, Ptr<mptcp_data_frag> dfrag,
      Ptr<mptcp_sendmsg_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_seq_show(Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_set_path_manager($arg1, (const u8*)$arg2)")
  public static int mptcp_set_path_manager(String path_manager, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_set_rcvlowat(Ptr<sock> sk, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_set_scheduler($arg1, (const u8*)$arg2)")
  public static int mptcp_set_scheduler(String scheduler, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_set_state(Ptr<sock> sk, int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_setsockopt(Ptr<sock> sk, int level, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_setsockopt_sol_socket(Ptr<mptcp_sock> msk, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_setsockopt_sol_socket_int(Ptr<mptcp_sock> msk, int optname,
      sockptr_t optval, @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_setsockopt_sol_socket_linger(Ptr<mptcp_sock> msk, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_setsockopt_sol_tcp(Ptr<mptcp_sock> msk, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_setsockopt_sol_tcp_congestion(Ptr<mptcp_sock> msk, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_setsockopt_v4(Ptr<mptcp_sock> msk, int optname, sockptr_t optval,
      @Unsigned int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_shutdown(Ptr<sock> sk, int how) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_shutdown_subflows(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_sk_clone_init((const struct sock*)$arg1, (const struct mptcp_options_received*)$arg2, $arg3, $arg4)")
  public static Ptr<sock> mptcp_sk_clone_init(Ptr<sock> sk, Ptr<mptcp_options_received> mp_opt,
      Ptr<sock> ssk, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_sock_graft(Ptr<sock> sk, Ptr<socket> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_sockopt_sync_locked(Ptr<mptcp_sock> msk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_sol_socket_sync_intval(Ptr<mptcp_sock> msk, int optname, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_space((const struct sock*)$arg1, $arg2, $arg3)")
  public static void mptcp_space(Ptr<sock> ssk, Ptr<java.lang.Integer> space,
      Ptr<java.lang.Integer> full_space) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_stale_loss_cnt((const struct net*)$arg1)")
  public static @Unsigned int mptcp_stale_loss_cnt(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_stream_accept(Ptr<socket> sock, Ptr<socket> newsock,
      Ptr<proto_accept_arg> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_stream_memory_free((const struct sock*)$arg1, $arg2)")
  public static boolean mptcp_stream_memory_free(Ptr<sock> sk, int wake) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_subflow_active(Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_subflow_create_socket(Ptr<sock> sk, @Unsigned short family,
      Ptr<Ptr<socket>> new_sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_subflow_data_available(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_drop_ctx(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> mptcp_subflow_get_retrans(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> mptcp_subflow_get_send(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_subflow_init_cookie_req($arg1, (const struct sock*)$arg2, $arg3)")
  public static int mptcp_subflow_init_cookie_req(Ptr<request_sock> req, Ptr<sock> sk_listener,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_process_delegated(Ptr<sock> ssk, long status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_queue_clean(Ptr<sock> listener_sk, Ptr<sock> listener_ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_subflow_reqsk_alloc((const struct request_sock_ops*)$arg1, $arg2, $arg3)")
  public static Ptr<request_sock> mptcp_subflow_reqsk_alloc(Ptr<request_sock_ops> ops,
      Ptr<sock> sk_listener, boolean attach_listener) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_reset(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_set_active(Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_set_scheduled(Ptr<mptcp_subflow_context> subflow,
      boolean scheduled) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_subflow_shutdown(Ptr<sock> sk, Ptr<sock> ssk, int how) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_supported_sockopt(int level, int optname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_syn_options($arg1, (const struct sk_buff*)$arg2, $arg3, $arg4)")
  public static boolean mptcp_syn_options(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned Integer> size, Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_synack_options((const struct request_sock*)$arg1, $arg2, $arg3)")
  public static boolean mptcp_synack_options(Ptr<request_sock> req,
      Ptr<java.lang. @Unsigned Integer> size, Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int mptcp_sync_mss(Ptr<sock> sk, @Unsigned int pmtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_token_accept(Ptr<mptcp_subflow_request_sock> req, Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_token_destroy(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_token_destroy_request(Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_token_exists(@Unsigned int token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mptcp_sock> mptcp_token_get_sock(Ptr<net> net, @Unsigned int token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_token_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_token_iter_next((const struct net*)$arg1, $arg2, $arg3)")
  public static Ptr<mptcp_sock> mptcp_token_iter_next(Ptr<net> net, Ptr<java.lang.Long> s_slot,
      Ptr<java.lang.Long> s_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_token_join_cookie_init_state(
      Ptr<mptcp_subflow_request_sock> subflow_req, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_token_new_connect(Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_token_new_request(Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_tout_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_try_coalesce(Ptr<sock> sk, Ptr<sk_buff> to, Ptr<sk_buff> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_unhash(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_unregister_scheduler(Ptr<mptcp_sched_ops> sched) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_update_data_checksum(Ptr<sk_buff> skb, int added) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_update_rcv_data_fin(Ptr<mptcp_sock> msk, @Unsigned long data_fin_seq,
      boolean use_64bit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_userspace_pm_active((const struct mptcp_sock*)$arg1)")
  public static boolean mptcp_userspace_pm_active(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_userspace_pm_append_new_local_addr(Ptr<mptcp_sock> msk,
      Ptr<mptcp_pm_addr_entry> entry, boolean needs_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_userspace_pm_delete_local_addr(Ptr<mptcp_sock> msk,
      Ptr<mptcp_pm_addr_entry> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_userspace_pm_dump_addr(Ptr<sk_buff> msg, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_userspace_pm_free_local_addr_list(Ptr<mptcp_sock> msk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_userspace_pm_get_addr(char id, Ptr<mptcp_pm_addr_entry> addr,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_userspace_pm_get_local_id(Ptr<mptcp_sock> msk,
      Ptr<mptcp_pm_addr_entry> skc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("mptcp_userspace_pm_get_sock((const struct genl_info*)$arg1)")
  public static Ptr<mptcp_sock> mptcp_userspace_pm_get_sock(Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean mptcp_userspace_pm_is_backup(Ptr<mptcp_sock> msk,
      Ptr<mptcp_addr_info> skc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_userspace_pm_set_flags(Ptr<mptcp_pm_addr_entry> local,
      Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int mptcp_validate_scheduler(Ptr<mptcp_sched_ops> sched) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_worker(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void mptcp_write_options(Ptr<tcphdr> th,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> ptr, Ptr<tcp_sock> tp,
      Ptr<mptcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_ext"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_ext extends Struct {
    @InlineUnion(61841)
    public @Unsigned long data_ack;

    @InlineUnion(61841)
    public @Unsigned int data_ack32;

    public @Unsigned long data_seq;

    public @Unsigned int subflow_seq;

    public @Unsigned short data_len;

    public @Unsigned @OriginalName("__sum16") short csum;

    public char use_map;

    public char dsn64;

    public char data_fin;

    public char use_ack;

    public char ack64;

    public char mpc_map;

    public char frozen;

    public char reset_transient;

    public char reset_reason;

    public char csum_reqd;

    public char infinite_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_rm_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_rm_list extends Struct {
    public char @Size(8) [] ids;

    public char nr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_addr_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_addr_info extends Struct {
    public char id;

    public @Unsigned @OriginalName("sa_family_t") short family;

    public @Unsigned @OriginalName("__be16") short port;

    @InlineUnion(61870)
    public in_addr addr;

    @InlineUnion(61870)
    public in6_addr addr6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_out_options"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_out_options extends Struct {
    public @Unsigned short suboptions;

    public mptcp_rm_list rm_list;

    public char join_id;

    public char backup;

    public char reset_reason;

    public char reset_transient;

    public char csum_reqd;

    public char allow_join_id0;

    @InlineUnion(61876)
    public anon_member_of_anon_member_of_mptcp_out_options anon8$0;

    @InlineUnion(61876)
    public anon_member_of_anon_member_of_mptcp_out_options anon8$1;

    @InlineUnion(61876)
    public anon_member_of_anon_member_of_mptcp_out_options anon8$2;

    @InlineUnion(61876)
    public anon_member_of_anon_member_of_mptcp_out_options anon8$3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_mib"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_mib extends Struct {
    public @Unsigned long @Size(77) [] mibs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum mptcp_event_type"
  )
  public enum mptcp_event_type implements Enum<mptcp_event_type>, TypedEnum<mptcp_event_type, java.lang. @Unsigned Integer> {
    /**
     * {@code MPTCP_EVENT_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "MPTCP_EVENT_UNSPEC"
    )
    MPTCP_EVENT_UNSPEC,

    /**
     * {@code MPTCP_EVENT_CREATED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "MPTCP_EVENT_CREATED"
    )
    MPTCP_EVENT_CREATED,

    /**
     * {@code MPTCP_EVENT_ESTABLISHED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "MPTCP_EVENT_ESTABLISHED"
    )
    MPTCP_EVENT_ESTABLISHED,

    /**
     * {@code MPTCP_EVENT_CLOSED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "MPTCP_EVENT_CLOSED"
    )
    MPTCP_EVENT_CLOSED,

    /**
     * {@code MPTCP_EVENT_ANNOUNCED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "MPTCP_EVENT_ANNOUNCED"
    )
    MPTCP_EVENT_ANNOUNCED,

    /**
     * {@code MPTCP_EVENT_REMOVED = 7}
     */
    @EnumMember(
        value = 7L,
        name = "MPTCP_EVENT_REMOVED"
    )
    MPTCP_EVENT_REMOVED,

    /**
     * {@code MPTCP_EVENT_SUB_ESTABLISHED = 10}
     */
    @EnumMember(
        value = 10L,
        name = "MPTCP_EVENT_SUB_ESTABLISHED"
    )
    MPTCP_EVENT_SUB_ESTABLISHED,

    /**
     * {@code MPTCP_EVENT_SUB_CLOSED = 11}
     */
    @EnumMember(
        value = 11L,
        name = "MPTCP_EVENT_SUB_CLOSED"
    )
    MPTCP_EVENT_SUB_CLOSED,

    /**
     * {@code MPTCP_EVENT_SUB_PRIORITY = 13}
     */
    @EnumMember(
        value = 13L,
        name = "MPTCP_EVENT_SUB_PRIORITY"
    )
    MPTCP_EVENT_SUB_PRIORITY,

    /**
     * {@code MPTCP_EVENT_LISTENER_CREATED = 15}
     */
    @EnumMember(
        value = 15L,
        name = "MPTCP_EVENT_LISTENER_CREATED"
    )
    MPTCP_EVENT_LISTENER_CREATED,

    /**
     * {@code MPTCP_EVENT_LISTENER_CLOSED = 16}
     */
    @EnumMember(
        value = 16L,
        name = "MPTCP_EVENT_LISTENER_CLOSED"
    )
    MPTCP_EVENT_LISTENER_CLOSED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_sched_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_sched_ops extends Struct {
    public Ptr<?> get_send;

    public Ptr<?> get_retrans;

    public char @Size(16) [] name;

    public Ptr<module> owner;

    public list_head list;

    public Ptr<?> init;

    public Ptr<?> release;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_sock extends Struct {
    public inet_connection_sock sk;

    public @Unsigned long local_key;

    public @Unsigned long remote_key;

    public @Unsigned long write_seq;

    public @Unsigned long bytes_sent;

    public @Unsigned long snd_nxt;

    public @Unsigned long bytes_received;

    public @Unsigned long ack_seq;

    public atomic64_t rcv_wnd_sent;

    public @Unsigned long rcv_data_fin_seq;

    public @Unsigned long bytes_retrans;

    public @Unsigned long bytes_consumed;

    public int snd_burst;

    public int old_wspace;

    public @Unsigned long recovery_snd_nxt;

    public @Unsigned long bytes_acked;

    public @Unsigned long snd_una;

    public @Unsigned long wnd_end;

    public @Unsigned int last_data_sent;

    public @Unsigned int last_data_recv;

    public @Unsigned int last_ack_recv;

    public @Unsigned long timer_ival;

    public @Unsigned int token;

    public @Unsigned long flags;

    public @Unsigned long cb_flags;

    public boolean recovery;

    public boolean can_ack;

    public boolean fully_established;

    public boolean rcv_data_fin;

    public boolean snd_data_fin_enable;

    public boolean rcv_fastclose;

    public boolean use_64bit_ack;

    public boolean csum_enabled;

    public boolean allow_infinite_fallback;

    public char pending_state;

    public char mpc_endpoint_id;

    public char recvmsg_inq;

    public char cork;

    public char nodelay;

    public char fastopening;

    public char in_accept_queue;

    public char free_first;

    public char rcvspace_init;

    public char fastclosing;

    public @Unsigned int notsent_lowat;

    public int keepalive_cnt;

    public int keepalive_idle;

    public int keepalive_intvl;

    public int maxseg;

    public work_struct work;

    public Ptr<sk_buff> ooo_last_skb;

    public rb_root out_of_order_queue;

    public list_head conn_list;

    public list_head rtx_queue;

    public Ptr<mptcp_data_frag> first_pending;

    public list_head join_list;

    public Ptr<sock> first;

    public mptcp_pm_data pm;

    public Ptr<mptcp_sched_ops> sched;

    public rcvq_space_of_mptcp_sock rcvq_space;

    public char scaling_ratio;

    public boolean allow_subflows;

    public @Unsigned int subflow_id;

    public @Unsigned int setsockopt_seq;

    public char @Size(16) [] ca_name;

    public @OriginalName("spinlock_t") spinlock fallback_lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_skb_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_skb_cb extends Struct {
    public @Unsigned long map_seq;

    public @Unsigned long end_seq;

    public @Unsigned int offset;

    public char has_rxtstamp;

    public char cant_coalesce;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_options_received"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_options_received extends Struct {
    public @Unsigned long sndr_key;

    public @Unsigned long rcvr_key;

    public @Unsigned long data_ack;

    public @Unsigned long data_seq;

    public @Unsigned int subflow_seq;

    public @Unsigned short data_len;

    public @Unsigned @OriginalName("__sum16") short csum;

    @InlineUnion(64960)
    public anon_member_of_anon_member_of_mptcp_options_received_and_status_of_anon_member_of_mptcp_options_received anon7$0;

    @InlineUnion(64960)
    public anon_member_of_anon_member_of_mptcp_options_received_and_status_of_anon_member_of_mptcp_options_received status;

    public char join_id;

    public @Unsigned int token;

    public @Unsigned int nonce;

    public @Unsigned long thmac;

    public char @Size(20) [] hmac;

    public mptcp_addr_info addr;

    public mptcp_rm_list rm_list;

    public @Unsigned long ahmac;

    public @Unsigned long fail_seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_pm_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_pm_data extends Struct {
    public mptcp_addr_info local;

    public mptcp_addr_info remote;

    public list_head anno_list;

    public list_head userspace_pm_local_addr_list;

    public @OriginalName("spinlock_t") spinlock lock;

    @InlineUnion(64964)
    public anon_member_of_anon_member_of_mptcp_pm_data_and_reset_of_anon_member_of_mptcp_pm_data anon5$0;

    @InlineUnion(64964)
    public anon_member_of_anon_member_of_mptcp_pm_data_and_reset_of_anon_member_of_mptcp_pm_data reset;

    public @Unsigned long @Size(4) [] id_avail_bitmap;

    public mptcp_rm_list rm_list_tx;

    public mptcp_rm_list rm_list_rx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_data_frag"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_data_frag extends Struct {
    public list_head list;

    public @Unsigned long data_seq;

    public @Unsigned short data_len;

    public @Unsigned short offset;

    public @Unsigned short overhead;

    public @Unsigned short already_sent;

    public Ptr<page> page;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_subflow_request_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_subflow_request_sock extends Struct {
    public tcp_request_sock sk;

    public @Unsigned short mp_capable;

    public @Unsigned short mp_join;

    public @Unsigned short backup;

    public @Unsigned short request_bkup;

    public @Unsigned short csum_reqd;

    public @Unsigned short allow_join_id0;

    public char local_id;

    public char remote_id;

    public @Unsigned long local_key;

    public @Unsigned long idsn;

    public @Unsigned int token;

    public @Unsigned int ssn_offset;

    public @Unsigned long thmac;

    public @Unsigned int local_nonce;

    public @Unsigned int remote_nonce;

    public Ptr<mptcp_sock> msk;

    public hlist_nulls_node token_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_delegated_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_delegated_action extends Struct {
    public napi_struct napi;

    public @OriginalName("local_lock_t") lockdep_map_p bh_lock;

    public list_head head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_subflow_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_subflow_context extends Struct {
    public list_head node;

    @InlineUnion(64975)
    public anon_member_of_anon_member_of_mptcp_subflow_context_and_reset_of_anon_member_of_mptcp_subflow_context anon1$0;

    @InlineUnion(64975)
    public anon_member_of_anon_member_of_mptcp_subflow_context_and_reset_of_anon_member_of_mptcp_subflow_context reset;

    public list_head delegated_node;

    public @Unsigned int setsockopt_seq;

    public @Unsigned int stale_rcv_tstamp;

    public int cached_sndbuf;

    public Ptr<sock> tcp_sock;

    public Ptr<sock> conn;

    public Ptr<inet_connection_sock_af_ops> icsk_af_ops;

    public Ptr<?> tcp_state_change;

    public Ptr<?> tcp_error_report;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_sendmsg_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_sendmsg_info extends Struct {
    public int mss_now;

    public int size_goal;

    public @Unsigned short limit;

    public @Unsigned short sent;

    public @Unsigned int flags;

    public boolean data_lock_held;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum mptcp_pm_type"
  )
  public enum mptcp_pm_type implements Enum<mptcp_pm_type>, TypedEnum<mptcp_pm_type, java.lang. @Unsigned Integer> {
    /**
     * {@code MPTCP_PM_TYPE_KERNEL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "MPTCP_PM_TYPE_KERNEL"
    )
    MPTCP_PM_TYPE_KERNEL,

    /**
     * {@code MPTCP_PM_TYPE_USERSPACE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "MPTCP_PM_TYPE_USERSPACE"
    )
    MPTCP_PM_TYPE_USERSPACE,

    /**
     * {@code __MPTCP_PM_TYPE_NR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__MPTCP_PM_TYPE_NR"
    )
    __MPTCP_PM_TYPE_NR,

    /**
     * {@code __MPTCP_PM_TYPE_MAX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "__MPTCP_PM_TYPE_MAX"
    )
    __MPTCP_PM_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_pm_local"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_pm_local extends Struct {
    public mptcp_addr_info addr;

    public char flags;

    public int ifindex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum mptcp_addr_signal_status"
  )
  public enum mptcp_addr_signal_status implements Enum<mptcp_addr_signal_status>, TypedEnum<mptcp_addr_signal_status, java.lang. @Unsigned Integer> {
    /**
     * {@code MPTCP_ADD_ADDR_SIGNAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "MPTCP_ADD_ADDR_SIGNAL"
    )
    MPTCP_ADD_ADDR_SIGNAL,

    /**
     * {@code MPTCP_ADD_ADDR_ECHO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "MPTCP_ADD_ADDR_ECHO"
    )
    MPTCP_ADD_ADDR_ECHO,

    /**
     * {@code MPTCP_RM_ADDR_SIGNAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "MPTCP_RM_ADDR_SIGNAL"
    )
    MPTCP_RM_ADDR_SIGNAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_pm_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_pm_ops extends Struct {
    public char @Size(16) [] name;

    public Ptr<module> owner;

    public list_head list;

    public Ptr<?> init;

    public Ptr<?> release;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_pernet"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_pernet extends Struct {
    public Ptr<ctl_table_header> ctl_table_hdr;

    public @Unsigned int add_addr_timeout;

    public @Unsigned int blackhole_timeout;

    public @Unsigned int close_timeout;

    public @Unsigned int stale_loss_cnt;

    public atomic_t active_disable_times;

    public char syn_retrans_before_tcp_fallback;

    public @Unsigned long active_disable_stamp;

    public char mptcp_enabled;

    public char checksum_enabled;

    public char allow_join_initial_addr_port;

    public char pm_type;

    public char @Size(16) [] scheduler;

    public char @Size(16) [] path_manager;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum mptcp_pm_status"
  )
  public enum mptcp_pm_status implements Enum<mptcp_pm_status>, TypedEnum<mptcp_pm_status, java.lang. @Unsigned Integer> {
    /**
     * {@code MPTCP_PM_ADD_ADDR_RECEIVED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "MPTCP_PM_ADD_ADDR_RECEIVED"
    )
    MPTCP_PM_ADD_ADDR_RECEIVED,

    /**
     * {@code MPTCP_PM_ADD_ADDR_SEND_ACK = 1}
     */
    @EnumMember(
        value = 1L,
        name = "MPTCP_PM_ADD_ADDR_SEND_ACK"
    )
    MPTCP_PM_ADD_ADDR_SEND_ACK,

    /**
     * {@code MPTCP_PM_RM_ADDR_RECEIVED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "MPTCP_PM_RM_ADDR_RECEIVED"
    )
    MPTCP_PM_RM_ADDR_RECEIVED,

    /**
     * {@code MPTCP_PM_ESTABLISHED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "MPTCP_PM_ESTABLISHED"
    )
    MPTCP_PM_ESTABLISHED,

    /**
     * {@code MPTCP_PM_SUBFLOW_ESTABLISHED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "MPTCP_PM_SUBFLOW_ESTABLISHED"
    )
    MPTCP_PM_SUBFLOW_ESTABLISHED,

    /**
     * {@code MPTCP_PM_ALREADY_ESTABLISHED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "MPTCP_PM_ALREADY_ESTABLISHED"
    )
    MPTCP_PM_ALREADY_ESTABLISHED,

    /**
     * {@code MPTCP_PM_MPC_ENDPOINT_ACCOUNTED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "MPTCP_PM_MPC_ENDPOINT_ACCOUNTED"
    )
    MPTCP_PM_MPC_ENDPOINT_ACCOUNTED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_pm_addr_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_pm_addr_entry extends Struct {
    public list_head list;

    public mptcp_addr_info addr;

    public char flags;

    public int ifindex;

    public Ptr<socket> lsk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_pm_add_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_pm_add_entry extends Struct {
    public list_head list;

    public mptcp_addr_info addr;

    public char retrans_times;

    public timer_list add_timer;

    public Ptr<mptcp_sock> sock;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum mptcp_event_attr"
  )
  public enum mptcp_event_attr implements Enum<mptcp_event_attr>, TypedEnum<mptcp_event_attr, java.lang. @Unsigned Integer> {
    /**
     * {@code MPTCP_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "MPTCP_ATTR_UNSPEC"
    )
    MPTCP_ATTR_UNSPEC,

    /**
     * {@code MPTCP_ATTR_TOKEN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "MPTCP_ATTR_TOKEN"
    )
    MPTCP_ATTR_TOKEN,

    /**
     * {@code MPTCP_ATTR_FAMILY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "MPTCP_ATTR_FAMILY"
    )
    MPTCP_ATTR_FAMILY,

    /**
     * {@code MPTCP_ATTR_LOC_ID = 3}
     */
    @EnumMember(
        value = 3L,
        name = "MPTCP_ATTR_LOC_ID"
    )
    MPTCP_ATTR_LOC_ID,

    /**
     * {@code MPTCP_ATTR_REM_ID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "MPTCP_ATTR_REM_ID"
    )
    MPTCP_ATTR_REM_ID,

    /**
     * {@code MPTCP_ATTR_SADDR4 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "MPTCP_ATTR_SADDR4"
    )
    MPTCP_ATTR_SADDR4,

    /**
     * {@code MPTCP_ATTR_SADDR6 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "MPTCP_ATTR_SADDR6"
    )
    MPTCP_ATTR_SADDR6,

    /**
     * {@code MPTCP_ATTR_DADDR4 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "MPTCP_ATTR_DADDR4"
    )
    MPTCP_ATTR_DADDR4,

    /**
     * {@code MPTCP_ATTR_DADDR6 = 8}
     */
    @EnumMember(
        value = 8L,
        name = "MPTCP_ATTR_DADDR6"
    )
    MPTCP_ATTR_DADDR6,

    /**
     * {@code MPTCP_ATTR_SPORT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "MPTCP_ATTR_SPORT"
    )
    MPTCP_ATTR_SPORT,

    /**
     * {@code MPTCP_ATTR_DPORT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "MPTCP_ATTR_DPORT"
    )
    MPTCP_ATTR_DPORT,

    /**
     * {@code MPTCP_ATTR_BACKUP = 11}
     */
    @EnumMember(
        value = 11L,
        name = "MPTCP_ATTR_BACKUP"
    )
    MPTCP_ATTR_BACKUP,

    /**
     * {@code MPTCP_ATTR_ERROR = 12}
     */
    @EnumMember(
        value = 12L,
        name = "MPTCP_ATTR_ERROR"
    )
    MPTCP_ATTR_ERROR,

    /**
     * {@code MPTCP_ATTR_FLAGS = 13}
     */
    @EnumMember(
        value = 13L,
        name = "MPTCP_ATTR_FLAGS"
    )
    MPTCP_ATTR_FLAGS,

    /**
     * {@code MPTCP_ATTR_TIMEOUT = 14}
     */
    @EnumMember(
        value = 14L,
        name = "MPTCP_ATTR_TIMEOUT"
    )
    MPTCP_ATTR_TIMEOUT,

    /**
     * {@code MPTCP_ATTR_IF_IDX = 15}
     */
    @EnumMember(
        value = 15L,
        name = "MPTCP_ATTR_IF_IDX"
    )
    MPTCP_ATTR_IF_IDX,

    /**
     * {@code MPTCP_ATTR_RESET_REASON = 16}
     */
    @EnumMember(
        value = 16L,
        name = "MPTCP_ATTR_RESET_REASON"
    )
    MPTCP_ATTR_RESET_REASON,

    /**
     * {@code MPTCP_ATTR_RESET_FLAGS = 17}
     */
    @EnumMember(
        value = 17L,
        name = "MPTCP_ATTR_RESET_FLAGS"
    )
    MPTCP_ATTR_RESET_FLAGS,

    /**
     * {@code MPTCP_ATTR_SERVER_SIDE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "MPTCP_ATTR_SERVER_SIDE"
    )
    MPTCP_ATTR_SERVER_SIDE,

    /**
     * {@code __MPTCP_ATTR_MAX = 19}
     */
    @EnumMember(
        value = 19L,
        name = "__MPTCP_ATTR_MAX"
    )
    __MPTCP_ATTR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_info extends Struct {
    public char mptcpi_subflows;

    public char mptcpi_add_addr_signal;

    public char mptcpi_add_addr_accepted;

    public char mptcpi_subflows_max;

    public char mptcpi_add_addr_signal_max;

    public char mptcpi_add_addr_accepted_max;

    public @Unsigned int mptcpi_flags;

    public @Unsigned int mptcpi_token;

    public @Unsigned long mptcpi_write_seq;

    public @Unsigned long mptcpi_snd_una;

    public @Unsigned long mptcpi_rcv_nxt;

    public char mptcpi_local_addr_used;

    public char mptcpi_local_addr_max;

    public char mptcpi_csum_enabled;

    public @Unsigned int mptcpi_retransmits;

    public @Unsigned long mptcpi_bytes_retrans;

    public @Unsigned long mptcpi_bytes_sent;

    public @Unsigned long mptcpi_bytes_received;

    public @Unsigned long mptcpi_bytes_acked;

    public char mptcpi_subflows_total;

    public char @Size(3) [] reserved;

    public @Unsigned int mptcpi_last_data_sent;

    public @Unsigned int mptcpi_last_data_recv;

    public @Unsigned int mptcpi_last_ack_recv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_subflow_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_subflow_data extends Struct {
    public @Unsigned int size_subflow_data;

    public @Unsigned int num_subflows;

    public @Unsigned int size_kernel;

    public @Unsigned int size_user;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_subflow_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_subflow_addrs extends Struct {
    @InlineUnion(65087)
    public @Unsigned @OriginalName("__kernel_sa_family_t") short sa_family;

    @InlineUnion(65087)
    public sockaddr sa_local;

    @InlineUnion(65087)
    public sockaddr_in sin_local;

    @InlineUnion(65087)
    public sockaddr_in6 sin6_local;

    @InlineUnion(65087)
    public __kernel_sockaddr_storage ss_local;

    @InlineUnion(65088)
    public sockaddr sa_remote;

    @InlineUnion(65088)
    public sockaddr_in sin_remote;

    @InlineUnion(65088)
    public sockaddr_in6 sin6_remote;

    @InlineUnion(65088)
    public __kernel_sockaddr_storage ss_remote;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_subflow_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_subflow_info extends Struct {
    public @Unsigned int id;

    public mptcp_subflow_addrs addrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct mptcp_full_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class mptcp_full_info extends Struct {
    public @Unsigned int size_tcpinfo_kernel;

    public @Unsigned int size_tcpinfo_user;

    public @Unsigned int size_sfinfo_kernel;

    public @Unsigned int size_sfinfo_user;

    public @Unsigned int num_subflows;

    public @Unsigned int size_arrays_user;

    public @Unsigned long subflow_info;

    public @Unsigned long tcp_info;

    public mptcp_info mptcp_info;
  }
}
