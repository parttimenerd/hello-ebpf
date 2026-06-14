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
 * Generated class for BPF runtime types that start with ncsi
 */
@java.lang.SuppressWarnings("unused")
public final class NcsiDefinitions {
  public static final @Unsigned int ncsi_dev_state_registered = 0;

  public static final @Unsigned int ncsi_dev_state_functional = 256;

  public static final @Unsigned int ncsi_dev_state_probe = 512;

  public static final @Unsigned int ncsi_dev_state_config = 768;

  public static final @Unsigned int ncsi_dev_state_suspend = 1024;

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ncsi_channel> ncsi_add_channel(Ptr<ncsi_package> np, char id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ncsi_package> ncsi_add_package(Ptr<ncsi_dev_priv> ndp, char id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_aen_handler_cr(Ptr<ncsi_dev_priv> ndp, Ptr<ncsi_aen_pkt_hdr> h) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_aen_handler_hncdsc(Ptr<ncsi_dev_priv> ndp, Ptr<ncsi_aen_pkt_hdr> h) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_aen_handler_lsc(Ptr<ncsi_dev_priv> ndp, Ptr<ncsi_aen_pkt_hdr> h) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ncsi_request> ncsi_alloc_request(Ptr<ncsi_dev_priv> ndp,
      @Unsigned int req_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ncsi_calculate_checksum(String data, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ncsi_channel_has_link(Ptr<ncsi_channel> channel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ncsi_channel_is_last(Ptr<ncsi_dev_priv> ndp, Ptr<ncsi_channel> channel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ncsi_channel_is_tx(Ptr<ncsi_dev_priv> ndp, Ptr<ncsi_channel> nc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_channel_monitor(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_choose_active_channel(Ptr<ncsi_dev_priv> ndp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_clear_interface_nl(Ptr<sk_buff> msg, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_cmd_build_header(Ptr<ncsi_pkt_hdr> h, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_ae(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_dc(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_default(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_ebf(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_egmf(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_ev(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_oem(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_rc(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_sl(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_sma(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_snfc(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_sp(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_cmd_handler_svf(Ptr<sk_buff> skb, Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_configure_channel(Ptr<ncsi_dev_priv> ndp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_dev_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ncsi_channel> ncsi_find_channel(Ptr<ncsi_package> np, char id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ncsi_dev> ncsi_find_dev(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ncsi_package> ncsi_find_package(Ptr<ncsi_dev_priv> ndp, char id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_find_package_and_channel(Ptr<ncsi_dev_priv> ndp, char id,
      Ptr<Ptr<ncsi_package>> np, Ptr<Ptr<ncsi_channel>> nc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_free_request(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_init_netlink() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_kick_channels(Ptr<ncsi_dev_priv> ndp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_oem_gma_handler_bcm(Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_oem_gma_handler_intel(Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_oem_gma_handler_mlx(Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_oem_smaf_mlx(Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_pkg_info_all_nl(Ptr<sk_buff> skb, Ptr<netlink_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_pkg_info_nl(Ptr<sk_buff> msg, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_probe_channel(Ptr<ncsi_dev_priv> ndp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_process_next_channel(Ptr<ncsi_dev_priv> ndp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rcv_rsp(Ptr<sk_buff> skb, Ptr<net_device> dev, Ptr<packet_type> pt,
      Ptr<net_device> orig_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ncsi_register_dev($arg1, (void (*)(struct ncsi_dev*))$arg2)")
  public static Ptr<ncsi_dev> ncsi_register_dev(Ptr<net_device> dev, Ptr<?> handler) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_remove_package(Ptr<ncsi_package> np) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_report_link(Ptr<ncsi_dev_priv> ndp, boolean force_down) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_request_timeout(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_reset_dev(Ptr<ncsi_dev> nd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_ae(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_cis(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_dbf(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_dc(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_dcnt(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_dgmf(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_dp(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_dv(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_ebf(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_ec(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_ecnt(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_egmf(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_ev(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gc(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gcps(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gls(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gmcma(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gnpts(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gns(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gp(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gps(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gpuuid(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_gvi(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_oem(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_oem_bcm(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_oem_intel(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_oem_mlx(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_pldm(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_rc(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_sl(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_sma(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_snfc(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_sp(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_rsp_handler_svf(Ptr<ncsi_request> nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_send_cmd_nl(Ptr<sk_buff> msg, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ncsi_send_netlink_err($arg1, $arg2, $arg3, (const struct nlmsghdr*)$arg4, $arg5)")
  public static int ncsi_send_netlink_err(Ptr<net_device> dev, @Unsigned int snd_seq,
      @Unsigned int snd_portid, Ptr<nlmsghdr> nlhdr, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_send_netlink_rsp(Ptr<ncsi_request> nr, Ptr<ncsi_package> np,
      Ptr<ncsi_channel> nc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_send_netlink_timeout(Ptr<ncsi_request> nr, Ptr<ncsi_package> np,
      Ptr<ncsi_channel> nc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_set_channel_mask_nl(Ptr<sk_buff> msg, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_set_interface_nl(Ptr<sk_buff> msg, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_set_package_mask_nl(Ptr<sk_buff> msg, Ptr<genl_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_start_channel_monitor(Ptr<ncsi_channel> nc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_start_dev(Ptr<ncsi_dev> nd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_stop_channel_monitor(Ptr<ncsi_channel> nc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_stop_dev(Ptr<ncsi_dev> nd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_suspend_channel(Ptr<ncsi_dev_priv> ndp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ncsi_unregister_dev(Ptr<ncsi_dev> nd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_update_tx_channel(Ptr<ncsi_dev_priv> ndp, Ptr<ncsi_package> _package,
      Ptr<ncsi_channel> disable, Ptr<ncsi_channel> enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_validate_rsp_pkt(Ptr<ncsi_request> nr, @Unsigned short payload) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_vlan_rx_add_vid(Ptr<net_device> dev,
      @Unsigned @OriginalName("__be16") short proto, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_vlan_rx_kill_vid(Ptr<net_device> dev,
      @Unsigned @OriginalName("__be16") short proto, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_write_package_info(Ptr<sk_buff> skb, Ptr<ncsi_dev_priv> ndp,
      @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ncsi_xmit_cmd(Ptr<ncsi_cmd_arg> nca) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_dev extends Struct {
    public int state;

    public int link_up;

    public Ptr<net_device> dev;

    public Ptr<?> handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_channel_version"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_channel_version extends Struct {
    public char major;

    public char minor;

    public char update;

    public char alpha1;

    public char alpha2;

    public char @Size(13) [] fw_name;

    public @Unsigned int fw_version;

    public @Unsigned short @Size(4) [] pci_ids;

    public @Unsigned int mf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_channel_cap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_channel_cap extends Struct {
    public @Unsigned int index;

    public @Unsigned int cap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_channel_mode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_channel_mode extends Struct {
    public @Unsigned int index;

    public @Unsigned int enable;

    public @Unsigned int size;

    public @Unsigned int @Size(8) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_channel_mac_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_channel_mac_filter extends Struct {
    public char n_uc;

    public char n_mc;

    public char n_mixed;

    public @Unsigned long bitmap;

    public String addrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_channel_vlan_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_channel_vlan_filter extends Struct {
    public char n_vids;

    public @Unsigned long bitmap;

    public Ptr<java.lang. @Unsigned Short> vids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_channel_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_channel_stats extends Struct {
    public @Unsigned long hnc_cnt;

    public @Unsigned long hnc_rx_bytes;

    public @Unsigned long hnc_tx_bytes;

    public @Unsigned long hnc_rx_uc_pkts;

    public @Unsigned long hnc_rx_mc_pkts;

    public @Unsigned long hnc_rx_bc_pkts;

    public @Unsigned long hnc_tx_uc_pkts;

    public @Unsigned long hnc_tx_mc_pkts;

    public @Unsigned long hnc_tx_bc_pkts;

    public @Unsigned int hnc_fcs_err;

    public @Unsigned int hnc_align_err;

    public @Unsigned int hnc_false_carrier;

    public @Unsigned int hnc_runt_pkts;

    public @Unsigned int hnc_jabber_pkts;

    public @Unsigned int hnc_rx_pause_xon;

    public @Unsigned int hnc_rx_pause_xoff;

    public @Unsigned int hnc_tx_pause_xon;

    public @Unsigned int hnc_tx_pause_xoff;

    public @Unsigned int hnc_tx_s_collision;

    public @Unsigned int hnc_tx_m_collision;

    public @Unsigned int hnc_l_collision;

    public @Unsigned int hnc_e_collision;

    public @Unsigned int hnc_rx_ctl_frames;

    public @Unsigned int hnc_rx_64_frames;

    public @Unsigned int hnc_rx_127_frames;

    public @Unsigned int hnc_rx_255_frames;

    public @Unsigned int hnc_rx_511_frames;

    public @Unsigned int hnc_rx_1023_frames;

    public @Unsigned int hnc_rx_1522_frames;

    public @Unsigned int hnc_rx_9022_frames;

    public @Unsigned int hnc_tx_64_frames;

    public @Unsigned int hnc_tx_127_frames;

    public @Unsigned int hnc_tx_255_frames;

    public @Unsigned int hnc_tx_511_frames;

    public @Unsigned int hnc_tx_1023_frames;

    public @Unsigned int hnc_tx_1522_frames;

    public @Unsigned int hnc_tx_9022_frames;

    public @Unsigned long hnc_rx_valid_bytes;

    public @Unsigned int hnc_rx_runt_pkts;

    public @Unsigned int hnc_rx_jabber_pkts;

    public @Unsigned int ncsi_rx_cmds;

    public @Unsigned int ncsi_dropped_cmds;

    public @Unsigned int ncsi_cmd_type_errs;

    public @Unsigned int ncsi_cmd_csum_errs;

    public @Unsigned int ncsi_rx_pkts;

    public @Unsigned int ncsi_tx_pkts;

    public @Unsigned int ncsi_tx_aen_pkts;

    public @Unsigned int pt_tx_pkts;

    public @Unsigned int pt_tx_dropped;

    public @Unsigned int pt_tx_channel_err;

    public @Unsigned int pt_tx_us_err;

    public @Unsigned int pt_rx_pkts;

    public @Unsigned int pt_rx_dropped;

    public @Unsigned int pt_rx_channel_err;

    public @Unsigned int pt_rx_us_err;

    public @Unsigned int pt_rx_os_err;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_channel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_channel extends Struct {
    public char id;

    public int state;

    public boolean reconfigure_needed;

    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<ncsi_package> _package;

    public ncsi_channel_version version;

    public ncsi_channel_cap @Size(6) [] caps;

    public ncsi_channel_mode @Size(8) [] modes;

    public ncsi_channel_mac_filter mac_filter;

    public ncsi_channel_vlan_filter vlan_filter;

    public ncsi_channel_stats stats;

    public monitor_of_ncsi_channel monitor;

    public list_head node;

    public list_head link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_package"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_package extends Struct {
    public char id;

    public char @Size(16) [] uuid;

    public Ptr<ncsi_dev_priv> ndp;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned int channel_num;

    public list_head channels;

    public list_head node;

    public boolean multi_channel;

    public @Unsigned int channel_whitelist;

    public Ptr<ncsi_channel> preferred_channel;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_dev_priv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_dev_priv extends Struct {
    public ncsi_dev ndev;

    public @Unsigned int flags;

    public @Unsigned int gma_flag;

    public __kernel_sockaddr_storage pending_mac;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned int package_probe_id;

    public @Unsigned int package_num;

    public @Unsigned int channel_probe_id;

    public list_head packages;

    public Ptr<ncsi_channel> hot_channel;

    public ncsi_request @Size(256) [] requests;

    public @Unsigned int request_id;

    public @Unsigned int pending_req_num;

    public Ptr<ncsi_package> active_package;

    public Ptr<ncsi_channel> active_channel;

    public list_head channel_queue;

    public work_struct work;

    public packet_type ptype;

    public list_head node;

    public list_head vlan_vids;

    public boolean multi_package;

    public boolean mlx_multi_host;

    public @Unsigned int package_whitelist;

    public char channel_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_request extends Struct {
    public char id;

    public boolean used;

    public @Unsigned int flags;

    public Ptr<ncsi_dev_priv> ndp;

    public Ptr<sk_buff> cmd;

    public Ptr<sk_buff> rsp;

    public timer_list timer;

    public boolean enabled;

    public @Unsigned int snd_seq;

    public @Unsigned int snd_portid;

    public nlmsghdr nlhdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_arg extends Struct {
    public Ptr<ncsi_dev_priv> ndp;

    public char type;

    public char id;

    public char _package;

    public char channel;

    public @Unsigned short payload;

    public @Unsigned int req_flags;

    @InlineUnion(64739)
    public char @Size(16) [] bytes;

    @InlineUnion(64739)
    public @Unsigned short @Size(8) [] words;

    @InlineUnion(64739)
    public @Unsigned int @Size(4) [] dwords;

    public String data;

    public Ptr<genl_info> info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_pkt_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_pkt_hdr extends Struct {
    public char mc_id;

    public char revision;

    public char reserved;

    public char id;

    public char type;

    public char channel;

    public @Unsigned @OriginalName("__be16") short length;

    public @Unsigned @OriginalName("__be32") int @Size(2) [] reserved1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_pkt_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_pkt_hdr extends Struct {
    public ncsi_pkt_hdr common;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(26) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_sp_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_sp_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public char @Size(3) [] reserved;

    public char hw_arbitration;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_dc_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_dc_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public char @Size(3) [] reserved;

    public char ald;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_rc_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_rc_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public @Unsigned @OriginalName("__be32") int reserved;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_ae_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_ae_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public char @Size(3) [] reserved;

    public char mc_id;

    public @Unsigned @OriginalName("__be32") int mode;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(18) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_sl_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_sl_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public @Unsigned @OriginalName("__be32") int mode;

    public @Unsigned @OriginalName("__be32") int oem_mode;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(18) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_svf_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_svf_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public @Unsigned @OriginalName("__be16") short reserved;

    public @Unsigned @OriginalName("__be16") short vlan;

    public @Unsigned @OriginalName("__be16") short reserved1;

    public char index;

    public char enable;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(18) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_ev_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_ev_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public char @Size(3) [] reserved;

    public char mode;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_sma_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_sma_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public char @Size(6) [] mac;

    public char index;

    public char at_e;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(18) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_ebf_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_ebf_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public @Unsigned @OriginalName("__be32") int mode;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_egmf_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_egmf_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public @Unsigned @OriginalName("__be32") int mode;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_snfc_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_snfc_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public char @Size(3) [] reserved;

    public char mode;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_oem_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_oem_pkt extends Struct {
    public ncsi_cmd_pkt_hdr cmd;

    public @Unsigned @OriginalName("__be32") int mfr_id;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_cmd_handler"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_cmd_handler extends Struct {
    public char type;

    public int payload;

    public Ptr<?> handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_pkt_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_pkt_hdr extends Struct {
    public ncsi_pkt_hdr common;

    public @Unsigned @OriginalName("__be16") short code;

    public @Unsigned @OriginalName("__be16") short reason;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(22) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_oem_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_oem_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be32") int mfr_id;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_oem_mlx_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_oem_mlx_pkt extends Struct {
    public char cmd_rev;

    public char cmd;

    public char param;

    public char optional;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_oem_bcm_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_oem_bcm_pkt extends Struct {
    public char ver;

    public char type;

    public @Unsigned @OriginalName("__be16") short len;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_oem_intel_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_oem_intel_pkt extends Struct {
    public char cmd;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gls_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gls_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be32") int status;

    public @Unsigned @OriginalName("__be32") int other;

    public @Unsigned @OriginalName("__be32") int oem_status;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(10) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gvi_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gvi_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public char major;

    public char minor;

    public char update;

    public char alpha1;

    public char @Size(3) [] reserved;

    public char alpha2;

    public char @Size(12) [] fw_name;

    public @Unsigned @OriginalName("__be32") int fw_version;

    public @Unsigned @OriginalName("__be16") short @Size(4) [] pci_ids;

    public @Unsigned @OriginalName("__be32") int mf_id;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gc_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gc_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be32") int cap;

    public @Unsigned @OriginalName("__be32") int bc_cap;

    public @Unsigned @OriginalName("__be32") int mc_cap;

    public @Unsigned @OriginalName("__be32") int buf_cap;

    public @Unsigned @OriginalName("__be32") int aen_cap;

    public char vlan_cnt;

    public char mixed_cnt;

    public char mc_cnt;

    public char uc_cnt;

    public char @Size(2) [] reserved;

    public char vlan_mode;

    public char channel_cnt;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gp_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gp_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public char mac_cnt;

    public char @Size(2) [] reserved;

    public char mac_enable;

    public char vlan_cnt;

    public char reserved1;

    public @Unsigned @OriginalName("__be16") short vlan_enable;

    public @Unsigned @OriginalName("__be32") int link_mode;

    public @Unsigned @OriginalName("__be32") int bc_mode;

    public @Unsigned @OriginalName("__be32") int valid_modes;

    public char vlan_mode;

    public char fc_mode;

    public char @Size(2) [] reserved2;

    public @Unsigned @OriginalName("__be32") int aen_mode;

    public char @Size(6) [] mac;

    public @Unsigned @OriginalName("__be16") short vlan;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gcps_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gcps_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be64") long cnt;

    public @Unsigned @OriginalName("__be64") long rx_bytes;

    public @Unsigned @OriginalName("__be64") long tx_bytes;

    public @Unsigned @OriginalName("__be64") long rx_uc_pkts;

    public @Unsigned @OriginalName("__be64") long rx_mc_pkts;

    public @Unsigned @OriginalName("__be64") long rx_bc_pkts;

    public @Unsigned @OriginalName("__be64") long tx_uc_pkts;

    public @Unsigned @OriginalName("__be64") long tx_mc_pkts;

    public @Unsigned @OriginalName("__be64") long tx_bc_pkts;

    public @Unsigned @OriginalName("__be32") int fcs_err;

    public @Unsigned @OriginalName("__be32") int align_err;

    public @Unsigned @OriginalName("__be32") int false_carrier;

    public @Unsigned @OriginalName("__be32") int runt_pkts;

    public @Unsigned @OriginalName("__be32") int jabber_pkts;

    public @Unsigned @OriginalName("__be32") int rx_pause_xon;

    public @Unsigned @OriginalName("__be32") int rx_pause_xoff;

    public @Unsigned @OriginalName("__be32") int tx_pause_xon;

    public @Unsigned @OriginalName("__be32") int tx_pause_xoff;

    public @Unsigned @OriginalName("__be32") int tx_s_collision;

    public @Unsigned @OriginalName("__be32") int tx_m_collision;

    public @Unsigned @OriginalName("__be32") int l_collision;

    public @Unsigned @OriginalName("__be32") int e_collision;

    public @Unsigned @OriginalName("__be32") int rx_ctl_frames;

    public @Unsigned @OriginalName("__be32") int rx_64_frames;

    public @Unsigned @OriginalName("__be32") int rx_127_frames;

    public @Unsigned @OriginalName("__be32") int rx_255_frames;

    public @Unsigned @OriginalName("__be32") int rx_511_frames;

    public @Unsigned @OriginalName("__be32") int rx_1023_frames;

    public @Unsigned @OriginalName("__be32") int rx_1522_frames;

    public @Unsigned @OriginalName("__be32") int rx_9022_frames;

    public @Unsigned @OriginalName("__be32") int tx_64_frames;

    public @Unsigned @OriginalName("__be32") int tx_127_frames;

    public @Unsigned @OriginalName("__be32") int tx_255_frames;

    public @Unsigned @OriginalName("__be32") int tx_511_frames;

    public @Unsigned @OriginalName("__be32") int tx_1023_frames;

    public @Unsigned @OriginalName("__be32") int tx_1522_frames;

    public @Unsigned @OriginalName("__be32") int tx_9022_frames;

    public @Unsigned @OriginalName("__be64") long rx_valid_bytes;

    public @Unsigned @OriginalName("__be32") int rx_runt_pkts;

    public @Unsigned @OriginalName("__be32") int rx_jabber_pkts;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gns_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gns_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be32") int rx_cmds;

    public @Unsigned @OriginalName("__be32") int dropped_cmds;

    public @Unsigned @OriginalName("__be32") int cmd_type_errs;

    public @Unsigned @OriginalName("__be32") int cmd_csum_errs;

    public @Unsigned @OriginalName("__be32") int rx_pkts;

    public @Unsigned @OriginalName("__be32") int tx_pkts;

    public @Unsigned @OriginalName("__be32") int tx_aen_pkts;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gnpts_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gnpts_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be32") int tx_pkts;

    public @Unsigned @OriginalName("__be32") int tx_dropped;

    public @Unsigned @OriginalName("__be32") int tx_channel_err;

    public @Unsigned @OriginalName("__be32") int tx_us_err;

    public @Unsigned @OriginalName("__be32") int rx_pkts;

    public @Unsigned @OriginalName("__be32") int rx_dropped;

    public @Unsigned @OriginalName("__be32") int rx_channel_err;

    public @Unsigned @OriginalName("__be32") int rx_us_err;

    public @Unsigned @OriginalName("__be32") int rx_os_err;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gps_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gps_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public @Unsigned @OriginalName("__be32") int status;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gpuuid_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gpuuid_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public char @Size(16) [] uuid;

    public @Unsigned @OriginalName("__be32") int checksum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_gmcma_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_gmcma_pkt extends Struct {
    public ncsi_rsp_pkt_hdr rsp;

    public char address_count;

    public char @Size(3) [] reserved;

    public char @Size(0) [] addresses;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_oem_handler"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_oem_handler extends Struct {
    public @Unsigned int mfr_id;

    public Ptr<?> handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_rsp_handler"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_rsp_handler extends Struct {
    public char type;

    public int payload;

    public Ptr<?> handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_aen_pkt_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_aen_pkt_hdr extends Struct {
    public ncsi_pkt_hdr common;

    public char @Size(3) [] reserved2;

    public char type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_aen_lsc_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_aen_lsc_pkt extends Struct {
    public ncsi_aen_pkt_hdr aen;

    public @Unsigned @OriginalName("__be32") int status;

    public @Unsigned @OriginalName("__be32") int oem_status;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(14) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_aen_hncdsc_pkt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_aen_hncdsc_pkt extends Struct {
    public ncsi_aen_pkt_hdr aen;

    public @Unsigned @OriginalName("__be32") int status;

    public @Unsigned @OriginalName("__be32") int checksum;

    public char @Size(18) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_aen_handler"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_aen_handler extends Struct {
    public char type;

    public int payload;

    public Ptr<?> handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ncsi_dev_state"
  )
  public enum ncsi_dev_state implements Enum<ncsi_dev_state>, TypedEnum<ncsi_dev_state, java.lang. @Unsigned Integer> {
    /**
     * {@code ncsi_dev_state_registered = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ncsi_dev_state_registered"
    )
    ncsi_dev_state_registered,

    /**
     * {@code ncsi_dev_state_functional = 256}
     */
    @EnumMember(
        value = 256L,
        name = "ncsi_dev_state_functional"
    )
    ncsi_dev_state_functional,

    /**
     * {@code ncsi_dev_state_probe = 512}
     */
    @EnumMember(
        value = 512L,
        name = "ncsi_dev_state_probe"
    )
    ncsi_dev_state_probe,

    /**
     * {@code ncsi_dev_state_config = 768}
     */
    @EnumMember(
        value = 768L,
        name = "ncsi_dev_state_config"
    )
    ncsi_dev_state_config,

    /**
     * {@code ncsi_dev_state_suspend = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "ncsi_dev_state_suspend"
    )
    ncsi_dev_state_suspend
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ncsi_oem_gma_handler"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ncsi_oem_gma_handler extends Struct {
    public @Unsigned int mfr_id;

    public Ptr<?> handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ncsi_nl_commands"
  )
  public enum ncsi_nl_commands implements Enum<ncsi_nl_commands>, TypedEnum<ncsi_nl_commands, java.lang. @Unsigned Integer> {
    /**
     * {@code NCSI_CMD_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NCSI_CMD_UNSPEC"
    )
    NCSI_CMD_UNSPEC,

    /**
     * {@code NCSI_CMD_PKG_INFO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NCSI_CMD_PKG_INFO"
    )
    NCSI_CMD_PKG_INFO,

    /**
     * {@code NCSI_CMD_SET_INTERFACE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NCSI_CMD_SET_INTERFACE"
    )
    NCSI_CMD_SET_INTERFACE,

    /**
     * {@code NCSI_CMD_CLEAR_INTERFACE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NCSI_CMD_CLEAR_INTERFACE"
    )
    NCSI_CMD_CLEAR_INTERFACE,

    /**
     * {@code NCSI_CMD_SEND_CMD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NCSI_CMD_SEND_CMD"
    )
    NCSI_CMD_SEND_CMD,

    /**
     * {@code NCSI_CMD_SET_PACKAGE_MASK = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NCSI_CMD_SET_PACKAGE_MASK"
    )
    NCSI_CMD_SET_PACKAGE_MASK,

    /**
     * {@code NCSI_CMD_SET_CHANNEL_MASK = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NCSI_CMD_SET_CHANNEL_MASK"
    )
    NCSI_CMD_SET_CHANNEL_MASK,

    /**
     * {@code __NCSI_CMD_AFTER_LAST = 7}
     */
    @EnumMember(
        value = 7L,
        name = "__NCSI_CMD_AFTER_LAST"
    )
    __NCSI_CMD_AFTER_LAST,

    /**
     * {@code NCSI_CMD_MAX = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NCSI_CMD_MAX"
    )
    NCSI_CMD_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ncsi_nl_attrs"
  )
  public enum ncsi_nl_attrs implements Enum<ncsi_nl_attrs>, TypedEnum<ncsi_nl_attrs, java.lang. @Unsigned Integer> {
    /**
     * {@code NCSI_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NCSI_ATTR_UNSPEC"
    )
    NCSI_ATTR_UNSPEC,

    /**
     * {@code NCSI_ATTR_IFINDEX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NCSI_ATTR_IFINDEX"
    )
    NCSI_ATTR_IFINDEX,

    /**
     * {@code NCSI_ATTR_PACKAGE_LIST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NCSI_ATTR_PACKAGE_LIST"
    )
    NCSI_ATTR_PACKAGE_LIST,

    /**
     * {@code NCSI_ATTR_PACKAGE_ID = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NCSI_ATTR_PACKAGE_ID"
    )
    NCSI_ATTR_PACKAGE_ID,

    /**
     * {@code NCSI_ATTR_CHANNEL_ID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NCSI_ATTR_CHANNEL_ID"
    )
    NCSI_ATTR_CHANNEL_ID,

    /**
     * {@code NCSI_ATTR_DATA = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NCSI_ATTR_DATA"
    )
    NCSI_ATTR_DATA,

    /**
     * {@code NCSI_ATTR_MULTI_FLAG = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NCSI_ATTR_MULTI_FLAG"
    )
    NCSI_ATTR_MULTI_FLAG,

    /**
     * {@code NCSI_ATTR_PACKAGE_MASK = 7}
     */
    @EnumMember(
        value = 7L,
        name = "NCSI_ATTR_PACKAGE_MASK"
    )
    NCSI_ATTR_PACKAGE_MASK,

    /**
     * {@code NCSI_ATTR_CHANNEL_MASK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "NCSI_ATTR_CHANNEL_MASK"
    )
    NCSI_ATTR_CHANNEL_MASK,

    /**
     * {@code __NCSI_ATTR_AFTER_LAST = 9}
     */
    @EnumMember(
        value = 9L,
        name = "__NCSI_ATTR_AFTER_LAST"
    )
    __NCSI_ATTR_AFTER_LAST,

    /**
     * {@code NCSI_ATTR_MAX = 8}
     */
    @EnumMember(
        value = 8L,
        name = "NCSI_ATTR_MAX"
    )
    NCSI_ATTR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ncsi_nl_pkg_attrs"
  )
  public enum ncsi_nl_pkg_attrs implements Enum<ncsi_nl_pkg_attrs>, TypedEnum<ncsi_nl_pkg_attrs, java.lang. @Unsigned Integer> {
    /**
     * {@code NCSI_PKG_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NCSI_PKG_ATTR_UNSPEC"
    )
    NCSI_PKG_ATTR_UNSPEC,

    /**
     * {@code NCSI_PKG_ATTR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NCSI_PKG_ATTR"
    )
    NCSI_PKG_ATTR,

    /**
     * {@code NCSI_PKG_ATTR_ID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NCSI_PKG_ATTR_ID"
    )
    NCSI_PKG_ATTR_ID,

    /**
     * {@code NCSI_PKG_ATTR_FORCED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NCSI_PKG_ATTR_FORCED"
    )
    NCSI_PKG_ATTR_FORCED,

    /**
     * {@code NCSI_PKG_ATTR_CHANNEL_LIST = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NCSI_PKG_ATTR_CHANNEL_LIST"
    )
    NCSI_PKG_ATTR_CHANNEL_LIST,

    /**
     * {@code __NCSI_PKG_ATTR_AFTER_LAST = 5}
     */
    @EnumMember(
        value = 5L,
        name = "__NCSI_PKG_ATTR_AFTER_LAST"
    )
    __NCSI_PKG_ATTR_AFTER_LAST,

    /**
     * {@code NCSI_PKG_ATTR_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NCSI_PKG_ATTR_MAX"
    )
    NCSI_PKG_ATTR_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ncsi_nl_channel_attrs"
  )
  public enum ncsi_nl_channel_attrs implements Enum<ncsi_nl_channel_attrs>, TypedEnum<ncsi_nl_channel_attrs, java.lang. @Unsigned Integer> {
    /**
     * {@code NCSI_CHANNEL_ATTR_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NCSI_CHANNEL_ATTR_UNSPEC"
    )
    NCSI_CHANNEL_ATTR_UNSPEC,

    /**
     * {@code NCSI_CHANNEL_ATTR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NCSI_CHANNEL_ATTR"
    )
    NCSI_CHANNEL_ATTR,

    /**
     * {@code NCSI_CHANNEL_ATTR_ID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NCSI_CHANNEL_ATTR_ID"
    )
    NCSI_CHANNEL_ATTR_ID,

    /**
     * {@code NCSI_CHANNEL_ATTR_VERSION_MAJOR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "NCSI_CHANNEL_ATTR_VERSION_MAJOR"
    )
    NCSI_CHANNEL_ATTR_VERSION_MAJOR,

    /**
     * {@code NCSI_CHANNEL_ATTR_VERSION_MINOR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "NCSI_CHANNEL_ATTR_VERSION_MINOR"
    )
    NCSI_CHANNEL_ATTR_VERSION_MINOR,

    /**
     * {@code NCSI_CHANNEL_ATTR_VERSION_STR = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NCSI_CHANNEL_ATTR_VERSION_STR"
    )
    NCSI_CHANNEL_ATTR_VERSION_STR,

    /**
     * {@code NCSI_CHANNEL_ATTR_LINK_STATE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NCSI_CHANNEL_ATTR_LINK_STATE"
    )
    NCSI_CHANNEL_ATTR_LINK_STATE,

    /**
     * {@code NCSI_CHANNEL_ATTR_ACTIVE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "NCSI_CHANNEL_ATTR_ACTIVE"
    )
    NCSI_CHANNEL_ATTR_ACTIVE,

    /**
     * {@code NCSI_CHANNEL_ATTR_FORCED = 8}
     */
    @EnumMember(
        value = 8L,
        name = "NCSI_CHANNEL_ATTR_FORCED"
    )
    NCSI_CHANNEL_ATTR_FORCED,

    /**
     * {@code NCSI_CHANNEL_ATTR_VLAN_LIST = 9}
     */
    @EnumMember(
        value = 9L,
        name = "NCSI_CHANNEL_ATTR_VLAN_LIST"
    )
    NCSI_CHANNEL_ATTR_VLAN_LIST,

    /**
     * {@code NCSI_CHANNEL_ATTR_VLAN_ID = 10}
     */
    @EnumMember(
        value = 10L,
        name = "NCSI_CHANNEL_ATTR_VLAN_ID"
    )
    NCSI_CHANNEL_ATTR_VLAN_ID,

    /**
     * {@code __NCSI_CHANNEL_ATTR_AFTER_LAST = 11}
     */
    @EnumMember(
        value = 11L,
        name = "__NCSI_CHANNEL_ATTR_AFTER_LAST"
    )
    __NCSI_CHANNEL_ATTR_AFTER_LAST,

    /**
     * {@code NCSI_CHANNEL_ATTR_MAX = 10}
     */
    @EnumMember(
        value = 10L,
        name = "NCSI_CHANNEL_ATTR_MAX"
    )
    NCSI_CHANNEL_ATTR_MAX
  }
}
